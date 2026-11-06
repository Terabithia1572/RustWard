//! Platform-independent model of the Device Installation Restrictions
//! registry key, and the planning logic that must be correct before any
//! write path exists (Phase 9B):
//!
//! - [`PolicySnapshot`]: the values under `HKLM\…\DeviceInstall\Restrictions`
//!   as they would be captured read-only on a workstation;
//! - [`compare`]: what a plan would add or change, and [`PolicyConflict`]s with
//!   policy that already exists (other GPO settings, retroactive flags,
//!   list-index collisions, overlapping deny entries);
//! - [`merge_plan`]: renumber planned list entries after existing ones so no
//!   existing value is overwritten;
//! - [`apply_ops`] / [`rollback_ops`]: exact forward and rollback operations;
//!   applying a plan and then its rollback restores the captured state
//!   bit-for-bit (tested);
//! - [`suspend_ops`]: the feature-update maintenance step (disable the class
//!   prevent rule, keep the lists);
//! - [`staleness`]: a plan approved for one baseline is invalid after
//!   hardware, OS build or policy changes.
//!
//! **Nothing here reads or writes the registry.** Capturing a
//! [`PolicySnapshot`] on Windows (read-only `RegGetValueW`) and writing
//! values are both unimplemented; writing stays impossible while
//! [`crate::ACTIVATION_ENABLED`] is `false`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use rustward_core::class_guids;
use rustward_core::classify::{DeviceCategory, classify};
use rustward_core::device::DeviceSnapshot;

use crate::device_install::RESTRICTIONS_KEY;
use crate::{EnforcementPlan, PlannedChange};

/// List subkeys used by the planned policy.
pub const LIST_SUBKEYS: [&str; 3] = ["AllowDeviceIDs", "AllowInstanceIDs", "DenyDeviceClasses"];

/// Registry data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum RegData {
    /// `REG_DWORD`.
    Dword(u32),
    /// `REG_SZ` (also used for `REG_EXPAND_SZ` read verbatim, unexpanded).
    Sz(String),
    /// `REG_MULTI_SZ`, as captured (never produced by a plan).
    MultiSz(Vec<String>),
    /// Any other registry type, captured only as type and size so an
    /// inspection can report it without interpreting it.
    Other {
        /// Win32 `REG_*` type code.
        reg_type: u32,
        /// Data size in bytes.
        bytes: usize,
    },
}

/// Value location: key path relative to `HKLM` and value name. Compared
/// case-insensitively, like the registry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ValueRef {
    /// Key below HKLM (normalised to upper case).
    pub key: String,
    /// Value name (normalised to upper case).
    pub name: String,
}

impl ValueRef {
    /// Normalised reference.
    #[must_use]
    pub fn new(key: &str, name: &str) -> Self {
        Self {
            key: key.to_ascii_uppercase(),
            name: name.to_ascii_uppercase(),
        }
    }

    fn in_restrictions(name: &str) -> Self {
        Self::new(RESTRICTIONS_KEY, name)
    }

    fn list_subkey(&self) -> Option<&'static str> {
        let prefix = format!("{}\\", RESTRICTIONS_KEY.to_ascii_uppercase());
        let sub = self.key.strip_prefix(&prefix)?;
        LIST_SUBKEYS
            .into_iter()
            .find(|s| s.eq_ignore_ascii_case(sub))
    }
}

/// Captured (or simulated) values of the Restrictions key and its subkeys.
/// Serialised as a list of `{key, name, data}` entries (JSON object keys
/// must be strings); deserialising normalises names like the registry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    /// Values.
    #[serde(with = "as_entries")]
    pub values: BTreeMap<ValueRef, RegData>,
}

mod as_entries {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{RegData, ValueRef};

    #[derive(Serialize)]
    struct EntryRef<'a> {
        key: &'a str,
        name: &'a str,
        data: &'a RegData,
    }

    #[derive(Deserialize)]
    struct Entry {
        key: String,
        name: String,
        data: RegData,
    }

    pub fn serialize<S: Serializer>(
        m: &BTreeMap<ValueRef, RegData>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_seq(m.iter().map(|(k, data)| EntryRef {
            key: &k.key,
            name: &k.name,
            data,
        }))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<ValueRef, RegData>, D::Error> {
        Ok(Vec::<Entry>::deserialize(d)?
            .into_iter()
            .map(|e| (ValueRef::new(&e.key, &e.name), e.data))
            .collect())
    }
}

impl PolicySnapshot {
    /// Insert a value (builder).
    #[must_use]
    pub fn with(mut self, key: &str, name: &str, data: RegData) -> Self {
        self.values.insert(ValueRef::new(key, name), data);
        self
    }

    /// A `REG_DWORD` directly under the Restrictions key.
    #[must_use]
    pub fn dword(&self, name: &str) -> Option<u32> {
        match self.values.get(&ValueRef::in_restrictions(name)) {
            Some(RegData::Dword(v)) => Some(*v),
            _ => None,
        }
    }

    /// Entries of a list subkey, by numeric index.
    #[must_use]
    pub fn list(&self, subkey: &str) -> BTreeMap<u32, String> {
        let key = format!(r"{RESTRICTIONS_KEY}\{subkey}").to_ascii_uppercase();
        self.values
            .iter()
            .filter(|(r, _)| r.key == key)
            .filter_map(|(r, d)| match (r.name.parse::<u32>(), d) {
                (Ok(i), RegData::Sz(s)) => Some((i, s.clone())),
                _ => None,
            })
            .collect()
    }
}

/// A single registry operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RegOp {
    /// Create or overwrite a value.
    Set {
        /// Where.
        at: ValueRef,
        /// Data.
        data: RegData,
    },
    /// Delete a value.
    Delete {
        /// Where.
        at: ValueRef,
    },
}

/// Apply operations to a snapshot (in-memory model of the registry).
#[must_use]
pub fn apply_ops(before: &PolicySnapshot, ops: &[RegOp]) -> PolicySnapshot {
    let mut s = before.clone();
    for op in ops {
        match op {
            RegOp::Set { at, data } => {
                s.values.insert(at.clone(), data.clone());
            }
            RegOp::Delete { at } => {
                s.values.remove(at);
            }
        }
    }
    s
}

fn data_of(c: &PlannedChange) -> Result<RegData, String> {
    match c.value_type.as_str() {
        "REG_DWORD" => c
            .data
            .parse::<u32>()
            .map(RegData::Dword)
            .map_err(|_| format!("{}\\{}: invalid DWORD {:?}", c.key, c.value_name, c.data)),
        "REG_SZ" => Ok(RegData::Sz(c.data.clone())),
        other => Err(format!(
            "{}\\{}: unsupported type {other}",
            c.key, c.value_name
        )),
    }
}

/// Desired values of a plan.
///
/// # Errors
/// A planned change with an unsupported type or invalid data.
pub fn desired_values(plan: &EnforcementPlan) -> Result<BTreeMap<ValueRef, RegData>, String> {
    plan.changes
        .iter()
        .map(|c| Ok((ValueRef::new(&c.key, &c.value_name), data_of(c)?)))
        .collect()
}

/// Forward operations: set every desired value that differs.
///
/// # Errors
/// See [`desired_values`].
pub fn forward_ops(before: &PolicySnapshot, plan: &EnforcementPlan) -> Result<Vec<RegOp>, String> {
    Ok(desired_values(plan)?
        .into_iter()
        .filter(|(at, data)| before.values.get(at) != Some(data))
        .map(|(at, data)| RegOp::Set { at, data })
        .collect())
}

/// Exact rollback of `forward` applied to `before`: every touched value is
/// restored to its previous data, or deleted if it did not exist.
#[must_use]
pub fn rollback_ops(before: &PolicySnapshot, forward: &[RegOp]) -> Vec<RegOp> {
    let mut touched = BTreeSet::new();
    for op in forward {
        match op {
            RegOp::Set { at, .. } | RegOp::Delete { at } => {
                touched.insert(at.clone());
            }
        }
    }
    touched
        .into_iter()
        .map(|at| match before.values.get(&at) {
            Some(data) => RegOp::Set {
                at,
                data: data.clone(),
            },
            None => RegOp::Delete { at },
        })
        .collect()
}

/// Feature-update / storage-driver maintenance: disable the class prevent
/// rule (so a re-detected boot disk can install) while keeping all lists.
/// Resume = [`rollback_ops`] of these operations.
#[must_use]
pub fn suspend_ops(current: &PolicySnapshot) -> Vec<RegOp> {
    match current.dword("DenyDeviceClasses") {
        Some(0) | None => Vec::new(),
        Some(_) => vec![RegOp::Set {
            at: ValueRef::in_restrictions("DenyDeviceClasses"),
            data: RegData::Dword(0),
        }],
    }
}

/// A conflict between planned and existing policy. Any conflict blocks the
/// plan until an administrator resolves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyConflict {
    /// `DenyUnspecified` = 1 ("prevent installation of devices not described
    /// by other policy settings") blocks every new device, including
    /// keyboards and mice.
    ExistingDenyUnspecified,
    /// A retroactive flag is set; retroactive rules uninstall matching
    /// devices that are already present (system disk hazard).
    RetroactiveFlag {
        /// Value name.
        value: String,
    },
    /// An existing list entry has the same index as a planned entry with a
    /// different value (would be overwritten). Resolved by [`merge_plan`].
    ListIndexCollision {
        /// List subkey.
        list: String,
        /// Index.
        index: u32,
        /// Existing value.
        existing: String,
        /// Planned value.
        planned: String,
    },
    /// An existing prevent entry matches a planned allow entry at the same
    /// layer. Microsoft: an allow applies "unless another policy setting at
    /// the same or higher layer in the hierarchy specifically prevents that
    /// installation", so the planned allow would be ineffective. For
    /// `DenyInstanceIDs` versus a planned internal-disk instance allow this
    /// means the system disk could be blocked.
    DenyOverlapsAllow {
        /// Existing prevent list (`DenyDeviceIDs` / `DenyInstanceIDs`).
        deny_list: String,
        /// The matching ID.
        id: String,
    },
    /// A planned value has an unsupported type or data.
    InvalidPlannedValue {
        /// Description.
        detail: String,
    },
}

/// Result of [`compare`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyComparison {
    /// Values that do not exist yet.
    pub to_add: Vec<ValueRef>,
    /// Values that exist with different data.
    pub to_change: Vec<(ValueRef, RegData, RegData)>,
    /// Values already as planned.
    pub unchanged: Vec<ValueRef>,
    /// Existing values RustWard does not plan and leaves untouched.
    pub foreign: Vec<ValueRef>,
    /// Conflicts.
    pub conflicts: Vec<PolicyConflict>,
}

impl PolicyComparison {
    /// No conflicts.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
    }
}

/// Compare a plan with captured policy.
#[must_use]
pub fn compare(existing: &PolicySnapshot, plan: &EnforcementPlan) -> PolicyComparison {
    let mut out = PolicyComparison::default();
    let desired = match desired_values(plan) {
        Ok(d) => d,
        Err(detail) => {
            out.conflicts
                .push(PolicyConflict::InvalidPlannedValue { detail });
            return out;
        }
    };
    if existing.dword("DenyUnspecified") == Some(1) {
        out.conflicts.push(PolicyConflict::ExistingDenyUnspecified);
    }
    for v in [
        "DenyDeviceClassesRetroactive",
        "DenyDeviceIDsRetroactive",
        "DenyInstanceIDsRetroactive",
    ] {
        if existing.dword(v).is_some_and(|d| d != 0) {
            out.conflicts
                .push(PolicyConflict::RetroactiveFlag { value: v.into() });
        }
    }
    // Note: "Prevent installation of removable devices" is the LOWEST layer
    // (instance IDs > device IDs > setup class > removable devices), so the
    // planned device-ID allows take precedence over it; it is reported as a
    // foreign value, not as a conflict.
    for (at, data) in &desired {
        match existing.values.get(at) {
            None => out.to_add.push(at.clone()),
            Some(d) if d == data => out.unchanged.push(at.clone()),
            Some(d) => {
                if let (Some(list), Ok(index), RegData::Sz(old), RegData::Sz(new)) =
                    (at.list_subkey(), at.name.parse::<u32>(), d, data)
                {
                    out.conflicts.push(PolicyConflict::ListIndexCollision {
                        list: list.into(),
                        index,
                        existing: old.clone(),
                        planned: new.clone(),
                    });
                }
                out.to_change.push((at.clone(), d.clone(), data.clone()));
            }
        }
    }
    out.foreign = existing
        .values
        .keys()
        .filter(|k| !desired.contains_key(*k))
        .cloned()
        .collect();
    for (deny_list, allow_suffix) in [
        ("DenyDeviceIDs", "\\ALLOWDEVICEIDS"),
        ("DenyInstanceIDs", "\\ALLOWINSTANCEIDS"),
    ] {
        let denied: BTreeSet<String> = existing
            .list(deny_list)
            .into_values()
            .map(|s| s.to_ascii_uppercase())
            .collect();
        for c in &plan.changes {
            if c.key.to_ascii_uppercase().ends_with(allow_suffix)
                && denied.contains(&c.data.to_ascii_uppercase())
            {
                out.conflicts.push(PolicyConflict::DenyOverlapsAllow {
                    deny_list: deny_list.into(),
                    id: c.data.clone(),
                });
            }
        }
    }
    out
}

/// Renumber planned list entries so they follow existing entries; entries
/// already present (same text, any index) are not duplicated. Control
/// values are unchanged. Removes every [`PolicyConflict::ListIndexCollision`].
#[must_use]
pub fn merge_plan(existing: &PolicySnapshot, plan: &EnforcementPlan) -> EnforcementPlan {
    let mut merged = plan.clone();
    let mut kept = Vec::with_capacity(plan.changes.len());
    let mut next: BTreeMap<&str, u32> = BTreeMap::new();
    for c in &plan.changes {
        let at = ValueRef::new(&c.key, &c.value_name);
        let Some(list) = at.list_subkey() else {
            kept.push(c.clone());
            continue;
        };
        let current = existing.list(list);
        if current.values().any(|v| v.eq_ignore_ascii_case(&c.data)) {
            continue; // already present
        }
        let n = next
            .entry(list)
            .or_insert_with(|| current.keys().max().copied().unwrap_or(0));
        *n += 1;
        let mut c = c.clone();
        c.value_name = n.to_string();
        kept.push(c);
    }
    merged.changes = kept;
    merged
}

/// Why an approved plan is no longer valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaleReason {
    /// An internal disk appeared that the plan has no allow rule for: with a
    /// class prevent rule it could not install (data/boot hazard).
    NewInternalDisk {
        /// Instance ID.
        instance_id: String,
    },
    /// A disk whose attachment cannot be determined appeared.
    UnknownDisk {
        /// Instance ID.
        instance_id: String,
    },
    /// An internal disk in the baseline is gone (its allow rule is now
    /// unused; harmless but the baseline no longer describes the machine).
    InternalDiskRemoved {
        /// Instance ID.
        instance_id: String,
    },
    /// OS build or update revision changed (feature/cumulative update).
    OsBuildChanged {
        /// At planning.
        planned: Option<(u32, u32)>,
        /// Now.
        current: Option<(u32, u32)>,
    },
    /// The active policy version differs from the plan's.
    PolicyVersionChanged {
        /// Plan.
        planned: u64,
        /// Now.
        current: u64,
    },
}

fn internal_disks(s: &DeviceSnapshot) -> (BTreeSet<String>, BTreeSet<String>) {
    let index = s.index();
    let mut internal = BTreeSet::new();
    let mut unknown = BTreeSet::new();
    for d in &s.devices {
        if !d.class_is(class_guids::DISK_DRIVE) {
            continue;
        }
        match classify(&index, d).category {
            DeviceCategory::SystemOrNonUsbStorage => {
                internal.insert(d.instance_id.to_ascii_uppercase());
            }
            DeviceCategory::StorageAttachmentUnknown => {
                unknown.insert(d.instance_id.to_ascii_uppercase());
            }
            _ => {}
        }
    }
    (internal, unknown)
}

/// Inputs to [`staleness`].
#[derive(Debug, Clone, Copy)]
pub struct StalenessInputs<'a> {
    /// The approved plan.
    pub plan: &'a EnforcementPlan,
    /// Snapshot the plan was built from.
    pub baseline: &'a DeviceSnapshot,
    /// Snapshot now.
    pub current: &'a DeviceSnapshot,
    /// OS build at planning.
    pub planned_os_build: Option<(u32, u32)>,
    /// OS build now.
    pub current_os_build: Option<(u32, u32)>,
    /// Active policy version now.
    pub current_policy_version: u64,
}

/// Reasons the plan must be rebuilt and re-approved (empty = still valid).
#[must_use]
pub fn staleness(i: &StalenessInputs<'_>) -> Vec<StaleReason> {
    let mut out = Vec::new();
    let allowed: BTreeSet<String> = i
        .plan
        .changes
        .iter()
        .filter(|c| c.key.to_ascii_uppercase().ends_with("\\ALLOWINSTANCEIDS"))
        .map(|c| c.data.to_ascii_uppercase())
        .collect();
    let (base_internal, _) = internal_disks(i.baseline);
    let (now_internal, now_unknown) = internal_disks(i.current);
    for id in now_internal.difference(&allowed) {
        out.push(StaleReason::NewInternalDisk {
            instance_id: id.clone(),
        });
    }
    for id in &now_unknown {
        out.push(StaleReason::UnknownDisk {
            instance_id: id.clone(),
        });
    }
    for id in base_internal.difference(&now_internal) {
        out.push(StaleReason::InternalDiskRemoved {
            instance_id: id.clone(),
        });
    }
    if i.planned_os_build != i.current_os_build {
        out.push(StaleReason::OsBuildChanged {
            planned: i.planned_os_build,
            current: i.current_os_build,
        });
    }
    if i.plan.policy_version != i.current_policy_version {
        out.push(StaleReason::PolicyVersionChanged {
            planned: i.plan.policy_version,
            current: i.current_policy_version,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceInstallRestrictionProvider, EnforcementProvider, EnvironmentFacts, PlanInputs,
    };
    use rustward_core::catalog::ValidatedCatalog;
    use rustward_core::policy::ValidatedPolicy;

    const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
    const POLICY: &str = include_str!("../../../config/policy.example.json");
    const SNAPSHOT: &str = include_str!("../../../tests/fixtures/synthetic-lab-snapshot.json");

    fn snapshot() -> DeviceSnapshot {
        let mut s = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
        // Remove the fixture's broken-chain disk so the baseline is complete.
        s.devices.retain(|d| !d.instance_id.contains("PSSD_T7"));
        s
    }

    fn plan_for(s: &DeviceSnapshot) -> EnforcementPlan {
        let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
        let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
        let env = EnvironmentFacts::default();
        DeviceInstallRestrictionProvider.plan(PlanInputs {
            policy: &policy,
            catalog: &catalog,
            snapshot: s,
            env: &env,
        })
    }

    fn sub(list: &str) -> String {
        format!(r"{RESTRICTIONS_KEY}\{list}")
    }

    /// A workstation with an unrelated pre-existing policy.
    fn existing() -> PolicySnapshot {
        PolicySnapshot::default()
            .with(RESTRICTIONS_KEY, "AllowDenyLayered", RegData::Dword(0))
            .with(RESTRICTIONS_KEY, "AllowDeviceIDs", RegData::Dword(1))
            .with(
                &sub("AllowDeviceIDs"),
                "1",
                RegData::Sz("USB\\VID_046D&PID_C52B".into()),
            )
            .with(
                &sub("AllowDeviceIDs"),
                "2",
                RegData::Sz("HID\\VID_046D&PID_C52B".into()),
            )
    }

    #[test]
    fn snapshots_round_trip_through_json_and_normalise_names() {
        let s = existing()
            .with(RESTRICTIONS_KEY, "Odd", RegData::MultiSz(vec!["a".into()]))
            .with(
                RESTRICTIONS_KEY,
                "Bin",
                RegData::Other {
                    reg_type: 3,
                    bytes: 4,
                },
            );
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<PolicySnapshot>(&json).unwrap(), s);
        let lower = r#"{"values":[{"key":"software\\policies\\microsoft\\windows\\deviceinstall\\restrictions","name":"allowdenylayered","data":{"type":"dword","data":1}}]}"#;
        let p: PolicySnapshot = serde_json::from_str(lower).unwrap();
        assert_eq!(p.dword("AllowDenyLayered"), Some(1));
    }

    #[test]
    fn plan_values_are_well_formed() {
        let plan = plan_for(&snapshot());
        let desired = desired_values(&plan).unwrap();
        assert_eq!(desired.len(), plan.changes.len(), "no duplicate value");
        assert_eq!(
            desired.get(&ValueRef::new(
                RESTRICTIONS_KEY,
                "DenyDeviceClassesRetroactive"
            )),
            Some(&RegData::Dword(0))
        );
    }

    #[test]
    fn clean_machine_has_no_conflicts_and_rollback_is_exact() {
        let plan = plan_for(&snapshot());
        let before = PolicySnapshot::default();
        let cmp = compare(&before, &plan);
        assert!(cmp.is_clean(), "{:?}", cmp.conflicts);
        assert_eq!(cmp.to_add.len(), plan.changes.len());
        let fwd = forward_ops(&before, &plan).unwrap();
        let after = apply_ops(&before, &fwd);
        assert_eq!(after.values, desired_values(&plan).unwrap());
        let back = apply_ops(&after, &rollback_ops(&before, &fwd));
        assert_eq!(back, before, "rollback restores an empty key exactly");
    }

    #[test]
    fn existing_lists_collide_until_merged_and_are_then_preserved() {
        let plan = plan_for(&snapshot());
        let before = existing();
        let cmp = compare(&before, &plan);
        assert!(
            cmp.conflicts
                .iter()
                .any(|c| matches!(c, PolicyConflict::ListIndexCollision { list, index: 1, .. } if list == "AllowDeviceIDs")),
            "{:?}",
            cmp.conflicts
        );
        assert!(
            cmp.to_change
                .iter()
                .any(|(r, _, _)| r.name == "ALLOWDENYLAYERED")
        );

        let merged = merge_plan(&before, &plan);
        let cmp = compare(&before, &merged);
        assert!(cmp.is_clean(), "{:?}", cmp.conflicts);
        let fwd = forward_ops(&before, &merged).unwrap();
        let after = apply_ops(&before, &fwd);
        // The administrator's own entries survive at their indices.
        let allow = after.list("AllowDeviceIDs");
        assert_eq!(
            allow.get(&1).map(String::as_str),
            Some("USB\\VID_046D&PID_C52B")
        );
        assert_eq!(
            allow.get(&2).map(String::as_str),
            Some("HID\\VID_046D&PID_C52B")
        );
        assert!(allow.len() > 2);
        // Rollback restores the previous state exactly, including the
        // pre-existing AllowDenyLayered = 0.
        assert_eq!(apply_ops(&after, &rollback_ops(&before, &fwd)), before);
        // Merging is idempotent: merging again against the result adds nothing.
        let again = merge_plan(&after, &merged);
        assert!(forward_ops(&after, &again).unwrap().is_empty());
    }

    #[test]
    fn hazardous_existing_policy_is_reported() {
        let plan = plan_for(&snapshot());
        let find = |suffix: &str| {
            plan.changes
                .iter()
                .find(|c| c.key.ends_with(suffix))
                .unwrap()
                .data
                .clone()
        };
        let allowed_brand = find("\\AllowDeviceIDs");
        let internal_disk = find("\\AllowInstanceIDs");
        let before = PolicySnapshot::default()
            .with(RESTRICTIONS_KEY, "DenyUnspecified", RegData::Dword(1))
            .with(
                RESTRICTIONS_KEY,
                "DenyDeviceIDsRetroactive",
                RegData::Dword(1),
            )
            .with(RESTRICTIONS_KEY, "DenyRemovableDevices", RegData::Dword(1))
            .with(
                &sub("DenyDeviceIDs"),
                "1",
                RegData::Sz(allowed_brand.to_ascii_lowercase()),
            )
            .with(
                &sub("DenyInstanceIDs"),
                "1",
                RegData::Sz(internal_disk.clone()),
            );
        let cmp = compare(&before, &plan);
        assert!(
            cmp.conflicts
                .contains(&PolicyConflict::ExistingDenyUnspecified)
        );
        assert!(cmp.conflicts.contains(&PolicyConflict::RetroactiveFlag {
            value: "DenyDeviceIDsRetroactive".into()
        }));
        assert!(cmp.conflicts.contains(&PolicyConflict::DenyOverlapsAllow {
            deny_list: "DenyDeviceIDs".into(),
            id: allowed_brand.clone(),
        }));
        // A prevent on the system disk's instance ID outranks every allow.
        assert!(cmp.conflicts.contains(&PolicyConflict::DenyOverlapsAllow {
            deny_list: "DenyInstanceIDs".into(),
            id: internal_disk,
        }));
        // "Prevent removable devices" is the lowest layer: not a conflict.
        assert_eq!(cmp.conflicts.len(), 4, "{:?}", cmp.conflicts);
        // Unplanned values are reported as foreign and never touched.
        assert!(cmp.foreign.iter().any(|r| r.name == "DENYUNSPECIFIED"));
        assert!(cmp.foreign.iter().any(|r| r.name == "DENYREMOVABLEDEVICES"));
        let fwd = forward_ops(&before, &plan).unwrap();
        assert!(fwd.iter().all(|op| match op {
            RegOp::Set { at, .. } | RegOp::Delete { at } => !cmp.foreign.contains(at),
        }));
    }

    #[test]
    fn invalid_planned_data_is_a_conflict_not_a_panic() {
        let mut plan = plan_for(&snapshot());
        plan.changes[0].data = "yes".into();
        let cmp = compare(&PolicySnapshot::default(), &plan);
        assert!(matches!(
            cmp.conflicts[..],
            [PolicyConflict::InvalidPlannedValue { .. }]
        ));
    }

    #[test]
    fn maintenance_suspend_and_resume_round_trip() {
        let plan = plan_for(&snapshot());
        let active = apply_ops(
            &PolicySnapshot::default(),
            &forward_ops(&PolicySnapshot::default(), &plan).unwrap(),
        );
        let suspend = suspend_ops(&active);
        assert_eq!(suspend.len(), 1);
        let suspended = apply_ops(&active, &suspend);
        assert_eq!(suspended.dword("DenyDeviceClasses"), Some(0));
        // Lists are kept while suspended.
        assert_eq!(
            suspended.list("AllowInstanceIDs"),
            active.list("AllowInstanceIDs")
        );
        let resumed = apply_ops(&suspended, &rollback_ops(&active, &suspend));
        assert_eq!(resumed, active);
        assert!(suspend_ops(&suspended).is_empty(), "already suspended");
    }

    #[test]
    fn plan_goes_stale_on_hardware_os_and_policy_changes() {
        let baseline = snapshot();
        let plan = plan_for(&baseline);
        let fresh = StalenessInputs {
            plan: &plan,
            baseline: &baseline,
            current: &baseline,
            planned_os_build: Some((19045, 5011)),
            current_os_build: Some((19045, 5011)),
            current_policy_version: plan.policy_version,
        };
        assert!(staleness(&fresh).is_empty());

        // A new internal disk: clone an internal disk with a new instance ID.
        let mut changed = baseline.clone();
        let idx = baseline.index();
        let internal = baseline
            .devices
            .iter()
            .find(|d| {
                d.class_is(class_guids::DISK_DRIVE)
                    && classify(&idx, d).category == DeviceCategory::SystemOrNonUsbStorage
            })
            .unwrap()
            .clone();
        let mut new_disk = internal.clone();
        new_disk.instance_id = format!("{}NEW", internal.instance_id);
        changed.devices.push(new_disk);
        let r = staleness(&StalenessInputs {
            current: &changed,
            current_os_build: Some((19045, 5131)),
            current_policy_version: plan.policy_version + 1,
            ..fresh
        });
        assert!(r.iter().any(|x| matches!(x, StaleReason::NewInternalDisk { instance_id } if instance_id.ends_with("NEW"))), "{r:?}");
        assert!(
            r.iter()
                .any(|x| matches!(x, StaleReason::OsBuildChanged { .. }))
        );
        assert!(
            r.iter()
                .any(|x| matches!(x, StaleReason::PolicyVersionChanged { .. }))
        );

        // Internal disk removed.
        let mut removed = baseline.clone();
        removed
            .devices
            .retain(|d| d.instance_id != internal.instance_id);
        let r = staleness(&StalenessInputs {
            current: &removed,
            ..fresh
        });
        assert!(
            r.iter()
                .any(|x| matches!(x, StaleReason::InternalDiskRemoved { .. })),
            "{r:?}"
        );

        // The fixture's own broken-chain disk counts as unknown.
        let full = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
        let r = staleness(&StalenessInputs {
            current: &full,
            ..fresh
        });
        assert!(
            r.iter()
                .any(|x| matches!(x, StaleReason::UnknownDisk { .. })),
            "{r:?}"
        );
    }
}
