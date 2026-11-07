//! Interpretation of a **read-only** capture of the Device Installation
//! Restrictions policy (Phase 10, step 1).
//!
//! The capture itself is done by `rustward-windows::policy_reader` (Windows,
//! `KEY_READ` only) or by a mock in tests. It records *every* value under
//! the Restrictions key and its subkeys verbatim, so nothing depends on
//! guessed names. This module only **labels** what was found:
//!
//! - **Documented**: the eight value names in Microsoft's "Policy CSP –
//!   DeviceInstallation" ADMX mapping table: `AllowDenyLayered`,
//!   `AllowDeviceIDs`, `AllowInstanceIDs`, `AllowDeviceClasses`,
//!   `DenyUnspecified`, `DenyDeviceIDs`, `DenyInstanceIDs`,
//!   `DenyDeviceClasses`.
//! - **Unresolved**: the list-entry layout (a subkey named after the policy
//!   holding values `1`, `2`, …: the ADMX list convention, not shown in the
//!   CSP table), and the retroactive flags (`*Retroactive`; names come from
//!   ADMX/security-baseline references, not from the CSP table). They are
//!   reported but flagged until confirmed by a `reg export` in the VM.
//! - **Unrecognised**: anything else; shown raw, never interpreted, never
//!   touched.
//!
//! Nothing in this module or its callers writes the registry.

use serde::{Deserialize, Serialize};

use crate::policy_state::{PolicyConflict, PolicySnapshot, RegData, ValueRef, compare};
use crate::{EnforcementPlan, device_install::RESTRICTIONS_KEY};

/// The eight documented value names (Policy CSP – DeviceInstallation).
pub const DOCUMENTED_VALUES: [&str; 8] = [
    "AllowDenyLayered",
    "AllowDeviceIDs",
    "AllowInstanceIDs",
    "AllowDeviceClasses",
    "DenyUnspecified",
    "DenyDeviceIDs",
    "DenyInstanceIDs",
    "DenyDeviceClasses",
];

/// Retroactive option names as found in ADMX / baseline references. Not in
/// the CSP mapping table: reported as [`NameStatus::Unresolved`].
pub const RETROACTIVE_VALUES: [&str; 3] = [
    "DenyDeviceIDsRetroactive",
    "DenyInstanceIDsRetroactive",
    "DenyDeviceClassesRetroactive",
];

/// List policies: (name, allow?, layer label).
pub const LIST_POLICIES: [(&str, bool, &str); 6] = [
    ("AllowInstanceIDs", true, "instance_id"),
    ("DenyInstanceIDs", false, "instance_id"),
    ("AllowDeviceIDs", true, "device_id"),
    ("DenyDeviceIDs", false, "device_id"),
    ("AllowDeviceClasses", true, "setup_class"),
    ("DenyDeviceClasses", false, "setup_class"),
];

/// How sure we are about a name or layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameStatus {
    /// In Microsoft's CSP mapping table.
    Documented,
    /// Seen in secondary references only; confirm on Windows.
    Unresolved,
}

/// Operating-system facts gathered read-only alongside the capture.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsFacts {
    /// Captured on Windows (false = mock / not available).
    pub is_windows: bool,
    /// `RtlGetVersion` major.
    pub major: Option<u32>,
    /// `RtlGetVersion` minor.
    pub minor: Option<u32>,
    /// `RtlGetVersion` build number.
    pub build: Option<u32>,
    /// Update build revision. **No documented API exposes it**; when present
    /// it was read from the `UBR` registry value (widely used, undocumented).
    pub ubr: Option<u32>,
    /// `GetProductInfo` product type code (e.g. 0x30 = Professional).
    pub product_type: Option<u32>,
}

/// A raw read-only capture.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedPolicy {
    /// Capture time (UTC ms).
    pub captured_ms: i64,
    /// The Restrictions key exists.
    pub key_present: bool,
    /// Every value found (key and one level of subkeys).
    pub values: PolicySnapshot,
    /// Non-fatal read problems (access denied on a subkey, oversized value).
    pub read_errors: Vec<String>,
    /// OS facts.
    pub os: OsFacts,
}

/// One list policy as found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListView {
    /// Value name.
    pub name: String,
    /// Allow (true) or prevent (false).
    pub allow: bool,
    /// `instance_id` / `device_id` / `setup_class`.
    pub layer: String,
    /// Enabling DWORD (None = absent).
    pub enabled: Option<u32>,
    /// Entries read from the list subkey.
    pub entries: Vec<String>,
    /// Name status (documented).
    pub name_status: NameStatus,
    /// Layout of the entries (unresolved: ADMX list convention).
    pub layout_status: NameStatus,
}

/// One flag value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlagView {
    /// Value name.
    pub name: String,
    /// DWORD value (None = absent or not a DWORD).
    pub value: Option<u32>,
    /// Name status.
    pub name_status: NameStatus,
}

/// Layered-evaluation support on this OS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LayeringSupport {
    /// Windows 11 (build ≥ 22000).
    Supported,
    /// Build older than the 2004 family, or UBR below 19041.1151.
    NotSupported {
        /// Why.
        reason: String,
        /// Why (Turkish).
        #[serde(default)]
        reason_tr: String,
    },
    /// Cannot be decided from documented facts.
    Unresolved {
        /// Why.
        reason: String,
        /// Why (Turkish).
        #[serde(default)]
        reason_tr: String,
    },
}

/// RustWard plan values found on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PlanPresence {
    /// No plan value present.
    NotApplied,
    /// Some plan values present and others missing or different: an
    /// interrupted or partially reverted operation.
    Partial {
        /// Values present with the planned data.
        matching: usize,
        /// Values absent.
        missing: usize,
        /// Values present with other data.
        different: usize,
    },
    /// Every plan value present with the planned data. **This is policy
    /// state only, never proof that access is denied.**
    PolicyValuesPresent,
}

/// Interpreted inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInspection {
    /// Capture time.
    pub captured_ms: i64,
    /// Key exists.
    pub key_present: bool,
    /// `AllowDenyLayered` (documented).
    pub layered: FlagView,
    /// `DenyUnspecified` (documented).
    pub deny_unspecified: FlagView,
    /// List policies.
    pub lists: Vec<ListView>,
    /// Retroactive flags (unresolved names).
    pub retroactive: Vec<FlagView>,
    /// Values not interpreted.
    pub unrecognised: Vec<(ValueRef, RegData)>,
    /// OS facts.
    pub os: OsFacts,
    /// Edition supports the policy (Pro/Enterprise/Education/Server).
    pub edition_supported: Option<bool>,
    /// Layered-evaluation support.
    pub layering: LayeringSupport,
    /// Conflicts with the RustWard plan (empty without a plan).
    pub conflicts: Vec<PolicyConflict>,
    /// RustWard plan values found.
    pub plan_presence: Option<PlanPresence>,
    /// Read problems.
    pub read_errors: Vec<String>,
}

fn flag(values: &PolicySnapshot, name: &str, status: NameStatus) -> FlagView {
    FlagView {
        name: name.into(),
        value: values.dword(name),
        name_status: status,
    }
}

/// `GetProductInfo` codes of editions where Device Installation policies
/// apply (Microsoft: the policies require Pro, Enterprise, Education or
/// Server). Home editions do not process them.
fn edition_supported(product: u32) -> bool {
    // PRODUCT_PROFESSIONAL 0x30, PRODUCT_PROFESSIONAL_N 0x31,
    // PRODUCT_ENTERPRISE 0x04, PRODUCT_ENTERPRISE_N 0x1B,
    // PRODUCT_ENTERPRISE_S 0x7D, PRODUCT_ENTERPRISE_S_N 0x7E,
    // PRODUCT_EDUCATION 0x79, PRODUCT_EDUCATION_N 0x7A,
    // PRODUCT_PRO_WORKSTATION 0xA1, PRODUCT_PRO_WORKSTATION_N 0xA2.
    // Codes checked against windows-sys 0.61.2 constants; editions without
    // a constant there (e.g. Pro Education) are not listed and report false.
    matches!(
        product,
        0x30 | 0x31 | 0x04 | 0x1B | 0x7D | 0x7E | 0x79 | 0x7A | 0xA1 | 0xA2
    )
}

/// Layered-evaluation support from OS facts.
#[must_use]
pub fn layering_support(os: &OsFacts) -> LayeringSupport {
    match os.build {
        None => LayeringSupport::Unresolved {
            reason: "OS build not captured".into(),
            reason_tr: "İşletim sistemi derlemesi okunamadı.".into(),
        },
        Some(b) if b >= 22000 => LayeringSupport::Supported,
        Some(b) if (19041..=19045).contains(&b) => match os.ubr {
            Some(u) if u >= crate::device_install::MIN_LAYERING_UBR_19041 => {
                LayeringSupport::Unresolved {
                    reason: format!(
                        "build {b}.{u} meets 19041.1151, but the update revision comes from the undocumented UBR registry value; confirm with winver"
                    ),
                    reason_tr: format!(
                        "Derleme {b}.{u}, 19041.1151 koşulunu karşılıyor; ancak güncelleme düzeltmesi belgelenmemiş UBR kayıt değerinden okunuyor. winver ile doğrulayın."
                    ),
                }
            }
            Some(u) => LayeringSupport::NotSupported {
                reason: format!("build {b}.{u} is below 19041.1151 (KB5004296)"),
                reason_tr: format!("Derleme {b}.{u}, 19041.1151 sürümünün altında (KB5004296)."),
            },
            None => LayeringSupport::Unresolved {
                reason: format!(
                    "build {b}: update revision unknown; layering needs 19041.1151 or later"
                ),
                reason_tr: format!(
                    "Derleme {b}: güncelleme düzeltmesi bilinmiyor; katmanlı değerlendirme 19041.1151 veya sonrasını gerektirir."
                ),
            },
        },
        Some(b) => LayeringSupport::NotSupported {
            reason: format!("build {b} is older than the Windows 10 2004 family"),
            reason_tr: format!("Derleme {b}, Windows 10 2004 ailesinden daha eski."),
        },
    }
}

/// Which plan values are present.
#[must_use]
pub fn plan_presence(current: &PolicySnapshot, plan: &EnforcementPlan) -> PlanPresence {
    let Ok(desired) = crate::policy_state::desired_values(plan) else {
        return PlanPresence::NotApplied;
    };
    let (mut matching, mut missing, mut different) = (0, 0, 0);
    for (at, data) in &desired {
        match current.values.get(at) {
            None => missing += 1,
            Some(d) if d == data => matching += 1,
            Some(_) => different += 1,
        }
    }
    if matching == desired.len() && !desired.is_empty() {
        PlanPresence::PolicyValuesPresent
    } else if matching == 0 && different == 0 {
        PlanPresence::NotApplied
    } else {
        // Values RustWard plans that already exist with the same data on a
        // machine where nothing was applied (e.g. AllowDenyLayered = 1 set by
        // an administrator) also land here; the UI explains this.
        PlanPresence::Partial {
            matching,
            missing,
            different,
        }
    }
}

/// Interpret a capture, optionally against the RustWard plan.
#[must_use]
pub fn inspect(captured: &CapturedPolicy, plan: Option<&EnforcementPlan>) -> PolicyInspection {
    let v = &captured.values;
    let lists = LIST_POLICIES
        .iter()
        .map(|(name, allow, layer)| ListView {
            name: (*name).into(),
            allow: *allow,
            layer: (*layer).into(),
            enabled: v.dword(name),
            entries: v.list(name).into_values().collect(),
            name_status: NameStatus::Documented,
            layout_status: NameStatus::Unresolved,
        })
        .collect();
    let restrictions = RESTRICTIONS_KEY.to_ascii_uppercase();
    let known_top: Vec<String> = DOCUMENTED_VALUES
        .iter()
        .chain(RETROACTIVE_VALUES.iter())
        .map(|n| n.to_ascii_uppercase())
        .collect();
    let known_lists: Vec<String> = LIST_POLICIES
        .iter()
        .map(|(n, _, _)| format!("{restrictions}\\{}", n.to_ascii_uppercase()))
        .collect();
    let unrecognised = v
        .values
        .iter()
        .filter(|(r, d)| {
            let top = r.key == restrictions && known_top.contains(&r.name);
            let entry = known_lists.contains(&r.key)
                && r.name.parse::<u32>().is_ok()
                && matches!(d, RegData::Sz(_));
            !(top || entry)
        })
        .map(|(r, d)| (r.clone(), d.clone()))
        .collect();
    PolicyInspection {
        captured_ms: captured.captured_ms,
        key_present: captured.key_present,
        layered: flag(v, "AllowDenyLayered", NameStatus::Documented),
        deny_unspecified: flag(v, "DenyUnspecified", NameStatus::Documented),
        lists,
        retroactive: RETROACTIVE_VALUES
            .iter()
            .map(|n| flag(v, n, NameStatus::Unresolved))
            .collect(),
        unrecognised,
        os: captured.os.clone(),
        edition_supported: captured.os.product_type.map(edition_supported),
        layering: layering_support(&captured.os),
        conflicts: plan.map(|p| compare(v, p).conflicts).unwrap_or_default(),
        plan_presence: plan.map(|p| plan_presence(v, p)),
        read_errors: captured.read_errors.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_state::{apply_ops, forward_ops};
    use crate::{
        DeviceInstallRestrictionProvider, EnforcementProvider, EnvironmentFacts, PlanInputs,
    };
    use rustward_core::catalog::ValidatedCatalog;
    use rustward_core::device::DeviceSnapshot;
    use rustward_core::policy::ValidatedPolicy;

    const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
    const POLICY: &str = include_str!("../../../config/policy.example.json");
    const SNAPSHOT: &str = include_str!("../../../tests/fixtures/synthetic-lab-snapshot.json");

    fn plan() -> EnforcementPlan {
        let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
        let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
        let mut s = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
        s.devices.retain(|d| !d.instance_id.contains("PSSD_T7"));
        DeviceInstallRestrictionProvider.plan(PlanInputs {
            policy: &policy,
            catalog: &catalog,
            snapshot: &s,
            env: &EnvironmentFacts::default(),
        })
    }

    fn sub(list: &str) -> String {
        format!(r"{RESTRICTIONS_KEY}\{list}")
    }

    #[test]
    fn empty_machine_is_reported_as_no_policy() {
        let i = inspect(&CapturedPolicy::default(), Some(&plan()));
        assert!(!i.key_present);
        assert_eq!(i.layered.value, None);
        assert!(
            i.lists
                .iter()
                .all(|l| l.entries.is_empty() && l.enabled.is_none())
        );
        assert!(i.conflicts.is_empty());
        assert_eq!(i.plan_presence, Some(PlanPresence::NotApplied));
        assert!(matches!(i.layering, LayeringSupport::Unresolved { .. }));
    }

    #[test]
    fn values_are_labelled_documented_unresolved_or_unrecognised() {
        let captured = CapturedPolicy {
            key_present: true,
            values: PolicySnapshot::default()
                .with(RESTRICTIONS_KEY, "AllowDenyLayered", RegData::Dword(1))
                .with(RESTRICTIONS_KEY, "DenyDeviceClasses", RegData::Dword(1))
                .with(
                    &sub("DenyDeviceClasses"),
                    "1",
                    RegData::Sz("{4d36e967-e325-11ce-bfc1-08002be10318}".into()),
                )
                .with(
                    RESTRICTIONS_KEY,
                    "DenyDeviceClassesRetroactive",
                    RegData::Dword(0),
                )
                .with(
                    RESTRICTIONS_KEY,
                    "DenyUnspecified_Text",
                    RegData::Sz("x".into()),
                )
                .with(
                    RESTRICTIONS_KEY,
                    "SomeVendorTool",
                    RegData::Other {
                        reg_type: 3,
                        bytes: 8,
                    },
                )
                .with(
                    &sub("DenyDeviceClasses"),
                    "note",
                    RegData::MultiSz(vec!["a".into()]),
                ),
            ..CapturedPolicy::default()
        };
        let i = inspect(&captured, None);
        assert_eq!(i.layered.value, Some(1));
        assert_eq!(i.layered.name_status, NameStatus::Documented);
        let deny_class = i
            .lists
            .iter()
            .find(|l| l.name == "DenyDeviceClasses")
            .unwrap();
        assert_eq!(deny_class.enabled, Some(1));
        assert_eq!(
            deny_class.entries,
            ["{4d36e967-e325-11ce-bfc1-08002be10318}"]
        );
        assert_eq!(deny_class.layout_status, NameStatus::Unresolved);
        let retro = i
            .retroactive
            .iter()
            .find(|f| f.name == "DenyDeviceClassesRetroactive")
            .unwrap();
        assert_eq!(
            (retro.value, retro.name_status),
            (Some(0), NameStatus::Unresolved)
        );
        // Unknown names are reported raw, never guessed.
        let names: Vec<&str> = i
            .unrecognised
            .iter()
            .map(|(r, _)| r.name.as_str())
            .collect();
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(
            names.contains(&"SOMEVENDORTOOL")
                && names.contains(&"NOTE")
                && names.contains(&"DENYUNSPECIFIED_TEXT")
        );
        assert!(i.plan_presence.is_none() && i.conflicts.is_empty());
    }

    #[test]
    fn conflicts_and_plan_presence_are_reported() {
        let plan = plan();
        let hazardous = CapturedPolicy {
            key_present: true,
            values: PolicySnapshot::default().with(
                RESTRICTIONS_KEY,
                "DenyUnspecified",
                RegData::Dword(1),
            ),
            ..CapturedPolicy::default()
        };
        let i = inspect(&hazardous, Some(&plan));
        assert!(
            i.conflicts
                .contains(&PolicyConflict::ExistingDenyUnspecified)
        );

        let full = apply_ops(
            &PolicySnapshot::default(),
            &forward_ops(&PolicySnapshot::default(), &plan).unwrap(),
        );
        let i = inspect(
            &CapturedPolicy {
                key_present: true,
                values: full.clone(),
                ..CapturedPolicy::default()
            },
            Some(&plan),
        );
        assert_eq!(i.plan_presence, Some(PlanPresence::PolicyValuesPresent));
        // An interrupted application: only the first three values were written.
        let fwd = forward_ops(&PolicySnapshot::default(), &plan).unwrap();
        let partial = apply_ops(&PolicySnapshot::default(), &fwd[..3]);
        assert!(matches!(
            plan_presence(&partial, &plan),
            PlanPresence::Partial {
                matching: 3,
                different: 0,
                ..
            }
        ));
    }

    #[test]
    fn layering_and_edition_follow_documented_thresholds() {
        let os = |build, ubr| OsFacts {
            is_windows: true,
            build: Some(build),
            ubr,
            product_type: Some(0x30),
            ..OsFacts::default()
        };
        assert_eq!(
            layering_support(&os(22631, None)),
            LayeringSupport::Supported
        );
        assert!(matches!(
            layering_support(&os(19045, Some(1150))),
            LayeringSupport::NotSupported { .. }
        ));
        assert!(
            matches!(
                layering_support(&os(19045, Some(5011))),
                LayeringSupport::Unresolved { .. }
            ),
            "UBR is undocumented"
        );
        assert!(matches!(
            layering_support(&os(19045, None)),
            LayeringSupport::Unresolved { .. }
        ));
        assert!(matches!(
            layering_support(&os(18363, Some(9999))),
            LayeringSupport::NotSupported { .. }
        ));
        let pro = CapturedPolicy {
            os: os(19045, None),
            ..CapturedPolicy::default()
        };
        assert_eq!(inspect(&pro, None).edition_supported, Some(true));
        let home = CapturedPolicy {
            os: OsFacts {
                product_type: Some(0x65),
                ..os(19045, None)
            },
            ..CapturedPolicy::default()
        };
        assert_eq!(
            inspect(&home, None).edition_supported,
            Some(false),
            "Core (Home) 0x65"
        );
    }
}
