//! Model of how Windows evaluates Device Installation Restrictions for one
//! device node, **as documented by Microsoft**. Used to predict what an
//! existing or planned policy would do to each device in an inventory.
//! It is a model: it decides nothing on a real system, and its predictions
//! are **NOT VERIFIED ON WINDOWS** (acceptance stage F).
//!
//! Documented behaviour encoded here (Microsoft Learn, "Manage Device
//! Installation with Group Policy" and "Policy CSP – DeviceInstallation"):
//!
//! - With layered evaluation (`AllowDenyLayered = 1`) the order is
//!   *device instance IDs > device IDs > device setup class > removable
//!   devices*; within a layer a prevent rule wins ("unless another policy
//!   setting at the same or higher layer … specifically prevents that
//!   installation").
//! - Without it, "all *Prevent installation…* policy settings have
//!   precedence over any other policy setting that allows Windows to install
//!   a device".
//! - Device-ID rules match when "a hardware ID or compatible ID matches an
//!   ID in this list".
//! - `DenyUnspecified` prevents devices not described by other settings.
//! - Rules act on **installation**; without the retroactive option, devices
//!   installed before the policy keep working (see `installed_assessment`).
//!
//! Not modelled (reported as limitations): the "removable devices" layer
//! (its registry value name is not in Microsoft's CSP mapping table), driver
//! *updates* of installed devices, and multi-function device subtleties.

use serde::{Deserialize, Serialize};

use rustward_core::device::DeviceRecord;

use crate::policy_state::PolicySnapshot;

/// Layer of a matching rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleLayer {
    /// Device instance ID lists (most specific).
    InstanceId,
    /// Hardware / compatible ID lists.
    DeviceId,
    /// Device setup class lists.
    SetupClass,
    /// "Prevent installation of devices not described by other policy
    /// settings".
    Unspecified,
}

/// Which rule decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedRule {
    /// Layer.
    pub layer: RuleLayer,
    /// List value name (e.g. `DenyDeviceIDs`), or `DenyUnspecified`.
    pub list: String,
    /// The matching entry.
    pub entry: String,
}

/// Predicted outcome of an installation attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum InstallOutcome {
    /// An allow rule applies.
    Allowed {
        /// The rule.
        rule: MatchedRule,
    },
    /// A prevent rule applies.
    Prevented {
        /// The rule.
        rule: MatchedRule,
    },
    /// No restriction applies (installation proceeds as without policy).
    NotRestricted,
}

impl InstallOutcome {
    /// Installation would be blocked.
    #[must_use]
    pub fn is_prevented(&self) -> bool {
        matches!(self, Self::Prevented { .. })
    }
}

/// Enabled entries of one list policy. A list counts only when its enabling
/// `REG_DWORD` (same name, directly under the Restrictions key) is 1.
fn enabled_list(policy: &PolicySnapshot, name: &str) -> Vec<String> {
    if policy.dword(name) == Some(1) {
        policy.list(name).into_values().collect()
    } else {
        Vec::new()
    }
}

fn find(policy: &PolicySnapshot, name: &str, candidates: &[&str]) -> Option<MatchedRule> {
    enabled_list(policy, name).into_iter().find_map(|entry| {
        candidates
            .iter()
            .any(|c| c.eq_ignore_ascii_case(entry.trim()))
            .then(|| MatchedRule {
                layer: layer_of(name),
                list: name.to_owned(),
                entry,
            })
    })
}

fn layer_of(list: &str) -> RuleLayer {
    match list {
        "AllowInstanceIDs" | "DenyInstanceIDs" => RuleLayer::InstanceId,
        "AllowDeviceIDs" | "DenyDeviceIDs" => RuleLayer::DeviceId,
        "AllowDeviceClasses" | "DenyDeviceClasses" => RuleLayer::SetupClass,
        _ => RuleLayer::Unspecified,
    }
}

/// Predict the installation outcome of `device` under `policy`.
#[must_use]
pub fn evaluate_install(policy: &PolicySnapshot, device: &DeviceRecord) -> InstallOutcome {
    let instance = [device.instance_id.as_str()];
    let ids: Vec<&str> = device
        .hardware_ids
        .iter()
        .chain(&device.compatible_ids)
        .map(String::as_str)
        .collect();
    let class: Vec<&str> = device.class_guid.as_deref().into_iter().collect();
    let layers: [(&str, &str, &[&str]); 3] = [
        ("DenyInstanceIDs", "AllowInstanceIDs", &instance),
        ("DenyDeviceIDs", "AllowDeviceIDs", &ids),
        ("DenyDeviceClasses", "AllowDeviceClasses", &class),
    ];
    if policy.dword("AllowDenyLayered") == Some(1) {
        for (deny, allow, candidates) in layers {
            if let Some(rule) = find(policy, deny, candidates) {
                return InstallOutcome::Prevented { rule };
            }
            if let Some(rule) = find(policy, allow, candidates) {
                return InstallOutcome::Allowed { rule };
            }
        }
    } else {
        // Default evaluation: any prevent rule has precedence over any allow.
        for (deny, _, candidates) in layers {
            if let Some(rule) = find(policy, deny, candidates) {
                return InstallOutcome::Prevented { rule };
            }
        }
        for (_, allow, candidates) in layers {
            if let Some(rule) = find(policy, allow, candidates) {
                return InstallOutcome::Allowed { rule };
            }
        }
    }
    if policy.dword("DenyUnspecified") == Some(1) {
        return InstallOutcome::Prevented {
            rule: MatchedRule {
                layer: RuleLayer::Unspecified,
                list: "DenyUnspecified".into(),
                entry: "*".into(),
            },
        };
    }
    InstallOutcome::NotRestricted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_install::RESTRICTIONS_KEY;
    use crate::policy_state::RegData;

    const DISK: &str = "{4d36e967-e325-11ce-bfc1-08002be10318}";

    fn dev(instance: &str, hw: &[&str], compat: &[&str]) -> DeviceRecord {
        DeviceRecord {
            instance_id: instance.into(),
            hardware_ids: hw.iter().map(|s| (*s).into()).collect(),
            compatible_ids: compat.iter().map(|s| (*s).into()).collect(),
            class_guid: Some(DISK.into()),
            ..DeviceRecord::default()
        }
    }

    fn sub(list: &str) -> String {
        format!(r"{RESTRICTIONS_KEY}\{list}")
    }

    fn base(layered: bool) -> PolicySnapshot {
        PolicySnapshot::default()
            .with(
                RESTRICTIONS_KEY,
                "AllowDenyLayered",
                RegData::Dword(u32::from(layered)),
            )
            .with(RESTRICTIONS_KEY, "DenyDeviceClasses", RegData::Dword(1))
            .with(
                &sub("DenyDeviceClasses"),
                "1",
                RegData::Sz(DISK.to_uppercase()),
            )
            .with(RESTRICTIONS_KEY, "AllowDeviceIDs", RegData::Dword(1))
            .with(
                &sub("AllowDeviceIDs"),
                "1",
                RegData::Sz("USBSTOR\\DiskSanDisk_".into()),
            )
            .with(
                &sub("AllowDeviceIDs"),
                "2",
                RegData::Sz("SCSI\\DiskSanDisk_".into()),
            )
            .with(RESTRICTIONS_KEY, "AllowInstanceIDs", RegData::Dword(1))
            .with(
                &sub("AllowInstanceIDs"),
                "1",
                RegData::Sz("SCSI\\DISK&VEN_NVME&PROD_SAMSUNG\\5&1".into()),
            )
    }

    fn sandisk() -> DeviceRecord {
        dev(
            "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\\4C53",
            &[
                "USBSTOR\\DiskSanDisk_Ultra___________1.00",
                "USBSTOR\\DiskSanDisk_Ultra___________",
                "USBSTOR\\DiskSanDisk_",
            ],
            &["USBSTOR\\Disk", "GenDisk"],
        )
    }

    fn kingston() -> DeviceRecord {
        dev(
            "USBSTOR\\DISK&VEN_KINGSTON&PROD_DT\\0019",
            &[
                "USBSTOR\\DiskKingstonDataTraveler_3.0PMAP",
                "USBSTOR\\DiskKingston",
            ],
            &["USBSTOR\\Disk", "GenDisk"],
        )
    }

    #[test]
    fn layered_policy_allows_the_brand_prevents_others_and_keeps_internal_disks() {
        let p = base(true);
        assert!(matches!(
            evaluate_install(&p, &sandisk()),
            InstallOutcome::Allowed { rule } if rule.layer == RuleLayer::DeviceId
        ));
        assert!(matches!(
            evaluate_install(&p, &kingston()),
            InstallOutcome::Prevented { rule } if rule.layer == RuleLayer::SetupClass
        ));
        let internal = dev(
            "SCSI\\DISK&VEN_NVME&PROD_SAMSUNG\\5&1",
            &["SCSI\\DiskNVMe____Samsung"],
            &["GenDisk"],
        );
        assert!(matches!(
            evaluate_install(&p, &internal),
            InstallOutcome::Allowed { rule } if rule.layer == RuleLayer::InstanceId
        ));
        // A UASP SanDisk drive (SCSI namespace) is allowed by the SCSI entry.
        let uasp = dev(
            "SCSI\\DISK&VEN_SANDISK&PROD_EXTREME\\7&2",
            &["SCSI\\DiskSanDisk_Extreme_55AE", "SCSI\\DiskSanDisk_"],
            &["SCSI\\Disk", "GenDisk"],
        );
        assert!(!evaluate_install(&p, &uasp).is_prevented());
    }

    #[test]
    fn without_layering_any_prevent_beats_every_allow() {
        // The same lists without AllowDenyLayered: the class prevent rule wins
        // even over instance and device-ID allows (Microsoft default).
        let p = base(false);
        assert!(evaluate_install(&p, &sandisk()).is_prevented());
        let internal = dev(
            "SCSI\\DISK&VEN_NVME&PROD_SAMSUNG\\5&1",
            &["SCSI\\DiskNVMe____Samsung"],
            &["GenDisk"],
        );
        assert!(
            evaluate_install(&p, &internal).is_prevented(),
            "system-disk hazard without layering"
        );
    }

    #[test]
    fn prevent_wins_within_a_layer_and_higher_layers_win() {
        let p = base(true)
            .with(RESTRICTIONS_KEY, "DenyDeviceIDs", RegData::Dword(1))
            .with(
                &sub("DenyDeviceIDs"),
                "1",
                RegData::Sz("usbstor\\disksandisk_".into()),
            );
        assert!(matches!(
            evaluate_install(&p, &sandisk()),
            InstallOutcome::Prevented { rule } if rule.list == "DenyDeviceIDs"
        ));
        // An instance allow (higher layer) beats the device-ID prevent.
        let mut d = sandisk();
        d.instance_id = "SCSI\\DISK&VEN_NVME&PROD_SAMSUNG\\5&1".into();
        assert!(matches!(
            evaluate_install(&p, &d),
            InstallOutcome::Allowed { rule } if rule.layer == RuleLayer::InstanceId
        ));
    }

    #[test]
    fn compatible_ids_match_and_disabled_lists_are_ignored() {
        let p = PolicySnapshot::default()
            .with(RESTRICTIONS_KEY, "DenyDeviceIDs", RegData::Dword(1))
            .with(&sub("DenyDeviceIDs"), "1", RegData::Sz("GenDisk".into()));
        assert!(
            evaluate_install(&p, &sandisk()).is_prevented(),
            "compatible ID GenDisk matches"
        );
        let disabled = PolicySnapshot::default()
            .with(RESTRICTIONS_KEY, "DenyDeviceIDs", RegData::Dword(0))
            .with(&sub("DenyDeviceIDs"), "1", RegData::Sz("GenDisk".into()));
        assert_eq!(
            evaluate_install(&disabled, &sandisk()),
            InstallOutcome::NotRestricted
        );
    }

    #[test]
    fn deny_unspecified_catches_everything_not_described() {
        let p =
            PolicySnapshot::default().with(RESTRICTIONS_KEY, "DenyUnspecified", RegData::Dword(1));
        let mouse = DeviceRecord {
            instance_id: "HID\\VID_046D&PID_C52B\\1".into(),
            hardware_ids: vec!["HID\\VID_046D&PID_C52B".into()],
            class_guid: Some("{745a17a0-74d3-11d0-b6fe-00a0c90f57da}".into()),
            ..DeviceRecord::default()
        };
        assert!(matches!(
            evaluate_install(&p, &mouse),
            InstallOutcome::Prevented { rule } if rule.layer == RuleLayer::Unspecified
        ));
        assert_eq!(
            evaluate_install(&PolicySnapshot::default(), &mouse),
            InstallOutcome::NotRestricted
        );
    }
}
