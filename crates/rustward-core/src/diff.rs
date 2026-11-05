//! Inventory diffs and re-enumeration correlation.
//!
//! Decisions are stateless per devnode: every new devnode is evaluated on
//! its own. This matters for encrypted drives such as TÜBİTAK SIR II, which
//! may expose a different interface (or no storage at all) while locked and
//! re-enumerate as a new device after the PIN is entered on the keypad. The
//! unlocked storage devnode is evaluated when it appears; the locked state
//! can never pre-authorize it.
//!
//! [`correlate_reenumeration`] only *links* a removal and an arrival on the
//! same USB port for the audit trail. It never influences a decision.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::device::{DeviceRecord, DeviceSnapshot};

/// Changes between two snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryDiff {
    /// Devnodes that became present (new, or previously non-present).
    pub arrived: Vec<DeviceRecord>,
    /// Devnodes that are no longer present.
    pub removed: Vec<DeviceRecord>,
}

fn is_present(d: &DeviceRecord) -> bool {
    d.present != Some(false)
}

/// Compute the diff `old -> new` by instance ID (case-insensitive).
#[must_use]
pub fn diff_snapshots(old: &DeviceSnapshot, new: &DeviceSnapshot) -> InventoryDiff {
    let old_map: HashMap<String, &DeviceRecord> = old
        .devices
        .iter()
        .map(|d| (d.instance_id.to_ascii_uppercase(), d))
        .collect();
    let new_map: HashMap<String, &DeviceRecord> = new
        .devices
        .iter()
        .map(|d| (d.instance_id.to_ascii_uppercase(), d))
        .collect();
    let mut diff = InventoryDiff::default();
    for d in &new.devices {
        let was_present = old_map
            .get(&d.instance_id.to_ascii_uppercase())
            .is_some_and(|o| is_present(o));
        if is_present(d) && !was_present {
            diff.arrived.push(d.clone());
        }
    }
    for d in &old.devices {
        let still_present = new_map
            .get(&d.instance_id.to_ascii_uppercase())
            .is_some_and(|n| is_present(n));
        if is_present(d) && !still_present {
            diff.removed.push(d.clone());
        }
    }
    diff
}

/// A removal and an arrival on the same parent (hub port) in one diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReenumerationLink {
    /// Parent (hub) instance ID shared by both.
    pub parent_instance_id: String,
    /// Removed USB devnode.
    pub removed: String,
    /// Arrived USB devnode.
    pub arrived: String,
}

/// Link removed and arrived top-level USB devnodes that share a parent.
/// Audit only; never used for authorization.
#[must_use]
pub fn correlate_reenumeration(diff: &InventoryDiff) -> Vec<ReenumerationLink> {
    let is_usb_device =
        |d: &DeviceRecord| d.enumerator_name() == "USB" && !d.instance_id.contains("&MI_");
    let mut links = Vec::new();
    for r in diff.removed.iter().filter(|d| is_usb_device(d)) {
        let Some(parent) = r.parent_instance_id.as_deref() else {
            continue;
        };
        for a in diff.arrived.iter().filter(|d| is_usb_device(d)) {
            if a.parent_instance_id
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(parent))
            {
                links.push(ReenumerationLink {
                    parent_instance_id: parent.to_owned(),
                    removed: r.instance_id.clone(),
                    arrived: a.instance_id.clone(),
                });
            }
        }
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{SNAPSHOT_SCHEMA_VERSION, SnapshotSource};

    fn rec(id: &str, parent: Option<&str>, present: bool) -> DeviceRecord {
        DeviceRecord {
            instance_id: id.into(),
            parent_instance_id: parent.map(Into::into),
            present: Some(present),
            ..DeviceRecord::default()
        }
    }

    fn snap(devices: Vec<DeviceRecord>) -> DeviceSnapshot {
        DeviceSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: SnapshotSource::Synthetic {
                description: "unit".into(),
            },
            devices,
        }
    }

    #[test]
    fn diff_detects_arrivals_removals_and_presence_changes() {
        let old = snap(vec![
            rec("A", None, true),
            rec("B", None, true),
            rec("C", None, false),
        ]);
        let new = snap(vec![
            rec("a", None, true),
            rec("B", None, false),
            rec("C", None, true),
            rec("D", None, true),
        ]);
        let d = diff_snapshots(&old, &new);
        let arrived: Vec<_> = d.arrived.iter().map(|x| x.instance_id.as_str()).collect();
        let removed: Vec<_> = d.removed.iter().map(|x| x.instance_id.as_str()).collect();
        assert_eq!(arrived, ["C", "D"]);
        assert_eq!(removed, ["B"]);
    }

    #[test]
    fn reenumeration_on_same_port_is_linked_for_audit() {
        let hub = "USB\\ROOT_HUB30\\4&1";
        let old = snap(vec![
            rec(hub, None, true),
            rec("USB\\VID_FFFF&PID_0001\\LOCKED", Some(hub), true),
        ]);
        let new = snap(vec![
            rec(hub, None, true),
            rec("USB\\VID_FFFF&PID_0002\\UNLOCKED", Some(hub), true),
            rec(
                "USBSTOR\\Disk&Ven_EXAMPLE\\UNLOCKED&0",
                Some("USB\\VID_FFFF&PID_0002\\UNLOCKED"),
                true,
            ),
        ]);
        let d = diff_snapshots(&old, &new);
        let links = correlate_reenumeration(&d);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].removed, "USB\\VID_FFFF&PID_0001\\LOCKED");
        assert_eq!(links[0].arrived, "USB\\VID_FFFF&PID_0002\\UNLOCKED");
    }
}
