//! Raw device facts as collected by a platform adapter.
//!
//! A [`DeviceSnapshot`] is a point-in-time, read-only description of the
//! Plug and Play tree. It can come from the live Windows enumerator
//! (`rustward-windows`) or from a synthetic JSON fixture used in tests.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Current snapshot schema version.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Maximum parent-chain depth walked before giving up (cycle/corruption guard).
pub const MAX_ANCESTOR_DEPTH: usize = 32;

/// Facts about one Plug and Play device node. Every field except
/// `instance_id` is optional because Windows may not expose it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Device instance ID, e.g. `USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\4C53...&0`.
    pub instance_id: String,
    /// Hardware IDs (most specific first).
    #[serde(default)]
    pub hardware_ids: Vec<String>,
    /// Compatible IDs.
    #[serde(default)]
    pub compatible_ids: Vec<String>,
    /// Setup class GUID, lower-case with braces.
    #[serde(default)]
    pub class_guid: Option<String>,
    /// Setup class name, e.g. `DiskDrive`.
    #[serde(default)]
    pub class_name: Option<String>,
    /// Enumerator name, e.g. `USB`, `USBSTOR`, `SCSI`.
    #[serde(default)]
    pub enumerator: Option<String>,
    /// Function driver service name, e.g. `USBSTOR`, `UASPStor`, `disk`.
    #[serde(default)]
    pub service: Option<String>,
    /// `DEVPKEY_Device_Manufacturer`. This comes from the **driver INF**
    /// (often "(Standard disk drives)" or "Compatible USB storage device"),
    /// not from the hardware. Never use it as a brand identity.
    #[serde(default)]
    pub inf_manufacturer: Option<String>,
    /// Friendly name.
    #[serde(default)]
    pub friendly_name: Option<String>,
    /// Device description.
    #[serde(default)]
    pub description: Option<String>,
    /// Bus-reported description (for USB: the device's iProduct string).
    #[serde(default)]
    pub bus_reported_description: Option<String>,
    /// Parent device instance ID.
    #[serde(default)]
    pub parent_instance_id: Option<String>,
    /// Whether the device is currently present.
    #[serde(default)]
    pub present: Option<bool>,
    /// Configuration Manager problem code, if any.
    #[serde(default)]
    pub problem_code: Option<u32>,
}

impl DeviceRecord {
    /// Enumerator: explicit value or the instance-ID prefix before `\`.
    #[must_use]
    pub fn enumerator_name(&self) -> String {
        self.enumerator
            .clone()
            .unwrap_or_else(|| {
                self.instance_id
                    .split('\\')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .to_ascii_uppercase()
    }

    /// Case-insensitive membership test across hardware and compatible IDs.
    #[must_use]
    pub fn has_id(&self, id: &str) -> bool {
        self.hardware_ids
            .iter()
            .chain(self.compatible_ids.iter())
            .any(|h| h.eq_ignore_ascii_case(id))
    }

    /// Case-insensitive class GUID comparison.
    #[must_use]
    pub fn class_is(&self, guid: &str) -> bool {
        self.class_guid
            .as_deref()
            .is_some_and(|g| g.eq_ignore_ascii_case(guid))
    }

    /// Case-insensitive service comparison.
    #[must_use]
    pub fn service_is(&self, service: &str) -> bool {
        self.service
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case(service))
    }
}

/// Where a snapshot came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SnapshotSource {
    /// Collected from the running system.
    Live {
        /// Computer name reported by the OS, if collected.
        computer_name: Option<String>,
        /// Collection time, seconds since the Unix epoch (UTC).
        collected_unix_seconds: u64,
        /// Whether non-present (previously installed) devices were included.
        includes_non_present: bool,
    },
    /// Hand-written or generated test data. Not real hardware.
    Synthetic {
        /// What the fixture models.
        description: String,
    },
}

/// A point-in-time device tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSnapshot {
    /// Schema version, currently [`SNAPSHOT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Provenance.
    pub source: SnapshotSource,
    /// Device nodes.
    pub devices: Vec<DeviceRecord>,
}

/// Errors loading a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// JSON syntax or shape error.
    #[error("snapshot JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    /// Unsupported schema version.
    #[error("unsupported snapshot schema version {0}")]
    SchemaVersion(u32),
    /// Two records share an instance ID.
    #[error("duplicate device instance ID {0}")]
    DuplicateInstanceId(String),
}

impl DeviceSnapshot {
    /// Parse and structurally validate a snapshot from JSON.
    pub fn from_json(json: &str) -> Result<Self, SnapshotError> {
        let snap: Self = serde_json::from_str(json)?;
        if snap.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(SnapshotError::SchemaVersion(snap.schema_version));
        }
        let mut seen = HashSet::new();
        for d in &snap.devices {
            if !seen.insert(d.instance_id.to_ascii_uppercase()) {
                return Err(SnapshotError::DuplicateInstanceId(d.instance_id.clone()));
            }
        }
        Ok(snap)
    }

    /// Build a lookup index.
    #[must_use]
    pub fn index(&self) -> SnapshotIndex<'_> {
        let by_id = self
            .devices
            .iter()
            .enumerate()
            .map(|(i, d)| (d.instance_id.to_ascii_uppercase(), i))
            .collect();
        SnapshotIndex {
            snapshot: self,
            by_id,
        }
    }
}

/// Index over a snapshot for parent/child navigation.
#[derive(Debug)]
pub struct SnapshotIndex<'a> {
    snapshot: &'a DeviceSnapshot,
    by_id: HashMap<String, usize>,
}

impl<'a> SnapshotIndex<'a> {
    /// Underlying snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &'a DeviceSnapshot {
        self.snapshot
    }

    /// Look up a device by instance ID (case-insensitive).
    #[must_use]
    pub fn get(&self, instance_id: &str) -> Option<&'a DeviceRecord> {
        self.by_id
            .get(&instance_id.to_ascii_uppercase())
            .and_then(|&i| self.snapshot.devices.get(i))
    }

    /// Parent record, if present in the snapshot.
    #[must_use]
    pub fn parent(&self, device: &DeviceRecord) -> Option<&'a DeviceRecord> {
        device
            .parent_instance_id
            .as_deref()
            .and_then(|p| self.get(p))
    }

    /// Ancestors from nearest to farthest. Stops at a missing parent, a
    /// cycle, or [`MAX_ANCESTOR_DEPTH`].
    #[must_use]
    pub fn ancestors(&self, device: &DeviceRecord) -> Vec<&'a DeviceRecord> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        seen.insert(device.instance_id.to_ascii_uppercase());
        let mut cur = self.parent(device);
        while let Some(p) = cur {
            if out.len() >= MAX_ANCESTOR_DEPTH || !seen.insert(p.instance_id.to_ascii_uppercase()) {
                break;
            }
            out.push(p);
            cur = self.parent(p);
        }
        out
    }

    /// Direct children.
    #[must_use]
    pub fn children(&self, device: &DeviceRecord) -> Vec<&'a DeviceRecord> {
        self.snapshot
            .devices
            .iter()
            .filter(|d| {
                d.parent_instance_id
                    .as_deref()
                    .is_some_and(|p| p.eq_ignore_ascii_case(&device.instance_id))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, parent: Option<&str>) -> DeviceRecord {
        DeviceRecord {
            instance_id: id.to_owned(),
            parent_instance_id: parent.map(str::to_owned),
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
    fn ancestors_are_ordered_and_case_insensitive() {
        let s = snap(vec![
            rec("A", None),
            rec("B", Some("a")),
            rec("C", Some("B")),
        ]);
        let idx = s.index();
        let c = idx.get("c").unwrap();
        let chain: Vec<_> = idx
            .ancestors(c)
            .iter()
            .map(|d| d.instance_id.clone())
            .collect();
        assert_eq!(chain, vec!["B", "A"]);
        assert_eq!(idx.children(idx.get("A").unwrap()).len(), 1);
    }

    #[test]
    fn ancestor_walk_terminates_on_cycles() {
        let s = snap(vec![rec("A", Some("B")), rec("B", Some("A"))]);
        let idx = s.index();
        let chain = idx.ancestors(idx.get("A").unwrap());
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn rejects_duplicate_ids_and_wrong_schema() {
        let dup = r#"{"schema_version":1,"source":{"kind":"synthetic","description":"x"},
            "devices":[{"instance_id":"A"},{"instance_id":"a"}]}"#;
        assert!(matches!(
            DeviceSnapshot::from_json(dup),
            Err(SnapshotError::DuplicateInstanceId(_))
        ));
        let bad =
            r#"{"schema_version":9,"source":{"kind":"synthetic","description":"x"},"devices":[]}"#;
        assert!(matches!(
            DeviceSnapshot::from_json(bad),
            Err(SnapshotError::SchemaVersion(9))
        ));
    }

    #[test]
    fn enumerator_falls_back_to_instance_id_prefix() {
        let d = rec("usbstor\\Disk&Ven_X\\1", None);
        assert_eq!(d.enumerator_name(), "USBSTOR");
    }
}
