//! **Read-only** interpretation of the *Removable Storage Access* Group
//! Policy (`HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices`).
//!
//! These policies deny read/write/execute access per storage *class* (all
//! removable disks, all CD/DVD drives, all WPD devices, …). They cannot tell
//! one manufacturer from another, so they can never implement "allow
//! SanDisk, deny Kingston": a removable-disk read deny also denies the
//! allowed brands. RustWard only reports what is configured; whether access
//! is really refused is an administrator observation in the test VM.

use serde::{Deserialize, Serialize};

use crate::policy_state::{PolicySnapshot, RegData};

/// Policy key (under HKLM).
pub const RSA_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";
/// Removable Disks class.
pub const REMOVABLE_DISKS: &str = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";

/// Other documented classes, with a short name.
const OTHER_CLASSES: [(&str, &str); 5] = [
    ("{53f56308-b6bf-11d0-94f2-00a0c91efb8b}", "CD/DVD"),
    ("{53f56311-b6bf-11d0-94f2-00a0c91efb8b}", "Floppy"),
    ("{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}", "Tape"),
    ("{6AC27878-A6FA-4155-BA85-F98F491D4F33}", "WPD"),
    ("{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}", "WPD"),
];

/// What the Removable Storage Access policy configures.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovableStorageState {
    /// Any value is configured under the policy key.
    pub configured: bool,
    /// "All Removable Storage classes: Deny all access".
    pub deny_all: bool,
    /// Removable Disks: Deny read access.
    pub disks_deny_read: bool,
    /// Removable Disks: Deny write access.
    pub disks_deny_write: bool,
    /// Removable Disks: Deny execute access.
    pub disks_deny_execute: bool,
    /// Other classes with a deny value (short names, sorted, unique).
    pub other_classes: Vec<String>,
}

impl RemovableStorageState {
    /// A read or write restriction applies to removable disks.
    #[must_use]
    pub fn disks_restricted(&self) -> bool {
        self.deny_all || self.disks_deny_read || self.disks_deny_write
    }
}

fn on(d: &RegData) -> bool {
    matches!(d, RegData::Dword(v) if *v != 0)
}

/// Interpret a capture of the policy key (values + one level of subkeys).
#[must_use]
pub fn removable_storage_state(p: &PolicySnapshot) -> RemovableStorageState {
    let root = RSA_KEY.to_ascii_uppercase();
    let mut s = RemovableStorageState::default();
    for (r, d) in &p.values {
        let key = r.key.to_ascii_uppercase();
        let Some(sub) = key.strip_prefix(&root) else {
            continue;
        };
        s.configured = true;
        let sub = sub.trim_start_matches('\\');
        let name = r.name.to_ascii_uppercase();
        if sub.is_empty() {
            if name == "DENY_ALL" && on(d) {
                s.deny_all = true;
            }
            continue;
        }
        if !name.starts_with("DENY_") || !on(d) {
            continue;
        }
        if sub.eq_ignore_ascii_case(REMOVABLE_DISKS) {
            match name.as_str() {
                "DENY_READ" => s.disks_deny_read = true,
                "DENY_WRITE" => s.disks_deny_write = true,
                "DENY_EXECUTE" => s.disks_deny_execute = true,
                _ => {}
            }
        } else {
            let label = OTHER_CLASSES
                .iter()
                .find(|(g, _)| g.eq_ignore_ascii_case(sub))
                .map_or_else(|| sub.to_string(), |(_, n)| (*n).to_string());
            if !s.other_classes.contains(&label) {
                s.other_classes.push(label);
            }
        }
    }
    s.other_classes.sort();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disks(name: &str, v: u32) -> PolicySnapshot {
        PolicySnapshot::default().with(
            &format!(r"{RSA_KEY}\{REMOVABLE_DISKS}"),
            name,
            RegData::Dword(v),
        )
    }

    #[test]
    fn empty_capture_is_not_configured() {
        let s = removable_storage_state(&PolicySnapshot::default());
        assert!(!s.configured);
        assert!(!s.disks_restricted());
    }

    #[test]
    fn removable_disk_read_and_write_denies_are_recognised() {
        let s = removable_storage_state(&disks("Deny_Read", 1));
        assert!(s.configured && s.disks_deny_read && !s.disks_deny_write);
        assert!(s.disks_restricted());
        let s = removable_storage_state(&disks("Deny_Write", 1));
        assert!(s.disks_deny_write && !s.disks_deny_read);
        // A 0 value is "not denied".
        let s = removable_storage_state(&disks("Deny_Read", 0));
        assert!(s.configured && !s.disks_restricted());
    }

    #[test]
    fn deny_all_and_other_classes() {
        let p = PolicySnapshot::default()
            .with(RSA_KEY, "Deny_All", RegData::Dword(1))
            .with(
                &format!(r"{RSA_KEY}\{{6AC27878-A6FA-4155-BA85-F98F491D4F33}}"),
                "Deny_Write",
                RegData::Dword(1),
            );
        let s = removable_storage_state(&p);
        assert!(s.deny_all && s.disks_restricted());
        assert_eq!(s.other_classes, vec!["WPD".to_string()]);
    }

    #[test]
    fn other_keys_are_ignored() {
        let p = PolicySnapshot::default().with(
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceIDs",
            RegData::Dword(1),
        );
        assert!(!removable_storage_state(&p).configured);
    }
}
