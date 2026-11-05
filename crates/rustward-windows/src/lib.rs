//! Read-only Windows device inventory for RustWard.
//!
//! This crate **only reads** Plug and Play state through SetupAPI device
//! properties. It does not disable, remove, install or reconfigure
//! devices, and it does not touch the registry or Group Policy. The set of
//! imported Win32 functions is pinned by [`WIN32_API_ALLOWLIST`] and
//! checked by a unit test.
//!
//! On non-Windows hosts [`collect_inventory`] returns
//! [`InventoryError::UnsupportedPlatform`]. The `host-typecheck` feature
//! compiles the SetupAPI backend anyway so it can be type-checked in CI.

#![cfg_attr(not(any(windows, feature = "host-typecheck")), forbid(unsafe_code))]

pub mod wide;

#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
mod setupapi;

use rustward_core::device::{
    DeviceRecord, DeviceSnapshot, SNAPSHOT_SCHEMA_VERSION, SnapshotSource,
};

/// Every Win32 function the backend is permitted to import. All are
/// read-only (or handle cleanup).
pub const WIN32_API_ALLOWLIST: &[&str] = &[
    "SetupDiGetClassDevsW",
    "SetupDiEnumDeviceInfo",
    "SetupDiGetDevicePropertyW",
    "SetupDiDestroyDeviceInfoList",
    "GetLastError",
];

/// Which device nodes to include.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumerationScope {
    /// Currently connected devices only.
    PresentOnly,
    /// Also previously installed, currently disconnected devices. These
    /// matter because device-installation restrictions do not re-evaluate
    /// already-installed devices.
    IncludeNonPresent,
}

/// Inventory errors.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// Not running on Windows.
    #[error("live device inventory is only available on Windows")]
    UnsupportedPlatform,
    /// A Win32 call failed.
    #[error("{api} failed with Win32 error {code}")]
    Win32 {
        /// Function name.
        api: &'static str,
        /// `GetLastError` value.
        code: u32,
    },
    /// The device has no instance ID.
    #[error("device has no instance ID")]
    MissingInstanceId,
    /// A property kept growing between reads.
    #[error("property size changed repeatedly while reading")]
    PropertyUnstable,
    /// Buffer size does not fit the API.
    #[error("property buffer too large")]
    BufferTooLarge,
    /// Device index overflow.
    #[error("too many devices")]
    TooManyDevices,
}

/// A collected inventory and any per-device read warnings.
#[derive(Debug, Clone)]
pub struct Inventory {
    /// The snapshot.
    pub snapshot: DeviceSnapshot,
    /// Devices that could not be read.
    pub warnings: Vec<String>,
}

/// Wrap enumerated records into a live snapshot. Platform-neutral so it is
/// compiled and tested on every host.
#[must_use]
pub fn assemble_live_inventory(
    devices: Vec<DeviceRecord>,
    warnings: Vec<String>,
    scope: EnumerationScope,
    computer_name: Option<String>,
    collected_unix_seconds: u64,
) -> Inventory {
    Inventory {
        snapshot: DeviceSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: SnapshotSource::Live {
                computer_name,
                collected_unix_seconds,
                includes_non_present: scope == EnumerationScope::IncludeNonPresent,
            },
            devices,
        },
        warnings,
    }
}

/// Collect a read-only snapshot of the Plug and Play tree.
pub fn collect_inventory(scope: EnumerationScope) -> Result<Inventory, InventoryError> {
    #[cfg(windows)]
    {
        let (devices, warnings) = setupapi::enumerate(scope)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Ok(assemble_live_inventory(
            devices,
            warnings,
            scope,
            std::env::var("COMPUTERNAME").ok(),
            now,
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = scope;
        Err(InventoryError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only contract: the backend may only reference allowlisted
    /// Win32 functions, and none of the known state-changing APIs.
    #[test]
    fn backend_imports_only_allowlisted_read_only_apis() {
        let src = include_str!("setupapi.rs");
        let tokens: Vec<&str> = src
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty())
            .collect();
        let api_like = |t: &str| {
            t.starts_with("SetupDi")
                || t.starts_with("CM_")
                || t.starts_with("Reg")
                || t.starts_with("DIF_")
                || t == "DeviceIoControl"
                || t.starts_with("CreateFile")
                || t.starts_with("UpdateDriver")
                || t.starts_with("DiInstall")
                || t.starts_with("DiUninstall")
        };
        for t in tokens.iter().copied().filter(|t| api_like(t)) {
            assert!(
                WIN32_API_ALLOWLIST.contains(&t),
                "setupapi.rs references non-allowlisted API {t}"
            );
        }
        for forbidden in [
            "SetupDiSetDeviceRegistryPropertyW",
            "SetupDiSetDevicePropertyW",
            "SetupDiCallClassInstaller",
            "SetupDiChangeState",
            "SetupDiRemoveDevice",
            "SetupDiSetClassInstallParamsW",
            "CM_Disable_DevNode",
            "CM_Uninstall_DevNode",
            "RegSetValueExW",
            "RegCreateKeyExW",
        ] {
            assert!(
                !tokens.contains(&forbidden),
                "forbidden API {forbidden} present"
            );
        }
    }

    #[test]
    fn assembles_live_snapshot_metadata() {
        let inv = assemble_live_inventory(
            vec![DeviceRecord {
                instance_id: "X".into(),
                ..DeviceRecord::default()
            }],
            vec!["w".into()],
            EnumerationScope::IncludeNonPresent,
            Some("PC-01".into()),
            42,
        );
        assert_eq!(inv.snapshot.schema_version, SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(
            inv.snapshot.source,
            SnapshotSource::Live {
                computer_name: Some("PC-01".into()),
                collected_unix_seconds: 42,
                includes_non_present: true,
            }
        );
        assert_eq!(inv.warnings, ["w"]);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_hosts_report_unsupported() {
        assert!(matches!(
            collect_inventory(EnumerationScope::PresentOnly),
            Err(InventoryError::UnsupportedPlatform)
        ));
    }
}
