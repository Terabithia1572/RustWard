//! Windows adapters for RustWard.
//!
//! - Read-only device inventory through SetupAPI device properties
//!   ([`collect_inventory`]); the imported inventory functions are pinned by
//!   [`WIN32_API_ALLOWLIST`].
//! - Device-change notifications (`device_notify`, telemetry only).
//! - Windows Event Log writer (`event_log`).
//! - Service Control Manager host (`service_host`).
//!
//! Nothing in this crate disables, removes, installs or reconfigures
//! devices or drivers, or writes the registry or Group Policy; a unit test
//! scans every source file for such APIs.
//!
//! Platform-neutral logic ([`engine`], [`wide`], [`svc_control`],
//! [`devchange`], [`eventlog_map`]) builds and is tested on every OS. The
//! FFI modules compile on Windows, and on other hosts with the
//! `host-typecheck` feature so CI can type-check them; they are **not
//! verified on Windows yet**.

#![cfg_attr(not(any(windows, feature = "host-typecheck")), forbid(unsafe_code))]

pub mod devchange;
pub mod dpapi;
pub mod engine;
pub mod eventlog_map;
pub mod regdecode;
pub mod svc_control;
pub mod wide;
pub mod wts;

#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
mod setupapi;

#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
pub mod device_notify;
#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
pub mod event_log;
#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
pub mod policy_reader;
#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
pub mod gpo_writer;
#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
pub mod service_host;

/// Read-only capture of the Device Installation Restrictions policy (see
/// [`policy_reader`]). Off Windows this returns an error; nothing is read.
///
/// # Errors
/// Unsupported platform, or the key exists but cannot be read.
pub fn capture_device_install_policy(
    now_ms: i64,
) -> Result<rustward_enforcement::policy_inspect::CapturedPolicy, String> {
    #[cfg(windows)]
    {
        policy_reader::capture(now_ms)
    }
    #[cfg(not(windows))]
    {
        let _ = now_ms;
        Err("policy inspection requires Windows".into())
    }
}

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
    /// Buffer size does not fit the API or exceeds the sanity limit.
    #[error("property buffer too large")]
    BufferTooLarge,
    /// The API reported "insufficient buffer" with a non-growing size.
    #[error("property size reported inconsistently")]
    PropertySizeInconsistent,
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
        let src = concat!(include_str!("setupapi.rs"), include_str!("engine.rs"));
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

    /// No source file in this crate may reference APIs that change device,
    /// driver, service-configuration, registry or policy state.
    #[test]
    fn no_module_references_state_changing_apis() {
        let src = concat!(
            include_str!("setupapi.rs"),
            include_str!("engine.rs"),
            include_str!("device_notify.rs"),
            include_str!("event_log.rs"),
            include_str!("service_host.rs"),
            include_str!("svc_control.rs"),
            include_str!("devchange.rs"),
            include_str!("eventlog_map.rs"),
            include_str!("wide.rs"),
        );
        let tokens: std::collections::HashSet<&str> = src
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty())
            .collect();
        let forbidden_prefixes = [
            "SetupDiSet",
            "SetupDiCall",
            "SetupDiChange",
            "SetupDiRemove",
            "SetupDiInstall",
            "SetupDiRegister",
            "SetupDiDelete",
            "CM_Disable",
            "CM_Enable",
            "CM_Uninstall",
            "CM_Set",
            "CM_Setup",
            "CM_Reenumerate",
            "CM_Query_And_Remove",
            "CM_Request_Device_Eject",
            "RegSet",
            "RegCreate",
            "RegDelete",
            "RegOpen",
            "DiInstall",
            "DiUninstall",
            "UpdateDriver",
            "CreateService",
            "DeleteService",
            "ChangeServiceConfig",
            "OpenSCManager",
            "StartServiceW",
            "ControlService",
            "DeviceIoControl",
            "CreateFile",
        ];
        for t in &tokens {
            for p in forbidden_prefixes {
                assert!(
                    !t.starts_with(p),
                    "forbidden API-like token {t} (prefix {p})"
                );
            }
        }
    }

    /// The policy reader may use only read-only registry functions and
    /// read-only access rights, and none of the state-changing APIs that the
    /// rest of the crate forbids.
    #[test]
    fn policy_reader_is_read_only() {
        let src = include_str!("policy_reader.rs");
        let tokens: std::collections::HashSet<&str> = src
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty())
            .collect();
        let allowed_reg = [
            "RegOpenKeyExW",
            "RegEnumKeyExW",
            "RegEnumValueW",
            "RegGetValueW",
            "RegCloseKey",
        ];
        let allowed_key = ["KEY_READ", "KEY_WOW64_64KEY"];
        for t in &tokens {
            if t.starts_with("Reg") && t.len() > 3 && t.as_bytes()[3].is_ascii_uppercase() {
                assert!(
                    allowed_reg.contains(t),
                    "registry API {t} not on the read-only allowlist"
                );
            }
            if t.starts_with("KEY_") {
                assert!(allowed_key.contains(t), "access right {t} not read-only");
            }
            for p in [
                "SetupDi",
                "CM_",
                "CreateFile",
                "DeviceIoControl",
                "CreateService",
                "DeleteService",
                "ChangeServiceConfig",
                "OpenSCManager",
                "ControlService",
            ] {
                assert!(!t.starts_with(p), "unexpected API {t}");
            }
        }
        for f in [
            "RegSetValueExW",
            "RegCreateKeyExW",
            "RegDeleteValueW",
            "RegDeleteKeyW",
            "RegSaveKeyW",
            "RegRestoreKeyW",
            "RegLoadKeyW",
            "KEY_WRITE",
            "KEY_SET_VALUE",
            "KEY_ALL_ACCESS",
        ] {
            assert!(!tokens.contains(f), "{f} must never appear");
        }
        assert!(src.contains("KEY_READ | KEY_WOW64_64KEY"));
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
