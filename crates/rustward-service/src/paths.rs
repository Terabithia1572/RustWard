//! Service names and data locations.

use std::path::{Path, PathBuf};

/// SCM service name.
pub const SERVICE_NAME: &str = "RustWardService";

/// Database and backup locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePaths {
    /// Data directory.
    pub data_dir: PathBuf,
    /// Database file.
    pub database: PathBuf,
    /// Backup directory.
    pub backups: PathBuf,
}

impl ServicePaths {
    /// Layout under a directory.
    #[must_use]
    pub fn under(dir: &Path) -> Self {
        Self {
            data_dir: dir.to_path_buf(),
            database: dir.join("rustward.db"),
            backups: dir.join("backups"),
        }
    }

    /// Production layout: `%ProgramData%\RustWard`. The installer restricts
    /// this directory to SYSTEM and Administrators (see OFFLINE-DEPLOYMENT).
    #[must_use]
    pub fn production() -> Option<Self> {
        std::env::var_os("ProgramData").map(|p| Self::under(&PathBuf::from(p).join("RustWard")))
    }

    /// Development layout in the temp directory (never ProgramData).
    #[must_use]
    pub fn development() -> Self {
        Self::under(&std::env::temp_dir().join("rustward-dev"))
    }
}

/// Planning text for deployment. Printed only; never executed by RustWard.
pub const INSTALL_PLAN: &str = r#"RustWard service deployment plan (PLANNING ONLY - not executed by this tool).
Run by the offline installer in Phase 8, after Windows VM validation:

  sc.exe create RustWardService binPath= "\"C:\Program Files\RustWard\rustward-service.exe\" service" start= auto obj= LocalSystem DisplayName= "RustWard USB Depolama Denetimi"
  sc.exe description RustWardService "Offline USB storage access control (RustWard)"
  sc.exe failure RustWardService reset= 86400 actions= restart/5000/restart/5000/restart/5000
  sc.exe sidtype RustWardService unrestricted
  mkdir "%ProgramData%\RustWard"
  icacls "%ProgramData%\RustWard" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F"

Uninstall: sc.exe stop RustWardService && sc.exe delete RustWardService; keep or export
%ProgramData%\RustWard (audit data) according to the administrator's choice.
No device, driver, registry policy or Group Policy is changed by installing the service in this build."#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts() {
        let p = ServicePaths::under(Path::new("base"));
        assert_eq!(p.database, Path::new("base").join("rustward.db"));
        assert_eq!(p.backups, Path::new("base").join("backups"));
        assert!(
            ServicePaths::development()
                .data_dir
                .ends_with("rustward-dev")
        );
        assert!(INSTALL_PLAN.contains("PLANNING ONLY"));
    }

    const WXS: &str = include_str!("../../../packaging/wix/rustward-service.wxs");
    const TAURI_CONF: &str =
        include_str!("../../../apps/rustward-desktop/src-tauri/tauri.conf.json");
    const PACKAGE_JSON: &str = include_str!("../../../apps/rustward-desktop/package.json");

    fn json_version(text: &str) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(text)
            .ok()?
            .get("version")?
            .as_str()
            .map(str::to_owned)
    }

    /// The installer fragment, the runtime constants and the plan text must
    /// agree; a mismatch would install a service the code cannot find, or
    /// register an event source the code does not write to.
    #[test]
    fn installer_fragment_matches_runtime_constants() {
        assert!(WXS.contains(&format!("Name=\"{SERVICE_NAME}\"")));
        assert!(INSTALL_PLAN.contains(SERVICE_NAME));
        assert!(WXS.contains(&format!(
            "<util:EventSource Log=\"Application\" Name=\"{}\"",
            rustward_windows::eventlog_map::EVENT_SOURCE
        )));
        assert!(WXS.contains("EventMessageFile=\"[#RustWardServiceExe]\""));
        assert!(WXS.contains("Arguments=\"service\""));
        assert!(WXS.contains("Account=\"LocalSystem\""));
        // Protected (P), auto-inherited (AI), SYSTEM + Administrators only.
        assert!(WXS.contains("Sddl=\"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\""));
        assert!(!WXS.contains(";;;AU)") && !WXS.contains(";;;WD)") && !WXS.contains(";;;BU)"));
        assert!(
            WXS.contains("Permanent=\"yes\""),
            "audit data survives uninstall"
        );
        // V1.1 notifier startup entry + all-users Start Menu AUMID metadata are allowed;
        // nothing in the fragment touches DeviceInstall Group Policy.
        assert!(WXS.contains("Name=\"rustward-notifier.exe\""));
        assert!(WXS.contains("Source=\"$(env.TAURI_RUSTWARD_NOTIFIER_EXE)\""));
        assert!(WXS.contains("Key=\"Software\\Microsoft\\Windows\\CurrentVersion\\Run\""));
        assert!(WXS.contains("Name=\"RustWardNotifier\""));
        assert!(WXS.contains("System.AppUserModel.ID"));
        assert!(WXS.contains("Terabithia.RustWard.Desktop"));
        assert_eq!(WXS.matches("<RegistryValue").count(), 1);
        for forbidden in [
            "DeviceInstall",
            "Restrictions",
            "DenyDeviceClasses",
        ] {
            assert!(!WXS.contains(forbidden), "{forbidden}");
        }
    }

    /// The desktop app loads nothing from the network: every CSP source is
    /// local ('self', data: images, the Tauri IPC origin) or 'none'.
    #[test]
    fn desktop_csp_allows_no_remote_origin() {
        let conf: serde_json::Value = serde_json::from_str(TAURI_CONF).unwrap_or_default();
        let csp = conf["app"]["security"]["csp"].as_str().unwrap_or_default();
        assert!(csp.starts_with("default-src 'self'"), "{csp}");
        for directive in csp.split(';').map(str::trim).filter(|d| !d.is_empty()) {
            for source in directive.split_whitespace().skip(1) {
                assert!(
                    ["'self'", "'none'", "data:", "ipc:", "http://ipc.localhost"].contains(&source),
                    "remote or unexpected CSP source {source:?} in {directive:?}"
                );
            }
        }
        assert!(conf["app"]["withGlobalTauri"] != serde_json::Value::Bool(true));
    }

    #[test]
    fn product_versions_are_consistent() {
        let crate_version = env!("CARGO_PKG_VERSION");
        assert_eq!(json_version(TAURI_CONF).as_deref(), Some(crate_version));
        assert_eq!(json_version(PACKAGE_JSON).as_deref(), Some(crate_version));
        let conf: serde_json::Value = serde_json::from_str(TAURI_CONF).unwrap_or_default();
        let windows = &conf["bundle"]["windows"];
        assert_eq!(windows["webviewInstallMode"]["type"], "offlineInstaller");
        assert_eq!(conf["bundle"]["targets"], serde_json::json!(["msi"]));
    }
}
