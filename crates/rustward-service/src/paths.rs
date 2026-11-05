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

  sc.exe create RustWardService binPath= "\"C:\Program Files\RustWard\rustward-service.exe\" service" start= auto obj= LocalSystem DisplayName= "RustWard USB Storage Control"
  sc.exe description RustWardService "Offline USB storage access control (RustWard)"
  sc.exe failure RustWardService reset= 86400 actions= restart/5000/restart/30000/restart/60000
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
}
