//! Service SIDs and pipe security descriptors for the service account
//! (Phase 9A finding F-16: the service runs as LocalSystem).
//!
//! Windows gives every service a SID `NT SERVICE\<name>` =
//! `S-1-5-80-<a>-<b>-<c>-<d>-<e>`, where the five sub-authorities are the
//! SHA-1 of the upper-cased service name in UTF-16LE, read as little-endian
//! `u32`s. A virtual service account runs with that SID as its user. This
//! module computes it without Windows so the pipe owner, the pipe DACLs and
//! the data-directory ACL can be generated for either account and checked
//! by tests.
//!
//! **Status:** the service still runs as LocalSystem. Switching to
//! `NT SERVICE\RustWardService` is prepared (owner check accepts both, SDDL
//! builders, installer variant documented) but needs the VM validation in
//! docs/WINDOWS-VM-ACCEPTANCE.md Stage C; it is not enabled here.

use sha1::{Digest, Sha1};

/// String SID of `NT SERVICE\<service_name>`.
#[must_use]
pub fn service_sid(service_name: &str) -> String {
    let upper: Vec<u8> = service_name
        .to_uppercase()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = Sha1::digest(&upper);
    let subs: Vec<String> = digest
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string())
        .collect();
    format!("S-1-5-80-{}", subs.join("-"))
}

/// String SID of the RustWard service.
#[must_use]
pub fn rustward_service_sid() -> String {
    service_sid(crate::SERVICE_NAME)
}

/// Account the service process runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAccount {
    /// `LocalSystem` (current).
    LocalSystem,
    /// `NT SERVICE\RustWardService` virtual account (prepared, not used).
    VirtualAccount,
}

impl ServiceAccount {
    /// SDDL trustee for the account.
    #[must_use]
    pub fn trustee(self) -> String {
        match self {
            Self::LocalSystem => "SY".into(),
            Self::VirtualAccount => rustward_service_sid(),
        }
    }
}

/// Read rights for Authenticated Users on the status pipe:
/// `FILE_GENERIC_READ | FILE_WRITE_DATA`, never `FILE_CREATE_PIPE_INSTANCE`.
const STATUS_USER_RIGHTS: &str = "0x12008b";

/// Status pipe SDDL for `account` (owner = the service account).
#[must_use]
pub fn status_pipe_sddl(account: ServiceAccount) -> String {
    let o = account.trustee();
    let mut s = format!("O:{o}D:P(A;;GA;;;{o})");
    if account != ServiceAccount::LocalSystem {
        s.push_str("(A;;GA;;;SY)");
    }
    s.push_str(&format!("(A;;GA;;;BA)(A;;{STATUS_USER_RIGHTS};;;AU)"));
    s
}

/// Admin pipe SDDL for `account`.
#[must_use]
pub fn admin_pipe_sddl(account: ServiceAccount) -> String {
    let o = account.trustee();
    let mut s = format!("O:{o}D:P(A;;GA;;;{o})");
    if account != ServiceAccount::LocalSystem {
        s.push_str("(A;;GA;;;SY)");
    }
    s.push_str("(A;;GA;;;BA)");
    s
}

/// Data-directory SDDL for `account` (protected, inherited by children).
#[must_use]
pub fn data_dir_sddl(account: ServiceAccount) -> String {
    match account {
        ServiceAccount::LocalSystem => "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".into(),
        ServiceAccount::VirtualAccount => format!(
            "D:PAI(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            rustward_service_sid()
        ),
    }
}

/// Whether a pipe owner SID (string form) is acceptable to clients: the
/// LocalSystem SID or the RustWard service SID. Standard users can assign
/// neither as owner.
#[must_use]
pub fn is_trusted_pipe_owner(owner_sid: &str) -> bool {
    owner_sid.eq_ignore_ascii_case("S-1-5-18")
        || owner_sid.eq_ignore_ascii_case(&rustward_service_sid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_sid_matches_well_known_windows_values() {
        // NT SERVICE\TrustedInstaller, documented by Microsoft and present in
        // every Windows installation's file ACLs.
        assert_eq!(
            service_sid("TrustedInstaller"),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        // Case-insensitive like the SCM.
        assert_eq!(
            service_sid("trustedinstaller"),
            service_sid("TRUSTEDINSTALLER")
        );
        let sid = rustward_service_sid();
        assert!(sid.starts_with("S-1-5-80-"));
        assert_eq!(sid.split('-').count(), 9, "S-1-5-80 + five sub-authorities");
    }

    #[test]
    fn localsystem_sddl_builders_equal_the_shipped_constants() {
        assert_eq!(
            status_pipe_sddl(ServiceAccount::LocalSystem),
            crate::SDDL_STATUS
        );
        assert_eq!(
            admin_pipe_sddl(ServiceAccount::LocalSystem),
            crate::SDDL_ADMIN
        );
    }

    #[test]
    fn virtual_account_descriptors_keep_users_out() {
        let sid = rustward_service_sid();
        let admin = admin_pipe_sddl(ServiceAccount::VirtualAccount);
        assert!(admin.starts_with(&format!("O:{sid}D:P(")));
        assert!(
            !admin.contains(";;;AU)") && !admin.contains(";;;BU)") && !admin.contains(";;;WD)")
        );
        let status = status_pipe_sddl(ServiceAccount::VirtualAccount);
        assert!(status.ends_with("(A;;0x12008b;;;AU)"));
        assert!(data_dir_sddl(ServiceAccount::VirtualAccount).contains(&sid));
    }

    #[test]
    fn only_system_and_the_service_sid_are_trusted_owners() {
        assert!(is_trusted_pipe_owner("S-1-5-18"));
        assert!(is_trusted_pipe_owner(&rustward_service_sid()));
        for untrusted in [
            "S-1-5-32-544",                                                   // Administrators
            "S-1-5-21-1-2-3-1001",                                            // a user
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // another service
            "S-1-5-19",                                                       // LocalService
        ] {
            assert!(!is_trusted_pipe_owner(untrusted), "{untrusted}");
        }
    }
}
