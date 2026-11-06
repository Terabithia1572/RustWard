//! RustWard local IPC.
//!
//! - [`messages`]: versioned, typed requests and responses.
//! - [`validate`]: server-side input validation (never trust the UI).
//! - Authorization: every request has an [`AccessLevel`]; privileged
//!   requests require an elevated administrator identity established by the
//!   transport (Windows token of the pipe client), never by the frontend.
//! - [`frame`]: length-prefixed JSON frames with a size limit.
//! - [`transport`]: transport trait + in-memory mock with timeouts and
//!   disconnects.
//! - [`rpc`]: client and server loops.
//! - `pipe`: Windows named-pipe transport (Windows only; type-checked on
//!   other hosts with `host-typecheck`). **Not verified on Windows yet.**
//!
//! There is no request that executes commands, writes arbitrary files or
//! changes OS security settings.

pub mod frame;
pub mod messages;
pub mod rpc;
pub mod transport;
pub mod validate;

#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
pub mod pipe;

use serde::{Deserialize, Serialize};

pub use messages::{AccessLevel, Request, ResponseBody};

/// Protocol version. Bump on any incompatible change.
pub const PROTOCOL_VERSION: u16 = 1;

/// Read-only pipe (any authenticated local user).
pub const PIPE_NAME_STATUS: &str = r"\\.\pipe\RustWard.Status.v1";
/// Administrative pipe (SYSTEM + Administrators only).
pub const PIPE_NAME_ADMIN: &str = r"\\.\pipe\RustWard.Admin.v1";

/// SDDL for the read-only pipe: owner LocalSystem (clients verify it),
/// SYSTEM and Administrators full access, Authenticated Users read/write
/// (needed to send requests; the server still accepts only read-only
/// requests on this pipe).
pub const SDDL_STATUS: &str = "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";
/// SDDL for the admin pipe: owner LocalSystem, SYSTEM and Administrators
/// only. Standard users cannot open it at all.
pub const SDDL_ADMIN: &str = "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// Request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    /// Protocol version.
    pub version: u16,
    /// Correlation id.
    pub request_id: u64,
    /// Request.
    pub request: Request,
}

/// Response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    /// Protocol version.
    pub version: u16,
    /// Correlation id.
    pub request_id: u64,
    /// Result.
    pub result: Result<ResponseBody, IpcError>,
}

/// Error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed or invalid request.
    InvalidRequest,
    /// Caller lacks the required access level.
    Unauthorized,
    /// Unknown entity.
    NotFound,
    /// Stale policy version or duplicate.
    Conflict,
    /// Policy/catalog validation failed.
    ValidationFailed,
    /// Protocol version mismatch.
    VersionMismatch,
    /// Not available on this backend/platform.
    NotSupported,
    /// Service unavailable.
    Unavailable,
    /// Timed out.
    Timeout,
    /// Unexpected server error.
    Internal,
}

/// An error returned to the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct IpcError {
    /// Code.
    pub code: ErrorCode,
    /// Message (safe to show; no internal paths or secrets).
    pub message: String,
}

impl IpcError {
    /// Construct.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// How the identity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// Windows token of the named-pipe client.
    NamedPipeToken,
    /// In-process development backend (debug builds only).
    DevBackend,
    /// Unit tests.
    Test,
}

/// Caller identity as established by the transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// `DOMAIN\user`.
    pub account: String,
    /// SID string if known.
    pub sid: Option<String>,
    /// Member of BUILTIN\Administrators (enabled in the token).
    pub is_administrator: bool,
    /// Token is elevated.
    pub elevated: bool,
    /// Source.
    pub source: IdentitySource,
    /// Which pipe/channel the request arrived on.
    pub channel_max_access: AccessLevel,
}

impl ClientIdentity {
    /// Actor string for audit records.
    #[must_use]
    pub fn actor(&self) -> String {
        match self.source {
            IdentitySource::DevBackend => format!("dev-backend:{}", self.account),
            _ => self.account.clone(),
        }
    }
}

/// Authorize a request for an identity.
pub fn authorize(request: &Request, identity: &ClientIdentity) -> Result<(), IpcError> {
    let needed = request.access_level();
    if needed > identity.channel_max_access {
        return Err(IpcError::new(
            ErrorCode::Unauthorized,
            "this channel accepts read-only requests only",
        ));
    }
    match needed {
        AccessLevel::ReadOnly => Ok(()),
        AccessLevel::Administrator if identity.is_administrator && identity.elevated => Ok(()),
        AccessLevel::Administrator => Err(IpcError::new(
            ErrorCode::Unauthorized,
            "administrator rights (elevated) are required for this operation",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(admin: bool, elevated: bool, channel: AccessLevel) -> ClientIdentity {
        ClientIdentity {
            account: "PC\\user".into(),
            sid: None,
            is_administrator: admin,
            elevated,
            source: IdentitySource::Test,
            channel_max_access: channel,
        }
    }

    /// Parse `(A;;RIGHTS;;;SID)` ACEs from an SDDL DACL.
    fn aces(sddl: &str) -> Vec<(String, String)> {
        let dacl = &sddl[sddl.find("D:").expect("dacl")..];
        dacl.split('(')
            .skip(1)
            .map(|ace| {
                let f: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
                assert_eq!(f.len(), 6, "{ace}");
                assert_eq!(f[0], "A", "only allow ACEs: {ace}");
                (f[2].to_string(), f[5].to_string())
            })
            .collect()
    }

    #[test]
    fn pipe_sddl_owner_is_system_and_dacls_are_minimal() {
        for sddl in [SDDL_ADMIN, SDDL_STATUS] {
            assert!(
                sddl.starts_with("O:SYD:P("),
                "owner SYSTEM + protected DACL: {sddl}"
            );
            for (_, sid) in aces(sddl) {
                assert!(
                    !["WD", "AN", "NU", "BG", "IU"].contains(&sid.as_str()),
                    "{sid}"
                );
            }
        }
        assert_eq!(
            aces(SDDL_ADMIN),
            [("GA".into(), "SY".into()), ("GA".into(), "BA".into())],
            "only SYSTEM and Administrators may open the admin pipe"
        );
        let status = aces(SDDL_STATUS);
        assert!(status.contains(&("GRGW".into(), "AU".into())));
        assert!(
            !status.iter().any(|(r, s)| s == "AU" && r.contains("GA")),
            "authenticated users never get full control"
        );
    }

    #[test]
    fn authorization_matrix() {
        let read = Request::GetDashboard;
        let write = Request::RemoveManufacturer {
            id: "kingston".into(),
            expected_policy_version: 1,
        };
        assert!(authorize(&read, &id(false, false, AccessLevel::ReadOnly)).is_ok());
        assert!(authorize(&write, &id(false, false, AccessLevel::Administrator)).is_err());
        assert!(
            authorize(&write, &id(true, false, AccessLevel::Administrator)).is_err(),
            "unelevated admin"
        );
        assert!(
            authorize(&write, &id(true, true, AccessLevel::ReadOnly)).is_err(),
            "read-only channel"
        );
        assert!(authorize(&write, &id(true, true, AccessLevel::Administrator)).is_ok());
    }

    #[test]
    fn every_mutating_request_is_privileged() {
        let mutating = [
            Request::AddManufacturer {
                input: rustward_core::policy_edit::ManufacturerInput {
                    id: None,
                    display_name: "x".into(),
                    aliases: vec![],
                    identifiers: vec![],
                    notes: None,
                },
                allowed: true,
                expected_policy_version: 1,
            },
            Request::SetRuleEnabled {
                id: "a".into(),
                enabled: true,
                expected_policy_version: 1,
            },
            Request::UpdateSettings {
                settings: messages::SettingsView {
                    theme: "dark".into(),
                    language: "tr".into(),
                    notifications_enabled: true,
                    audit_retention_days: 365,
                    inventory_refresh_seconds: 30,
                },
            },
            Request::ApplyRetention,
            Request::CreateBackup,
            Request::LoadSyntheticInventory,
            Request::ExportEvents {
                query: messages::EventQuery::default(),
                format: messages::ExportFormat::Csv,
            },
        ];
        for r in mutating {
            assert_eq!(r.access_level(), AccessLevel::Administrator, "{}", r.name());
        }
    }
}
