//! Server-side request validation. Runs before authorization-dependent
//! handlers; the frontend's own validation is a convenience only.

use rustward_core::catalog::IdentifierKind;
use rustward_core::policy_edit::{MAX_ALIASES, MAX_IDENTIFIERS, MAX_TEXT_LEN, ManufacturerInput};

use crate::messages::{EventQuery, Request, SettingsView};
use crate::{ErrorCode, IpcError};

/// Maximum rows for list requests.
pub const MAX_LIST_LIMIT: u32 = 5000;

fn bad(msg: impl Into<String>) -> IpcError {
    IpcError::new(ErrorCode::InvalidRequest, msg)
}

fn slug(field: &str, s: &str) -> Result<(), IpcError> {
    if (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        Ok(())
    } else {
        Err(bad(format!("{field} must match [a-z0-9-]{{1,32}}")))
    }
}

fn text(field: &str, s: &str, max: usize) -> Result<(), IpcError> {
    if s.chars().count() > max {
        return Err(bad(format!("{field} longer than {max} characters")));
    }
    if s.chars().any(char::is_control) {
        return Err(bad(format!("{field} contains control characters")));
    }
    Ok(())
}

fn manufacturer(input: &ManufacturerInput) -> Result<(), IpcError> {
    if let Some(id) = &input.id {
        slug("id", id)?;
    }
    text("display_name", &input.display_name, MAX_TEXT_LEN)?;
    if input.display_name.trim().is_empty() {
        return Err(bad("display_name is required"));
    }
    if input.aliases.len() > MAX_ALIASES {
        return Err(bad(format!("at most {MAX_ALIASES} aliases")));
    }
    for a in &input.aliases {
        text("alias", a, MAX_TEXT_LEN)?;
    }
    if input.identifiers.len() > MAX_IDENTIFIERS {
        return Err(bad(format!("at most {MAX_IDENTIFIERS} identifiers")));
    }
    for i in &input.identifiers {
        text("identifier source", &i.source, MAX_TEXT_LEN)?;
        match i.kind {
            IdentifierKind::InquiryVendor => text("inquiry vendor", &i.value, 8)?,
            IdentifierKind::UsbVid => {
                if !(i.value.len() == 4 && i.value.bytes().all(|b| b.is_ascii_hexdigit())) {
                    return Err(bad("usb_vid must be 4 hex digits"));
                }
            }
        }
    }
    if let Some(n) = &input.notes {
        text("notes", n, MAX_TEXT_LEN)?;
    }
    Ok(())
}

fn query(q: &EventQuery) -> Result<(), IpcError> {
    if let Some(t) = &q.text {
        text("text", t, 200)?;
    }
    if let Some(s) = &q.min_severity
        && !["info", "warning", "critical"].contains(&s.as_str())
    {
        return Err(bad("min_severity must be info, warning or critical"));
    }
    if let Some(k) = &q.kind
        && !(1..=64).contains(&k.len())
    {
        return Err(bad("kind length out of range"));
    }
    if let Some(k) = &q.kind
        && !k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    {
        return Err(bad("kind must match [a-z_]+"));
    }
    if let (Some(a), Some(b)) = (q.since_ms, q.until_ms)
        && a > b
    {
        return Err(bad("since_ms must not be after until_ms"));
    }
    if q.limit.is_some_and(|l| l == 0 || l > MAX_LIST_LIMIT) {
        return Err(bad(format!("limit must be 1..={MAX_LIST_LIMIT}")));
    }
    Ok(())
}

fn settings(s: &SettingsView) -> Result<(), IpcError> {
    if !["system", "light", "dark"].contains(&s.theme.as_str()) {
        return Err(bad("theme must be system, light or dark"));
    }
    if !["tr", "en"].contains(&s.language.as_str()) {
        return Err(bad("language must be tr or en"));
    }
    if !(30..=3650).contains(&s.audit_retention_days) {
        return Err(bad("audit_retention_days must be 30..=3650"));
    }
    if !(5..=3600).contains(&s.inventory_refresh_seconds) {
        return Err(bad("inventory_refresh_seconds must be 5..=3600"));
    }
    Ok(())
}

fn limit(l: u32, max: u32) -> Result<(), IpcError> {
    if l == 0 || l > max {
        Err(bad(format!("limit must be 1..={max}")))
    } else {
        Ok(())
    }
}

/// Validate a request's fields.
pub fn validate_request(r: &Request) -> Result<(), IpcError> {
    match r {
        Request::GetDashboard
        | Request::ListDevices { .. }
        | Request::ListManufacturers
        | Request::GetDiagnostics
        | Request::GetSettings
        | Request::RunSimulation
        | Request::ApplyRetention
        | Request::CreateBackup
        | Request::RefreshInventory
        | Request::LoadSyntheticInventory => Ok(()),
        Request::ExplainDevice { device_key } => {
            if device_key.len() == 32 && device_key.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(())
            } else {
                Err(bad("device_key must be 32 hex characters"))
            }
        }
        Request::ListBlocked { limit: l } => limit(*l, 1000),
        Request::ListPolicyChanges { limit: l } => limit(*l, 1000),
        Request::ListEvents { query: q } | Request::ExportEvents { query: q, .. } => query(q),
        Request::AddManufacturer { input, .. } => manufacturer(input),
        Request::UpdateManufacturer { id, input, .. } => {
            slug("id", id)?;
            manufacturer(input)
        }
        Request::RemoveManufacturer { id, .. }
        | Request::SetManufacturerAllowed { id, .. }
        | Request::SetRuleEnabled { id, .. } => slug("id", id),
        Request::UpdateSettings { settings: s } => settings(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustward_core::catalog::{BrandIdentifier, Verification};

    fn input(name: &str) -> ManufacturerInput {
        ManufacturerInput {
            id: None,
            display_name: name.into(),
            aliases: vec![],
            identifiers: vec![],
            notes: None,
        }
    }

    #[test]
    fn rejects_bad_fields() {
        let cases = [
            Request::ExplainDevice {
                device_key: "../etc".into(),
            },
            Request::ListBlocked { limit: 0 },
            Request::ListPolicyChanges { limit: 100_000 },
            Request::ListEvents {
                query: EventQuery {
                    min_severity: Some("debug".into()),
                    ..EventQuery::default()
                },
            },
            Request::ListEvents {
                query: EventQuery {
                    kind: Some("DROP TABLE".into()),
                    ..EventQuery::default()
                },
            },
            Request::ListEvents {
                query: EventQuery {
                    since_ms: Some(10),
                    until_ms: Some(5),
                    ..EventQuery::default()
                },
            },
            Request::RemoveManufacturer {
                id: "Sandisk Corp".into(),
                expected_policy_version: 1,
            },
            Request::AddManufacturer {
                input: input(""),
                allowed: true,
                expected_policy_version: 1,
            },
            Request::AddManufacturer {
                input: input("a\u{0}b"),
                allowed: true,
                expected_policy_version: 1,
            },
            Request::AddManufacturer {
                input: ManufacturerInput {
                    identifiers: vec![BrandIdentifier {
                        kind: IdentifierKind::UsbVid,
                        value: "78".into(),
                        verification: Verification::Unverified,
                        source: "x".into(),
                    }],
                    ..input("Acme")
                },
                allowed: true,
                expected_policy_version: 1,
            },
            Request::UpdateSettings {
                settings: SettingsView {
                    theme: "neon".into(),
                    language: "tr".into(),
                    notifications_enabled: true,
                    audit_retention_days: 365,
                    inventory_refresh_seconds: 30,
                },
            },
        ];
        for c in cases {
            let e = validate_request(&c).unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidRequest, "{c:?}");
        }
    }

    #[test]
    fn accepts_good_fields() {
        for c in [
            Request::ExplainDevice {
                device_key: "0123456789abcdef0123456789ABCDEF".into(),
            },
            Request::ListEvents {
                query: EventQuery {
                    text: Some("sandisk".into()),
                    limit: Some(50),
                    ..EventQuery::default()
                },
            },
            Request::AddManufacturer {
                input: input("TÜBİTAK BİLGEM"),
                allowed: true,
                expected_policy_version: 3,
            },
            Request::SetRuleEnabled {
                id: "tubitak".into(),
                enabled: false,
                expected_policy_version: 3,
            },
        ] {
            validate_request(&c).unwrap();
        }
    }
}
