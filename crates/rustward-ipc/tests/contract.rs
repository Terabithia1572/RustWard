//! Golden contract test: the request names and access levels that the
//! TypeScript client relies on (`apps/rustward-desktop/src/api/types.ts`).
//!
//! Regenerate with `RUSTWARD_BLESS=1 cargo test -p rustward-ipc --test contract`
//! after an intentional protocol change; the frontend test then fails until the
//! TypeScript mirror is updated too.

use rustward_core::policy_edit::ManufacturerInput;
use rustward_ipc::PROTOCOL_VERSION;
use rustward_ipc::messages::{AccessLevel, EventQuery, ExportFormat, Request, SettingsView};
use serde_json::{Value, json};

fn input() -> ManufacturerInput {
    ManufacturerInput {
        id: None,
        display_name: "X".into(),
        aliases: vec![],
        identifiers: vec![],
        notes: None,
    }
}

fn settings() -> SettingsView {
    SettingsView {
        theme: "system".into(),
        language: "tr".into(),
        notifications_enabled: true,
        audit_retention_days: 365,
        inventory_refresh_seconds: 30,
    }
}

/// One sample of every request. The `match` below makes adding a variant
/// without updating this list a compile error.
fn all_requests() -> Vec<Request> {
    let all = vec![
        Request::GetDashboard,
        Request::ListDevices {
            include_absent: true,
        },
        Request::ListManufacturers,
        Request::ExplainDevice {
            device_key: "k".into(),
        },
        Request::ListBlocked { limit: 1 },
        Request::ListEvents {
            query: EventQuery::default(),
        },
        Request::ListPolicyChanges { limit: 1 },
        Request::GetDiagnostics,
        Request::GetSettings,
        Request::RunSimulation,
        Request::AddManufacturer {
            input: input(),
            allowed: true,
            expected_policy_version: 1,
        },
        Request::UpdateManufacturer {
            id: "x".into(),
            input: input(),
            expected_policy_version: 1,
        },
        Request::RemoveManufacturer {
            id: "x".into(),
            expected_policy_version: 1,
        },
        Request::SetManufacturerAllowed {
            id: "x".into(),
            allowed: true,
            expected_policy_version: 1,
        },
        Request::SetRuleEnabled {
            id: "x".into(),
            enabled: true,
            expected_policy_version: 1,
        },
        Request::UpdateSettings {
            settings: settings(),
        },
        Request::ExportEvents {
            query: EventQuery::default(),
            format: ExportFormat::Csv,
        },
        Request::ApplyRetention,
        Request::CreateBackup,
        Request::RefreshInventory,
        Request::LoadSyntheticInventory,
        Request::SetWorkstationId {
            workstation_id: "PC-02".into(),
            expected_policy_version: 1,
        },
        Request::ListBackups,
        Request::RestoreBackup {
            file_name: "rustward-backup-1.db".into(),
        },
    ];
    for r in &all {
        // Exhaustiveness guard.
        match r {
            Request::GetDashboard
            | Request::ListDevices { .. }
            | Request::ListManufacturers
            | Request::ExplainDevice { .. }
            | Request::ListBlocked { .. }
            | Request::ListEvents { .. }
            | Request::ListPolicyChanges { .. }
            | Request::GetDiagnostics
            | Request::GetSettings
            | Request::RunSimulation
            | Request::AddManufacturer { .. }
            | Request::UpdateManufacturer { .. }
            | Request::RemoveManufacturer { .. }
            | Request::SetManufacturerAllowed { .. }
            | Request::SetRuleEnabled { .. }
            | Request::UpdateSettings { .. }
            | Request::ExportEvents { .. }
            | Request::ApplyRetention
            | Request::CreateBackup
            | Request::RefreshInventory
            | Request::LoadSyntheticInventory
            | Request::SetWorkstationId { .. }
            | Request::ListBackups
            | Request::RestoreBackup { .. } => {}
        }
    }
    all
}

fn contract() -> Value {
    let requests: Vec<Value> = all_requests()
        .iter()
        .map(|r| {
            let access = match r.access_level() {
                AccessLevel::ReadOnly => "read_only",
                AccessLevel::Administrator => "administrator",
            };
            json!({ "type": r.name(), "access": access })
        })
        .collect();
    json!({ "protocol_version": PROTOCOL_VERSION, "requests": requests })
}

#[test]
fn request_contract_matches_golden_file() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contract/request-types.json");
    let mut rendered = serde_json::to_string_pretty(&contract()).unwrap();
    rendered.push('\n');
    if std::env::var_os("RUSTWARD_BLESS").is_some() {
        std::fs::write(&path, &rendered).unwrap();
    }
    let golden = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        golden.replace("\r\n", "\n"),
        rendered,
        "IPC contract changed; re-bless and update the TypeScript mirror"
    );
}

#[test]
fn every_request_round_trips() {
    for r in all_requests() {
        let s = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }
}

#[test]
fn names_are_unique_snake_case() {
    let names: Vec<String> = all_requests().iter().map(Request::name).collect();
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
    assert!(
        names
            .iter()
            .all(|n| n.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
    );
}
