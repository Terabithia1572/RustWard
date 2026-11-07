//! Privileged-IPC security regression tests (Phase 9A).
//!
//! Every privileged request is sent through the real server pipeline
//! (`rpc::process` / `rpc::serve_connection`: version check, validation,
//! authorization, handler) into a real `AppService` with a file database.
//! Identities are constructed here because the Windows token check in
//! `rustward-ipc::pipe` cannot run on Linux; that part is NOT covered and
//! is listed in docs/WINDOWS-VM-ACCEPTANCE.md (Stage B/C).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustward_app::{AppConfig, AppService, BackendKind, EmptyInventory, default_policy_state};
use rustward_core::catalog::{BrandIdentifier, IdentifierKind, Verification};
use rustward_core::policy_edit::ManufacturerInput;
use rustward_ipc::messages::{
    AccessLevel, EventQuery, ExportFormat, Request, ResponseBody, SettingsView,
};
use rustward_ipc::rpc::{Client, Handler, process, serve_connection, serve_connection_identified};
use rustward_ipc::transport::mock_pair;
use rustward_ipc::{ClientIdentity, ErrorCode, IdentitySource, PROTOCOL_VERSION, RequestEnvelope};
use rustward_storage::{ManualClock, Store};

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "rustward-ipcsec-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn service(dir: &TempDir, clock: Arc<ManualClock>) -> AppService {
    AppService::new(
        Store::open(&dir.0.join("rustward.db"), clock.clone()).unwrap(),
        clock,
        Box::new(EmptyInventory),
        AppConfig {
            backend: BackendKind::WindowsService,
            allow_synthetic: true,
            backup_dir: Some(dir.0.join("backups")),
            database_location: "dev_temp".into(),
            app_version: "test".into(),
        },
        &default_policy_state().unwrap(),
    )
    .unwrap()
}

fn who(account: &str, admin: bool, elevated: bool, channel: AccessLevel) -> ClientIdentity {
    ClientIdentity {
        account: account.into(),
        sid: None,
        is_administrator: admin,
        elevated,
        source: IdentitySource::Test,
        channel_max_access: channel,
    }
}

fn admin() -> ClientIdentity {
    who("PC-01\\secadmin", true, true, AccessLevel::Administrator)
}

fn input(name: &str) -> ManufacturerInput {
    ManufacturerInput {
        id: None,
        display_name: name.into(),
        aliases: vec![],
        identifiers: vec![BrandIdentifier {
            kind: IdentifierKind::InquiryVendor,
            value: "ROGUE".into(),
            verification: Verification::Unverified,
            source: "attack".into(),
        }],
        notes: None,
    }
}

/// One valid sample of every privileged request. The `match` makes adding a
/// privileged request without a test here a compile error.
fn privileged_samples(version: u64) -> Vec<Request> {
    let all = vec![
        Request::PrepareEnforcementSession {
            device_key: "0".repeat(32),
            retroactive: true,
        },
        Request::VerifyEnforcementApplied {
            session_id: "0".repeat(16),
        },
        Request::VerifyEnforcementRollback {
            session_id: "0".repeat(16),
        },
        Request::CancelEnforcementSession {
            session_id: "0".repeat(16),
        },
        Request::AddManufacturer {
            input: input("Rogue Brand"),
            allowed: true,
            expected_policy_version: version,
        },
        Request::UpdateManufacturer {
            id: "sandisk".into(),
            input: input("SanDisk"),
            expected_policy_version: version,
        },
        Request::RemoveManufacturer {
            id: "sandisk".into(),
            expected_policy_version: version,
        },
        Request::SetManufacturerAllowed {
            id: "kingston".into(),
            allowed: true,
            expected_policy_version: version,
        },
        Request::SetRuleEnabled {
            id: "sandisk".into(),
            enabled: false,
            expected_policy_version: version,
        },
        Request::UpdateSettings {
            settings: SettingsView {
                theme: "dark".into(),
                language: "en".into(),
                notifications_enabled: false,
                audit_retention_days: 30,
                inventory_refresh_seconds: 3600,
            },
        },
        Request::ExportEvents {
            query: EventQuery::default(),
            format: ExportFormat::Json,
        },
        Request::ApplyRetention,
        Request::CreateBackup,
        Request::RefreshInventory,
        Request::LoadSyntheticInventory,
        Request::SetWorkstationId {
            workstation_id: "HIJACKED".into(),
            expected_policy_version: version,
        },
        Request::ListBackups,
        Request::PrepareRestore {
            file_name: "rustward-backup-1.db".into(),
        },
        Request::ApplyRestore {
            restore_id: "0123456789abcdef0123456789abcdef".into(),
            expected_policy_version: version,
        },
    ];
    for r in &all {
        assert_eq!(r.access_level(), AccessLevel::Administrator, "{}", r.name());
        match r {
            Request::PrepareEnforcementSession { .. }
            | Request::VerifyEnforcementApplied { .. }
            | Request::VerifyEnforcementRollback { .. }
            | Request::CancelEnforcementSession { .. }
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
            | Request::PrepareRestore { .. }
            | Request::ApplyRestore { .. } => {}
            Request::GetDashboard
            | Request::ListDevices { .. }
            | Request::ListManufacturers
            | Request::ExplainDevice { .. }
            | Request::ListBlocked { .. }
            | Request::ListEvents { .. }
            | Request::ListPolicyChanges { .. }
            | Request::GetDiagnostics
            | Request::GetEnforcementReadiness
            | Request::GetEnforcementObservation
            | Request::GetPolicyChecklist { .. }
            | Request::GetEnforcementSession
            | Request::GetSettings
            | Request::RunSimulation => unreachable!("read-only request in privileged list"),
        }
    }
    all
}

/// Everything an unauthorized request could have changed.
#[derive(Debug, PartialEq)]
struct Fingerprint {
    policy_version: u64,
    workstation_id: String,
    manufacturers: Vec<(String, bool, bool)>,
    settings: SettingsView,
    devices: usize,
    backup_files: usize,
    non_auth_events: usize,
}

fn fingerprint(s: &AppService, dir: &TempDir) -> Fingerprint {
    let id = admin();
    let ResponseBody::Manufacturers(m) = s.handle(&Request::ListManufacturers, &id).unwrap() else {
        panic!()
    };
    let ResponseBody::Settings(settings) = s.handle(&Request::GetSettings, &id).unwrap() else {
        panic!()
    };
    let ResponseBody::Devices(d) = s
        .handle(
            &Request::ListDevices {
                include_absent: true,
            },
            &id,
        )
        .unwrap()
    else {
        panic!()
    };
    let ResponseBody::Events(ev) = s
        .handle(
            &Request::ListEvents {
                query: EventQuery {
                    limit: Some(5000),
                    ..EventQuery::default()
                },
            },
            &id,
        )
        .unwrap()
    else {
        panic!()
    };
    Fingerprint {
        policy_version: m.policy_version,
        workstation_id: m.workstation_id.clone(),
        manufacturers: m
            .manufacturers
            .iter()
            .map(|b| (b.id.clone(), b.allowed, b.enabled))
            .collect(),
        settings,
        devices: d.len(),
        backup_files: std::fs::read_dir(dir.0.join("backups")).map_or(0, |r| r.count()),
        non_auth_events: ev
            .iter()
            .filter(|e| e.kind != "authorization_failed")
            .count(),
    }
}

fn auth_failures(s: &AppService) -> Vec<String> {
    let ResponseBody::Events(ev) = s
        .handle(
            &Request::ListEvents {
                query: EventQuery {
                    kind: Some("authorization_failed".into()),
                    limit: Some(5000),
                    ..EventQuery::default()
                },
            },
            &admin(),
        )
        .unwrap()
    else {
        panic!()
    };
    ev.into_iter().map(|e| e.message).collect()
}

#[test]
fn no_privileged_request_succeeds_without_an_elevated_administrator_on_the_admin_channel() {
    let dir = TempDir::new("matrix");
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = service(&dir, clock.clone());
    let before = fingerprint(&s, &dir);
    let callers = [
        who("PC-01\\operator", false, false, AccessLevel::Administrator),
        who(
            "PC-01\\admin-unelevated",
            true,
            false,
            AccessLevel::Administrator,
        ),
        who(
            "PC-01\\elevated-but-not-admin",
            false,
            true,
            AccessLevel::Administrator,
        ),
        who(
            "PC-01\\admin-on-status-pipe",
            true,
            true,
            AccessLevel::ReadOnly,
        ),
        who(
            "PC-01\\operator-on-status-pipe",
            false,
            false,
            AccessLevel::ReadOnly,
        ),
    ];
    let mut attempts = 0;
    for caller in &callers {
        for request in privileged_samples(before.policy_version) {
            let env = RequestEnvelope {
                version: PROTOCOL_VERSION,
                request_id: attempts,
                request,
            };
            let reply = process(&env, caller, &s);
            let err = reply.result.unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::Unauthorized,
                "{} by {}",
                env.request.name(),
                caller.account
            );
            attempts += 1;
        }
        // Stay below the per-minute audit cap so every attempt is itemised.
        clock.advance(rustward_app::AUTH_AUDIT_WINDOW_MS);
    }
    assert_eq!(fingerprint(&s, &dir), before, "no state changed");
    let failures = auth_failures(&s);
    assert_eq!(failures.len() as u64, attempts, "every refusal is audited");
    for caller in &callers {
        assert!(failures.iter().any(|m| m.contains(&caller.account)));
    }
}

#[test]
fn read_only_requests_work_for_standard_users_and_change_nothing() {
    let dir = TempDir::new("readonly");
    let s = service(&dir, Arc::new(ManualClock::new(1_793_836_800_000)));
    let before = fingerprint(&s, &dir);
    let user = who("PC-01\\operator", false, false, AccessLevel::ReadOnly);
    for r in [
        Request::GetDashboard,
        Request::ListDevices {
            include_absent: true,
        },
        Request::ListManufacturers,
        Request::ListBlocked { limit: 10 },
        Request::ListEvents {
            query: EventQuery::default(),
        },
        Request::ListPolicyChanges { limit: 10 },
        Request::GetDiagnostics,
        Request::GetEnforcementReadiness,
        Request::GetEnforcementObservation,
        Request::GetEnforcementSession,
        Request::GetSettings,
        Request::RunSimulation,
    ] {
        let env = RequestEnvelope {
            version: PROTOCOL_VERSION,
            request_id: 1,
            request: r,
        };
        assert!(
            process(&env, &user, &s).result.is_ok(),
            "{}",
            env.request.name()
        );
    }
    assert_eq!(fingerprint(&s, &dir), before);
}

#[test]
fn replayed_policy_mutations_are_rejected_by_version_checks() {
    let dir = TempDir::new("replay");
    let s = service(&dir, Arc::new(ManualClock::new(1_793_836_800_000)));
    let v = fingerprint(&s, &dir).policy_version;
    for r in [
        Request::SetManufacturerAllowed {
            id: "kingston".into(),
            allowed: true,
            expected_policy_version: v,
        },
        Request::AddManufacturer {
            input: input("Replay Brand"),
            allowed: false,
            expected_policy_version: v,
        },
        Request::SetWorkstationId {
            workstation_id: "PC-07".into(),
            expected_policy_version: v,
        },
        Request::RemoveManufacturer {
            id: "seagate".into(),
            expected_policy_version: v,
        },
    ] {
        let env = RequestEnvelope {
            version: PROTOCOL_VERSION,
            request_id: 5,
            request: r,
        };
        let first = process(&env, &admin(), &s);
        let replay = process(&env, &admin(), &s);
        if env.request.name() == "set_manufacturer_allowed" {
            assert!(first.result.is_ok());
        }
        assert_eq!(
            replay.result.unwrap_err().code,
            ErrorCode::Conflict,
            "replay of {} must not apply twice",
            env.request.name()
        );
    }
    // Exactly one of the four captured requests could apply (they share v).
    assert_eq!(fingerprint(&s, &dir).policy_version, v + 1);
}

#[test]
fn interrupted_connection_applies_a_mutation_at_most_once() {
    let dir = TempDir::new("interrupt");
    let s = Arc::new(service(&dir, Arc::new(ManualClock::new(1_793_836_800_000))));
    let v = fingerprint(&s, &dir).policy_version;
    let request = Request::SetManufacturerAllowed {
        id: "kingston".into(),
        allowed: true,
        expected_policy_version: v,
    };

    // The client sends the request and vanishes before reading the reply.
    let (mut client_end, mut server_end) = mock_pair();
    let server = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || {
            serve_connection(
                &mut server_end,
                &admin(),
                s.as_ref(),
                Duration::from_secs(2),
            )
        })
    };
    let frame = rustward_ipc::frame::encode(&RequestEnvelope {
        version: PROTOCOL_VERSION,
        request_id: 1,
        request: request.clone(),
    })
    .unwrap();
    rustward_ipc::transport::Transport::send(&mut client_end, &frame).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    drop(client_end);
    let end = server.join().unwrap();
    assert!(
        !matches!(end, rustward_ipc::rpc::SessionEnd::ProtocolViolation(_)),
        "{end:?}"
    );

    // A retry on a new connection cannot apply the change a second time.
    let (client_end, mut server_end) = mock_pair();
    let server = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || {
            serve_connection(
                &mut server_end,
                &admin(),
                s.as_ref(),
                Duration::from_secs(2),
            )
        })
    };
    let mut client = Client::new(client_end, Duration::from_secs(2));
    match client.call(request) {
        Err(rustward_ipc::rpc::ClientError::Server(e)) => assert_eq!(e.code, ErrorCode::Conflict),
        other => panic!("{other:?}"),
    }
    drop(client);
    server.join().unwrap();
    assert_eq!(
        fingerprint(&s, &dir).policy_version,
        v + 1,
        "applied exactly once"
    );
}

#[test]
fn duplicate_non_versioned_admin_requests_are_harmless_and_audited() {
    let dir = TempDir::new("dupes");
    let s = service(&dir, Arc::new(ManualClock::new(1_793_836_800_000)));
    let settings = SettingsView {
        theme: "dark".into(),
        language: "tr".into(),
        notifications_enabled: true,
        audit_retention_days: 365,
        inventory_refresh_seconds: 30,
    };
    for _ in 0..2 {
        s.handle(
            &Request::UpdateSettings {
                settings: settings.clone(),
            },
            &admin(),
        )
        .unwrap();
        s.handle(&Request::CreateBackup, &admin()).unwrap();
    }
    let ResponseBody::Settings(now) = s.handle(&Request::GetSettings, &admin()).unwrap() else {
        panic!()
    };
    assert_eq!(now, settings, "settings updates are idempotent");
    let ResponseBody::Backups(b) = s.handle(&Request::ListBackups, &admin()).unwrap() else {
        panic!()
    };
    assert_eq!(b.len(), 2, "each backup is distinct and registered");
}

#[test]
fn malformed_and_unsupported_envelopes_are_refused_without_side_effects() {
    let dir = TempDir::new("malformed");
    let s = service(&dir, Arc::new(ManualClock::new(1_793_836_800_000)));
    let before = fingerprint(&s, &dir);
    let env = RequestEnvelope {
        version: PROTOCOL_VERSION + 1,
        request_id: 1,
        request: Request::RemoveManufacturer {
            id: "sandisk".into(),
            expected_policy_version: before.policy_version,
        },
    };
    assert_eq!(
        process(&env, &admin(), &s).result.unwrap_err().code,
        ErrorCode::VersionMismatch
    );
    for bad in [
        Request::RemoveManufacturer {
            id: "../../etc".into(),
            expected_policy_version: 1,
        },
        Request::SetWorkstationId {
            workstation_id: "PC 01; DROP TABLE".into(),
            expected_policy_version: 1,
        },
        Request::ApplyRestore {
            restore_id: "not-hex".into(),
            expected_policy_version: 1,
        },
    ] {
        let env = RequestEnvelope {
            version: PROTOCOL_VERSION,
            request_id: 2,
            request: bad,
        };
        assert_eq!(
            process(&env, &admin(), &s).result.unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }
    let after = fingerprint(&s, &dir);
    assert_eq!(
        Fingerprint {
            non_auth_events: before.non_auth_events,
            ..after
        },
        before,
        "only audit records were added"
    );
}

#[test]
fn unidentified_callers_are_refused_audited_and_change_nothing() {
    let dir = TempDir::new("unidentified");
    let s = Arc::new(service(&dir, Arc::new(ManualClock::new(1_793_836_800_000))));
    let before = fingerprint(&s, &dir);
    let (client_end, mut server_end) = mock_pair();
    let server = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || {
            let identify = |_: &rustward_ipc::transport::MockEnd| {
                Err(rustward_ipc::transport::TransportError::Io(
                    "ImpersonateNamedPipeClient failed with Win32 error 1368".into(),
                ))
            };
            serve_connection_identified(
                &mut server_end,
                &identify,
                s.as_ref(),
                Duration::from_secs(2),
            )
        })
    };
    let mut client = Client::new(client_end, Duration::from_secs(2));
    let reply = client.call(Request::RemoveManufacturer {
        id: "sandisk".into(),
        expected_policy_version: before.policy_version,
    });
    match reply {
        Err(rustward_ipc::rpc::ClientError::Server(e)) => {
            assert_eq!(e.code, ErrorCode::Unauthorized)
        }
        other => panic!("{other:?}"),
    }
    drop(client);
    server.join().unwrap();
    assert_eq!(fingerprint(&s, &dir), before);
    let failures = auth_failures(&s);
    assert_eq!(failures.len(), 1);
    assert!(
        failures[0].contains("could not be identified"),
        "{}",
        failures[0]
    );
    assert!(failures[0].contains("1368"));
}
