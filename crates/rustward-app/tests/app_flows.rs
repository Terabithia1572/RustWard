//! Integration tests of the application service (Milestone G) on synthetic
//! fixtures and temporary databases. No Windows APIs are exercised.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use rustward_app::{
    AppConfig, AppService, BackendKind, EmptyInventory, FixtureInventory, InventorySource,
    UnavailablePolicySource, default_policy_state,
};
use rustward_core::catalog::{BrandIdentifier, IdentifierKind, Verification};
use rustward_core::device::DeviceSnapshot;
use rustward_core::policy_edit::ManufacturerInput;
use rustward_ipc::messages::{AccessLevel, EventQuery, ExportFormat, Request, ResponseBody};
use rustward_ipc::rpc::Handler;
use rustward_ipc::{ClientIdentity, ErrorCode, IdentitySource};
use rustward_storage::{ManualClock, Store};

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "rustward-app-{tag}-{}-{}",
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

fn admin() -> ClientIdentity {
    ClientIdentity {
        account: "PC-01\\securityadmin".into(),
        sid: None,
        is_administrator: true,
        elevated: true,
        source: IdentitySource::Test,
        channel_max_access: AccessLevel::Administrator,
    }
}

fn config(allow_synthetic: bool, backup_dir: Option<PathBuf>) -> AppConfig {
    AppConfig {
        backend: BackendKind::DevBackend,
        allow_synthetic,
        backup_dir,
        database_location: "dev_temp".into(),
        app_version: "test".into(),
    }
}

fn service_with(
    store: Store,
    clock: Arc<ManualClock>,
    inv: Box<dyn InventorySource>,
    allow_synthetic: bool,
    backup: Option<PathBuf>,
) -> AppService {
    AppService::new(
        store,
        clock,
        inv,
        config(allow_synthetic, backup),
        &default_policy_state().unwrap(),
    )
    .unwrap()
    .with_policy_source(Box::new(UnavailablePolicySource::default()))
}

fn mem_service() -> AppService {
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    service_with(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(EmptyInventory),
        true,
        None,
    )
}

fn call(s: &AppService, r: Request) -> ResponseBody {
    s.handle(&r, &admin())
        .unwrap_or_else(|e| panic!("{r:?} failed: {e}"))
}

fn policy_version(s: &AppService) -> u64 {
    match call(s, Request::ListManufacturers) {
        ResponseBody::Manufacturers(m) => m.policy_version,
        other => panic!("{other:?}"),
    }
}

fn devices(s: &AppService) -> Vec<rustward_ipc::messages::DeviceView> {
    match call(
        s,
        Request::ListDevices {
            include_absent: true,
        },
    ) {
        ResponseBody::Devices(d) => d,
        other => panic!("{other:?}"),
    }
}

fn input(name: &str, vendor: Option<&str>) -> ManufacturerInput {
    ManufacturerInput {
        id: None,
        display_name: name.into(),
        aliases: vec![],
        identifiers: vendor
            .map(|v| BrandIdentifier {
                kind: IdentifierKind::InquiryVendor,
                value: v.into(),
                verification: Verification::Unverified,
                source: "admin entry".into(),
            })
            .into_iter()
            .collect(),
        notes: None,
    }
}

#[test]
fn manufacturer_crud_persists_across_restart() {
    let dir = TempDir::new("crud");
    let db = dir.0.join("rustward.db");
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    {
        let s = service_with(
            Store::open(&db, clock.clone()).unwrap(),
            clock.clone(),
            Box::new(EmptyInventory),
            true,
            None,
        );
        let v = policy_version(&s);
        assert!(matches!(
            call(&s, Request::AddManufacturer { input: input("Acme Storage", Some("ACME")), allowed: true, expected_policy_version: v }),
            ResponseBody::Mutation(m) if m.policy_version == v + 1
        ));
        let mut edited = input("Acme Storage", Some("ACME"));
        edited.aliases = vec!["ACMEDISK".into()];
        call(
            &s,
            Request::UpdateManufacturer {
                id: "acme-storage".into(),
                input: edited,
                expected_policy_version: v + 1,
            },
        );
        call(
            &s,
            Request::RemoveManufacturer {
                id: "seagate".into(),
                expected_policy_version: v + 2,
            },
        );
        call(
            &s,
            Request::SetRuleEnabled {
                id: "tubitak".into(),
                enabled: false,
                expected_policy_version: v + 3,
            },
        );
    }
    // Restart: new service over the same database file.
    let s = service_with(
        Store::open(&db, clock.clone()).unwrap(),
        clock,
        Box::new(EmptyInventory),
        true,
        None,
    );
    let ResponseBody::Manufacturers(m) = call(&s, Request::ListManufacturers) else {
        panic!()
    };
    assert_eq!(m.policy_version, 5);
    let acme = m
        .manufacturers
        .iter()
        .find(|b| b.id == "acme-storage")
        .unwrap();
    assert!(acme.allowed && acme.enabled && acme.enforceable);
    assert_eq!(acme.aliases, ["ACMEDISK"]);
    assert_eq!(
        acme.identifiers[0].vendor_level_ids,
        ["USBSTOR\\DiskACME____", "SCSI\\DiskACME____"]
    );
    assert!(m.manufacturers.iter().all(|b| b.id != "seagate"));
    let tub = m.manufacturers.iter().find(|b| b.id == "tubitak").unwrap();
    assert!(tub.allowed && !tub.enabled);
    let ResponseBody::PolicyChanges(changes) = call(&s, Request::ListPolicyChanges { limit: 10 })
    else {
        panic!()
    };
    assert_eq!(changes.len(), 4);
    assert!(changes.iter().all(|c| c.actor == "PC-01\\securityadmin"));
}

#[test]
fn conflicts_and_invalid_edits_are_reported_with_codes() {
    let s = mem_service();
    let v = policy_version(&s);
    let err = |r: Request| s.handle(&r, &admin()).unwrap_err().code;
    assert_eq!(
        err(Request::AddManufacturer {
            input: input("Hardware-Encrypted Storage", None),
            allowed: true,
            expected_policy_version: v
        }),
        ErrorCode::Conflict
    );
    assert_eq!(
        err(Request::AddManufacturer {
            input: input("Clone", Some("SanDisk")),
            allowed: true,
            expected_policy_version: v
        }),
        ErrorCode::ValidationFailed
    );
    assert_eq!(
        err(Request::AddManufacturer {
            input: input("Generic Co", Some("Generic")),
            allowed: true,
            expected_policy_version: v
        }),
        ErrorCode::ValidationFailed
    );
    assert_eq!(
        err(Request::RemoveManufacturer {
            id: "nope".into(),
            expected_policy_version: v
        }),
        ErrorCode::NotFound
    );
    assert_eq!(
        err(Request::SetManufacturerAllowed {
            id: "sandisk".into(),
            allowed: true,
            expected_policy_version: v
        }),
        ErrorCode::Conflict,
        "no-op"
    );
    assert_eq!(
        err(Request::SetManufacturerAllowed {
            id: "kingston".into(),
            allowed: true,
            expected_policy_version: v + 7
        }),
        ErrorCode::Conflict,
        "stale version"
    );
    assert_eq!(policy_version(&s), v, "nothing changed");
}

#[test]
fn synthetic_inventory_simulation_and_reevaluation() {
    let s = mem_service();
    assert!(matches!(
        call(&s, Request::LoadSyntheticInventory),
        ResponseBody::Done { .. }
    ));
    let devs = devices(&s);
    assert!(devs.iter().all(|d| d.synthetic && !d.enforcement_verified));
    let find = |devs: &[rustward_ipc::messages::DeviceView], p: &str| {
        devs.iter()
            .find(|d| d.display_id.starts_with(p))
            .cloned()
            .unwrap()
    };
    assert_eq!(
        find(&devs, "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&").simulated_decision,
        "allow"
    );
    let kingston = find(&devs, "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0");
    assert_eq!(kingston.simulated_decision, "deny");
    assert_eq!(kingston.enforcement_state, "pending_validation");
    assert!(
        !devs
            .iter()
            .any(|d| d.display_id.contains("E0D55EA573DCF450E97C0B8A")),
        "serials are masked"
    );

    let ResponseBody::Simulation(sim) = call(&s, Request::RunSimulation) else {
        panic!()
    };
    assert!(sim.simulated_deny > 0 && sim.simulated_allow > 0);
    assert_eq!(sim.enforcement_gaps.len(), 3);
    assert!(sim.notice.contains("NOT ACTIVE"));

    let ResponseBody::Explanation(ex) = call(
        &s,
        Request::ExplainDevice {
            device_key: kingston.device_key.clone(),
        },
    ) else {
        panic!()
    };
    assert!(ex.explanation.summary_tr.starts_with("SİMÜLE RET"));

    // Allow Kingston: stored decisions are re-evaluated without new detections.
    let v = policy_version(&s);
    call(
        &s,
        Request::SetManufacturerAllowed {
            id: "kingston".into(),
            allowed: true,
            expected_policy_version: v,
        },
    );
    assert_eq!(
        find(
            &devices(&s),
            "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
        )
        .simulated_decision,
        "allow"
    );

    let ResponseBody::Events(events) = call(
        &s,
        Request::ListEvents {
            query: EventQuery::default(),
        },
    ) else {
        panic!()
    };
    let kinds: Vec<_> = events.iter().map(|e| e.kind.as_str()).collect();
    for k in [
        "backend_started",
        "device_detected",
        "decision_simulated",
        "policy_changed",
        "decisions_reevaluated",
    ] {
        assert!(kinds.contains(&k), "missing {k}");
    }
    assert!(
        events
            .iter()
            .filter(|e| e.kind == "decision_simulated")
            .all(|e| e.simulated && e.message.contains("NOT ACTIVE"))
    );
}

#[test]
fn dashboard_never_claims_protection() {
    let s = mem_service();
    call(&s, Request::LoadSyntheticInventory);
    let ResponseBody::Dashboard(d) = call(&s, Request::GetDashboard) else {
        panic!()
    };
    assert!(!d.protection_verified);
    assert_eq!(d.enforcement_state, "pending_validation");
    assert_eq!(
        d.not_validated_banner.as_deref(),
        Some("Koruma henüz gerçek Windows ortamında doğrulanmadı.")
    );
    assert!(d.synthetic_data_present);
    assert!(!d.recent_denied.is_empty());
    assert_eq!(d.allowed_manufacturers, 2);
    assert!(d.connected_storage > 0);
    assert_eq!(d.service.backend, "dev_backend");
}

#[test]
fn arrivals_and_removals_produce_events_once() {
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let full = FixtureInventory::bundled().unwrap();
    let s = service_with(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock.clone(),
        Box::new(full),
        false,
        None,
    );
    let first = s.refresh_inventory().unwrap();
    assert!(first.arrived > 0);
    let second = s.refresh_inventory().unwrap();
    assert_eq!(
        (second.arrived, second.removed),
        (0, 0),
        "no duplicate detections"
    );
    assert_eq!(
        s.handle(&Request::LoadSyntheticInventory, &admin())
            .unwrap_err()
            .code,
        ErrorCode::NotSupported
    );
}

#[test]
fn removal_is_detected_and_device_marked_absent() {
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let snap = DeviceSnapshot::from_json(rustward_app::inventory::SYNTHETIC_FIXTURE).unwrap();
    struct Seq(Vec<DeviceSnapshot>);
    impl InventorySource for Seq {
        fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
            if self.0.len() > 1 {
                Ok((self.0.remove(0), vec![]))
            } else {
                Ok((self.0[0].clone(), vec![]))
            }
        }
        fn kind(&self) -> &'static str {
            "synthetic"
        }
    }
    let mut without = snap.clone();
    without
        .devices
        .retain(|d| !d.instance_id.contains("Kingston&Prod_DataTraveler_3.0"));
    let s = service_with(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(Seq(vec![snap, without])),
        false,
        None,
    );
    s.refresh_inventory().unwrap();
    let r = s.refresh_inventory().unwrap();
    assert_eq!(r.removed, 1);
    let k = devices(&s)
        .into_iter()
        .find(|d| d.display_id.contains("Kingston&Prod_DataTraveler_3.0"))
        .unwrap();
    assert!(!k.present, "kept as previously detected");
}

#[test]
fn inventory_failures_degrade_health_and_recover() {
    struct Flaky(u32);
    impl InventorySource for Flaky {
        fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
            self.0 += 1;
            if self.0 <= 2 {
                Err("simulated SetupAPI failure".into())
            } else {
                FixtureInventory::bundled()?.collect()
            }
        }
        fn kind(&self) -> &'static str {
            "synthetic"
        }
    }
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = service_with(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(Flaky(0)),
        false,
        None,
    );
    assert_eq!(
        s.refresh_inventory().unwrap_err().code,
        ErrorCode::Unavailable
    );
    assert!(s.refresh_inventory().is_err());
    assert_eq!(s.consecutive_failures(), 2);
    let ResponseBody::Dashboard(d) = call(&s, Request::GetDashboard) else {
        panic!()
    };
    assert_eq!(d.service.state, "degraded");
    s.refresh_inventory().unwrap();
    assert_eq!(s.consecutive_failures(), 0);
}

#[test]
fn export_backup_settings_and_retention() {
    let dir = TempDir::new("export");
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = service_with(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(EmptyInventory),
        true,
        Some(dir.0.join("backups")),
    );
    call(&s, Request::LoadSyntheticInventory);
    let ResponseBody::Export(csv) = call(
        &s,
        Request::ExportEvents {
            query: EventQuery::default(),
            format: ExportFormat::Csv,
        },
    ) else {
        panic!()
    };
    assert!(csv.content.starts_with("id,utc,severity,kind,simulated"));
    assert!(csv.file_name.ends_with(".csv") && csv.count > 0);
    let ResponseBody::Export(json) = call(
        &s,
        Request::ExportEvents {
            query: EventQuery {
                limit: Some(3),
                ..EventQuery::default()
            },
            format: ExportFormat::Json,
        },
    ) else {
        panic!()
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json.content)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let ResponseBody::Done { message, .. } = call(&s, Request::CreateBackup) else {
        panic!()
    };
    assert!(message.starts_with("backup created: rustward-backup-"));
    assert_eq!(std::fs::read_dir(dir.0.join("backups")).unwrap().count(), 1);

    let ResponseBody::Settings(mut st) = call(&s, Request::GetSettings) else {
        panic!()
    };
    st.theme = "dark".into();
    st.audit_retention_days = 90;
    call(
        &s,
        Request::UpdateSettings {
            settings: st.clone(),
        },
    );
    assert_eq!(call(&s, Request::GetSettings), ResponseBody::Settings(st));
    assert!(matches!(
        call(&s, Request::ApplyRetention),
        ResponseBody::Done { .. }
    ));
}

#[test]
fn corrupt_policy_fails_closed_but_diagnostics_still_work() {
    let dir = TempDir::new("corrupt");
    let db = dir.0.join("rustward.db");
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    drop(service_with(
        Store::open(&db, clock.clone()).unwrap(),
        clock.clone(),
        Box::new(EmptyInventory),
        true,
        None,
    ));
    rusqlite_tamper(&db);
    let s = service_with(
        Store::open(&db, clock.clone()).unwrap(),
        clock,
        Box::new(EmptyInventory),
        true,
        None,
    );
    let e = s
        .handle(
            &Request::SetManufacturerAllowed {
                id: "kingston".into(),
                allowed: true,
                expected_policy_version: 1,
            },
            &admin(),
        )
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    let ResponseBody::Diagnostics(d) = call(&s, Request::GetDiagnostics) else {
        panic!()
    };
    assert!(!d.policy.valid);
    assert_eq!(d.enforcement.state, "error");
    assert!(d.database.integrity_ok);
}

fn rusqlite_tamper(db: &std::path::Path) {
    let store = Store::open(db, Arc::new(ManualClock::new(0))).unwrap();
    store
        .connection_for_tests()
        // A privileged attacker drops the guard trigger, then edits the row.
        .execute_batch("DROP TRIGGER policy_states_immutable; UPDATE policy_states SET state_json = replace(state_json, '\"enabled\":true', '\"enabled\":false') WHERE active = 1;")
        .unwrap();
}

#[test]
fn diagnostics_report_pending_native_work_honestly() {
    let s = mem_service();
    call(&s, Request::LoadSyntheticInventory);
    let ResponseBody::Diagnostics(d) = call(&s, Request::GetDiagnostics) else {
        panic!()
    };
    assert!(d.policy.valid);
    assert!(d.database.chain_ok);
    assert_eq!(d.enforcement.state, "pending_validation");
    assert!(!d.enforcement.capabilities.activation_available);
    assert!(d.enforcement.planned_changes > 0);
    assert!(
        d.enforcement
            .preconditions
            .iter()
            .any(|p| p.id == "vm_validation")
    );
    assert!(!d.pending_native_tests.is_empty());
    assert!(!d.windows_adapter.live_inventory_available);
}

fn event_kinds(s: &AppService) -> Vec<String> {
    match call(
        s,
        Request::ListEvents {
            query: EventQuery::default(),
        },
    ) {
        ResponseBody::Events(e) => e.into_iter().map(|e| e.kind).collect(),
        other => panic!("{other:?}"),
    }
}

fn file_service(dir: &TempDir, clock: Arc<ManualClock>) -> AppService {
    service_with(
        Store::open(&dir.0.join("rustward.db"), clock.clone()).unwrap(),
        clock,
        Box::new(EmptyInventory),
        true,
        Some(dir.0.join("backups")),
    )
}

#[test]
fn workstation_id_is_a_versioned_audited_policy_edit() {
    let s = mem_service();
    let v = policy_version(&s);
    let ResponseBody::Mutation(m) = call(
        &s,
        Request::SetWorkstationId {
            workstation_id: "PC-04".into(),
            expected_policy_version: v,
        },
    ) else {
        panic!()
    };
    assert_eq!(m.policy_version, v + 1);
    let ResponseBody::Dashboard(d) = call(&s, Request::GetDashboard) else {
        panic!()
    };
    assert_eq!(d.workstation_id, "PC-04");
    let ResponseBody::PolicyChanges(h) = call(&s, Request::ListPolicyChanges { limit: 5 }) else {
        panic!()
    };
    assert_eq!(h[0].action, "workstation_id_changed");
    // Stale version and no-op edits are refused.
    let stale = s
        .handle(
            &Request::SetWorkstationId {
                workstation_id: "PC-05".into(),
                expected_policy_version: v,
            },
            &admin(),
        )
        .unwrap_err();
    assert_eq!(stale.code, ErrorCode::Conflict);
}

fn prepare(s: &AppService, file: &str) -> rustward_ipc::messages::RestorePreviewView {
    match call(
        s,
        Request::PrepareRestore {
            file_name: file.into(),
        },
    ) {
        ResponseBody::RestorePreview(p) => p,
        other => panic!("{other:?}"),
    }
}

fn kinds_of(s: &AppService, kind: &str) -> Vec<rustward_ipc::messages::EventView> {
    match call(
        s,
        Request::ListEvents {
            query: EventQuery {
                kind: Some(kind.into()),
                ..EventQuery::default()
            },
        },
    ) {
        ResponseBody::Events(e) => e,
        other => panic!("{other:?}"),
    }
}

fn create_backup(s: &AppService) -> String {
    let ResponseBody::Done { message, .. } = call(s, Request::CreateBackup) else {
        panic!()
    };
    message.trim_start_matches("backup created: ").to_owned()
}

#[test]
fn restore_is_two_step_and_never_rolls_back_versions_history_or_audit() {
    let dir = TempDir::new("restore");
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = file_service(&dir, clock.clone());
    let backup = create_backup(&s);
    let v1 = policy_version(&s);
    clock.advance(1_000);
    call(
        &s,
        Request::SetManufacturerAllowed {
            id: "kingston".into(),
            allowed: true,
            expected_policy_version: v1,
        },
    );
    let events_before = event_kinds(&s).len();

    // Step 1: preview only.
    let p = prepare(&s, &backup);
    assert_eq!(p.backup_policy_version, v1);
    assert_eq!(p.current_policy_version, v1 + 1);
    assert_eq!(p.resulting_policy_version, v1 + 2);
    assert!(
        p.changes
            .iter()
            .any(|c| c == "would no longer be allowed: kingston"),
        "{:?}",
        p.changes
    );
    assert!(p.notice.contains("Nothing has been changed yet"));
    assert_eq!(policy_version(&s), v1 + 1, "prepare changes no policy");
    assert_eq!(kinds_of(&s, "restore_prepared").len(), 1);

    // Step 2: apply as a NEW version.
    clock.advance(1_000);
    let ResponseBody::Mutation(m) = call(
        &s,
        Request::ApplyRestore {
            restore_id: p.restore_id.clone(),
            expected_policy_version: p.current_policy_version,
        },
    ) else {
        panic!()
    };
    assert_eq!(m.policy_version, v1 + 2, "versions only increase");
    assert!(m.summary.contains("rustward-pre-restore-"));
    let ResponseBody::Manufacturers(mv) = call(&s, Request::ListManufacturers) else {
        panic!()
    };
    assert!(
        !mv.manufacturers
            .iter()
            .find(|b| b.id == "kingston")
            .unwrap()
            .allowed
    );
    // History and audit are kept and extended, never replaced.
    let ResponseBody::PolicyChanges(h) = call(&s, Request::ListPolicyChanges { limit: 10 }) else {
        panic!()
    };
    assert_eq!(h[0].action, "policy_restored");
    assert!(
        h.iter().any(|c| c.action == "allowlist_changed"),
        "earlier change still listed"
    );
    assert!(event_kinds(&s).len() > events_before);
    let restored = kinds_of(&s, "policy_restored");
    assert_eq!(restored.len(), 1);
    assert!(restored[0].message.contains("PC-01\\securityadmin"));
    let ResponseBody::Diagnostics(d) = call(&s, Request::GetDiagnostics) else {
        panic!()
    };
    assert!(d.database.chain_ok, "hash chain intact after restore");

    // The pre-restore backup is registered and can itself be restored.
    let ResponseBody::Backups(list) = call(&s, Request::ListBackups) else {
        panic!()
    };
    let pre = list.iter().find(|b| b.kind == "pre_restore").unwrap();
    assert!(pre.file_present && pre.policy_version == v1 + 1 && !pre.sha256.is_empty());
    let p2 = prepare(&s, &pre.file_name.clone());
    call(
        &s,
        Request::ApplyRestore {
            restore_id: p2.restore_id,
            expected_policy_version: p2.current_policy_version,
        },
    );
    let ResponseBody::Manufacturers(mv) = call(&s, Request::ListManufacturers) else {
        panic!()
    };
    assert!(
        mv.manufacturers
            .iter()
            .find(|b| b.id == "kingston")
            .unwrap()
            .allowed,
        "restore undone"
    );
    assert_eq!(policy_version(&s), v1 + 3);
}

#[test]
fn prepared_restores_are_single_use_bound_to_the_admin_and_expire() {
    let dir = TempDir::new("restore-guard");
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = file_service(&dir, clock.clone());
    let backup = create_backup(&s);
    let apply = |id: &str, v: u64, who: &ClientIdentity| {
        s.handle(
            &Request::ApplyRestore {
                restore_id: id.into(),
                expected_policy_version: v,
            },
            who,
        )
    };

    // Another administrator cannot use someone else's preview.
    let p = prepare(&s, &backup);
    let other = ClientIdentity {
        account: "PC-01\\otheradmin".into(),
        ..admin()
    };
    assert_eq!(
        apply(&p.restore_id, p.current_policy_version, &other)
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
    // The owner still can, exactly once (replay is refused).
    assert!(apply(&p.restore_id, p.current_policy_version, &admin()).is_ok());
    let replay = apply(&p.restore_id, p.current_policy_version, &admin()).unwrap_err();
    assert_eq!(replay.code, ErrorCode::NotFound);

    // Stale version: refused, preview consumed, nothing changed.
    let v = policy_version(&s);
    let p = prepare(&s, &backup);
    assert_eq!(
        apply(&p.restore_id, v - 1, &admin()).unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(policy_version(&s), v);
    assert_eq!(
        apply(&p.restore_id, v, &admin()).unwrap_err().code,
        ErrorCode::NotFound
    );

    // Expired preview.
    let p = prepare(&s, &backup);
    clock.advance(rustward_app::RESTORE_PREVIEW_TTL_MS + 1);
    assert_eq!(
        apply(&p.restore_id, v, &admin()).unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(policy_version(&s), v);

    let failures = kinds_of(&s, "restore_failed");
    let reasons: Vec<String> = failures.iter().map(|e| e.message.clone()).collect();
    for r in [
        "different_administrator",
        "no_prepared_restore",
        "conflict",
        "preview_expired",
    ] {
        assert!(
            reasons.iter().any(|m| m.contains(r)),
            "missing {r} in {reasons:?}"
        );
    }
}

#[test]
fn foreign_altered_and_traversal_restores_are_refused_and_audited() {
    use rustward_ipc::rpc::process;
    use rustward_ipc::{PROTOCOL_VERSION, RequestEnvelope};
    let dir = TempDir::new("restore-bad");
    let s = file_service(&dir, Arc::new(ManualClock::new(1_793_836_800_000)));
    let v = policy_version(&s);
    let backup = create_backup(&s);
    let err = |r: Request| s.handle(&r, &admin()).unwrap_err();

    assert_eq!(
        err(Request::PrepareRestore {
            file_name: "rustward-backup-42.db".into()
        })
        .code,
        ErrorCode::ValidationFailed
    );
    // A copy dropped into the directory under a new name is not registered.
    std::fs::copy(
        dir.0.join("backups").join(&backup),
        dir.0.join("backups").join("rustward-backup-7.db"),
    )
    .unwrap();
    let e = err(Request::PrepareRestore {
        file_name: "rustward-backup-7.db".into(),
    });
    assert!(e.message.contains("not_registered"), "{}", e.message);
    // Altered content.
    let path = dir.0.join("backups").join(&backup);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[100] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();
    assert!(
        err(Request::PrepareRestore {
            file_name: backup.clone()
        })
        .message
        .contains("hash_mismatch")
    );
    // Path traversal never reaches the handler but is audited.
    let env = RequestEnvelope {
        version: PROTOCOL_VERSION,
        request_id: 9,
        request: Request::PrepareRestore {
            file_name: "..\\..\\Windows\\System32\\config\\SAM".into(),
        },
    };
    let reply = process(&env, &admin(), &s);
    assert_eq!(reply.result.unwrap_err().code, ErrorCode::InvalidRequest);
    assert_eq!(policy_version(&s), v, "nothing applied");
    let reasons: Vec<String> = kinds_of(&s, "restore_failed")
        .into_iter()
        .map(|e| e.message)
        .collect();
    for r in ["not_registered", "hash_mismatch", "invalid_request"] {
        assert!(
            reasons.iter().any(|m| m.contains(r)),
            "missing {r} in {reasons:?}"
        );
    }
    assert!(reasons.iter().any(|m| m.contains("SAM")));
}

#[test]
fn backups_are_unavailable_without_a_backup_directory() {
    let s = mem_service();
    for r in [Request::ListBackups, Request::CreateBackup] {
        assert_eq!(
            s.handle(&r, &admin()).unwrap_err().code,
            ErrorCode::NotSupported
        );
    }
}

#[test]
fn backup_creation_is_audited() {
    let dir = TempDir::new("backup-audit");
    let s = file_service(&dir, Arc::new(ManualClock::new(1_793_836_800_000)));
    call(&s, Request::CreateBackup);
    assert_eq!(event_kinds(&s)[0], "backup_created");
}

#[test]
fn refused_privileged_requests_are_audited_and_rate_limited() {
    use rustward_ipc::rpc::process;
    use rustward_ipc::{PROTOCOL_VERSION, RequestEnvelope};
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = service_with(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock.clone(),
        Box::new(EmptyInventory),
        true,
        None,
    );
    let user = ClientIdentity {
        account: "PC-01\\operator".into(),
        sid: None,
        is_administrator: false,
        elevated: false,
        source: IdentitySource::Test,
        channel_max_access: AccessLevel::Administrator,
    };
    let env = RequestEnvelope {
        version: PROTOCOL_VERSION,
        request_id: 1,
        request: Request::RemoveManufacturer {
            id: "sandisk".into(),
            expected_policy_version: 1,
        },
    };
    for _ in 0..(rustward_app::AUTH_AUDIT_LIMIT + 15) {
        assert!(process(&env, &user, &s).result.is_err());
    }
    let count = |s: &AppService| {
        event_kinds(s)
            .iter()
            .filter(|k| *k == "authorization_failed")
            .count()
    };
    assert_eq!(
        count(&s),
        rustward_app::AUTH_AUDIT_LIMIT as usize,
        "flood is capped"
    );
    clock.advance(rustward_app::AUTH_AUDIT_WINDOW_MS);
    let _ = process(&env, &user, &s);
    let ResponseBody::Events(ev) = call(
        &s,
        Request::ListEvents {
            query: EventQuery {
                kind: Some("authorization_failed".into()),
                ..EventQuery::default()
            },
        },
    ) else {
        panic!()
    };
    assert!(
        ev[0].message.contains("15 earlier refusals"),
        "{}",
        ev[0].message
    );
    assert!(ev[0].message.contains("PC-01\\operator"));
    // The refused request had no effect.
    assert!(policy_version(&s) >= 1);
    let ResponseBody::Manufacturers(m) = call(&s, Request::ListManufacturers) else {
        panic!()
    };
    assert!(m.manufacturers.iter().any(|b| b.id == "sandisk"));
}

#[test]
fn event_observer_mirrors_events_and_is_reported_in_diagnostics() {
    use rustward_storage::{EventObserver, SecurityEvent};
    #[derive(Default)]
    struct Sink(std::sync::Mutex<Vec<String>>);
    impl EventObserver for Sink {
        fn on_event(&self, e: &SecurityEvent) -> Result<(), String> {
            self.0.lock().unwrap().push(e.kind.clone());
            Ok(())
        }
    }
    let s = mem_service();
    let sink = Arc::new(Sink::default());
    s.set_event_observer(sink.clone()).unwrap();
    call(&s, Request::LoadSyntheticInventory);
    let mirrored = sink.0.lock().unwrap().clone();
    assert!(mirrored.contains(&"decision_simulated".to_owned()));
    let ResponseBody::Diagnostics(d) = call(&s, Request::GetDiagnostics) else {
        panic!()
    };
    assert!(d.event_log.attached);
    assert_eq!(d.event_log.delivered as usize, mirrored.len());
    assert_eq!(d.event_log.failures, 0);
}

#[test]
fn event_log_outage_is_reported_as_pending_and_recovers_in_order() {
    use rustward_storage::{EventObserver, SecurityEvent};
    use std::sync::atomic::{AtomicBool, Ordering};
    #[derive(Default)]
    struct Sink {
        seen: std::sync::Mutex<Vec<i64>>,
        down: AtomicBool,
    }
    impl EventObserver for Sink {
        fn on_event(&self, e: &SecurityEvent) -> Result<(), String> {
            if self.down.load(Ordering::SeqCst) {
                return Err("RPC server unavailable".into());
            }
            self.seen.lock().unwrap().push(e.id);
            Ok(())
        }
    }
    let s = mem_service();
    let sink = Arc::new(Sink::default());
    s.set_event_observer(sink.clone()).unwrap();
    sink.down.store(true, Ordering::SeqCst);
    call(&s, Request::LoadSyntheticInventory);
    let ResponseBody::Diagnostics(d) = call(&s, Request::GetDiagnostics) else {
        panic!()
    };
    assert!(
        d.event_log.pending > 0,
        "outage is visible, nothing dropped"
    );
    sink.down.store(false, Ordering::SeqCst);
    s.retry_event_mirror();
    let ResponseBody::Diagnostics(d) = call(&s, Request::GetDiagnostics) else {
        panic!()
    };
    assert_eq!(d.event_log.pending, 0);
    let ids = sink.seen.lock().unwrap().clone();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "in order, once");
}

#[test]
fn truncated_audit_chain_is_reported_and_checkpointed() {
    let dir = TempDir::new("truncated");
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = file_service(&dir, clock.clone());
    call(&s, Request::LoadSyntheticInventory);
    let cp = s.record_audit_checkpoint().unwrap();
    assert_eq!(cp.chain, "intact");
    drop(s);
    {
        let store = Store::open(&dir.0.join("rustward.db"), clock.clone()).unwrap();
        store
            .connection_for_tests()
            .execute_batch(
                "DROP TRIGGER security_events_retention_only_delete;
                 DELETE FROM security_events WHERE id >= (SELECT MAX(id) - 2 FROM security_events);",
            )
            .unwrap();
    }
    let s = file_service(&dir, clock);
    let ResponseBody::Diagnostics(d) = call(&s, Request::GetDiagnostics) else {
        panic!()
    };
    // Restarting appended new events onto the remaining head, so the chain
    // hashes verify; the id gap still reveals the removal.
    assert!(!d.database.chain_ok);
    assert!(
        d.database.chain_status.starts_with("EVENTS MISSING"),
        "{}",
        d.database.chain_status
    );
    let cp = s.record_audit_checkpoint().unwrap();
    assert_eq!(cp.chain, "missing");
}

#[test]
fn enforcement_readiness_is_read_only_and_reports_inspection_and_assessment() {
    use rustward_app::StaticPolicySource;
    use rustward_enforcement::device_install::RESTRICTIONS_KEY;
    use rustward_enforcement::policy_inspect::CapturedPolicy;
    use rustward_enforcement::policy_state::{PolicyConflict, PolicySnapshot, RegData};

    // Without a source that works (Linux), the inspection is reported missing.
    let plain = mem_service();
    call(&plain, Request::LoadSyntheticInventory);
    let ResponseBody::EnforcementReadiness(v) = call(&plain, Request::GetEnforcementReadiness)
    else {
        panic!()
    };
    assert!(v.inspection.is_none());
    assert_eq!(v.inspection_source, "unavailable");
    assert!(v.inspection_error.is_some());

    let captured = CapturedPolicy {
        key_present: true,
        values: PolicySnapshot::default().with(
            RESTRICTIONS_KEY,
            "DenyUnspecified",
            RegData::Dword(1),
        ),
        ..CapturedPolicy::default()
    };
    let s = mem_service().with_policy_source(Box::new(StaticPolicySource(captured)));
    call(&s, Request::LoadSyntheticInventory);
    let version = policy_version(&s);
    let before = event_kinds(&s);
    let ResponseBody::EnforcementReadiness(v) = call(&s, Request::GetEnforcementReadiness) else {
        panic!()
    };
    // Real status, never inferred from configuration.
    assert!(!v.actual_enforcement.verified_protection);
    assert!(!v.actual_enforcement.activation_available);
    assert_eq!(v.inspection_source, "fixture");
    assert!(
        v.conflicts
            .contains(&PolicyConflict::ExistingDenyUnspecified)
    );
    assert!(
        v.gates
            .iter()
            .any(|g| g.code == "existing_policy_compatible"
                && g.status == rustward_enforcement::PreconditionStatus::NotMet)
    );
    assert!(v.gates.iter().any(|g| g.code == "administrator_authorized"
        && g.status == rustward_enforcement::PreconditionStatus::Met));
    assert!(v.recovery.rollback_modelled_exact);
    assert!(v.installed.summary.denied_but_installed > 0);
    assert!(v.installed.sanitized);
    // Reading changed nothing: no policy version, no audit event.
    assert_eq!(policy_version(&s), version);
    assert_eq!(event_kinds(&s), before);
}

#[cfg(windows)]
#[test]
fn live_policy_source_reads_windows_registry_read_only_without_mutating_anything() {
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = AppService::new(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(EmptyInventory),
        config(true, None),
        &default_policy_state().unwrap(),
    )
    .unwrap();
    call(&s, Request::LoadSyntheticInventory);
    let version = policy_version(&s);
    let before = event_kinds(&s);
    let ResponseBody::EnforcementReadiness(v) = call(&s, Request::GetEnforcementReadiness) else {
        panic!()
    };
    assert_eq!(v.inspection_source, "windows_registry_read_only");
    assert!(v.inspection.is_some());
    assert!(v.inspection_error.is_none());
    assert!(!v.actual_enforcement.activation_available);
    assert_eq!(policy_version(&s), version);
    assert_eq!(event_kinds(&s), before);
}

#[test]
fn denylist_matched_brand_conflicting_vid_and_deduplicated_warnings() {
    use rustward_core::device::{DeviceRecord, SNAPSHOT_SCHEMA_VERSION, SnapshotSource};
    use std::collections::HashSet;

    struct CustomInv(DeviceSnapshot);
    impl InventorySource for CustomInv {
        fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
            Ok((self.0.clone(), vec![]))
        }
        fn kind(&self) -> &'static str {
            "synthetic"
        }
    }

    let snap = DeviceSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::Synthetic {
            description: "denylist and conflict check".into(),
        },
        devices: vec![
            DeviceRecord {
                instance_id: "USB\\VID_0951&PID_1666\\K001".into(),
                hardware_ids: vec!["USB\\VID_0951&PID_1666".into()],
                class_name: Some("USB".into()),
                enumerator: Some("USB".into()),
                service: Some("USBSTOR".into()),
                present: Some(true),
                ..DeviceRecord::default()
            },
            DeviceRecord {
                instance_id: "USBSTOR\\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP\\K001&0"
                    .into(),
                hardware_ids: vec![
                    "USBSTOR\\DiskKingstonDataTraveler_3.0PMAP".into(),
                    "USBSTOR\\DiskKingstonDataTraveler_3.0".into(),
                    "USBSTOR\\DiskKingston".into(),
                ],
                class_guid: Some("{4d36e967-e325-11ce-bfc1-08002be10318}".into()),
                class_name: Some("DiskDrive".into()),
                enumerator: Some("USBSTOR".into()),
                service: Some("disk".into()),
                parent_instance_id: Some("USB\\VID_0951&PID_1666\\K001".into()),
                present: Some(true),
                ..DeviceRecord::default()
            },
            DeviceRecord {
                instance_id: "USB\\VID_0951&PID_9999\\SPOOFK1".into(),
                hardware_ids: vec!["USB\\VID_0951&PID_9999".into()],
                class_name: Some("USB".into()),
                enumerator: Some("USB".into()),
                service: Some("USBSTOR".into()),
                present: Some(true),
                ..DeviceRecord::default()
            },
            DeviceRecord {
                instance_id: "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\\SPOOFK1&0".into(),
                hardware_ids: vec![
                    "USBSTOR\\DiskSanDisk_Ultra___________1.00".into(),
                    "USBSTOR\\DiskSanDisk_Ultra___________".into(),
                    "USBSTOR\\DiskSanDisk_".into(),
                ],
                class_guid: Some("{4d36e967-e325-11ce-bfc1-08002be10318}".into()),
                class_name: Some("DiskDrive".into()),
                enumerator: Some("USBSTOR".into()),
                service: Some("disk".into()),
                parent_instance_id: Some("USB\\VID_0951&PID_9999\\SPOOFK1".into()),
                present: Some(true),
                ..DeviceRecord::default()
            },
        ],
    };

    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let s = service_with(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(CustomInv(snap)),
        true,
        None,
    );
    call(&s, Request::RefreshInventory);

    let devs = devices(&s);
    let kingston = devs
        .iter()
        .find(|d| d.usb_vid_pid.as_deref() == Some("0951:1666"))
        .unwrap();
    assert_eq!(kingston.simulated_decision, "deny");
    assert_eq!(kingston.reason, "brand_denied");
    assert_eq!(kingston.matched_brand.as_deref(), Some("kingston"));

    let conflict = devs
        .iter()
        .find(|d| d.usb_vid_pid.as_deref() == Some("0951:9999"))
        .unwrap();
    assert_eq!(conflict.simulated_decision, "deny");
    assert_eq!(conflict.reason, "conflicting_identifiers");
    assert_eq!(conflict.matched_brand, None);

    let ResponseBody::Explanation(exp) = call(
        &s,
        Request::ExplainDevice {
            device_key: conflict.device_key.clone(),
        },
    ) else {
        panic!()
    };
    assert!(
        exp.explanation.summary_tr.contains("Kimlik çelişkisi"),
        "{}",
        exp.explanation.summary_tr
    );
    assert!(!exp.explanation.summary_tr.contains("[çevrilmedi]"));

    let ResponseBody::Manufacturers(m) = call(&s, Request::ListManufacturers) else {
        panic!()
    };
    let unique_tr: HashSet<&String> = m.warnings_tr.iter().collect();
    assert_eq!(
        unique_tr.len(),
        m.warnings_tr.len(),
        "manufacturer warnings_tr must not contain duplicate entries: {:?}",
        m.warnings_tr
    );
    let ResponseBody::Diagnostics(diag) = call(&s, Request::GetDiagnostics) else {
        panic!()
    };
    let unique_diag_tr: HashSet<&String> = diag.policy.warnings_tr.iter().collect();
    assert_eq!(
        unique_diag_tr.len(),
        diag.policy.warnings_tr.len(),
        "diagnostics warnings_tr must not contain duplicate entries: {:?}",
        diag.policy.warnings_tr
    );
}
