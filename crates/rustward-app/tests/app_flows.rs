//! Integration tests of the application service (Milestone G) on synthetic
//! fixtures and temporary databases. No Windows APIs are exercised.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use rustward_app::{
    AppConfig, AppService, BackendKind, EmptyInventory, FixtureInventory, InventorySource,
    default_policy_state,
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
            call(&s, Request::AddManufacturer { input: input("Western Digital", Some("WD")), allowed: true, expected_policy_version: v }),
            ResponseBody::Mutation(m) if m.policy_version == v + 1
        ));
        let mut edited = input("Western Digital", Some("WD"));
        edited.aliases = vec!["WDC".into()];
        call(
            &s,
            Request::UpdateManufacturer {
                id: "western-digital".into(),
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
    let wd = m
        .manufacturers
        .iter()
        .find(|b| b.id == "western-digital")
        .unwrap();
    assert!(wd.allowed && wd.enabled && wd.enforceable);
    assert_eq!(wd.aliases, ["WDC"]);
    assert_eq!(
        wd.identifiers[0].vendor_level_ids,
        ["USBSTOR\\DiskWD______", "SCSI\\DiskWD______"]
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
            input: input("Tübitak Bilgem", None),
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

    let ResponseBody::Done { message } = call(&s, Request::CreateBackup) else {
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
        .execute("UPDATE policy_states SET state_json = replace(state_json, '\"enabled\":true', '\"enabled\":false') WHERE active = 1", [])
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
