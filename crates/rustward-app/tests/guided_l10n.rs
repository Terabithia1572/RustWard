//! Turkish localization coverage and the administrator-guided enforcement
//! session, through the application with test doubles fed with the
//! identifiers and states observed in the Windows 10 test VM.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use rustward_app::l10n::{self, UNTRANSLATED};
use rustward_app::{
    AppConfig, AppService, BackendKind, InventorySource, PolicySource, default_policy_state,
};
use rustward_core::device::DeviceSnapshot;
use rustward_enforcement::device_install::RESTRICTIONS_KEY;
use rustward_enforcement::policy_inspect::CapturedPolicy;
use rustward_enforcement::policy_state::{PolicySnapshot, RegData};
use rustward_ipc::messages::{
    AccessLevel, EnforcementSessionView, EventQuery, Request, ResponseBody,
};
use rustward_ipc::rpc::process;
use rustward_ipc::{
    ClientIdentity, ErrorCode, IdentitySource, IpcError, PROTOCOL_VERSION, RequestEnvelope,
};
use rustward_storage::{ManualClock, SecurityEvent, Severity, Store};

const OBSERVED: &str = include_str!("../../../tests/fixtures/vm-observed-usb-2026-11-07.json");
const KINGSTON_ID: &str = "USBSTOR\\DiskKingstonDataTraveler_3.0____";

#[derive(Clone)]
struct Inv(Arc<Mutex<DeviceSnapshot>>);
impl InventorySource for Inv {
    fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
        Ok((self.0.lock().unwrap().clone(), vec![]))
    }
    fn kind(&self) -> &'static str {
        "live"
    }
}

#[derive(Clone)]
struct Pol(Arc<Mutex<PolicySnapshot>>);
impl PolicySource for Pol {
    fn capture(&self, now_ms: i64) -> Result<CapturedPolicy, String> {
        let values = self.0.lock().unwrap().clone();
        Ok(CapturedPolicy {
            captured_ms: now_ms,
            key_present: !values.values.is_empty(),
            values,
            ..CapturedPolicy::default()
        })
    }
    fn name(&self) -> &'static str {
        "test_double"
    }
}

fn who(admin: bool) -> ClientIdentity {
    ClientIdentity {
        account: "PC-01\\yonetici".into(),
        sid: None,
        is_administrator: admin,
        elevated: admin,
        source: IdentitySource::Test,
        channel_max_access: if admin {
            AccessLevel::Administrator
        } else {
            AccessLevel::ReadOnly
        },
    }
}

struct Rig {
    s: AppService,
    inv: Inv,
    pol: Pol,
}

fn rig() -> Rig {
    let clock = Arc::new(ManualClock::new(1_794_050_000_000));
    let inv = Inv(Arc::new(Mutex::new(
        DeviceSnapshot::from_json(OBSERVED).unwrap(),
    )));
    let pol = Pol(Arc::new(Mutex::new(PolicySnapshot::default())));
    let s = AppService::new(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(inv.clone()),
        AppConfig {
            backend: BackendKind::WindowsService,
            allow_synthetic: true,
            backup_dir: None,
            database_location: "dev_temp".into(),
            app_version: "test".into(),
        },
        &default_policy_state().unwrap(),
    )
    .unwrap()
    .with_policy_source(Box::new(pol.clone()));
    Rig { s, inv, pol }
}

impl Rig {
    /// Through the real request pipeline (validation, authorization,
    /// localization).
    fn call(&self, r: Request, admin: bool) -> Result<ResponseBody, IpcError> {
        process(
            &RequestEnvelope {
                version: PROTOCOL_VERSION,
                request_id: 1,
                request: r,
                auth_token: None,
            },
            &who(admin),
            &self.s,
        )
        .result
    }
    fn ok(&self, r: Request) -> ResponseBody {
        self.call(r, true).unwrap()
    }
    fn session(&self, r: Request, admin: bool) -> Result<EnforcementSessionView, IpcError> {
        match self.call(r, admin)? {
            ResponseBody::EnforcementSession(v) => Ok(*v),
            other => panic!("{other:?}"),
        }
    }
    fn kingston(&self, problem: Option<u32>) {
        let mut s = self.inv.0.lock().unwrap();
        let d = s
            .devices
            .iter_mut()
            .find(|d| d.instance_id.starts_with("USBSTOR\\DISK&VEN_KINGSTON"))
            .unwrap();
        d.problem_code = problem;
        drop(s);
        self.ok(Request::RefreshInventory);
    }
    fn set_policy(&self, p: PolicySnapshot) {
        *self.pol.0.lock().unwrap() = p;
    }
    fn kingston_key(&self) -> String {
        match self.ok(Request::GetEnforcementObservation) {
            ResponseBody::EnforcementObservation(v) => v
                .devices
                .iter()
                .find(|d| d.observed.vid_pid.as_deref() == Some("0951:1666"))
                .unwrap()
                .device_key
                .clone(),
            other => panic!("{other:?}"),
        }
    }
}

fn applied() -> PolicySnapshot {
    PolicySnapshot::default()
        .with(RESTRICTIONS_KEY, "DenyDeviceIDs", RegData::Dword(1))
        .with(
            RESTRICTIONS_KEY,
            "DenyDeviceIDsRetroactive",
            RegData::Dword(1),
        )
        .with(
            &format!("{RESTRICTIONS_KEY}\\DenyDeviceIDs"),
            "1",
            RegData::Sz(KINGSTON_ID.into()),
        )
}

fn ladder(v: &EnforcementSessionView, code: &str) -> String {
    v.ladder
        .iter()
        .find(|s| s.code == code)
        .unwrap()
        .status
        .clone()
}

#[test]
fn guided_session_full_cycle_with_real_identifiers() {
    let r = rig();
    r.ok(Request::RefreshInventory);
    let key = r.kingston_key();

    // No session: simulation only, automated application blocked.
    let v = r.session(Request::GetEnforcementSession, false).unwrap();
    assert_eq!(v.state, "policy_simulation");
    assert!(!v.automated_apply_available);
    assert!(
        v.automated_apply_blocker
            .tr
            .contains("RustWard Windows Grup İlkesine veya kayıt defterine yazmaz")
    );
    assert_eq!(ladder(&v, "read_write_verified"), "not_verified");

    // Preparing needs an elevated administrator.
    let refused = r
        .session(
            Request::PrepareEnforcementSession {
                device_key: key.clone(),
                retroactive: true,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(refused.code, ErrorCode::Unauthorized);
    assert!(
        refused
            .message_tr
            .unwrap()
            .contains("Bu bağlantı yalnızca salt okunur")
    );

    let v = r
        .session(
            Request::PrepareEnforcementSession {
                device_key: key.clone(),
                retroactive: true,
            },
            true,
        )
        .unwrap();
    assert_eq!(v.state, "protection_inactive");
    let s = v.session.clone().unwrap();
    assert_eq!(s.hardware_id, KINGSTON_ID);
    assert_eq!(s.expected_lines.len(), 3);
    let id = s.session_id.clone();
    // Only one session at a time.
    let second = r
        .session(
            Request::PrepareEnforcementSession {
                device_key: key.clone(),
                retroactive: false,
            },
            true,
        )
        .unwrap_err();
    assert_eq!(second.code, ErrorCode::Conflict);

    // Verification before the administrator changed anything.
    let early = r
        .session(
            Request::VerifyEnforcementApplied {
                session_id: id.clone(),
            },
            true,
        )
        .unwrap_err();
    assert!(early.message_tr.unwrap().contains("önce kontrol listesini"));

    // The administrator applies exactly the checklist; Windows blocks the
    // Kingston (Code 1 after the retroactive removal).
    r.set_policy(applied());
    r.kingston(Some(1));
    let v = r
        .session(
            Request::VerifyEnforcementApplied {
                session_id: id.clone(),
            },
            true,
        )
        .unwrap();
    assert_eq!(v.state, "windows_install_denied");
    assert_eq!(ladder(&v, "windows_restriction_configured"), "yes");
    assert_eq!(ladder(&v, "windows_install_denied"), "yes");
    assert_eq!(ladder(&v, "read_write_verified"), "not_verified");
    assert_eq!(ladder(&v, "protection_inactive"), "no");
    assert!(
        v.state_tr
            .contains("Okuma/yazma yolları ayrıca doğrulanmadı")
    );

    // Somebody adds an unrelated rule: enforcement error, never "fine".
    r.set_policy(applied().with(RESTRICTIONS_KEY, "DenyUnspecified", RegData::Dword(1)));
    let v = r.session(Request::GetEnforcementSession, false).unwrap();
    assert_eq!(v.state, "enforcement_error");
    assert!(v.differences.iter().any(|d| d.contains("DENYUNSPECIFIED")));
    // A session whose change is applied cannot be cancelled.
    let cancel = r
        .session(
            Request::CancelEnforcementSession {
                session_id: id.clone(),
            },
            true,
        )
        .unwrap_err();
    assert_eq!(cancel.code, ErrorCode::Conflict);

    // Incomplete rollback: recovery required.
    r.set_policy(PolicySnapshot::default().with(
        RESTRICTIONS_KEY,
        "DenyUnspecified",
        RegData::Dword(1),
    ));
    let v = r
        .session(
            Request::VerifyEnforcementRollback {
                session_id: id.clone(),
            },
            true,
        )
        .unwrap();
    assert_eq!(v.state, "recovery_required");

    // Exact rollback closes the session; the Kingston works again.
    r.set_policy(PolicySnapshot::default());
    r.kingston(None);
    let v = r
        .session(
            Request::VerifyEnforcementRollback {
                session_id: id.clone(),
            },
            true,
        )
        .unwrap();
    assert_eq!(v.state, "policy_simulation");
    assert!(v.session.is_none());

    // Every step is in the audit log, in Turkish too.
    let ResponseBody::Events(ev) = r.ok(Request::ListEvents {
        query: EventQuery::default(),
    }) else {
        panic!()
    };
    for kind in [
        "enforcement_session_prepared",
        "enforcement_session_apply_verified",
        "enforcement_session_rollback_mismatch",
        "enforcement_session_rollback_verified",
    ] {
        let e = ev
            .iter()
            .find(|e| e.kind == kind)
            .unwrap_or_else(|| panic!("{kind}"));
        assert!(!e.message_tr.starts_with(UNTRANSLATED), "{}", e.message_tr);
        assert!(!e.simulated);
    }
}

#[test]
fn cancel_is_allowed_only_while_nothing_was_applied() {
    let r = rig();
    r.ok(Request::RefreshInventory);
    let key = r.kingston_key();
    let v = r
        .session(
            Request::PrepareEnforcementSession {
                device_key: key,
                retroactive: false,
            },
            true,
        )
        .unwrap();
    let id = v.session.unwrap().session_id;
    let v = r
        .session(Request::CancelEnforcementSession { session_id: id }, true)
        .unwrap();
    assert_eq!(v.state, "policy_simulation");
}

#[test]
fn internal_disk_and_input_devices_cannot_be_targeted() {
    let r = rig();
    r.ok(Request::RefreshInventory);
    let ResponseBody::Devices(devs) = r.ok(Request::ListDevices {
        include_absent: true,
    }) else {
        panic!()
    };
    for d in devs
        .iter()
        .filter(|d| !d.category.starts_with("usb_storage_disk"))
    {
        let e = r
            .session(
                Request::PrepareEnforcementSession {
                    device_key: d.device_key.clone(),
                    retroactive: true,
                },
                true,
            )
            .unwrap_err();
        assert!(
            matches!(e.code, ErrorCode::ValidationFailed | ErrorCode::NotFound),
            "{e:?}"
        );
        assert!(e.message_tr.is_some());
    }
}

fn assert_turkish(label: &str, texts: &[String]) {
    for t in texts {
        assert!(!t.starts_with(UNTRANSLATED), "{label}: untranslated: {t}");
        assert!(!t.is_empty(), "{label}: empty Turkish text");
    }
}

#[test]
fn every_user_facing_backend_text_has_a_turkish_rendering() {
    let r = rig();
    r.ok(Request::RefreshInventory);
    r.ok(Request::LoadSyntheticInventory);
    let version = |r: &Rig| match r.ok(Request::ListManufacturers) {
        ResponseBody::Manufacturers(m) => m.policy_version,
        other => panic!("{other:?}"),
    };
    // Every policy edit kind (each built against the current version).
    let edits: Vec<Box<dyn Fn(u64) -> Request>> = vec![
        Box::new(|v| Request::SetManufacturerAllowed {
            id: "kingston".into(),
            allowed: true,
            expected_policy_version: v,
        }),
        Box::new(|v| Request::SetRuleEnabled {
            id: "kingston".into(),
            enabled: false,
            expected_policy_version: v,
        }),
        Box::new(|v| Request::SetManufacturerAllowed {
            id: "kingston".into(),
            allowed: false,
            expected_policy_version: v,
        }),
        Box::new(|v| Request::SetWorkstationId {
            workstation_id: "PC-07".into(),
            expected_policy_version: v,
        }),
    ];
    for make in &edits {
        let ResponseBody::Mutation(m) = r.ok(make(version(&r))) else {
            panic!()
        };
        assert_turkish("mutation summary", std::slice::from_ref(&m.summary_tr));
        assert_turkish("mutation warnings", &m.warnings_tr);
    }
    r.ok(Request::ApplyRetention);
    r.ok(Request::RunSimulation);

    let ResponseBody::Dashboard(d) = r.ok(Request::GetDashboard) else {
        panic!()
    };
    assert_turkish("dashboard warnings", &d.warnings_tr);
    assert_turkish("service", std::slice::from_ref(&d.service.message_tr));
    assert_eq!(d.service.message_tr, "RustWard hizmeti çalışıyor.");
    let ResponseBody::Manufacturers(m) = r.ok(Request::ListManufacturers) else {
        panic!()
    };
    assert_turkish("manufacturer warnings", &m.warnings_tr);
    for x in &m.manufacturers {
        assert_turkish("manufacturer issues", &x.issues_tr);
    }
    assert!(m.warnings_tr.iter().any(|w| w.starts_with("Encrypted USB Storage (Unverified) için uygulanabilir donanım kimliği bulunamadı.")));
    assert!(
        m.warnings_tr.iter().any(|w| w
            == "SanDisk markasının donanım kimlikleri henüz gerçek cihaz üzerinde doğrulanmadı.")
    );
    let ResponseBody::Diagnostics(g) = r.ok(Request::GetDiagnostics) else {
        panic!()
    };
    assert_turkish("policy warnings", &g.policy.warnings_tr);
    assert_turkish("risks", &g.enforcement.risks_tr);
    assert_turkish("unsupported", &g.unsupported_features_tr);
    assert_turkish("pending", &g.pending_native_tests_tr);
    let ResponseBody::Simulation(s) = r.ok(Request::RunSimulation) else {
        panic!()
    };
    assert_turkish("simulation", std::slice::from_ref(&s.notice_tr));
    let ResponseBody::PolicyChanges(c) = r.ok(Request::ListPolicyChanges { limit: 50 }) else {
        panic!()
    };
    assert!(!c.is_empty());
    for x in &c {
        assert_turkish("policy change", std::slice::from_ref(&x.summary_tr));
    }
    assert!(
        c.iter()
            .any(|x| x.summary_tr == "Kingston izin verilen üreticiler listesinden çıkarıldı.")
    );
    let ResponseBody::Done { message_tr, .. } = r.ok(Request::RefreshInventory) else {
        panic!()
    };
    assert!(message_tr.starts_with("Envanter yenilendi:"));
    let ResponseBody::Events(ev) = r.ok(Request::ListEvents {
        query: EventQuery {
            limit: Some(1000),
            ..EventQuery::default()
        },
    }) else {
        panic!()
    };
    assert!(ev.len() > 20);
    for e in &ev {
        assert_turkish(
            &format!("event {}", e.kind),
            std::slice::from_ref(&e.message_tr),
        );
    }
    // Errors: version conflict and validation, through the pipeline.
    let e = r
        .call(
            Request::SetManufacturerAllowed {
                id: "kingston".into(),
                allowed: true,
                expected_policy_version: 1,
            },
            true,
        )
        .unwrap_err();
    assert!(!e.message_tr.unwrap().starts_with(UNTRANSLATED));
}

#[test]
fn every_registered_event_kind_renders_in_turkish() {
    let names = |id: &str| id.to_string();
    for (kind, _) in rustward_windows::eventlog_map::EVENT_IDS {
        let e = SecurityEvent {
            id: 1,
            utc_ms: 0,
            severity: Severity::Info,
            kind: (*kind).to_string(),
            device_key: None,
            message: match *kind {
                "policy_changed" => {
                    "manufacturer \"kingston\" removed from the allowlist (by PC\\admin)".into()
                }
                "policy_restored" => {
                    "backup b.db applied as policy v5; previous state saved as pre.db by PC\\admin"
                        .into()
                }
                "policy_initialized" => "policy v1 initialized for PC-01 by rustward-setup".into(),
                _ => "Kingston DataTraveler 3.0 USB Device detected (usb_storage_disk)".into(),
            },
            simulated: false,
            enforcement_state: "n/a".into(),
            policy_version: None,
            details: serde_json::json!({ "summary_tr": "x", "session_id": "0123456789abcdef" }),
            prev_hash: String::new(),
            hash: String::new(),
        };
        let t = l10n::event(&e, &names);
        assert!(!t.starts_with(UNTRANSLATED), "{kind}: {t}");
    }
}
