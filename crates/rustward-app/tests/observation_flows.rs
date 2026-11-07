//! Windows enforcement observer through the application: deduplicated
//! audit events, history after rollback, disconnects, read-only access and
//! the administrator checklist. Policy and inventory are test doubles fed
//! with the identifiers and states observed in the test VM.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use rustward_app::{
    AppConfig, AppService, BackendKind, InventorySource, PolicySource, default_policy_state,
};
use rustward_core::device::DeviceSnapshot;
use rustward_enforcement::device_install::RESTRICTIONS_KEY;
use rustward_enforcement::observer::{EvidenceLevel, ObservedState};
use rustward_enforcement::policy_inspect::CapturedPolicy;
use rustward_enforcement::policy_state::{PolicySnapshot, RegData};
use rustward_ipc::messages::{
    AccessLevel, EnforcementObservationView, EventQuery, Request, ResponseBody,
};
use rustward_ipc::rpc::Handler;
use rustward_ipc::{ClientIdentity, ErrorCode, IdentitySource};
use rustward_storage::{ManualClock, Store, device_key};

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

fn identity(admin: bool) -> ClientIdentity {
    ClientIdentity {
        account: "PC-01\\user".into(),
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
    let clock = Arc::new(ManualClock::new(1_794_047_400_000));
    let inv = Inv(Arc::new(Mutex::new(
        DeviceSnapshot::from_json(OBSERVED).unwrap(),
    )));
    let pol = Pol(Arc::new(Mutex::new(PolicySnapshot::default())));
    let s = AppService::new(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(inv.clone()),
        AppConfig {
            backend: BackendKind::DevBackend,
            allow_synthetic: false,
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
    fn call(&self, r: Request, admin: bool) -> Result<ResponseBody, rustward_ipc::IpcError> {
        self.s.handle(&r, &identity(admin))
    }
    fn refresh(&self) {
        self.call(Request::RefreshInventory, true).unwrap();
    }
    fn observe(&self) -> EnforcementObservationView {
        match self
            .call(Request::GetEnforcementObservation, false)
            .unwrap()
        {
            ResponseBody::EnforcementObservation(v) => *v,
            other => panic!("{other:?}"),
        }
    }
    fn kingston(&self, present: bool, problem: Option<u32>) {
        let mut s = self.inv.0.lock().unwrap();
        let d = s
            .devices
            .iter_mut()
            .find(|d| d.instance_id.starts_with("USBSTOR\\DISK&VEN_KINGSTON"))
            .unwrap();
        d.present = Some(present);
        d.problem_code = problem;
        drop(s);
        self.refresh();
    }
    fn policy(&self, applied: bool) {
        *self.pol.0.lock().unwrap() = if applied {
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
        } else {
            PolicySnapshot::default()
        };
    }
    fn events(&self, kind: &str) -> usize {
        match self
            .call(
                Request::ListEvents {
                    query: EventQuery {
                        kind: Some(kind.into()),
                        ..EventQuery::default()
                    },
                },
                false,
            )
            .unwrap()
        {
            ResponseBody::Events(e) => e.len(),
            other => panic!("{other:?}"),
        }
    }
}

fn kingston_key(v: &EnforcementObservationView) -> String {
    v.devices
        .iter()
        .find(|d| d.observed.vid_pid.as_deref() == Some("0951:1666"))
        .unwrap()
        .device_key
        .clone()
}

#[test]
fn full_kingston_episode_is_audited_once_and_ends_as_history() {
    let r = rig();
    r.refresh();
    // Baseline: no Windows rule; both sticks only simulated denials.
    let v = r.observe();
    assert!(!v.windows_restrictions_configured);
    assert!(v.rustward_applies_nothing);
    assert_eq!(v.devices.len(), 2);
    assert!(v.newly_observed_denials.is_empty());
    for d in &v.devices {
        assert!(d.observed.states.contains(&ObservedState::SimulatedDeny));
        assert!(
            d.observed
                .states
                .contains(&ObservedState::NoWindowsRestriction)
        );
        assert!(
            !d.observed.instance_id.contains("SERIAL-REDACTED"),
            "masked"
        );
    }
    let key = kingston_key(&v);

    // Policy applied, Code 1: newly observed and audited once.
    r.policy(true);
    r.kingston(true, Some(1));
    let v = r.observe();
    assert_eq!(v.newly_observed_denials, vec![key.clone()]);
    assert_eq!(r.events("windows_install_denied_observed"), 1);
    // Repeated refreshes and the reconnect (Code 28) do not repeat it.
    r.refresh();
    assert!(r.observe().newly_observed_denials.is_empty());
    r.kingston(true, Some(28));
    let v = r.observe();
    assert!(v.newly_observed_denials.is_empty());
    assert_eq!(r.events("windows_install_denied_observed"), 1);
    let k = v.devices.iter().find(|d| d.device_key == key).unwrap();
    assert_eq!(k.observed.evidence, EvidenceLevel::InstallDenied);
    assert!(k.observed.history.is_none(), "current, not history");

    // Disconnected: not blocked; the episode ends.
    r.kingston(false, Some(28));
    let v = r.observe();
    let k = v.devices.iter().find(|d| d.device_key == key).unwrap();
    assert_ne!(k.observed.evidence, EvidenceLevel::InstallDenied);
    assert!(k.observed.label_status_tr.starts_with("Bağlı değil"));
    assert!(k.observed.history.is_some());
    assert_eq!(r.events("windows_install_denial_ended"), 1);

    // Reconnected while still denied: a new episode.
    r.kingston(true, Some(28));
    assert_eq!(r.observe().newly_observed_denials, vec![key.clone()]);
    assert_eq!(r.events("windows_install_denied_observed"), 2);

    // Rolled back: accessible, history only, one ending event, then quiet.
    r.policy(false);
    r.kingston(true, None);
    let v = r.observe();
    let k = v.devices.iter().find(|d| d.device_key == key).unwrap();
    assert_eq!(k.observed.evidence, EvidenceLevel::None);
    assert_eq!(k.observed.label_policy_tr, "Kural uygulanmamış");
    assert!(k.observed.label_status_tr.starts_with("Erişilebilir"));
    assert!(k.observed.explanation_tr.starts_with("Geçmiş kanıt"));
    assert_eq!(k.observed.history.as_ref().unwrap().rule_entry, KINGSTON_ID);
    assert_eq!(r.events("windows_install_denial_ended"), 2);
    r.observe();
    assert_eq!(r.events("windows_install_denial_ended"), 2);
    assert_eq!(r.events("windows_install_denied_observed"), 2);
}

#[test]
fn checklist_is_generated_for_a_device_key_and_never_applied() {
    let r = rig();
    r.refresh();
    let key = kingston_key(&r.observe());
    let before = r.pol.0.lock().unwrap().clone();
    let ResponseBody::PolicyChecklist(c) = r
        .call(
            Request::GetPolicyChecklist {
                device_key: key,
                retroactive: true,
            },
            false,
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(c.checklist.hardware_id, KINGSTON_ID);
    assert!(c.text.contains("UYGULAMAZ"));
    assert_eq!(*r.pol.0.lock().unwrap(), before, "nothing applied");
    let missing = r
        .call(
            Request::GetPolicyChecklist {
                device_key: device_key("USBSTOR\\NOT-PRESENT"),
                retroactive: false,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::NotFound);
    // Malformed keys are refused by the IPC validator before dispatch.
    assert!(
        rustward_ipc::validate::validate_request(&Request::GetPolicyChecklist {
            device_key: "zz".into(),
            retroactive: false,
        })
        .is_err()
    );
}

struct Unreadable;
impl PolicySource for Unreadable {
    fn capture(&self, _: i64) -> Result<CapturedPolicy, String> {
        Err("not on Windows".into())
    }
    fn name(&self) -> &'static str {
        "unreadable"
    }
}

#[test]
fn unreadable_policy_never_claims_no_rule_and_records_nothing() {
    let r = rig();
    r.kingston(true, Some(28));
    let s = r.s.with_policy_source(Box::new(Unreadable));
    let ResponseBody::EnforcementObservation(v) = s
        .handle(&Request::GetEnforcementObservation, &identity(false))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(v.policy_source, "unavailable");
    assert!(v.policy_error.is_some());
    assert!(v.newly_observed_denials.is_empty());
    for d in &v.devices {
        assert_eq!(d.observed.label_policy_tr, "Windows politikası okunamadı");
        assert!(d.observed.states.contains(&ObservedState::StatusUnknown));
        assert!(
            !d.observed
                .states
                .contains(&ObservedState::NoWindowsRestriction)
        );
        assert_ne!(d.observed.evidence, EvidenceLevel::InstallDenied);
    }
}

struct SlowInv(DeviceSnapshot);
impl InventorySource for SlowInv {
    fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        Ok((self.0.clone(), vec![]))
    }
    fn kind(&self) -> &'static str {
        "live"
    }
}

#[test]
fn a_slow_windows_enumeration_does_not_block_other_requests() {
    let clock = Arc::new(ManualClock::new(1_794_047_400_000));
    let s = Arc::new(
        AppService::new(
            Store::open_in_memory(clock.clone()).unwrap(),
            clock,
            Box::new(SlowInv(DeviceSnapshot::from_json(OBSERVED).unwrap())),
            AppConfig {
                backend: BackendKind::DevBackend,
                allow_synthetic: false,
                backup_dir: None,
                database_location: "dev_temp".into(),
                app_version: "test".into(),
            },
            &default_policy_state().unwrap(),
        )
        .unwrap()
        .with_policy_source(Box::new(Pol(Arc::new(Mutex::new(
            PolicySnapshot::default(),
        ))))),
    );
    let bg = {
        let s = s.clone();
        std::thread::spawn(move || s.refresh_inventory().unwrap())
    };
    std::thread::sleep(std::time::Duration::from_millis(200));
    let t = std::time::Instant::now();
    s.handle(&Request::GetDashboard, &identity(false)).unwrap();
    s.handle(&Request::GetEnforcementObservation, &identity(false))
        .unwrap();
    assert!(
        t.elapsed() < std::time::Duration::from_millis(700),
        "requests waited for the enumeration: {:?}",
        t.elapsed()
    );
    bg.join().unwrap();
    let ResponseBody::Diagnostics(d) = s
        .handle(&Request::GetDiagnostics, &identity(false))
        .unwrap()
    else {
        panic!()
    };
    let p = &d.performance;
    assert_eq!(p.inventory_refreshes, 1);
    assert!(p.last_inventory_collect_ms.unwrap() >= 1400, "{p:?}");
    assert!(p.last_observation_ms.is_some());
    assert_eq!(p.last_inventory_devices, Some(10));
}

fn protection(r: &Rig) -> rustward_ipc::messages::WindowsProtectionView {
    match r.call(Request::GetDashboard, false).unwrap() {
        ResponseBody::Dashboard(d) => d.windows_protection,
        other => panic!("{other:?}"),
    }
}

#[test]
fn dashboard_protection_state_follows_real_windows_evidence_only() {
    let r = rig();
    r.refresh();
    let p = protection(&r);
    assert_eq!(p.state, "inactive");
    assert!(!p.automated_apply_available);
    let key = kingston_key(&r.observe());

    // Rule configured, Kingston still installed and working: not verified.
    r.policy(true);
    r.kingston(true, None);
    assert_eq!(protection(&r).state, "configured_unverified");

    // Real denial without a RustWard session.
    r.kingston(true, Some(1));
    let p = protection(&r);
    assert_eq!(p.state, "denial_observed");
    assert_eq!(p.denied_now, 1);

    // Through a guided session: prepare on the baseline, apply, verify.
    r.policy(false);
    r.kingston(true, None);
    let ResponseBody::EnforcementSession(v) = r
        .call(
            Request::PrepareEnforcementSession {
                device_key: key,
                retroactive: true,
            },
            true,
        )
        .unwrap()
    else {
        panic!()
    };
    let id = v.session.unwrap().session_id;
    r.policy(true);
    r.kingston(true, Some(1));
    r.call(
        Request::VerifyEnforcementApplied {
            session_id: id.clone(),
        },
        true,
    )
    .unwrap();
    let p = protection(&r);
    assert_eq!(p.state, "verified_active", "{p:?}");
    assert!(
        p.detail_tr
            .contains("Okuma/yazma yolları ayrıca doğrulanmadı")
    );

    // Disconnected: no current evidence any more.
    r.kingston(false, Some(1));
    assert_eq!(protection(&r).state, "configured_unverified");

    // Rolled back by the administrator, not yet verified: the guided
    // headline asks for the rollback verification instead of claiming the
    // policy was never changed.
    r.policy(false);
    r.kingston(true, None);
    let ResponseBody::EnforcementSession(v) =
        r.call(Request::GetEnforcementSession, false).unwrap()
    else {
        panic!()
    };
    assert_eq!(v.state, "protection_inactive");
    assert!(
        v.state_tr.contains("Geri almayı doğrulayın"),
        "{}",
        v.state_tr
    );
    assert!(!v.state_tr.contains("henüz değiştirilmedi"));
    // The Kingston's latest real audit event is never a simulated decision.
    let o = r.observe();
    let k = o
        .devices
        .iter()
        .find(|d| d.observed.vid_pid.as_deref() == Some("0951:1666"))
        .unwrap();
    assert!(k.last_event_kind.is_some());
    assert_ne!(k.last_event_kind.as_deref(), Some("decision_simulated"));

    // Rolled back and verified: inactive.
    r.call(Request::VerifyEnforcementRollback { session_id: id }, true)
        .unwrap();
    assert_eq!(protection(&r).state, "inactive");
}
