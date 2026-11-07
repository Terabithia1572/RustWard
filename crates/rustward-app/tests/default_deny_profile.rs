//! Phase 6 default-deny profile session: the administrator-guided layered
//! Device Installation Restrictions plan, verified against test doubles fed
//! with the devices observed in the test VM. RustWard writes nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use rustward_app::{
    AppConfig, AppService, BackendKind, InventorySource, PolicySource, default_policy_state,
};
use rustward_core::device::DeviceSnapshot;
use rustward_enforcement::policy_inspect::CapturedPolicy;
use rustward_enforcement::policy_state::{PolicySnapshot, RegData};
use rustward_ipc::messages::{AccessLevel, Request, ResponseBody};
use rustward_ipc::rpc::Handler;
use rustward_ipc::{ClientIdentity, ErrorCode, IdentitySource};
use rustward_storage::{ManualClock, Store};

const OBSERVED: &str = include_str!("../../../tests/fixtures/vm-observed-usb-2026-11-07.json");

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
    // The VM fixture with the internal NVMe disk's parent chain resolved
    // (as the live SetupAPI inventory provides it), so the plan protects
    // it with an instance-ID allow rule.
    let mut j: serde_json::Value = serde_json::from_str(OBSERVED).unwrap();
    let pci = "PCI\\VEN_15AD&DEV_07F0\\INSTANCE-REDACTED-NVME-CONTROLLER";
    let devices = j["devices"].as_array_mut().unwrap();
    for d in devices.iter_mut() {
        if d["instance_id"]
            .as_str()
            .unwrap()
            .starts_with("SCSI\\DISK&VEN_NVME")
        {
            d["parent_instance_id"] = pci.into();
        }
    }
    devices.push(serde_json::json!({
        "instance_id": pci,
        "class_name": "SCSIAdapter",
        "description": "Standard NVM Express Controller",
        "present": true
    }));
    let inv = Inv(Arc::new(Mutex::new(
        DeviceSnapshot::from_json(&j.to_string()).unwrap(),
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
}

fn session(r: &Rig, req: Request) -> rustward_ipc::messages::EnforcementSessionView {
    match r.call(req, true).unwrap() {
        ResponseBody::EnforcementSession(v) => *v,
        other => panic!("{other:?}"),
    }
}

fn protection(r: &Rig) -> rustward_ipc::messages::WindowsProtectionView {
    match r.call(Request::GetDashboard, false).unwrap() {
        ResponseBody::Dashboard(d) => d.windows_protection,
        other => panic!("{other:?}"),
    }
}

/// Simulate the administrator applying the expected lines in gpedit.
/// `write_retro_zero`: whether Group Policy writes the unchecked
/// "also apply to installed devices" box as 0 or leaves it out.
fn apply_lines(r: &Rig, lines: &[String], write_retro_zero: bool) {
    let mut p = PolicySnapshot::default();
    for l in lines {
        let l = l.strip_prefix("HKLM\\").unwrap();
        let (path, rest) = l.split_once(" = ").unwrap();
        let (key, name) = path.rsplit_once('\\').unwrap();
        let (ty, data) = rest.split_once(' ').unwrap();
        if name.ends_with("Retroactive") && data == "0" && !write_retro_zero {
            continue;
        }
        let d = if ty == "REG_DWORD" {
            RegData::Dword(data.parse().unwrap())
        } else {
            RegData::Sz(data.into())
        };
        p = p.with(key, name, d);
    }
    *r.pol.0.lock().unwrap() = p;
}

#[test]
fn profile_session_is_administrator_only_and_never_retroactive() {
    let r = rig();
    r.refresh();
    // Administrator only (enforced by the IPC layer before `handle`).
    assert_eq!(
        Request::PrepareDefaultDenySession.access_level(),
        AccessLevel::Administrator
    );

    let v = session(&r, Request::PrepareDefaultDenySession);
    let s = v.session.unwrap();
    assert_eq!(s.kind, "default_deny_profile");
    assert!(!s.retroactive);
    let joined = s.expected_lines.join("\n");
    assert!(
        joined.contains("AllowDenyLayered = REG_DWORD 1"),
        "{joined}"
    );
    assert!(joined.contains("DenyDeviceClasses = REG_DWORD 1"));
    assert!(joined.contains("{4d36e967-e325-11ce-bfc1-08002be10318}"));
    assert!(joined.contains("DenyDeviceClassesRetroactive = REG_DWORD 0"));
    assert!(!joined.contains("Retroactive = REG_DWORD 1"));
    // Never a device-ID deny of a brand: default deny comes from the class.
    assert!(!joined.contains("DenyDeviceIDs"));
    let text = s.checklist_text.unwrap();
    assert!(text.contains("İŞARETLENMEZ"));
    assert!(text.contains("Geri alma"));
    assert!(text.contains("okuma/yazma"));
    // The already-installed sticks are listed as not covered, masked.
    assert!(text.contains("ZATEN KURULU"));
    assert!(!text.contains("SERIAL"));
    // Nothing applied by RustWard: the live policy is still empty.
    assert!(r.pol.0.lock().unwrap().values.is_empty());
    assert_eq!(protection(&r).state, "inactive");
    // A second session is refused while this one is active.
    let e = r
        .call(Request::PrepareDefaultDenySession, true)
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
}

#[test]
fn profile_applied_by_the_administrator_is_verified_then_rolled_back() {
    for write_retro_zero in [true, false] {
        let r = rig();
        r.refresh();
        let v = session(&r, Request::PrepareDefaultDenySession);
        let s = v.session.unwrap();
        let id = s.session_id.clone();

        // A partial change is a mismatch, never a verification.
        apply_lines(&r, &s.expected_lines[..2], write_retro_zero);
        let v = session(
            &r,
            Request::VerifyEnforcementApplied {
                session_id: id.clone(),
            },
        );
        assert_eq!(
            v.session.as_ref().unwrap().last_verification.as_deref(),
            Some("enforcement_session_apply_mismatch")
        );

        apply_lines(&r, &s.expected_lines, write_retro_zero);
        let v = session(
            &r,
            Request::VerifyEnforcementApplied {
                session_id: id.clone(),
            },
        );
        assert_eq!(
            v.session.as_ref().unwrap().last_verification.as_deref(),
            Some("enforcement_session_apply_verified"),
            "retro0={write_retro_zero} {:?}",
            v.differences
        );
        // Installed sticks keep working (non-retroactive): configured, not
        // a block.
        assert_eq!(protection(&r).state, "configured_unverified");

        // The administrator reinstalls the Kingston: Windows refuses the
        // new installation under the class rule (Code 28).
        r.kingston(true, Some(28));
        let p = protection(&r);
        assert_eq!(p.state, "verified_active", "{p:?}");
        assert!(p.label_tr.contains("Varsayılan ret profili"));
        assert!(p.detail_tr.contains("okuma/yazma"));
        assert_eq!(p.denied_now, 1);

        // Rollback: Not Configured everywhere.
        *r.pol.0.lock().unwrap() = PolicySnapshot::default();
        r.kingston(true, None);
        let v = session(&r, Request::VerifyEnforcementRollback { session_id: id });
        assert!(v.session.is_none(), "closed");
        assert_eq!(protection(&r).state, "inactive");
    }
}

/// A policy source whose capture also carries a Removable Storage Access
/// "Removable Disks: Deny read access" value.
struct RsaPol;
impl PolicySource for RsaPol {
    fn capture(&self, now_ms: i64) -> Result<CapturedPolicy, String> {
        use rustward_enforcement::removable_storage::{REMOVABLE_DISKS, RSA_KEY};
        Ok(CapturedPolicy {
            captured_ms: now_ms,
            removable_storage: PolicySnapshot::default().with(
                &format!("{RSA_KEY}\\{REMOVABLE_DISKS}"),
                "Deny_Read",
                RegData::Dword(1),
            ),
            ..CapturedPolicy::default()
        })
    }
    fn name(&self) -> &'static str {
        "test_double_rsa"
    }
}

#[test]
fn removable_storage_read_deny_is_reported_as_class_wide_not_as_protection() {
    let clock = Arc::new(ManualClock::new(1_794_047_400_000));
    let s = AppService::new(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(Inv(Arc::new(Mutex::new(
            DeviceSnapshot::from_json(OBSERVED).unwrap(),
        )))),
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
    .with_policy_source(Box::new(RsaPol));
    s.handle(&Request::RefreshInventory, &identity(true))
        .unwrap();
    let ResponseBody::EnforcementObservation(o) = s
        .handle(&Request::GetEnforcementObservation, &identity(false))
        .unwrap()
    else {
        panic!()
    };
    assert!(o.removable_storage.configured);
    assert!(o.removable_storage.disks_deny_read);
    assert!(!o.removable_storage.disks_deny_write);
    let ResponseBody::Dashboard(d) = s.handle(&Request::GetDashboard, &identity(false)).unwrap()
    else {
        panic!()
    };
    let p = d.windows_protection;
    // Not an installation restriction: protection stays "inactive", and the
    // class-wide limitation and the unverified read/write state are listed.
    assert_eq!(p.state, "inactive");
    let codes: Vec<_> = p.blockers.iter().map(|b| b.code.as_str()).collect();
    assert!(codes.contains(&"removable_storage_class_wide"), "{codes:?}");
    assert!(codes.contains(&"read_write_unverified"));
}
