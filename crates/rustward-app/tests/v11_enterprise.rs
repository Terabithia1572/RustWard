//! Comprehensive V1.1 enterprise security, policy persistence/reconciliation,
//! bulk operations, exit authorization, notifications, auditing, About metadata,
//! and accurate dashboard protection tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use rustward_app::{
    AppConfig, AppService, BackendKind, GpoBackend, InventorySource, PolicySource,
    default_policy_state,
};
use rustward_core::catalog::{BrandIdentifier, IdentifierKind, Verification};
use rustward_core::device::DeviceSnapshot;
use rustward_core::policy_edit::{BulkManufacturerAction, ManufacturerInput};
use rustward_enforcement::device_install::RESTRICTIONS_KEY;
use rustward_enforcement::policy_inspect::CapturedPolicy;
use rustward_enforcement::policy_state::{PolicySnapshot, RegData};
use rustward_ipc::messages::{
    AccessLevel, EventQuery, ExportFormat, Request, ResponseBody, SettingsView,
};
use rustward_ipc::rpc::Handler;
use rustward_ipc::{ClientIdentity, ErrorCode, IdentitySource};
use rustward_storage::{Clock, ManualClock, Store};

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

#[derive(Clone)]
struct MockGpo {
    pol: Arc<Mutex<PolicySnapshot>>,
    apply_calls: Arc<Mutex<usize>>,
    rollback_calls: Arc<Mutex<usize>>,
    restarted_instances: Arc<Mutex<Vec<String>>>,
}

impl MockGpo {
    fn new(pol: Arc<Mutex<PolicySnapshot>>) -> Self {
        Self {
            pol,
            apply_calls: Arc::new(Mutex::new(0)),
            rollback_calls: Arc::new(Mutex::new(0)),
            restarted_instances: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn write_entries(
        pol: &Arc<Mutex<PolicySnapshot>>,
        denies: &[String],
        allows: &[String],
        retroactive: bool,
    ) {
        let mut snap = PolicySnapshot::default();
        if !denies.is_empty() {
            snap = snap.with(RESTRICTIONS_KEY, "DenyDeviceIDs", RegData::Dword(1));
            if retroactive {
                snap = snap.with(
                    RESTRICTIONS_KEY,
                    "DenyDeviceIDsRetroactive",
                    RegData::Dword(1),
                );
            }
            let sub = format!("{RESTRICTIONS_KEY}\\DenyDeviceIDs");
            for (idx, val) in denies.iter().enumerate() {
                snap = snap.with(&sub, &(idx + 1).to_string(), RegData::Sz(val.clone()));
            }
        }
        if !allows.is_empty() {
            snap = snap.with(RESTRICTIONS_KEY, "AllowDeviceIDs", RegData::Dword(1));
            let sub = format!("{RESTRICTIONS_KEY}\\AllowDeviceIDs");
            for (idx, val) in allows.iter().enumerate() {
                snap = snap.with(&sub, &(idx + 1).to_string(), RegData::Sz(val.clone()));
            }
        }
        *pol.lock().unwrap() = snap;
    }
}

fn merge_entries(managed: &[String], third_party: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in third_party.iter().chain(managed.iter()) {
        if !out
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(item))
        {
            out.push(item.clone());
        }
    }
    out
}

impl GpoBackend for MockGpo {
    fn check_capability(&self) -> Result<(), String> {
        Ok(())
    }

    fn apply_compound_policy(
        &self,
        deny_ids: &[String],
        allow_ids: &[String],
        third_party_denies: &[String],
        third_party_allows: &[String],
        retroactive: bool,
    ) -> Result<(), String> {
        *self.apply_calls.lock().unwrap() += 1;
        let combined_deny = merge_entries(deny_ids, third_party_denies);
        let combined_allow = merge_entries(allow_ids, third_party_allows);
        Self::write_entries(&self.pol, &combined_deny, &combined_allow, retroactive);
        Ok(())
    }

    fn restore_compound_policy(
        &self,
        third_party_denies: &[String],
        third_party_allows: &[String],
    ) -> Result<(), String> {
        *self.rollback_calls.lock().unwrap() += 1;
        Self::write_entries(&self.pol, third_party_denies, third_party_allows, true);
        Ok(())
    }

    fn restart_device_instance(&self, instance_id: &str) -> Result<(), String> {
        self.restarted_instances
            .lock()
            .unwrap()
            .push(instance_id.to_owned());
        Ok(())
    }

    fn trigger_refresh(&self) {}

    fn trigger_rescan(&self) {}
}

fn identity(admin: bool) -> ClientIdentity {
    ClientIdentity {
        account: "PC-SEC\\adminwin".into(),
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

fn win_user_present() -> Option<String> {
    Some("PC-SEC\\yunus".into())
}

fn win_user_ambiguous() -> Option<String> {
    None
}

struct Harness {
    service: AppService,
    db_path: std::path::PathBuf,
    clock: Arc<ManualClock>,
    inv: Inv,
    pol: Pol,
    gpo: Arc<MockGpo>,
    _dir: TempDir,
}

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "rustward-v11-test-{name}-{}",
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

fn harness(name: &str, auth_enforced: bool) -> Harness {
    let dir = TempDir::new(name);
    let db_path = dir.0.join("rustward.db");
    let clock = Arc::new(ManualClock::new(1_794_100_000_000));
    let inv = Inv(Arc::new(Mutex::new(DeviceSnapshot::from_json(OBSERVED).unwrap())));
    let pol = Pol(Arc::new(Mutex::new(PolicySnapshot::default())));
    let gpo = Arc::new(MockGpo::new(Arc::clone(&pol.0)));
    let store = Store::open(&db_path, clock.clone()).unwrap();
    let service = AppService::new(
        store,
        clock.clone(),
        Box::new(inv.clone()),
        AppConfig {
            backend: BackendKind::WindowsService,
            allow_synthetic: false,
            backup_dir: Some(dir.0.join("backups")),
            database_location: "program_data".into(),
            app_version: "1.1.0-test".into(),
        },
        &default_policy_state().unwrap(),
    )
    .unwrap()
    .with_policy_source(Box::new(pol.clone()))
    .with_gpo_backend(gpo.clone())
    .with_windows_user_resolver(win_user_present)
    .with_app_auth(auth_enforced);
    Harness {
        service,
        db_path,
        clock,
        inv,
        pol,
        gpo,
        _dir: dir,
    }
}

fn setup_admin_session(service: &AppService) -> (String, String) {
    let ResponseBody::Login(login) = service
        .handle_with_token(
            &Request::SetupInitialAdmin {
                username: "secadmin".into(),
                display_name: "Güvenlik Yöneticisi".into(),
                password: "Strong!Admin#2026".into(),
            },
            &identity(true),
            None,
        )
        .unwrap()
    else {
        panic!("expected login response");
    };
    (
        login.session_token,
        login.recovery_key_once.expect("initial recovery key once"),
    )
}

#[test]
fn phase7_8_mandatory_first_setup_auth_rbac_lockout_recovery_and_exit() {
    let h = harness("phase7-8", true);

    // 1. Fresh DB requires initial setup and blocks all operational endpoints fail-closed.
    let ResponseBody::AuthStatus(st) = h
        .service
        .handle_with_token(&Request::GetAuthStatus, &identity(true), None)
        .unwrap()
    else {
        panic!();
    };
    assert!(st.setup_required);
    assert!(st.auth_enforced);
    assert!(!st.authenticated);

    let err = h
        .service
        .handle_with_token(&Request::GetDashboard, &identity(true), None)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);

    // Standard non-admin Windows token cannot perform initial admin creation.
    let err = h
        .service
        .handle_with_token(
            &Request::SetupInitialAdmin {
                username: "secadmin".into(),
                display_name: "Admin".into(),
                password: "Strong!Admin#2026".into(),
            },
            &identity(false),
            None,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);

    // Weak passwords must be rejected before setup succeeds.
    for weak in ["123456", "admin", "password", "short1!"] {
        let err = h
            .service
            .handle_with_token(
                &Request::SetupInitialAdmin {
                    username: "secadmin".into(),
                    display_name: "Admin".into(),
                    password: weak.into(),
                },
                &identity(true),
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ValidationFailed, "weak={weak}");
    }

    // 2. Valid initial admin setup returns token + one-time recovery key; second attempt conflicts.
    let (admin_token, recovery_key_1) = setup_admin_session(&h.service);
    assert!(recovery_key_1.starts_with("RWREC-"));

    let conflict = h
        .service
        .handle_with_token(
            &Request::SetupInitialAdmin {
                username: "otheradmin".into(),
                display_name: "Other".into(),
                password: "Strong!Admin#2026".into(),
            },
            &identity(true),
            None,
        )
        .unwrap_err();
    assert_eq!(conflict.code, ErrorCode::Conflict);

    // 3. Create read_only operator; verify strict backend RBAC even on admin IPC identity.
    h.service
        .handle_with_token(
            &Request::CreateAppUser {
                username: "auditor1".into(),
                display_name: "Salt Okunur Denetçi".into(),
                role: "read_only".into(),
                password: "Auditor!Pass2026".into(),
            },
            &identity(true),
            Some(&admin_token),
        )
        .unwrap();

    let ResponseBody::Login(ro_login) = h
        .service
        .handle_with_token(
            &Request::Login {
                username: "auditor1".into(),
                password: "Auditor!Pass2026".into(),
            },
            &identity(false),
            None,
        )
        .unwrap()
    else {
        panic!();
    };
    let ro_token = ro_login.session_token;
    assert_eq!(ro_login.user.role, "read_only");
    assert!(ro_login.recovery_key_once.is_none());

    // Read-only operator succeeds on Dashboard, Audit Query, About, and ChangePassword...
    assert!(
        h.service
            .handle_with_token(&Request::GetDashboard, &identity(false), Some(&ro_token))
            .is_ok()
    );
    assert!(
        h.service
            .handle_with_token(&Request::GetAboutInfo, &identity(false), Some(&ro_token))
            .is_ok()
    );
    assert!(
        h.service
            .handle_with_token(
                &Request::ChangePassword {
                    current_password: "Auditor!Pass2026".into(),
                    new_password: "Auditor!NewPass99".into(),
                },
                &identity(false),
                Some(&ro_token),
            )
            .is_ok()
    );

    // ...but MUST BE REFUSED on policy mutation & user creation even if transport is admin!
    for forbidden in [
        Request::SetManufacturerDenied {
            id: "kingston".into(),
            denied: true,
            expected_policy_version: 1,
        },
        Request::CreateAppUser {
            username: "rogue".into(),
            display_name: "Rogue".into(),
            role: "admin".into(),
            password: "Rogue!Pass2026".into(),
        },
        Request::DeleteAppUser {
            username: "secadmin".into(),
        },
    ] {
        let e = h
            .service
            .handle_with_token(&forbidden, &identity(true), Some(&ro_token))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
    }

    // Read-only account MUST ALSO BE REFUSED on protected exit authorization!
    let exit_err = h
        .service
        .handle_with_token(
            &Request::VerifyExitAuthorization {
                username: "auditor1".into(),
                password: "Auditor!NewPass99".into(),
            },
            &identity(true),
            None,
        )
        .unwrap_err();
    assert_eq!(exit_err.code, ErrorCode::Unauthorized);

    // Admin wrong password fails; valid admin password succeeds with single-use exit nonce.
    let bad_exit = h
        .service
        .handle_with_token(
            &Request::VerifyExitAuthorization {
                username: "secadmin".into(),
                password: "WrongPassword!99".into(),
            },
            &identity(true),
            None,
        )
        .unwrap_err();
    assert_eq!(bad_exit.code, ErrorCode::Unauthorized);

    let ResponseBody::ExitAuthorized(exit_ok) = h
        .service
        .handle_with_token(
            &Request::VerifyExitAuthorization {
                username: "secadmin".into(),
                password: "Strong!Admin#2026".into(),
            },
            &identity(true),
            None,
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(exit_ok.authorized);
    assert!(!exit_ok.exit_nonce.is_empty());

    // 4. Idle timeout locks/expires session cleanly.
    h.clock.advance(20 * 60 * 1000);
    let idle_err = h
        .service
        .handle_with_token(&Request::GetDashboard, &identity(true), Some(&admin_token))
        .unwrap_err();
    assert_eq!(idle_err.code, ErrorCode::Unauthorized);

    // 5. Lockout after repeated failed login attempts.
    for _ in 0..5 {
        let _ = h.service.handle_with_token(
            &Request::Login {
                username: "auditor1".into(),
                password: "WrongPassword!99".into(),
            },
            &identity(false),
            None,
        );
    }
    let locked_err = h
        .service
        .handle_with_token(
            &Request::Login {
                username: "auditor1".into(),
                password: "Auditor!NewPass99".into(),
            },
            &identity(false),
            None,
        )
        .unwrap_err();
    assert_eq!(locked_err.code, ErrorCode::Unauthorized);

    // 6. One-time recovery key resets password and rotates key; old key no longer works.
    let ResponseBody::RecoveryReset(reset) = h
        .service
        .handle_with_token(
            &Request::ResetPasswordWithRecovery {
                username: "secadmin".into(),
                recovery_key: recovery_key_1.clone(),
                new_password: "Recovered!Admin#77".into(),
            },
            &identity(true),
            None,
        )
        .unwrap()
    else {
        panic!();
    };
    let recovery_key_2 = reset.new_recovery_key_once.expect("rotated key");
    assert_ne!(recovery_key_1, recovery_key_2);

    // Old recovery key must fail now.
    let reused_err = h
        .service
        .handle_with_token(
            &Request::ResetPasswordWithRecovery {
                username: "secadmin".into(),
                recovery_key: recovery_key_1,
                new_password: "Another!Admin#88".into(),
            },
            &identity(true),
            None,
        )
        .unwrap_err();
    assert_eq!(reused_err.code, ErrorCode::Unauthorized);

    // Logging in with new password works.
    let ResponseBody::Login(rel) = h
        .service
        .handle_with_token(
            &Request::Login {
                username: "secadmin".into(),
                password: "Recovered!Admin#77".into(),
            },
            &identity(true),
            None,
        )
        .unwrap()
    else {
        panic!();
    };
    assert_eq!(rel.user.username, "secadmin");
}

#[test]
fn phase5_persistence_third_party_preservation_and_startup_reconcile() {
    let h = harness("phase5", true);
    let (token, _) = setup_admin_session(&h.service);

    // Pre-existing third-party Windows GPO entry (non-USBSTOR/non-RustWard) must be preserved.
    let third_party = "PCI\\VEN_8086&DEV_9999".to_owned();
    MockGpo::write_entries(&h.pol.0, std::slice::from_ref(&third_party), &[], true);

    // Add a manufacturer deny and apply to Windows GPO.
    let ResponseBody::Manufacturers(m) = h
        .service
        .handle_with_token(&Request::ListManufacturers, &identity(true), Some(&token))
        .unwrap()
    else {
        panic!();
    };
    h.service
        .handle_with_token(
            &Request::SetManufacturerDenied {
                id: "sandisk".into(),
                denied: true,
                expected_policy_version: m.policy_version,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap();
    let ResponseBody::CompoundPolicyPlan(plan) = h
        .service
        .handle_with_token(
            &Request::ApplyCompoundPolicy {
                retroactive: true,
                expected_policy_version: m.policy_version + 1,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(plan.is_applied);
    assert!(
        plan.observed.active_denies.contains(&third_party),
        "third-party GPO entry must survive compound apply: {:?}",
        plan.observed.active_denies
    );
    assert!(
        plan.observed
            .active_denies
            .iter()
            .any(|id| id.to_ascii_uppercase().contains("KINGSTON")),
        "Kingston rule must be in GPO: {:?}",
        plan.observed.active_denies
    );

    // Simulate OS reboot where Windows GPO was externally cleared/drifted back to just third-party.
    MockGpo::write_entries(&h.pol.0, std::slice::from_ref(&third_party), &[], true);

    // Reopen fresh AppService over the same persisted database and run startup reconcile.
    let reopened = AppService::new(
        Store::open(&h.db_path, h.clock.clone()).unwrap(),
        h.clock.clone(),
        Box::new(h.inv.clone()),
        AppConfig {
            backend: BackendKind::WindowsService,
            allow_synthetic: false,
            backup_dir: None,
            database_location: "program_data".into(),
            app_version: "1.1.0-test".into(),
        },
        &default_policy_state().unwrap(),
    )
    .unwrap()
    .with_policy_source(Box::new(h.pol.clone()))
    .with_gpo_backend(h.gpo.clone())
    .with_windows_user_resolver(win_user_present)
    .with_app_auth(true);

    let outcome = reopened.reconcile_startup().unwrap();
    assert_eq!(outcome, "reconciled");

    let cap = h.pol.capture(h.clock.now_ms()).unwrap();
    let denies: Vec<String> = cap
        .values
        .values
        .iter()
        .filter(|(k, _)| k.key.to_ascii_uppercase().contains("DENYDEVICEIDS"))
        .filter_map(|(_, d)| match d {
            RegData::Sz(s) => Some(s.clone()),
            _ => None,
        })
        .collect();
    assert!(denies.contains(&third_party));
    assert!(denies.iter().any(|s| s.to_ascii_uppercase().contains("KINGSTON")));

    // Subsequent reconcile with zero drift reports already_in_sync without extra GPO write.
    let calls_before = *h.gpo.apply_calls.lock().unwrap();
    assert_eq!(reopened.reconcile_startup().unwrap(), "already_in_sync");
    assert_eq!(*h.gpo.apply_calls.lock().unwrap(), calls_before);

    // Disabling reconcile_on_startup skips reconciliation even after GPO drift.
    let (tok2, _) = match reopened
        .handle_with_token(
            &Request::Login {
                username: "secadmin".into(),
                password: "Strong!Admin#2026".into(),
            },
            &identity(true),
            None,
        )
        .unwrap()
    {
        ResponseBody::Login(l) => (l.session_token, l.user),
        _ => panic!(),
    };
    reopened
        .handle_with_token(
            &Request::UpdateSettings {
                settings: SettingsView {
                    reconcile_on_startup: false,
                    ..SettingsView::default()
                },
            },
            &identity(true),
            Some(&tok2),
        )
        .unwrap();
    MockGpo::write_entries(&h.pol.0, &[third_party], &[], true);
    assert_eq!(reopened.reconcile_startup().unwrap(), "skipped_disabled");
}

#[test]
fn phase6_bulk_manufacturer_preview_apply_preserves_custom_ids_and_overrides() {
    let h = harness("phase6", true);
    let (token, _) = setup_admin_session(&h.service);

    let ResponseBody::Manufacturers(m0) = h
        .service
        .handle_with_token(&Request::ListManufacturers, &identity(true), Some(&token))
        .unwrap()
    else {
        panic!();
    };
    // Add custom brand + identifier first.
    let ResponseBody::Mutation(m1) = h
        .service
        .handle_with_token(
            &Request::AddManufacturer {
                input: ManufacturerInput {
                    id: Some("customcorp".into()),
                    display_name: "CustomCorp".into(),
                    aliases: vec![],
                    identifiers: vec![BrandIdentifier {
                        kind: IdentifierKind::UsbVid,
                        value: "DEAD".into(),
                        verification: Verification::VendorDocumented,
                        source: "custom_admin".into(),
                    }],
                    notes: None,
                },
                allowed: true,
                expected_policy_version: m0.policy_version,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap()
    else {
        panic!();
    };

    // Preview ExplicitDenyAll before executing.
    let ResponseBody::BulkPreview(preview) = h
        .service
        .handle_with_token(
            &Request::PreviewBulkManufacturers {
                action: BulkManufacturerAction::ExplicitDenyAll,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(preview.total_manufacturers > 5);
    assert!(preview.manufacturers_changing > 0);
    assert!(preview.compiled_deny_ids_count > 0);

    // Apply bulk ExplicitDenyAll + Windows commit atomically.
    let ResponseBody::BulkApplyResult(applied) = h
        .service
        .handle_with_token(
            &Request::ApplyBulkManufacturers {
                action: BulkManufacturerAction::ExplicitDenyAll,
                apply_to_windows: true,
                retroactive: true,
                expected_policy_version: m1.policy_version,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(applied.applied_to_windows);
    assert!(applied.policy_version > m1.policy_version);

    // Custom identifier is untouched and CustomCorp now transitioned to denied.
    let ResponseBody::Manufacturers(after_m) = h
        .service
        .handle_with_token(&Request::ListManufacturers, &identity(true), Some(&token))
        .unwrap()
    else {
        panic!();
    };
    let custom = after_m
        .manufacturers
        .iter()
        .find(|x| x.id == "customcorp")
        .unwrap();
    assert!(custom.denied);
    assert!(custom.identifiers.iter().any(|i| i.value.contains("DEAD")));

    // Apply AllowAll then UnconfiguredAll (local draft).
    let ResponseBody::BulkApplyResult(allow_res) = h
        .service
        .handle_with_token(
            &Request::ApplyBulkManufacturers {
                action: BulkManufacturerAction::AllowAll,
                apply_to_windows: false,
                retroactive: true,
                expected_policy_version: applied.policy_version,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap()
    else {
        panic!();
    };
    let ResponseBody::BulkApplyResult(unc_res) = h
        .service
        .handle_with_token(
            &Request::ApplyBulkManufacturers {
                action: BulkManufacturerAction::UnconfiguredAll,
                apply_to_windows: false,
                retroactive: true,
                expected_policy_version: allow_res.policy_version,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(unc_res.manufacturers_updated > 0);
    assert!(!unc_res.applied_to_windows);
}

#[test]
fn phase9_10_12_13_notifications_audit_wts_about_and_honest_dashboard() {
    let h = harness("phase9-13", true);
    let (token, _) = setup_admin_session(&h.service);

    // Refresh while GPO is empty (no rules in Windows) -> Kingston is not denied in Windows yet.
    let ResponseBody::Manufacturers(m) = h
        .service
        .handle_with_token(&Request::ListManufacturers, &identity(true), Some(&token))
        .unwrap()
    else {
        panic!();
    };
    h.service
        .handle_with_token(
            &Request::SetManufacturerDenied {
                id: "sandisk".into(),
                denied: true,
                expected_policy_version: m.policy_version,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap();

    // With pending deny rule but no Windows GPO yet -> Dashboard reports pending_apply.
    let ResponseBody::Dashboard(dash_pending) = h
        .service
        .handle_with_token(&Request::GetDashboard, &identity(true), Some(&token))
        .unwrap()
    else {
        panic!();
    };
    assert_eq!(dash_pending.protection_category, "pending_apply");

    // Device refresh arrives without GPO enforcement -> usb_deny_not_enforced warning notification!
    h.service
        .handle_with_token(&Request::RefreshInventory, &identity(true), Some(&token))
        .unwrap();
    let ResponseBody::NotificationFeed(feed1) = h
        .service
        .handle_with_token(
            &Request::GetNotificationFeed {
                after_event_id: None,
            },
            &identity(false),
            None,
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(
        feed1
            .items
            .iter()
            .any(|n| n.category == "deny_not_enforced_warning" && !n.title_tr.contains("Engellendi")),
        "unblocked denied device must emit honest warning, never 'Engellendi': {:?}",
        feed1.items
    );

    // Apply GPO & set Kingston present=true, problem_code=Some(28).
    h.service
        .handle_with_token(
            &Request::ApplyCompoundPolicy {
                retroactive: true,
                expected_policy_version: m.policy_version + 1,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap();
    {
        let mut s = h.inv.0.lock().unwrap();
        let d = s
            .devices
            .iter_mut()
            .find(|d| d.instance_id.starts_with("USBSTOR\\DISK&VEN_KINGSTON"))
            .unwrap();
        d.present = Some(true);
        d.problem_code = Some(28);
    }
    h.service
        .handle_with_token(&Request::RefreshInventory, &identity(true), Some(&token))
        .unwrap();
    h.service
        .handle_with_token(
            &Request::GetEnforcementObservation,
            &identity(true),
            Some(&token),
        )
        .unwrap();

    // Feed after feed1.latest_event_id now emits verified "RustWard — USB Engellendi"!
    let ResponseBody::NotificationFeed(feed2) = h
        .service
        .handle_with_token(
            &Request::GetNotificationFeed {
                after_event_id: Some(feed1.latest_event_id),
            },
            &identity(false),
            None,
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(
        feed2
            .items
            .iter()
            .any(|n| n.category == "blocked_verified" && n.title_tr.contains("USB Engellendi")),
        "expected verified USB Engellendi toast item: {:?}",
        feed2.items
    );
    // Polling with new cursor returns zero duplicates.
    let ResponseBody::NotificationFeed(feed3) = h
        .service
        .handle_with_token(
            &Request::GetNotificationFeed {
                after_event_id: Some(feed2.latest_event_id),
            },
            &identity(false),
            None,
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(feed3.items.is_empty());

    // Dashboard now suppresses false "USB KORUMASI ETKİN DEĞİLDİR" / not-validated banner!
    let ResponseBody::Dashboard(dash_active) = h
        .service
        .handle_with_token(&Request::GetDashboard, &identity(true), Some(&token))
        .unwrap()
    else {
        panic!();
    };
    assert_eq!(dash_active.not_validated_banner, None);
    assert!(dash_active.protection_verified);
    assert!(
        matches!(
            dash_active.protection_category.as_str(),
            "protection_active" | "protection_partial" | "policy_applied_no_target"
        ),
        "unexpected category: {}",
        dash_active.protection_category
    );

    // Verify Audit chain, structured query, CSV export, and WTS attribution.
    let ResponseBody::AuditPage(page) = h
        .service
        .handle_with_token(
            &Request::QueryAuditEvents {
                query: EventQuery {
                    actor_username: Some("secadmin".into()),
                    limit: Some(10),
                    offset: Some(0),
                    ..EventQuery::default()
                },
            },
            &identity(true),
            Some(&token),
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(page.chain_ok);
    assert!(page.total_count > 0);
    assert!(!page.events.is_empty());

    let ResponseBody::AuditChainVerification(chain) = h
        .service
        .handle_with_token(&Request::VerifyAuditChain, &identity(true), Some(&token))
        .unwrap()
    else {
        panic!();
    };
    assert!(chain.intact);

    let ResponseBody::Export(csv) = h
        .service
        .handle_with_token(
            &Request::ExportEvents {
                query: EventQuery::default(),
                format: ExportFormat::Csv,
            },
            &identity(true),
            Some(&token),
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(csv.content.starts_with("id,utc,severity,kind,simulated"));
    assert!(csv.content.contains("actor_username"));

    // Ambiguous Windows session attribution test: resolver returning None leaves windows_user unset.
    let h_amb = AppService::new(
        Store::open_in_memory(h.clock.clone()).unwrap(),
        h.clock.clone(),
        Box::new(h.inv.clone()),
        AppConfig {
            backend: BackendKind::DevBackend,
            allow_synthetic: false,
            backup_dir: None,
            database_location: "memory".into(),
            app_version: "1.1.0-test".into(),
        },
        &default_policy_state().unwrap(),
    )
    .unwrap()
    .with_windows_user_resolver(win_user_ambiguous);
    h_amb.refresh_inventory().unwrap();
    let ResponseBody::AuditPage(amb_page) = h_amb
        .handle_with_token(
            &Request::QueryAuditEvents {
                query: EventQuery::default(),
            },
            &identity(true),
            None,
        )
        .unwrap()
    else {
        panic!();
    };
    assert!(
        amb_page
            .events
            .iter()
            .all(|e| e.windows_user.is_none()),
        "ambiguous Windows user must never guess SYSTEM/wrong user"
    );

    // Phase 12 About metadata must include Yunus İNAN and NO org-confidential project codenames.
    let ResponseBody::AboutInfo(about) = h
        .service
        .handle_with_token(&Request::GetAboutInfo, &identity(true), Some(&token))
        .unwrap()
    else {
        panic!();
    };
    assert_eq!(about.author, "Yunus İNAN");
    assert_eq!(
        about.tagline_tr,
        "Çevrimdışı USB Depolama Erişim Kontrolü ve Güvenlik Yönetimi"
    );
    let dumped = format!("{about:?}").to_ascii_lowercase();
    assert!(!dumped.contains("argon 4") && !dumped.contains("argon4"));
    assert!(!dumped.contains("phase"));
}
