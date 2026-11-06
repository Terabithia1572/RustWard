//! Destructive-operation tests against a **mock** Windows policy backend.
//!
//! `MockRegistry` is an in-memory stand-in for the Restrictions key that
//! applies [`RegOp`]s one at a time and can be told to fail at a given
//! operation (simulating an interrupted write, a crash or an access error).
//! It exists only in this test file: RustWard has no code that writes the
//! real registry, and `ACTIVATION_ENABLED` stays `false`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::device::DeviceSnapshot;
use rustward_core::policy::ValidatedPolicy;
use rustward_enforcement::activation::{
    ActivationRequest, GateId, ProtectionStage, StageEvidence, evaluate_gates, highest_stage,
    plan_fingerprint, request_activation,
};
use rustward_enforcement::device_install::RESTRICTIONS_KEY;
use rustward_enforcement::policy_inspect::{PlanPresence, plan_presence};
use rustward_enforcement::policy_state::{
    PolicySnapshot, RegData, RegOp, apply_ops, forward_ops, merge_plan, rollback_ops,
};
use rustward_enforcement::{
    ActivationError, DeviceInstallRestrictionProvider, EnforcementPlan, EnforcementProvider,
    EnvironmentFacts, PlanInputs, PreconditionStatus,
};

const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
const POLICY: &str = include_str!("../../../config/policy.example.json");
const SNAPSHOT: &str = include_str!("../../../tests/fixtures/synthetic-lab-snapshot.json");

/// In-memory registry with fault injection.
#[derive(Debug, Clone, Default)]
struct MockRegistry {
    state: PolicySnapshot,
    /// Fail when this many operations have been applied in the current call.
    fail_after: Option<usize>,
    applied_total: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct Interrupted {
    applied: usize,
}

impl MockRegistry {
    fn with(state: PolicySnapshot) -> Self {
        Self {
            state,
            ..Self::default()
        }
    }
    /// Apply operations in order; stop at the injected failure.
    fn apply(&mut self, ops: &[RegOp]) -> Result<(), Interrupted> {
        for (n, op) in ops.iter().enumerate() {
            if self.fail_after == Some(n) {
                self.fail_after = None;
                return Err(Interrupted { applied: n });
            }
            self.state = apply_ops(&self.state, std::slice::from_ref(op));
            self.applied_total += 1;
        }
        Ok(())
    }
    /// Read-only capture.
    fn capture(&self) -> PolicySnapshot {
        self.state.clone()
    }
}

fn sub(list: &str) -> String {
    format!(r"{RESTRICTIONS_KEY}\{list}")
}

fn plan() -> EnforcementPlan {
    let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
    let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
    let mut s = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
    s.devices.retain(|d| !d.instance_id.contains("PSSD_T7"));
    DeviceInstallRestrictionProvider.plan(PlanInputs {
        policy: &policy,
        catalog: &catalog,
        snapshot: &s,
        env: &EnvironmentFacts::default(),
    })
}

/// A handful of realistic pre-existing configurations.
fn baselines() -> Vec<PolicySnapshot> {
    vec![
        PolicySnapshot::default(),
        PolicySnapshot::default().with(RESTRICTIONS_KEY, "AllowDenyLayered", RegData::Dword(0)),
        PolicySnapshot::default()
            .with(RESTRICTIONS_KEY, "AllowDeviceIDs", RegData::Dword(1))
            .with(
                &sub("AllowDeviceIDs"),
                "1",
                RegData::Sz("USBPRINT\\SYNTHETIC0001".into()),
            )
            .with(
                &sub("AllowDeviceIDs"),
                "2",
                RegData::Sz("HID\\VID_FFFF&PID_0001".into()),
            ),
        PolicySnapshot::default()
            .with(RESTRICTIONS_KEY, "DenyDeviceClasses", RegData::Dword(0))
            .with(
                &sub("DenyDeviceClasses"),
                "1",
                RegData::Sz("{6bdd1fc6-810f-11d0-bec7-08002be2092f}".into()),
            )
            .with(
                RESTRICTIONS_KEY,
                "Unrelated",
                RegData::Other {
                    reg_type: 3,
                    bytes: 16,
                },
            ),
    ]
}

#[test]
fn interrupted_application_is_detected_as_partial_and_rolled_back_exactly() {
    for before in baselines() {
        let merged = merge_plan(&before, &plan());
        let forward = forward_ops(&before, &merged).unwrap();
        assert!(forward.len() > 3);
        for stop in 1..forward.len() {
            let mut reg = MockRegistry::with(before.clone());
            reg.fail_after = Some(stop);
            assert_eq!(reg.apply(&forward), Err(Interrupted { applied: stop }));
            // The read-only inspection reports the interruption.
            assert!(
                matches!(
                    plan_presence(&reg.capture(), &merged),
                    PlanPresence::Partial { .. }
                ),
                "stop at {stop}"
            );
            // The rollback computed from the captured baseline undoes every
            // touched value, including those never reached.
            reg.apply(&rollback_ops(&before, &forward)).unwrap();
            assert_eq!(reg.capture(), before, "stop at {stop}");
        }
    }
}

#[test]
fn an_interrupted_rollback_can_be_resumed_to_the_exact_baseline() {
    for before in baselines() {
        let merged = merge_plan(&before, &plan());
        let forward = forward_ops(&before, &merged).unwrap();
        let rollback = rollback_ops(&before, &forward);
        let mut reg = MockRegistry::with(before.clone());
        reg.apply(&forward).unwrap();
        assert_eq!(
            plan_presence(&reg.capture(), &merged),
            PlanPresence::PolicyValuesPresent
        );
        reg.fail_after = Some(rollback.len() / 2);
        assert!(reg.apply(&rollback).is_err());
        assert_ne!(reg.capture(), before);
        // Rollback operations are idempotent: running all of them again
        // finishes the job.
        reg.apply(&rollback).unwrap();
        assert_eq!(reg.capture(), before);
    }
}

#[test]
fn apply_then_rollback_never_touches_unrelated_values() {
    for before in baselines() {
        let merged = merge_plan(&before, &plan());
        let forward = forward_ops(&before, &merged).unwrap();
        let mut reg = MockRegistry::with(before.clone());
        reg.apply(&forward).unwrap();
        let after = reg.capture();
        for (at, data) in &before.values {
            let planned = forward
                .iter()
                .any(|op| matches!(op, RegOp::Set { at: a, .. } if a == at));
            if !planned {
                assert_eq!(
                    after.values.get(at),
                    Some(data),
                    "unrelated value {at:?} changed"
                );
            }
        }
        // Every pre-existing list entry survives at its index.
        for list in ["AllowDeviceIDs", "DenyDeviceClasses"] {
            for (i, v) in before.list(list) {
                assert_eq!(after.list(list).get(&i), Some(&v));
            }
        }
    }
}

#[test]
fn a_plan_approved_before_the_policy_changed_is_stale() {
    let base = PolicySnapshot::default();
    let p = plan();
    let approved = merge_plan(&base, &p);
    let fp = plan_fingerprint(&approved);
    // Meanwhile an administrator adds an entry: the merged plan changes.
    let changed = base
        .with(RESTRICTIONS_KEY, "AllowDeviceIDs", RegData::Dword(1))
        .with(
            &sub("AllowDeviceIDs"),
            "1",
            RegData::Sz("USBPRINT\\NEW".into()),
        );
    let current = merge_plan(&changed, &p);
    assert_ne!(
        plan_fingerprint(&current),
        fp,
        "fingerprint follows the merged plan"
    );

    let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
    let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
    let snapshot = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
    let env = EnvironmentFacts::default();
    let inputs = PlanInputs {
        policy: &policy,
        catalog: &catalog,
        snapshot: &snapshot,
        env: &env,
    };
    let dry = DeviceInstallRestrictionProvider.dry_run(&current, inputs);
    let request = ActivationRequest {
        caller_is_elevated_administrator: true,
        confirmed_changes_fingerprint: Some(fp.clone()),
        approval_fingerprint: Some(fp),
        existing_policy: Some(changed),
        ..ActivationRequest::default()
    };
    let r = evaluate_gates(&current, &dry, &inputs, &request);
    let status = |id: GateId| r.gates.iter().find(|g| g.id == id).unwrap().status;
    assert_eq!(
        status(GateId::ExactChangesConfirmed),
        PreconditionStatus::NotMet
    );
    assert_eq!(status(GateId::ExplicitApproval), PreconditionStatus::NotMet);
    assert_eq!(
        request_activation(&DeviceInstallRestrictionProvider, &current, &r),
        Err(ActivationError::ActivationDisabled)
    );
}

#[test]
fn authorization_failures_keep_the_administrator_gate_shut() {
    let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
    let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
    let snapshot = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
    let env = EnvironmentFacts::default();
    let inputs = PlanInputs {
        policy: &policy,
        catalog: &catalog,
        snapshot: &snapshot,
        env: &env,
    };
    let p = DeviceInstallRestrictionProvider.plan(inputs);
    let dry = DeviceInstallRestrictionProvider.dry_run(&p, inputs);
    for caller_is_elevated_administrator in [false, true] {
        let r = evaluate_gates(
            &p,
            &dry,
            &inputs,
            &ActivationRequest {
                caller_is_elevated_administrator,
                ..ActivationRequest::default()
            },
        );
        let g = r
            .gates
            .iter()
            .find(|g| g.id == GateId::AdministratorAuthorized)
            .unwrap();
        assert_eq!(
            g.status == PreconditionStatus::Met,
            caller_is_elevated_administrator
        );
        assert!(!r.all_gates_met);
    }
}

#[test]
fn policy_values_present_is_never_verified_protection() {
    // Even with every plan value in place (mock backend), there is no
    // receipt and no verification evidence: the stage stays "planned".
    let p = merge_plan(&PolicySnapshot::default(), &plan());
    let mut reg = MockRegistry::default();
    reg.apply(&forward_ops(&PolicySnapshot::default(), &p).unwrap())
        .unwrap();
    assert_eq!(
        plan_presence(&reg.capture(), &p),
        PlanPresence::PolicyValuesPresent
    );
    let stage = highest_stage(&StageEvidence {
        devices_enumerated: 10,
        classified: true,
        simulated: true,
        plan: Some(&p),
        applied: None,
        verified: None,
    });
    assert_eq!(stage, Some(ProtectionStage::PlannedEnforcement));
    assert!(!stage.unwrap().claims_protection());
    const { assert!(!rustward_enforcement::ACTIVATION_ENABLED) };
}

#[test]
fn a_verification_failure_is_reported_not_hidden() {
    // A mock "write" that silently dropped one value: the read-back shows a
    // partial state, so a verification step built on plan_presence fails.
    let p = merge_plan(&PolicySnapshot::default(), &plan());
    let mut forward = forward_ops(&PolicySnapshot::default(), &p).unwrap();
    let dropped = forward.remove(2);
    let mut reg = MockRegistry::default();
    reg.apply(&forward).unwrap();
    match plan_presence(&reg.capture(), &p) {
        PlanPresence::Partial {
            missing, different, ..
        } => assert_eq!((missing, different), (1, 0)),
        other => panic!("{other:?} (dropped {dropped:?})"),
    }
    // A value overwritten by someone else afterwards is detected as different.
    let mut reg2 = MockRegistry::default();
    reg2.apply(&forward_ops(&PolicySnapshot::default(), &p).unwrap())
        .unwrap();
    reg2.apply(&[RegOp::Set {
        at: rustward_enforcement::policy_state::ValueRef::new(RESTRICTIONS_KEY, "AllowDenyLayered"),
        data: RegData::Dword(0),
    }])
    .unwrap();
    assert!(matches!(
        plan_presence(&reg2.capture(), &p),
        PlanPresence::Partial { different: 1, .. }
    ));
}

#[test]
fn installed_assessment_against_mock_policy_is_read_only_and_storage_only() {
    use rustward_enforcement::installed_assessment::{AssessmentInputs, Finding, assess};
    let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
    let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
    let snapshot = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
    let p = plan();
    for base in baselines() {
        let reg = MockRegistry::with(base.clone());
        let before = reg.capture();
        let a = assess(&AssessmentInputs {
            snapshot: &snapshot,
            policy: &policy,
            catalog: &catalog,
            plan: &p,
            existing: &reg.capture(),
            sanitize: true,
        });
        // Assessment never writes (the mock saw zero operations).
        assert_eq!(reg.applied_total, 0);
        assert_eq!(reg.capture(), before);
        assert!(a.manual_only);
        assert!(a.sanitized);
        assert!(!a.devices.is_empty());
        assert!(a.summary.denied_but_installed > 0, "{:?}", a.summary);
        // Keyboards, mice, printers and hubs are never assessed.
        for d in &a.devices {
            for word in ["HID\\", "USBPRINT\\", "ROOT_HUB"] {
                assert!(!d.instance_id.contains(word), "{}", d.instance_id);
            }
        }
        // Internal disks are never offered remediation.
        for d in a
            .devices
            .iter()
            .filter(|d| d.finding == Finding::InternalDiskProtected)
        {
            assert!(d.remediation.is_empty(), "{}", d.instance_id);
        }
        // Install-time restrictions are not retroactive: a denied device that
        // is already installed stays accessible after (modelled) activation.
        for d in a
            .devices
            .iter()
            .filter(|d| d.finding == Finding::DeniedButInstalled)
        {
            assert!(d.remains_accessible_after_activation);
            assert!(!d.remediation.is_empty());
        }
    }
}
