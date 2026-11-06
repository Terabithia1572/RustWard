//! Controlled activation workflow — **gates only; activation stays refused.**
//!
//! This module defines what must be true before a future build may write
//! Windows Device Installation Restriction policy, and evaluates those gates
//! so the operator can see exactly which ones are open. It never activates
//! anything: [`request_activation`] refuses while [`crate::ACTIVATION_ENABLED`]
//! is `false`, and even with every gate met it can only hand the plan to
//! [`EnforcementProvider::activate`], which has no write path in this build.
//!
//! # Stages (never conflated)
//!
//! | Stage | Means | Claims protection? |
//! |---|---|---|
//! | [`ProtectionStage::DeviceDetection`] | devices were enumerated | no |
//! | [`ProtectionStage::ManufacturerClassification`] | storage scope + brand resolved | no |
//! | [`ProtectionStage::SimulatedAuthorization`] | allow/deny verdicts computed | no |
//! | [`ProtectionStage::PlannedEnforcement`] | exact registry values described | no |
//! | [`ProtectionStage::ActivatedWindowsPolicy`] | policy written (receipt) | no — not verified |
//! | [`ProtectionStage::VerifiedReadWriteDenial`] | read/write denial observed | **yes** |
//!
//! The last two require values ([`AppliedPolicyReceipt`],
//! [`VerificationEvidence`]) that have no public constructor and are not
//! `Deserialize`, so configuration state can never be promoted to
//! "protected".
//!
//! # Approval binding
//!
//! Operator confirmations carry the [`plan_fingerprint`] (SHA-256 over the
//! provider, workstation, policy version and every planned change). Any
//! change to the plan invalidates earlier confirmations.

use serde::Serialize;
use sha2::{Digest, Sha256};

use rustward_core::class_guids;
use rustward_core::classify::{DeviceCategory, classify};
use rustward_core::policy::PolicyMode;

use crate::{
    ActivationError, DryRunReport, EnforcementPlan, EnforcementProvider, PlanInputs,
    PreconditionStatus, VerificationEvidence,
};

/// Exact phrase the operator must type to confirm a disposable test
/// environment (the workstation id is appended: `"... PC-01"`).
pub const TEST_ENVIRONMENT_PHRASE: &str = "I CONFIRM THIS IS A DISPOSABLE TEST MACHINE";

/// Ordered protection stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionStage {
    /// Devices were enumerated (telemetry only).
    DeviceDetection,
    /// Storage scope and manufacturer were resolved.
    ManufacturerClassification,
    /// Allow/deny verdicts were computed; nothing is enforced.
    SimulatedAuthorization,
    /// The exact OS changes are described; nothing is written.
    PlannedEnforcement,
    /// OS policy was written; its effect is NOT yet verified.
    ActivatedWindowsPolicy,
    /// Read and write denial of an unauthorized device was observed.
    VerifiedReadWriteDenial,
}

impl ProtectionStage {
    /// Stable code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::DeviceDetection => "device_detection",
            Self::ManufacturerClassification => "manufacturer_classification",
            Self::SimulatedAuthorization => "simulated_authorization",
            Self::PlannedEnforcement => "planned_enforcement",
            Self::ActivatedWindowsPolicy => "activated_windows_policy",
            Self::VerifiedReadWriteDenial => "verified_read_write_denial",
        }
    }

    /// Only verified read/write denial is protection.
    #[must_use]
    pub fn claims_protection(self) -> bool {
        self == Self::VerifiedReadWriteDenial
    }

    /// Turkish label.
    #[must_use]
    pub fn label_tr(self) -> &'static str {
        match self {
            Self::DeviceDetection => "Aygıt algılama — koruma değil",
            Self::ManufacturerClassification => "Üretici sınıflandırması — koruma değil",
            Self::SimulatedAuthorization => "Simüle yetkilendirme — koruma değil",
            Self::PlannedEnforcement => "Planlanan uygulama — hiçbir şey yazılmadı",
            Self::ActivatedWindowsPolicy => "Windows politikası uygulandı — doğrulanmadı",
            Self::VerifiedReadWriteDenial => "Okuma/yazma engeli doğrulandı",
        }
    }
}

/// Receipt that OS policy was written. No public constructor and not
/// `Deserialize`; nothing in this build creates one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppliedPolicyReceipt {
    plan_fingerprint: String,
    applied_ms: i64,
}

impl AppliedPolicyReceipt {
    /// Fingerprint of the plan that was applied.
    #[must_use]
    pub fn plan_fingerprint(&self) -> &str {
        &self.plan_fingerprint
    }
    /// When it was applied.
    #[must_use]
    pub fn applied_ms(&self) -> i64 {
        self.applied_ms
    }
}

/// What is known about the pipeline on this workstation.
#[derive(Debug, Clone, Copy, Default)]
pub struct StageEvidence<'a> {
    /// Number of devices enumerated.
    pub devices_enumerated: usize,
    /// Classification ran.
    pub classified: bool,
    /// Simulated verdicts exist.
    pub simulated: bool,
    /// A dry-run plan exists.
    pub plan: Option<&'a EnforcementPlan>,
    /// OS policy receipt (never present in this build).
    pub applied: Option<&'a AppliedPolicyReceipt>,
    /// Observed denial (never present in this build).
    pub verified: Option<&'a VerificationEvidence>,
}

/// Highest stage reached. Each stage requires all earlier ones; verified
/// denial additionally requires a receipt for the *current* plan.
#[must_use]
pub fn highest_stage(e: &StageEvidence<'_>) -> Option<ProtectionStage> {
    if e.devices_enumerated == 0 {
        return None;
    }
    let mut stage = ProtectionStage::DeviceDetection;
    if !e.classified {
        return Some(stage);
    }
    stage = ProtectionStage::ManufacturerClassification;
    if !e.simulated {
        return Some(stage);
    }
    stage = ProtectionStage::SimulatedAuthorization;
    let Some(plan) = e.plan else {
        return Some(stage);
    };
    stage = ProtectionStage::PlannedEnforcement;
    let Some(receipt) = e.applied else {
        return Some(stage);
    };
    if receipt.plan_fingerprint != plan_fingerprint(plan) {
        // Applied policy no longer matches the plan: not even "activated".
        return Some(stage);
    }
    stage = ProtectionStage::ActivatedWindowsPolicy;
    if e.verified.is_some() {
        stage = ProtectionStage::VerifiedReadWriteDenial;
    }
    Some(stage)
}

#[derive(Serialize)]
struct FingerprintInput<'a> {
    provider_id: &'a str,
    workstation_id: &'a str,
    policy_version: u64,
    changes: &'a [crate::PlannedChange],
}

/// SHA-256 (lowercase hex) over the plan's identity and exact OS changes.
#[must_use]
pub fn plan_fingerprint(plan: &EnforcementPlan) -> String {
    let input = FingerprintInput {
        provider_id: &plan.provider_id,
        workstation_id: &plan.workstation_id,
        policy_version: plan.policy_version,
        changes: &plan.changes,
    };
    // Serialising plain strings/numbers cannot fail.
    let bytes = serde_json::to_vec(&input).unwrap_or_default();
    Sha256::digest(&bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Activation gates, in the order they are presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateId {
    /// The build contains an activation path (`ACTIVATION_ENABLED`).
    BuildPermitsActivation,
    /// Windows edition/build supported and Stages A–E accepted on this model.
    WindowsCompatibilityVerified,
    /// The caller is an elevated administrator (service-side check).
    AdministratorAuthorized,
    /// Operator typed the test-environment phrase for this workstation.
    TestEnvironmentConfirmed,
    /// Baseline inventory and a registered backup exist.
    BaselineSaved,
    /// Recovery procedure is printed/acknowledged and rollback data captured.
    RecoveryProcedureReady,
    /// Policy is in enforce mode, versions match, values documented.
    PolicyValidated,
    /// Every system/internal disk is protected by an instance-ID allow rule.
    SystemDisksProtected,
    /// The dry-run of this exact plan was reviewed and shows no gaps.
    DryRunReviewed,
    /// The operator confirmed this exact set of OS changes.
    ExactChangesConfirmed,
    /// Explicit, separate administrative approval for this plan.
    ExplicitApproval,
    /// Post-activation verification procedure is ready.
    PostActivationVerificationReady,
    /// Rollback (remove written values) is prepared and tested in the VM.
    RollbackReady,
}

impl GateId {
    /// Stable code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::BuildPermitsActivation => "build_permits_activation",
            Self::WindowsCompatibilityVerified => "windows_compatibility_verified",
            Self::AdministratorAuthorized => "administrator_authorized",
            Self::TestEnvironmentConfirmed => "test_environment_confirmed",
            Self::BaselineSaved => "baseline_saved",
            Self::RecoveryProcedureReady => "recovery_procedure_ready",
            Self::PolicyValidated => "policy_validated",
            Self::SystemDisksProtected => "system_disks_protected",
            Self::DryRunReviewed => "dry_run_reviewed",
            Self::ExactChangesConfirmed => "exact_changes_confirmed",
            Self::ExplicitApproval => "explicit_approval",
            Self::PostActivationVerificationReady => "post_activation_verification_ready",
            Self::RollbackReady => "rollback_ready",
        }
    }
}

/// One evaluated gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GateResult {
    /// Gate.
    pub id: GateId,
    /// Status.
    pub status: PreconditionStatus,
    /// Why (English, operator-facing).
    pub detail: String,
}

/// Operator inputs. Every confirmation that refers to the plan carries its
/// fingerprint so it cannot be reused for a different plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActivationRequest {
    /// Set by the service from the authenticated Windows identity, never by
    /// the UI.
    pub caller_is_elevated_administrator: bool,
    /// Acceptance record id for Stages A–E on this hardware model.
    pub windows_acceptance_record: Option<String>,
    /// Typed phrase: `TEST_ENVIRONMENT_PHRASE + " " + workstation_id`.
    pub test_environment_phrase: Option<String>,
    /// Registered backup file taken for this policy version.
    pub baseline_backup_file: Option<String>,
    /// Recovery procedure acknowledged and offline rollback data captured.
    pub recovery_procedure_acknowledged: bool,
    /// Fingerprint the operator reviewed the dry-run for.
    pub dry_run_reviewed_fingerprint: Option<String>,
    /// Fingerprint the operator confirmed the exact changes for.
    pub confirmed_changes_fingerprint: Option<String>,
    /// Fingerprint of the separate final approval.
    pub approval_fingerprint: Option<String>,
    /// Verification procedure (test devices on hand, write/read probe) ready.
    pub verification_procedure_ready: bool,
    /// Rollback tested in the VM for this build.
    pub rollback_tested: bool,
}

/// Result of gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActivationReadiness {
    /// Fingerprint of the evaluated plan.
    pub plan_fingerprint: String,
    /// All gates in order.
    pub gates: Vec<GateResult>,
    /// Every gate is `Met`.
    pub all_gates_met: bool,
}

impl ActivationReadiness {
    /// Ids of gates that are not met.
    #[must_use]
    pub fn open_gates(&self) -> Vec<String> {
        self.gates
            .iter()
            .filter(|g| g.status != PreconditionStatus::Met)
            .map(|g| g.id.code().to_owned())
            .collect()
    }
}

fn gate(id: GateId, ok: bool, detail: impl Into<String>) -> GateResult {
    GateResult {
        id,
        status: if ok {
            PreconditionStatus::Met
        } else {
            PreconditionStatus::NotMet
        },
        detail: detail.into(),
    }
}

fn precondition(plan: &EnforcementPlan, id: &str) -> PreconditionStatus {
    plan.preconditions
        .iter()
        .find(|p| p.id == id)
        .map_or(PreconditionStatus::Unknown, |p| p.status)
}

/// System-disk gate, computed from the baseline snapshot and the plan.
///
/// Met only if: the snapshot contains at least one non-USB disk; every such
/// disk has an `AllowInstanceIDs` entry; no disk has an unknown attachment
/// (it could be the system disk); and the class rule is not retroactive.
#[must_use]
pub fn system_disk_gate(plan: &EnforcementPlan, inputs: &PlanInputs<'_>) -> GateResult {
    let index = inputs.snapshot.index();
    let allowed: Vec<String> = plan
        .changes
        .iter()
        .filter(|c| c.key.ends_with("AllowInstanceIDs"))
        .map(|c| c.data.to_ascii_uppercase())
        .collect();
    let mut internal = 0usize;
    let mut problems = Vec::new();
    for d in &inputs.snapshot.devices {
        if !d.class_is(class_guids::DISK_DRIVE) {
            continue;
        }
        match classify(&index, d).category {
            DeviceCategory::SystemOrNonUsbStorage => {
                internal += 1;
                if !allowed.contains(&d.instance_id.to_ascii_uppercase()) {
                    problems.push(format!(
                        "internal disk without allow rule: {}",
                        d.instance_id
                    ));
                }
            }
            DeviceCategory::StorageAttachmentUnknown => problems.push(format!(
                "disk attachment unknown (could be the system disk): {}",
                d.instance_id
            )),
            _ => {}
        }
    }
    if internal == 0 {
        problems.push("no internal disk in the baseline snapshot: snapshot is incomplete".into());
    }
    if plan
        .changes
        .iter()
        .any(|c| c.value_name == "DenyDeviceClassesRetroactive" && c.data != "0")
    {
        problems.push("class prevent rule is retroactive".into());
    }
    if problems.is_empty() {
        gate(
            GateId::SystemDisksProtected,
            true,
            format!("{internal} internal disk(s) protected by instance-ID allow rules"),
        )
    } else {
        gate(GateId::SystemDisksProtected, false, problems.join("; "))
    }
}

/// Evaluate every gate. Pure: reads the plan, dry-run and inputs only.
#[must_use]
pub fn evaluate_gates(
    plan: &EnforcementPlan,
    dry_run: &DryRunReport,
    inputs: &PlanInputs<'_>,
    request: &ActivationRequest,
) -> ActivationReadiness {
    let fp = plan_fingerprint(plan);
    let same_fp = |v: &Option<String>| v.as_deref() == Some(fp.as_str());
    let policy = inputs.policy.policy();

    let os_ok = ["windows", "edition", "layering_supported"]
        .iter()
        .all(|id| precondition(plan, id) == PreconditionStatus::Met);
    let acceptance = request
        .windows_acceptance_record
        .as_deref()
        .is_some_and(|r| !r.trim().is_empty());
    let undocumented = plan
        .changes
        .iter()
        .filter(|c| !c.confirmed_against_documentation)
        .count();
    let expected_phrase = format!("{TEST_ENVIRONMENT_PHRASE} {}", plan.workstation_id);
    let baseline = inputs.env.baseline_captured
        && request
            .baseline_backup_file
            .as_deref()
            .is_some_and(|f| f.starts_with("rustward-"));
    let dry_clean = dry_run.enforcement_gaps.is_empty()
        && dry_run.over_blocking.is_empty()
        && (dry_run.already_installed_denied.is_empty() || inputs.env.installed_devices_reviewed);

    let gates = vec![
        gate(
            GateId::BuildPermitsActivation,
            crate::ACTIVATION_ENABLED,
            "ACTIVATION_ENABLED is false: this build has no activation path",
        ),
        gate(
            GateId::WindowsCompatibilityVerified,
            os_ok && acceptance && precondition(plan, "vm_validation") == PreconditionStatus::Met,
            format!(
                "OS preconditions met: {os_ok}; Stage A–E acceptance record: {acceptance}; VM validation precondition: {:?}",
                precondition(plan, "vm_validation")
            ),
        ),
        gate(
            GateId::AdministratorAuthorized,
            request.caller_is_elevated_administrator,
            "service-side Windows token check (elevated BUILTIN\\Administrators)",
        ),
        gate(
            GateId::TestEnvironmentConfirmed,
            request.test_environment_phrase.as_deref() == Some(expected_phrase.as_str()),
            format!("type exactly: \"{expected_phrase}\""),
        ),
        gate(
            GateId::BaselineSaved,
            baseline,
            "baseline inventory captured and a registered RustWard backup named",
        ),
        gate(
            GateId::RecoveryProcedureReady,
            request.recovery_procedure_acknowledged && !plan.recovery.is_empty(),
            format!("{} recovery steps in plan", plan.recovery.len()),
        ),
        gate(
            GateId::PolicyValidated,
            policy.mode == PolicyMode::Enforce
                && plan.policy_version == policy.policy_version
                && plan.workstation_id == policy.workstation_id
                && undocumented == 0,
            format!(
                "mode {:?}; plan v{} vs policy v{}; {undocumented} planned value(s) not yet confirmed against Microsoft documentation",
                policy.mode, plan.policy_version, policy.policy_version
            ),
        ),
        system_disk_gate(plan, inputs),
        gate(
            GateId::DryRunReviewed,
            same_fp(&request.dry_run_reviewed_fingerprint) && dry_clean,
            format!(
                "{} enforcement gap(s), {} over-blocking, {} already-installed denied device(s)",
                dry_run.enforcement_gaps.len(),
                dry_run.over_blocking.len(),
                dry_run.already_installed_denied.len()
            ),
        ),
        gate(
            GateId::ExactChangesConfirmed,
            same_fp(&request.confirmed_changes_fingerprint),
            format!("{} planned change(s), fingerprint {fp}", plan.changes.len()),
        ),
        gate(
            GateId::ExplicitApproval,
            same_fp(&request.approval_fingerprint),
            "separate final approval bound to the plan fingerprint",
        ),
        gate(
            GateId::PostActivationVerificationReady,
            request.verification_procedure_ready,
            "approved + unapproved test devices on hand; read/write probe procedure (docs/WINDOWS-VM-ACCEPTANCE.md Stage F)",
        ),
        gate(
            GateId::RollbackReady,
            request.rollback_tested,
            "removal of every written value tested in the VM for this build",
        ),
    ];
    let all_gates_met = gates.iter().all(|g| g.status == PreconditionStatus::Met);
    ActivationReadiness {
        plan_fingerprint: fp,
        gates,
        all_gates_met,
    }
}

/// Request activation. Refused unless the build permits activation, every
/// gate is met and the readiness was computed for this exact plan; then the
/// provider decides (and refuses in this build).
///
/// # Errors
/// Always in this build: [`ActivationError::ActivationDisabled`] or
/// [`ActivationError::PreconditionsNotMet`].
pub fn request_activation(
    provider: &dyn EnforcementProvider,
    plan: &EnforcementPlan,
    readiness: &ActivationReadiness,
) -> Result<(), ActivationError> {
    if !crate::ACTIVATION_ENABLED {
        return Err(ActivationError::ActivationDisabled);
    }
    if readiness.plan_fingerprint != plan_fingerprint(plan) {
        return Err(ActivationError::PreconditionsNotMet(vec![
            "plan_changed_since_gate_evaluation".into(),
        ]));
    }
    if !readiness.all_gates_met {
        return Err(ActivationError::PreconditionsNotMet(readiness.open_gates()));
    }
    provider.activate(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceInstallRestrictionProvider, EnvironmentFacts, SimulationOnlyProvider};
    use rustward_core::catalog::ValidatedCatalog;
    use rustward_core::device::DeviceSnapshot;
    use rustward_core::policy::ValidatedPolicy;

    const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
    const POLICY: &str = include_str!("../../../config/policy.example.json");
    const SNAPSHOT: &str = include_str!("../../../tests/fixtures/synthetic-lab-snapshot.json");

    fn with_inputs<R>(
        env: &EnvironmentFacts,
        edit: impl FnOnce(&mut DeviceSnapshot),
        f: impl FnOnce(PlanInputs<'_>) -> R,
    ) -> R {
        let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
        let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
        let mut snapshot = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
        edit(&mut snapshot);
        f(PlanInputs {
            policy: &policy,
            catalog: &catalog,
            snapshot: &snapshot,
            env,
        })
    }

    fn full_env() -> EnvironmentFacts {
        EnvironmentFacts {
            is_windows: true,
            os_build: Some((19045, 5011)),
            edition: Some("Professional".into()),
            baseline_captured: true,
            installed_devices_reviewed: true,
            feature_update_risk_acknowledged: true,
        }
    }

    /// Every operator input satisfied, bound to `fp`.
    fn everything(fp: &str, ws: &str) -> ActivationRequest {
        ActivationRequest {
            caller_is_elevated_administrator: true,
            windows_acceptance_record: Some("VM-ACC-001".into()),
            test_environment_phrase: Some(format!("{TEST_ENVIRONMENT_PHRASE} {ws}")),
            baseline_backup_file: Some("rustward-backup-1.db".into()),
            recovery_procedure_acknowledged: true,
            dry_run_reviewed_fingerprint: Some(fp.into()),
            confirmed_changes_fingerprint: Some(fp.into()),
            approval_fingerprint: Some(fp.into()),
            verification_procedure_ready: true,
            rollback_tested: true,
        }
    }

    fn status(r: &ActivationReadiness, id: GateId) -> PreconditionStatus {
        r.gates.iter().find(|g| g.id == id).unwrap().status
    }

    #[test]
    fn activation_is_refused_even_when_every_operator_input_is_given() {
        let env = full_env();
        with_inputs(
            &env,
            |_| {},
            |i| {
                let p = DeviceInstallRestrictionProvider;
                let plan = p.plan(i);
                let dry = p.dry_run(&plan, i);
                let fp = plan_fingerprint(&plan);
                let r = evaluate_gates(&plan, &dry, &i, &everything(&fp, &plan.workstation_id));
                assert!(!r.all_gates_met);
                assert_eq!(
                    status(&r, GateId::BuildPermitsActivation),
                    PreconditionStatus::NotMet
                );
                // Honest NotMet gates in this build, independent of operator input:
                assert_eq!(
                    status(&r, GateId::WindowsCompatibilityVerified),
                    PreconditionStatus::NotMet,
                    "vm_validation precondition is hard-wired NotMet"
                );
                assert_eq!(
                    status(&r, GateId::PolicyValidated),
                    PreconditionStatus::NotMet,
                    "example policy is not in enforce mode / values undocumented"
                );
                assert_eq!(
                    status(&r, GateId::DryRunReviewed),
                    PreconditionStatus::NotMet,
                    "synthetic snapshot has CD-ROM/MTP enforcement gaps"
                );
                assert_eq!(
                    request_activation(&p, &plan, &r),
                    Err(ActivationError::ActivationDisabled)
                );
                assert_eq!(
                    request_activation(&SimulationOnlyProvider, &plan, &r),
                    Err(ActivationError::ActivationDisabled)
                );
            },
        );
    }

    #[test]
    fn a_forged_readiness_is_still_refused() {
        let env = full_env();
        with_inputs(
            &env,
            |_| {},
            |i| {
                let plan = DeviceInstallRestrictionProvider.plan(i);
                let forged = ActivationReadiness {
                    plan_fingerprint: plan_fingerprint(&plan),
                    gates: Vec::new(),
                    all_gates_met: true,
                };
                assert_eq!(
                    request_activation(&DeviceInstallRestrictionProvider, &plan, &forged),
                    Err(ActivationError::ActivationDisabled)
                );
            },
        );
    }

    #[test]
    fn confirmations_are_bound_to_the_exact_plan() {
        let env = full_env();
        with_inputs(
            &env,
            |_| {},
            |i| {
                let p = DeviceInstallRestrictionProvider;
                let plan = p.plan(i);
                let dry = p.dry_run(&plan, i);
                let fp = plan_fingerprint(&plan);
                assert_eq!(fp.len(), 64);
                assert_eq!(fp, plan_fingerprint(&plan.clone()), "deterministic");

                let mut changed = plan.clone();
                changed.changes[0].data.push('X');
                let fp2 = plan_fingerprint(&changed);
                assert_ne!(fp, fp2, "any changed value changes the fingerprint");

                // Confirmations given for the old plan do not carry over.
                let r = evaluate_gates(&changed, &dry, &i, &everything(&fp, &plan.workstation_id));
                for g in [
                    GateId::ExactChangesConfirmed,
                    GateId::ExplicitApproval,
                    GateId::DryRunReviewed,
                ] {
                    assert_eq!(status(&r, g), PreconditionStatus::NotMet, "{g:?}");
                }
                let ok = evaluate_gates(&plan, &dry, &i, &everything(&fp, &plan.workstation_id));
                assert_eq!(
                    status(&ok, GateId::ExactChangesConfirmed),
                    PreconditionStatus::Met
                );
                assert_eq!(
                    status(&ok, GateId::ExplicitApproval),
                    PreconditionStatus::Met
                );
            },
        );
    }

    #[test]
    fn operator_gates_default_to_not_met() {
        let env = EnvironmentFacts::default();
        with_inputs(
            &env,
            |_| {},
            |i| {
                let p = DeviceInstallRestrictionProvider;
                let plan = p.plan(i);
                let dry = p.dry_run(&plan, i);
                let r = evaluate_gates(&plan, &dry, &i, &ActivationRequest::default());
                let met: Vec<_> = r
                    .gates
                    .iter()
                    .filter(|g| g.status == PreconditionStatus::Met)
                    .map(|g| g.id)
                    .collect();
                assert!(
                    met.is_empty(),
                    "nothing is met without operator input; the synthetic snapshot also \
                     contains a disk with a broken parent chain, which keeps the disk gate shut: {met:?}"
                );
                assert_eq!(r.open_gates().len(), r.gates.len());
                // Wrong workstation in the phrase.
                let req = ActivationRequest {
                    test_environment_phrase: Some(format!("{TEST_ENVIRONMENT_PHRASE} OTHER-PC")),
                    ..ActivationRequest::default()
                };
                let r = evaluate_gates(&plan, &dry, &i, &req);
                assert_eq!(
                    status(&r, GateId::TestEnvironmentConfirmed),
                    PreconditionStatus::NotMet
                );
            },
        );
    }

    #[test]
    fn system_disk_gate_detects_unprotected_and_unknown_disks() {
        let env = full_env();
        // The fixture as shipped contains a disk with a broken parent chain:
        // fail closed.
        with_inputs(
            &env,
            |_| {},
            |i| {
                let plan = DeviceInstallRestrictionProvider.plan(i);
                let g = system_disk_gate(&plan, &i);
                assert_eq!(g.status, PreconditionStatus::NotMet);
                assert!(g.detail.contains("PSSD_T7"), "{}", g.detail);
            },
        );
        // Without it: internal disks protected by the plan.
        with_inputs(
            &env,
            |s| s.devices.retain(|d| !d.instance_id.contains("PSSD_T7")),
            |i| {
                let plan = DeviceInstallRestrictionProvider.plan(i);
                let g = system_disk_gate(&plan, &i);
                assert_eq!(g.status, PreconditionStatus::Met, "{}", g.detail);

                // The plan lost the allow rule for the system disk.
                let mut stripped = plan.clone();
                stripped
                    .changes
                    .retain(|c| !c.key.ends_with("AllowInstanceIDs"));
                assert_eq!(
                    system_disk_gate(&stripped, &i).status,
                    PreconditionStatus::NotMet
                );

                // A retroactive class rule is never acceptable.
                let mut retro = plan.clone();
                for c in &mut retro.changes {
                    if c.value_name == "DenyDeviceClassesRetroactive" {
                        c.data = "1".into();
                    }
                }
                let g = system_disk_gate(&retro, &i);
                assert_eq!(g.status, PreconditionStatus::NotMet);
                assert!(g.detail.contains("retroactive"));
            },
        );
        // A disk whose parent chain is broken may be the system disk.
        with_inputs(
            &env,
            |s| {
                s.devices.retain(|d| !d.instance_id.contains("PSSD_T7"));
                let disk = s
                    .devices
                    .iter_mut()
                    .find(|d| {
                        d.class_is(class_guids::DISK_DRIVE) && !d.instance_id.starts_with("USBSTOR")
                    })
                    .unwrap();
                disk.parent_instance_id = Some("PCI\\MISSING\\0".into());
            },
            |i| {
                let plan = DeviceInstallRestrictionProvider.plan(i);
                let g = system_disk_gate(&plan, &i);
                assert_eq!(g.status, PreconditionStatus::NotMet);
                assert!(g.detail.contains("attachment unknown"), "{}", g.detail);
            },
        );
        // No internal disk at all: snapshot incomplete.
        with_inputs(
            &env,
            |s| {
                let idx = s.index();
                let keep: Vec<_> = s
                    .devices
                    .iter()
                    .map(|d| {
                        !(d.class_is(class_guids::DISK_DRIVE)
                            && classify(&idx, d).category == DeviceCategory::SystemOrNonUsbStorage)
                    })
                    .collect();
                let mut it = keep.into_iter();
                s.devices.retain(|_| it.next().unwrap_or(true));
            },
            |i| {
                let plan = DeviceInstallRestrictionProvider.plan(i);
                let g = system_disk_gate(&plan, &i);
                assert_eq!(g.status, PreconditionStatus::NotMet);
                assert!(g.detail.contains("incomplete"));
            },
        );
    }

    #[test]
    fn stages_are_ordered_and_only_verified_denial_claims_protection() {
        let env = EnvironmentFacts::default();
        with_inputs(
            &env,
            |_| {},
            |i| {
                let plan = DeviceInstallRestrictionProvider.plan(i);
                let none = StageEvidence::default();
                assert_eq!(highest_stage(&none), None);
                let mut e = StageEvidence {
                    devices_enumerated: 3,
                    ..StageEvidence::default()
                };
                assert_eq!(highest_stage(&e), Some(ProtectionStage::DeviceDetection));
                e.classified = true;
                assert_eq!(
                    highest_stage(&e),
                    Some(ProtectionStage::ManufacturerClassification)
                );
                e.simulated = true;
                assert_eq!(
                    highest_stage(&e),
                    Some(ProtectionStage::SimulatedAuthorization)
                );
                e.plan = Some(&plan);
                assert_eq!(highest_stage(&e), Some(ProtectionStage::PlannedEnforcement));

                // Evidence without a receipt never jumps to verified.
                let ev = VerificationEvidence::for_tests("T");
                e.verified = Some(&ev);
                assert_eq!(highest_stage(&e), Some(ProtectionStage::PlannedEnforcement));

                // A receipt for a different plan is ignored.
                let stale = AppliedPolicyReceipt {
                    plan_fingerprint: "0".repeat(64),
                    applied_ms: 1,
                };
                e.applied = Some(&stale);
                assert_eq!(highest_stage(&e), Some(ProtectionStage::PlannedEnforcement));

                let receipt = AppliedPolicyReceipt {
                    plan_fingerprint: plan_fingerprint(&plan),
                    applied_ms: 1,
                };
                e.applied = Some(&receipt);
                e.verified = None;
                assert_eq!(
                    highest_stage(&e),
                    Some(ProtectionStage::ActivatedWindowsPolicy)
                );
                assert!(!ProtectionStage::ActivatedWindowsPolicy.claims_protection());
                e.verified = Some(&ev);
                assert_eq!(
                    highest_stage(&e),
                    Some(ProtectionStage::VerifiedReadWriteDenial)
                );

                let claims: Vec<_> = [
                    ProtectionStage::DeviceDetection,
                    ProtectionStage::ManufacturerClassification,
                    ProtectionStage::SimulatedAuthorization,
                    ProtectionStage::PlannedEnforcement,
                    ProtectionStage::ActivatedWindowsPolicy,
                    ProtectionStage::VerifiedReadWriteDenial,
                ]
                .into_iter()
                .filter(|s| s.claims_protection())
                .collect();
                assert_eq!(claims, [ProtectionStage::VerifiedReadWriteDenial]);
            },
        );
    }
}
