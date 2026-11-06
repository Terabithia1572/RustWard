//! Enforcement provider architecture. **DRY-RUN ONLY in this build.**
//!
//! The pipeline is split into four separately typed stages so that no stage
//! can be mistaken for another:
//!
//! 1. **Policy decision** — `rustward-core::evaluate` (simulated verdicts).
//! 2. **Planned OS change** — [`EnforcementPlan`] with [`PlannedChange`]s
//!    (descriptions of registry policy values; never written here).
//! 3. **Activation** — [`EnforcementProvider::activate`]; always returns
//!    [`ActivationError::ActivationDisabled`] because
//!    [`ACTIVATION_ENABLED`] is `false` and this crate contains no code that
//!    can write the registry or Group Policy (a test enforces it).
//! 4. **Verification** — only [`VerificationEvidence`] can produce
//!    [`EnforcementState::VerifiedProtected`]; it has no public constructor
//!    and nothing in this build creates one.
//!
//! Failure never degrades to "allow": a provider that fails reports
//! `Degraded`/`Error`, and the UI must show protection as not verified.

#![forbid(unsafe_code)]

pub mod activation;
pub mod device_install;

use serde::{Deserialize, Serialize};

pub use device_install::DeviceInstallRestrictionProvider;

/// Compile-time switch for OS policy activation. Must stay `false` until the
/// Windows VM acceptance phase; changing it requires implementing an
/// activation path, which does not exist in this build.
pub const ACTIVATION_ENABLED: bool = false;

/// Opaque proof that the security property was observed at runtime.
/// No public constructor; nothing in this build creates one.
///
/// Deliberately **not** `Deserialize`: evidence must never be forged from
/// JSON received over IPC or read from a file (Phase 9A finding F-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationEvidence {
    evidence_id: String,
    observed_property: String,
}

impl VerificationEvidence {
    /// Evidence id (audit reference).
    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }
    /// Observed property.
    #[must_use]
    pub fn observed_property(&self) -> &str {
        &self.observed_property
    }
    #[cfg(test)]
    pub(crate) fn for_tests(id: &str) -> Self {
        Self {
            evidence_id: id.into(),
            observed_property: "test".into(),
        }
    }
}

/// Workstation enforcement state shown to operators.
///
/// Not `Deserialize` for the same reason as [`VerificationEvidence`]: a
/// `VerifiedProtected` state can only be produced inside the process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EnforcementState {
    /// No enforcement provider configured.
    NotConfigured,
    /// Decisions are simulated; nothing is enforced.
    Simulated,
    /// A plan exists and awaits VM/hardware validation; nothing is enforced.
    PendingValidation,
    /// OS policy applied but its effect not verified.
    ActiveUnverified,
    /// Enforcement observed to work.
    VerifiedProtected {
        /// Evidence.
        evidence: VerificationEvidence,
    },
    /// Partially working; protection must be treated as not verified.
    Degraded {
        /// Reason.
        reason: String,
    },
    /// Provider failed; protection must be treated as not verified.
    Error {
        /// Reason.
        reason: String,
    },
}

impl EnforcementState {
    /// Stable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Simulated => "simulated",
            Self::PendingValidation => "pending_validation",
            Self::ActiveUnverified => "active_unverified",
            Self::VerifiedProtected { .. } => "verified_protected",
            Self::Degraded { .. } => "degraded",
            Self::Error { .. } => "error",
        }
    }

    /// True only for verified protection.
    #[must_use]
    pub fn is_verified_protection(&self) -> bool {
        matches!(self, Self::VerifiedProtected { .. })
    }

    /// Turkish label.
    #[must_use]
    pub fn label_tr(&self) -> &'static str {
        match self {
            Self::NotConfigured => "Uygulama sağlayıcısı yapılandırılmadı",
            Self::Simulated => "Yalnızca simülasyon — koruma etkin değil",
            Self::PendingValidation => "Doğrulama bekleniyor — koruma etkin değil",
            Self::ActiveUnverified => "Uygulandı, doğrulanmadı",
            Self::VerifiedProtected { .. } => "Koruma etkin ve doğrulandı",
            Self::Degraded { .. } => "Kısmen çalışıyor — koruma doğrulanmadı",
            Self::Error { .. } => "Hata — koruma doğrulanmadı",
        }
    }

    /// English label.
    #[must_use]
    pub fn label_en(&self) -> &'static str {
        match self {
            Self::NotConfigured => "No enforcement provider configured",
            Self::Simulated => "Simulation only — protection not active",
            Self::PendingValidation => "Pending validation — protection not active",
            Self::ActiveUnverified => "Applied, not verified",
            Self::VerifiedProtected { .. } => "Protection active and verified",
            Self::Degraded { .. } => "Degraded — protection not verified",
            Self::Error { .. } => "Error — protection not verified",
        }
    }
}

/// Status of one capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Not implemented in this build.
    NotImplemented,
    /// The mechanism cannot provide this (documented limitation).
    Unsupported,
    /// Designed and planned; requires Windows validation.
    DesignedNotVerified,
    /// Implemented and verified with evidence.
    Verified,
}

/// What a provider can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// Provider id.
    pub provider_id: String,
    /// Blocks unauthorized storage before it becomes readable.
    pub pre_access_blocking: CapabilityStatus,
    /// Brand-level allowlisting.
    pub brand_allowlisting: CapabilityStatus,
    /// Handles devices installed before activation.
    pub previously_installed_devices: CapabilityStatus,
    /// Survives UI exit, service stop, reboot.
    pub persistence: CapabilityStatus,
    /// Can prove its own effect.
    pub self_verification: CapabilityStatus,
    /// OS policy activation available in this build.
    pub activation_available: bool,
}

/// Facts about the target environment used for precondition checks.
/// Unknown values are `None` and make the related precondition `Unknown`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentFacts {
    /// Running on Windows.
    pub is_windows: bool,
    /// OS build number and UBR, e.g. (19045, 4291).
    pub os_build: Option<(u32, u32)>,
    /// Edition, e.g. `Professional`.
    pub edition: Option<String>,
    /// A baseline device snapshot (incl. non-present) was captured.
    pub baseline_captured: bool,
    /// Already-installed unauthorized USB storage has been reviewed.
    pub installed_devices_reviewed: bool,
    /// Administrator acknowledged feature-update / driver-reinstall risk.
    pub feature_update_risk_acknowledged: bool,
}

/// Precondition outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconditionStatus {
    /// Satisfied.
    Met,
    /// Not satisfied.
    NotMet,
    /// Cannot be determined here.
    Unknown,
}

/// A precondition for activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Precondition {
    /// Stable id.
    pub id: String,
    /// English description.
    pub en: String,
    /// Turkish description.
    pub tr: String,
    /// Status.
    pub status: PreconditionStatus,
}

/// A planned registry policy value. **Description only — never written by
/// this build.**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedChange {
    /// Hive.
    pub hive: String,
    /// Key path below the hive.
    pub key: String,
    /// Value name.
    pub value_name: String,
    /// `REG_DWORD` or `REG_SZ`.
    pub value_type: String,
    /// Data as text.
    pub data: String,
    /// Why.
    pub purpose: String,
    /// Whether the value name/semantics were confirmed against Microsoft
    /// ADMX/CSP documentation (`false` = must be confirmed in the VM phase).
    pub confirmed_against_documentation: bool,
}

/// One recovery step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStep {
    /// Order.
    pub order: u32,
    /// English.
    pub en: String,
    /// Turkish.
    pub tr: String,
}

/// Plan mode. Only dry-run exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanMode {
    /// Describe only.
    DryRun,
}

/// A complete enforcement plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPlan {
    /// Provider.
    pub provider_id: String,
    /// Always dry-run.
    pub mode: PlanMode,
    /// Workstation.
    pub workstation_id: String,
    /// Policy version.
    pub policy_version: u64,
    /// Planned OS changes (not applied).
    pub changes: Vec<PlannedChange>,
    /// Preconditions.
    pub preconditions: Vec<Precondition>,
    /// Risks the administrator must accept.
    pub risks: Vec<String>,
    /// Recovery steps.
    pub recovery: Vec<RecoveryStep>,
    /// Always false in this build.
    pub activation_allowed: bool,
}

/// Dry-run evaluation of a plan against an inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunReport {
    /// Devices the modelled OS rules would leave unblocked although the
    /// policy denies them (scope gaps).
    pub enforcement_gaps: Vec<String>,
    /// Devices the modelled OS rules would block although the policy
    /// does not deny them.
    pub over_blocking: Vec<String>,
    /// Denied devices already installed: install-time rules would NOT block
    /// them without a reviewed baseline cleanup.
    pub already_installed_denied: Vec<String>,
    /// Summary lines.
    pub notes: Vec<String>,
}

/// Activation refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ActivationError {
    /// This build cannot activate OS policy.
    #[error("activation is disabled in this build (dry-run only)")]
    ActivationDisabled,
    /// Preconditions not met.
    #[error("preconditions not met: {}", .0.join(", "))]
    PreconditionsNotMet(Vec<String>),
}

/// Audit record produced by a provider (stored by the application layer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAuditRecord {
    /// Event kind (`[a-z_]+`).
    pub kind: String,
    /// `info`, `warning` or `critical`.
    pub severity: String,
    /// Message.
    pub message: String,
    /// Details object.
    pub details: serde_json::Value,
}

/// Inputs for planning.
#[derive(Debug, Clone, Copy)]
pub struct PlanInputs<'a> {
    /// Validated policy.
    pub policy: &'a rustward_core::policy::ValidatedPolicy,
    /// Validated catalog.
    pub catalog: &'a rustward_core::catalog::ValidatedCatalog,
    /// Baseline / current inventory.
    pub snapshot: &'a rustward_core::device::DeviceSnapshot,
    /// Environment facts.
    pub env: &'a EnvironmentFacts,
}

/// An enforcement provider.
pub trait EnforcementProvider {
    /// Stable id.
    fn id(&self) -> &'static str;
    /// Capabilities in an environment.
    fn capabilities(&self, env: &EnvironmentFacts) -> CapabilityReport;
    /// Build a dry-run plan.
    fn plan(&self, inputs: PlanInputs<'_>) -> EnforcementPlan;
    /// Evaluate a plan against decisions without changing anything.
    fn dry_run(&self, plan: &EnforcementPlan, inputs: PlanInputs<'_>) -> DryRunReport;
    /// Attempt activation. Always refused in this build.
    fn activate(&self, plan: &EnforcementPlan) -> Result<(), ActivationError>;
    /// Current state.
    fn status(&self) -> EnforcementState;
    /// Audit record describing a plan/dry-run/activation attempt.
    fn audit(
        &self,
        what: &str,
        plan: &EnforcementPlan,
        result: Result<(), &ActivationError>,
    ) -> ProviderAuditRecord {
        ProviderAuditRecord {
            kind: format!("enforcement_{what}"),
            severity: if result.is_ok() { "info" } else { "warning" }.into(),
            message: match result {
                Ok(()) => format!(
                    "{} {what} for policy v{} (dry-run)",
                    self.id(),
                    plan.policy_version
                ),
                Err(e) => format!("{} {what} refused: {e}", self.id()),
            },
            details: serde_json::json!({
                "provider": self.id(),
                "mode": "dry_run",
                "planned_changes": plan.changes.len(),
                "activation_allowed": plan.activation_allowed,
            }),
        }
    }
}

/// Provider used when no OS mechanism is selected: simulation only.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimulationOnlyProvider;

impl EnforcementProvider for SimulationOnlyProvider {
    fn id(&self) -> &'static str {
        "simulation-only"
    }

    fn capabilities(&self, _env: &EnvironmentFacts) -> CapabilityReport {
        CapabilityReport {
            provider_id: self.id().into(),
            pre_access_blocking: CapabilityStatus::NotImplemented,
            brand_allowlisting: CapabilityStatus::NotImplemented,
            previously_installed_devices: CapabilityStatus::NotImplemented,
            persistence: CapabilityStatus::NotImplemented,
            self_verification: CapabilityStatus::NotImplemented,
            activation_available: false,
        }
    }

    fn plan(&self, inputs: PlanInputs<'_>) -> EnforcementPlan {
        EnforcementPlan {
            provider_id: self.id().into(),
            mode: PlanMode::DryRun,
            workstation_id: inputs.policy.policy().workstation_id.clone(),
            policy_version: inputs.policy.policy().policy_version,
            changes: Vec::new(),
            preconditions: Vec::new(),
            risks: vec!["No OS mechanism selected: nothing can be enforced.".into()],
            recovery: Vec::new(),
            activation_allowed: false,
        }
    }

    fn dry_run(&self, _plan: &EnforcementPlan, _inputs: PlanInputs<'_>) -> DryRunReport {
        DryRunReport {
            enforcement_gaps: Vec::new(),
            over_blocking: Vec::new(),
            already_installed_denied: Vec::new(),
            notes: vec!["simulation-only provider: no OS rules modelled".into()],
        }
    }

    fn activate(&self, _plan: &EnforcementPlan) -> Result<(), ActivationError> {
        Err(ActivationError::ActivationDisabled)
    }

    fn status(&self) -> EnforcementState {
        EnforcementState::Simulated
    }
}

/// Required operator message for a verified block (Turkish UI).
pub const BLOCKED_NOTIFICATION_TR: &str = "USB engellenmiştir. İşlem kayıt altına alınmıştır.";

/// Message when a block cannot be confirmed.
pub const UNVERIFIED_NOTIFICATION_TR: &str =
    "Koruma doğrulanamadı: bu USB depolama aygıtının engellendiği teyit edilemedi.";

/// Dashboard banner shown until real enforcement validation succeeds.
pub const NOT_VALIDATED_BANNER_TR: &str = "Koruma henüz gerçek Windows ortamında doğrulanmadı.";

/// Operator notification for an unauthorized storage device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Notification {
    /// Block verified for this device.
    BlockedVerified {
        /// Text.
        text: String,
    },
    /// Block could not be verified.
    ProtectionNotVerified {
        /// Text.
        text: String,
    },
}

/// Choose the notification for a denied device.
#[must_use]
pub fn notification_for(
    state: &EnforcementState,
    device_block: Option<&VerificationEvidence>,
) -> Notification {
    if state.is_verified_protection() && device_block.is_some() {
        Notification::BlockedVerified {
            text: BLOCKED_NOTIFICATION_TR.into(),
        }
    } else {
        Notification::ProtectionNotVerified {
            text: UNVERIFIED_NOTIFICATION_TR.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_is_compiled_out() {
        const { assert!(!ACTIVATION_ENABLED) };
    }

    #[test]
    fn simulation_provider_never_claims_protection() {
        let p = SimulationOnlyProvider;
        assert_eq!(p.status(), EnforcementState::Simulated);
        assert!(!p.status().is_verified_protection());
        let caps = p.capabilities(&EnvironmentFacts::default());
        assert!(!caps.activation_available);
    }

    #[test]
    fn blocked_message_requires_verified_state_and_device_evidence() {
        let ev = VerificationEvidence::for_tests("T-1");
        let verified = EnforcementState::VerifiedProtected {
            evidence: ev.clone(),
        };
        assert!(matches!(
            notification_for(&verified, Some(&ev)),
            Notification::BlockedVerified { .. }
        ));
        for state in [
            EnforcementState::NotConfigured,
            EnforcementState::Simulated,
            EnforcementState::PendingValidation,
            EnforcementState::ActiveUnverified,
            EnforcementState::Degraded { reason: "x".into() },
            EnforcementState::Error { reason: "x".into() },
        ] {
            assert!(matches!(
                notification_for(&state, Some(&ev)),
                Notification::ProtectionNotVerified { .. }
            ));
            assert!(!state.is_verified_protection());
        }
        assert!(matches!(
            notification_for(&verified, None),
            Notification::ProtectionNotVerified { .. }
        ));
    }

    #[test]
    fn state_codes_are_stable() {
        let codes: Vec<_> = [
            EnforcementState::NotConfigured,
            EnforcementState::Simulated,
            EnforcementState::PendingValidation,
            EnforcementState::ActiveUnverified,
            EnforcementState::Degraded {
                reason: String::new(),
            },
            EnforcementState::Error {
                reason: String::new(),
            },
        ]
        .iter()
        .map(EnforcementState::code)
        .collect();
        assert_eq!(
            codes,
            [
                "not_configured",
                "simulated",
                "pending_validation",
                "active_unverified",
                "degraded",
                "error"
            ]
        );
    }

    /// The crate must not contain any registry / Group Policy / device
    /// state-changing API reference.
    #[test]
    fn no_system_modification_apis_in_this_crate() {
        let src = concat!(
            include_str!("lib.rs"),
            include_str!("device_install.rs"),
            include_str!("activation.rs")
        );
        let forbidden = [
            ["Reg", "SetValueEx"].concat(),
            ["Reg", "CreateKey"].concat(),
            ["Reg", "DeleteValue"].concat(),
            ["win", "reg"].concat(),
            ["windows", "_sys"].concat(),
            ["Command", "::new"].concat(),
            ["CM_", "Disable"].concat(),
            ["SetupDi", "RemoveDevice"].concat(),
            ["SetupDi", "CallClassInstaller"].concat(),
            ["Std", "Command"].concat(),
            ["Local", "GroupPolicy"].concat(),
        ];
        for f in &forbidden {
            assert!(!src.contains(f.as_str()), "forbidden API reference {f}");
        }
    }
}
