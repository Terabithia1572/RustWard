//! Enforcement abstractions and protection-state reporting.
//!
//! Phase 1 ships **no** enforcement provider. The only provider,
//! [`SimulationOnlyProvider`], reports every capability as not implemented
//! and the protection state as simulation-only.
//!
//! The types here exist so that every later component (service, UI,
//! notifications) has to go through one honest answer to "is this
//! workstation actually protected?":
//!
//! - [`ProtectionState::EnforcedVerified`] can only be constructed from a
//!   [`VerificationEvidence`] value, which a provider must produce after
//!   *observing* the security property (e.g. a denied read on a test
//!   device), not after merely writing a configuration.
//! - The Turkish "blocked" notification ([`BLOCKED_NOTIFICATION_TR`]) is only
//!   returned by [`notification_for`] when both the workstation state and
//!   the individual device block are verified.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Status of one capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Not implemented in this build.
    NotImplemented,
    /// The mechanism cannot provide this property (documented limitation).
    Unsupported,
    /// Implemented but not verified on this workstation.
    ImplementedUnverified,
    /// Implemented and verified with recorded evidence.
    Verified,
}

/// What a provider can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// Provider id.
    pub provider_id: &'static str,
    /// Prevents unauthorized storage from becoming readable/writable.
    pub pre_access_blocking: CapabilityStatus,
    /// Brand-level (not per-model) allowlisting.
    pub brand_allowlisting: CapabilityStatus,
    /// Handles devices installed before the policy.
    pub previously_installed_devices: CapabilityStatus,
    /// Survives UI exit, service restart and reboot.
    pub persistence: CapabilityStatus,
    /// Can prove its own effect.
    pub self_verification: CapabilityStatus,
}

/// Opaque proof that a security property was observed. Only providers can
/// create it; there is deliberately no public constructor in Phase 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// The property that was observed.
    #[must_use]
    pub fn observed_property(&self) -> &str {
        &self.observed_property
    }
}

/// Workstation-level protection state shown to operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProtectionState {
    /// No enforcement is active.
    NotProtected {
        /// Why.
        reason: String,
    },
    /// Decisions are computed but nothing is enforced.
    SimulationOnly,
    /// A configuration was applied but its effect is not verified.
    EnforcedUnverified,
    /// Enforcement observed to work.
    EnforcedVerified {
        /// Evidence.
        evidence: VerificationEvidence,
    },
}

impl ProtectionState {
    /// True only for verified enforcement.
    #[must_use]
    pub fn is_verified_protection(&self) -> bool {
        matches!(self, Self::EnforcedVerified { .. })
    }

    /// Short Turkish label for the dashboard.
    #[must_use]
    pub fn label_tr(&self) -> &'static str {
        match self {
            Self::NotProtected { .. } => "Koruma yok",
            Self::SimulationOnly => "Yalnızca simülasyon — koruma etkin değil",
            Self::EnforcedUnverified => "Uygulandı, doğrulanmadı",
            Self::EnforcedVerified { .. } => "Koruma etkin ve doğrulandı",
        }
    }
}

/// An enforcement provider.
pub trait EnforcementProvider {
    /// Stable id.
    fn id(&self) -> &'static str;
    /// Capabilities.
    fn capabilities(&self) -> CapabilityReport;
    /// Current protection state.
    fn protection_state(&self) -> ProtectionState;
}

/// The only provider in Phase 1. Never enforces anything.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimulationOnlyProvider;

impl EnforcementProvider for SimulationOnlyProvider {
    fn id(&self) -> &'static str {
        "simulation-only"
    }

    fn capabilities(&self) -> CapabilityReport {
        CapabilityReport {
            provider_id: self.id(),
            pre_access_blocking: CapabilityStatus::NotImplemented,
            brand_allowlisting: CapabilityStatus::NotImplemented,
            previously_installed_devices: CapabilityStatus::NotImplemented,
            persistence: CapabilityStatus::NotImplemented,
            self_verification: CapabilityStatus::NotImplemented,
        }
    }

    fn protection_state(&self) -> ProtectionState {
        ProtectionState::SimulationOnly
    }
}

/// Required operator message for a verified block (Turkish UI).
pub const BLOCKED_NOTIFICATION_TR: &str = "USB engellenmiştir. İşlem kayıt altına alınmıştır.";

/// Message when a block cannot be confirmed.
pub const UNVERIFIED_NOTIFICATION_TR: &str =
    "Koruma doğrulanamadı: bu USB depolama aygıtının engellendiği teyit edilemedi.";

/// Operator notification for an unauthorized storage device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Notification {
    /// Block verified for this device.
    BlockedVerified {
        /// Text.
        text: &'static str,
    },
    /// Block could not be verified.
    ProtectionNotVerified {
        /// Text.
        text: &'static str,
    },
}

/// Choose the notification for a denied device. `device_block` is
/// evidence that *this* device was observed blocked (e.g. no disk/volume
/// created, install refused by policy).
#[must_use]
pub fn notification_for(
    state: &ProtectionState,
    device_block: Option<&VerificationEvidence>,
) -> Notification {
    if state.is_verified_protection() && device_block.is_some() {
        Notification::BlockedVerified {
            text: BLOCKED_NOTIFICATION_TR,
        }
    } else {
        Notification::ProtectionNotVerified {
            text: UNVERIFIED_NOTIFICATION_TR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulation_provider_never_claims_protection() {
        let p = SimulationOnlyProvider;
        let state = p.protection_state();
        assert!(!state.is_verified_protection());
        assert_eq!(state, ProtectionState::SimulationOnly);
        let caps = p.capabilities();
        for s in [
            caps.pre_access_blocking,
            caps.brand_allowlisting,
            caps.previously_installed_devices,
            caps.persistence,
            caps.self_verification,
        ] {
            assert_eq!(s, CapabilityStatus::NotImplemented);
        }
    }

    #[test]
    fn blocked_message_requires_verified_state_and_device_evidence() {
        let ev = VerificationEvidence {
            evidence_id: "T-1".into(),
            observed_property: "read denied".into(),
        };
        let verified = ProtectionState::EnforcedVerified {
            evidence: ev.clone(),
        };
        assert_eq!(
            notification_for(&verified, Some(&ev)),
            Notification::BlockedVerified {
                text: BLOCKED_NOTIFICATION_TR
            }
        );
        for (state, dev) in [
            (verified.clone(), None),
            (ProtectionState::SimulationOnly, Some(&ev)),
            (ProtectionState::EnforcedUnverified, Some(&ev)),
            (ProtectionState::NotProtected { reason: "x".into() }, None),
        ] {
            assert!(matches!(
                notification_for(&state, dev),
                Notification::ProtectionNotVerified { .. }
            ));
        }
    }

    #[test]
    fn labels_distinguish_simulation_from_protection() {
        assert!(
            ProtectionState::SimulationOnly
                .label_tr()
                .contains("simülasyon")
        );
        assert_ne!(
            ProtectionState::EnforcedUnverified.label_tr(),
            ProtectionState::EnforcedVerified {
                evidence: VerificationEvidence {
                    evidence_id: String::new(),
                    observed_property: String::new()
                }
            }
            .label_tr()
        );
    }
}
