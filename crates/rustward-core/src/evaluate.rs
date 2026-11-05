//! Default-deny policy evaluation with evidence.
//!
//! The decision rule deliberately mirrors what the candidate Windows
//! mechanism can actually enforce (an exact match on the vendor-level
//! INQUIRY hardware ID). Corroborating data such as the USB VID or
//! friendly-name text is recorded as evidence but **never** changes the
//! verdict, because a decision the OS cannot enforce would mislead the
//! operator.

use serde::{Deserialize, Serialize};

use crate::catalog::ValidatedCatalog;
use crate::classify::{Classification, DeviceCategory, StorageScope, classify};
use crate::device::{DeviceRecord, DeviceSnapshot};
use crate::policy::{PolicyMode, ValidatedPolicy};

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Storage access would be permitted.
    Allow,
    /// Storage access would be denied.
    Deny,
    /// The device is not subject to the storage policy.
    NotApplicable,
}

/// Why a verdict was reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum DecisionReason {
    /// Vendor-level INQUIRY ID matches an enabled, allowed brand.
    BrandAllowed {
        /// Brand id.
        brand_id: String,
    },
    /// Identified as a catalog brand that is not allowed (or disabled).
    BrandNotAllowed {
        /// Brand id.
        brand_id: String,
    },
    /// The INQUIRY vendor is not in the catalog.
    UnknownManufacturer {
        /// Vendor as displayed.
        vendor: String,
    },
    /// The INQUIRY vendor is a reserved generic value.
    GenericVendorIdentity {
        /// Vendor as displayed.
        vendor: String,
    },
    /// No vendor-level hardware ID could be recovered.
    MissingEnforceableIdentity,
    /// Storage-like device whose scope is not yet decided; default deny.
    ScopeDecisionPending,
    /// Not storage, or system storage, or a storage interface node.
    NotInScope,
}

/// Evidence strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// The identifier the decision (and the OS rule) is based on.
    Enforceable,
    /// Agrees with the decision but is not used by it.
    Corroborating,
    /// Weak textual similarity. Never used for authorization.
    Hint,
    /// Something an administrator should look at.
    Warning,
}

/// One piece of evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Strength.
    pub kind: EvidenceKind,
    /// Field the evidence came from.
    pub source: String,
    /// Description.
    pub detail: String,
}

/// Enforcement status attached to every decision produced by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    /// Simulation only — nothing was enforced. The only value this crate
    /// ever produces.
    NotEnforcedSimulation,
}

/// A policy decision for one device node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Device instance ID.
    pub instance_id: String,
    /// Classification.
    pub classification: Classification,
    /// Verdict.
    pub verdict: Verdict,
    /// Reason.
    pub reason: DecisionReason,
    /// Evidence.
    pub evidence: Vec<Evidence>,
    /// Policy version used.
    pub policy_version: u64,
    /// Catalog version used.
    pub catalog_version: String,
    /// Policy mode.
    pub mode: PolicyMode,
    /// Always [`EnforcementStatus::NotEnforcedSimulation`].
    pub enforcement: EnforcementStatus,
}

fn ev(kind: EvidenceKind, source: &str, detail: String) -> Evidence {
    Evidence {
        kind,
        source: source.to_owned(),
        detail,
    }
}

fn identity_verdict(
    classification: &Classification,
    policy: &ValidatedPolicy,
    catalog: &ValidatedCatalog,
    evidence: &mut Vec<Evidence>,
) -> (Verdict, DecisionReason) {
    let Some(inq) = classification.inquiry.as_ref() else {
        evidence.push(ev(
            EvidenceKind::Warning,
            "hardware_ids",
            "no vendor-level USBSTOR/SCSI hardware ID found; brand cannot be determined".into(),
        ));
        return (Verdict::Deny, DecisionReason::MissingEnforceableIdentity);
    };
    let vendor = inq.vendor_display();
    evidence.push(ev(
        EvidenceKind::Enforceable,
        "hardware_ids",
        format!("vendor-level hardware ID {:?}", inq.vendor_level_id),
    ));
    if !inq.namespace.vendor_level_format_documented() {
        evidence.push(ev(
            EvidenceKind::Warning,
            "hardware_ids",
            "SCSI-namespace vendor-level ID format is not yet confirmed on hardware; the SCSI namespace is shared with internal disks".into(),
        ));
    }
    if catalog.is_generic_vendor(&inq.vendor_field) {
        return (
            Verdict::Deny,
            DecisionReason::GenericVendorIdentity { vendor },
        );
    }
    match catalog.brand_for_inquiry_field(&inq.vendor_field) {
        None => (
            Verdict::Deny,
            DecisionReason::UnknownManufacturer { vendor },
        ),
        Some(brand) if policy.brand_allowed(brand) => (
            Verdict::Allow,
            DecisionReason::BrandAllowed {
                brand_id: brand.to_owned(),
            },
        ),
        Some(brand) => (
            Verdict::Deny,
            DecisionReason::BrandNotAllowed {
                brand_id: brand.to_owned(),
            },
        ),
    }
}

fn add_corroboration(
    device: &DeviceRecord,
    classification: &Classification,
    reason: &DecisionReason,
    catalog: &ValidatedCatalog,
    evidence: &mut Vec<Evidence>,
) {
    let matched_brand = match reason {
        DecisionReason::BrandAllowed { brand_id }
        | DecisionReason::BrandNotAllowed { brand_id } => Some(brand_id.as_str()),
        _ => None,
    };
    if let Some(usb) = &classification.usb_ancestor {
        let vid_brands = catalog.brands_for_vid(usb.ids.vid);
        let vid = usb.ids.vid_hex();
        match (matched_brand, vid_brands.is_empty()) {
            (Some(b), false) if vid_brands.iter().any(|x| x == b) => evidence.push(ev(
                EvidenceKind::Corroborating,
                "usb_vid",
                format!("USB VID {vid} is listed for brand {b:?} in the catalog"),
            )),
            (Some(b), _) => evidence.push(ev(
                EvidenceKind::Warning,
                "usb_vid",
                format!(
                    "USB VID {vid} does not corroborate brand {b:?} (bridge chip, OEM controller, or spoofing); verdict unchanged because the OS rule matches only the INQUIRY vendor"
                ),
            )),
            (None, false) => evidence.push(ev(
                EvidenceKind::Hint,
                "usb_vid",
                format!("USB VID {vid} is listed for {vid_brands:?}; VID alone never authorizes"),
            )),
            (None, true) => {}
        }
    }
    let texts = [
        ("friendly_name", device.friendly_name.as_deref()),
        (
            "bus_reported_description",
            device.bus_reported_description.as_deref(),
        ),
    ];
    for (field, text) in texts {
        let Some(text) = text else { continue };
        let lower = text.to_lowercase();
        for brand in &catalog.catalog().brands {
            let hit = std::iter::once(&brand.display_name)
                .chain(brand.aliases.iter())
                .any(|a| !a.trim().is_empty() && lower.contains(&a.to_lowercase()));
            if hit {
                evidence.push(ev(
                    EvidenceKind::Hint,
                    field,
                    format!(
                        "text {text:?} resembles brand {:?}; names never authorize",
                        brand.id
                    ),
                ));
            }
        }
    }
}

/// Evaluate one device.
#[must_use]
pub fn evaluate_device(
    classification: Classification,
    device: &DeviceRecord,
    policy: &ValidatedPolicy,
    catalog: &ValidatedCatalog,
) -> Decision {
    let mut evidence = Vec::new();
    let (verdict, reason) = match classification.category.scope() {
        StorageScope::NotInScope => (Verdict::NotApplicable, DecisionReason::NotInScope),
        StorageScope::ScopeDecisionPending => {
            evidence.push(ev(
                EvidenceKind::Warning,
                "classification",
                format!(
                    "{:?} is storage-capable but outside the brand policy scope; default deny pending an explicit scope decision",
                    classification.category
                ),
            ));
            (Verdict::Deny, DecisionReason::ScopeDecisionPending)
        }
        StorageScope::InScope => identity_verdict(&classification, policy, catalog, &mut evidence),
    };
    if matches!(
        classification.category,
        DeviceCategory::UsbStorageDisk { .. }
    ) {
        add_corroboration(device, &classification, &reason, catalog, &mut evidence);
    }
    Decision {
        instance_id: device.instance_id.clone(),
        classification,
        verdict,
        reason,
        evidence,
        policy_version: policy.policy().policy_version,
        catalog_version: catalog.catalog().catalog_version.clone(),
        mode: policy.policy().mode,
        enforcement: EnforcementStatus::NotEnforcedSimulation,
    }
}

/// Evaluate every device in a snapshot.
#[must_use]
pub fn evaluate_snapshot(
    snapshot: &DeviceSnapshot,
    policy: &ValidatedPolicy,
    catalog: &ValidatedCatalog,
) -> Vec<Decision> {
    let index = snapshot.index();
    snapshot
        .devices
        .iter()
        .map(|d| evaluate_device(classify(&index, d), d, policy, catalog))
        .collect()
}
