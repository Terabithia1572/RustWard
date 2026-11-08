//! Default-deny policy evaluation with evidence.
//!
//! The decision rule mirrors what the candidate Windows mechanism can
//! enforce (an exact match on the vendor-level INQUIRY hardware ID), while
//! failing closed when a device's USB VID belongs to a *different* catalog
//! manufacturer than its self-reported INQUIRY vendor (e.g. a Kingston VID
//! claiming `SanDisk` in SCSI INQUIRY). Unlisted bridge VIDs and friendly
//! names never authorize on their own and are recorded as evidence.

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
    /// Identified as a catalog brand the policy explicitly denies.
    BrandDenied {
        /// Brand id.
        brand_id: String,
    },
    /// Identified as a catalog brand that is not allowed (or disabled).
    BrandNotAllowed {
        /// Brand id.
        brand_id: String,
    },
    /// INQUIRY vendor matches an allowed brand, but the USB ancestor VID
    /// belongs to a different catalog manufacturer (fail-closed deny).
    ConflictingIdentifiers {
        /// Brand matched by INQUIRY vendor.
        inquiry_brand: String,
        /// Hex USB VID of the USB ancestor (e.g. `"0951"`).
        usb_vid: String,
        /// Catalog brand(s) associated with `usb_vid`.
        vid_brands: Vec<String>,
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
    if inq.namespace.shared_with_internal_disks() {
        evidence.push(ev(
            EvidenceKind::Warning,
            "hardware_ids",
            "SCSI-namespace ID: shared with internal/virtual disks; UASP enumeration not yet observed on hardware".into(),
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
        // An explicit deny always wins (validation also forbids a brand
        // that is both allowed and denied).
        Some(brand) if policy.brand_denied(brand) => (
            Verdict::Deny,
            DecisionReason::BrandDenied {
                brand_id: brand.to_owned(),
            },
        ),
        Some(brand) if policy.brand_allowed(brand) => {
            if let Some(usb) = &classification.usb_ancestor {
                let vid_brands = catalog.brands_for_vid(usb.ids.vid);
                if !vid_brands.is_empty() && !vid_brands.iter().any(|x| x == brand) {
                    return (
                        Verdict::Deny,
                        DecisionReason::ConflictingIdentifiers {
                            inquiry_brand: brand.to_owned(),
                            usb_vid: usb.ids.vid_hex(),
                            vid_brands: vid_brands.to_vec(),
                        },
                    );
                }
            }
            (
                Verdict::Allow,
                DecisionReason::BrandAllowed {
                    brand_id: brand.to_owned(),
                },
            )
        }
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
        | DecisionReason::BrandDenied { brand_id }
        | DecisionReason::BrandNotAllowed { brand_id } => Some(brand_id.as_str()),
        _ => None,
    };
    if let DecisionReason::ConflictingIdentifiers {
        inquiry_brand,
        usb_vid,
        vid_brands,
    } = reason
    {
        evidence.push(ev(
            EvidenceKind::Warning,
            "usb_vid",
            format!(
                "USB VID {usb_vid} belongs to catalog brand(s) {vid_brands:?}, conflicting with INQUIRY brand {inquiry_brand:?}; failed closed (deny)"
            ),
        ));
    } else if let Some(usb) = &classification.usb_ancestor {
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
        StorageScope::InScope => {
            if classification.category == DeviceCategory::StorageAttachmentUnknown {
                evidence.push(ev(
                    EvidenceKind::Warning,
                    "parent_instance_id",
                    "parent chain is broken or unreadable; USB vs. internal attachment cannot be proven, so the device is treated as in scope (fail-closed)".into(),
                ));
            }
            identity_verdict(&classification, policy, catalog, &mut evidence)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::SnapshotSource;
    use crate::plan::{ModelOutcome, check_consistency, compile_plan};

    const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
    const POLICY: &str = include_str!("../../../config/policy.example.json");

    fn load_state() -> (ValidatedCatalog, ValidatedPolicy) {
        let cat = ValidatedCatalog::from_json(CATALOG).expect("catalog valid");
        let pol = ValidatedPolicy::from_json(POLICY, &cat).expect("policy valid");
        (cat, pol)
    }

    fn usb_disk_snapshot(vid: &str, pid: &str, vendor8: &str, prod16: &str) -> DeviceSnapshot {
        let usb_id = format!("USB\\VID_{vid}&PID_{pid}\\SERIAL0001");
        let disk_id = format!("USBSTOR\\Disk&Ven_{vendor8}&Prod_{prod16}&Rev_1.00\\SERIAL0001&0");
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "source": SnapshotSource::Synthetic { description: "evaluate unit test".into() },
            "devices": [
                {
                    "instance_id": usb_id,
                    "class_guid": "{36fc9e60-c465-11cf-8056-444553540000}",
                    "class_name": "USB",
                    "service": "USBSTOR",
                    "hardware_ids": [format!("USB\\VID_{vid}&PID_{pid}")],
                    "present": true
                },
                {
                    "instance_id": disk_id,
                    "parent_instance_id": usb_id,
                    "class_guid": "{4d36e967-e325-11ce-bfc1-08002be10318}",
                    "class_name": "DiskDrive",
                    "service": "disk",
                    "hardware_ids": [
                        format!("USBSTOR\\Disk{vendor8}{prod16}1.00"),
                        format!("USBSTOR\\Disk{vendor8}{prod16}"),
                        format!("USBSTOR\\Disk{vendor8}"),
                        "GenDisk"
                    ],
                    "present": true
                }
            ]
        }))
        .expect("snapshot valid")
    }

    #[test]
    fn conflicting_kingston_vid_with_sandisk_inquiry_fails_closed() {
        let (cat, pol) = load_state();
        let snap = usb_disk_snapshot("0951", "1666", "SanDisk_", "DataTraveler_3.0");
        let decisions = evaluate_snapshot(&snap, &pol, &cat);
        let disk = &decisions[1];
        assert_eq!(disk.verdict, Verdict::Deny);
        assert_eq!(
            disk.reason,
            DecisionReason::ConflictingIdentifiers {
                inquiry_brand: "sandisk".into(),
                usb_vid: "0951".into(),
                vid_brands: vec!["kingston".into()],
            }
        );
        assert!(
            disk.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::Warning && e.source == "usb_vid")
        );

        // Consistency check surfaces the OS INQUIRY-only allow gap explicitly.
        let plan = compile_plan(&pol, &cat, Some(&snap));
        let gaps = check_consistency(&plan, &snap, &decisions);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].kind, "enforcement_gap");
        assert!(matches!(gaps[0].model, ModelOutcome::Allowed { .. }));
    }

    #[test]
    fn conflicting_seagate_vid_with_sandisk_inquiry_fails_closed() {
        let (cat, pol) = load_state();
        let snap = usb_disk_snapshot("0BC2", "2344", "SanDisk_", "Fake_Ultra______");
        let decisions = evaluate_snapshot(&snap, &pol, &cat);
        let disk = &decisions[1];
        assert_eq!(disk.verdict, Verdict::Deny);
        assert_eq!(
            disk.reason,
            DecisionReason::ConflictingIdentifiers {
                inquiry_brand: "sandisk".into(),
                usb_vid: "0BC2".into(),
                vid_brands: vec!["seagate".into()],
            }
        );
    }

    #[test]
    fn vm_observed_vendorc_and_kingston_and_internal_nvme_behave_as_specified() {
        let (cat, pol) = load_state();
        // VendorC 346D:5678 (ASELSAN-labelled stick with generic controller descriptors) -> Deny
        let vendorc = usb_disk_snapshot("346D", "5678", "VendorC_", "ProductCode_____");
        let dec_vc = &evaluate_snapshot(&vendorc, &pol, &cat)[1];
        assert_eq!(dec_vc.verdict, Verdict::Deny);
        assert_eq!(
            dec_vc.reason,
            DecisionReason::GenericVendorIdentity {
                vendor: "VendorC".into()
            }
        );

        // Kingston 0951:1666 -> Explicit BrandDenied
        let kingston = usb_disk_snapshot("0951", "1666", "Kingston", "DataTraveler_3.0");
        let dec_k = &evaluate_snapshot(&kingston, &pol, &cat)[1];
        assert_eq!(dec_k.verdict, Verdict::Deny);
        assert_eq!(
            dec_k.reason,
            DecisionReason::BrandDenied {
                brand_id: "kingston".into()
            }
        );

        // VMware NVMe boot disk under PCI\VEN_15AD&DEV_07F0 -> NotApplicable
        let nvme_snap: DeviceSnapshot = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "source": SnapshotSource::Synthetic { description: "vmware nvme".into() },
            "devices": [
                {
                    "instance_id": "PCI\\VEN_15AD&DEV_07F0&SUBSYS_07F015AD&REV_00\\4&3A2B1C&0&00A8",
                    "class_guid": "{4d36e97b-e325-11ce-bfc1-08002be10318}",
                    "class_name": "SCSIAdapter",
                    "service": "stornvme",
                    "hardware_ids": ["PCI\\VEN_15AD&DEV_07F0"],
                    "present": true
                },
                {
                    "instance_id": "SCSI\\DISK&VEN_NVME&PROD_VMWARE_VIRTUAL_N\\5&25A13950&0&000000",
                    "parent_instance_id": "PCI\\VEN_15AD&DEV_07F0&SUBSYS_07F015AD&REV_00\\4&3A2B1C&0&00A8",
                    "class_guid": "{4d36e967-e325-11ce-bfc1-08002be10318}",
                    "class_name": "DiskDrive",
                    "service": "disk",
                    "hardware_ids": ["SCSI\\DiskNVMe____VMware_Virtual_N", "SCSI\\DiskNVMe____", "GenDisk"],
                    "present": true
                }
            ]
        }))
        .expect("nvme snapshot");
        let dec_nvme = &evaluate_snapshot(&nvme_snap, &pol, &cat)[1];
        assert_eq!(
            dec_nvme.classification.category,
            DeviceCategory::SystemOrNonUsbStorage
        );
        assert_eq!(dec_nvme.verdict, Verdict::NotApplicable);
        assert_eq!(dec_nvme.reason, DecisionReason::NotInScope);
    }
}
