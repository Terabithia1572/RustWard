//! Preview of a Windows Device Installation Restriction configuration.
//!
//! [`compile_plan`] turns a validated policy into the *data* a future
//! Phase 2 enforcement provider would write (layered evaluation enabled,
//! prevent the DiskDrive setup class, allow vendor-level INQUIRY hardware
//! IDs of allowed brands, allow the instance IDs of existing system disks).
//!
//! [`model_install_outcome`] is a *model* of Microsoft's documented layered
//! evaluation order (instance IDs > device IDs > setup class). It exists
//! so the decision engine and the OS-level rule set can be checked for
//! agreement; it is not Windows and proves nothing about Windows.
//!
//! Nothing in this module modifies the system. `PlanStatus` is always
//! `NotApplied`.

use serde::{Deserialize, Serialize};

use crate::catalog::{ValidatedCatalog, Verification};
use crate::class_guids;
use crate::classify::{DeviceCategory, classify};
use crate::device::{DeviceRecord, DeviceSnapshot};
use crate::evaluate::{Decision, Verdict};
use crate::ids::{StorageIdNamespace, vendor_level_hardware_id};
use crate::policy::ValidatedPolicy;

/// Plan status. There is deliberately no "applied" variant in Phase 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    /// Preview only.
    NotApplied,
}

/// An allow rule on a hardware/compatible ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowDeviceIdRule {
    /// Exact ID string.
    pub device_id: String,
    /// Brand it was compiled from.
    pub brand_id: String,
    /// ID namespace.
    pub namespace: StorageIdNamespace,
    /// Whether the catalog identifier is lab-verified.
    pub identifier_lab_verified: bool,
    /// Whether Microsoft documents this namespace's vendor-level format.
    pub namespace_format_documented: bool,
}

/// A prevent rule on a setup class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreventClassRule {
    /// Class GUID.
    pub class_guid: String,
    /// Class name.
    pub class_name: String,
    /// Retroactive application. Always `false`: retroactively applying a
    /// DiskDrive prevent rule would affect the system disk.
    pub retroactive: bool,
}

/// An allow rule on a device instance ID (protects existing system disks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowInstanceIdRule {
    /// Instance ID.
    pub instance_id: String,
    /// Why it is listed.
    pub reason: String,
}

/// Preview of a Device Installation Restriction configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInstallPlan {
    /// Always `NotApplied`.
    pub status: PlanStatus,
    /// Workstation.
    pub workstation_id: String,
    /// Source policy version.
    pub policy_version: u64,
    /// Source catalog version.
    pub catalog_version: String,
    /// `EnableInstallationPolicyLayering` (AllowDenyLayered).
    pub layered_evaluation: bool,
    /// Instance-ID allow rules.
    pub allow_instance_ids: Vec<AllowInstanceIdRule>,
    /// Device-ID allow rules.
    pub allow_device_ids: Vec<AllowDeviceIdRule>,
    /// Setup-class prevent rules.
    pub prevent_setup_classes: Vec<PreventClassRule>,
    /// Open issues the administrator must see.
    pub warnings: Vec<String>,
}

/// Compile a policy into a plan preview. `baseline` (a live snapshot)
/// supplies existing non-USB disks to protect via instance-ID allow rules.
#[must_use]
pub fn compile_plan(
    policy: &ValidatedPolicy,
    catalog: &ValidatedCatalog,
    baseline: Option<&DeviceSnapshot>,
) -> DeviceInstallPlan {
    let mut warnings = Vec::new();
    let mut allow_device_ids = Vec::new();

    for brand_id in policy.enabled_brands() {
        let Some(brand) = catalog.brand(brand_id) else {
            continue;
        };
        let mut any = false;
        for ident in brand.enforceable_identifiers() {
            for ns in StorageIdNamespace::ALL {
                match vendor_level_hardware_id(ns, "Disk", &ident.value) {
                    Ok(device_id) => {
                        any = true;
                        allow_device_ids.push(AllowDeviceIdRule {
                            device_id,
                            brand_id: brand.id.clone(),
                            namespace: ns,
                            identifier_lab_verified: ident.verification
                                == Verification::LabVerified,
                            namespace_format_documented: ns.vendor_level_format_documented(),
                        });
                    }
                    Err(e) => warnings.push(format!("brand {:?}: {e}", brand.id)),
                }
            }
        }
        if !any {
            warnings.push(format!(
                "allowed brand {:?} contributes no allow rule; its devices will be blocked",
                brand.id
            ));
        }
    }
    if allow_device_ids.iter().any(|r| !r.identifier_lab_verified) {
        warnings.push("some allow rules come from identifiers that are not lab-verified".into());
    }
    if allow_device_ids
        .iter()
        .any(|r| r.namespace == StorageIdNamespace::Scsi)
    {
        warnings.push(
            "SCSI\\Disk<vendor> allow rules also match internal/virtual disks with the same INQUIRY vendor and their padding is unconfirmed; validate on UASP hardware".into(),
        );
    }

    let mut allow_instance_ids = Vec::new();
    match baseline {
        Some(snap) => {
            let index = snap.index();
            for d in &snap.devices {
                if d.class_is(class_guids::DISK_DRIVE)
                    && classify(&index, d).category == DeviceCategory::SystemOrNonUsbStorage
                {
                    allow_instance_ids.push(AllowInstanceIdRule {
                        instance_id: d.instance_id.clone(),
                        reason: "existing non-USB disk captured in baseline".into(),
                    });
                }
            }
        }
        None => warnings.push(
            "no baseline snapshot supplied: existing system disks are not protected by instance-ID allow rules".into(),
        ),
    }

    warnings.push(
        "devices installed before the policy (including non-present ones) are NOT affected by install restrictions; a reviewed baseline cleanup is required (Phase 2)".into(),
    );
    warnings.push(
        "scope decisions pending: USB CD/DVD (CDROM class) and MTP/PTP (WPD class) are not covered by this plan".into(),
    );

    DeviceInstallPlan {
        status: PlanStatus::NotApplied,
        workstation_id: policy.policy().workstation_id.clone(),
        policy_version: policy.policy().policy_version,
        catalog_version: catalog.catalog().catalog_version.clone(),
        layered_evaluation: true,
        allow_instance_ids,
        allow_device_ids,
        prevent_setup_classes: vec![PreventClassRule {
            class_guid: class_guids::DISK_DRIVE.into(),
            class_name: "DiskDrive".into(),
            retroactive: false,
        }],
        warnings,
    }
}

/// Layer at which the modelled evaluation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    /// Device instance IDs.
    InstanceId,
    /// Hardware/compatible IDs.
    DeviceId,
    /// Setup class.
    SetupClass,
}

/// Modelled outcome of installing a device under a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ModelOutcome {
    /// An allow rule matched first.
    Allowed {
        /// Layer.
        layer: PolicyLayer,
    },
    /// A prevent rule matched first.
    Prevented {
        /// Layer.
        layer: PolicyLayer,
    },
    /// No rule matched; installation is not restricted.
    NotRestricted,
}

/// Model of layered evaluation for a *new installation* of `device`.
#[must_use]
pub fn model_install_outcome(plan: &DeviceInstallPlan, device: &DeviceRecord) -> ModelOutcome {
    if plan
        .allow_instance_ids
        .iter()
        .any(|r| r.instance_id.eq_ignore_ascii_case(&device.instance_id))
    {
        return ModelOutcome::Allowed {
            layer: PolicyLayer::InstanceId,
        };
    }
    if plan
        .allow_device_ids
        .iter()
        .any(|r| device.has_id(&r.device_id))
    {
        return ModelOutcome::Allowed {
            layer: PolicyLayer::DeviceId,
        };
    }
    if plan
        .prevent_setup_classes
        .iter()
        .any(|r| device.class_is(&r.class_guid))
    {
        return ModelOutcome::Prevented {
            layer: PolicyLayer::SetupClass,
        };
    }
    ModelOutcome::NotRestricted
}

/// Disagreement between the decision engine and the modelled OS rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyFinding {
    /// Device.
    pub instance_id: String,
    /// Decision engine verdict.
    pub verdict: Verdict,
    /// Modelled OS outcome.
    pub model: ModelOutcome,
    /// `enforcement_gap`: engine denies but OS rules would allow;
    /// `over_blocking`: engine allows/ignores but OS rules would prevent.
    pub kind: &'static str,
}

/// Compare every decision with the modelled plan outcome.
#[must_use]
pub fn check_consistency(
    plan: &DeviceInstallPlan,
    snapshot: &DeviceSnapshot,
    decisions: &[Decision],
) -> Vec<ConsistencyFinding> {
    let index = snapshot.index();
    decisions
        .iter()
        .filter_map(|dec| {
            let device = index.get(&dec.instance_id)?;
            let model = model_install_outcome(plan, device);
            let kind = match (dec.verdict, model) {
                (Verdict::Deny, ModelOutcome::Allowed { .. } | ModelOutcome::NotRestricted) => {
                    "enforcement_gap"
                }
                (Verdict::Allow | Verdict::NotApplicable, ModelOutcome::Prevented { .. }) => {
                    "over_blocking"
                }
                _ => return None,
            };
            Some(ConsistencyFinding {
                instance_id: dec.instance_id.clone(),
                verdict: dec.verdict,
                model,
                kind,
            })
        })
        .collect()
}
