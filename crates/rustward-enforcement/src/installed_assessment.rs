//! Read-only assessment of storage devices that **already have a device
//! installation** (Phase 10, step 2).
//!
//! Device Installation Restrictions act when Windows *installs* a device.
//! Microsoft: without the retroactive option, devices installed before the
//! policy keep working ("blocks all future … installations, but doesn't
//! apply to existing installs"). RustWard never plans a retroactive class
//! rule (it would also act on internal disks), so every denied device that
//! already has an installation **would remain accessible** when reconnected.
//!
//! This module only *reports*: for each storage device in an inventory it
//! states the simulated RustWard decision, the modelled outcome of a *new*
//! installation under the planned policy (`policy_eval`, NOT VERIFIED), and
//! whether the device would stay accessible; and it produces a reviewable,
//! **manual** remediation list. RustWard never uninstalls, removes, disables
//! or ejects a device and offers no code path to do so.

use serde::{Deserialize, Serialize};

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::class_guids;
use rustward_core::classify::{DeviceCategory, UsbStorageTransport};
use rustward_core::device::{DeviceRecord, DeviceSnapshot};
use rustward_core::evaluate::{Verdict, evaluate_snapshot};
use rustward_core::policy::ValidatedPolicy;
use rustward_core::report::Pseudonymizer;

use crate::EnforcementPlan;
use crate::policy_eval::{InstallOutcome, evaluate_install};
use crate::policy_state::{PolicySnapshot, apply_ops, forward_ops, merge_plan};

/// Windows problem code 28: "The drivers for this device are not installed."
pub const CM_PROB_FAILED_INSTALL: u32 = 28;

/// Whether the device node already has an installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallState {
    /// A driver service is recorded and no "drivers not installed" problem.
    Installed,
    /// Problem code 28: no installation exists; a policy would apply.
    NotInstalled,
    /// Not determinable from the inventory: treated as installed
    /// (fail-safe: assume it would stay accessible).
    Unknown,
}

fn install_state(d: &DeviceRecord) -> InstallState {
    if d.problem_code == Some(CM_PROB_FAILED_INSTALL) {
        InstallState::NotInstalled
    } else if d.service.as_deref().is_some_and(|s| !s.is_empty()) {
        InstallState::Installed
    } else {
        InstallState::Unknown
    }
}

/// What the assessment found for one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    /// Denied by policy, but its existing installation keeps working:
    /// manual remediation needed before enforcement could be effective.
    DeniedButInstalled,
    /// Denied by policy and not installed: a new installation would be
    /// prevented under the planned policy (model).
    DeniedNotInstalled,
    /// Allowed by policy; nothing to do.
    Allowed,
    /// Internal/system disk: out of scope, protected by an instance-ID
    /// allow rule; must never be remediated.
    InternalDiskProtected,
    /// Internal disk without an allow rule in the plan: activation hazard.
    InternalDiskUnprotected,
    /// Attachment cannot be determined: manual review, never remediation.
    AttachmentUnknown,
    /// Allowed by policy but the modelled new installation would be
    /// prevented (over-blocking in the plan).
    AllowedButPlanPrevents,
    /// Denied by policy but the modelled new installation would be allowed
    /// (gap in the plan).
    DeniedButPlanAllows,
}

/// One manual step for an administrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationStep {
    /// Turkish.
    pub tr: String,
    /// English.
    pub en: String,
}

/// Assessment of one storage device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessedDevice {
    /// Instance ID (pseudonymised tail when sanitised).
    pub instance_id: String,
    /// Friendly name or vendor/product.
    pub name: String,
    /// `usb_bot`, `usb_uasp`, `usb_other`, `internal`, `unknown_attachment`.
    pub attachment: String,
    /// Connected at inventory time.
    pub present: Option<bool>,
    /// Installation state.
    pub install_state: InstallState,
    /// Simulated RustWard verdict (`allow` / `deny`).
    pub simulated_verdict: String,
    /// Modelled outcome of a *new* installation under the planned policy.
    pub planned_new_install: InstallOutcome,
    /// Would remain usable after activation of the planned policy, because
    /// its existing installation is not affected.
    pub remains_accessible_after_activation: bool,
    /// Finding.
    pub finding: Finding,
    /// Manual remediation (only for [`Finding::DeniedButInstalled`]).
    pub remediation: Vec<RemediationStep>,
}

/// Counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentSummary {
    /// Storage devices assessed.
    pub assessed: usize,
    /// Denied devices that would stay accessible.
    pub denied_but_installed: usize,
    /// Denied devices a new installation of which would be prevented.
    pub denied_not_installed: usize,
    /// Allowed devices.
    pub allowed: usize,
    /// Internal disks (protected / unprotected).
    pub internal_protected: usize,
    /// Internal disks without an allow rule.
    pub internal_unprotected: usize,
    /// Devices needing manual review.
    pub needs_review: usize,
    /// Plan disagreements (over-blocking + gaps).
    pub plan_disagreements: usize,
}

/// The full, reviewable report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledAssessment {
    /// Instance IDs pseudonymised.
    pub sanitized: bool,
    /// Devices.
    pub devices: Vec<AssessedDevice>,
    /// Counts.
    pub summary: AssessmentSummary,
    /// Requirements the selected mechanism cannot fulfil (TR / EN).
    pub limitations: Vec<RemediationStep>,
    /// Always `true`: RustWard performs none of the remediation itself.
    pub manual_only: bool,
}

fn step(tr: &str, en: &str) -> RemediationStep {
    RemediationStep {
        tr: tr.into(),
        en: en.into(),
    }
}

fn remediation() -> Vec<RemediationStep> {
    vec![
        step(
            "Aygıtın gerçekten gerekli olmadığını ve verilerinin yedeklendiğini doğrulayın; sistem geri yükleme noktası veya disk imajı alın.",
            "Confirm the device is not needed and its data is backed up; take a restore point or disk image.",
        ),
        step(
            "Aygıtı çıkarın. Yönetici olarak Aygıt Yöneticisi'nde Görünüm → Gizli aygıtları göster; Disk sürücüleri altında bu aygıtı seçip “Aygıtı kaldır” ile kurulumunu elle kaldırın. RustWard bu işlemi yapmaz.",
            "Disconnect it. As an administrator, in Device Manager choose View → Show hidden devices, select the device under Disk drives and use “Uninstall device” to remove its installation manually. RustWard never does this.",
        ),
        step(
            "Envanteri yeniden alın ve bu değerlendirmeyi tekrar çalıştırın: aygıt artık listelenmemeli ya da “kurulu değil” görünmelidir. Gerçek engelleme yalnızca etkinleştirme ve okuma/yazma doğrulamasından sonra kanıtlanır.",
            "Recapture the inventory and run this assessment again: the device must no longer be listed or must show as not installed. Actual blocking is proven only after activation and a read/write verification.",
        ),
    ]
}

fn limitations(denied_installed: usize) -> Vec<RemediationStep> {
    vec![
        step(
            &format!(
                "Yükleme kısıtlamaları mevcut kurulumları etkilemez: {denied_installed} reddedilen aygıt elle kaldırılmadıkça erişilebilir kalır."
            ),
            &format!(
                "Installation restrictions do not affect existing installations: {denied_installed} denied device(s) stay accessible until removed manually."
            ),
        ),
        step(
            "Geriye dönük (retroaktif) sınıf kuralı kullanılmaz: dahili diskleri de etkiler ve sistemi açılmaz hâle getirebilir.",
            "No retroactive class rule is used: it would also act on internal disks and could make the system unbootable.",
        ),
        step(
            "Marka kimliği aygıtın bildirdiği satıcı dizesidir; kriptografik olarak doğrulanmaz.",
            "Brand identity is the vendor string the device reports; it is not cryptographically verified.",
        ),
        step(
            "CD/DVD, MTP telefonlar ve DiskDrive dışı sınıflar disk sınıfı kuralının kapsamında değildir.",
            "CD/DVD, MTP phones and non-DiskDrive classes are outside the disk-class rule.",
        ),
        step(
            "Bu rapor bir modeldir; Windows davranışı aşama F'de doğrulanmalıdır.",
            "This report is a model; Windows behaviour must be verified in stage F.",
        ),
    ]
}

/// Inputs.
#[derive(Debug, Clone, Copy)]
pub struct AssessmentInputs<'a> {
    /// Inventory, ideally including non-present devices.
    pub snapshot: &'a DeviceSnapshot,
    /// Active policy.
    pub policy: &'a ValidatedPolicy,
    /// Catalog.
    pub catalog: &'a ValidatedCatalog,
    /// The RustWard plan.
    pub plan: &'a EnforcementPlan,
    /// Captured existing policy (empty if unknown).
    pub existing: &'a PolicySnapshot,
    /// Pseudonymise instance IDs.
    pub sanitize: bool,
}

/// The policy that would be in place after the plan was merged with the
/// existing policy (model only).
#[must_use]
pub fn planned_policy(existing: &PolicySnapshot, plan: &EnforcementPlan) -> PolicySnapshot {
    let merged = merge_plan(existing, plan);
    match forward_ops(existing, &merged) {
        Ok(ops) => apply_ops(existing, &ops),
        Err(_) => existing.clone(),
    }
}

/// Assess every disk-class device in the inventory.
#[must_use]
pub fn assess(i: &AssessmentInputs<'_>) -> InstalledAssessment {
    let planned = planned_policy(i.existing, i.plan);
    let decisions = evaluate_snapshot(i.snapshot, i.policy, i.catalog);
    let mut pseudo = Pseudonymizer::default();
    let mut devices = Vec::new();
    let mut summary = AssessmentSummary::default();
    for d in &i.snapshot.devices {
        if !d.class_is(class_guids::DISK_DRIVE) {
            continue; // keyboards, mice, printers, hubs: never assessed
        }
        let Some(decision) = decisions.iter().find(|x| x.instance_id == d.instance_id) else {
            continue;
        };
        let attachment = match &decision.classification.category {
            DeviceCategory::UsbStorageDisk { transport } => match transport {
                UsbStorageTransport::BulkOnly => "usb_bot",
                UsbStorageTransport::Uasp => "usb_uasp",
                UsbStorageTransport::Unknown => "usb_other",
            },
            DeviceCategory::SystemOrNonUsbStorage => "internal",
            DeviceCategory::StorageAttachmentUnknown => "unknown_attachment",
            _ => continue,
        };
        let state = install_state(d);
        let outcome = evaluate_install(&planned, d);
        let installed = state != InstallState::NotInstalled;
        let verdict = decision.verdict;
        let finding = match (attachment, verdict) {
            ("internal", _) if outcome.is_prevented() => Finding::InternalDiskUnprotected,
            ("internal", _) => Finding::InternalDiskProtected,
            ("unknown_attachment", _) => Finding::AttachmentUnknown,
            (_, Verdict::Allow) if outcome.is_prevented() => Finding::AllowedButPlanPrevents,
            (_, Verdict::Allow) => Finding::Allowed,
            (_, _) if !outcome.is_prevented() => Finding::DeniedButPlanAllows,
            (_, _) if installed => Finding::DeniedButInstalled,
            (_, _) => Finding::DeniedNotInstalled,
        };
        match finding {
            Finding::DeniedButInstalled => summary.denied_but_installed += 1,
            Finding::DeniedNotInstalled => summary.denied_not_installed += 1,
            Finding::Allowed => summary.allowed += 1,
            Finding::InternalDiskProtected => summary.internal_protected += 1,
            Finding::InternalDiskUnprotected => summary.internal_unprotected += 1,
            Finding::AttachmentUnknown => summary.needs_review += 1,
            Finding::AllowedButPlanPrevents | Finding::DeniedButPlanAllows => {
                summary.plan_disagreements += 1;
            }
        }
        let name = d
            .friendly_name
            .clone()
            .or_else(|| {
                decision.classification.inquiry.as_ref().map(|q| {
                    format!(
                        "{} {}",
                        q.vendor_field.trim_end_matches('_'),
                        q.product_field
                            .as_deref()
                            .unwrap_or("")
                            .trim_end_matches('_')
                    )
                })
            })
            .unwrap_or_else(|| "—".into());
        devices.push(AssessedDevice {
            instance_id: if i.sanitize {
                pseudo.instance_id(&d.instance_id)
            } else {
                d.instance_id.clone()
            },
            name,
            attachment: attachment.into(),
            present: d.present,
            install_state: state,
            simulated_verdict: match verdict {
                Verdict::Allow => "allow".into(),
                Verdict::Deny => "deny".into(),
                Verdict::NotApplicable => "not_applicable".into(),
            },
            remains_accessible_after_activation: installed && verdict == Verdict::Deny,
            planned_new_install: outcome,
            remediation: if finding == Finding::DeniedButInstalled {
                remediation()
            } else {
                Vec::new()
            },
            finding,
        });
    }
    summary.assessed = devices.len();
    InstalledAssessment {
        sanitized: i.sanitize,
        limitations: limitations(summary.denied_but_installed),
        devices,
        summary,
        manual_only: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_install::RESTRICTIONS_KEY;
    use crate::policy_state::RegData;
    use crate::{
        DeviceInstallRestrictionProvider, EnforcementProvider, EnvironmentFacts, PlanInputs,
    };

    const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
    const POLICY: &str = include_str!("../../../config/policy.example.json");
    const SNAPSHOT: &str = include_str!("../../../tests/fixtures/synthetic-lab-snapshot.json");

    fn run(
        edit: impl FnOnce(&mut DeviceSnapshot),
        existing: &PolicySnapshot,
        sanitize: bool,
    ) -> InstalledAssessment {
        let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
        let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
        let mut snapshot = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
        edit(&mut snapshot);
        let env = EnvironmentFacts::default();
        let plan = DeviceInstallRestrictionProvider.plan(PlanInputs {
            policy: &policy,
            catalog: &catalog,
            snapshot: &snapshot,
            env: &env,
        });
        assess(&AssessmentInputs {
            snapshot: &snapshot,
            policy: &policy,
            catalog: &catalog,
            plan: &plan,
            existing,
            sanitize,
        })
    }

    fn by<'a>(a: &'a InstalledAssessment, needle: &str) -> &'a AssessedDevice {
        a.devices
            .iter()
            .find(|d| d.instance_id.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not assessed"))
    }

    #[test]
    fn installed_denied_brands_stay_accessible_and_get_manual_remediation() {
        let a = run(|_| {}, &PolicySnapshot::default(), false);
        assert!(a.manual_only);
        let kingston = by(&a, "Ven_Kingston&Prod_DataTraveler_3.0");
        assert_eq!(kingston.simulated_verdict, "deny");
        assert_eq!(kingston.finding, Finding::DeniedButInstalled);
        assert!(kingston.remains_accessible_after_activation);
        assert!(
            kingston.planned_new_install.is_prevented(),
            "a fresh install would be prevented (model)"
        );
        assert_eq!(kingston.remediation.len(), 3);
        assert!(
            kingston.remediation[1]
                .tr
                .contains("RustWard bu işlemi yapmaz")
        );
        // A previously connected (non-present) Kingston keeps its installation too.
        let old = by(&a, "Ven_Kingston&Prod_DT_101_G2");
        assert_eq!(old.present, Some(false));
        assert!(old.remains_accessible_after_activation);
        // Unknown manufacturers are denied, never allowed by default.
        let generic = by(&a, "Ven_Generic&Prod_Flash_Disk");
        assert_eq!(generic.simulated_verdict, "deny");
        assert!(generic.remains_accessible_after_activation);
        assert!(a.summary.denied_but_installed >= 4, "{:?}", a.summary);
        assert!(
            a.limitations[0]
                .en
                .contains(&a.summary.denied_but_installed.to_string())
        );
    }

    #[test]
    fn allowed_brands_including_uasp_and_unseen_models_are_allowed() {
        let a = run(|_| {}, &PolicySnapshot::default(), false);
        let sandisk = by(&a, "Ven_SanDisk&Prod_Ultra&Rev");
        assert_eq!(sandisk.finding, Finding::Allowed);
        assert!(!sandisk.planned_new_install.is_prevented());
        assert!(
            !sandisk.remains_accessible_after_activation,
            "not a denied device"
        );
        // A SanDisk model the catalog has never seen, by vendor-level ID.
        let a = run(
            |s| {
                let mut d = s
                    .devices
                    .iter()
                    .find(|d| d.instance_id.contains("Prod_Ultra&Rev"))
                    .unwrap()
                    .clone();
                d.instance_id =
                    "USBSTOR\\Disk&Ven_SanDisk&Prod_Extreme_PRO_2TB&Rev_1.00\\NEWSERIAL&0".into();
                d.hardware_ids = vec![
                    "USBSTOR\\DiskSanDisk_Extreme_PRO_2TB1.00".into(),
                    "USBSTOR\\DiskSanDisk_Extreme_PRO_2TB".into(),
                    "USBSTOR\\DiskSanDisk_".into(),
                    "USBSTOR\\SanDisk_Extreme_PRO_2TB1".into(),
                    "SanDisk_Extreme_PRO_2TB1".into(),
                    "USBSTOR\\GenDisk".into(),
                    "GenDisk".into(),
                ];
                d.friendly_name = Some("SanDisk Extreme PRO 2TB".into());
                s.devices.push(d);
            },
            &PolicySnapshot::default(),
            false,
        );
        let new_model = by(&a, "Prod_Extreme_PRO_2TB");
        assert_eq!(new_model.finding, Finding::Allowed, "{new_model:?}");
        assert!(!new_model.planned_new_install.is_prevented());
    }

    #[test]
    fn internal_disks_are_protected_never_remediated_and_peripherals_ignored() {
        let a = run(|_| {}, &PolicySnapshot::default(), false);
        for d in a.devices.iter().filter(|d| d.attachment == "internal") {
            assert_eq!(d.finding, Finding::InternalDiskProtected, "{d:?}");
            assert!(d.remediation.is_empty());
            assert!(!d.remains_accessible_after_activation);
        }
        assert!(a.summary.internal_protected >= 2);
        // The fixture's broken-chain disk: review, never remediation.
        let t7 = by(&a, "PSSD_T7");
        assert_eq!(t7.finding, Finding::AttachmentUnknown);
        assert!(t7.remediation.is_empty());
        // Only disk-class devices are assessed.
        assert!(a.devices.iter().all(|d| d.attachment != "peripheral"));
        assert!(!a.devices.iter().any(|d| d.instance_id.starts_with("HID\\")));
    }

    #[test]
    fn not_installed_denied_devices_would_be_prevented() {
        let a = run(
            |s| {
                let k = s
                    .devices
                    .iter_mut()
                    .find(|d| d.instance_id.contains("Prod_DataTraveler_3.0"))
                    .unwrap();
                k.problem_code = Some(CM_PROB_FAILED_INSTALL);
            },
            &PolicySnapshot::default(),
            false,
        );
        let k = by(&a, "Prod_DataTraveler_3.0");
        assert_eq!(k.install_state, InstallState::NotInstalled);
        assert_eq!(k.finding, Finding::DeniedNotInstalled);
        assert!(!k.remains_accessible_after_activation);
        assert!(k.remediation.is_empty());
    }

    #[test]
    fn existing_policy_can_turn_the_plan_into_a_hazard() {
        // An existing prevent on an internal disk's instance ID outranks the
        // planned allow: reported, not hidden.
        let internal = {
            let s = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
            s.devices
                .iter()
                .find(|d| d.instance_id.starts_with("SCSI\\Disk&Ven_Samsung&Prod_SSD"))
                .unwrap()
                .instance_id
                .clone()
        };
        let existing = PolicySnapshot::default()
            .with(RESTRICTIONS_KEY, "DenyInstanceIDs", RegData::Dword(1))
            .with(
                &format!(r"{RESTRICTIONS_KEY}\DenyInstanceIDs"),
                "1",
                RegData::Sz(internal.clone()),
            );
        let a = run(|_| {}, &existing, false);
        let d = by(&a, "Prod_SSD_870_EVO");
        assert_eq!(d.finding, Finding::InternalDiskUnprotected);
        assert_eq!(a.summary.internal_unprotected, 1);
    }

    #[test]
    fn sanitised_reports_hide_serial_numbers() {
        let a = run(|_| {}, &PolicySnapshot::default(), true);
        assert!(a.sanitized);
        assert!(
            a.devices
                .iter()
                .all(|d| !d.instance_id.contains("4C5300012306151"))
        );
        assert!(a.devices.iter().any(|d| d.instance_id.contains("ID-0")));
    }
}
