//! Windows Device Installation Restrictions provider — **design + dry-run**.
//!
//! Translates `rustward-core::plan::DeviceInstallPlan` into the registry
//! policy values a future activation would write under
//! `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`,
//! checks preconditions, models the outcome on an inventory and produces a
//! recovery plan. It never writes anything.
//!
//! Not an automatic production feature: the DiskDrive class prevent rule is
//! never retroactive, internal disks are protected by instance-ID allow
//! rules, and activation stays disabled until VM validation.

use rustward_core::evaluate::{Verdict, evaluate_snapshot};
use rustward_core::plan::{check_consistency, compile_plan};
use rustward_core::policy::PolicyMode;

use crate::{
    ActivationError, CapabilityReport, CapabilityStatus, DryRunReport, EnforcementPlan,
    EnforcementProvider, EnforcementState, EnvironmentFacts, PlanInputs, PlanMode, PlannedChange,
    Precondition, PreconditionStatus, RecoveryStep,
};

/// Registry key of the device installation restriction policies.
pub const RESTRICTIONS_KEY: &str =
    r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";

/// Minimum Windows 10 2004/20H2/21H2/22H2 UBR family with layered evaluation
/// (Microsoft: 2004 needs KB5004296, build 19041.1151). 19042-19045 share the
/// servicing branch with 19041; the same UBR threshold is applied.
pub const MIN_LAYERING_UBR_19041: u32 = 1151;

/// The dry-run Device Installation Restrictions provider.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceInstallRestrictionProvider;

fn change(
    name: &str,
    sub: Option<&str>,
    ty: &str,
    data: &str,
    purpose: &str,
    confirmed: bool,
) -> PlannedChange {
    PlannedChange {
        hive: "HKLM".into(),
        key: match sub {
            Some(s) => format!(r"{RESTRICTIONS_KEY}\{s}"),
            None => RESTRICTIONS_KEY.into(),
        },
        value_name: name.into(),
        value_type: ty.into(),
        data: data.into(),
        purpose: purpose.into(),
        confirmed_against_documentation: confirmed,
    }
}

fn pre(id: &str, en: &str, tr: &str, status: PreconditionStatus) -> Precondition {
    Precondition {
        id: id.into(),
        en: en.into(),
        tr: tr.into(),
        status,
    }
}

fn layering_supported(build: Option<(u32, u32)>) -> PreconditionStatus {
    match build {
        None => PreconditionStatus::Unknown,
        Some((b, ubr)) if (19041..=19045).contains(&b) => {
            if ubr >= MIN_LAYERING_UBR_19041 {
                PreconditionStatus::Met
            } else {
                PreconditionStatus::NotMet
            }
        }
        Some((b, _)) if b >= 22000 => PreconditionStatus::Met,
        Some(_) => PreconditionStatus::NotMet,
    }
}

impl DeviceInstallRestrictionProvider {
    fn preconditions(inputs: &PlanInputs<'_>, has_internal_allow: bool) -> Vec<Precondition> {
        let env = inputs.env;
        let met = |b: bool| {
            if b {
                PreconditionStatus::Met
            } else {
                PreconditionStatus::NotMet
            }
        };
        let edition = match env.edition.as_deref() {
            None => PreconditionStatus::Unknown,
            Some(e) => met(["Professional", "Enterprise", "Education"]
                .iter()
                .any(|x| e.contains(x))),
        };
        vec![
            pre(
                "windows",
                "Running on Windows",
                "Windows üzerinde çalışıyor",
                met(env.is_windows),
            ),
            pre(
                "edition",
                "Windows Pro/Enterprise/Education edition",
                "Windows Pro/Enterprise/Education sürümü",
                edition,
            ),
            pre(
                "layering_supported",
                "OS build supports layered evaluation (Win10 19041.1151+ or Win11)",
                "İşletim sistemi katmanlı değerlendirmeyi destekliyor (Win10 19041.1151+ veya Win11)",
                layering_supported(env.os_build),
            ),
            pre(
                "policy_enforce_mode",
                "Policy is in enforce mode with lab-verified identifiers",
                "Politika uygulama modunda ve kimlikler laboratuvarda doğrulanmış",
                met(inputs.policy.policy().mode == PolicyMode::Enforce),
            ),
            pre(
                "baseline_captured",
                "Baseline inventory (incl. non-present devices) captured",
                "Önceden yüklenmiş aygıtlar dahil temel envanter alındı",
                met(env.baseline_captured),
            ),
            pre(
                "internal_disks_protected",
                "Every existing internal disk has an instance-ID allow rule",
                "Mevcut her dahili disk için örnek kimliği izin kuralı var",
                met(has_internal_allow),
            ),
            pre(
                "installed_devices_reviewed",
                "Already-installed unauthorized USB storage reviewed (install rules do not affect them)",
                "Önceden yüklenmiş yetkisiz USB depolama gözden geçirildi (yükleme kuralları bunları etkilemez)",
                met(env.installed_devices_reviewed),
            ),
            pre(
                "feature_update_risk_acknowledged",
                "Feature-update / storage-driver-reinstall boot risk acknowledged and maintenance procedure in place",
                "Sürüm yükseltme / depolama sürücüsü yeniden yükleme önyükleme riski kabul edildi, bakım prosedürü hazır",
                met(env.feature_update_risk_acknowledged),
            ),
            pre(
                "vm_validation",
                "Plan validated in the Windows VM acceptance phase",
                "Plan Windows sanal makine kabul aşamasında doğrulandı",
                PreconditionStatus::NotMet,
            ),
        ]
    }
}

impl EnforcementProvider for DeviceInstallRestrictionProvider {
    fn id(&self) -> &'static str {
        "windows-device-install-restrictions"
    }

    fn capabilities(&self, env: &EnvironmentFacts) -> CapabilityReport {
        let designed = if env.is_windows {
            CapabilityStatus::DesignedNotVerified
        } else {
            CapabilityStatus::Unsupported
        };
        CapabilityReport {
            provider_id: self.id().into(),
            pre_access_blocking: designed,
            brand_allowlisting: designed,
            // Install-time rules never re-evaluate installed devices.
            previously_installed_devices: CapabilityStatus::Unsupported,
            persistence: designed,
            self_verification: CapabilityStatus::NotImplemented,
            activation_available: crate::ACTIVATION_ENABLED,
        }
    }

    fn plan(&self, inputs: PlanInputs<'_>) -> EnforcementPlan {
        let dip = compile_plan(inputs.policy, inputs.catalog, Some(inputs.snapshot));
        let mut changes = vec![change(
            "AllowDenyLayered",
            None,
            "REG_DWORD",
            "1",
            "Apply layered order of evaluation (instance IDs > device IDs > setup class)",
            true,
        )];
        if !dip.prevent_setup_classes.is_empty() {
            changes.push(change(
                "DenyDeviceClasses",
                None,
                "REG_DWORD",
                "1",
                "Enable prevent-by-setup-class list",
                false,
            ));
            changes.push(change(
                "DenyDeviceClassesRetroactive",
                None,
                "REG_DWORD",
                "0",
                "Never retroactive: a retroactive DiskDrive rule would affect the system disk",
                false,
            ));
            for (i, r) in dip.prevent_setup_classes.iter().enumerate() {
                changes.push(change(
                    &(i + 1).to_string(),
                    Some("DenyDeviceClasses"),
                    "REG_SZ",
                    &r.class_guid,
                    &format!("Prevent class {}", r.class_name),
                    false,
                ));
            }
        }
        if !dip.allow_device_ids.is_empty() {
            changes.push(change(
                "AllowDeviceIDs",
                None,
                "REG_DWORD",
                "1",
                "Enable allow-by-device-ID list",
                false,
            ));
            for (i, r) in dip.allow_device_ids.iter().enumerate() {
                changes.push(change(
                    &(i + 1).to_string(),
                    Some("AllowDeviceIDs"),
                    "REG_SZ",
                    &r.device_id,
                    &format!("Allow brand {:?} ({:?} namespace)", r.brand_id, r.namespace),
                    false,
                ));
            }
        }
        if !dip.allow_instance_ids.is_empty() {
            changes.push(change(
                "AllowInstanceIDs",
                None,
                "REG_DWORD",
                "1",
                "Enable allow-by-instance-ID list",
                false,
            ));
            for (i, r) in dip.allow_instance_ids.iter().enumerate() {
                changes.push(change(
                    &(i + 1).to_string(),
                    Some("AllowInstanceIDs"),
                    "REG_SZ",
                    &r.instance_id,
                    &r.reason,
                    false,
                ));
            }
        }

        let mut risks = dip.warnings.clone();
        risks.extend([
            "Feature updates and storage-controller driver changes re-detect hardware; with a DiskDrive prevent rule the boot disk may be blocked (community-reported BSOD/Startup Repair). Suspend the policy during maintenance.".to_owned(),
            "New internal disks, VHD/VHDX mounts, Storage Spaces and iSCSI disks are blocked until allowed.".to_owned(),
            "A device reporting an approved INQUIRY vendor string is allowed even if not genuine (identifiers are not authenticated).".to_owned(),
            "A local administrator can remove the policy; operators must be standard users.".to_owned(),
        ]);

        let recovery = [
            ("Export the current Restrictions key before activation (baseline).", "Etkinleştirmeden önce mevcut Restrictions anahtarını dışa aktarın (temel durum)."),
            ("To roll back, restore the exported key (or delete the RustWard-set values) and run gpupdate /force; rescan devices.", "Geri almak için dışa aktarılan anahtarı geri yükleyin (veya RustWard değerlerini silin), gpupdate /force çalıştırın ve aygıtları yeniden tarayın."),
            ("If the system does not boot after an update, boot WinRE, load the offline SOFTWARE hive and remove the DenyDeviceClasses values, or restore the disk image.", "Güncelleme sonrası sistem açılmazsa WinRE ile başlatın, çevrimdışı SOFTWARE kovanını yükleyip DenyDeviceClasses değerlerini kaldırın veya disk imajını geri yükleyin."),
            ("Verify keyboard, mouse and internal disks after every change; record evidence.", "Her değişiklikten sonra klavye, fare ve dahili diskleri doğrulayın; kanıt kaydedin."),
        ]
        .iter()
        .zip(1u32..)
        .map(|((en, tr), order)| RecoveryStep {
            order,
            en: (*en).into(),
            tr: (*tr).into(),
        })
        .collect();

        EnforcementPlan {
            provider_id: self.id().into(),
            mode: PlanMode::DryRun,
            workstation_id: inputs.policy.policy().workstation_id.clone(),
            policy_version: inputs.policy.policy().policy_version,
            preconditions: Self::preconditions(&inputs, !dip.allow_instance_ids.is_empty()),
            changes,
            risks,
            recovery,
            activation_allowed: false,
        }
    }

    fn dry_run(&self, _plan: &EnforcementPlan, inputs: PlanInputs<'_>) -> DryRunReport {
        let dip = compile_plan(inputs.policy, inputs.catalog, Some(inputs.snapshot));
        let decisions = evaluate_snapshot(inputs.snapshot, inputs.policy, inputs.catalog);
        let findings = check_consistency(&dip, inputs.snapshot, &decisions);
        DryRunReport {
            enforcement_gaps: findings
                .iter()
                .filter(|f| f.kind == "enforcement_gap")
                .map(|f| f.instance_id.clone())
                .collect(),
            over_blocking: findings
                .iter()
                .filter(|f| f.kind == "over_blocking")
                .map(|f| f.instance_id.clone())
                .collect(),
            already_installed_denied: decisions
                .iter()
                .filter(|d| d.verdict == Verdict::Deny)
                .map(|d| d.instance_id.clone())
                .collect(),
            notes: vec![
                "Dry-run model only: no registry value was written and nothing is enforced.".into(),
                format!(
                    "{} planned allow rules, {} prevent rules",
                    dip.allow_device_ids.len() + dip.allow_instance_ids.len(),
                    dip.prevent_setup_classes.len()
                ),
            ],
        }
    }

    fn activate(&self, plan: &EnforcementPlan) -> Result<(), ActivationError> {
        if !crate::ACTIVATION_ENABLED || !plan.activation_allowed {
            return Err(ActivationError::ActivationDisabled);
        }
        let unmet: Vec<String> = plan
            .preconditions
            .iter()
            .filter(|p| p.status != PreconditionStatus::Met)
            .map(|p| p.id.clone())
            .collect();
        if unmet.is_empty() {
            // No activation path exists in this build.
            Err(ActivationError::ActivationDisabled)
        } else {
            Err(ActivationError::PreconditionsNotMet(unmet))
        }
    }

    fn status(&self) -> EnforcementState {
        EnforcementState::PendingValidation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustward_core::catalog::ValidatedCatalog;
    use rustward_core::device::DeviceSnapshot;
    use rustward_core::policy::ValidatedPolicy;

    const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
    const POLICY: &str = include_str!("../../../config/policy.example.json");
    const SNAPSHOT: &str = include_str!("../../../tests/fixtures/synthetic-lab-snapshot.json");

    fn with_inputs<R>(env: &EnvironmentFacts, f: impl FnOnce(PlanInputs<'_>) -> R) -> R {
        let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
        let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
        let snapshot = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
        f(PlanInputs {
            policy: &policy,
            catalog: &catalog,
            snapshot: &snapshot,
            env,
        })
    }

    #[test]
    fn plan_is_dry_run_never_retroactive_and_protects_internal_disks() {
        let env = EnvironmentFacts::default();
        let plan = with_inputs(&env, |i| DeviceInstallRestrictionProvider.plan(i));
        assert_eq!(plan.mode, PlanMode::DryRun);
        assert!(!plan.activation_allowed);
        let retro = plan
            .changes
            .iter()
            .find(|c| c.value_name == "DenyDeviceClassesRetroactive")
            .unwrap();
        assert_eq!(retro.data, "0");
        assert!(
            plan.changes
                .iter()
                .any(|c| c.key.ends_with("AllowInstanceIDs"))
        );
        assert!(
            plan.changes
                .iter()
                .any(|c| c.data == r"USBSTOR\DiskSanDisk_")
        );
        assert!(
            !plan.changes.iter().any(|c| c.data.contains("Kingston")),
            "unapproved brands get no allow rule"
        );
        let layered = plan
            .changes
            .iter()
            .find(|c| c.value_name == "AllowDenyLayered")
            .unwrap();
        assert!(layered.confirmed_against_documentation);
        assert!(
            plan.changes
                .iter()
                .filter(|c| c.value_name != "AllowDenyLayered")
                .all(|c| !c.confirmed_against_documentation)
        );
        assert!(plan.risks.iter().any(|r| r.contains("Feature updates")));
        assert_eq!(plan.recovery.len(), 4);
    }

    #[test]
    fn preconditions_reflect_environment_and_block_activation() {
        let env = EnvironmentFacts {
            is_windows: true,
            os_build: Some((19045, 900)),
            edition: Some("Professional".into()),
            ..EnvironmentFacts::default()
        };
        let plan = with_inputs(&env, |i| DeviceInstallRestrictionProvider.plan(i));
        let status = |id: &str| {
            plan.preconditions
                .iter()
                .find(|p| p.id == id)
                .unwrap()
                .status
        };
        assert_eq!(status("windows"), PreconditionStatus::Met);
        assert_eq!(status("edition"), PreconditionStatus::Met);
        assert_eq!(
            status("layering_supported"),
            PreconditionStatus::NotMet,
            "UBR below 1151"
        );
        assert_eq!(status("vm_validation"), PreconditionStatus::NotMet);
        assert_eq!(
            DeviceInstallRestrictionProvider.activate(&plan),
            Err(ActivationError::ActivationDisabled)
        );
        // Even a forged plan claiming activation_allowed is refused.
        let forged = EnforcementPlan {
            activation_allowed: true,
            ..plan
        };
        assert_eq!(
            DeviceInstallRestrictionProvider.activate(&forged),
            Err(ActivationError::ActivationDisabled)
        );
    }

    #[test]
    fn layering_build_thresholds() {
        assert_eq!(
            layering_supported(Some((19045, 1151))),
            PreconditionStatus::Met
        );
        assert_eq!(
            layering_supported(Some((22631, 1))),
            PreconditionStatus::Met
        );
        assert_eq!(
            layering_supported(Some((18363, 9999))),
            PreconditionStatus::NotMet
        );
        assert_eq!(layering_supported(None), PreconditionStatus::Unknown);
    }

    #[test]
    fn dry_run_reports_gaps_and_installed_devices_without_side_effects() {
        let env = EnvironmentFacts::default();
        let report = with_inputs(&env, |i| {
            let plan = DeviceInstallRestrictionProvider.plan(i);
            DeviceInstallRestrictionProvider.dry_run(&plan, i)
        });
        assert_eq!(
            report.enforcement_gaps.len(),
            3,
            "2 CD-ROM LUNs + MTP phone"
        );
        assert!(report.over_blocking.is_empty());
        assert!(
            report
                .already_installed_denied
                .iter()
                .any(|d| d.contains("Kingston"))
        );
        assert!(report.notes[0].contains("no registry value was written"));
    }

    #[test]
    fn status_and_capabilities_are_honest() {
        let p = DeviceInstallRestrictionProvider;
        assert_eq!(p.status(), EnforcementState::PendingValidation);
        let caps = p.capabilities(&EnvironmentFacts {
            is_windows: true,
            ..EnvironmentFacts::default()
        });
        assert_eq!(
            caps.previously_installed_devices,
            CapabilityStatus::Unsupported
        );
        assert_eq!(
            caps.pre_access_blocking,
            CapabilityStatus::DesignedNotVerified
        );
        assert!(!caps.activation_available);
        let linux = p.capabilities(&EnvironmentFacts::default());
        assert_eq!(linux.pre_access_blocking, CapabilityStatus::Unsupported);
    }
}
