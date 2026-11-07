//! Regression tests on sanitized identifiers observed on real hardware in the
//! authorized test VM (`tests/fixtures/vm-observed-usb-2026-11-07.json`),
//! evaluated under the DRY-RUN ONLY VM test policy
//! (`config/vm-enforcement-test-policy.json`).
//!
//! Every verdict here is a SIMULATED decision of RustWard's model. Nothing
//! in this file says that Windows blocked anything.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::classify::{DeviceCategory, UsbStorageTransport};
use rustward_core::device::DeviceSnapshot;
use rustward_core::evaluate::{
    Decision, DecisionReason, EnforcementStatus, Verdict, evaluate_snapshot,
};
use rustward_core::policy::{PolicyError, PolicyMode, ValidatedPolicy};
use rustward_enforcement::activation::system_disk_gate;
use rustward_enforcement::installed_assessment::{AssessmentInputs, Finding, assess};
use rustward_enforcement::policy_state::{PolicySnapshot, RegData, desired_values};
use rustward_enforcement::{
    DeviceInstallRestrictionProvider, EnforcementPlan, EnforcementProvider, EnvironmentFacts,
    PlanInputs, PreconditionStatus,
};

const OBSERVED: &str = include_str!("../../../tests/fixtures/vm-observed-usb-2026-11-07.json");
const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
const TEST_POLICY: &str = include_str!("../../../config/vm-enforcement-test-policy.json");

const KINGSTON: &str = "USBSTOR\\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0";
const ASELSAN_LABELLED: &str = "USBSTOR\\DISK&VEN_VENDORC&PROD_PRODUCTCODE";
const INTERNAL_NVME: &str = "SCSI\\DISK&VEN_NVME";

struct Ctx {
    snapshot: DeviceSnapshot,
    catalog: ValidatedCatalog,
    policy: ValidatedPolicy,
    decisions: Vec<Decision>,
}

fn ctx() -> Ctx {
    let snapshot = DeviceSnapshot::from_json(OBSERVED).unwrap();
    let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
    let policy = ValidatedPolicy::from_json(TEST_POLICY, &catalog).unwrap();
    let decisions = evaluate_snapshot(&snapshot, &policy, &catalog);
    Ctx {
        snapshot,
        catalog,
        policy,
        decisions,
    }
}

fn decision<'a>(c: &'a Ctx, prefix: &str) -> &'a Decision {
    let m: Vec<_> = c
        .decisions
        .iter()
        .filter(|d| d.instance_id.starts_with(prefix))
        .collect();
    assert_eq!(m.len(), 1, "exactly one device starting with {prefix}");
    m[0]
}

fn plan(c: &Ctx) -> EnforcementPlan {
    DeviceInstallRestrictionProvider.plan(PlanInputs {
        policy: &c.policy,
        catalog: &c.catalog,
        snapshot: &c.snapshot,
        env: &EnvironmentFacts::default(),
    })
}

/// Every string value the plan would write (allow-list entries).
fn planned_strings(p: &EnforcementPlan) -> Vec<String> {
    desired_values(p)
        .expect("plan values")
        .into_values()
        .filter_map(|v| match v {
            RegData::Sz(s) => Some(s.to_ascii_uppercase()),
            _ => None,
        })
        .collect()
}

#[test]
fn fixture_is_sanitized() {
    let s = DeviceSnapshot::from_json(OBSERVED).unwrap();
    assert!(OBSERVED.contains("\"computer_name\": null"));
    for d in &s.devices {
        let tail = d.instance_id.rsplit('\\').next().unwrap();
        assert!(
            tail.contains("REDACTED"),
            "unredacted suffix: {}",
            d.instance_id
        );
    }
}

#[test]
fn test_policy_is_dry_run_only_and_cannot_be_switched_to_enforce() {
    let c = ctx();
    assert_eq!(c.policy.policy().mode, PolicyMode::DryRun);
    assert!(TEST_POLICY.contains("DRY-RUN ONLY"));
    // TÜBİTAK SIR II is deferred: present only as a disabled entry.
    let tubitak = c
        .policy
        .policy()
        .allowed_brands
        .iter()
        .find(|b| b.brand_id == "tubitak")
        .unwrap();
    assert!(!tubitak.enabled);
    assert!(tubitak.note.as_deref().unwrap_or("").contains("DEFERRED"));
    // The validator refuses it as an enforce policy: SanDisk's identifier is
    // not lab-verified (and the observed stick did not confirm it).
    let enforce = TEST_POLICY.replace("\"dry_run\"", "\"enforce\"");
    match ValidatedPolicy::from_json(&enforce, &c.catalog) {
        Err(PolicyError::Invalid(issues)) => {
            assert!(issues.iter().any(|i| i.code == "identifier_unverified"));
        }
        other => panic!("enforce must be refused, got {other:?}"),
    }
}

#[test]
fn kingston_receives_a_simulated_deny() {
    let c = ctx();
    let k = decision(&c, KINGSTON);
    assert_eq!(k.verdict, Verdict::Deny);
    assert_eq!(
        k.reason,
        DecisionReason::BrandNotAllowed {
            brand_id: "kingston".into()
        }
    );
    assert_eq!(
        k.classification.category,
        DeviceCategory::UsbStorageDisk {
            transport: UsbStorageTransport::BulkOnly
        }
    );
    let ids = &k.classification.usb_ancestor.as_ref().unwrap().ids;
    assert_eq!((ids.vid, ids.pid), (0x0951, 0x1666));
    assert_eq!(k.enforcement, EnforcementStatus::NotEnforcedSimulation);
}

#[test]
fn aselsan_labelled_stick_reports_unknown_vendor_and_is_denied() {
    // Physically labelled ASELSAN; it reports INQUIRY vendor "VendorC" and
    // VID 346D. That identity is what this one stick reports, not an
    // authenticated ASELSAN identity. It is not in the catalog, so the model
    // denies it (simulated), and the SanDisk rule must not match it.
    let c = ctx();
    let s = decision(&c, ASELSAN_LABELLED);
    assert_eq!(s.verdict, Verdict::Deny);
    assert_eq!(
        s.reason,
        DecisionReason::UnknownManufacturer {
            vendor: "VendorC".into()
        }
    );
    let ids = &s.classification.usb_ancestor.as_ref().unwrap().ids;
    assert_eq!((ids.vid, ids.pid), (0x346D, 0x5678));
    assert_eq!(s.enforcement, EnforcementStatus::NotEnforcedSimulation);

    // None of its hardware IDs equals an allow entry of the modelled plan.
    let allow = planned_strings(&plan(&c));
    let rec = c
        .snapshot
        .devices
        .iter()
        .find(|d| d.instance_id.starts_with(ASELSAN_LABELLED))
        .unwrap();
    for hw in &rec.hardware_ids {
        assert!(
            !allow.contains(&hw.to_ascii_uppercase()),
            "{hw} would be allowed"
        );
    }
    assert!(allow.iter().any(|a| a == "USBSTOR\\DISKSANDISK_"));
}

#[test]
fn no_observed_usb_stick_matches_the_sandisk_allow_rule() {
    let c = ctx();
    for d in &c.decisions {
        assert!(
            !matches!(&d.reason, DecisionReason::BrandAllowed { .. }),
            "{} unexpectedly allowed",
            d.instance_id
        );
    }
}

#[test]
fn input_devices_are_out_of_scope() {
    let c = ctx();
    let mut seen = 0;
    for prefix in ["HID\\", "ACPI\\", "USB\\VID_0E0F"] {
        for d in c
            .decisions
            .iter()
            .filter(|d| d.instance_id.starts_with(prefix))
        {
            assert_eq!(d.verdict, Verdict::NotApplicable, "{}", d.instance_id);
            seen += 1;
        }
    }
    assert_eq!(seen, 5);
}

#[test]
fn internal_disk_without_its_controller_chain_blocks_activation() {
    // The fixture holds the internal NVMe disk's hardware IDs but not its
    // parent controller (not recorded). RustWard must then treat it as
    // "attachment unknown": it could be the system disk, so the plan does
    // not pin it and the system-disk gate refuses activation (fail closed).
    let c = ctx();
    let nvme = decision(&c, INTERNAL_NVME);
    assert_eq!(
        nvme.classification.category,
        DeviceCategory::StorageAttachmentUnknown
    );
    let rec = c
        .snapshot
        .devices
        .iter()
        .find(|d| d.instance_id.starts_with(INTERNAL_NVME))
        .unwrap();
    assert!(rec.hardware_ids.iter().all(|h| !h.contains("SanDisk")));
    let p = plan(&c);
    let inputs = PlanInputs {
        policy: &c.policy,
        catalog: &c.catalog,
        snapshot: &c.snapshot,
        env: &EnvironmentFacts::default(),
    };
    let g = system_disk_gate(&p, &inputs);
    assert_eq!(g.status, PreconditionStatus::NotMet);
    assert!(g.detail.contains("attachment unknown"), "{}", g.detail);
}

#[test]
fn previously_installed_denied_sticks_are_reported_separately() {
    // Both sticks were already installed in the VM. A device-installation
    // restriction would not affect them: they are listed for manual review
    // instead of being counted as blocked.
    let c = ctx();
    let p = plan(&c);
    let a = assess(&AssessmentInputs {
        snapshot: &c.snapshot,
        policy: &c.policy,
        catalog: &c.catalog,
        plan: &p,
        existing: &PolicySnapshot::default(),
        sanitize: true,
    });
    let denied_installed: Vec<_> = a
        .devices
        .iter()
        .filter(|d| d.finding == Finding::DeniedButInstalled)
        .collect();
    assert_eq!(denied_installed.len(), 2, "{:?}", a.summary);
    assert!(
        denied_installed
            .iter()
            .all(|d| d.remains_accessible_after_activation)
    );
    // The internal disk is never offered remediation.
    let nvme = a
        .devices
        .iter()
        .find(|d| d.finding == Finding::AttachmentUnknown)
        .unwrap();
    assert!(nvme.remediation.is_empty());
    for d in &a.devices {
        assert!(!d.instance_id.contains("HID\\") && !d.instance_id.contains("ACPI\\"));
    }
}
