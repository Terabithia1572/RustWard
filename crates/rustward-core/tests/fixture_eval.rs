//! End-to-end tests of classification, evaluation and plan modelling
//! against the synthetic lab snapshot and the shipped catalog/policy.
//!
//! These tests exercise RustWard's *model*. They say nothing about how
//! Windows behaves; that requires the hardware acceptance tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::classify::{DeviceCategory, PeripheralKind, UsbStorageTransport};
use rustward_core::device::DeviceSnapshot;
use rustward_core::evaluate::{
    Decision, DecisionReason, EnforcementStatus, EvidenceKind, Verdict, evaluate_snapshot,
};
use rustward_core::plan::{
    ModelOutcome, PlanStatus, check_consistency, compile_plan, model_install_outcome,
};
use rustward_core::policy::{PolicyError, PolicyMode, ValidatedPolicy};

const SNAPSHOT: &str = include_str!("../../../tests/fixtures/synthetic-lab-snapshot.json");
const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
const POLICY: &str = include_str!("../../../config/policy.example.json");

struct Ctx {
    snapshot: DeviceSnapshot,
    catalog: ValidatedCatalog,
    policy: ValidatedPolicy,
    decisions: Vec<Decision>,
}

fn ctx() -> Ctx {
    let snapshot = DeviceSnapshot::from_json(SNAPSHOT).unwrap();
    let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
    let policy = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
    let decisions = evaluate_snapshot(&snapshot, &policy, &catalog);
    Ctx {
        snapshot,
        catalog,
        policy,
        decisions,
    }
}

fn decision<'a>(c: &'a Ctx, id_prefix: &str) -> &'a Decision {
    let matches: Vec<_> = c
        .decisions
        .iter()
        .filter(|d| d.instance_id.starts_with(id_prefix))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one device starting with {id_prefix}"
    );
    matches[0]
}

fn assert_brand_allowed(d: &Decision, brand: &str) {
    assert_eq!(d.verdict, Verdict::Allow, "{}", d.instance_id);
    assert_eq!(
        d.reason,
        DecisionReason::BrandAllowed {
            brand_id: brand.into()
        }
    );
}

#[test]
fn shipped_catalog_and_example_policy_are_valid_in_dry_run_only() {
    let c = ctx();
    assert_eq!(c.policy.policy().mode, PolicyMode::DryRun);
    let codes: Vec<_> = c.policy.warnings().iter().map(|w| w.code).collect();
    assert!(codes.contains(&"identifier_unverified"));
    assert!(
        codes.contains(&"brand_not_enforceable"),
        "tubitak must be flagged"
    );

    let enforce = POLICY.replace("\"dry_run\"", "\"enforce\"");
    match ValidatedPolicy::from_json(&enforce, &c.catalog) {
        Err(PolicyError::Invalid(issues)) => {
            assert!(issues.iter().any(|i| i.code == "identifier_unverified"));
            assert!(issues.iter().any(|i| i.code == "brand_not_enforceable"));
        }
        other => {
            panic!("enforce mode must be rejected without lab-verified identifiers: {other:?}")
        }
    }
}

#[test]
fn approved_brand_is_allowed_across_models_and_capacities() {
    let c = ctx();
    let ultra = decision(&c, "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&");
    assert_brand_allowed(ultra, "sandisk");
    assert!(
        ultra
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Corroborating)
    );
    // A model never registered anywhere is allowed purely at brand level.
    assert_brand_allowed(
        decision(&c, "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra_Fit"),
        "sandisk",
    );
}

#[test]
fn unapproved_catalog_brands_are_denied_including_uasp_and_non_present() {
    let c = ctx();
    let kingston = decision(&c, "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0");
    assert_eq!(kingston.verdict, Verdict::Deny);
    assert_eq!(
        kingston.reason,
        // Phase 6 example policy denies Kingston explicitly.
        DecisionReason::BrandDenied {
            brand_id: "kingston".into()
        }
    );
    let previously_installed = decision(&c, "USBSTOR\\Disk&Ven_Kingston&Prod_DT_101");
    assert_eq!(previously_installed.verdict, Verdict::Deny);

    let seagate = decision(&c, "SCSI\\Disk&Ven_Seagate");
    assert_eq!(seagate.verdict, Verdict::Deny);
    assert_eq!(
        seagate.classification.category,
        DeviceCategory::UsbStorageDisk {
            transport: UsbStorageTransport::Uasp
        }
    );
    assert!(
        seagate
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Warning && e.detail.contains("SCSI-namespace")),
        "SCSI namespace uncertainty must be surfaced"
    );
}

#[test]
fn generic_unknown_and_unidentifiable_devices_are_denied() {
    let c = ctx();
    assert!(matches!(
        decision(&c, "USBSTOR\\Disk&Ven_Generic&Prod_Flash").reason,
        DecisionReason::GenericVendorIdentity { .. }
    ));
    assert!(matches!(
        decision(&c, "SCSI\\Disk&Ven_JMicron").reason,
        DecisionReason::GenericVendorIdentity { .. }
    ));
    assert!(matches!(
        decision(&c, "USBSTOR\\Disk&Ven_ACMEDATA").reason,
        DecisionReason::UnknownManufacturer { .. }
    ));
    let smi = decision(&c, "USBSTOR\\Disk&Ven_SMI");
    assert_eq!(smi.verdict, Verdict::Deny);
    assert_eq!(smi.reason, DecisionReason::MissingEnforceableIdentity);
}

#[test]
fn spoofed_inquiry_vendor_is_allowed_documenting_the_known_limitation() {
    // A device with an unrelated VID that reports INQUIRY vendor "SanDisk"
    // is allowed: the OS-enforceable identifier is not authenticated.
    // The VID mismatch is surfaced as a warning but cannot change the
    // verdict. See docs/KNOWN-LIMITATIONS.md (L-01).
    let c = ctx();
    let spoof = decision(&c, "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Blade");
    assert_brand_allowed(spoof, "sandisk");
    assert!(
        spoof
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Warning && e.source == "usb_vid")
    );
}

#[test]
fn peripherals_and_system_disks_are_never_in_scope() {
    let c = ctx();
    for d in &c.decisions {
        if let DeviceCategory::Peripheral { .. } | DeviceCategory::SystemOrNonUsbStorage =
            d.classification.category
        {
            assert_eq!(d.verdict, Verdict::NotApplicable, "{}", d.instance_id);
        }
    }
    let kinds: Vec<_> = c
        .decisions
        .iter()
        .filter_map(|d| match d.classification.category {
            DeviceCategory::Peripheral { peripheral } => Some(peripheral),
            _ => None,
        })
        .collect();
    for k in [
        PeripheralKind::Keyboard,
        PeripheralKind::Mouse,
        PeripheralKind::Printer,
        PeripheralKind::CompositeParent,
        PeripheralKind::Hub,
    ] {
        assert!(kinds.contains(&k), "fixture must cover {k:?}");
    }
    assert_eq!(
        decision(&c, "SCSI\\Disk&Ven_Samsung&Prod_SSD_870")
            .classification
            .category,
        DeviceCategory::SystemOrNonUsbStorage
    );
    assert_eq!(
        decision(&c, "SCSI\\Disk&Ven_NVMe").classification.category,
        DeviceCategory::SystemOrNonUsbStorage
    );
}

#[test]
fn composite_device_is_classified_per_function() {
    let c = ctx();
    assert_eq!(
        decision(&c, "HID\\VID_1A2B&PID_0001&MI_00")
            .classification
            .category,
        DeviceCategory::Peripheral {
            peripheral: PeripheralKind::Keyboard
        }
    );
    let storage = decision(&c, "USBSTOR\\Disk&Ven_ACMEDATA");
    assert_eq!(storage.verdict, Verdict::Deny);
    assert_eq!(
        storage
            .classification
            .usb_ancestor
            .as_ref()
            .unwrap()
            .ids
            .vid,
        0x1A2B
    );
}

#[test]
fn no_decision_ever_claims_enforcement() {
    let c = ctx();
    assert!(
        c.decisions
            .iter()
            .all(|d| d.enforcement == EnforcementStatus::NotEnforcedSimulation)
    );
}

#[test]
fn plan_contains_only_allowed_brand_rules_and_is_never_applied() {
    let c = ctx();
    let plan = compile_plan(&c.policy, &c.catalog, Some(&c.snapshot));
    assert_eq!(plan.status, PlanStatus::NotApplied);
    assert!(plan.layered_evaluation);
    let ids: Vec<_> = plan
        .allow_device_ids
        .iter()
        .map(|r| r.device_id.as_str())
        .collect();
    assert_eq!(ids, ["USBSTOR\\DiskSanDisk_", "SCSI\\DiskSanDisk_"]);
    assert!(plan.prevent_setup_classes.iter().all(|r| !r.retroactive));
    assert_eq!(
        plan.allow_instance_ids.len(),
        2,
        "both internal disks protected"
    );
    assert!(plan.warnings.iter().any(|w| w.contains("\"tubitak\"")));
}

#[test]
fn decision_engine_and_modelled_os_rules_agree_except_documented_scope_gaps() {
    let c = ctx();
    let plan = compile_plan(&c.policy, &c.catalog, Some(&c.snapshot));
    let findings = check_consistency(&plan, &c.snapshot, &c.decisions);
    let mut gaps: Vec<_> = findings
        .iter()
        .map(|f| (f.kind, f.instance_id.as_str()))
        .collect();
    gaps.sort_unstable();
    assert_eq!(
        gaps,
        [
            (
                "enforcement_gap",
                "USBSTOR\\CdRom&Ven_HL-DT-ST&Prod_DVDRAM_GP57EB40&Rev_PR10\\5&2F3E4D&0&2&0"
            ),
            (
                "enforcement_gap",
                "USBSTOR\\CdRom&Ven_SanDisk&Prod_U3_Cruzer_Micro&Rev_8.02\\0774910E4B21C9A8&1"
            ),
            ("enforcement_gap", "USB\\VID_04E8&PID_6860\\R58M12345AB"),
        ],
        "only the pending CD-ROM (incl. a U3 virtual CD LUN) and MTP scope decisions may disagree"
    );

    // Keyboards, mice, printers are untouched by the plan.
    let index = c.snapshot.index();
    for d in &c.decisions {
        if matches!(d.classification.category, DeviceCategory::Peripheral { .. }) {
            let dev = index.get(&d.instance_id).unwrap();
            assert_eq!(
                model_install_outcome(&plan, dev),
                ModelOutcome::NotRestricted
            );
        }
    }
}

#[test]
fn missing_baseline_is_reported_as_over_blocking_of_system_disks() {
    let c = ctx();
    let plan = compile_plan(&c.policy, &c.catalog, None);
    let findings = check_consistency(&plan, &c.snapshot, &c.decisions);
    let over: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == "over_blocking")
        .collect();
    assert_eq!(over.len(), 2);
    assert!(
        over.iter()
            .all(|f| f.instance_id.starts_with("SCSI\\Disk&Ven_Samsung")
                || f.instance_id.starts_with("SCSI\\Disk&Ven_NVMe"))
    );
}

#[test]
fn multi_lun_devices_are_evaluated_per_logical_unit() {
    let c = ctx();
    let disk_lun = decision(&c, "USBSTOR\\Disk&Ven_SanDisk&Prod_U3_Cruzer_Micro");
    let cd_lun = decision(&c, "USBSTOR\\CdRom&Ven_SanDisk&Prod_U3_Cruzer_Micro");
    assert_brand_allowed(disk_lun, "sandisk");
    // The virtual CD LUN of an approved brand is still a separate, pending scope.
    assert_eq!(cd_lun.verdict, Verdict::Deny);
    assert_eq!(cd_lun.reason, DecisionReason::ScopeDecisionPending);
    assert_eq!(
        disk_lun
            .classification
            .usb_ancestor
            .as_ref()
            .unwrap()
            .instance_id,
        cd_lun
            .classification
            .usb_ancestor
            .as_ref()
            .unwrap()
            .instance_id,
        "both LUNs belong to the same USB function"
    );

    let reader_luns: Vec<_> = c
        .decisions
        .iter()
        .filter(|d| d.instance_id.starts_with("USBSTOR\\Disk&Ven_Generic-"))
        .collect();
    assert_eq!(reader_luns.len(), 2);
    assert!(
        reader_luns
            .iter()
            .all(|d| matches!(d.reason, DecisionReason::GenericVendorIdentity { .. }))
    );
}

#[test]
fn friendly_name_spoof_never_authorizes() {
    // INQUIRY says Kingston; friendly/bus names say "SanDisk Extreme".
    let c = ctx();
    let d = decision(&c, "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_SE9");
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(
        d.reason,
        // Phase 6 example policy denies Kingston explicitly.
        DecisionReason::BrandDenied {
            brand_id: "kingston".into()
        }
    );
    assert!(
        d.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Hint && e.detail.contains("\"sandisk\""))
    );
}

#[test]
fn approved_vid_with_generic_inquiry_is_denied() {
    // USB VID 0781 (SanDisk in the catalog) but INQUIRY vendor "Generic".
    let c = ctx();
    let d = decision(&c, "USBSTOR\\Disk&Ven_Generic&Prod_Mass_Storage");
    assert_eq!(d.verdict, Verdict::Deny);
    assert!(matches!(
        d.reason,
        DecisionReason::GenericVendorIdentity { .. }
    ));
    assert!(
        d.evidence
            .iter()
            .any(|e| e.source == "usb_vid" && e.detail.contains("never authorizes"))
    );
}

#[test]
fn orphaned_non_present_disk_fails_closed() {
    let c = ctx();
    let d = decision(&c, "SCSI\\Disk&Ven_Samsung&Prod_PSSD_T7");
    assert_eq!(
        d.classification.category,
        DeviceCategory::StorageAttachmentUnknown
    );
    assert_eq!(d.verdict, Verdict::Deny);
    assert!(d.evidence.iter().any(|e| e.source == "parent_instance_id"));
}

#[test]
fn non_present_devices_are_still_evaluated() {
    let c = ctx();
    let index = c.snapshot.index();
    let non_present: Vec<_> = c
        .decisions
        .iter()
        .filter(|d| index.get(&d.instance_id).unwrap().present == Some(false))
        .collect();
    assert!(
        non_present.len() >= 3,
        "fixture models previously installed devices"
    );
    assert!(
        non_present
            .iter()
            .filter(|d| d.classification.category.scope()
                != rustward_core::classify::StorageScope::NotInScope)
            .all(|d| d.verdict == Verdict::Deny)
    );
}

mod reports {
    use super::*;
    use rustward_core::device::SnapshotSource;
    use rustward_core::report::{
        ENFORCEMENT_NOT_ACTIVE, NOTICE, SimulatedDecision, build_report, render_markdown,
    };

    fn live_ctx() -> Ctx {
        let mut c = ctx();
        c.snapshot.source = SnapshotSource::Live {
            computer_name: Some("SECRET-PC-01".into()),
            collected_unix_seconds: 1_793_836_800,
            includes_non_present: true,
        };
        c
    }

    #[test]
    fn every_report_states_enforcement_not_active_and_never_claims_blocking() {
        let c = live_ctx();
        for sanitize in [false, true] {
            let r = build_report(&c.snapshot, &[], &c.policy, &c.catalog, sanitize);
            assert_eq!(r.enforcement, ENFORCEMENT_NOT_ACTIVE);
            assert!(
                r.entries
                    .iter()
                    .all(|e| e.enforcement == ENFORCEMENT_NOT_ACTIVE)
            );
            let md = render_markdown(&r);
            assert!(
                md.lines().take(4).any(|l| l.contains(NOTICE)),
                "notice at top"
            );
            assert!(
                md.trim_end().ends_with(&format!("> **{NOTICE}**")),
                "notice at bottom"
            );
            let json = serde_json::to_string(&r).unwrap();
            for text in [&md, &json] {
                let lower = text.to_lowercase();
                assert!(
                    !lower.contains("engellenmi"),
                    "Turkish 'blocked' notice must never appear"
                );
                assert!(!lower.contains("\"blocked\""), "no 'blocked' verdict value");
                assert!(
                    !text.contains("| Allow |") && !text.contains("| Deny |"),
                    "decisions must be labelled SIMULATED"
                );
            }
            assert!(
                r.entries
                    .iter()
                    .any(|e| e.simulated_decision == SimulatedDecision::SimulatedDeny)
            );
        }
    }

    #[test]
    fn sanitized_report_contains_no_serials_or_machine_identity() {
        let c = live_ctx();
        let r = build_report(
            &c.snapshot,
            &["USBSTOR\\Disk&Ven_X\\TOPSECRETSERIAL&0: property Parent unreadable".into()],
            &c.policy,
            &c.catalog,
            true,
        );
        let md = render_markdown(&r);
        let json = serde_json::to_string(&r).unwrap();
        let tails: Vec<String> = c
            .snapshot
            .devices
            .iter()
            .flat_map(|d| std::iter::once(&d.instance_id).chain(d.parent_instance_id.iter()))
            .filter_map(|id| id.rsplit('\\').next().map(str::to_owned))
            .filter(|t| t.len() >= 6)
            .collect();
        for t in &tails {
            assert!(
                !md.contains(t.as_str()),
                "serial/instance tail {t} leaked into sanitized markdown"
            );
            assert!(
                !json.contains(t.as_str()),
                "serial/instance tail {t} leaked into sanitized JSON"
            );
        }
        for secret in ["SECRET-PC-01", "TOPSECRETSERIAL"] {
            assert!(
                !md.contains(secret) && !json.contains(secret),
                "{secret} leaked"
            );
        }
        assert_eq!(r.summary.read_warnings, 1);
        assert!(r.read_warnings.is_empty());
        let phone = r
            .entries
            .iter()
            .find(|e| e.device.starts_with("USB\\VID_04E8&PID_6860"))
            .unwrap();
        assert!(
            phone.friendly_name.is_none(),
            "portable-device names may be personal"
        );
        assert_eq!(r.source.collected_utc_date.as_deref(), Some("2026-11-05"));

        // The raw report keeps everything for local diagnosis.
        let raw = build_report(&c.snapshot, &[], &c.policy, &c.catalog, false);
        assert!(
            serde_json::to_string(&raw)
                .unwrap()
                .contains("4C530001230615110223")
        );
        assert_eq!(raw.source.computer_name.as_deref(), Some("SECRET-PC-01"));
    }

    #[test]
    fn sanitized_report_preserves_tree_structure() {
        let c = live_ctx();
        let r = build_report(&c.snapshot, &[], &c.policy, &c.catalog, true);
        let disk = r
            .entries
            .iter()
            .find(|e| {
                e.device
                    .starts_with("USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&")
            })
            .unwrap();
        let parent = disk.parent.as_deref().unwrap();
        assert!(
            r.entries.iter().any(|e| e.device == parent),
            "pseudonymized parent resolves"
        );
    }
}
