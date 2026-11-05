//! Architecture test for keypad-encrypted drives (e.g. TÜBİTAK SIR II).
//!
//! The identifiers used here are SYNTHETIC placeholders (`EXAMPLEX`,
//! VID FFFF) chosen so they cannot be mistaken for real TÜBİTAK hardware
//! descriptors, which remain unknown until physical inspection.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustward_core::catalog::{
    BrandEntry, BrandIdentifier, IdentifierKind, ManufacturerCatalog, ValidatedCatalog,
    Verification,
};
use rustward_core::device::{
    DeviceRecord, DeviceSnapshot, SNAPSHOT_SCHEMA_VERSION, SnapshotSource,
};
use rustward_core::diff::{correlate_reenumeration, diff_snapshots};
use rustward_core::evaluate::{DecisionReason, Verdict, evaluate_snapshot};
use rustward_core::explain::explain;
use rustward_core::policy::{BrandRule, PolicyMode, ValidatedPolicy, WorkstationPolicy};

const HUB: &str = "USB\\ROOT_HUB30\\4&SYN&0&0";
const LOCKED: &str = "USB\\VID_FFFF&PID_0001\\SYNLOCKED01";
const UNLOCKED: &str = "USB\\VID_FFFF&PID_0002\\SYNUNLOCK01";
const DISK: &str = "USBSTOR\\Disk&Ven_EXAMPLEX&Prod_Secure_Drive&Rev_1.00\\SYNUNLOCK01&0";

fn dev(id: &str, parent: Option<&str>, service: Option<&str>, hw: &[&str]) -> DeviceRecord {
    DeviceRecord {
        instance_id: id.into(),
        parent_instance_id: parent.map(Into::into),
        service: service.map(Into::into),
        hardware_ids: hw.iter().map(|s| (*s).to_owned()).collect(),
        present: Some(true),
        ..DeviceRecord::default()
    }
}

fn snap(devices: Vec<DeviceRecord>) -> DeviceSnapshot {
    DeviceSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::Synthetic {
            description: "SYNTHETIC encrypted-drive lifecycle".into(),
        },
        devices,
    }
}

fn locked_state() -> DeviceSnapshot {
    // Locked: only a vendor-specific control interface, no storage function.
    snap(vec![
        dev(HUB, None, Some("USBHUB3"), &[]),
        dev(
            LOCKED,
            Some(HUB),
            Some("WinUSB"),
            &["USB\\VID_FFFF&PID_0001"],
        ),
    ])
}

fn unlocked_state() -> DeviceSnapshot {
    snap(vec![
        dev(HUB, None, Some("USBHUB3"), &[]),
        dev(
            UNLOCKED,
            Some(HUB),
            Some("USBSTOR"),
            &["USB\\VID_FFFF&PID_0002"],
        ),
        dev(
            DISK,
            Some(UNLOCKED),
            Some("disk"),
            &[
                "USBSTOR\\DiskEXAMPLEXSecure_Drive_____1.00",
                "USBSTOR\\DiskEXAMPLEXSecure_Drive_____",
                "USBSTOR\\DiskEXAMPLEX",
                "GenDisk",
            ],
        ),
    ])
}

fn rules(identifier: Option<&str>, allowed: bool) -> (ValidatedCatalog, ValidatedPolicy) {
    let catalog = ValidatedCatalog::validate(ManufacturerCatalog {
        schema_version: 1,
        catalog_version: "synthetic-1".into(),
        brands: vec![BrandEntry {
            id: "example-encrypted".into(),
            display_name: "Example Encrypted (SYNTHETIC)".into(),
            aliases: vec![],
            identifiers: identifier
                .map(|v| BrandIdentifier {
                    kind: IdentifierKind::InquiryVendor,
                    value: v.into(),
                    verification: Verification::Unverified,
                    source: "synthetic test placeholder".into(),
                })
                .into_iter()
                .collect(),
            notes: None,
        }],
        reserved_generic_vendors: vec![],
    })
    .unwrap();
    let policy = ValidatedPolicy::validate(
        WorkstationPolicy {
            schema_version: 1,
            workstation_id: "PC-TEST".into(),
            policy_version: 7,
            mode: PolicyMode::DryRun,
            catalog_version: "synthetic-1".into(),
            allowed_brands: if allowed {
                vec![BrandRule {
                    brand_id: "example-encrypted".into(),
                    enabled: true,
                    note: None,
                }]
            } else {
                vec![]
            },
        },
        &catalog,
    )
    .unwrap();
    (catalog, policy)
}

#[test]
fn locked_state_exposes_nothing_to_authorize() {
    let (c, p) = rules(Some("EXAMPLEX"), true);
    let decisions = evaluate_snapshot(&locked_state(), &p, &c);
    assert!(
        decisions
            .iter()
            .all(|d| d.verdict == Verdict::NotApplicable)
    );
}

#[test]
fn unlocked_storage_is_evaluated_on_arrival_and_linked_to_the_locked_device() {
    let d = diff_snapshots(&locked_state(), &unlocked_state());
    assert!(d.arrived.iter().any(|x| x.instance_id == DISK));
    let links = correlate_reenumeration(&d);
    assert_eq!(links.len(), 1, "audit links the re-enumeration");

    let (c, p) = rules(Some("EXAMPLEX"), true);
    let decisions = evaluate_snapshot(&unlocked_state(), &p, &c);
    let disk = decisions.iter().find(|x| x.instance_id == DISK).unwrap();
    assert_eq!(disk.verdict, Verdict::Allow);
}

#[test]
fn brand_without_known_identifier_is_denied_after_unlock() {
    // Mirrors the shipped TÜBİTAK catalog entry: allowed, but no identifier yet.
    let (c, p) = rules(None, true);
    let decisions = evaluate_snapshot(&unlocked_state(), &p, &c);
    let disk = decisions.iter().find(|x| x.instance_id == DISK).unwrap();
    assert_eq!(disk.verdict, Verdict::Deny);
    assert!(matches!(
        disk.reason,
        DecisionReason::UnknownManufacturer { .. }
    ));
    let e = explain(disk);
    assert!(e.summary_tr.starts_with("SİMÜLE RET"));
    assert!(e.steps.last().unwrap().tr.contains("simülasyondur"));
    assert!(
        e.steps
            .last()
            .unwrap()
            .en
            .contains("real enforcement is not active")
    );
}
