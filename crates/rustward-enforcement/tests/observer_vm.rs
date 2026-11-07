//! Observer and checklist against the sanitized identifiers observed in the
//! authorized test VM, with the exact policy that was applied on 2026-11-07
//! and the states Windows showed (Code 1 / Code 28, working, disconnected).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::device::DeviceSnapshot;
use rustward_core::policy::ValidatedPolicy;
use rustward_enforcement::checklist::{
    ChecklistError, POLICY_EN, POLICY_TR, device_deny_checklist,
};
use rustward_enforcement::device_install::RESTRICTIONS_KEY;
use rustward_enforcement::observer::{
    EvidenceLevel, HistoricalDenial, Observation, ObservedDevice, ObservedState as S,
    attach_history, observe,
};
use rustward_enforcement::policy_inspect::CapturedPolicy;
use rustward_enforcement::policy_state::{PolicySnapshot, RegData};

const OBSERVED: &str = include_str!("../../../tests/fixtures/vm-observed-usb-2026-11-07.json");
const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
const POLICY: &str = include_str!("../../../config/vm-enforcement-test-policy.json");
const KINGSTON: &str = "USBSTOR\\DISK&VEN_KINGSTON";
const ASELSAN: &str = "USBSTOR\\DISK&VEN_VENDORC";
const KINGSTON_ID: &str = "USBSTOR\\DiskKingstonDataTraveler_3.0____";

fn applied_policy() -> PolicySnapshot {
    PolicySnapshot::default()
        .with(RESTRICTIONS_KEY, "DenyDeviceIDs", RegData::Dword(1))
        .with(
            RESTRICTIONS_KEY,
            "DenyDeviceIDsRetroactive",
            RegData::Dword(1),
        )
        .with(
            &format!("{RESTRICTIONS_KEY}\\DenyDeviceIDs"),
            "1",
            RegData::Sz(KINGSTON_ID.into()),
        )
}

fn run(policy: PolicySnapshot, edit: impl Fn(&mut DeviceSnapshot)) -> Observation {
    let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
    let rw = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
    let mut snap = DeviceSnapshot::from_json(OBSERVED).unwrap();
    edit(&mut snap);
    let captured = CapturedPolicy {
        captured_ms: 1,
        key_present: !policy.values.is_empty(),
        values: policy,
        ..CapturedPolicy::default()
    };
    observe(&snap, &rw, &catalog, &captured)
}

fn dev<'a>(o: &'a Observation, prefix: &str) -> &'a ObservedDevice {
    o.devices
        .iter()
        .find(|d| d.instance_id.starts_with(prefix))
        .unwrap()
}

fn set_kingston(snap: &mut DeviceSnapshot, present: bool, problem: Option<u32>) {
    let d = snap
        .devices
        .iter_mut()
        .find(|d| d.instance_id.starts_with(KINGSTON))
        .unwrap();
    d.present = Some(present);
    d.problem_code = problem;
}

#[test]
fn only_usb_storage_is_observed_with_real_identities() {
    let o = run(PolicySnapshot::default(), |_| {});
    assert_eq!(o.devices.len(), 2, "{:?}", o.devices);
    let k = dev(&o, KINGSTON);
    assert_eq!(k.vid_pid.as_deref(), Some("0951:1666"));
    assert_eq!(k.reported_vendor.as_deref(), Some("Kingston"));
    assert_eq!(k.hardware_id.as_deref(), Some(KINGSTON_ID));
    let a = dev(&o, ASELSAN);
    assert_eq!(a.vid_pid.as_deref(), Some("346D:5678"));
    assert_eq!(a.reported_vendor.as_deref(), Some("VendorC"));
    assert_eq!(a.rustward_reason, "unknown_manufacturer");
}

#[test]
fn current_state_after_rollback_is_no_restriction_and_accessible() {
    let o = run(PolicySnapshot::default(), |_| {});
    assert!(!o.windows_restrictions_configured);
    for d in &o.devices {
        assert!(d.states.contains(&S::SimulatedDeny));
        assert!(d.states.contains(&S::NoWindowsRestriction));
        assert!(!d.states.contains(&S::PolicyMismatch), "no Windows policy");
        assert_eq!(d.evidence, EvidenceLevel::None);
        assert_eq!(d.label_rustward_tr, "Simülasyonda ret");
        assert_eq!(d.label_policy_tr, "Kural uygulanmamış");
        assert!(d.label_status_tr.starts_with("Erişilebilir"));
    }
    assert_eq!(o.currently_denied().count(), 0);
}

#[test]
fn observed_block_is_install_denied_but_access_not_verified() {
    for code in [1, 28] {
        let o = run(applied_policy(), |s| set_kingston(s, true, Some(code)));
        let k = dev(&o, KINGSTON);
        assert!(k.states.contains(&S::WindowsInstallDenied));
        assert!(k.states.contains(&S::WindowsAccessNotVerified));
        assert!(!k.states.contains(&S::PolicyMismatch));
        assert_eq!(k.evidence, EvidenceLevel::InstallDenied);
        assert_eq!(
            k.label_status_tr,
            format!("Windows kurulumu engelledi (Kod {code})")
        );
        assert!(
            k.explanation_tr
                .contains("Okuma/yazma yolları ayrıca test edilmedi")
        );
        // The ASELSAN stick is not covered by the Windows rule: a discrepancy.
        let a = dev(&o, ASELSAN);
        assert!(a.states.contains(&S::NoWindowsRestriction));
        assert!(a.states.contains(&S::PolicyMismatch));
        assert_eq!(a.evidence, EvidenceLevel::None);
        assert_eq!(o.currently_denied().count(), 1);
    }
}

#[test]
fn configured_policy_alone_is_not_a_denial() {
    // Rule matches, but the device is installed and working.
    let o = run(applied_policy(), |s| set_kingston(s, true, None));
    let k = dev(&o, KINGSTON);
    assert!(k.states.contains(&S::WindowsRuleConfigured));
    assert!(!k.states.contains(&S::WindowsInstallDenied));
    assert_eq!(k.evidence, EvidenceLevel::PolicyOnly);
    assert!(k.label_status_tr.starts_with("Erişilebilir"));
}

#[test]
fn disconnected_device_is_never_reported_as_blocked() {
    for problem in [None, Some(28)] {
        let o = run(applied_policy(), |s| set_kingston(s, false, problem));
        let k = dev(&o, KINGSTON);
        assert!(k.states.contains(&S::StatusUnknown));
        assert!(!k.states.contains(&S::WindowsInstallDenied));
        assert_ne!(k.evidence, EvidenceLevel::InstallDenied);
        assert!(k.label_status_tr.starts_with("Bağlı değil"));
    }
}

#[test]
fn problem_code_without_a_matching_rule_proves_nothing() {
    let o = run(PolicySnapshot::default(), |s| {
        set_kingston(s, true, Some(28))
    });
    let k = dev(&o, KINGSTON);
    assert!(k.states.contains(&S::StatusUnknown));
    assert!(!k.states.contains(&S::WindowsInstallDenied));
    assert_eq!(k.evidence, EvidenceLevel::None);
}

#[test]
fn earlier_denial_is_history_once_the_policy_is_removed() {
    let o = run(PolicySnapshot::default(), |_| {});
    let mut k = dev(&o, KINGSTON).clone();
    let h = HistoricalDenial {
        observed_ms: 1_794_047_470_000,
        problem_code: 1,
        rule_entry: KINGSTON_ID.into(),
    };
    attach_history(&mut k, Some(h.clone()));
    assert_eq!(k.history, Some(h.clone()));
    assert!(k.explanation_tr.starts_with("Geçmiş kanıt"));
    assert_eq!(
        k.evidence,
        EvidenceLevel::None,
        "history is not a current block"
    );
    // A current denial is not turned into history.
    let o = run(applied_policy(), |s| set_kingston(s, true, Some(28)));
    let mut k = dev(&o, KINGSTON).clone();
    attach_history(&mut k, Some(h));
    assert_eq!(k.history, None);
}

fn checklist(
    live: &PolicySnapshot,
    prefix: &str,
    retro: bool,
    edit: impl Fn(&mut DeviceSnapshot),
) -> Result<rustward_enforcement::checklist::PolicyChecklist, ChecklistError> {
    let catalog = ValidatedCatalog::from_json(CATALOG).unwrap();
    let rw = ValidatedPolicy::from_json(POLICY, &catalog).unwrap();
    let mut snap = DeviceSnapshot::from_json(OBSERVED).unwrap();
    edit(&mut snap);
    let id = snap
        .devices
        .iter()
        .find(|d| d.instance_id.starts_with(prefix))
        .unwrap()
        .instance_id
        .clone();
    device_deny_checklist(&snap, &rw, &catalog, live, &id, retro)
}

#[test]
fn checklist_reproduces_the_verified_kingston_experiment() {
    let c = checklist(&PolicySnapshot::default(), KINGSTON, true, |_| {}).unwrap();
    assert_eq!(c.hardware_id, KINGSTON_ID);
    assert_eq!(c.vid_pid.as_deref(), Some("0951:1666"));
    assert_eq!(c.policy_name_en, POLICY_EN);
    assert_eq!(c.policy_name_tr, POLICY_TR);
    assert_eq!(c.affected_devices.len(), 1, "only the Kingston");
    assert_eq!(
        c.expected_registry,
        vec![
            "DenyDeviceIDs = 1 (REG_DWORD)".to_string(),
            format!("DenyDeviceIDs\\1 = \"{KINGSTON_ID}\" (REG_SZ)"),
            "DenyDeviceIDsRetroactive = 1 (REG_DWORD)".to_string(),
        ]
    );
    assert!(c.rollback[0].contains("Yapılandırılmadı"));
    assert!(c.verification.iter().any(|v| v.contains("Kod 1")));
    assert!(c.risks.iter().any(|r| r.contains("TÜM birimleriyle")));
    let text = c.render_text();
    assert!(text.contains("UYGULAMAZ") && text.contains(KINGSTON_ID) && text.contains(POLICY_TR));
    assert!(
        !text.to_ascii_uppercase().contains("DENYDEVICECLASSES ="),
        "no class rule"
    );
}

#[test]
fn checklist_without_retroactive_warns_that_installed_device_stays_usable() {
    let c = checklist(&PolicySnapshot::default(), KINGSTON, false, |_| {}).unwrap();
    assert!(c.risks.iter().any(|r| r.contains("ERİŞİLEBİLİR KALIR")));
    assert_eq!(c.expected_registry.len(), 2);
}

#[test]
fn checklist_appends_to_an_existing_list_and_keeps_its_rollback_narrow() {
    let live = PolicySnapshot::default()
        .with(RESTRICTIONS_KEY, "DenyDeviceIDs", RegData::Dword(1))
        .with(
            &format!("{RESTRICTIONS_KEY}\\DenyDeviceIDs"),
            "1",
            RegData::Sz("USBSTOR\\DiskOtherVen_SomeProduct_______".into()),
        );
    let c = checklist(&live, ASELSAN, false, |_| {}).unwrap();
    assert!(
        c.expected_registry
            .iter()
            .any(|l| l.starts_with("DenyDeviceIDs\\2 = "))
    );
    assert!(c.rollback[0].contains("YALNIZCA bu satırı"));
}

#[test]
fn checklist_refuses_generic_ids_internal_disks_and_collateral_damage() {
    // Internal (unknown attachment) disk.
    assert_eq!(
        checklist(
            &PolicySnapshot::default(),
            "SCSI\\DISK&VEN_NVME",
            true,
            |_| {}
        ),
        Err(ChecklistError::NotUsbStorage)
    );
    // Generic first hardware ID.
    let generic = checklist(&PolicySnapshot::default(), KINGSTON, true, |s| {
        let d = s
            .devices
            .iter_mut()
            .find(|d| d.instance_id.starts_with(KINGSTON))
            .unwrap();
        d.hardware_ids.insert(0, "USBSTOR\\GenDisk".into());
    });
    assert!(matches!(
        generic,
        Err(ChecklistError::NoSpecificHardwareId(_))
    ));
    // A keyboard that (absurdly) reports the same ID would be hit too.
    let collateral = checklist(&PolicySnapshot::default(), KINGSTON, true, |s| {
        let d = s
            .devices
            .iter_mut()
            .find(|d| d.instance_id.starts_with("HID\\"))
            .unwrap();
        d.compatible_ids.push(KINGSTON_ID.into());
    });
    assert!(matches!(
        collateral,
        Err(ChecklistError::AffectsNonUsbStorage(_))
    ));
}
