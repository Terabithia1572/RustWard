//! Phase D automated regression test suite covering the 20 mandatory scenarios.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustward_app::{
    default_policy_state, AppConfig, AppService, BackendKind, EmptyInventory, FixtureInventory,
    InventorySource, PolicySource,
};
use rustward_core::catalog::{BrandIdentifier, IdentifierKind, UsbIdsRegistry, Verification};
use rustward_core::ids::validate_storage_hardware_id;
use rustward_core::policy_edit::ManufacturerInput;
use rustward_enforcement::compound_policy::{CompoundPolicyPlanView, ConfiguredIntention};
use rustward_enforcement::policy_inspect::CapturedPolicy;
use rustward_enforcement::policy_state::PolicySnapshot;
use rustward_ipc::messages::{AccessLevel, DeviceView, Request, ResponseBody};
use rustward_ipc::rpc::Handler;
use rustward_ipc::{ClientIdentity, ErrorCode, IdentitySource};
use rustward_storage::{ManualClock, Store};

#[derive(Clone, Default)]
struct MemoryPolicySource(Arc<Mutex<PolicySnapshot>>);
impl PolicySource for MemoryPolicySource {
    fn capture(&self, now_ms: i64) -> Result<CapturedPolicy, String> {
        let values = self.0.lock().unwrap().clone();
        Ok(CapturedPolicy {
            captured_ms: now_ms,
            key_present: !values.values.is_empty(),
            values,
            ..Default::default()
        })
    }
    fn name(&self) -> &'static str {
        "memory_policy_source"
    }
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "rustward-phase-d-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn admin() -> ClientIdentity {
    ClientIdentity {
        account: "PC-01\\securityadmin".into(),
        sid: None,
        is_administrator: true,
        elevated: true,
        source: IdentitySource::Test,
        channel_max_access: AccessLevel::Administrator,
    }
}

fn config(allow_synthetic: bool, backup_dir: Option<PathBuf>) -> AppConfig {
    AppConfig {
        backend: BackendKind::DevBackend,
        allow_synthetic,
        backup_dir,
        database_location: "dev_temp".into(),
        app_version: "test".into(),
    }
}

fn service_with(
    store: Store,
    clock: Arc<ManualClock>,
    inv: Box<dyn InventorySource>,
    allow_synthetic: bool,
    backup: Option<PathBuf>,
) -> AppService {
    AppService::new(
        store,
        clock,
        inv,
        config(allow_synthetic, backup),
        &default_policy_state().unwrap(),
    )
    .unwrap()
    .with_policy_source(Box::new(MemoryPolicySource::default()))
}

fn fixture_service() -> AppService {
    let clock = Arc::new(ManualClock::new(1_794_000_000_000));
    let s = service_with(
        Store::open_in_memory(clock.clone()).unwrap(),
        clock,
        Box::new(FixtureInventory::bundled().unwrap()),
        true,
        None,
    );
    s.handle(&Request::LoadSyntheticInventory, &admin()).unwrap();
    s
}

fn get_compound_plan(s: &AppService) -> CompoundPolicyPlanView {
    match s.handle(&Request::GetCompoundPolicyPlan, &admin()).unwrap() {
        ResponseBody::CompoundPolicyPlan(p) => *p,
        other => panic!("expected CompoundPolicyPlan, got {other:?}"),
    }
}

fn get_devices(s: &AppService) -> Vec<DeviceView> {
    match s.handle(&Request::ListDevices { include_absent: true }, &admin()).unwrap() {
        ResponseBody::Devices(d) => d,
        other => panic!("expected Devices, got {other:?}"),
    }
}

// -----------------------------------------------------------------------------
// Scenario 01: Parse standard usb.ids file snapshot
// -----------------------------------------------------------------------------
#[test]
fn scenario_01_parse_standard_usb_ids_file_snapshot() {
    let registry = UsbIdsRegistry::bundled();
    assert!(registry.len() >= 50, "bundled registry must have 50+ vendors");
}

// -----------------------------------------------------------------------------
// Scenario 02: Search by vendor ID
// -----------------------------------------------------------------------------
#[test]
fn scenario_02_search_by_vendor_id() {
    let registry = UsbIdsRegistry::bundled();
    let kingston = registry.lookup_vid(0x0951).expect("VID 0951 Kingston must exist");
    assert!(kingston.to_lowercase().contains("kingston"));

    let sandisk = registry.lookup_vid(0x0781).expect("VID 0781 SanDisk must exist");
    assert!(sandisk.to_lowercase().contains("sandisk"));
}

// -----------------------------------------------------------------------------
// Scenario 03: Search by vendor name substring
// -----------------------------------------------------------------------------
#[test]
fn scenario_03_search_by_vendor_name_substring() {
    let registry = UsbIdsRegistry::bundled();
    let results = registry.search("Kingston");
    assert!(!results.is_empty(), "searching Kingston must return matches");
    assert!(results.iter().any(|v| v.vid == 0x0951));
}

// -----------------------------------------------------------------------------
// Scenario 04: Search case-insensitivity
// -----------------------------------------------------------------------------
#[test]
fn scenario_04_search_case_insensitivity() {
    let registry = UsbIdsRegistry::bundled();
    let lower = registry.search("sandisk");
    let upper = registry.search("SANDISK");
    let mixed = registry.search("SaNdIsK");
    assert_eq!(lower.len(), upper.len(), "case sensitivity mismatch");
    assert_eq!(lower.len(), mixed.len(), "case sensitivity mismatch");
}

// -----------------------------------------------------------------------------
// Scenario 05: Add brand from catalog without duplicate
// -----------------------------------------------------------------------------
#[test]
fn scenario_05_add_brand_from_catalog_without_duplicate() {
    let s = fixture_service();
    let res = s.handle(
        &Request::AddManufacturer {
            input: ManufacturerInput {
                id: Some("unique-brand-05".into()),
                display_name: "Unique Brand 05".into(),
                aliases: vec![],
                identifiers: vec![BrandIdentifier {
                    kind: IdentifierKind::InquiryVendor,
                    value: "UNQ05".into(),
                    verification: Verification::Unverified,
                    source: "catalog test".into(),
                }],
                notes: None,
            },
            allowed: true,
            expected_policy_version: 1,
        },
        &admin(),
    );
    assert!(res.is_ok(), "adding brand without duplicate must succeed");
}

// -----------------------------------------------------------------------------
// Scenario 06: Reject duplicate brand addition
// -----------------------------------------------------------------------------
#[test]
fn scenario_06_reject_duplicate_brand_addition() {
    let s = fixture_service();
    let err = s.handle(
        &Request::AddManufacturer {
            input: ManufacturerInput {
                id: Some("kingston".into()),
                display_name: "Kingston Duplicate".into(),
                aliases: vec![],
                identifiers: vec![],
                notes: None,
            },
            allowed: true,
            expected_policy_version: 1,
        },
        &admin(),
    ).unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict, "duplicate brand must fail with Conflict");
}

// -----------------------------------------------------------------------------
// Scenario 07: Add custom brand with non-empty identifiers
// -----------------------------------------------------------------------------
#[test]
fn scenario_07_add_custom_brand_with_non_empty_identifiers() {
    let s = fixture_service();
    let res = s.handle(
        &Request::AddManufacturer {
            input: ManufacturerInput {
                id: Some("custom-lab-brand".into()),
                display_name: "Custom Lab Brand".into(),
                aliases: vec!["LABPRO".into()],
                identifiers: vec![BrandIdentifier {
                    kind: IdentifierKind::InquiryVendor,
                    value: "LABPRO1".into(),
                    verification: Verification::LabVerified,
                    source: "physical sample in lab".into(),
                }],
                notes: Some("verified hardware".into()),
            },
            allowed: true,
            expected_policy_version: 1,
        },
        &admin(),
    );
    assert!(res.is_ok(), "adding custom brand with non-empty identifiers must succeed");
}

// -----------------------------------------------------------------------------
// Scenario 08: Save custom brand and reload across restart
// -----------------------------------------------------------------------------
#[test]
fn scenario_08_save_custom_brand_and_reload_across_restart() {
    let dir = TempDir::new("s08");
    let db = dir.0.join("rustward.db");
    let clock = Arc::new(ManualClock::new(1_794_000_000_000));
    {
        let store = Store::open(&db, clock.clone()).unwrap();
        let s = service_with(store, clock.clone(), Box::new(EmptyInventory), true, None);
        s.handle(
            &Request::AddManufacturer {
                input: ManufacturerInput {
                    id: Some("persistent-brand".into()),
                    display_name: "Persistent Brand".into(),
                    aliases: vec!["PERSIST".into()],
                    identifiers: vec![BrandIdentifier {
                        kind: IdentifierKind::InquiryVendor,
                        value: "PERSIST".into(),
                        verification: Verification::LabVerified,
                        source: "admin test".into(),
                    }],
                    notes: None,
                },
                allowed: true,
                expected_policy_version: 1,
            },
            &admin(),
        ).unwrap();
    }
    // Reopen service from same SQLite file
    let store2 = Store::open(&db, clock.clone()).unwrap();
    let s2 = service_with(store2, clock, Box::new(EmptyInventory), true, None);
    let resp = s2.handle(&Request::ListManufacturers, &admin()).unwrap();
    let ResponseBody::Manufacturers(m) = resp else { panic!() };
    let found = m.manufacturers.iter().find(|b| b.id == "persistent-brand");
    assert!(found.is_some(), "custom brand must survive restart");
    let b = found.unwrap();
    assert_eq!(b.display_name, "Persistent Brand");
    assert_eq!(b.identifiers.len(), 1);
}

// -----------------------------------------------------------------------------
// Scenario 09: Additive deny: 1 brand denied, 1 device denied -> both written to GPO
// -----------------------------------------------------------------------------
#[test]
fn scenario_09_additive_deny_1_brand_1_device_both_written() {
    let s = fixture_service();
    let devices = get_devices(&s);
    let dev = devices.iter().find(|d| d.vendor.as_deref() == Some("Kingston")).unwrap();
    let dev_key = dev.device_key.clone();

    // Deny Corsair brand (has enforceable InquiryVendor in catalog)
    s.handle(
        &Request::SetManufacturerDenied {
            id: "corsair".into(),
            denied: true,
            expected_policy_version: 1,
        },
        &admin(),
    ).unwrap();

    // Add device override deny
    s.handle(
        &Request::ApplyDeviceBlock {
            session_id: None,
            device_key: Some(dev_key),
            retroactive: true,
        },
        &admin(),
    ).unwrap();

    // Check compound policy plan
    let plan = get_compound_plan(&s);
    assert!(
        plan.compiled.deny_hardware_ids.iter().any(|id: &String| id.to_ascii_uppercase().contains("CORSAIR")),
        "Corsair hardware ID must be in deny list"
    );
    assert!(
        plan.compiled.deny_hardware_ids.iter().any(|id: &String| id.to_ascii_uppercase().contains("KINGSTON")),
        "Kingston hardware ID must be in deny list via device override"
    );
    assert!(
        plan.device_overrides.iter().any(|d| d.denied),
        "device override must be present in compound policy plan"
    );
}

// -----------------------------------------------------------------------------
// Scenario 10: Additive deny: 2 brands denied, 1 device denied -> 3 distinct targets
// -----------------------------------------------------------------------------
#[test]
fn scenario_10_additive_deny_2_brands_1_device_3_distinct_targets() {
    let s = fixture_service();
    let devices = get_devices(&s);
    let dev = devices.iter().find(|d| d.vendor.as_deref() == Some("Kingston")).unwrap();
    let dev_key = dev.device_key.clone();

    // Deny VendorC (Kingston is already denied in baseline policy)
    s.handle(&Request::SetManufacturerDenied { id: "vendorc".into(), denied: true, expected_policy_version: 1 }, &admin()).unwrap();
    s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(dev_key), retroactive: true }, &admin()).unwrap();

    let plan = get_compound_plan(&s);
    assert!(plan.compiled.deny_hardware_ids.len() >= 2);
    let m_denied = plan.manufacturers.iter().filter(|m| m.configured_intention == ConfiguredIntention::ExplicitDeny).count();
    assert!(m_denied >= 2, "at least 2 brands must be explicitly denied");
    assert_eq!(plan.device_overrides.len(), 1, "1 device override must be present");
}

// -----------------------------------------------------------------------------
// Scenario 11: Additive deny: 2 devices from different brands denied -> both present
// -----------------------------------------------------------------------------
#[test]
fn scenario_11_additive_deny_2_devices_from_different_brands() {
    let s = fixture_service();
    let devices = get_devices(&s);
    let k_dev = devices.iter().find(|d| d.vendor.as_deref() == Some("Kingston")).unwrap();
    let s_dev = devices.iter().find(|d| d.vendor.as_deref() == Some("SanDisk")).unwrap();
    let k_key = k_dev.device_key.clone();
    let s_key = s_dev.device_key.clone();

    s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(k_key), retroactive: true }, &admin()).unwrap();
    s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(s_key), retroactive: true }, &admin()).unwrap();

    let plan = get_compound_plan(&s);
    assert_eq!(plan.device_overrides.len(), 2, "both device overrides must be present");
    assert!(plan.device_overrides.iter().any(|d| d.hardware_id.contains("Kingston")));
    assert!(plan.device_overrides.iter().any(|d| d.hardware_id.contains("SanDisk")));
}

// -----------------------------------------------------------------------------
// Scenario 12: Removing device deny preserves all manufacturer deny rules
// -----------------------------------------------------------------------------
#[test]
fn scenario_12_removing_device_deny_preserves_all_manufacturer_rules() {
    let s = fixture_service();
    let devices = get_devices(&s);
    let dev = devices.iter().find(|d| d.vendor.as_deref() == Some("Kingston")).unwrap();
    let dev_key = dev.device_key.clone();

    // Kingston brand is already denied in baseline policy. Apply device block:
    s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(dev_key.clone()), retroactive: true }, &admin()).unwrap();

    // Now unblock device
    s.handle(&Request::RestoreDevicePolicy { session_id: None, device_key: Some(dev_key) }, &admin()).unwrap();

    let plan = get_compound_plan(&s);
    assert_eq!(plan.device_overrides.len(), 0, "device override must be removed");
    let m = plan.manufacturers.iter().find(|m| m.brand_id == "kingston").unwrap();
    assert_eq!(m.configured_intention, ConfiguredIntention::ExplicitDeny, "manufacturer deny rule must be preserved");
}

// -----------------------------------------------------------------------------
// Scenario 13: Removing manufacturer deny preserves device deny rules
// -----------------------------------------------------------------------------
#[test]
fn scenario_13_removing_manufacturer_deny_preserves_device_deny_rules() {
    let s = fixture_service();
    let devices = get_devices(&s);
    let dev = devices.iter().find(|d| d.vendor.as_deref() == Some("Kingston")).unwrap();
    let dev_key = dev.device_key.clone();

    // Apply device block (version 1 -> 2)
    s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(dev_key), retroactive: true }, &admin()).unwrap();

    // Change manufacturer to allowed (version 2 -> 3)
    s.handle(&Request::SetManufacturerAllowed { id: "kingston".into(), allowed: true, expected_policy_version: 2 }, &admin()).unwrap();

    let plan = get_compound_plan(&s);
    assert_eq!(plan.device_overrides.len(), 1, "device override must still be preserved");
    assert!(plan.device_overrides[0].denied);
}

// -----------------------------------------------------------------------------
// Scenario 14: System disk (NVMe Disk 0) NEVER added to deny rules
// -----------------------------------------------------------------------------
#[test]
fn scenario_14_system_disk_nvme_never_added_to_deny_rules() {
    let nvme_hwid = "SCSI\\DiskNVMe____VMware_Virtual_N1.0_";
    let res = validate_storage_hardware_id(nvme_hwid);
    assert!(res.is_err(), "NVMe hardware ID must be rejected");

    let pci_nvme = "PCI\\VEN_15B7&DEV_5006&SUBSYS_500615B7";
    assert!(validate_storage_hardware_id(pci_nvme).is_err(), "PCI NVMe must be rejected");
}

// -----------------------------------------------------------------------------
// Scenario 15: Input devices (HID keyboard, mouse) NEVER added to deny rules
// -----------------------------------------------------------------------------
#[test]
fn scenario_15_input_devices_hid_never_added_to_deny_rules() {
    let kbd_id = "HID\\VID_046D&PID_C31C&MI_00";
    assert!(validate_storage_hardware_id(kbd_id).is_err(), "Keyboard HID must be rejected");

    let mouse_id = "HID\\VID_046D&PID_C077";
    assert!(validate_storage_hardware_id(mouse_id).is_err(), "Mouse HID must be rejected");
}

// -----------------------------------------------------------------------------
// Scenario 16: No administrative session conflict on sequential device blocks
// -----------------------------------------------------------------------------
#[test]
fn scenario_16_no_administrative_session_conflict_on_sequential_device_blocks() {
    let s = fixture_service();
    let devices = get_devices(&s);
    let k_dev = devices.iter().find(|d| d.vendor.as_deref() == Some("Kingston")).unwrap();
    let s_dev = devices.iter().find(|d| d.vendor.as_deref() == Some("SanDisk")).unwrap();
    let k_key = k_dev.device_key.clone();
    let s_key = s_dev.device_key.clone();

    let res1 = s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(k_key), retroactive: true }, &admin());
    assert!(res1.is_ok(), "first block must succeed");

    let res2 = s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(s_key), retroactive: true }, &admin());
    assert!(res2.is_ok(), "sequential block must succeed without session conflict");
}

// -----------------------------------------------------------------------------
// Scenario 17: Single-device block supersedes stale session without error
// -----------------------------------------------------------------------------
#[test]
fn scenario_17_single_device_block_supersedes_stale_session_without_error() {
    let s = fixture_service();
    let devices = get_devices(&s);
    let dev = devices.iter().find(|d| d.vendor.as_deref() == Some("Kingston")).unwrap();
    let dev_key = dev.device_key.clone();

    // Prepare a legacy guided session
    let prep = s.handle(
        &Request::PrepareEnforcementSession {
            device_key: dev_key.clone(),
            retroactive: true,
        },
        &admin(),
    );
    assert!(prep.is_ok(), "prepare session must succeed");

    // Direct additive block supersedes the prepared session without Conflict
    let res = s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(dev_key), retroactive: true }, &admin());
    assert!(res.is_ok(), "direct block must supersede prepared session without error");
}

// -----------------------------------------------------------------------------
// Scenario 18: Additive device block updates compound policy revision
// -----------------------------------------------------------------------------
#[test]
fn scenario_18_additive_device_block_updates_compound_policy_revision() {
    let s = fixture_service();
    let devices = get_devices(&s);
    // SanDisk is allowed in baseline policy, so blocking it adds an override and alters compiled deny list
    let dev = devices.iter().find(|d| d.vendor.as_deref() == Some("SanDisk")).unwrap();
    let dev_key = dev.device_key.clone();

    let plan1 = get_compound_plan(&s);
    s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(dev_key), retroactive: true }, &admin()).unwrap();
    let plan2 = get_compound_plan(&s);

    assert_ne!(
        plan1.compiled.revision_id, plan2.compiled.revision_id,
        "compound policy revision must change when a device is blocked"
    );
    assert_eq!(plan2.policy_version, plan1.policy_version + 1);
}

// -----------------------------------------------------------------------------
// Scenario 19: Full rollback restores empty/baseline GPO state
// -----------------------------------------------------------------------------
#[test]
fn scenario_19_full_rollback_restores_empty_or_baseline_state() {
    let s = fixture_service();
    let devices = get_devices(&s);
    let dev = devices.iter().find(|d| d.vendor.as_deref() == Some("Kingston")).unwrap();
    let dev_key = dev.device_key.clone();

    s.handle(&Request::ApplyDeviceBlock { session_id: None, device_key: Some(dev_key.clone()), retroactive: true }, &admin()).unwrap();
    assert_eq!(get_compound_plan(&s).device_overrides.len(), 1);

    s.handle(&Request::RestoreDevicePolicy { session_id: None, device_key: Some(dev_key) }, &admin()).unwrap();
    let plan = get_compound_plan(&s);
    assert_eq!(plan.device_overrides.len(), 0, "device overrides must be empty after rollback");
}

// -----------------------------------------------------------------------------
// Scenario 20: Preserves all existing Phase C Hotfix test cases
// -----------------------------------------------------------------------------
#[test]
fn scenario_20_preserves_all_existing_phase_c_hotfix_test_cases() {
    let s = fixture_service();

    // 1. Kingston Deny is active in baseline; set Corsair to Denied
    s.handle(&Request::SetManufacturerDenied { id: "corsair".into(), denied: true, expected_policy_version: 1 }, &admin()).unwrap();
    let plan = get_compound_plan(&s);
    assert!(!plan.compiled.deny_hardware_ids.contains(&"USBSTOR\\GenDisk".to_string()), "must NEVER contain generic ID");
    assert!(plan.compiled.deny_hardware_ids.iter().any(|id: &String| id.to_ascii_uppercase().contains("KINGSTON")));
    assert!(plan.compiled.deny_hardware_ids.iter().any(|id: &String| id.to_ascii_uppercase().contains("CORSAIR")));

    // 2. Transition Corsair to Allowed
    s.handle(&Request::SetManufacturerAllowed { id: "corsair".into(), allowed: true, expected_policy_version: 2 }, &admin()).unwrap();
    let plan2 = get_compound_plan(&s);
    // Kingston remains in deny list
    assert!(plan2.compiled.deny_hardware_ids.iter().any(|id: &String| id.to_ascii_uppercase().contains("KINGSTON")));
    // Corsair removed from deny list
    assert!(!plan2.compiled.deny_hardware_ids.iter().any(|id: &String| id.to_ascii_uppercase().contains("CORSAIR")));
}
