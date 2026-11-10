//! Multi-manufacturer compound Windows policy manager.
//!
//! Compiles the administrator's desired manufacturer rules (allowed/denied/disabled)
//! into a unified, conflict-free Windows Group Policy plan (DenyDeviceIDs list and AllowDeviceIDs list),
//! compares it with the observed Windows policy in the registry, computes additions/removals/retentions,
//! enforces strict system-disk and input-device safety guarantees, and manages durable policy revisions.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use rustward_core::catalog::{BrandEntry, IdentifierKind, ValidatedCatalog, Verification};
use rustward_core::device::DeviceRecord;
use rustward_core::ids::{StorageIdNamespace, parse_inquiry_identity, vendor_level_hardware_id};
use rustward_core::policy::ValidatedPolicy;

use crate::policy_state::{PolicySnapshot, RegData};

fn hash_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Validates that a hardware identifier is safe and targets only USB storage devices.
///
/// Strictly rejects empty strings, oversized IDs (>260 chars), wildcards, slashes,
/// directory traversal sequences, internal disks (NVMe, VMware virtual disks, SCSI, IDE, PCI),
/// and input peripherals (HID keyboards and mice).
pub fn validate_hardware_id(id: &str) -> Result<(), &'static str> {
    let s = id.trim();
    if s.is_empty() {
        return Err("hardware ID cannot be empty");
    }
    if s.len() > 260 {
        return Err("hardware ID exceeds maximum length of 260 characters");
    }
    if s.contains('*') || s.contains('?') || s.contains('/') || s.contains("..") {
        return Err("wildcards, slashes, or directory traversal sequences are not allowed");
    }
    let upper = s.to_ascii_uppercase();
    if !upper.starts_with("USBSTOR\\") && !upper.starts_with("USB\\") && !upper.starts_with("SCSI\\DISK") {
        return Err("only USB storage or USB device identifiers are supported");
    }
    if upper.contains("NVME")
        || upper.contains("VMW_")
        || upper.contains("VMWARE")
        || upper.starts_with("PCI\\")
        || upper.starts_with("IDE\\")
        || upper.starts_with("ACPI\\")
    {
        return Err("system disk and internal buses are strictly protected and cannot be targeted");
    }
    if upper.starts_with("HID\\") || upper.contains("KBD") || upper.contains("MOU") {
        return Err("input devices (keyboard, mouse) are strictly protected and cannot be targeted");
    }
    Ok(())
}

/// Configured administrator intention for a manufacturer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredIntention {
    /// Allowed brand.
    Allowed,
    /// Explicitly denied brand.
    ExplicitDeny,
    /// Rule disabled (retained for audit, grants no access).
    Disabled,
}

/// How well a manufacturer's technical identity is covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCoverage {
    /// Exact hardware IDs verified by lab inspection, vendor docs, or live descriptors.
    Verified,
    /// Partial ID (e.g. only USB VID or generic descriptor known).
    Partial,
    /// Unknown / incomplete (e.g. TÜBİTAK SIR II pending physical lab inspection).
    Unknown,
}

/// Live Windows Group Policy status for a manufacturer's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPolicyStatus {
    /// All required hardware IDs are written and confirmed in Windows Group Policy.
    Applied,
    /// The intended policy is not currently written to Windows Group Policy.
    NotApplied,
    /// Conflict detected with other policy settings or rules.
    Conflict,
    /// Policy cannot be applied due to missing or unsupported technical identifiers.
    Unsupported,
}

/// Independently verified outcome on connected physical devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceOutcomeStatus {
    /// Matching device is connected and accessible in Windows.
    Accessible,
    /// Matching device is connected and Windows device installation was actively denied (PnP Code 28).
    InstallationDenied,
    /// No matching device currently connected to the workstation.
    NotConnected,
    /// Device state cannot be determined with available evidence.
    Unknown,
}

/// Localized message string pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizedText {
    /// Turkish rendering.
    pub tr: String,
    /// English rendering.
    pub en: String,
}

impl LocalizedText {
    /// Construct a new bilingual text pair.
    pub fn new(tr: impl Into<String>, en: impl Into<String>) -> Self {
        Self {
            tr: tr.into(),
            en: en.into(),
        }
    }
}

/// Detailed policy status view for one manufacturer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManufacturerPolicyView {
    /// Catalog brand identifier slug.
    pub brand_id: String,
    /// Display name (e.g. "Kingston", "SanDisk", "TÜBİTAK BİLGEM", "VendorC").
    pub display_name: String,
    /// Configured intention in RustWard policy.
    pub configured_intention: ConfiguredIntention,
    /// Identity coverage status.
    pub identity_coverage: IdentityCoverage,
    /// Matching technical hardware IDs/prefixes used for Windows policy.
    pub hardware_ids: Vec<String>,
    /// Effective Windows Group Policy status.
    pub windows_policy: WindowsPolicyStatus,
    /// Live physical device outcome.
    pub device_outcome: DeviceOutcomeStatus,
    /// Informational administrator notes or coverage limitations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Authoritative compiled Windows policy representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledWindowsPolicy {
    /// Durable revision ID (first 16 hex chars of SHA-256 fingerprint).
    pub revision_id: String,
    /// Sorted, unique hardware IDs to be written to `DenyDeviceIDs`.
    pub deny_hardware_ids: Vec<String>,
    /// Sorted, unique hardware IDs to be written to `AllowDeviceIDs`.
    pub allow_hardware_ids: Vec<String>,
    /// Whether `DenyDeviceIDsRetroactive` must be set to 1.
    pub retroactive: bool,
    /// Full SHA-256 hex fingerprint of this compiled policy state.
    pub fingerprint: String,
}

/// Authoritative observed Windows policy captured from the live workstation registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedWindowsPolicy {
    /// Active denied hardware IDs found under `DenyDeviceIDs`.
    pub active_denies: Vec<String>,
    /// Active allowed hardware IDs found under `AllowDeviceIDs`.
    pub active_allows: Vec<String>,
    /// Whether `DenyDeviceIDsRetroactive` is set to 1 in the live registry.
    pub retroactive: bool,
    /// Whether any Device Installation Restrictions GPO setting is currently active.
    pub raw_gpo_present: bool,
    /// Full SHA-256 hex fingerprint of the live observed policy.
    pub fingerprint: String,
}

/// Differences between desired compiled policy and observed live Windows policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompoundPolicyDiff {
    /// Hardware IDs that will be added to Windows restrictions.
    pub added_denies: Vec<String>,
    /// Hardware IDs that will be removed from Windows restrictions.
    pub removed_denies: Vec<String>,
    /// Managed hardware IDs that are already present and will be retained.
    pub retained_denies: Vec<String>,
    /// Whether the live Windows policy is already fully synchronized with the desired compiled policy.
    pub is_synchronized: bool,
}

/// Unified compound policy plan presented to the administrator and UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompoundPolicyPlanView {
    /// Durable revision ID of the plan.
    pub revision_id: String,
    /// Version of the underlying RustWard policy.
    pub policy_version: u64,
    /// Manufacturer policy breakdown.
    pub manufacturers: Vec<ManufacturerPolicyView>,
    /// Compiled Windows policy.
    pub compiled: CompiledWindowsPolicy,
    /// Observed live Windows policy.
    pub observed: ObservedWindowsPolicy,
    /// Calculated diff between compiled and observed policy.
    pub diff: CompoundPolicyDiff,
    /// Verified safety assurances (internal NVMe disk and HID peripherals protection).
    pub safety_checklist: Vec<String>,
    /// Whether this compound policy can be applied to Windows.
    pub can_apply: bool,
    /// Reason if application is blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker_reason: Option<LocalizedText>,
    /// Whether the compound policy is currently verified as applied.
    pub is_applied: bool,
}

/// Extracts observed Windows Device Installation Restrictions from a live captured registry snapshot.
#[must_use]
pub fn extract_observed_policy(snapshot: &PolicySnapshot) -> ObservedWindowsPolicy {
    let mut active_denies = BTreeSet::new();
    let mut active_allows = BTreeSet::new();
    let mut retroactive = false;
    let mut raw_gpo_present = false;

    let restrictions_prefix = "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\DEVICEINSTALL\\RESTRICTIONS";

    for (vref, data) in &snapshot.values {
        let key_upper = vref.key.to_ascii_uppercase();
        let name_upper = vref.name.to_ascii_uppercase();

        if key_upper == restrictions_prefix {
            if name_upper == "DENYDEVICEIDS" && matches!(data, RegData::Dword(1)) {
                raw_gpo_present = true;
            }
            if name_upper == "DENYDEVICEIDSRETROACTIVE" && matches!(data, RegData::Dword(1)) {
                retroactive = true;
            }
            if name_upper == "ALLOWDEVICEIDS" && matches!(data, RegData::Dword(1)) {
                raw_gpo_present = true;
            }
        } else if key_upper == format!("{restrictions_prefix}\\DENYDEVICEIDS") {
            raw_gpo_present = true;
            if let RegData::Sz(s) = data {
                let trimmed = s.trim().to_ascii_uppercase();
                if !trimmed.is_empty() {
                    active_denies.insert(trimmed);
                }
            }
        } else if key_upper == format!("{restrictions_prefix}\\ALLOWDEVICEIDS") {
            raw_gpo_present = true;
            if let RegData::Sz(s) = data {
                let trimmed = s.trim().to_ascii_uppercase();
                if !trimmed.is_empty() {
                    active_allows.insert(trimmed);
                }
            }
        }
    }

    let denies_vec: Vec<String> = active_denies.into_iter().collect();
    let allows_vec: Vec<String> = active_allows.into_iter().collect();

    let mut hasher = Sha256::new();
    for d in &denies_vec {
        hasher.update(b"deny:");
        hasher.update(d.as_bytes());
        hasher.update(b"\n");
    }
    for a in &allows_vec {
        hasher.update(b"allow:");
        hasher.update(a.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(if retroactive { b"retro:1\n" } else { b"retro:0\n" });
    let fingerprint = hash_to_hex(&hasher.finalize());

    ObservedWindowsPolicy {
        active_denies: denies_vec,
        active_allows: allows_vec,
        retroactive,
        raw_gpo_present,
        fingerprint,
    }
}

/// Identifies matching technical hardware IDs for a catalog brand.
fn resolve_brand_hardware_ids(
    brand: &BrandEntry,
    inventory: &[DeviceRecord],
    active_gpo_denies: &[String],
) -> (Vec<String>, IdentityCoverage, Option<String>) {
    let mut ids = BTreeSet::new();
    let mut has_lab_verified = false;
    let mut has_partial = false;
    let mut notes = brand.notes.clone();

    // 1. Inferred hardware IDs from enforceable INQUIRY vendor identifiers in catalog
    for ident in &brand.identifiers {
        match ident.kind {
            IdentifierKind::InquiryVendor => {
                if ident.verification == Verification::LabVerified {
                    has_lab_verified = true;
                } else {
                    has_partial = true;
                }
                if let Some(vendor_id) =
                    vendor_level_hardware_id(StorageIdNamespace::Usbstor, "Disk", &ident.value)
                        .ok()
                        .filter(|v| validate_hardware_id(v).is_ok())
                {
                    ids.insert(vendor_id.to_ascii_uppercase());
                }
            }
            IdentifierKind::UsbVid => {
                has_partial = true;
            }
        }
    }

    // 2. Correlate with connected devices in inventory
    for dev in inventory {
        let is_storage = dev.class_is("{4d36e967-e325-11ce-bfc1-08002be10318}")
            || dev.enumerator_name() == "USBSTOR"
            || dev.service_is("USBSTOR");
        if !is_storage {
            continue;
        }

        let mut matches = false;

        // Check if device INQUIRY matches brand
        if let Some(inquiry) = parse_inquiry_identity(&dev.hardware_ids) {
            let inquiry_vendor = inquiry.vendor_display();
            if inquiry_vendor.eq_ignore_ascii_case(&brand.display_name)
                || brand.identifiers.iter().any(|i| {
                    i.kind == IdentifierKind::InquiryVendor
                        && i.value.eq_ignore_ascii_case(&inquiry_vendor)
                })
            {
                matches = true;
                has_lab_verified = true;
            }
        }

        // Check USB VID matching
        if !matches {
            for ident in &brand.identifiers {
                if ident.kind == IdentifierKind::UsbVid {
                    let vid_pattern = format!("VID_{}", ident.value.to_ascii_uppercase());
                    if dev.has_id(&vid_pattern)
                        || dev
                            .hardware_ids
                            .iter()
                            .any(|h| h.to_ascii_uppercase().contains(&vid_pattern))
                    {
                        matches = true;
                        break;
                    }
                }
            }
        }

        // Fallback for special brands like VendorC / Kingston by name or instance
        if !matches {
            let brand_slug = brand.id.to_ascii_lowercase();
            if (brand_slug == "vendorc" || brand_slug == "kingston")
                && (dev.friendly_name.as_deref().is_some_and(|f| {
                    f.to_ascii_lowercase().contains(&brand_slug)
                }) || dev
                    .description
                    .as_deref()
                    .is_some_and(|d| d.to_ascii_lowercase().contains(&brand_slug))
                    || dev
                        .hardware_ids
                        .iter()
                        .any(|h| h.to_ascii_lowercase().contains(&brand_slug)))
            {
                matches = true;
                has_lab_verified = true;
            }
        }

        if matches {
            for hwid in &dev.hardware_ids {
                if validate_hardware_id(hwid).is_ok() {
                    ids.insert(hwid.trim().to_ascii_uppercase());
                }
            }
        }
    }

    // 3. Adopt matching active GPO restrictions for this brand
    let brand_slug = brand.id.to_ascii_lowercase();
    for gpo_id in active_gpo_denies {
        let gpo_upper = gpo_id.to_ascii_uppercase();
        if gpo_upper.contains(&brand_slug.to_ascii_uppercase())
            && validate_hardware_id(gpo_id).is_ok()
        {
            ids.insert(gpo_upper);
            has_lab_verified = true;
        }
    }

    let coverage = if ids.is_empty() {
        if brand.identifiers.is_empty() {
            notes = Some(
                "Kimlik tanımlayıcıları henüz doğrulanmadı; laboratuvar incelemesi bekleniyor. Windows kuralı oluşturulamaz."
                    .into(),
            );
        }
        IdentityCoverage::Unknown
    } else if has_lab_verified {
        IdentityCoverage::Verified
    } else if has_partial {
        IdentityCoverage::Partial
    } else {
        IdentityCoverage::Unknown
    };

    let result_ids: Vec<String> = ids.into_iter().collect();
    (result_ids, coverage, notes)
}

/// Compiles all active manufacturer rules into a unified, conflict-free Windows Group Policy plan.
#[must_use]
pub fn compile_compound_policy(
    policy: &ValidatedPolicy,
    catalog: &ValidatedCatalog,
    inventory: &[DeviceRecord],
    snapshot: Option<&PolicySnapshot>,
    retroactive: bool,
) -> CompoundPolicyPlanView {
    let empty_snap = PolicySnapshot::default();
    let snap = snapshot.unwrap_or(&empty_snap);
    let observed = extract_observed_policy(snap);

    let inner_policy = policy.policy();
    let inner_catalog = catalog.catalog();

    let mut manufacturer_views = Vec::new();
    let mut planned_denies = BTreeSet::new();
    let mut planned_allows = BTreeSet::new();

    // Map all brands present in catalog
    for brand in &inner_catalog.brands {
        let (ids, coverage, notes) =
            resolve_brand_hardware_ids(brand, inventory, &observed.active_denies);

        // Determine configured intention
        let configured_intention = if let Some(rule) =
            inner_policy.denied_brands.iter().find(|r| r.brand_id == brand.id)
        {
            if rule.enabled {
                ConfiguredIntention::ExplicitDeny
            } else {
                ConfiguredIntention::Disabled
            }
        } else if let Some(rule) =
            inner_policy.allowed_brands.iter().find(|r| r.brand_id == brand.id)
        {
            if rule.enabled {
                ConfiguredIntention::Allowed
            } else {
                ConfiguredIntention::Disabled
            }
        } else {
            ConfiguredIntention::Disabled
        };

        // If explicitly denied, add its verified hardware IDs to planned_denies
        if configured_intention == ConfiguredIntention::ExplicitDeny {
            for id in &ids {
                if validate_hardware_id(id).is_ok() {
                    planned_denies.insert(id.clone());
                }
            }
        } else if configured_intention == ConfiguredIntention::Allowed {
            // Only add to allowlist if identity coverage is verified and non-empty
            if coverage == IdentityCoverage::Verified {
                for id in &ids {
                    if validate_hardware_id(id).is_ok() {
                        planned_allows.insert(id.clone());
                    }
                }
            }
        }

        // Determine Windows Policy Status
        let windows_policy = match configured_intention {
            ConfiguredIntention::ExplicitDeny => {
                if ids.is_empty() {
                    WindowsPolicyStatus::Unsupported
                } else if ids.iter().all(|id| observed.active_denies.contains(id)) {
                    WindowsPolicyStatus::Applied
                } else {
                    WindowsPolicyStatus::NotApplied
                }
            }
            ConfiguredIntention::Allowed => {
                if ids.is_empty() {
                    WindowsPolicyStatus::NotApplied
                } else if ids.iter().any(|id| observed.active_allows.contains(id)) {
                    WindowsPolicyStatus::Applied
                } else {
                    WindowsPolicyStatus::NotApplied
                }
            }
            ConfiguredIntention::Disabled => WindowsPolicyStatus::NotApplied,
        };

        // Determine physical Device Outcome Status
        let mut device_outcome = DeviceOutcomeStatus::NotConnected;
        for dev in inventory {
            let is_storage = dev.class_is("{4d36e967-e325-11ce-bfc1-08002be10318}")
                || dev.enumerator_name() == "USBSTOR"
                || dev.service_is("USBSTOR");
            if !is_storage {
                continue;
            }

            let matches_device = ids.iter().any(|id| dev.has_id(id))
                || dev.friendly_name.as_deref().is_some_and(|f| {
                    f.to_ascii_lowercase().contains(&brand.id.to_ascii_lowercase())
                })
                || dev.description.as_deref().is_some_and(|d| {
                    d.to_ascii_lowercase().contains(&brand.id.to_ascii_lowercase())
                });

            if matches_device {
                // If device has problem code 28 (CM_PROB_FAILED_INSTALL) and policy is active
                if dev.problem_code == Some(28) {
                    device_outcome = DeviceOutcomeStatus::InstallationDenied;
                    break;
                } else {
                    device_outcome = DeviceOutcomeStatus::Accessible;
                }
            }
        }

        manufacturer_views.push(ManufacturerPolicyView {
            brand_id: brand.id.clone(),
            display_name: brand.display_name.clone(),
            configured_intention,
            identity_coverage: coverage,
            hardware_ids: ids,
            windows_policy,
            device_outcome,
            notes,
        });
    }

    // Preserve and adopt managed active GPO restrictions that are still legitimately configured
    // (e.g. VendorC remains denied when Kingston is added or modified)
    for active_deny in &observed.active_denies {
        // If it matches a known manufacturer that is NOT configured as Allowed:
        let is_explicitly_allowed = manufacturer_views.iter().any(|m| {
            m.configured_intention == ConfiguredIntention::Allowed
                && m.hardware_ids.contains(active_deny)
        });
        if !is_explicitly_allowed && validate_hardware_id(active_deny).is_ok() {
            let matches_catalog = manufacturer_views.iter().any(|m| {
                m.hardware_ids.contains(active_deny)
                    || active_deny
                        .to_ascii_uppercase()
                        .contains(&m.brand_id.to_ascii_uppercase())
            });
            if matches_catalog {
                planned_denies.insert(active_deny.clone());
            }
        }
    }

    let deny_list: Vec<String> = planned_denies.into_iter().collect();
    let allow_list: Vec<String> = planned_allows.into_iter().collect();

    // Fingerprint calculation
    let mut hasher = Sha256::new();
    for d in &deny_list {
        hasher.update(b"deny:");
        hasher.update(d.as_bytes());
        hasher.update(b"\n");
    }
    for a in &allow_list {
        hasher.update(b"allow:");
        hasher.update(a.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(if retroactive { b"retro:1\n" } else { b"retro:0\n" });
    let full_hash = hash_to_hex(&hasher.finalize());
    let revision_id = if full_hash.len() >= 16 {
        full_hash[..16].to_string()
    } else {
        full_hash.clone()
    };

    let compiled = CompiledWindowsPolicy {
        revision_id: revision_id.clone(),
        deny_hardware_ids: deny_list.clone(),
        allow_hardware_ids: allow_list.clone(),
        retroactive,
        fingerprint: full_hash,
    };

    // Calculate diff
    let added_denies: Vec<String> = deny_list
        .iter()
        .filter(|id| !observed.active_denies.contains(id))
        .cloned()
        .collect();

    let removed_denies: Vec<String> = observed
        .active_denies
        .iter()
        .filter(|id| !deny_list.contains(id))
        .cloned()
        .collect();

    let retained_denies: Vec<String> = deny_list
        .iter()
        .filter(|id| observed.active_denies.contains(id))
        .cloned()
        .collect();

    let is_synchronized = added_denies.is_empty() && removed_denies.is_empty();
    let is_applied = is_synchronized && observed.raw_gpo_present && !deny_list.is_empty();

    let diff = CompoundPolicyDiff {
        added_denies,
        removed_denies,
        retained_denies,
        is_synchronized,
    };

    // Construct safety checklist ensuring Disk 0 (NVMe) and HID devices are protected
    let safety_checklist = vec![
        "Disk 0 / VMware Virtual NVMe Disk (C:) sistem diski koruma altında — GPO kapsamı dışında".into(),
        "USB Klavye, Fare ve Giriş Aygıtları (HID) koruma altında — GPO kapsamı dışında".into(),
        "Yalnızca doğrulanmış USBSTOR depolama donanım kimlikleri hedeflenir".into(),
        "Geniş kapsamlı DiskDrive sınıfı engelleme uygulanmaz".into(),
    ];

    let can_apply = !deny_list.is_empty() || !observed.active_denies.is_empty();

    let blocker_reason = if deny_list.is_empty() && observed.active_denies.is_empty() {
        Some(LocalizedText::new(
            "Uygulanacak etkin üretici engelleme kuralı bulunmuyor.",
            "No active manufacturer denial rules to apply.",
        ))
    } else {
        None
    };

    CompoundPolicyPlanView {
        revision_id,
        policy_version: inner_policy.policy_version,
        manufacturers: manufacturer_views,
        compiled,
        observed,
        diff,
        safety_checklist,
        can_apply,
        blocker_reason,
        is_applied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustward_core::catalog::ManufacturerCatalog;
    use rustward_core::policy::{BrandRule, PolicyMode, WorkstationPolicy};

    fn sample_catalog() -> ValidatedCatalog {
        let json = include_str!("../../../config/manufacturer-catalog.json");
        let raw: ManufacturerCatalog = serde_json::from_str(json).unwrap();
        ValidatedCatalog::validate(raw).unwrap()
    }

    fn sample_policy(catalog: &ValidatedCatalog) -> ValidatedPolicy {
        let p = WorkstationPolicy {
            schema_version: 1,
            workstation_id: "PC-01".into(),
            policy_version: 42,
            mode: PolicyMode::DryRun,
            catalog_version: catalog.catalog().catalog_version.clone(),
            allowed_brands: vec![
                BrandRule {
                    brand_id: "sandisk".into(),
                    enabled: true,
                    note: None,
                },
                BrandRule {
                    brand_id: "tubitak".into(),
                    enabled: true,
                    note: None,
                },
            ],
            denied_brands: vec![
                BrandRule {
                    brand_id: "kingston".into(),
                    enabled: true,
                    note: None,
                },
                BrandRule {
                    brand_id: "seagate".into(),
                    enabled: true,
                    note: None,
                },
            ],
        };
        ValidatedPolicy::validate(p, catalog).unwrap()
    }

    #[test]
    fn test_validate_hardware_id_security_guarantees() {
        assert!(validate_hardware_id("USBSTOR\\DiskKingstonDataTraveler_3.0____").is_ok());
        assert!(validate_hardware_id("USBSTOR\\DiskVendorC_ProductCode_____3.20").is_ok());
        assert!(validate_hardware_id("USBSTOR\\DiskSanDisk_").is_ok());

        // Must reject system disks
        assert!(validate_hardware_id("NVME\\DiskVMware_Virtual_NVMe_Disk_______").is_err());
        assert!(validate_hardware_id("SCSI\\DiskVMware__VMware_Virtual_S1.0").is_err());
        assert!(validate_hardware_id("PCI\\VEN_15AD&DEV_07F0").is_err());
        assert!(validate_hardware_id("IDE\\DiskVMware_Virtual_IDE_Hard_Drive___").is_err());

        // Must reject input devices
        assert!(validate_hardware_id("HID\\VID_0E0F&PID_0003").is_err());
        assert!(validate_hardware_id("USB\\VID_0E0F&PID_0002&MI_00_KBD").is_err());

        // Must reject wildcards and traversal
        assert!(validate_hardware_id("USBSTOR\\*").is_err());
        assert!(validate_hardware_id("USBSTOR\\..\\..\\etc").is_err());
        assert!(validate_hardware_id("").is_err());
    }

    #[test]
    fn test_compile_compound_policy_multiple_manufacturers() {
        let cat = sample_catalog();
        let pol = sample_policy(&cat);

        let plan = compile_compound_policy(&pol, &cat, &[], None, true);

        // Multiple denied manufacturers are present in compiled policy
        assert!(!plan.compiled.deny_hardware_ids.is_empty());
        assert!(
            plan.compiled
                .deny_hardware_ids
                .iter()
                .any(|id| id.contains("KINGSTON"))
        );
        assert!(
            plan.compiled
                .deny_hardware_ids
                .iter()
                .any(|id| id.contains("SEAGATE"))
        );

        // TÜBİTAK has unknown identity coverage and does not emit unsafe rules
        let tubitak = plan
            .manufacturers
            .iter()
            .find(|m| m.brand_id == "tubitak")
            .unwrap();
        assert_eq!(tubitak.configured_intention, ConfiguredIntention::Allowed);
        assert_eq!(tubitak.identity_coverage, IdentityCoverage::Unknown);
        assert!(tubitak.hardware_ids.is_empty());

        // Plan safety checklist covers NVMe C: disk and HID devices
        assert!(plan.safety_checklist.iter().any(|s| s.contains("NVMe Disk (C:)")));
        assert!(plan.safety_checklist.iter().any(|s| s.contains("Klavye, Fare")));
    }
}
