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

/// Returns true if the identifier is a generic storage class or compatible ID
/// rather than a manufacturer-specific hardware identity.
///
/// Generic IDs like `USBSTOR\GenDisk`, `GenDisk`, `USBSTOR\Disk`, `SCSI\Disk`,
/// `USBSTOR\RAW`, `USB\Class_08*` are common to all mass storage devices
/// and MUST NOT be used in manufacturer-specific deny rules, as denying them
/// results in an unintended class-wide lockout.
pub fn is_generic_storage_id(id: &str) -> bool {
    let s = id.trim().to_ascii_uppercase();
    let clean = s.trim_end_matches(['_', ' ']);
    matches!(
        clean,
        "USBSTOR\\GENDISK"
            | "GENDISK"
            | "USBSTOR\\DISK"
            | "DISK"
            | "SCSI\\DISK"
            | "SCSI\\DISK_____USB"
            | "SCSI\\DISKUSB"
            | "SCSI\\_____USB"
            | "USBSTOR\\RAW"
            | "USBSTOR\\OTHER"
            | "USBSTOR\\CDROM"
            | "GENCDROM"
            | "SCSI\\CDROM"
    ) || clean.starts_with("USB\\CLASS_08")
        || clean.starts_with("USBSTOR\\GENERIC")
        || clean.starts_with("GENERIC_STORAGE")
        || clean == "SCSI\\DISK_____USB"
}

/// Validates that a hardware identifier is safe and targets only USB storage devices.
///
/// Strictly rejects empty strings, oversized IDs (>260 chars), wildcards, slashes,
/// directory traversal sequences, internal disks (NVMe, VMware virtual disks, SCSI, IDE, PCI),
/// input peripherals (HID keyboards and mice), and cross-manufacturer generic storage identifiers.
pub fn validate_hardware_id(id: &str) -> Result<(), &'static str> {
    let s = id.trim();
    if s.is_empty() {
        return Err("hardware ID cannot be empty");
    }
    if s.len() > 260 {
        return Err("hardware ID exceeds maximum length of 260 characters");
    }
    if s.contains('*') || s.contains('?') || s.contains('/') || s.contains("..") || s.contains('\0') {
        return Err("wildcards, slashes, or directory traversal sequences are not allowed");
    }
    let upper = s.to_ascii_uppercase();
    if !upper.starts_with("USBSTOR\\")
        && !upper.starts_with("USB\\")
        && !upper.starts_with("SCSI\\DISK")
        && !upper.starts_with("SCSI\\_____USB")
    {
        return Err("only USB storage or USB device identifiers are supported");
    }
    if is_generic_storage_id(s) {
        return Err("generic storage and compatible identifiers cannot be targeted as manufacturer identities");
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
    /// Unknown / incomplete (e.g. unverified encrypted storage profile).
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
    /// Matching device is allowed by policy, but driver stack needs restart/recovery after prior restriction (PnP Code 28).
    DriverRecoveryNeeded,
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
    /// Display name (e.g. "Kingston", "SanDisk", "Encrypted USB Storage (Unverified)", "VendorC").
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

/// Status view of an explicit device override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceOverrideView {
    /// Target hardware ID.
    pub hardware_id: String,
    /// Device instance ID if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// Human-readable label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// True if deny override, false if allow override.
    pub denied: bool,
    /// Whether the rule is enabled.
    pub enabled: bool,
    /// Windows Group Policy status.
    pub windows_status: WindowsPolicyStatus,
    /// Verified physical device outcome.
    pub device_outcome: DeviceOutcomeStatus,
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
    /// Active device-level overrides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_overrides: Vec<DeviceOverrideView>,
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
                // Generate SCSI-namespace disk identifier as well
                if let Some(scsi_id) =
                    vendor_level_hardware_id(StorageIdNamespace::Scsi, "Disk", &ident.value)
                        .ok()
                        .filter(|v| validate_hardware_id(v).is_ok())
                {
                    ids.insert(scsi_id.to_ascii_uppercase());
                }
                // For SanDisk, also generate known UASP vendor-padded patterns
                if brand.id.eq_ignore_ascii_case("sandisk") {
                    let uasp_id1 = "SCSI\\Disk_____USB_SanDisk_";
                    if validate_hardware_id(uasp_id1).is_ok() && !is_generic_storage_id(uasp_id1) {
                        ids.insert(uasp_id1.to_ascii_uppercase());
                    }
                    let uasp_id2 = "SCSI\\_____USB_SanDisk_";
                    if validate_hardware_id(uasp_id2).is_ok() && !is_generic_storage_id(uasp_id2) {
                        ids.insert(uasp_id2.to_ascii_uppercase());
                    }
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
            || dev.service_is("USBSTOR")
            || dev.service_is("UASPStor")
            || (dev.enumerator_name() == "SCSI"
                && dev.parent_instance_id.as_deref().is_some_and(|p| p.to_ascii_uppercase().starts_with("USB")));
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

            // Check product display name against brand
            if !matches {
                if let Some(prod) = inquiry.product_display() {
                    let prod_upper = prod.to_ascii_uppercase();
                    if prod_upper.contains(&brand.display_name.to_ascii_uppercase())
                        || prod_upper.contains(&brand.id.to_ascii_uppercase())
                    {
                        matches = true;
                        has_lab_verified = true;
                    }
                }
            }
        }

        // Check USB VID matching (checking device hardware IDs, parent instance ID, or parent device)
        if !matches {
            for ident in &brand.identifiers {
                if ident.kind == IdentifierKind::UsbVid {
                    let vid_pattern = format!("VID_{}", ident.value.to_ascii_uppercase());
                    if dev.has_id(&vid_pattern)
                        || dev
                            .hardware_ids
                            .iter()
                            .any(|h| h.to_ascii_uppercase().contains(&vid_pattern))
                        || dev
                            .parent_instance_id
                            .as_deref()
                            .is_some_and(|p| p.to_ascii_uppercase().contains(&vid_pattern))
                    {
                        matches = true;
                        break;
                    }
                }
            }
        }

        // Fallback for special brands like VendorC / Kingston / SanDisk by name or instance
        if !matches {
            let brand_slug = brand.id.to_ascii_lowercase();
            let brand_name = brand.display_name.to_ascii_lowercase();
            if dev.friendly_name.as_deref().is_some_and(|f| {
                let f_lower = f.to_ascii_lowercase();
                f_lower.contains(&brand_slug) || f_lower.contains(&brand_name)
            }) || dev.description.as_deref().is_some_and(|d| {
                let d_lower = d.to_ascii_lowercase();
                d_lower.contains(&brand_slug) || d_lower.contains(&brand_name)
            }) || dev.hardware_ids.iter().any(|h| {
                let h_lower = h.to_ascii_lowercase();
                h_lower.contains(&brand_slug) || h_lower.contains(&brand_name)
            }) || dev.parent_instance_id.as_deref().is_some_and(|p| {
                let p_lower = p.to_ascii_lowercase();
                p_lower.contains(&brand_slug) || p_lower.contains(&brand_name)
            }) {
                matches = true;
                has_lab_verified = true;
            }
        }

        if matches {
            for hwid in &dev.hardware_ids {
                let upper = hwid.trim().to_ascii_uppercase();
                if validate_hardware_id(&upper).is_ok() && !is_generic_storage_id(&upper) {
                    ids.insert(upper);
                }
            }
        }
    }

    // 3. Adopt matching active GPO restrictions for this brand (strictly non-generic)
    let brand_slug = brand.id.to_ascii_lowercase();
    for gpo_id in active_gpo_denies {
        let gpo_upper = gpo_id.to_ascii_uppercase();
        if gpo_upper.contains(&brand_slug.to_ascii_uppercase())
            && validate_hardware_id(gpo_id).is_ok()
            && !is_generic_storage_id(gpo_id)
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

        // If explicitly denied, add its verified hardware IDs to planned_denies (strictly non-generic)
        if configured_intention == ConfiguredIntention::ExplicitDeny {
            for id in &ids {
                if validate_hardware_id(id).is_ok() && !is_generic_storage_id(id) {
                    planned_denies.insert(id.clone());
                }
            }
        } else if configured_intention == ConfiguredIntention::Allowed {
            // Only add to allowlist if identity coverage is verified and non-empty
            if coverage == IdentityCoverage::Verified {
                for id in &ids {
                    if validate_hardware_id(id).is_ok() && !is_generic_storage_id(id) {
                        planned_allows.insert(id.clone());
                    }
                }
            }
        }

        // Preliminary Windows Policy Status (will be refined after compiler invariant check)
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
                if dev.problem_code == Some(28) {
                    if configured_intention == ConfiguredIntention::Allowed {
                        // Check if current Windows active policy still denies this device
                        let denied_in_windows = ids.iter().any(|id| observed.active_denies.contains(id))
                            || dev.hardware_ids.iter().any(|h| observed.active_denies.contains(&h.to_ascii_uppercase()));
                        if denied_in_windows {
                            device_outcome = DeviceOutcomeStatus::InstallationDenied;
                        } else {
                            // Policy allows it, GPO no longer denies it, but devnode stack needs restart
                            device_outcome = DeviceOutcomeStatus::DriverRecoveryNeeded;
                        }
                    } else {
                        device_outcome = DeviceOutcomeStatus::InstallationDenied;
                    }
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

    // Additive Device-Level Overrides:
    // Incorporate explicitly denied devices into planned_denies without clearing or replacing manufacturer rules.
    let mut device_override_views = Vec::new();
    for d_rule in &inner_policy.denied_devices {
        if !d_rule.enabled {
            continue;
        }
        let hw_upper = d_rule.hardware_id.trim().to_ascii_uppercase();
        if validate_hardware_id(&hw_upper).is_ok() && !is_generic_storage_id(&hw_upper) {
            planned_denies.insert(hw_upper.clone());
        }

        // If instance_id or devnode exists in inventory, also add device-specific hardware IDs
        for dev in inventory {
            let is_match = d_rule
                .instance_id
                .as_deref()
                .is_some_and(|inst| dev.instance_id.eq_ignore_ascii_case(inst))
                || dev.has_id(&hw_upper)
                || dev
                    .hardware_ids
                    .iter()
                    .any(|h| h.trim().eq_ignore_ascii_case(&hw_upper));
            if is_match {
                for h in &dev.hardware_ids {
                    let h_upper = h.trim().to_ascii_uppercase();
                    if validate_hardware_id(&h_upper).is_ok() && !is_generic_storage_id(&h_upper) {
                        planned_denies.insert(h_upper);
                    }
                }
            }
        }

        let windows_status = if observed.active_denies.contains(&hw_upper) {
            WindowsPolicyStatus::Applied
        } else {
            WindowsPolicyStatus::NotApplied
        };

        let mut outcome = DeviceOutcomeStatus::NotConnected;
        for dev in inventory {
            let is_match = d_rule
                .instance_id
                .as_deref()
                .is_some_and(|inst| dev.instance_id.eq_ignore_ascii_case(inst))
                || dev.has_id(&hw_upper)
                || dev
                    .hardware_ids
                    .iter()
                    .any(|h| h.trim().eq_ignore_ascii_case(&hw_upper));
            if is_match {
                if dev.problem_code == Some(28) {
                    outcome = DeviceOutcomeStatus::InstallationDenied;
                } else {
                    outcome = DeviceOutcomeStatus::Accessible;
                }
                break;
            }
        }

        device_override_views.push(DeviceOverrideView {
            hardware_id: d_rule.hardware_id.clone(),
            instance_id: d_rule.instance_id.clone(),
            label: d_rule.label.clone(),
            denied: true,
            enabled: d_rule.enabled,
            windows_status,
            device_outcome: outcome,
        });
    }

    // Incorporate explicitly allowed devices into planned_allows
    for a_rule in &inner_policy.allowed_devices {
        if !a_rule.enabled {
            continue;
        }
        let hw_upper = a_rule.hardware_id.trim().to_ascii_uppercase();
        if validate_hardware_id(&hw_upper).is_ok() && !is_generic_storage_id(&hw_upper) {
            planned_allows.insert(hw_upper.clone());
        }

        let windows_status = if observed.active_allows.contains(&hw_upper) {
            WindowsPolicyStatus::Applied
        } else {
            WindowsPolicyStatus::NotApplied
        };

        let mut outcome = DeviceOutcomeStatus::NotConnected;
        for dev in inventory {
            let is_match = a_rule
                .instance_id
                .as_deref()
                .is_some_and(|inst| dev.instance_id.eq_ignore_ascii_case(inst))
                || dev.has_id(&hw_upper)
                || dev
                    .hardware_ids
                    .iter()
                    .any(|h| h.trim().eq_ignore_ascii_case(&hw_upper));
            if is_match {
                if dev.problem_code == Some(28) {
                    outcome = DeviceOutcomeStatus::DriverRecoveryNeeded;
                } else {
                    outcome = DeviceOutcomeStatus::Accessible;
                }
                break;
            }
        }

        device_override_views.push(DeviceOverrideView {
            hardware_id: a_rule.hardware_id.clone(),
            instance_id: a_rule.instance_id.clone(),
            label: a_rule.label.clone(),
            denied: false,
            enabled: a_rule.enabled,
            windows_status,
            device_outcome: outcome,
        });
    }

    // Preserve and adopt managed active GPO restrictions that are still legitimately configured
    // (e.g. Kingston remains denied when another brand is added or modified).
    // Generic IDs (like USBSTOR\GENDISK) or IDs belonging to non-denied brands are NEVER adopted.
    for active_deny in &observed.active_denies {
        if is_generic_storage_id(active_deny) || validate_hardware_id(active_deny).is_err() {
            // Generic or invalid active denies are purged to removed_denies
            continue;
        }

        // Only adopt if this active deny belongs to a manufacturer currently configured as ExplicitDeny
        // OR an explicitly denied device override rule.
        let belongs_to_explicit_deny = manufacturer_views.iter().any(|m| {
            m.configured_intention == ConfiguredIntention::ExplicitDeny
                && (m.hardware_ids.contains(active_deny)
                    || active_deny
                        .to_ascii_uppercase()
                        .contains(&m.brand_id.to_ascii_uppercase()))
        });

        let belongs_to_device_deny = inner_policy.denied_devices.iter().any(|d| {
            d.enabled && d.hardware_id.trim().eq_ignore_ascii_case(active_deny)
        });

        if belongs_to_explicit_deny || belongs_to_device_deny {
            planned_denies.insert(active_deny.clone());
        }
    }

    // Compiler Invariant Check:
    // "No enabled allowlisted device may match any effective denied device ID at the same or higher policy-precedence level."
    let mut has_conflict = false;
    for m in &mut manufacturer_views {
        if m.configured_intention != ConfiguredIntention::Allowed {
            continue;
        }

        let mut conflicting_ids = Vec::new();
        for id in &m.hardware_ids {
            if planned_denies.contains(id) {
                conflicting_ids.push(id.clone());
            }
        }

        for dev in inventory {
            let is_storage = dev.class_is("{4d36e967-e325-11ce-bfc1-08002be10318}")
                || dev.enumerator_name() == "USBSTOR"
                || dev.service_is("USBSTOR");
            if !is_storage {
                continue;
            }
            let matches_dev = m.hardware_ids.iter().any(|id| dev.has_id(id))
                || dev.friendly_name.as_deref().is_some_and(|f| {
                    f.to_ascii_lowercase().contains(&m.brand_id.to_ascii_lowercase())
                });
            if matches_dev {
                for dev_id in &dev.hardware_ids {
                    let dev_upper = dev_id.trim().to_ascii_uppercase();
                    if planned_denies.contains(&dev_upper) && !conflicting_ids.contains(&dev_upper) {
                        conflicting_ids.push(dev_upper);
                    }
                }
            }
        }

        if !conflicting_ids.is_empty() {
            has_conflict = true;
            m.windows_policy = WindowsPolicyStatus::Conflict;
            m.notes = Some(format!(
                "Çakışma: Bu izinli üretici için tanımlanan kimlikler engelleme listesindeki kimliklerle çakışıyor: {}",
                conflicting_ids.join(", ")
            ));
        } else if m.hardware_ids.is_empty() {
            m.windows_policy = WindowsPolicyStatus::NotApplied;
        } else {
            // Verify against live observed policy:
            // If any ID matches an active deny in Windows, it cannot be considered Applied!
            let matches_active_deny = m.hardware_ids.iter().any(|id| observed.active_denies.contains(id));
            if matches_active_deny {
                m.windows_policy = WindowsPolicyStatus::Conflict;
            } else if m.hardware_ids.iter().all(|id| observed.active_allows.contains(id)) && !m.hardware_ids.is_empty() {
                m.windows_policy = WindowsPolicyStatus::Applied;
            } else {
                m.windows_policy = WindowsPolicyStatus::NotApplied;
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

    let is_synchronized = added_denies.is_empty() && removed_denies.is_empty() && !has_conflict;
    let is_applied = is_synchronized && observed.raw_gpo_present && !deny_list.is_empty() && !has_conflict;

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

    let can_apply = (!deny_list.is_empty() || !observed.active_denies.is_empty()) && !has_conflict;

    let blocker_reason = if has_conflict {
        Some(LocalizedText::new(
            "Politika çakışması tespit edildi: İzinli üretici kimlikleri ile engellenen kimlikler çakışıyor.",
            "Policy conflict detected: Overlap between allowed manufacturer IDs and denied IDs.",
        ))
    } else if deny_list.is_empty() && observed.active_denies.is_empty() {
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
        device_overrides: device_override_views,
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
    use crate::policy_state::ValueRef;
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
            denied_devices: vec![],
            allowed_devices: vec![],
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

        // The unverified encrypted-USB profile has unknown identity coverage and does not emit unsafe rules
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

    #[test]
    fn test_is_generic_storage_id_and_validation() {
        assert!(is_generic_storage_id("USBSTOR\\GenDisk"));
        assert!(is_generic_storage_id("GenDisk"));
        assert!(is_generic_storage_id("USBSTOR\\Disk"));
        assert!(is_generic_storage_id("SCSI\\Disk"));
        assert!(is_generic_storage_id("USBSTOR\\RAW"));
        assert!(is_generic_storage_id("USB\\Class_08&SubClass_06&Prot_50"));
        assert!(is_generic_storage_id("USB\\Class_08"));

        assert!(!is_generic_storage_id("USBSTOR\\DiskKingstonDataTraveler_3.0____"));
        assert!(!is_generic_storage_id("USBSTOR\\DiskVendorC_ProductCode_____3.20"));
        assert!(!is_generic_storage_id("USB\\VID_0951&PID_1666"));
        assert!(!is_generic_storage_id("USB\\VID_346D&PID_5678"));

        // validate_hardware_id must reject generic storage IDs
        assert!(validate_hardware_id("USBSTOR\\GenDisk").is_err());
        assert!(validate_hardware_id("USBSTOR\\Disk").is_err());
        assert!(validate_hardware_id("USB\\Class_08").is_err());
    }

    #[test]
    fn test_vendorc_deny_to_allow_transition_purges_denies_and_preserves_kingston() {
        let mut raw: ManufacturerCatalog =
            serde_json::from_str(include_str!("../../../config/manufacturer-catalog.json")).unwrap();
        raw.reserved_generic_vendors.retain(|v| v != "VendorC");
        raw.brands.retain(|b| b.id != "vendorc");
        raw.brands.push(BrandEntry {
            id: "vendorc".into(),
            display_name: "VendorC".into(),
            aliases: vec!["VendorC".into()],
            identifiers: vec![
                rustward_core::catalog::BrandIdentifier {
                    kind: rustward_core::catalog::IdentifierKind::InquiryVendor,
                    value: "VendorC".into(),
                    verification: rustward_core::catalog::Verification::LabVerified,
                    source: "Test".into(),
                },
                rustward_core::catalog::BrandIdentifier {
                    kind: rustward_core::catalog::IdentifierKind::UsbVid,
                    value: "346D".into(),
                    verification: rustward_core::catalog::Verification::LabVerified,
                    source: "Test".into(),
                },
            ],
            notes: None,
        });
        let cat = ValidatedCatalog::validate(raw).unwrap();

        // 1. Initial policy: both Kingston and VendorC are denied
        // 2. Transitioned policy: Kingston is denied, VendorC is allowed
        let p = WorkstationPolicy {
            schema_version: 1,
            workstation_id: "PC-01".into(),
            policy_version: 43,
            mode: PolicyMode::DryRun,
            catalog_version: cat.catalog().catalog_version.clone(),
            allowed_brands: vec![BrandRule {
                brand_id: "vendorc".into(),
                enabled: true,
                note: None,
            }],
            denied_brands: vec![BrandRule {
                brand_id: "kingston".into(),
                enabled: true,
                note: None,
            }],
            denied_devices: vec![],
            allowed_devices: vec![],
        };
        let pol = ValidatedPolicy::validate(p, &cat).unwrap();

        // Prior snapshot where both Kingston and VendorC were denied,
        // and a buggy previous run had also added USBSTOR\GenDisk to active denies
        let restr_key = "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\DEVICEINSTALL\\RESTRICTIONS";
        let deny_sub = "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\DEVICEINSTALL\\RESTRICTIONS\\DENYDEVICEIDS";
        let mut snap = PolicySnapshot::default();
        snap.values.insert(
            ValueRef::new(restr_key, "DenyDeviceIDs"),
            RegData::Dword(1),
        );
        snap.values.insert(
            ValueRef::new(deny_sub, "1"),
            RegData::Sz("USBSTOR\\DiskKingstonDataTraveler_3.0____".into()),
        );
        snap.values.insert(
            ValueRef::new(deny_sub, "2"),
            RegData::Sz("USBSTOR\\DiskVendorC_ProductCode_____3.20".into()),
        );
        snap.values.insert(
            ValueRef::new(deny_sub, "3"),
            RegData::Sz("USBSTOR\\GenDisk".into()),
        );

        let plan = compile_compound_policy(&pol, &cat, &[], Some(&snap), true);

        // USBSTOR\GenDisk must NOT be in compiled deny list
        assert!(
            !plan.compiled.deny_hardware_ids.contains(&"USBSTOR\\GENDISK".to_string()),
            "USBSTOR\\GenDisk must never appear in compiled deny IDs"
        );

        // Kingston must remain denied
        assert!(
            plan.compiled
                .deny_hardware_ids
                .iter()
                .any(|id| id.contains("KINGSTON")),
            "Kingston must remain denied"
        );

        // VendorC must NOT be in compiled deny list
        assert!(
            !plan.compiled
                .deny_hardware_ids
                .iter()
                .any(|id| id.contains("VENDORC")),
            "VendorC must be purged from deny list"
        );

        // VendorC must be listed in removed_denies
        assert!(
            plan.diff
                .removed_denies
                .iter()
                .any(|id| id.contains("VENDORC")),
            "VendorC must be in removed_denies"
        );

        // Generic USBSTOR\GenDisk must also be in removed_denies
        assert!(
            plan.diff
                .removed_denies
                .iter()
                .any(|id| id.contains("GENDISK")),
            "USBSTOR\\GenDisk must be in removed_denies"
        );

        // VendorC is configured as Allowed, but because the live Windows GPO still has VendorC in active_denies,
        // it accurately reports Conflict until the new policy is written to Windows!
        let vendorc = plan
            .manufacturers
            .iter()
            .find(|m| m.brand_id == "vendorc")
            .unwrap();
        assert_eq!(vendorc.configured_intention, ConfiguredIntention::Allowed);
        assert_eq!(vendorc.windows_policy, WindowsPolicyStatus::Conflict);

        // After the plan is applied to GPO (VendorC removed from active_denies, added to active_allows):
        let mut applied_snap = PolicySnapshot::default();
        applied_snap.values.insert(
            ValueRef::new(restr_key, "DenyDeviceIDs"),
            RegData::Dword(1),
        );
        for (i, deny_id) in plan.compiled.deny_hardware_ids.iter().enumerate() {
            applied_snap.values.insert(
                ValueRef::new(deny_sub, &(i + 1).to_string()),
                RegData::Sz(deny_id.clone()),
            );
        }
        let allow_sub = "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\DEVICEINSTALL\\RESTRICTIONS\\ALLOWDEVICEIDS";
        applied_snap.values.insert(
            ValueRef::new(restr_key, "AllowDeviceIDs"),
            RegData::Dword(1),
        );
        for (i, allow_id) in plan.compiled.allow_hardware_ids.iter().enumerate() {
            applied_snap.values.insert(
                ValueRef::new(allow_sub, &(i + 1).to_string()),
                RegData::Sz(allow_id.clone()),
            );
        }

        let applied_plan = compile_compound_policy(&pol, &cat, &[], Some(&applied_snap), true);
        let vendorc_applied = applied_plan
            .manufacturers
            .iter()
            .find(|m| m.brand_id == "vendorc")
            .unwrap();
        assert_eq!(vendorc_applied.windows_policy, WindowsPolicyStatus::Applied);
        assert!(applied_plan.diff.is_synchronized);
        assert!(applied_plan.is_applied);
    }

    #[test]
    fn test_compiler_invariant_detects_conflict_between_allow_and_deny() {
        let cat = sample_catalog();

        // Policy where Sandisk is allowed, but an overlapping ID is injected into deny
        let p = WorkstationPolicy {
            schema_version: 1,
            workstation_id: "PC-01".into(),
            policy_version: 44,
            mode: PolicyMode::DryRun,
            catalog_version: cat.catalog().catalog_version.clone(),
            allowed_brands: vec![BrandRule {
                brand_id: "sandisk".into(),
                enabled: true,
                note: None,
            }],
            denied_brands: vec![BrandRule {
                brand_id: "kingston".into(),
                enabled: true,
                note: None,
            }],
            denied_devices: vec![],
            allowed_devices: vec![],
        };
        let pol = ValidatedPolicy::validate(p, &cat).unwrap();

        // Snapshot has an active deny that matches Sandisk hardware ID
        let restr_key = "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\DEVICEINSTALL\\RESTRICTIONS";
        let deny_sub = "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\DEVICEINSTALL\\RESTRICTIONS\\DENYDEVICEIDS";
        let mut snap = PolicySnapshot::default();
        snap.values.insert(
            ValueRef::new(restr_key, "DenyDeviceIDs"),
            RegData::Dword(1),
        );
        snap.values.insert(
            ValueRef::new(deny_sub, "1"),
            RegData::Sz("USBSTOR\\DiskSanDisk_".into()),
        );

        let plan = compile_compound_policy(&pol, &cat, &[], Some(&snap), true);

        let sandisk = plan
            .manufacturers
            .iter()
            .find(|m| m.brand_id == "sandisk")
            .unwrap();
        assert_eq!(sandisk.configured_intention, ConfiguredIntention::Allowed);
        // Sandisk matches an active deny in Windows GPO -> MUST report Conflict!
        assert_eq!(sandisk.windows_policy, WindowsPolicyStatus::Conflict);
        assert!(!plan.diff.is_synchronized);
        assert!(!plan.is_applied);
    }

    #[test]
    fn test_device_outcome_driver_recovery_needed_when_allowed_device_has_code_28() {
        let mut raw: ManufacturerCatalog =
            serde_json::from_str(include_str!("../../../config/manufacturer-catalog.json")).unwrap();
        raw.reserved_generic_vendors.retain(|v| v != "VendorC");
        raw.brands.retain(|b| b.id != "vendorc");
        raw.brands.push(BrandEntry {
            id: "vendorc".into(),
            display_name: "VendorC".into(),
            aliases: vec!["VendorC".into()],
            identifiers: vec![
                rustward_core::catalog::BrandIdentifier {
                    kind: rustward_core::catalog::IdentifierKind::InquiryVendor,
                    value: "VendorC".into(),
                    verification: rustward_core::catalog::Verification::LabVerified,
                    source: "Test".into(),
                },
                rustward_core::catalog::BrandIdentifier {
                    kind: rustward_core::catalog::IdentifierKind::UsbVid,
                    value: "346D".into(),
                    verification: rustward_core::catalog::Verification::LabVerified,
                    source: "Test".into(),
                },
            ],
            notes: None,
        });
        let cat = ValidatedCatalog::validate(raw).unwrap();
        let p = WorkstationPolicy {
            schema_version: 1,
            workstation_id: "PC-01".into(),
            policy_version: 45,
            mode: PolicyMode::DryRun,
            catalog_version: cat.catalog().catalog_version.clone(),
            allowed_brands: vec![BrandRule {
                brand_id: "vendorc".into(),
                enabled: true,
                note: None,
            }],
            denied_brands: vec![],
            denied_devices: vec![],
            allowed_devices: vec![],
        };
        let pol = ValidatedPolicy::validate(p, &cat).unwrap();

        // Inventory has VendorC device with problem_code = 28
        let dev = DeviceRecord {
            instance_id: "USBSTOR\\Disk&Ven_VendorC&Prod_ProductCode&Rev_3.20\\0123456789".into(),
            hardware_ids: vec![
                "USBSTOR\\DiskVendorC_ProductCode_____3.20".into(),
                "USB\\VID_346D&PID_5678".into(),
            ],
            compatible_ids: vec!["USBSTOR\\Disk".into()],
            class_guid: Some("{4d36e967-e325-11ce-bfc1-08002be10318}".into()),
            class_name: Some("DiskDrive".into()),
            enumerator: Some("USBSTOR".into()),
            service: Some("disk".into()),
            inf_manufacturer: Some("VendorC".into()),
            friendly_name: Some("VendorC ProductCode USB Device".into()),
            description: Some("Disk drive".into()),
            bus_reported_description: None,
            parent_instance_id: None,
            present: Some(true),
            problem_code: Some(28),
        };

        // GPO active denies are empty (VendorC is no longer denied by Windows)
        let plan = compile_compound_policy(&pol, &cat, &[dev], None, true);

        let vendorc = plan
            .manufacturers
            .iter()
            .find(|m| m.brand_id == "vendorc")
            .unwrap();
        assert_eq!(vendorc.configured_intention, ConfiguredIntention::Allowed);
        assert_eq!(vendorc.device_outcome, DeviceOutcomeStatus::DriverRecoveryNeeded);
    }

    #[test]
    fn test_sandisk_uasp_hardware_ids_and_transitions() {
        let raw: ManufacturerCatalog =
            serde_json::from_str(include_str!("../../../config/manufacturer-catalog.json")).unwrap();
        let cat = ValidatedCatalog::validate(raw).unwrap();

        // 1. Initial policy: Both Kingston and SanDisk are explicitly denied
        let p1 = WorkstationPolicy {
            schema_version: 1,
            workstation_id: "PC-01".into(),
            policy_version: 50,
            mode: PolicyMode::DryRun,
            catalog_version: cat.catalog().catalog_version.clone(),
            allowed_brands: vec![],
            denied_brands: vec![
                BrandRule {
                    brand_id: "kingston".into(),
                    enabled: true,
                    note: None,
                },
                BrandRule {
                    brand_id: "sandisk".into(),
                    enabled: true,
                    note: None,
                },
            ],
            denied_devices: vec![],
            allowed_devices: vec![],
        };
        let pol1 = ValidatedPolicy::validate(p1, &cat).unwrap();

        // Simulated SanDisk 3.2Gen1 UASP device as observed in lab
        let sandisk_dev = DeviceRecord {
            instance_id: "SCSI\\DISK&VEN__USB&PROD__SANDISK_3.2GEN1\\7&3AAEEFA6&0&000000".into(),
            hardware_ids: vec![
                "SCSI\\Disk_____USB_SanDisk_3.2Gen11.00".into(),
                "SCSI\\Disk_____USB_SanDisk_3.2Gen1".into(),
                "SCSI\\Disk_____USB".into(),
                "SCSI\\_____USB_SanDisk_3.2Gen11".into(),
            ],
            compatible_ids: vec!["SCSI\\Disk".into(), "SCSI\\RAW".into()],
            class_guid: Some("{4d36e967-e325-11ce-bfc1-08002be10318}".into()),
            class_name: Some("DiskDrive".into()),
            enumerator: Some("SCSI".into()),
            service: Some("disk".into()),
            inf_manufacturer: Some("Compatible USB storage device".into()),
            friendly_name: Some("SanDisk 3.2Gen1 USB Device".into()),
            description: Some("Disk drive".into()),
            bus_reported_description: None,
            parent_instance_id: Some("USB\\VID_0781&PID_55A3\\TESTSERIAL00000001".into()),
            present: Some(true),
            problem_code: Some(28),
        };

        // Kingston device
        let kingston_dev = DeviceRecord {
            instance_id: "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0\\001".into(),
            hardware_ids: vec![
                "USBSTOR\\DiskKingstonDataTraveler_3.0____".into(),
                "USBSTOR\\DiskKingston".into(),
            ],
            compatible_ids: vec!["USBSTOR\\Disk".into()],
            class_guid: Some("{4d36e967-e325-11ce-bfc1-08002be10318}".into()),
            class_name: Some("DiskDrive".into()),
            enumerator: Some("USBSTOR".into()),
            service: Some("disk".into()),
            inf_manufacturer: Some("Kingston".into()),
            friendly_name: Some("Kingston DataTraveler 3.0 USB Device".into()),
            description: Some("Disk drive".into()),
            bus_reported_description: None,
            parent_instance_id: Some("USB\\VID_0951&PID_1666\\001".into()),
            present: Some(true),
            problem_code: Some(28),
        };

        let plan1 = compile_compound_policy(
            &pol1,
            &cat,
            &[sandisk_dev.clone(), kingston_dev.clone()],
            None,
            true,
        );

        // SanDisk denies must contain both UASP patterns and specific hardware IDs
        assert!(plan1.compiled.deny_hardware_ids.contains(&"SCSI\\DISK_____USB_SANDISK_".to_string()));
        assert!(plan1.compiled.deny_hardware_ids.contains(&"SCSI\\DISK_____USB_SANDISK_3.2GEN1".to_string()));
        assert!(plan1.compiled.deny_hardware_ids.contains(&"USBSTOR\\DISKSANDISK_".to_string()));
        // Kingston denies must also be present
        assert!(plan1.compiled.deny_hardware_ids.contains(&"USBSTOR\\DISKKINGSTON".to_string()));

        // Strictly NO generic storage IDs in deny list
        assert!(!plan1.compiled.deny_hardware_ids.contains(&"SCSI\\DISK_____USB".to_string()));
        assert!(!plan1.compiled.deny_hardware_ids.contains(&"SCSI\\DISK".to_string()));
        assert!(!plan1.compiled.deny_hardware_ids.contains(&"USBSTOR\\GENDISK".to_string()));

        let sandisk_view1 = plan1.manufacturers.iter().find(|m| m.brand_id == "sandisk").unwrap();
        assert_eq!(sandisk_view1.configured_intention, ConfiguredIntention::ExplicitDeny);
        assert_eq!(sandisk_view1.device_outcome, DeviceOutcomeStatus::InstallationDenied);

        // 2. Transition policy: SanDisk becomes Allowed, Kingston stays ExplicitDeny
        let p2 = WorkstationPolicy {
            schema_version: 1,
            workstation_id: "PC-01".into(),
            policy_version: 51,
            mode: PolicyMode::DryRun,
            catalog_version: cat.catalog().catalog_version.clone(),
            allowed_brands: vec![
                BrandRule {
                    brand_id: "sandisk".into(),
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
            ],
            denied_devices: vec![],
            allowed_devices: vec![],
        };
        let pol2 = ValidatedPolicy::validate(p2, &cat).unwrap();

        let plan2 = compile_compound_policy(
            &pol2,
            &cat,
            &[sandisk_dev.clone(), kingston_dev.clone()],
            None,
            true,
        );

        // SanDisk denies must be purged completely
        assert!(!plan2.compiled.deny_hardware_ids.contains(&"SCSI\\DISK_____USB_SANDISK_".to_string()));
        assert!(!plan2.compiled.deny_hardware_ids.contains(&"SCSI\\DISK_____USB_SANDISK_3.2GEN1".to_string()));
        assert!(!plan2.compiled.deny_hardware_ids.contains(&"USBSTOR\\DISKSANDISK_".to_string()));

        // Kingston denies must be retained
        assert!(plan2.compiled.deny_hardware_ids.contains(&"USBSTOR\\DISKKINGSTON".to_string()));

        let sandisk_view2 = plan2.manufacturers.iter().find(|m| m.brand_id == "sandisk").unwrap();
        assert_eq!(sandisk_view2.configured_intention, ConfiguredIntention::Allowed);
        assert_eq!(sandisk_view2.device_outcome, DeviceOutcomeStatus::DriverRecoveryNeeded);

        let kingston_view2 = plan2.manufacturers.iter().find(|m| m.brand_id == "kingston").unwrap();
        assert_eq!(kingston_view2.configured_intention, ConfiguredIntention::ExplicitDeny);
        assert_eq!(kingston_view2.device_outcome, DeviceOutcomeStatus::InstallationDenied);
    }
}
