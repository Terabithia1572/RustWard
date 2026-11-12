//! Local, versioned manufacturer catalog.
//!
//! The catalog maps an administrator-facing *brand* (e.g. "SanDisk") to the
//! technical identifiers a device of that brand may expose. It is a local
//! JSON file, updated only by an authorized administrator; it is never
//! downloaded.
//!
//! Only [`IdentifierKind::InquiryVendor`] identifiers are *enforceable*,
//! because the INQUIRY vendor is the only brand-level identifier that
//! Windows exposes as a hardware ID (see [`crate::ids`]). USB VIDs are kept
//! as *corroborating* evidence only.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::ids::{INQUIRY_VENDOR_LEN, encode_inquiry_field, parse_vid};

/// Current catalog schema version.
pub const CATALOG_SCHEMA_VERSION: u32 = 1;

/// Kind of brand identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierKind {
    /// SCSI INQUIRY vendor identification (≤ 8 ASCII chars). Enforceable
    /// through the vendor-level USBSTOR/SCSI hardware ID.
    InquiryVendor,
    /// USB-IF vendor ID (4 hex digits). Corroborating evidence only.
    UsbVid,
}

impl IdentifierKind {
    /// Whether a Windows-supported mechanism can match this identifier at
    /// brand level (without enumerating every product).
    #[must_use]
    pub const fn enforceable(self) -> bool {
        matches!(self, Self::InquiryVendor)
    }
}

/// How well an identifier has been confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// Believed correct but never observed by us.
    Unverified,
    /// Taken from a public registry (e.g. the public USB ID list).
    PublicRegistry,
    /// Stated in manufacturer documentation.
    VendorDocumented,
    /// Observed on physical hardware in the RustWard lab, with evidence.
    LabVerified,
}

/// One identifier attached to a brand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandIdentifier {
    /// Identifier kind.
    pub kind: IdentifierKind,
    /// Raw value: INQUIRY vendor text (e.g. `SanDisk`) or VID hex (`0781`).
    pub value: String,
    /// Confirmation level.
    pub verification: Verification,
    /// Where the value came from (document, lab evidence ID, …).
    pub source: String,
}

/// A brand in the catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandEntry {
    /// Stable slug, e.g. `sandisk`.
    pub id: String,
    /// Display name (may contain non-ASCII, e.g. "Şifreli Depolama / Örnek").
    pub display_name: String,
    /// Alternative names. Used only for search and *hints*, never for
    /// authorization.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Technical identifiers.
    #[serde(default)]
    pub identifiers: Vec<BrandIdentifier>,
    /// Free-form administrator notes.
    #[serde(default)]
    pub notes: Option<String>,
}

impl BrandEntry {
    /// Enforceable identifiers of this brand.
    pub fn enforceable_identifiers(&self) -> impl Iterator<Item = &BrandIdentifier> {
        self.identifiers.iter().filter(|i| i.kind.enforceable())
    }
}

/// The catalog file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManufacturerCatalog {
    /// Schema version, currently [`CATALOG_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Catalog content version; policies are bound to it.
    pub catalog_version: String,
    /// Brands.
    pub brands: Vec<BrandEntry>,
    /// INQUIRY vendor strings that are known to be generic (controller,
    /// bridge-chip or placeholder values). They can never authorize access.
    #[serde(default)]
    pub reserved_generic_vendors: Vec<String>,
}

/// Severity of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Blocks activation.
    Error,
    /// Allowed but must be shown to the administrator.
    Warning,
}

/// A catalog validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogIssue {
    /// Severity.
    pub severity: Severity,
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Human-readable detail.
    pub detail: String,
}

/// Catalog rejected.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// JSON error.
    #[error("catalog JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    /// Validation errors.
    #[error("catalog failed validation with {} error(s)", .0.iter().filter(|i| i.severity == Severity::Error).count())]
    Invalid(Vec<CatalogIssue>),
}

/// A catalog that passed validation. Only obtainable through
/// [`ValidatedCatalog::validate`].
#[derive(Debug, Clone)]
pub struct ValidatedCatalog {
    catalog: ManufacturerCatalog,
    warnings: Vec<CatalogIssue>,
    /// Upper-cased encoded INQUIRY vendor field → brand id.
    inquiry_index: HashMap<String, String>,
    /// VID → brand ids (may be shared).
    vid_index: HashMap<u16, Vec<String>>,
    reserved: HashSet<String>,
}

fn normalize_generic(v: &str) -> String {
    v.trim()
        .trim_end_matches('_')
        .replace('_', " ")
        .trim()
        .to_ascii_uppercase()
}

fn valid_slug(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl ValidatedCatalog {
    /// Parse and validate a catalog from JSON.
    pub fn from_json(json: &str) -> Result<Self, CatalogError> {
        let catalog: ManufacturerCatalog = serde_json::from_str(json)?;
        Self::validate(catalog)
    }

    /// Validate a catalog.
    pub fn validate(catalog: ManufacturerCatalog) -> Result<Self, CatalogError> {
        let mut issues = Vec::new();
        let mut err = |code: &'static str, detail: String| {
            issues.push(CatalogIssue {
                severity: Severity::Error,
                code,
                detail,
            });
        };

        if catalog.schema_version != CATALOG_SCHEMA_VERSION {
            err(
                "schema_version",
                format!("unsupported catalog schema {}", catalog.schema_version),
            );
        }
        if catalog.catalog_version.trim().is_empty() {
            err(
                "catalog_version",
                "catalog_version must not be empty".into(),
            );
        }

        let reserved: HashSet<String> = catalog
            .reserved_generic_vendors
            .iter()
            .map(|v| normalize_generic(v))
            .collect();

        let mut ids = HashSet::new();
        let mut inquiry_index: HashMap<String, String> = HashMap::new();
        let mut vid_index: HashMap<u16, Vec<String>> = HashMap::new();
        let mut warnings = Vec::new();

        for brand in &catalog.brands {
            if !valid_slug(&brand.id) {
                err(
                    "brand_id",
                    format!("brand id {:?} must match [a-z0-9-]{{1,32}}", brand.id),
                );
            }
            if !ids.insert(brand.id.clone()) {
                err(
                    "brand_id_duplicate",
                    format!("duplicate brand id {:?}", brand.id),
                );
            }
            if brand.display_name.trim().is_empty() {
                err(
                    "display_name",
                    format!("brand {:?} has no display name", brand.id),
                );
            }
            for ident in &brand.identifiers {
                if ident.source.trim().is_empty() {
                    err(
                        "identifier_source",
                        format!(
                            "brand {:?}: identifier {:?} has no source",
                            brand.id, ident.value
                        ),
                    );
                }
                match ident.kind {
                    IdentifierKind::InquiryVendor => {
                        match encode_inquiry_field(&ident.value, INQUIRY_VENDOR_LEN) {
                            Err(e) => err(
                                "inquiry_vendor_invalid",
                                format!("brand {:?}: {e}", brand.id),
                            ),
                            Ok(encoded) => {
                                if reserved.contains(&normalize_generic(&ident.value)) {
                                    err(
                                        "inquiry_vendor_generic",
                                        format!(
                                            "brand {:?}: INQUIRY vendor {:?} is a reserved generic value and cannot identify a brand",
                                            brand.id, ident.value
                                        ),
                                    );
                                }
                                let key = encoded.to_ascii_uppercase();
                                if let Some(other) = inquiry_index.get(&key) {
                                    if other != &brand.id {
                                        err(
                                            "inquiry_vendor_ambiguous",
                                            format!(
                                                "INQUIRY vendor {:?} is claimed by both {:?} and {:?}",
                                                ident.value, other, brand.id
                                            ),
                                        );
                                    }
                                } else {
                                    inquiry_index.insert(key, brand.id.clone());
                                }
                            }
                        }
                    }
                    IdentifierKind::UsbVid => match parse_vid(&ident.value) {
                        None => err(
                            "usb_vid_invalid",
                            format!(
                                "brand {:?}: {:?} is not a 4-digit hex VID",
                                brand.id, ident.value
                            ),
                        ),
                        Some(vid) => {
                            let entry = vid_index.entry(vid).or_default();
                            if !entry.contains(&brand.id) {
                                entry.push(brand.id.clone());
                            }
                        }
                    },
                }
            }
            if brand.enforceable_identifiers().next().is_none() {
                warnings.push(CatalogIssue {
                    severity: Severity::Warning,
                    code: "brand_not_enforceable",
                    detail: format!(
                        "brand {:?} has no enforceable identifier; its devices cannot be recognized and will be denied",
                        brand.id
                    ),
                });
            }
        }
        // Aliases never authorize, but a name shared between brands or equal
        // to a generic vendor would mislead an administrator reading hints.
        let mut names: HashMap<String, Vec<String>> = HashMap::new();
        let mut seen_generic_aliases: HashSet<String> = HashSet::new();
        for brand in &catalog.brands {
            for name in std::iter::once(&brand.display_name).chain(brand.aliases.iter()) {
                let key = crate::names::normalize_brand_name(name);
                if key.is_empty() {
                    continue;
                }
                if reserved.contains(&normalize_generic(name)) {
                    let warn_key = format!("{}:{}", brand.id, normalize_generic(name));
                    if seen_generic_aliases.insert(warn_key) {
                        warnings.push(CatalogIssue {
                            severity: Severity::Warning,
                            code: "alias_generic",
                            detail: format!(
                                "brand {:?}: alias {name:?} is a reserved generic vendor name",
                                brand.id
                            ),
                        });
                    }
                }
                let entry = names.entry(key).or_default();
                if !entry.contains(&brand.id) {
                    entry.push(brand.id.clone());
                }
            }
        }
        let mut shared: Vec<_> = names.iter().filter(|(_, b)| b.len() > 1).collect();
        shared.sort();
        for (name, brands) in shared {
            warnings.push(CatalogIssue {
                severity: Severity::Warning,
                code: "alias_shared",
                detail: format!(
                    "name {name:?} is used by several brands {brands:?}; hints for it are ambiguous"
                ),
            });
        }
        for (vid, brands) in &vid_index {
            if brands.len() > 1 {
                warnings.push(CatalogIssue {
                    severity: Severity::Warning,
                    code: "usb_vid_shared",
                    detail: format!("USB VID {vid:04X} is listed for several brands: {brands:?}"),
                });
            }
        }

        if issues.is_empty() {
            Ok(Self {
                catalog,
                warnings,
                inquiry_index,
                vid_index,
                reserved,
            })
        } else {
            issues.extend(warnings);
            Err(CatalogError::Invalid(issues))
        }
    }

    /// The validated catalog content.
    #[must_use]
    pub fn catalog(&self) -> &ManufacturerCatalog {
        &self.catalog
    }

    /// Non-blocking findings.
    #[must_use]
    pub fn warnings(&self) -> &[CatalogIssue] {
        &self.warnings
    }

    /// Look up a brand by id.
    #[must_use]
    pub fn brand(&self, id: &str) -> Option<&BrandEntry> {
        self.catalog.brands.iter().find(|b| b.id == id)
    }

    /// Brand owning an encoded INQUIRY vendor field (case-insensitive).
    #[must_use]
    pub fn brand_for_inquiry_field(&self, vendor_field: &str) -> Option<&str> {
        self.inquiry_index
            .get(&vendor_field.to_ascii_uppercase())
            .map(String::as_str)
    }

    /// Brands listing a USB VID.
    #[must_use]
    pub fn brands_for_vid(&self, vid: u16) -> &[String] {
        self.vid_index.get(&vid).map_or(&[], Vec::as_slice)
    }

    /// Whether an INQUIRY vendor (raw or `_`-encoded) is a reserved generic value.
    #[must_use]
    pub fn is_generic_vendor(&self, vendor: &str) -> bool {
        let n = normalize_generic(vendor);
        n.is_empty() || self.reserved.contains(&n)
    }
}

/// An entry in the offline standard `usb.ids` registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbRegistryVendor {
    /// 16-bit USB vendor ID.
    pub vid: u16,
    /// 4-digit upper-case hex string (e.g. "0951").
    pub vid_hex: String,
    /// Human-readable vendor name as stated in usb.ids registry.
    pub vendor_name: String,
}

/// Offline USB-IF vendor database parsed from bundled `usb.ids`.
#[derive(Debug, Clone, Default)]
pub struct UsbIdsRegistry {
    vendors: HashMap<u16, String>,
}

impl UsbIdsRegistry {
    /// Parse from text format (Stephen J. Gowdy linux-usb / usb.ids syntax).
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        let mut vendors = HashMap::new();
        for line in text.lines() {
            let line = line.trim_end();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            // Device lines start with tab; ignore them for vendor registry
            if line.starts_with('\t') {
                continue;
            }
            // Vendor line: "<4-hex-chars>  <Vendor Name>"
            if line.len() >= 6 {
                let vid_str = &line[..4];
                if let Ok(vid) = u16::from_str_radix(vid_str, 16) {
                    let name = line[4..].trim();
                    if !name.is_empty() {
                        vendors.insert(vid, name.to_string());
                    }
                }
            }
        }
        Self { vendors }
    }

    /// Bundled static offline registry snapshot.
    pub fn bundled() -> &'static Self {
        static REGISTRY: std::sync::OnceLock<UsbIdsRegistry> = std::sync::OnceLock::new();
        REGISTRY.get_or_init(|| {
            let text = include_str!("../assets/usb.ids");
            Self::from_text(text)
        })
    }

    /// Number of registered vendors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vendors.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vendors.is_empty()
    }

    /// Lookup vendor name by numeric VID.
    #[must_use]
    pub fn lookup_vid(&self, vid: u16) -> Option<&str> {
        self.vendors.get(&vid).map(String::as_str)
    }

    /// Lookup vendor name by 4-hex-digit VID string.
    #[must_use]
    pub fn lookup_vid_hex(&self, hex: &str) -> Option<&str> {
        parse_vid(hex).and_then(|vid| self.lookup_vid(vid))
    }

    /// Search vendors by query substring (case-insensitive in name or hex VID).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<UsbRegistryVendor> {
        let q = query.trim().to_ascii_lowercase();
        let mut results = Vec::new();
        for (&vid, name) in &self.vendors {
            let hex = format!("{vid:04X}");
            if q.is_empty()
                || hex.to_ascii_lowercase().contains(&q)
                || name.to_ascii_lowercase().contains(&q)
            {
                results.push(UsbRegistryVendor {
                    vid,
                    vid_hex: hex,
                    vendor_name: name.clone(),
                });
            }
        }
        results.sort_by(|a, b| a.vendor_name.cmp(&b.vendor_name));
        results
    }

    /// Total number of known vendors in the offline registry.
    #[must_use]
    pub fn count(&self) -> usize {
        self.vendors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(kind: IdentifierKind, value: &str) -> BrandIdentifier {
        BrandIdentifier {
            kind,
            value: value.into(),
            verification: Verification::Unverified,
            source: "unit test".into(),
        }
    }

    fn brand(id: &str, idents: Vec<BrandIdentifier>) -> BrandEntry {
        BrandEntry {
            id: id.into(),
            display_name: id.to_uppercase(),
            aliases: vec![],
            identifiers: idents,
            notes: None,
        }
    }

    fn cat(brands: Vec<BrandEntry>) -> ManufacturerCatalog {
        ManufacturerCatalog {
            schema_version: 1,
            catalog_version: "test-1".into(),
            brands,
            reserved_generic_vendors: vec!["Generic".into(), "USB".into()],
        }
    }

    fn codes(e: CatalogError) -> Vec<&'static str> {
        match e {
            CatalogError::Invalid(v) => v
                .into_iter()
                .filter(|i| i.severity == Severity::Error)
                .map(|i| i.code)
                .collect(),
            CatalogError::Json(_) => vec!["json"],
        }
    }

    #[test]
    fn accepts_valid_catalog_and_indexes_it() {
        let c = ValidatedCatalog::validate(cat(vec![
            brand(
                "sandisk",
                vec![
                    ident(IdentifierKind::InquiryVendor, "SanDisk"),
                    ident(IdentifierKind::UsbVid, "0781"),
                ],
            ),
            brand("tubitak", vec![]),
        ]))
        .unwrap();
        assert_eq!(c.brand_for_inquiry_field("SANDISK_"), Some("sandisk"));
        assert_eq!(c.brands_for_vid(0x0781), ["sandisk".to_string()]);
        assert!(
            c.warnings()
                .iter()
                .any(|w| w.code == "brand_not_enforceable")
        );
    }

    #[test]
    fn rejects_ambiguous_inquiry_vendor() {
        let e = ValidatedCatalog::validate(cat(vec![
            brand("a", vec![ident(IdentifierKind::InquiryVendor, "ACME")]),
            brand("b", vec![ident(IdentifierKind::InquiryVendor, "acme")]),
        ]))
        .unwrap_err();
        assert!(codes(e).contains(&"inquiry_vendor_ambiguous"));
    }

    #[test]
    fn rejects_generic_non_ascii_and_bad_vid() {
        let e = ValidatedCatalog::validate(cat(vec![
            brand("x", vec![ident(IdentifierKind::InquiryVendor, "Generic")]),
            brand("y", vec![ident(IdentifierKind::InquiryVendor, "ÜRETİCİ")]),
            brand("z", vec![ident(IdentifierKind::UsbVid, "78")]),
        ]))
        .unwrap_err();
        let c = codes(e);
        assert!(c.contains(&"inquiry_vendor_generic"));
        assert!(c.contains(&"inquiry_vendor_invalid"));
        assert!(c.contains(&"usb_vid_invalid"));
    }

    #[test]
    fn rejects_bad_slugs_and_duplicates() {
        let e = ValidatedCatalog::validate(cat(vec![
            brand("Bad Id", vec![]),
            brand("dup", vec![]),
            brand("dup", vec![]),
        ]))
        .unwrap_err();
        let c = codes(e);
        assert!(c.contains(&"brand_id"));
        assert!(c.contains(&"brand_id_duplicate"));
    }

    #[test]
    fn alias_conflicts_are_reported_but_never_authorize() {
        let mut a = brand("a", vec![ident(IdentifierKind::InquiryVendor, "AAAA")]);
        a.aliases = vec!["Shared Corp".into(), "USB".into()];
        let mut b = brand("b", vec![ident(IdentifierKind::InquiryVendor, "BBBB")]);
        b.aliases = vec!["shared corp ".into()];
        let c = ValidatedCatalog::validate(cat(vec![a, b])).unwrap();
        let codes: Vec<_> = c.warnings().iter().map(|w| w.code).collect();
        assert!(codes.contains(&"alias_shared"));
        assert!(codes.contains(&"alias_generic"));
        // Aliases do not create enforceable identities.
        assert_eq!(c.brand_for_inquiry_field("Shared_C"), None);
    }

    #[test]
    fn generic_detection_handles_padding_and_case() {
        let c = ValidatedCatalog::validate(cat(vec![])).unwrap();
        assert!(c.is_generic_vendor("Generic_"));
        assert!(c.is_generic_vendor("usb_____"));
        assert!(c.is_generic_vendor("________"));
        assert!(!c.is_generic_vendor("SanDisk_"));
    }

    #[test]
    fn usb_ids_registry_parses_bundled_and_custom_text() {
        let reg = UsbIdsRegistry::bundled();
        assert!(reg.count() >= 40);
        assert_eq!(reg.lookup_vid(0x0951), Some("Kingston Technology"));
        assert_eq!(reg.lookup_vid_hex("0781"), Some("SanDisk Corp."));
        assert_eq!(reg.lookup_vid_hex("1058"), Some("Western Digital Technologies, Inc."));
        assert_eq!(reg.lookup_vid_hex("ffff"), None);

        let search_results = reg.search("Kingston");
        assert!(!search_results.is_empty());
        assert!(search_results.iter().any(|v| v.vid == 0x0951));
    }
}
