//! Validated, versioned edits of the manufacturer catalog and the
//! workstation policy.
//!
//! Every edit:
//! 1. is applied to a copy of the current [`PolicyState`];
//! 2. is rejected if names, ids or identifiers collide with another brand;
//! 3. is fully re-validated ([`ValidatedCatalog`] + [`ValidatedPolicy`]);
//! 4. bumps `policy_version` (always) and the local catalog revision (when
//!    catalog content changes), keeping the policy bound to the catalog;
//! 5. returns an audit-friendly [`ChangeRecord`].
//!
//! The default decision stays **deny**; edits can only add or remove brands
//! from the allowlist.

use serde::{Deserialize, Serialize};

use crate::catalog::{
    BrandEntry, BrandIdentifier, CatalogError, CatalogIssue, IdentifierKind, ManufacturerCatalog,
    Severity, ValidatedCatalog,
};
use crate::names::{normalize_brand_name, slug_from_name};
use crate::policy::{BrandRule, PolicyError, PolicyIssue, ValidatedPolicy, WorkstationPolicy};

/// Maximum aliases per brand.
pub const MAX_ALIASES: usize = 16;
/// Maximum identifiers per brand.
pub const MAX_IDENTIFIERS: usize = 32;
/// Maximum length of a display name, alias, note or source.
pub const MAX_TEXT_LEN: usize = 200;

/// Catalog + policy, the unit that is persisted and edited together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyState {
    /// Manufacturer catalog.
    pub catalog: ManufacturerCatalog,
    /// Workstation policy bound to the catalog version.
    pub policy: WorkstationPolicy,
}

/// Validation result of a whole state.
#[derive(Debug, Clone)]
pub struct ValidatedState {
    /// Validated catalog.
    pub catalog: ValidatedCatalog,
    /// Validated policy.
    pub policy: ValidatedPolicy,
}

impl PolicyState {
    /// Validate catalog and policy together.
    pub fn validate(&self) -> Result<ValidatedState, EditError> {
        let catalog = ValidatedCatalog::validate(self.catalog.clone()).map_err(EditError::from)?;
        let policy =
            ValidatedPolicy::validate(self.policy.clone(), &catalog).map_err(EditError::from)?;
        Ok(ValidatedState { catalog, policy })
    }
}

/// Administrator input describing one manufacturer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManufacturerInput {
    /// Optional explicit slug; derived from `display_name` when absent.
    #[serde(default)]
    pub id: Option<String>,
    /// Display name.
    pub display_name: String,
    /// Aliases (hints only).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Identifiers.
    #[serde(default)]
    pub identifiers: Vec<BrandIdentifier>,
    /// Notes.
    #[serde(default)]
    pub notes: Option<String>,
}

/// An edit operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PolicyEdit {
    /// Add a manufacturer to the catalog, optionally allowing it.
    AddManufacturer {
        /// Input.
        input: ManufacturerInput,
        /// Add to the allowlist (enabled).
        allowed: bool,
    },
    /// Replace a manufacturer's name, aliases, identifiers and notes.
    UpdateManufacturer {
        /// Existing brand id (cannot change).
        id: String,
        /// New content.
        input: ManufacturerInput,
    },
    /// Remove a manufacturer from catalog and allowlist.
    RemoveManufacturer {
        /// Brand id.
        id: String,
    },
    /// Add to / remove from the allowlist.
    SetAllowed {
        /// Brand id.
        id: String,
        /// Allowed.
        allowed: bool,
    },
    /// Add to / remove from the explicit denylist. Denying a brand removes
    /// it from the allowlist (and allowing removes it from the denylist).
    SetDenied {
        /// Brand id.
        id: String,
        /// Denied.
        denied: bool,
    },
    /// Enable / disable an existing allowlist rule (kept for history).
    SetRuleEnabled {
        /// Brand id.
        id: String,
        /// Enabled.
        enabled: bool,
    },
    /// Rename the workstation this policy belongs to (`[A-Za-z0-9_-]{1,64}`).
    /// Policy-level edit: the change record's `brand_id` is empty.
    SetWorkstationId {
        /// New workstation identifier.
        workstation_id: String,
    },
}

impl PolicyEdit {
    /// Stable action name for audit records.
    #[must_use]
    pub fn action(&self) -> &'static str {
        match self {
            Self::AddManufacturer { .. } => "manufacturer_added",
            Self::UpdateManufacturer { .. } => "manufacturer_updated",
            Self::RemoveManufacturer { .. } => "manufacturer_removed",
            Self::SetAllowed { .. } => "allowlist_changed",
            Self::SetDenied { .. } => "denylist_changed",
            Self::SetRuleEnabled { .. } => "rule_enabled_changed",
            Self::SetWorkstationId { .. } => "workstation_id_changed",
        }
    }
}

/// Edit rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum EditError {
    /// Unknown brand id.
    #[error("manufacturer {id:?} does not exist")]
    NotFound {
        /// Id.
        id: String,
    },
    /// Id already used.
    #[error("manufacturer id {id:?} already exists")]
    DuplicateId {
        /// Id.
        id: String,
    },
    /// Display name or alias collides (after normalization) with another brand.
    #[error("name {name:?} conflicts with manufacturer {other_id:?}")]
    NameConflict {
        /// Offending name.
        name: String,
        /// Other brand.
        other_id: String,
    },
    /// Input field invalid.
    #[error("invalid input: {detail}")]
    InvalidInput {
        /// Detail.
        detail: String,
    },
    /// No-op edit.
    #[error("the edit does not change anything")]
    NoChange,
    /// Catalog/policy validation failed.
    #[error("validation failed: {}", .issues.join("; "))]
    Validation {
        /// Error details.
        issues: Vec<String>,
    },
}

impl From<CatalogError> for EditError {
    fn from(e: CatalogError) -> Self {
        match e {
            CatalogError::Invalid(issues) => Self::Validation {
                issues: errors_only(&issues),
            },
            CatalogError::Json(j) => Self::Validation {
                issues: vec![j.to_string()],
            },
        }
    }
}

impl From<PolicyError> for EditError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::Invalid(issues) => Self::Validation {
                issues: issues
                    .iter()
                    .filter(|i| i.severity == Severity::Error)
                    .map(|i: &PolicyIssue| format!("{}: {}", i.code, i.detail))
                    .collect(),
            },
            PolicyError::Json(j) => Self::Validation {
                issues: vec![j.to_string()],
            },
        }
    }
}

fn errors_only(issues: &[CatalogIssue]) -> Vec<String> {
    issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| format!("{}: {}", i.code, i.detail))
        .collect()
}

/// Compact brand description for change records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandSnapshot {
    /// Id.
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Aliases.
    pub aliases: Vec<String>,
    /// Identifiers as `kind:value (verification)`.
    pub identifiers: Vec<String>,
    /// In the allowlist.
    pub allowed: bool,
    /// Rule enabled.
    pub enabled: bool,
    /// Explicitly denied.
    #[serde(default)]
    pub denied: bool,
}

/// Audit record of an applied edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeRecord {
    /// Action.
    pub action: String,
    /// Brand id.
    pub brand_id: String,
    /// One-line summary (English; UI localizes by `action`).
    pub summary: String,
    /// Policy version before.
    pub from_policy_version: u64,
    /// Policy version after.
    pub to_policy_version: u64,
    /// Catalog version before.
    pub from_catalog_version: String,
    /// Catalog version after.
    pub to_catalog_version: String,
    /// Brand before.
    pub before: Option<BrandSnapshot>,
    /// Brand after.
    pub after: Option<BrandSnapshot>,
}

/// Result of a successful edit.
#[derive(Debug, Clone)]
pub struct EditOutcome {
    /// New state.
    pub state: PolicyState,
    /// Validated new state.
    pub validated: ValidatedState,
    /// Audit record.
    pub change: ChangeRecord,
    /// Non-blocking warnings of the new state.
    pub warnings: Vec<String>,
}

fn snapshot_brand(state: &PolicyState, id: &str) -> Option<BrandSnapshot> {
    let b = state.catalog.brands.iter().find(|b| b.id == id)?;
    let rule = state
        .policy
        .allowed_brands
        .iter()
        .find(|r| r.brand_id == id);
    Some(BrandSnapshot {
        id: b.id.clone(),
        display_name: b.display_name.clone(),
        aliases: b.aliases.clone(),
        identifiers: b
            .identifiers
            .iter()
            .map(|i| {
                format!(
                    "{}:{} ({})",
                    match i.kind {
                        IdentifierKind::InquiryVendor => "inquiry_vendor",
                        IdentifierKind::UsbVid => "usb_vid",
                    },
                    i.value,
                    serde_json::to_value(i.verification)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default()
                )
            })
            .collect(),
        allowed: rule.is_some(),
        enabled: rule.is_some_and(|r| r.enabled),
        denied: state
            .policy
            .denied_brands
            .iter()
            .any(|r| r.brand_id == id && r.enabled),
    })
}

fn clean_text(field: &str, s: &str) -> Result<String, EditError> {
    let t = s.trim();
    if t.chars().count() > MAX_TEXT_LEN {
        return Err(EditError::InvalidInput {
            detail: format!("{field} longer than {MAX_TEXT_LEN} characters"),
        });
    }
    if t.chars().any(char::is_control) {
        return Err(EditError::InvalidInput {
            detail: format!("{field} contains control characters"),
        });
    }
    Ok(t.to_owned())
}

/// Normalize and validate the input into a brand entry.
fn build_entry(id: String, input: &ManufacturerInput) -> Result<BrandEntry, EditError> {
    let display_name = clean_text("display_name", &input.display_name)?;
    if normalize_brand_name(&display_name).is_empty() {
        return Err(EditError::InvalidInput {
            detail: "display_name must contain letters or digits".into(),
        });
    }
    if input.aliases.len() > MAX_ALIASES {
        return Err(EditError::InvalidInput {
            detail: format!("at most {MAX_ALIASES} aliases"),
        });
    }
    if input.identifiers.len() > MAX_IDENTIFIERS {
        return Err(EditError::InvalidInput {
            detail: format!("at most {MAX_IDENTIFIERS} identifiers"),
        });
    }
    let mut aliases: Vec<String> = Vec::new();
    for a in &input.aliases {
        let a = clean_text("alias", a)?;
        if normalize_brand_name(&a).is_empty() {
            continue;
        }
        if !aliases
            .iter()
            .any(|x| normalize_brand_name(x) == normalize_brand_name(&a))
        {
            aliases.push(a);
        }
    }
    let mut identifiers: Vec<BrandIdentifier> = Vec::new();
    for i in &input.identifiers {
        let value = clean_text("identifier value", &i.value)?;
        let value = match i.kind {
            IdentifierKind::UsbVid => value.to_ascii_uppercase(),
            IdentifierKind::InquiryVendor => value,
        };
        let source = clean_text("identifier source", &i.source)?;
        let dup = identifiers.iter().any(|x| {
            x.kind == i.kind
                && match i.kind {
                    // INQUIRY matching is case-insensitive after padding.
                    IdentifierKind::InquiryVendor => x.value.eq_ignore_ascii_case(&value),
                    IdentifierKind::UsbVid => x.value == value,
                }
        });
        if dup {
            return Err(EditError::InvalidInput {
                detail: format!("identifier {value:?} listed twice"),
            });
        }
        identifiers.push(BrandIdentifier {
            kind: i.kind,
            value,
            verification: i.verification,
            source,
        });
    }
    let notes = match &input.notes {
        Some(n) => {
            let n = clean_text("notes", n)?;
            (!n.is_empty()).then_some(n)
        }
        None => None,
    };
    Ok(BrandEntry {
        id,
        display_name,
        aliases,
        identifiers,
        notes,
    })
}

/// Reject names that normalize to another brand's display name or alias.
fn check_name_conflicts(
    catalog: &ManufacturerCatalog,
    entry: &BrandEntry,
) -> Result<(), EditError> {
    for name in std::iter::once(&entry.display_name).chain(entry.aliases.iter()) {
        let n = normalize_brand_name(name);
        for other in catalog.brands.iter().filter(|b| b.id != entry.id) {
            let hit = std::iter::once(&other.display_name)
                .chain(other.aliases.iter())
                .any(|o| normalize_brand_name(o) == n);
            if hit {
                return Err(EditError::NameConflict {
                    name: name.clone(),
                    other_id: other.id.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Next local catalog version: `base+local.N`.
#[must_use]
pub fn next_catalog_version(current: &str) -> String {
    match current.rsplit_once("+local.") {
        Some((base, n)) => {
            let n: u64 = n.parse().unwrap_or(0);
            format!("{base}+local.{}", n.saturating_add(1))
        }
        None => format!("{current}+local.1"),
    }
}

/// Apply an edit. Pure: the input state is not modified.
pub fn apply_edit(current: &PolicyState, edit: &PolicyEdit) -> Result<EditOutcome, EditError> {
    let mut next = current.clone();
    let mut catalog_changed = false;

    let brand_id = match edit {
        PolicyEdit::AddManufacturer { input, allowed } => {
            let id = match &input.id {
                Some(id) => id.trim().to_owned(),
                None => slug_from_name(&input.display_name).ok_or(EditError::InvalidInput {
                    detail: "cannot derive an id from display_name".into(),
                })?,
            };
            if next.catalog.brands.iter().any(|b| b.id == id) {
                return Err(EditError::DuplicateId { id });
            }
            let entry = build_entry(id.clone(), input)?;
            check_name_conflicts(&next.catalog, &entry)?;
            next.catalog.brands.push(entry);
            if *allowed {
                next.policy.allowed_brands.push(BrandRule {
                    brand_id: id.clone(),
                    enabled: true,
                    note: None,
                });
            }
            catalog_changed = true;
            id
        }
        PolicyEdit::UpdateManufacturer { id, input } => {
            if input.id.as_deref().is_some_and(|new| new != id) {
                return Err(EditError::InvalidInput {
                    detail: "the id of an existing manufacturer cannot change".into(),
                });
            }
            let pos = next
                .catalog
                .brands
                .iter()
                .position(|b| &b.id == id)
                .ok_or_else(|| EditError::NotFound { id: id.clone() })?;
            let entry = build_entry(id.clone(), input)?;
            check_name_conflicts(&next.catalog, &entry)?;
            if next.catalog.brands[pos] == entry {
                return Err(EditError::NoChange);
            }
            next.catalog.brands[pos] = entry;
            catalog_changed = true;
            id.clone()
        }
        PolicyEdit::RemoveManufacturer { id } => {
            let before = next.catalog.brands.len();
            next.catalog.brands.retain(|b| &b.id != id);
            if next.catalog.brands.len() == before {
                return Err(EditError::NotFound { id: id.clone() });
            }
            next.policy.allowed_brands.retain(|r| &r.brand_id != id);
            next.policy.denied_brands.retain(|r| &r.brand_id != id);
            catalog_changed = true;
            id.clone()
        }
        PolicyEdit::SetAllowed { id, allowed } => {
            if !next.catalog.brands.iter().any(|b| &b.id == id) {
                return Err(EditError::NotFound { id: id.clone() });
            }
            let present = next.policy.allowed_brands.iter().any(|r| &r.brand_id == id);
            match (present, *allowed) {
                (true, true) | (false, false) => return Err(EditError::NoChange),
                (false, true) => {
                    next.policy.denied_brands.retain(|r| &r.brand_id != id);
                    next.policy.allowed_brands.push(BrandRule {
                        brand_id: id.clone(),
                        enabled: true,
                        note: None,
                    });
                }
                (true, false) => next.policy.allowed_brands.retain(|r| &r.brand_id != id),
            }
            id.clone()
        }
        PolicyEdit::SetDenied { id, denied } => {
            if !next.catalog.brands.iter().any(|b| &b.id == id) {
                return Err(EditError::NotFound { id: id.clone() });
            }
            let present = next.policy.denied_brands.iter().any(|r| &r.brand_id == id);
            match (present, *denied) {
                (true, true) | (false, false) => return Err(EditError::NoChange),
                (false, true) => {
                    next.policy.allowed_brands.retain(|r| &r.brand_id != id);
                    next.policy.denied_brands.push(BrandRule {
                        brand_id: id.clone(),
                        enabled: true,
                        note: None,
                    });
                }
                (true, false) => next.policy.denied_brands.retain(|r| &r.brand_id != id),
            }
            id.clone()
        }
        PolicyEdit::SetRuleEnabled { id, enabled } => {
            let rule = next
                .policy
                .allowed_brands
                .iter_mut()
                .find(|r| &r.brand_id == id)
                .ok_or_else(|| EditError::NotFound { id: id.clone() })?;
            if rule.enabled == *enabled {
                return Err(EditError::NoChange);
            }
            rule.enabled = *enabled;
            id.clone()
        }
        PolicyEdit::SetWorkstationId { workstation_id } => {
            let new = workstation_id.trim();
            if new == next.policy.workstation_id {
                return Err(EditError::NoChange);
            }
            new.clone_into(&mut next.policy.workstation_id);
            String::new()
        }
    };

    if catalog_changed {
        next.catalog.catalog_version = next_catalog_version(&current.catalog.catalog_version);
        next.policy.catalog_version = next.catalog.catalog_version.clone();
    }
    next.policy.policy_version = current.policy.policy_version.saturating_add(1);

    let validated = next.validate()?;
    let warnings = validated
        .catalog
        .warnings()
        .iter()
        .map(|w| w.detail.clone())
        .chain(validated.policy.warnings().iter().map(|w| w.detail.clone()))
        .collect();

    let before = snapshot_brand(current, &brand_id);
    let after = snapshot_brand(&next, &brand_id);
    let summary = match edit {
        PolicyEdit::AddManufacturer { allowed, .. } => format!(
            "manufacturer {brand_id:?} added{}",
            if *allowed { " and allowed" } else { "" }
        ),
        PolicyEdit::UpdateManufacturer { .. } => format!("manufacturer {brand_id:?} updated"),
        PolicyEdit::RemoveManufacturer { .. } => format!("manufacturer {brand_id:?} removed"),
        PolicyEdit::SetAllowed { allowed, .. } => format!(
            "manufacturer {brand_id:?} {} the allowlist",
            if *allowed { "added to" } else { "removed from" }
        ),
        PolicyEdit::SetDenied { denied, .. } => format!(
            "manufacturer {brand_id:?} {} the denylist",
            if *denied { "added to" } else { "removed from" }
        ),
        PolicyEdit::SetRuleEnabled { enabled, .. } => format!(
            "allowlist rule for {brand_id:?} {}",
            if *enabled { "enabled" } else { "disabled" }
        ),
        PolicyEdit::SetWorkstationId { .. } => format!(
            "workstation id changed from {:?} to {:?}",
            current.policy.workstation_id, next.policy.workstation_id
        ),
    };
    let change = ChangeRecord {
        action: edit.action().to_owned(),
        brand_id,
        summary,
        from_policy_version: current.policy.policy_version,
        to_policy_version: next.policy.policy_version,
        from_catalog_version: current.catalog.catalog_version.clone(),
        to_catalog_version: next.catalog.catalog_version.clone(),
        before,
        after,
    };
    Ok(EditOutcome {
        state: next,
        validated,
        change,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Verification;
    use crate::policy::PolicyMode;

    const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
    const POLICY: &str = include_str!("../../../config/policy.example.json");

    fn state() -> PolicyState {
        PolicyState {
            catalog: serde_json::from_str(CATALOG).unwrap(),
            policy: serde_json::from_str(POLICY).unwrap(),
        }
    }

    fn inquiry(v: &str) -> BrandIdentifier {
        BrandIdentifier {
            kind: IdentifierKind::InquiryVendor,
            value: v.into(),
            verification: Verification::Unverified,
            source: "test".into(),
        }
    }

    fn input(name: &str, idents: Vec<BrandIdentifier>) -> ManufacturerInput {
        ManufacturerInput {
            id: None,
            display_name: name.into(),
            aliases: vec![],
            identifiers: idents,
            notes: None,
        }
    }

    #[test]
    fn denylist_edits_are_exclusive_with_the_allowlist() {
        let mut base = state();
        // The shipped example already denies Kingston and Seagate.
        assert_eq!(base.policy.denied_brands.len(), 2);
        base.policy.denied_brands.clear();
        // Deny Kingston: recorded, audited, versioned.
        let out = apply_edit(
            &base,
            &PolicyEdit::SetDenied {
                id: "kingston".into(),
                denied: true,
            },
        )
        .unwrap();
        assert!(out.validated.policy.brand_denied("kingston"));
        assert_eq!(out.change.action, "denylist_changed");
        assert!(out.change.after.as_ref().unwrap().denied);
        assert_eq!(
            out.state.policy.policy_version,
            base.policy.policy_version + 1
        );
        // Denying an allowed brand removes the allow rule.
        let out2 = apply_edit(
            &out.state,
            &PolicyEdit::SetDenied {
                id: "sandisk".into(),
                denied: true,
            },
        )
        .unwrap();
        assert!(!out2.validated.policy.brand_allowed("sandisk"));
        assert!(out2.validated.policy.brand_denied("sandisk"));
        // Allowing it again removes the deny rule.
        let out3 = apply_edit(
            &out2.state,
            &PolicyEdit::SetAllowed {
                id: "sandisk".into(),
                allowed: true,
            },
        )
        .unwrap();
        assert!(out3.validated.policy.brand_allowed("sandisk"));
        assert!(!out3.validated.policy.brand_denied("sandisk"));
        // No-ops and unknown brands are rejected.
        assert_eq!(
            apply_edit(
                &out3.state,
                &PolicyEdit::SetDenied {
                    id: "kingston".into(),
                    denied: true
                }
            )
            .unwrap_err(),
            EditError::NoChange
        );
        assert!(matches!(
            apply_edit(
                &base,
                &PolicyEdit::SetDenied {
                    id: "nope".into(),
                    denied: true
                }
            ),
            Err(EditError::NotFound { .. })
        ));
        // Removing a manufacturer also drops its deny rule.
        let out4 = apply_edit(
            &out3.state,
            &PolicyEdit::RemoveManufacturer {
                id: "kingston".into(),
            },
        )
        .unwrap();
        assert!(out4.state.policy.denied_brands.is_empty());
    }

    #[test]
    fn workstation_id_edit_is_versioned_validated_and_audited() {
        let base = state();
        let out = apply_edit(
            &base,
            &PolicyEdit::SetWorkstationId {
                workstation_id: " PC-03 ".into(),
            },
        )
        .unwrap();
        assert_eq!(out.state.policy.workstation_id, "PC-03");
        assert_eq!(
            out.state.policy.policy_version,
            base.policy.policy_version + 1
        );
        assert_eq!(out.state.catalog, base.catalog, "catalog untouched");
        assert_eq!(out.change.action, "workstation_id_changed");
        assert_eq!(out.change.brand_id, "");
        assert!(
            out.change.summary.contains("\"PC-01\"") && out.change.summary.contains("\"PC-03\"")
        );
        assert_eq!(
            apply_edit(
                &out.state,
                &PolicyEdit::SetWorkstationId {
                    workstation_id: "PC-03".into()
                }
            )
            .unwrap_err(),
            EditError::NoChange
        );
        for bad in ["", "PC 03", "PC/03", "İSTASYON", &"x".repeat(65)] {
            assert!(
                matches!(
                    apply_edit(
                        &base,
                        &PolicyEdit::SetWorkstationId {
                            workstation_id: bad.into()
                        }
                    ),
                    Err(EditError::Validation { .. })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn shipped_state_validates() {
        assert!(state().validate().is_ok());
    }

    #[test]
    fn add_allowed_manufacturer_bumps_versions_and_records_change() {
        let s = state();
        let out = apply_edit(
            &s,
            &PolicyEdit::AddManufacturer {
                input: input("Western Digital", vec![inquiry("WD")]),
                allowed: true,
            },
        )
        .unwrap();
        assert_eq!(out.change.brand_id, "western-digital");
        assert_eq!(out.state.policy.policy_version, 2);
        assert_eq!(
            out.state.catalog.catalog_version,
            "2026.11.07-phase6+local.1"
        );
        assert_eq!(
            out.state.policy.catalog_version,
            out.state.catalog.catalog_version
        );
        assert!(out.validated.policy.brand_allowed("western-digital"));
        assert!(out.change.before.is_none());
        assert!(out.change.after.as_ref().unwrap().allowed);
        assert_eq!(s.policy.policy_version, 1, "input state untouched");
    }

    #[test]
    fn duplicates_and_name_conflicts_are_rejected() {
        let s = state();
        let dup = apply_edit(
            &s,
            &PolicyEdit::AddManufacturer {
                input: ManufacturerInput {
                    id: Some("sandisk".into()),
                    ..input("Something", vec![])
                },
                allowed: false,
            },
        );
        assert!(matches!(dup, Err(EditError::DuplicateId { .. })));

        // "Tübitak Bilgem" normalizes to the existing TÜBİTAK BİLGEM display name.
        let conflict = apply_edit(
            &s,
            &PolicyEdit::AddManufacturer {
                input: ManufacturerInput {
                    id: Some("tb2".into()),
                    ..input("Tübitak Bilgem", vec![])
                },
                allowed: true,
            },
        );
        assert!(
            matches!(conflict, Err(EditError::NameConflict { other_id, .. }) if other_id == "tubitak")
        );

        let alias_conflict = apply_edit(
            &s,
            &PolicyEdit::AddManufacturer {
                input: ManufacturerInput {
                    aliases: vec!["sandisk corp".into()],
                    ..input("Acme", vec![])
                },
                allowed: false,
            },
        );
        assert!(matches!(
            alias_conflict,
            Err(EditError::NameConflict { .. })
        ));
    }

    #[test]
    fn conflicting_identifier_is_rejected_by_validation() {
        let s = state();
        let r = apply_edit(
            &s,
            &PolicyEdit::AddManufacturer {
                input: input("Clone Maker", vec![inquiry("sandisk")]),
                allowed: false,
            },
        );
        match r {
            Err(EditError::Validation { issues }) => {
                assert!(
                    issues
                        .iter()
                        .any(|i| i.contains("inquiry_vendor_ambiguous"))
                );
            }
            other => panic!("expected validation error, got {other:?}"),
        }
        let generic = apply_edit(
            &s,
            &PolicyEdit::AddManufacturer {
                input: input("Some Brand", vec![inquiry("Generic")]),
                allowed: false,
            },
        );
        assert!(matches!(generic, Err(EditError::Validation { .. })));
    }

    #[test]
    fn invalid_input_is_rejected() {
        let s = state();
        for bad in [
            input("", vec![]),
            input("   ", vec![]),
            input("Bad\u{7}Name", vec![]),
            input(&"x".repeat(MAX_TEXT_LEN + 1), vec![]),
            input("Dup Ident", vec![inquiry("ACME"), inquiry("acme")]),
        ] {
            assert!(
                apply_edit(
                    &s,
                    &PolicyEdit::AddManufacturer {
                        input: bad.clone(),
                        allowed: false
                    }
                )
                .is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn update_remove_allow_and_enable_flow() {
        let s = state();
        let upd = apply_edit(
            &s,
            &PolicyEdit::UpdateManufacturer {
                id: "kingston".into(),
                input: ManufacturerInput {
                    aliases: vec!["Kingston Technology".into(), "KINGSTON TECHNOLOGY".into()],
                    ..input("Kingston", vec![inquiry("Kingston")])
                },
            },
        )
        .unwrap();
        let k = upd
            .state
            .catalog
            .brands
            .iter()
            .find(|b| b.id == "kingston")
            .unwrap();
        assert_eq!(k.aliases.len(), 1, "normalized duplicate aliases collapse");

        let allowed = apply_edit(
            &upd.state,
            &PolicyEdit::SetAllowed {
                id: "kingston".into(),
                allowed: true,
            },
        )
        .unwrap();
        assert!(allowed.validated.policy.brand_allowed("kingston"));
        assert_eq!(
            allowed.state.catalog.catalog_version, upd.state.catalog.catalog_version,
            "allowlist change keeps catalog version"
        );

        let disabled = apply_edit(
            &allowed.state,
            &PolicyEdit::SetRuleEnabled {
                id: "kingston".into(),
                enabled: false,
            },
        )
        .unwrap();
        assert!(!disabled.validated.policy.brand_allowed("kingston"));
        assert!(matches!(
            apply_edit(
                &disabled.state,
                &PolicyEdit::SetRuleEnabled {
                    id: "kingston".into(),
                    enabled: false
                }
            ),
            Err(EditError::NoChange)
        ));

        let removed = apply_edit(
            &disabled.state,
            &PolicyEdit::RemoveManufacturer {
                id: "kingston".into(),
            },
        )
        .unwrap();
        assert!(
            removed
                .state
                .catalog
                .brands
                .iter()
                .all(|b| b.id != "kingston")
        );
        assert!(
            removed
                .state
                .policy
                .allowed_brands
                .iter()
                .all(|r| r.brand_id != "kingston")
        );
        assert_eq!(removed.state.policy.policy_version, 5);
        assert!(matches!(
            apply_edit(
                &removed.state,
                &PolicyEdit::RemoveManufacturer {
                    id: "kingston".into()
                }
            ),
            Err(EditError::NotFound { .. })
        ));
    }

    #[test]
    fn id_cannot_change_on_update_and_no_op_is_rejected() {
        let s = state();
        let sandisk = s
            .catalog
            .brands
            .iter()
            .find(|b| b.id == "sandisk")
            .unwrap()
            .clone();
        let same = ManufacturerInput {
            id: None,
            display_name: sandisk.display_name.clone(),
            aliases: sandisk.aliases.clone(),
            identifiers: sandisk.identifiers.clone(),
            notes: sandisk.notes.clone(),
        };
        assert!(matches!(
            apply_edit(
                &s,
                &PolicyEdit::UpdateManufacturer {
                    id: "sandisk".into(),
                    input: same.clone()
                }
            ),
            Err(EditError::NoChange)
        ));
        let renamed = ManufacturerInput {
            id: Some("other".into()),
            ..same
        };
        assert!(matches!(
            apply_edit(
                &s,
                &PolicyEdit::UpdateManufacturer {
                    id: "sandisk".into(),
                    input: renamed
                }
            ),
            Err(EditError::InvalidInput { .. })
        ));
    }

    #[test]
    fn enforce_mode_rejects_edits_that_leave_unverified_identifiers() {
        let mut s = state();
        s.policy.mode = PolicyMode::Enforce;
        // The shipped catalog has no lab-verified identifiers, so any edit of
        // an enforce-mode policy fails validation instead of silently passing.
        let r = apply_edit(
            &s,
            &PolicyEdit::SetRuleEnabled {
                id: "sandisk".into(),
                enabled: false,
            },
        );
        assert!(matches!(r, Err(EditError::Validation { .. })));
    }

    #[test]
    fn catalog_version_sequence() {
        assert_eq!(next_catalog_version("v1"), "v1+local.1");
        assert_eq!(next_catalog_version("v1+local.9"), "v1+local.10");
    }
}
