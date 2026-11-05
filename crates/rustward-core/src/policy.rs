//! Per-workstation brand allowlist policy.
//!
//! The default decision is always **deny**; it is not configurable. A
//! policy can only *add* brands to the allowlist.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::catalog::{Severity, ValidatedCatalog, Verification};

/// Current policy schema version.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Operating mode of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Decisions are computed and reported but nothing is enforced.
    DryRun,
    /// Intended for enforcement. Requires lab-verified identifiers. No
    /// enforcement provider exists yet (Phase 2), so this mode only
    /// tightens validation today.
    Enforce,
}

/// One brand allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandRule {
    /// Catalog brand id.
    pub brand_id: String,
    /// Disabled rules are kept for history but grant nothing.
    pub enabled: bool,
    /// Administrator note.
    #[serde(default)]
    pub note: Option<String>,
}

/// The policy file for one workstation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkstationPolicy {
    /// Schema version, currently [`POLICY_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Workstation identifier, e.g. `PC-01`.
    pub workstation_id: String,
    /// Monotonic policy version.
    pub policy_version: u64,
    /// Mode.
    pub mode: PolicyMode,
    /// Catalog version this policy was written against.
    pub catalog_version: String,
    /// Allowed brands.
    pub allowed_brands: Vec<BrandRule>,
}

/// A policy validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIssue {
    /// Severity.
    pub severity: Severity,
    /// Stable code.
    pub code: &'static str,
    /// Detail.
    pub detail: String,
}

/// Policy rejected.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// JSON error.
    #[error("policy JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    /// Validation errors.
    #[error("policy failed validation with {} error(s)", .0.iter().filter(|i| i.severity == Severity::Error).count())]
    Invalid(Vec<PolicyIssue>),
}

/// A policy validated against a specific catalog.
#[derive(Debug, Clone)]
pub struct ValidatedPolicy {
    policy: WorkstationPolicy,
    warnings: Vec<PolicyIssue>,
}

fn valid_workstation_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl ValidatedPolicy {
    /// Parse and validate.
    pub fn from_json(json: &str, catalog: &ValidatedCatalog) -> Result<Self, PolicyError> {
        let policy: WorkstationPolicy = serde_json::from_str(json)?;
        Self::validate(policy, catalog)
    }

    /// Validate a policy against a catalog.
    pub fn validate(
        policy: WorkstationPolicy,
        catalog: &ValidatedCatalog,
    ) -> Result<Self, PolicyError> {
        let mut issues = Vec::new();
        let mut warnings = Vec::new();
        let mut err = |code, detail| {
            issues.push(PolicyIssue {
                severity: Severity::Error,
                code,
                detail,
            });
        };

        if policy.schema_version != POLICY_SCHEMA_VERSION {
            err(
                "schema_version",
                format!("unsupported policy schema {}", policy.schema_version),
            );
        }
        if !valid_workstation_id(&policy.workstation_id) {
            err(
                "workstation_id",
                format!(
                    "workstation id {:?} must match [A-Za-z0-9_-]{{1,64}}",
                    policy.workstation_id
                ),
            );
        }
        if policy.policy_version == 0 {
            err("policy_version", "policy_version must be >= 1".into());
        }
        if policy.catalog_version != catalog.catalog().catalog_version {
            err(
                "catalog_version_mismatch",
                format!(
                    "policy targets catalog {:?} but catalog {:?} is loaded",
                    policy.catalog_version,
                    catalog.catalog().catalog_version
                ),
            );
        }

        let mut seen = HashSet::new();
        for rule in &policy.allowed_brands {
            if !seen.insert(rule.brand_id.as_str()) {
                err(
                    "brand_rule_duplicate",
                    format!("brand {:?} listed more than once", rule.brand_id),
                );
            }
            let Some(brand) = catalog.brand(&rule.brand_id) else {
                err(
                    "brand_unknown",
                    format!("brand {:?} is not in the catalog", rule.brand_id),
                );
                continue;
            };
            if !rule.enabled {
                continue;
            }
            let enforceable: Vec<_> = brand.enforceable_identifiers().collect();
            if enforceable.is_empty() {
                let detail = format!(
                    "allowed brand {:?} has no enforceable identifier in catalog {:?}; every device of this brand will be denied until a controlled catalog update adds one",
                    brand.id,
                    catalog.catalog().catalog_version
                );
                match policy.mode {
                    PolicyMode::Enforce => err("brand_not_enforceable", detail),
                    PolicyMode::DryRun => warnings.push(PolicyIssue {
                        severity: Severity::Warning,
                        code: "brand_not_enforceable",
                        detail,
                    }),
                }
                continue;
            }
            let unverified: Vec<_> = enforceable
                .iter()
                .filter(|i| i.verification != Verification::LabVerified)
                .map(|i| i.value.clone())
                .collect();
            if !unverified.is_empty() {
                let detail = format!(
                    "brand {:?}: identifiers {unverified:?} are not lab-verified",
                    brand.id
                );
                match policy.mode {
                    PolicyMode::Enforce => err("identifier_unverified", detail),
                    PolicyMode::DryRun => warnings.push(PolicyIssue {
                        severity: Severity::Warning,
                        code: "identifier_unverified",
                        detail,
                    }),
                }
            }
        }

        if issues.is_empty() {
            Ok(Self { policy, warnings })
        } else {
            issues.extend(warnings);
            Err(PolicyError::Invalid(issues))
        }
    }

    /// The policy.
    #[must_use]
    pub fn policy(&self) -> &WorkstationPolicy {
        &self.policy
    }

    /// Non-blocking findings.
    #[must_use]
    pub fn warnings(&self) -> &[PolicyIssue] {
        &self.warnings
    }

    /// Whether a brand is allowed and enabled.
    #[must_use]
    pub fn brand_allowed(&self, brand_id: &str) -> bool {
        self.policy
            .allowed_brands
            .iter()
            .any(|r| r.enabled && r.brand_id == brand_id)
    }

    /// Enabled brand ids.
    pub fn enabled_brands(&self) -> impl Iterator<Item = &str> {
        self.policy
            .allowed_brands
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.brand_id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{
        BrandEntry, BrandIdentifier, IdentifierKind, ManufacturerCatalog, ValidatedCatalog,
    };

    fn catalog(verification: Verification) -> ValidatedCatalog {
        ValidatedCatalog::validate(ManufacturerCatalog {
            schema_version: 1,
            catalog_version: "c1".into(),
            brands: vec![
                BrandEntry {
                    id: "sandisk".into(),
                    display_name: "SanDisk".into(),
                    aliases: vec![],
                    identifiers: vec![BrandIdentifier {
                        kind: IdentifierKind::InquiryVendor,
                        value: "SanDisk".into(),
                        verification,
                        source: "t".into(),
                    }],
                    notes: None,
                },
                BrandEntry {
                    id: "tubitak".into(),
                    display_name: "TÜBİTAK".into(),
                    aliases: vec![],
                    identifiers: vec![],
                    notes: None,
                },
            ],
            reserved_generic_vendors: vec![],
        })
        .unwrap()
    }

    fn policy(mode: PolicyMode, brands: &[(&str, bool)]) -> WorkstationPolicy {
        WorkstationPolicy {
            schema_version: 1,
            workstation_id: "PC-01".into(),
            policy_version: 1,
            mode,
            catalog_version: "c1".into(),
            allowed_brands: brands
                .iter()
                .map(|(b, e)| BrandRule {
                    brand_id: (*b).into(),
                    enabled: *e,
                    note: None,
                })
                .collect(),
        }
    }

    fn error_codes(e: PolicyError) -> Vec<&'static str> {
        match e {
            PolicyError::Invalid(v) => v
                .into_iter()
                .filter(|i| i.severity == Severity::Error)
                .map(|i| i.code)
                .collect(),
            PolicyError::Json(_) => vec!["json"],
        }
    }

    #[test]
    fn dry_run_accepts_unverified_and_unenforceable_with_warnings() {
        let p = ValidatedPolicy::validate(
            policy(PolicyMode::DryRun, &[("sandisk", true), ("tubitak", true)]),
            &catalog(Verification::PublicRegistry),
        )
        .unwrap();
        let codes: Vec<_> = p.warnings().iter().map(|w| w.code).collect();
        assert!(codes.contains(&"identifier_unverified"));
        assert!(codes.contains(&"brand_not_enforceable"));
        assert!(p.brand_allowed("sandisk"));
    }

    #[test]
    fn enforce_mode_requires_lab_verified_enforceable_identifiers() {
        let e = ValidatedPolicy::validate(
            policy(PolicyMode::Enforce, &[("sandisk", true), ("tubitak", true)]),
            &catalog(Verification::PublicRegistry),
        )
        .unwrap_err();
        let c = error_codes(e);
        assert!(c.contains(&"identifier_unverified"));
        assert!(c.contains(&"brand_not_enforceable"));

        let ok = ValidatedPolicy::validate(
            policy(PolicyMode::Enforce, &[("sandisk", true)]),
            &catalog(Verification::LabVerified),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn disabled_rules_grant_nothing() {
        let p = ValidatedPolicy::validate(
            policy(PolicyMode::DryRun, &[("sandisk", false)]),
            &catalog(Verification::LabVerified),
        )
        .unwrap();
        assert!(!p.brand_allowed("sandisk"));
        assert_eq!(p.enabled_brands().count(), 0);
    }

    #[test]
    fn rejects_unknown_duplicate_and_mismatched_catalog() {
        let mut pol = policy(
            PolicyMode::DryRun,
            &[("kingston", true), ("sandisk", true), ("sandisk", true)],
        );
        pol.catalog_version = "other".into();
        pol.workstation_id = "PC 01".into();
        pol.policy_version = 0;
        let c = error_codes(
            ValidatedPolicy::validate(pol, &catalog(Verification::LabVerified)).unwrap_err(),
        );
        for code in [
            "brand_unknown",
            "brand_rule_duplicate",
            "catalog_version_mismatch",
            "workstation_id",
            "policy_version",
        ] {
            assert!(c.contains(&code), "missing {code}");
        }
    }
}
