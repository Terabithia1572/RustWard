//! Diagnostic reports: raw (keep local) and sanitized (shareable for review).
//!
//! Every report and every entry states `enforcement: "NOT ACTIVE"` and
//! labels decisions as `SIMULATED_*`. There is no field or rendering path
//! that can express "blocked".
//!
//! Sanitization:
//! - the unique tail of every instance ID (serial number or bus-generated
//!   instance path) is replaced with a stable pseudonym (`ID-001`), so the
//!   device tree stays navigable but no serial survives;
//! - the computer name is removed; the timestamp is reduced to a UTC date;
//! - friendly/bus-reported names of portable devices (phones may carry a
//!   person's name) are removed;
//! - inventory read warnings (which embed instance IDs) are reduced to a count.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::catalog::ValidatedCatalog;
use crate::classify::{DeviceCategory, StorageScope};
use crate::device::{DeviceSnapshot, SnapshotSource};
use crate::evaluate::{Decision, DecisionReason, Evidence, Verdict, evaluate_snapshot};
use crate::plan::{check_consistency, compile_plan};
use crate::policy::ValidatedPolicy;
use crate::policy_edit::combined_warnings;

/// The only enforcement state a Phase 1 report can carry.
pub const ENFORCEMENT_NOT_ACTIVE: &str = "NOT ACTIVE";

/// Notice repeated at the top and bottom of every rendering.
pub const NOTICE: &str = "ENFORCEMENT: NOT ACTIVE. Every decision in this report is a SIMULATION computed from device metadata. RustWard does not block, restrict or protect anything on this computer.";

/// Simulated decision, named so it cannot be read as an enforcement result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SimulatedDecision {
    /// The policy would allow this device.
    SimulatedAllow,
    /// The policy would deny this device.
    SimulatedDeny,
    /// Not subject to the storage policy.
    NotApplicable,
}

impl From<Verdict> for SimulatedDecision {
    fn from(v: Verdict) -> Self {
        match v {
            Verdict::Allow => Self::SimulatedAllow,
            Verdict::Deny => Self::SimulatedDeny,
            Verdict::NotApplicable => Self::NotApplicable,
        }
    }
}

/// Manufacturer-matching stage outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ManufacturerMatch {
    /// Vendor-level ID matched a catalog brand.
    Matched {
        /// Brand id.
        brand_id: String,
    },
    /// INQUIRY vendor conflicts with USB VID manufacturer.
    ConflictingIdentifiers {
        /// INQUIRY brand id.
        inquiry_brand: String,
        /// Hex USB VID.
        usb_vid: String,
        /// Catalog brand(s) owning `usb_vid`.
        vid_brands: Vec<String>,
    },
    /// INQUIRY vendor not in the catalog.
    NotInCatalog {
        /// Vendor as displayed.
        vendor: String,
    },
    /// Reserved generic vendor.
    GenericVendor {
        /// Vendor as displayed.
        vendor: String,
    },
    /// No vendor-level hardware ID available.
    NoEnforceableIdentity,
    /// Matching not performed (not in scope / scope pending).
    NotEvaluated,
}

impl From<&DecisionReason> for ManufacturerMatch {
    fn from(r: &DecisionReason) -> Self {
        match r {
            DecisionReason::BrandAllowed { brand_id }
            | DecisionReason::BrandDenied { brand_id }
            | DecisionReason::BrandNotAllowed { brand_id } => Self::Matched {
                brand_id: brand_id.clone(),
            },
            DecisionReason::ConflictingIdentifiers {
                inquiry_brand,
                usb_vid,
                vid_brands,
            } => Self::ConflictingIdentifiers {
                inquiry_brand: inquiry_brand.clone(),
                usb_vid: usb_vid.clone(),
                vid_brands: vid_brands.clone(),
            },
            DecisionReason::UnknownManufacturer { vendor } => Self::NotInCatalog {
                vendor: vendor.clone(),
            },
            DecisionReason::GenericVendorIdentity { vendor } => Self::GenericVendor {
                vendor: vendor.clone(),
            },
            DecisionReason::MissingEnforceableIdentity => Self::NoEnforceableIdentity,
            DecisionReason::ScopeDecisionPending | DecisionReason::NotInScope => Self::NotEvaluated,
        }
    }
}

/// One device in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportEntry {
    /// Instance ID (pseudonymized tail when sanitized).
    pub device: String,
    /// Parent instance ID (same pseudonymization).
    pub parent: Option<String>,
    /// Present / previously installed.
    pub present: Option<bool>,
    /// Stage 1: detected (always true for listed entries).
    pub detected: bool,
    /// Stage 2: classification.
    pub classified: DeviceCategory,
    /// Nearest USB VID:PID.
    pub usb_vid_pid: Option<String>,
    /// Vendor-level hardware ID used for matching.
    pub vendor_level_id: Option<String>,
    /// Stage 3: manufacturer matching.
    pub manufacturer_match: ManufacturerMatch,
    /// Stage 4: simulated policy decision.
    pub simulated_decision: SimulatedDecision,
    /// Stage 5: always [`ENFORCEMENT_NOT_ACTIVE`].
    pub enforcement: String,
    /// Decision reason.
    pub reason: DecisionReason,
    /// Setup class name.
    pub class_name: Option<String>,
    /// Service.
    pub service: Option<String>,
    /// INF manufacturer string (not a brand identity).
    pub inf_manufacturer: Option<String>,
    /// Friendly name (removed for portable devices when sanitized).
    pub friendly_name: Option<String>,
    /// Hardware IDs.
    pub hardware_ids: Vec<String>,
    /// Compatible IDs.
    pub compatible_ids: Vec<String>,
    /// Evidence.
    pub evidence: Vec<Evidence>,
}

/// Report provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSource {
    /// `live` or `synthetic`.
    pub kind: String,
    /// Computer name (raw only).
    pub computer_name: Option<String>,
    /// Collection date (UTC, YYYY-MM-DD).
    pub collected_utc_date: Option<String>,
    /// Whether previously installed devices were enumerated.
    pub includes_non_present: bool,
    /// Synthetic description.
    pub description: Option<String>,
}

/// Counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// All devnodes in the snapshot.
    pub devices_total: usize,
    /// Devnodes listed in the report.
    pub devices_listed: usize,
    /// Non-present devnodes in the snapshot.
    pub non_present: usize,
    /// In-scope storage.
    pub storage_in_scope: usize,
    /// Storage with a pending scope decision.
    pub storage_scope_pending: usize,
    /// Peripherals.
    pub peripherals: usize,
    /// System / non-USB storage.
    pub system_storage: usize,
    /// Simulated allow.
    pub simulated_allow: usize,
    /// Simulated deny.
    pub simulated_deny: usize,
    /// Engine denies but modelled OS rules would not.
    pub enforcement_gaps: usize,
    /// Modelled OS rules would block something the engine does not deny.
    pub over_blocking: usize,
    /// Inventory read warnings.
    pub read_warnings: usize,
}

/// A diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Always [`ENFORCEMENT_NOT_ACTIVE`].
    pub enforcement: String,
    /// [`NOTICE`].
    pub notice: String,
    /// Sanitized for sharing.
    pub sanitized: bool,
    /// Provenance.
    pub source: ReportSource,
    /// Workstation id from the policy.
    pub workstation_policy: String,
    /// Policy version.
    pub policy_version: u64,
    /// Catalog version.
    pub catalog_version: String,
    /// Counts.
    pub summary: ReportSummary,
    /// Catalog/policy warnings (no device data).
    pub configuration_warnings: Vec<String>,
    /// Inventory read warnings (raw only).
    pub read_warnings: Vec<String>,
    /// `kind: device` consistency findings.
    pub consistency_findings: Vec<String>,
    /// Devices.
    pub entries: Vec<ReportEntry>,
}

/// Replaces instance-ID tails with stable pseudonyms.
#[derive(Debug, Default)]
pub struct Pseudonymizer {
    map: HashMap<String, String>,
}

impl Pseudonymizer {
    /// Pseudonymize the last `\`-separated segment of an instance ID.
    pub fn instance_id(&mut self, id: &str) -> String {
        let (head, tail) = match id.rfind('\\') {
            Some(i) => (&id[..i], &id[i + 1..]),
            None => ("", id),
        };
        let next = self.map.len() + 1;
        let alias = self
            .map
            .entry(tail.to_ascii_uppercase())
            .or_insert_with(|| format!("ID-{next:03}"))
            .clone();
        if head.is_empty() {
            alias
        } else {
            format!("{head}\\{alias}")
        }
    }
}

/// Convert Unix seconds to a UTC `YYYY-MM-DD` date (proleptic Gregorian).
#[must_use]
pub fn utc_date(unix_seconds: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let days = i64::try_from(unix_seconds / 86_400).unwrap_or(0);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn listed(category: &DeviceCategory) -> bool {
    !matches!(category, DeviceCategory::Other)
}

/// Build a report from a snapshot.
#[must_use]
pub fn build_report(
    snapshot: &DeviceSnapshot,
    read_warnings: &[String],
    policy: &ValidatedPolicy,
    catalog: &ValidatedCatalog,
    sanitize: bool,
) -> DiagnosticReport {
    let decisions: Vec<Decision> = evaluate_snapshot(snapshot, policy, catalog);
    let plan = compile_plan(policy, catalog, Some(snapshot));
    let findings = check_consistency(&plan, snapshot, &decisions);
    let index = snapshot.index();
    let mut pseudo = Pseudonymizer::default();
    let mut id = |s: &str| {
        if sanitize {
            pseudo.instance_id(s)
        } else {
            s.to_owned()
        }
    };

    let mut summary = ReportSummary {
        devices_total: snapshot.devices.len(),
        non_present: snapshot
            .devices
            .iter()
            .filter(|d| d.present == Some(false))
            .count(),
        read_warnings: read_warnings.len(),
        enforcement_gaps: findings
            .iter()
            .filter(|f| f.kind == "enforcement_gap")
            .count(),
        over_blocking: findings
            .iter()
            .filter(|f| f.kind == "over_blocking")
            .count(),
        ..ReportSummary::default()
    };

    let mut entries = Vec::new();
    for dec in &decisions {
        let cat = &dec.classification.category;
        match cat.scope() {
            StorageScope::InScope => summary.storage_in_scope += 1,
            StorageScope::ScopeDecisionPending => summary.storage_scope_pending += 1,
            StorageScope::NotInScope => {}
        }
        match cat {
            DeviceCategory::Peripheral { .. } => summary.peripherals += 1,
            DeviceCategory::SystemOrNonUsbStorage => summary.system_storage += 1,
            _ => {}
        }
        match dec.verdict {
            Verdict::Allow => summary.simulated_allow += 1,
            Verdict::Deny => summary.simulated_deny += 1,
            Verdict::NotApplicable => {}
        }
        if !listed(cat) {
            continue;
        }
        let Some(dev) = index.get(&dec.instance_id) else {
            continue;
        };
        let personal_name = matches!(cat, DeviceCategory::UsbPortableDevice);
        entries.push(ReportEntry {
            device: id(&dec.instance_id),
            parent: dev.parent_instance_id.as_deref().map(&mut id),
            present: dev.present,
            detected: true,
            classified: cat.clone(),
            usb_vid_pid: dec
                .classification
                .usb_ancestor
                .as_ref()
                .map(|u| format!("{:04X}:{:04X}", u.ids.vid, u.ids.pid)),
            vendor_level_id: dec
                .classification
                .inquiry
                .as_ref()
                .map(|i| i.vendor_level_id.clone()),
            manufacturer_match: ManufacturerMatch::from(&dec.reason),
            simulated_decision: dec.verdict.into(),
            enforcement: ENFORCEMENT_NOT_ACTIVE.to_owned(),
            reason: dec.reason.clone(),
            class_name: dev.class_name.clone(),
            service: dev.service.clone(),
            inf_manufacturer: dev.inf_manufacturer.clone(),
            friendly_name: if sanitize && personal_name {
                None
            } else {
                dev.friendly_name.clone()
            },
            hardware_ids: dev.hardware_ids.clone(),
            compatible_ids: dev.compatible_ids.clone(),
            evidence: if sanitize && personal_name {
                dec.evidence
                    .iter()
                    .filter(|e| {
                        e.source != "friendly_name" && e.source != "bus_reported_description"
                    })
                    .cloned()
                    .collect()
            } else {
                dec.evidence.clone()
            },
        });
    }
    summary.devices_listed = entries.len();

    let consistency_findings = findings
        .iter()
        .map(|f| {
            format!(
                "{}: {} (simulated {:?}, modelled {:?})",
                f.kind,
                id(&f.instance_id),
                f.verdict,
                f.model
            )
        })
        .collect();

    let source = match &snapshot.source {
        SnapshotSource::Live {
            computer_name,
            collected_unix_seconds,
            includes_non_present,
        } => ReportSource {
            kind: "live".into(),
            computer_name: if sanitize {
                None
            } else {
                computer_name.clone()
            },
            collected_utc_date: Some(utc_date(*collected_unix_seconds)),
            includes_non_present: *includes_non_present,
            description: None,
        },
        SnapshotSource::Synthetic { description } => ReportSource {
            kind: "synthetic".into(),
            computer_name: None,
            collected_utc_date: None,
            includes_non_present: true,
            description: Some(description.clone()),
        },
    };

    DiagnosticReport {
        enforcement: ENFORCEMENT_NOT_ACTIVE.to_owned(),
        notice: NOTICE.to_owned(),
        sanitized: sanitize,
        source,
        workstation_policy: policy.policy().workstation_id.clone(),
        policy_version: policy.policy().policy_version,
        catalog_version: catalog.catalog().catalog_version.clone(),
        summary,
        configuration_warnings: combined_warnings(catalog, policy)
            .into_iter()
            .map(|(_, detail)| detail)
            .collect(),
        read_warnings: if sanitize {
            Vec::new()
        } else {
            read_warnings.to_vec()
        },
        consistency_findings,
        entries,
    }
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn category_label(c: &DeviceCategory) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| {
            let kind = v.get("kind")?.as_str()?.to_owned();
            let detail = v
                .as_object()?
                .iter()
                .filter(|(k, _)| *k != "kind")
                .filter_map(|(_, v)| v.as_str().map(str::to_owned))
                .collect::<Vec<_>>();
            Some(if detail.is_empty() {
                kind
            } else {
                format!("{kind} ({})", detail.join(", "))
            })
        })
        .unwrap_or_default()
}

fn match_label(m: &ManufacturerMatch) -> String {
    match m {
        ManufacturerMatch::Matched { brand_id } => format!("matched `{brand_id}`"),
        ManufacturerMatch::ConflictingIdentifiers {
            inquiry_brand,
            usb_vid,
            vid_brands,
        } => format!(
            "conflicting (`{inquiry_brand}` vs VID `{usb_vid}` -> `{}`)",
            vid_brands.join(",")
        ),
        ManufacturerMatch::NotInCatalog { vendor } => format!("not in catalog (`{vendor}`)"),
        ManufacturerMatch::GenericVendor { vendor } => format!("generic vendor (`{vendor}`)"),
        ManufacturerMatch::NoEnforceableIdentity => "no enforceable identity".into(),
        ManufacturerMatch::NotEvaluated => "not evaluated".into(),
    }
}

/// Render a report as Markdown.
#[must_use]
pub fn render_markdown(r: &DiagnosticReport) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let kind = if r.sanitized {
        "SANITIZED - suitable for external code review"
    } else {
        "RAW - contains serial numbers and machine data; keep local, do not share"
    };
    let _ = writeln!(o, "# RustWard Diagnostic Report ({kind})\n");
    let _ = writeln!(o, "> **{}**\n", r.notice);
    let _ = writeln!(
        o,
        "- Source: {} | date (UTC): {} | computer: {} | non-present devices enumerated: {}",
        r.source.kind,
        r.source.collected_utc_date.as_deref().unwrap_or("n/a"),
        r.source
            .computer_name
            .as_deref()
            .unwrap_or("(not included)"),
        r.source.includes_non_present
    );
    let _ = writeln!(
        o,
        "- Policy: {} v{} | catalog {} | enforcement: **{}**\n",
        r.workstation_policy, r.policy_version, r.catalog_version, r.enforcement
    );
    let s = &r.summary;
    let _ = writeln!(o, "## Summary\n\n| Metric | Count |\n|---|---|");
    for (k, v) in [
        ("Devnodes in snapshot", s.devices_total),
        ("Devnodes listed below", s.devices_listed),
        ("Non-present (previously installed) devnodes", s.non_present),
        ("Storage in policy scope", s.storage_in_scope),
        (
            "Storage with pending scope decision",
            s.storage_scope_pending,
        ),
        ("Peripherals (never targeted)", s.peripherals),
        ("System / non-USB storage (never touched)", s.system_storage),
        ("SIMULATED allow", s.simulated_allow),
        ("SIMULATED deny", s.simulated_deny),
        ("Enforcement gaps (model)", s.enforcement_gaps),
        ("Over-blocking findings (model)", s.over_blocking),
        ("Inventory read warnings", s.read_warnings),
    ] {
        let _ = writeln!(o, "| {k} | {v} |");
    }
    let _ = writeln!(
        o,
        "\n## Devices\n\n| Device | Present | Detected | Classified | Manufacturer match | Simulated decision | Enforcement |\n|---|---|---|---|---|---|---|"
    );
    for e in &r.entries {
        let _ = writeln!(
            o,
            "| `{}` | {} | yes | {} | {} | {:?} | {} |",
            cell(&e.device),
            match e.present {
                Some(true) => "yes",
                Some(false) => "no",
                None => "?",
            },
            cell(&category_label(&e.classified)),
            cell(&match_label(&e.manufacturer_match)),
            e.simulated_decision,
            e.enforcement
        );
    }
    let _ = writeln!(o, "\n## Storage details\n");
    for e in r
        .entries
        .iter()
        .filter(|e| e.classified.scope() != StorageScope::NotInScope)
    {
        let _ = writeln!(o, "### `{}`\n", cell(&e.device));
        let _ = writeln!(
            o,
            "- Friendly name: {}",
            e.friendly_name.as_deref().unwrap_or("(none)")
        );
        let _ = writeln!(
            o,
            "- USB VID:PID: {}",
            e.usb_vid_pid.as_deref().unwrap_or("(none)")
        );
        let _ = writeln!(
            o,
            "- Vendor-level ID: {}",
            e.vendor_level_id
                .as_deref()
                .map_or("(none)".into(), |v| format!("`{v}`"))
        );
        let _ = writeln!(
            o,
            "- INF manufacturer (not a brand identity): {}",
            e.inf_manufacturer.as_deref().unwrap_or("(none)")
        );
        let _ = writeln!(
            o,
            "- Hardware IDs: {}",
            e.hardware_ids
                .iter()
                .map(|h| format!("`{h}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = writeln!(
            o,
            "- Compatible IDs: {}",
            e.compatible_ids
                .iter()
                .map(|h| format!("`{h}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = writeln!(
            o,
            "- Simulated decision: **{:?}** - enforcement **{}**",
            e.simulated_decision, e.enforcement
        );
        for ev in &e.evidence {
            let _ = writeln!(o, "  - {:?} [{}]: {}", ev.kind, ev.source, cell(&ev.detail));
        }
        let _ = writeln!(o);
    }
    if !r.consistency_findings.is_empty() {
        let _ = writeln!(
            o,
            "## Decision engine vs. modelled Device Installation plan\n"
        );
        for f in &r.consistency_findings {
            let _ = writeln!(o, "- {}", cell(f));
        }
        let _ = writeln!(o);
    }
    if !r.configuration_warnings.is_empty() {
        let _ = writeln!(o, "## Configuration warnings\n");
        for w in &r.configuration_warnings {
            let _ = writeln!(o, "- {}", cell(w));
        }
        let _ = writeln!(o);
    }
    if !r.read_warnings.is_empty() {
        let _ = writeln!(o, "## Inventory read warnings\n");
        for w in &r.read_warnings {
            let _ = writeln!(o, "- {}", cell(w));
        }
        let _ = writeln!(o);
    }
    let _ = writeln!(o, "---\n\n> **{}**", r.notice);
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_date_conversion() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(951_782_400), "2000-02-29");
        assert_eq!(utc_date(1_793_836_800), "2026-11-05");
    }

    #[test]
    fn pseudonyms_are_stable_and_hide_tails() {
        let mut p = Pseudonymizer::default();
        let a = p.instance_id("USB\\VID_0781&PID_5581\\4C530001230615110223");
        let b = p.instance_id("USBSTOR\\Disk&Ven_SanDisk\\4C530001230615110223&0");
        let a2 = p.instance_id("usb\\vid_0781&pid_5581\\4c530001230615110223");
        assert_eq!(a, "USB\\VID_0781&PID_5581\\ID-001");
        assert_eq!(b, "USBSTOR\\Disk&Ven_SanDisk\\ID-002");
        assert_eq!(a2, "usb\\vid_0781&pid_5581\\ID-001");
        assert_eq!(p.instance_id("NOSLASH"), "ID-003");
    }
}
