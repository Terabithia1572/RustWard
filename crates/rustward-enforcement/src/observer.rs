//! Read-only Windows enforcement observer.
//!
//! Correlates, for every USB storage device in an inventory snapshot:
//! the *live* Device Installation Restriction policy (as captured from the
//! registry), the device's hardware identifiers, its Device Manager problem
//! code and presence, and RustWard's own (simulated) manufacturer decision.
//!
//! It never writes anything and never claims more than the evidence shows:
//! - a configured policy alone is [`ObservedState::WindowsRuleConfigured`],
//!   not a denial;
//! - Code 1 / Code 28 on a connected device whose hardware IDs match a live
//!   prevent rule is [`ObservedState::WindowsInstallDenied`]; read/write
//!   paths are still [`ObservedState::WindowsAccessNotVerified`];
//! - a disconnected device is never reported as blocked;
//! - an earlier recorded denial whose evidence is gone is history, not a
//!   current block.

use serde::{Deserialize, Serialize};

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::classify::DeviceCategory;
use rustward_core::device::{DeviceRecord, DeviceSnapshot};
use rustward_core::evaluate::{Decision, DecisionReason, Verdict, evaluate_snapshot};
use rustward_core::policy::ValidatedPolicy;

use crate::policy_eval::{InstallOutcome, evaluate_install};
use crate::policy_inspect::CapturedPolicy;
use crate::policy_state::PolicySnapshot;

/// `CM_PROB_NOT_CONFIGURED`: seen right after a retroactive removal.
pub const CM_PROB_NOT_CONFIGURED: u32 = 1;
/// `CM_PROB_FAILED_INSTALL`: "drivers not installed"; seen on reconnect.
pub const CM_PROB_FAILED_INSTALL: u32 = 28;

/// Observer states. Several can apply to one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservedState {
    /// RustWard's manufacturer policy denies the device (simulation only).
    SimulatedDeny,
    /// No live Windows rule prevents this device.
    NoWindowsRestriction,
    /// A live Windows prevent rule matches the device, but no device-level
    /// denial is observed (installed earlier, or not connected).
    WindowsRuleConfigured,
    /// Connected, a live prevent rule matches, and Windows reports the
    /// installation as not done (Code 1 or 28).
    WindowsInstallDenied,
    /// Read/write denial was not tested directly.
    WindowsAccessNotVerified,
    /// Presence or install state cannot be established (e.g. disconnected).
    StatusUnknown,
    /// A Windows restriction policy exists and disagrees with RustWard.
    PolicyMismatch,
}

/// How strong the evidence of a denial is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// No Windows-side denial evidence.
    None,
    /// A live rule matches; the device was not observed denied.
    PolicyOnly,
    /// Windows refused the installation of the connected device (no disk
    /// driver, therefore no disk or volume object). Read/write paths were
    /// not tested directly.
    InstallDenied,
}

/// An earlier recorded denial (from the audit trail).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalDenial {
    /// When it was observed (UTC ms).
    pub observed_ms: i64,
    /// Problem code then.
    pub problem_code: u32,
    /// Matching rule entry then.
    pub rule_entry: String,
}

/// One observed USB storage device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedDevice {
    /// Instance ID (the caller masks it before showing it).
    pub instance_id: String,
    /// Friendly name or description.
    pub name: String,
    /// USB VID:PID of the USB ancestor, e.g. `0951:1666`.
    pub vid_pid: Option<String>,
    /// INQUIRY vendor field as reported by the device (unauthenticated).
    pub reported_vendor: Option<String>,
    /// INQUIRY product field.
    pub reported_product: Option<String>,
    /// Most specific hardware ID (first entry).
    pub hardware_id: Option<String>,
    /// RustWard verdict: `allow`, `deny`, `not_applicable`.
    pub rustward_verdict: String,
    /// RustWard reason code.
    pub rustward_reason: String,
    /// Outcome of the *live* Windows policy for a new installation.
    pub windows_rule: InstallOutcome,
    /// Connected at inventory time.
    pub present: Option<bool>,
    /// Device Manager problem code.
    pub problem_code: Option<u32>,
    /// A driver service is recorded and no "not installed" problem.
    pub driver_installed: Option<bool>,
    /// All applicable states.
    pub states: Vec<ObservedState>,
    /// Evidence level of a *current* denial.
    pub evidence: EvidenceLevel,
    /// Turkish labels for the three UI lines.
    pub label_rustward_tr: String,
    /// "Windows politikası: …".
    pub label_policy_tr: String,
    /// "Gerçek cihaz durumu: …".
    pub label_status_tr: String,
    /// Explanation of the correlation and any discrepancy (Turkish).
    pub explanation_tr: String,
    /// Earlier recorded denial that is no longer current.
    pub history: Option<HistoricalDenial>,
}

/// The whole observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// Policy capture time (UTC ms).
    pub policy_captured_ms: i64,
    /// The Restrictions key exists.
    pub policy_key_present: bool,
    /// Any Device Installation Restriction rule is configured.
    pub windows_restrictions_configured: bool,
    /// Devices (USB storage only).
    pub devices: Vec<ObservedDevice>,
}

impl Observation {
    /// Devices whose installation Windows currently denies.
    pub fn currently_denied(&self) -> impl Iterator<Item = &ObservedDevice> {
        self.devices
            .iter()
            .filter(|d| d.evidence == EvidenceLevel::InstallDenied)
    }
}

const LISTS: [&str; 7] = [
    "DenyDeviceIDs",
    "AllowDeviceIDs",
    "DenyInstanceIDs",
    "AllowInstanceIDs",
    "DenyDeviceClasses",
    "AllowDeviceClasses",
    "DenyUnspecified",
];

/// Any restriction toggle is set to 1.
#[must_use]
pub fn restrictions_configured(policy: &PolicySnapshot) -> bool {
    LISTS.iter().any(|n| policy.dword(n) == Some(1))
}

fn reason_code(r: &DecisionReason) -> &'static str {
    match r {
        DecisionReason::BrandAllowed { .. } => "brand_allowed",
        DecisionReason::BrandNotAllowed { .. } => "brand_not_allowed",
        DecisionReason::UnknownManufacturer { .. } => "unknown_manufacturer",
        DecisionReason::GenericVendorIdentity { .. } => "generic_vendor_identity",
        DecisionReason::MissingEnforceableIdentity => "missing_enforceable_identity",
        DecisionReason::ScopeDecisionPending => "scope_decision_pending",
        DecisionReason::NotInScope => "not_in_scope",
    }
}

fn verdict_code(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::NotApplicable => "not_applicable",
    }
}

fn is_usb_storage(d: &Decision) -> bool {
    matches!(
        d.classification.category,
        DeviceCategory::UsbStorageDisk { .. } | DeviceCategory::UsbStorageOtherType { .. }
    )
}

fn device_name(r: &DeviceRecord) -> String {
    r.friendly_name
        .clone()
        .or_else(|| r.description.clone())
        .unwrap_or_else(|| r.instance_id.clone())
}

fn driver_installed(r: &DeviceRecord) -> Option<bool> {
    match r.problem_code {
        Some(CM_PROB_NOT_CONFIGURED | CM_PROB_FAILED_INSTALL) => Some(false),
        _ if r.service.as_deref().is_some_and(|s| !s.is_empty()) => Some(true),
        _ => None,
    }
}

/// Observe one device.
#[must_use]
pub fn observe_device(
    record: &DeviceRecord,
    decision: &Decision,
    live: &PolicySnapshot,
    restrictions: bool,
) -> ObservedDevice {
    let windows_rule = evaluate_install(live, record);
    let prevented = matches!(windows_rule, InstallOutcome::Prevented { .. });
    let present = record.present;
    let installed = driver_installed(record);
    let denied_code = matches!(
        record.problem_code,
        Some(CM_PROB_NOT_CONFIGURED | CM_PROB_FAILED_INSTALL)
    );
    let rw_deny = decision.verdict == Verdict::Deny;

    let mut states = Vec::new();
    if rw_deny {
        states.push(ObservedState::SimulatedDeny);
    }
    let evidence;
    let label_status_tr;
    let mut notes: Vec<&str> = Vec::new();
    if present != Some(true) {
        // Disconnected: never a block.
        states.push(ObservedState::StatusUnknown);
        evidence = if prevented {
            EvidenceLevel::PolicyOnly
        } else {
            EvidenceLevel::None
        };
        label_status_tr = "Bağlı değil (engelli sayılmaz)".to_string();
        notes.push("Cihaz şu anda bağlı değil; bağlı olmayan bir cihaz engellenmiş sayılmaz.");
    } else if prevented && denied_code {
        states.push(ObservedState::WindowsInstallDenied);
        states.push(ObservedState::WindowsAccessNotVerified);
        evidence = EvidenceLevel::InstallDenied;
        label_status_tr = format!(
            "Windows kurulumu engelledi (Kod {})",
            record.problem_code.unwrap_or_default()
        );
        notes.push(
            "Windows bu cihazın sürücü kurulumunu reddetti; disk ve birim nesnesi oluşmaz. Okuma/yazma yolları ayrıca test edilmedi.",
        );
    } else if denied_code {
        // A failed install without a matching live rule: not our evidence.
        states.push(ObservedState::StatusUnknown);
        evidence = EvidenceLevel::None;
        label_status_tr = format!(
            "Kurulum sorunu (Kod {}), eşleşen kural yok",
            record.problem_code.unwrap_or_default()
        );
        notes.push("Windows bir kurulum sorunu bildiriyor ama hiçbir canlı kısıtlama kuralı bu cihazla eşleşmiyor; sebep başka olabilir.");
    } else if installed == Some(true) {
        evidence = if prevented {
            EvidenceLevel::PolicyOnly
        } else {
            EvidenceLevel::None
        };
        label_status_tr = "Erişilebilir (sürücü kurulu)".to_string();
        if prevented {
            notes.push("Kural eşleşiyor ama cihaz önceden kurulu ve çalışıyor: geriye dönük olmayan kural kurulu cihazı etkilemez.");
        }
    } else {
        states.push(ObservedState::StatusUnknown);
        evidence = if prevented {
            EvidenceLevel::PolicyOnly
        } else {
            EvidenceLevel::None
        };
        label_status_tr = "Durum belirlenemedi".to_string();
    }

    let label_policy_tr = match &windows_rule {
        InstallOutcome::Prevented { rule } => {
            if !states.contains(&ObservedState::WindowsInstallDenied) {
                states.push(ObservedState::WindowsRuleConfigured);
            }
            format!("Engelleme kuralı eşleşiyor ({}: {})", rule.list, rule.entry)
        }
        InstallOutcome::Allowed { rule } => {
            states.push(ObservedState::NoWindowsRestriction);
            format!("İzin kuralı eşleşiyor ({}: {})", rule.list, rule.entry)
        }
        InstallOutcome::NotRestricted => {
            states.push(ObservedState::NoWindowsRestriction);
            "Kural uygulanmamış".to_string()
        }
    };

    if restrictions && rw_deny != prevented && decision.verdict != Verdict::NotApplicable {
        states.push(ObservedState::PolicyMismatch);
        notes.push(if rw_deny {
            "Uyuşmazlık: RustWard bu cihazı reddediyor ama Windows politikası onu engellemiyor."
        } else {
            "Uyuşmazlık: RustWard bu cihaza izin veriyor ama Windows politikası onu engelliyor."
        });
    } else if rw_deny && !prevented {
        notes.push("RustWard kararı yalnızca simülasyondur; Windows bu cihazı engellemiyor.");
    }

    let label_rustward_tr = match decision.verdict {
        Verdict::Deny => "Simülasyonda ret",
        Verdict::Allow => "Simülasyonda izin",
        Verdict::NotApplicable => "Kapsam dışı",
    }
    .to_string();

    let inquiry = decision.classification.inquiry.as_ref();
    ObservedDevice {
        instance_id: record.instance_id.clone(),
        name: device_name(record),
        vid_pid: decision
            .classification
            .usb_ancestor
            .as_ref()
            .map(|a| format!("{:04X}:{:04X}", a.ids.vid, a.ids.pid)),
        reported_vendor: inquiry.map(|i| i.vendor_field.trim_end_matches('_').to_string()),
        reported_product: inquiry
            .and_then(|i| i.product_field.as_ref())
            .map(|p| p.trim_end_matches('_').to_string()),
        hardware_id: record.hardware_ids.first().cloned(),
        rustward_verdict: verdict_code(decision.verdict).into(),
        rustward_reason: reason_code(&decision.reason).into(),
        windows_rule,
        present,
        problem_code: record.problem_code,
        driver_installed: installed,
        states,
        evidence,
        label_rustward_tr,
        label_policy_tr,
        label_status_tr,
        explanation_tr: notes.join(" "),
        history: None,
    }
}

/// Attach an earlier recorded denial. It is kept only as history when the
/// device is not denied now; the explanation says so.
pub fn attach_history(dev: &mut ObservedDevice, last: Option<HistoricalDenial>) {
    let Some(h) = last else { return };
    if dev.evidence == EvidenceLevel::InstallDenied {
        return;
    }
    let note = "Geçmiş kanıt: Windows bu cihazın kurulumunu daha önce engelledi (kayıtlı); bu engel şu anda gözlenmiyor.";
    dev.explanation_tr = if dev.explanation_tr.is_empty() {
        note.to_string()
    } else {
        format!("{note} {}", dev.explanation_tr)
    };
    dev.history = Some(h);
}

/// Observe every USB storage device of `snapshot`.
#[must_use]
pub fn observe(
    snapshot: &DeviceSnapshot,
    policy: &ValidatedPolicy,
    catalog: &ValidatedCatalog,
    captured: &CapturedPolicy,
) -> Observation {
    let decisions = evaluate_snapshot(snapshot, policy, catalog);
    let restrictions = restrictions_configured(&captured.values);
    let devices = decisions
        .iter()
        .filter(|d| is_usb_storage(d))
        .filter_map(|d| {
            snapshot
                .devices
                .iter()
                .find(|r| r.instance_id == d.instance_id)
                .map(|r| observe_device(r, d, &captured.values, restrictions))
        })
        .collect();
    Observation {
        policy_captured_ms: captured.captured_ms,
        policy_key_present: captured.key_present,
        windows_restrictions_configured: restrictions,
        devices,
    }
}
