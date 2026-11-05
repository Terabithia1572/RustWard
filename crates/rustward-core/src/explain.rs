//! Audit-friendly explanations of simulated decisions, in Turkish (primary)
//! and English. Every explanation ends with the statement that the decision
//! is simulated and enforcement is not active.

use serde::{Deserialize, Serialize};

use crate::classify::{DeviceCategory, UsbStorageTransport};
use crate::evaluate::{Decision, DecisionReason, EvidenceKind, Verdict};

/// One explanation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplanationStep {
    /// Stage code: `classified`, `identity`, `manufacturer`, `policy`, `result`.
    pub stage: String,
    /// Turkish text.
    pub tr: String,
    /// English text.
    pub en: String,
}

/// Explanation of a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// Short Turkish summary.
    pub summary_tr: String,
    /// Short English summary.
    pub summary_en: String,
    /// Steps.
    pub steps: Vec<ExplanationStep>,
}

fn step(stage: &str, tr: String, en: String) -> ExplanationStep {
    ExplanationStep {
        stage: stage.into(),
        tr,
        en,
    }
}

fn category_text(c: &DeviceCategory) -> (String, String) {
    let (tr, en) = match c {
        DeviceCategory::UsbStorageDisk { transport } => match transport {
            UsbStorageTransport::BulkOnly => (
                "USB depolama diski (BOT/USBSTOR)",
                "USB storage disk (BOT/USBSTOR)",
            ),
            UsbStorageTransport::Uasp => ("USB depolama diski (UASP)", "USB storage disk (UASP)"),
            UsbStorageTransport::Unknown => (
                "USB altında bilinmeyen yığınla disk",
                "disk below USB via unknown stack",
            ),
        },
        DeviceCategory::UsbStorageOtherType { .. } => (
            "USB depolama (disk dışı tür)",
            "USB storage (non-disk type)",
        ),
        DeviceCategory::UsbStorageInterface => {
            ("USB yığın depolama arabirimi", "USB mass-storage interface")
        }
        DeviceCategory::UsbPortableDevice => {
            ("Taşınabilir aygıt (MTP/PTP)", "portable device (MTP/PTP)")
        }
        DeviceCategory::SystemOrNonUsbStorage => {
            ("Sistem / USB olmayan depolama", "system / non-USB storage")
        }
        DeviceCategory::StorageAttachmentUnknown => (
            "Bağlantı türü kanıtlanamayan disk",
            "disk with unprovable attachment",
        ),
        DeviceCategory::Peripheral { .. } => {
            ("Çevre birimi (depolama değil)", "peripheral (not storage)")
        }
        DeviceCategory::Other => ("Diğer aygıt", "other device"),
    };
    (tr.into(), en.into())
}

/// Build the explanation for a decision.
#[must_use]
pub fn explain(decision: &Decision) -> Explanation {
    let mut steps = Vec::new();
    let (ctr, cen) = category_text(&decision.classification.category);
    steps.push(step(
        "classified",
        format!("Sınıflandırma: {ctr}."),
        format!("Classification: {cen}."),
    ));

    if let Some(inq) = &decision.classification.inquiry {
        steps.push(step(
            "identity",
            format!(
                "Uygulanabilir kimlik: üretici düzeyi donanım kimliği {} (SCSI INQUIRY üretici alanı \"{}\").",
                inq.vendor_level_id,
                inq.vendor_display()
            ),
            format!(
                "Enforceable identity: vendor-level hardware ID {} (SCSI INQUIRY vendor \"{}\").",
                inq.vendor_level_id,
                inq.vendor_display()
            ),
        ));
    }
    if let Some(u) = &decision.classification.usb_ancestor {
        let vid = u.ids.vid_hex();
        steps.push(step(
            "identity",
            format!("USB VID {vid} yalnızca destekleyici kanıttır; tek başına yetki vermez."),
            format!("USB VID {vid} is corroborating evidence only; it never authorizes by itself."),
        ));
    }

    let (mtr, men) = match &decision.reason {
        DecisionReason::BrandAllowed { brand_id } => (
            format!("Katalog eşleşmesi: \"{brand_id}\" markası; izin listesinde ve etkin."),
            format!("Catalog match: brand \"{brand_id}\"; allowlisted and enabled."),
        ),
        DecisionReason::BrandNotAllowed { brand_id } => (
            format!(
                "Katalog eşleşmesi: \"{brand_id}\" markası; izin listesinde değil veya kural devre dışı."
            ),
            format!("Catalog match: brand \"{brand_id}\"; not allowlisted or rule disabled."),
        ),
        DecisionReason::UnknownManufacturer { vendor } => (
            format!("Üretici \"{vendor}\" katalogda yok; varsayılan karar reddetmektir."),
            format!("Vendor \"{vendor}\" is not in the catalog; the default decision is deny."),
        ),
        DecisionReason::GenericVendorIdentity { vendor } => (
            format!("\"{vendor}\" genel bir denetleyici/köprü adıdır; marka belirlenemez."),
            format!(
                "\"{vendor}\" is a generic controller/bridge name; the brand cannot be determined."
            ),
        ),
        DecisionReason::MissingEnforceableIdentity => (
            "Üretici düzeyi donanım kimliği bulunamadı; marka belirlenemez.".into(),
            "No vendor-level hardware ID found; the brand cannot be determined.".into(),
        ),
        DecisionReason::ScopeDecisionPending => (
            "Bu depolama türü için kapsam kararı bekleniyor; varsayılan karar reddetmektir.".into(),
            "A scope decision for this storage type is pending; the default decision is deny."
                .into(),
        ),
        DecisionReason::NotInScope => (
            "Bu aygıt depolama politikasının kapsamında değildir.".into(),
            "This device is not subject to the storage policy.".into(),
        ),
    };
    steps.push(step("manufacturer", mtr, men));

    let names_hint = decision.evidence.iter().any(|e| {
        e.kind == EvidenceKind::Hint
            && (e.source == "friendly_name" || e.source == "bus_reported_description")
    });
    if names_hint {
        steps.push(step(
            "policy",
            "Aygıt adları yalnızca ipucudur ve karara etki etmez.".into(),
            "Device names are hints only and do not influence the decision.".into(),
        ));
    }
    if decision
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::Warning && e.source == "usb_vid")
    {
        steps.push(step(
            "policy",
            "Uyarı: USB VID markayı doğrulamıyor (köprü yonga, OEM denetleyici veya taklit olabilir).".into(),
            "Warning: USB VID does not corroborate the brand (bridge chip, OEM controller or spoofing).".into(),
        ));
    }

    let (vtr, ven) = match decision.verdict {
        Verdict::Allow => ("SİMÜLE İZİN", "SIMULATED ALLOW"),
        Verdict::Deny => ("SİMÜLE RET", "SIMULATED DENY"),
        Verdict::NotApplicable => ("KAPSAM DIŞI", "NOT APPLICABLE"),
    };
    steps.push(step(
        "result",
        format!(
            "Sonuç: {vtr} (politika v{}). Bu bir simülasyondur; gerçek engelleme etkin değildir.",
            decision.policy_version
        ),
        format!(
            "Result: {ven} (policy v{}). This is a simulation; real enforcement is not active.",
            decision.policy_version
        ),
    ));

    Explanation {
        summary_tr: format!(
            "{vtr}: {}",
            steps
                .get(steps.len().saturating_sub(2))
                .map_or("", |s| s.tr.as_str())
        ),
        summary_en: format!(
            "{ven}: {}",
            steps
                .get(steps.len().saturating_sub(2))
                .map_or("", |s| s.en.as_str())
        ),
        steps,
    }
}
