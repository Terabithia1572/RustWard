//! Phase 6 default-deny assessment.
//!
//! Combines three independent inputs without letting one stand in for
//! another:
//!
//! 1. the RustWard **policy decision** (simulation; default deny),
//! 2. the **identity evidence** a device reports about itself (SCSI INQUIRY
//!    vendor, USB VID, names), graded by how well the sources agree,
//! 3. the **Windows observation** (live restriction policy + problem code).
//!
//! The result names one policy-side category and, for devices in scope,
//! one enforcement-side category. A policy category is never an enforcement
//! claim: only [`AssessmentCategory::WindowsDenialVerified`] says that
//! Windows refused the device, and even that is an *installation* denial,
//! not a tested read/write denial.
//!
//! No identity is ever "authenticated": USB descriptors and INQUIRY data are
//! self-reported by the device firmware and can be cloned. The best grade,
//! [`IdentityConfidence::Corroborated`], only means two self-reported
//! sources agree with the catalog.

use serde::{Deserialize, Serialize};

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::classify::StorageScope;
use rustward_core::evaluate::{Decision, DecisionReason, Verdict};

use crate::observer::EvidenceLevel;

/// Result categories (Phase 6 vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentCategory {
    /// Policy would allow it and the identity is corroborated. Not an
    /// access guarantee: nothing is enforced by RustWard.
    AllowCandidate,
    /// Policy denies it (explicit deny, unlisted or unknown manufacturer).
    DenyCandidate,
    /// The identity is missing, generic, ambiguous or conflicting, or an
    /// allow rule would rest on a single uncorroborated source. Denied by
    /// default.
    UnverifiedIdentity,
    /// Storage-capable but outside the brand policy (MTP, optical, …).
    /// Denied by default pending a scope decision.
    UnsupportedDevice,
    /// Not subject to the storage policy (keyboard, mouse, printer, hub,
    /// internal or virtual disk, interface node).
    OutOfScope,
    /// Windows currently refuses the installation of this connected device
    /// under a matching live rule (Code 1/28). Read/write not tested.
    WindowsDenialVerified,
    /// No Windows denial is observed for this device (no matching rule,
    /// installed before the rule, or not connected).
    EnforcementNotActive,
}

/// How well the self-reported identity sources agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityConfidence {
    /// INQUIRY vendor maps to a catalog brand and the USB VID is listed for
    /// that brand only. Still self-reported, not authenticated.
    Corroborated,
    /// Only one source identifies the manufacturer (VID unknown to the
    /// catalog, or a vendor that is not in the catalog at all).
    SingleSource,
    /// The USB VID is listed for several brands (shared controller VID).
    Ambiguous,
    /// INQUIRY vendor and USB VID point to different manufacturers.
    Conflicting,
    /// The INQUIRY vendor is a generic controller/bridge value.
    Generic,
    /// No vendor-level identifier could be recovered.
    Missing,
    /// Identity is not evaluated (out of scope or unsupported).
    NotEvaluated,
}

/// One identity signal, with its source and strength.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySignal {
    /// `scsi_inquiry_vendor`, `usb_vid`.
    pub source: String,
    /// Reported value.
    pub value: String,
    /// Catalog brand(s) this value maps to.
    pub brands: Vec<String>,
    /// `enforceable` (what a Windows device-ID rule can match) or
    /// `corroborating` (never authorizes on its own).
    pub strength: String,
}

/// Windows-side input for one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsInput {
    /// Connected at inventory time.
    pub present: Option<bool>,
    /// Evidence level from the observer.
    pub evidence: EvidenceLevel,
    /// A driver is installed (the device was installed before any rule).
    pub driver_installed: Option<bool>,
}

/// Assessment of one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAssessment {
    /// Policy-side category (one of the first five).
    pub policy_category: AssessmentCategory,
    /// Enforcement-side category for devices in scope; `None` when out of
    /// scope.
    pub enforcement_category: Option<AssessmentCategory>,
    /// Identity agreement.
    pub identity: IdentityConfidence,
    /// Brand named by the INQUIRY vendor, if it is in the catalog.
    pub reported_brand: Option<String>,
    /// Always `false`: no source is cryptographically authenticated.
    pub authenticated: bool,
    /// Signals used.
    pub signals: Vec<IdentitySignal>,
    /// Connected now (`None` when unknown).
    pub present: Option<bool>,
    /// Installed with a working driver (relevant for non-retroactive rules).
    pub previously_installed: bool,
    /// Short Turkish explanation.
    pub summary_tr: String,
    /// Short English explanation.
    pub summary_en: String,
}

fn identity_of(
    decision: &Decision,
    catalog: &ValidatedCatalog,
) -> (IdentityConfidence, Option<String>, Vec<IdentitySignal>) {
    let mut signals = Vec::new();
    let Some(inq) = decision.classification.inquiry.as_ref() else {
        return (IdentityConfidence::Missing, None, signals);
    };
    let brand = catalog
        .brand_for_inquiry_field(&inq.vendor_field)
        .map(str::to_owned);
    signals.push(IdentitySignal {
        source: "scsi_inquiry_vendor".into(),
        value: inq.vendor_display(),
        brands: brand.iter().cloned().collect(),
        strength: "enforceable".into(),
    });
    let vid_brands: Vec<String> = decision
        .classification
        .usb_ancestor
        .as_ref()
        .map(|u| {
            let b = catalog.brands_for_vid(u.ids.vid).to_vec();
            signals.push(IdentitySignal {
                source: "usb_vid".into(),
                value: u.ids.vid_hex(),
                brands: b.clone(),
                strength: "corroborating".into(),
            });
            b
        })
        .unwrap_or_default();
    if catalog.is_generic_vendor(&inq.vendor_field) {
        return (IdentityConfidence::Generic, None, signals);
    }
    let confidence = match &brand {
        Some(b) if vid_brands.is_empty() => {
            let _ = b;
            IdentityConfidence::SingleSource
        }
        Some(b) if vid_brands.iter().any(|x| x == b) => {
            if vid_brands.len() == 1 {
                IdentityConfidence::Corroborated
            } else {
                IdentityConfidence::Ambiguous
            }
        }
        Some(_) => IdentityConfidence::Conflicting,
        // Vendor not in the catalog, but the VID belongs to a known brand.
        None if !vid_brands.is_empty() => IdentityConfidence::Conflicting,
        None => IdentityConfidence::SingleSource,
    };
    (confidence, brand, signals)
}

fn texts(c: AssessmentCategory, identity: IdentityConfidence) -> (&'static str, &'static str) {
    use AssessmentCategory as A;
    match c {
        A::AllowCandidate => (
            "İzin adayı: politika bu üreticiye izin veriyor ve kimlik kaynakları birbiriyle uyumlu (yine de cihazın kendi bildirimi; doğrulanmış kimlik değil).",
            "Allow candidate: the policy allows this manufacturer and the identity sources agree (still self-reported; not an authenticated identity).",
        ),
        A::DenyCandidate => (
            "Ret adayı: politika bu cihazı reddediyor (açık ret, listede olmayan veya bilinmeyen üretici).",
            "Deny candidate: the policy denies this device (explicit deny, unlisted or unknown manufacturer).",
        ),
        A::UnverifiedIdentity => match identity {
            IdentityConfidence::Generic => (
                "Kimlik doğrulanamadı: cihaz genel bir denetleyici adı bildiriyor; üretici belirlenemez. Varsayılan karar ret.",
                "Unverified identity: the device reports a generic controller name; the manufacturer cannot be determined. Default deny.",
            ),
            IdentityConfidence::Conflicting => (
                "Kimlik çelişkili: SCSI üretici adı ile USB VID farklı üreticileri gösteriyor. Varsayılan karar ret.",
                "Conflicting identity: the SCSI vendor and the USB VID point to different manufacturers. Default deny.",
            ),
            IdentityConfidence::Ambiguous => (
                "Kimlik belirsiz: USB VID birden çok üreticiye ait olabilir. Varsayılan karar ret.",
                "Ambiguous identity: the USB VID may belong to several manufacturers. Default deny.",
            ),
            IdentityConfidence::Missing => (
                "Kimlik yok: üretici düzeyi donanım kimliği bulunamadı. Varsayılan karar ret.",
                "No identity: no vendor-level hardware ID was found. Default deny.",
            ),
            _ => (
                "Kimlik doğrulanamadı: izin tek bir kaynağa dayanırdı; doğrulanana kadar ret.",
                "Unverified identity: an allow would rest on a single source; denied until corroborated.",
            ),
        },
        A::UnsupportedDevice => (
            "Desteklenmeyen depolama türü (MTP, optik vb.); kapsam kararı bekleniyor, varsayılan karar ret.",
            "Unsupported storage type (MTP, optical, …); scope decision pending, default deny.",
        ),
        A::OutOfScope => (
            "Kapsam dışı: klavye, fare, yazıcı, iç disk gibi aygıtlar depolama politikasından etkilenmez.",
            "Out of scope: keyboards, mice, printers and internal disks are not affected by the storage policy.",
        ),
        A::WindowsDenialVerified | A::EnforcementNotActive => ("", ""),
    }
}

/// Assess one device.
#[must_use]
pub fn assess(
    decision: &Decision,
    catalog: &ValidatedCatalog,
    windows: Option<WindowsInput>,
) -> DeviceAssessment {
    use AssessmentCategory as A;
    let scope = decision.classification.category.scope();
    let (identity, reported_brand, signals) = match scope {
        StorageScope::InScope => identity_of(decision, catalog),
        _ => (IdentityConfidence::NotEvaluated, None, Vec::new()),
    };
    let policy_category = match scope {
        StorageScope::NotInScope => A::OutOfScope,
        StorageScope::ScopeDecisionPending => A::UnsupportedDevice,
        StorageScope::InScope => match decision.verdict {
            Verdict::Allow if identity == IdentityConfidence::Corroborated => A::AllowCandidate,
            Verdict::Allow => A::UnverifiedIdentity,
            Verdict::Deny
                if matches!(
                    identity,
                    IdentityConfidence::Corroborated | IdentityConfidence::SingleSource
                ) || matches!(decision.reason, DecisionReason::BrandDenied { .. }) =>
            {
                A::DenyCandidate
            }
            Verdict::Deny => A::UnverifiedIdentity,
            Verdict::NotApplicable => A::OutOfScope,
        },
    };
    let present = windows.and_then(|w| w.present);
    let previously_installed = windows.is_some_and(|w| w.driver_installed == Some(true));
    let enforcement_category = (policy_category != A::OutOfScope).then(|| match windows {
        Some(w) if w.present == Some(true) && w.evidence == EvidenceLevel::InstallDenied => {
            A::WindowsDenialVerified
        }
        _ => A::EnforcementNotActive,
    });
    let (ptr, pen) = texts(policy_category, identity);
    let (etr, een) = match enforcement_category {
        Some(A::WindowsDenialVerified) => (
            " Gerçek Windows kanıtı: Windows kurulumu reddetti; okuma/yazma ayrıca test edilmedi.",
            " Real Windows evidence: Windows refused the installation; read/write not tested separately.",
        ),
        Some(_) if present != Some(true) => (
            " Cihaz bağlı değil; Windows durumu gözlenemez.",
            " Not connected; the Windows state cannot be observed.",
        ),
        Some(_) => (
            " Windows bu cihaz için engel uygulamıyor (koruma etkin değil).",
            " Windows enforces no denial for this device (protection not active).",
        ),
        None => ("", ""),
    };
    // An allow candidate that Windows denies, or a deny candidate Windows
    // lets through, is stated plainly by the categories themselves.
    DeviceAssessment {
        policy_category,
        enforcement_category,
        identity,
        reported_brand,
        authenticated: false,
        signals,
        present,
        previously_installed,
        summary_tr: format!("{ptr}{etr}"),
        summary_en: format!("{pen}{een}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustward_core::catalog::ValidatedCatalog;
    use rustward_core::classify::classify;
    use rustward_core::device::{DeviceRecord, DeviceSnapshot};
    use rustward_core::evaluate::evaluate_device;
    use rustward_core::policy::ValidatedPolicy;

    const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");

    fn catalog() -> ValidatedCatalog {
        ValidatedCatalog::from_json(CATALOG).unwrap()
    }

    fn policy(c: &ValidatedCatalog, allowed: &[&str], denied: &[&str]) -> ValidatedPolicy {
        let rule = |b: &&str| serde_json::json!({"brand_id": b, "enabled": true});
        let json = serde_json::json!({
            "schema_version": 1,
            "workstation_id": "TEST",
            "policy_version": 1,
            "mode": "dry_run",
            "catalog_version": c.catalog().catalog_version,
            "allowed_brands": allowed.iter().map(rule).collect::<Vec<_>>(),
            "denied_brands": denied.iter().map(rule).collect::<Vec<_>>(),
        });
        ValidatedPolicy::from_json(&json.to_string(), c).unwrap()
    }

    fn rec(
        id: &str,
        parent: Option<&str>,
        class: &str,
        service: &str,
        hw: &[&str],
    ) -> DeviceRecord {
        serde_json::from_value(serde_json::json!({
            "instance_id": id,
            "parent_instance_id": parent,
            "class_name": class,
            "service": service,
            "hardware_ids": hw,
            "present": true,
        }))
        .unwrap()
    }

    /// USB function `VID:PID` with a USBSTOR disk child reporting `vendor`.
    fn usb_stick(vid: &str, pid: &str, vendor8: &str) -> DeviceSnapshot {
        let usb = format!("USB\\VID_{vid}&PID_{pid}\\SYNTH0001");
        let disk = format!("USBSTOR\\Disk&Ven_{vendor8}&Prod_Test&Rev_1.00\\SYNTH0001&0");
        let hw_usb = format!("USB\\VID_{vid}&PID_{pid}");
        let hw_disk = format!("USBSTOR\\Disk{vendor8}Test____________1.00");
        let hw_vendor = format!("USBSTOR\\Disk{vendor8}");
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "source": {"kind": "synthetic", "description": "assessment unit test"},
            "devices": [
                rec(&usb, None, "USB", "USBSTOR", &[&hw_usb]),
                rec(&disk, Some(&usb), "DiskDrive", "disk", &[&hw_disk, &hw_vendor, "GenDisk"]),
            ]
        }))
        .unwrap()
    }

    fn assess_disk(
        s: &DeviceSnapshot,
        p: &ValidatedPolicy,
        c: &ValidatedCatalog,
        w: Option<WindowsInput>,
    ) -> DeviceAssessment {
        let index = s.index();
        let d = &s.devices[1];
        let decision = evaluate_device(classify(&index, d), d, p, c);
        assess(&decision, c, w)
    }

    const CONNECTED: WindowsInput = WindowsInput {
        present: Some(true),
        evidence: EvidenceLevel::None,
        driver_installed: Some(true),
    };

    #[test]
    fn corroborated_allowed_brand_is_only_an_allow_candidate() {
        let c = catalog();
        let p = policy(&c, &["sandisk"], &["kingston"]);
        let a = assess_disk(
            &usb_stick("0781", "5581", "SanDisk_"),
            &p,
            &c,
            Some(CONNECTED),
        );
        assert_eq!(a.policy_category, AssessmentCategory::AllowCandidate);
        assert_eq!(a.identity, IdentityConfidence::Corroborated);
        assert_eq!(
            a.enforcement_category,
            Some(AssessmentCategory::EnforcementNotActive)
        );
        assert!(!a.authenticated);
    }

    #[test]
    fn sandisk_label_with_generic_vendor_is_unverified_and_denied() {
        // The physical "SanDisk/ASELSAN-labelled" stick seen in the VM
        // reports VendorC 346D:5678.
        let c = catalog();
        let p = policy(&c, &["sandisk"], &[]);
        let a = assess_disk(
            &usb_stick("346D", "5678", "VendorC_"),
            &p,
            &c,
            Some(CONNECTED),
        );
        assert_eq!(a.policy_category, AssessmentCategory::UnverifiedIdentity);
        assert_eq!(a.reported_brand, None);
    }

    #[test]
    fn allowed_vendor_name_with_foreign_vid_is_conflicting_not_allowed() {
        let c = catalog();
        let p = policy(&c, &["sandisk"], &[]);
        // Claims SanDisk in INQUIRY but sits behind a Kingston VID.
        let a = assess_disk(
            &usb_stick("0951", "1666", "SanDisk_"),
            &p,
            &c,
            Some(CONNECTED),
        );
        assert_eq!(a.identity, IdentityConfidence::Conflicting);
        assert_eq!(a.policy_category, AssessmentCategory::UnverifiedIdentity);
    }

    #[test]
    fn allowed_vendor_without_vid_corroboration_is_not_an_allow_candidate() {
        let c = catalog();
        let p = policy(&c, &["sandisk"], &[]);
        let a = assess_disk(
            &usb_stick("1234", "0001", "SanDisk_"),
            &p,
            &c,
            Some(CONNECTED),
        );
        assert_eq!(a.identity, IdentityConfidence::SingleSource);
        assert_eq!(a.policy_category, AssessmentCategory::UnverifiedIdentity);
    }

    #[test]
    fn explicitly_denied_kingston_is_a_deny_candidate() {
        let c = catalog();
        let p = policy(&c, &["sandisk"], &["kingston", "seagate"]);
        let a = assess_disk(
            &usb_stick("0951", "1666", "Kingston"),
            &p,
            &c,
            Some(CONNECTED),
        );
        assert_eq!(a.policy_category, AssessmentCategory::DenyCandidate);
        assert_eq!(a.identity, IdentityConfidence::Corroborated);
        assert_eq!(
            a.enforcement_category,
            Some(AssessmentCategory::EnforcementNotActive)
        );
        assert!(a.previously_installed);
    }

    #[test]
    fn unknown_manufacturer_is_a_deny_candidate() {
        let c = catalog();
        let p = policy(&c, &["sandisk"], &[]);
        let a = assess_disk(
            &usb_stick("ABCD", "0001", "Acme____"),
            &p,
            &c,
            Some(CONNECTED),
        );
        assert_eq!(a.policy_category, AssessmentCategory::DenyCandidate);
        assert_eq!(a.identity, IdentityConfidence::SingleSource);
    }

    #[test]
    fn only_a_connected_install_denied_device_is_windows_denial_verified() {
        let c = catalog();
        let p = policy(&c, &[], &["kingston"]);
        let s = usb_stick("0951", "1666", "Kingston");
        let denied = WindowsInput {
            present: Some(true),
            evidence: EvidenceLevel::InstallDenied,
            driver_installed: Some(false),
        };
        let a = assess_disk(&s, &p, &c, Some(denied));
        assert_eq!(
            a.enforcement_category,
            Some(AssessmentCategory::WindowsDenialVerified)
        );
        assert!(a.summary_tr.contains("okuma/yazma ayrıca test edilmedi"));
        // Disconnected: never verified, whatever the evidence says.
        let gone = WindowsInput {
            present: Some(false),
            ..denied
        };
        let a = assess_disk(&s, &p, &c, Some(gone));
        assert_eq!(
            a.enforcement_category,
            Some(AssessmentCategory::EnforcementNotActive)
        );
        // A rule alone is not a denial.
        let rule_only = WindowsInput {
            evidence: EvidenceLevel::PolicyOnly,
            ..CONNECTED
        };
        let a = assess_disk(&s, &p, &c, Some(rule_only));
        assert_eq!(
            a.enforcement_category,
            Some(AssessmentCategory::EnforcementNotActive)
        );
    }

    #[test]
    fn peripherals_and_internal_disks_are_out_of_scope() {
        let c = catalog();
        let p = policy(&c, &["sandisk"], &[]);
        let s: DeviceSnapshot = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "source": {"kind": "synthetic", "description": "assessment unit test"},
            "devices": [
                rec("USB\\VID_046D&PID_C52B\\SYNTH", None, "HIDClass", "HidUsb", &["USB\\VID_046D&PID_C52B"]),
                rec("PCI\\VEN_8086&DEV_2922\\SYNTH", None, "SCSIAdapter", "storahci", &["PCI\\VEN_8086&DEV_2922"]),
                rec("SCSI\\Disk&Ven_VMware&Prod_Virtual_disk\\SYNTH", Some("PCI\\VEN_8086&DEV_2922\\SYNTH"), "DiskDrive", "disk", &["SCSI\\DiskVMware__Virtual_disk____2.0_", "SCSI\\DiskVMware__", "GenDisk"]),
            ]
        }))
        .unwrap();
        let index = s.index();
        for d in [&s.devices[0], &s.devices[2]] {
            let decision = evaluate_device(classify(&index, d), d, &p, &c);
            let a = assess(&decision, &c, None);
            assert_eq!(
                a.policy_category,
                AssessmentCategory::OutOfScope,
                "{}",
                d.instance_id
            );
            assert_eq!(a.enforcement_category, None);
        }
    }
}
