//! Reviewable, device-specific Group Policy checklist for an administrator.
//!
//! RustWard never applies it. It models the exact change with the existing
//! policy evaluator, refuses generic identifiers and any change that would
//! also affect a device that is not USB storage, and never produces class
//! rules (so no broad or retroactive DiskDrive restriction can come from it).

use serde::{Deserialize, Serialize};

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::device::DeviceSnapshot;
use rustward_core::evaluate::evaluate_snapshot;
use rustward_core::policy::ValidatedPolicy;

use crate::device_install::RESTRICTIONS_KEY;
use crate::policy_eval::{InstallOutcome, evaluate_install};
use crate::policy_state::{PolicySnapshot, RegData};

/// English policy name (Group Policy Editor).
pub const POLICY_EN: &str = "Prevent installation of devices that match any of these device IDs";
/// Turkish policy name as shown by gpedit.msc on Turkish Windows 10.
pub const POLICY_TR: &str =
    "Bu aygıt kimliklerinden herhangi biriyle eşleşen aygıtların yüklenmesini engelle";
/// Policy path (English).
pub const PATH_EN: &str = "Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions";
/// Policy path (Turkish).
pub const PATH_TR: &str = "Bilgisayar Yapılandırması > Yönetim Şablonları > Sistem > Aygıt Yükleme > Aygıt Yükleme Kısıtlamaları";
/// Retroactive option label (Turkish).
pub const RETRO_TR: &str = "Ayrıca zaten yüklü olan eşleşen aygıtlara da uygulayın";

/// Identifiers that match whole device families and are never offered.
const GENERIC: [&str; 7] = [
    "GENDISK",
    "USBSTOR\\GENDISK",
    "USBSTOR\\DISK",
    "USBSTOR\\RAW",
    "SCSI\\DISK",
    "SCSI\\RAW",
    "USBSTOR\\GENSD",
];

/// Why a checklist cannot be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum ChecklistError {
    /// No such device in the inventory.
    #[error("device not found in the inventory")]
    DeviceNotFound,
    /// Only USB storage disks are supported.
    #[error("not a USB storage disk")]
    NotUsbStorage,
    /// The device has no specific (vendor + product) hardware ID.
    #[error("no specific hardware ID: {0}")]
    NoSpecificHardwareId(String),
    /// The rule would also prevent devices that are not USB storage.
    #[error("the rule would also affect: {0:?}")]
    AffectsNonUsbStorage(Vec<String>),
    /// An existing allow rule would override the prevent rule.
    #[error("an existing rule would keep the device allowed: {0}")]
    WouldNotBePrevented(String),
}

/// The checklist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChecklist {
    /// Device name.
    pub device_name: String,
    /// USB VID:PID.
    pub vid_pid: Option<String>,
    /// Exact hardware ID to enter.
    pub hardware_id: String,
    /// Policy (EN / TR) and path.
    pub policy_name_en: String,
    /// Turkish policy name.
    pub policy_name_tr: String,
    /// Path (EN).
    pub policy_path_en: String,
    /// Path (TR).
    pub policy_path_tr: String,
    /// Retroactive option chosen.
    pub retroactive: bool,
    /// The device is installed now.
    pub device_installed: bool,
    /// Current configuration (one line each).
    pub existing: Vec<String>,
    /// Expected registry values after the change (informational; written by
    /// Group Policy, never by RustWard).
    pub expected_registry: Vec<String>,
    /// Devices in the inventory the change would newly prevent.
    pub affected_devices: Vec<String>,
    /// Steps for the administrator.
    pub steps: Vec<String>,
    /// Risks.
    pub risks: Vec<String>,
    /// Rollback.
    pub rollback: Vec<String>,
    /// Expected verification results.
    pub verification: Vec<String>,
}

fn reg_line(name: &str, data: &RegData) -> String {
    match data {
        RegData::Dword(v) => format!("{name} = {v} (REG_DWORD)"),
        RegData::Sz(s) => format!("{name} = \"{s}\" (REG_SZ)"),
        other => format!("{name} = {other:?}"),
    }
}

/// The policy expected after an administrator applies the device-ID
/// prevent rule for `hardware_id` on top of `live`, and the value lines that
/// change. Shared by the checklist and the guided verification.
#[must_use]
pub fn planned_deny_policy(
    live: &PolicySnapshot,
    hardware_id: &str,
    retroactive: bool,
) -> (PolicySnapshot, Vec<String>) {
    let list = live.list("DenyDeviceIDs");
    let next = list.keys().max().map_or(1, |m| m + 1);
    let already = list.values().any(|v| v.eq_ignore_ascii_case(hardware_id));
    let list_key = format!("{RESTRICTIONS_KEY}\\DenyDeviceIDs");
    let mut planned = live
        .clone()
        .with(RESTRICTIONS_KEY, "DenyDeviceIDs", RegData::Dword(1));
    let mut expected = vec![reg_line("DenyDeviceIDs", &RegData::Dword(1))];
    if !already {
        let entry = RegData::Sz(hardware_id.to_string());
        expected.push(reg_line(&format!("DenyDeviceIDs\\{next}"), &entry));
        planned = planned.with(&list_key, &next.to_string(), entry);
    }
    if retroactive {
        planned = planned.with(
            RESTRICTIONS_KEY,
            "DenyDeviceIDsRetroactive",
            RegData::Dword(1),
        );
        expected.push(reg_line("DenyDeviceIDsRetroactive", &RegData::Dword(1)));
    }
    (planned, expected)
}

/// Build the checklist for preventing installation of `instance_id`.
///
/// # Errors
/// See [`ChecklistError`].
pub fn device_deny_checklist(
    snapshot: &DeviceSnapshot,
    policy: &ValidatedPolicy,
    catalog: &ValidatedCatalog,
    live: &PolicySnapshot,
    instance_id: &str,
    retroactive: bool,
) -> Result<PolicyChecklist, ChecklistError> {
    use rustward_core::classify::DeviceCategory;
    let decisions = evaluate_snapshot(snapshot, policy, catalog);
    let is_usb_storage = |id: &str| {
        decisions.iter().any(|d| {
            d.instance_id == id
                && matches!(
                    d.classification.category,
                    DeviceCategory::UsbStorageDisk { .. }
                )
        })
    };
    let record = snapshot
        .devices
        .iter()
        .find(|r| r.instance_id == instance_id)
        .ok_or(ChecklistError::DeviceNotFound)?;
    if !is_usb_storage(instance_id) {
        return Err(ChecklistError::NotUsbStorage);
    }
    let hardware_id = record
        .hardware_ids
        .first()
        .cloned()
        .ok_or_else(|| ChecklistError::NoSpecificHardwareId("none".into()))?;
    let upper = hardware_id.to_ascii_uppercase();
    let specific = (upper.starts_with("USBSTOR\\DISK") || upper.starts_with("SCSI\\DISK"))
        && upper.len() > "USBSTOR\\DISK".len() + 8
        && !GENERIC.contains(&upper.as_str());
    if !specific {
        return Err(ChecklistError::NoSpecificHardwareId(hardware_id));
    }

    // Model the change.
    let list = live.list("DenyDeviceIDs");
    let (planned, expected) = planned_deny_policy(live, &hardware_id, retroactive);

    match evaluate_install(&planned, record) {
        InstallOutcome::Prevented { .. } => {}
        InstallOutcome::Allowed { rule } => {
            return Err(ChecklistError::WouldNotBePrevented(format!(
                "{}: {}",
                rule.list, rule.entry
            )));
        }
        InstallOutcome::NotRestricted => {
            return Err(ChecklistError::WouldNotBePrevented("no match".into()));
        }
    }
    let mut affected = Vec::new();
    let mut outside = Vec::new();
    for r in &snapshot.devices {
        let newly = matches!(
            evaluate_install(&planned, r),
            InstallOutcome::Prevented { .. }
        ) && !matches!(evaluate_install(live, r), InstallOutcome::Prevented { .. });
        if newly {
            let name = r
                .friendly_name
                .clone()
                .unwrap_or_else(|| r.instance_id.clone());
            if is_usb_storage(&r.instance_id) {
                affected.push(name);
            } else {
                outside.push(name);
            }
        }
    }
    if !outside.is_empty() {
        return Err(ChecklistError::AffectsNonUsbStorage(outside));
    }

    let installed = record.service.as_deref().is_some_and(|s| !s.is_empty())
        && !matches!(record.problem_code, Some(1 | 28));
    let decision = decisions.iter().find(|d| d.instance_id == instance_id);
    let vid_pid = decision
        .and_then(|d| d.classification.usb_ancestor.as_ref())
        .map(|a| format!("{:04X}:{:04X}", a.ids.vid, a.ids.pid));

    let mut existing = Vec::new();
    for name in [
        "DenyDeviceIDs",
        "DenyDeviceIDsRetroactive",
        "AllowDeviceIDs",
        "DenyInstanceIDs",
        "AllowInstanceIDs",
        "DenyDeviceClasses",
        "AllowDeviceClasses",
        "AllowDenyLayered",
        "AllowAdminInstall",
    ] {
        existing.push(match live.dword(name) {
            Some(v) => format!("{name} = {v}"),
            None => format!("{name}: yapılandırılmamış"),
        });
    }
    for (i, v) in &list {
        existing.push(format!("DenyDeviceIDs\\{i} = \"{v}\""));
    }
    let policy_was_configured = live.dword("DenyDeviceIDs") == Some(1) || !list.is_empty();

    let mut risks = vec![
        format!("Bu kimlik bu modelin ve revizyonun TÜM birimleriyle eşleşir, yalnızca bu tek cihazla değil: {hardware_id}"),
        "Donanım kimlikleri doğrulanmaz: başka bir cihaz aynı satıcı/ürün dizesini bildirebilir.".to_string(),
        "Bu, tek bir cihaz modelini hedefleyen bir kuraldır; üreticiye dayalı varsayılan ret değildir.".to_string(),
        "Önce bir sanal makine anlık görüntüsü veya sistem geri yükleme noktası alın.".to_string(),
    ];
    if retroactive && installed {
        risks.push("Geriye dönük seçenek: Windows kurulu cihazı hemen kaldırır, birimleri (sürücü harfleri) kaybolur. Önce cihazdaki açık dosyaları kapatın.".into());
    }
    if !retroactive && installed {
        risks.push("Geriye dönük seçenek kapalı: cihaz zaten kurulu olduğu için ERİŞİLEBİLİR KALIR; yalnızca yeni kurulum engellenir.".into());
    }
    if affected.len() > 1 {
        risks.push(format!(
            "Envanterde bu kuraldan etkilenecek {} cihaz var: {}",
            affected.len(),
            affected.join(", ")
        ));
    }
    if live.dword("AllowAdminInstall") == Some(1) {
        risks.push("\"Yöneticilerin Aygıt Yükleme Kısıtlaması ilkelerini geçersiz kılmasına izin ver\" etkin: yöneticiler bu engeli aşabilir.".into());
    }
    if live.dword("DenyDeviceIDsRetroactive") == Some(1) && !retroactive {
        risks.push(
            "Mevcut ayarda geriye dönük seçenek zaten açık; onay kutusu tüm listeye uygulanır."
                .into(),
        );
    }

    let mut steps = vec![
        format!("gpedit.msc açın: {PATH_TR}"),
        format!("\"{POLICY_TR}\" ({POLICY_EN}) ilkesini açın."),
        "Mevcut ayarın aşağıdaki \"Mevcut yapılandırma\" ile aynı olduğunu doğrulayın.".to_string(),
        "\"Etkin\" seçin; \"Göster...\" listesine yalnızca şu satırı ekleyin (Aygıt Yöneticisi > Ayrıntılar > Donanım kimlikleri > ilk satır > Kopyala):".to_string(),
        format!("    {hardware_id}"),
    ];
    steps.push(if retroactive {
        format!("\"{RETRO_TR}\" kutusunu İŞARETLEYİN.")
    } else {
        format!("\"{RETRO_TR}\" kutusunu İŞARETLEMEYİN.")
    });
    steps.push("Tamam; ardından yönetici komut isteminde: gpupdate /force".into());
    steps.push("RustWard > Uygulama Hazırlığı > Gerçek Windows gözlemi bölümünü yenileyin.".into());

    let mut rollback = vec![if policy_was_configured {
        "İlkeyi açın; \"Göster...\" listesinden YALNIZCA bu satırı silin; onay kutusunu önceki haline getirin.".to_string()
    } else {
        "İlkeyi açın ve \"Yapılandırılmadı\" seçin.".to_string()
    }];
    rollback.push("gpupdate /force çalıştırın.".into());
    rollback
        .push("RustWard'da bu cihaz için \"Kural uygulanmamış\" göründüğünü doğrulayın.".into());
    rollback.push("Cihazı çıkarıp yeniden takın; Aygıt Yöneticisi'nde \"Bu aygıt düzgün çalışıyor\" ve sürücü harflerinin geri geldiğini doğrulayın.".into());

    let mut verification = vec![];
    if retroactive && installed {
        verification.push("Aygıt Yöneticisi: \"Aygıt düzgün olarak yapılandırılmadı (Kod 1)\" ve \"Bu aygıtın yüklenmesi sistem ilkesiyle yasaklanmıştır\".".to_string());
        verification.push(
            "Cihaz yeniden bağlandığında: \"Bu aygıtın sürücüleri yüklenmemiş (Kod 28)\"."
                .to_string(),
        );
    } else if installed {
        verification.push("Cihaz kurulu kaldığı için çalışmaya devam eder; RustWard \"Kural eşleşiyor, cihaz erişilebilir\" gösterir.".to_string());
    } else {
        verification.push("Cihaz bağlandığında: \"Bu aygıtın sürücüleri yüklenmemiş (Kod 28)\" ve \"sistem ilkesiyle yasaklanmıştır\".".to_string());
    }
    verification
        .push("Bu bilgisayar ve Disk Yönetimi: cihazın diski ve sürücü harfleri yok.".into());
    verification.push("RustWard: WINDOWS_INSTALL_DENIED + WINDOWS_ACCESS_NOT_VERIFIED (okuma/yazma yolları ayrıca test edilmez).".into());
    verification.push("Diğer USB depolama cihazları, iç disk, klavye ve fare etkilenmez.".into());

    Ok(PolicyChecklist {
        device_name: record
            .friendly_name
            .clone()
            .unwrap_or_else(|| record.instance_id.clone()),
        vid_pid,
        hardware_id,
        policy_name_en: POLICY_EN.into(),
        policy_name_tr: POLICY_TR.into(),
        policy_path_en: PATH_EN.into(),
        policy_path_tr: PATH_TR.into(),
        retroactive,
        device_installed: installed,
        existing,
        expected_registry: expected,
        affected_devices: affected,
        steps,
        risks,
        rollback,
        verification,
    })
}

impl PolicyChecklist {
    /// Plain-text rendering for copying or saving.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        let section = |s: &mut String, title: &str, lines: &[String]| {
            s.push_str(title);
            s.push('\n');
            for l in lines {
                s.push_str("- ");
                s.push_str(l);
                s.push('\n');
            }
            s.push('\n');
        };
        s.push_str("RustWard - Yönetici Grup İlkesi kontrol listesi (RustWard bu değişikliği UYGULAMAZ)\n\n");
        s.push_str(&format!(
            "Cihaz: {} ({})\nDonanım kimliği: {}\nİlke: {} / {}\nYol: {}\nGeriye dönük: {}\n\n",
            self.device_name,
            self.vid_pid.as_deref().unwrap_or("VID:PID yok"),
            self.hardware_id,
            self.policy_name_tr,
            self.policy_name_en,
            self.policy_path_tr,
            if self.retroactive { "evet" } else { "hayır" }
        ));
        section(&mut s, "Mevcut yapılandırma:", &self.existing);
        section(&mut s, "Adımlar:", &self.steps);
        section(
            &mut s,
            "Beklenen kayıt defteri değerleri (Grup İlkesi yazar):",
            &self.expected_registry,
        );
        section(
            &mut s,
            "Etkilenecek cihazlar (envanter):",
            &self.affected_devices,
        );
        section(&mut s, "Riskler:", &self.risks);
        section(&mut s, "Geri alma:", &self.rollback);
        section(&mut s, "Beklenen doğrulama sonuçları:", &self.verification);
        s
    }
}

/// Group Policy setting: (Turkish name, English name, how to fill it in).
type Setting = (&'static str, &'static str, &'static str);

/// Group Policy setting for one registry value of the default-deny profile.
fn profile_setting(value_name: &str, sub: &str) -> Setting {
    match (value_name, sub) {
        ("AllowDenyLayered", _) => (
            "Aygıt yükleme ve engelleme ilkeleri için katmanlı değerlendirme sırası uygula",
            "Apply layered order of evaluation for Allow and Prevent device installation policies across all device match criteria",
            "Etkin / Enabled",
        ),
        ("DenyDeviceClasses" | "DenyDeviceClassesRetroactive", _) | (_, "DenyDeviceClasses") => (
            "Bu aygıt kurulum sınıflarıyla eşleşen sürücüleri kullanan aygıtların yüklenmesini engelle",
            "Prevent installation of devices using drivers that match these device setup classes",
            "Etkin; \"Zaten yüklü olan eşleşen aygıtlara da uygula\" İŞARETLENMEZ / Enabled; \"Also apply to matching devices that are already installed\" UNCHECKED",
        ),
        ("AllowDeviceIDs", _) | (_, "AllowDeviceIDs") => (
            "Bu aygıt kimliklerinden herhangi biriyle eşleşen aygıtların yüklenmesine izin ver",
            "Allow installation of devices that match any of these device IDs",
            "Etkin / Enabled",
        ),
        ("AllowInstanceIDs", _) | (_, "AllowInstanceIDs") => (
            "Bu aygıt örneği kimliklerinden herhangi biriyle eşleşen aygıtların yüklenmesine izin ver",
            "Allow installation of devices that match any of these device instance IDs",
            "Etkin / Enabled",
        ),
        _ => ("(bilinmeyen ayar)", "(unknown setting)", ""),
    }
}

/// Administrator checklist for the **default-deny profile** (layered
/// Device Installation Restrictions). Text only: nothing is applied.
///
/// `not_covered` lists already-installed devices the profile does not
/// affect (the class rule is never retroactive).
#[must_use]
pub fn default_deny_profile_text(
    changes: &[crate::PlannedChange],
    not_covered: &[String],
) -> String {
    use std::fmt::Write as _;
    let mut groups: Vec<(Setting, Vec<String>)> = Vec::new();
    for c in changes {
        let sub = c
            .key
            .strip_prefix(RESTRICTIONS_KEY)
            .unwrap_or("")
            .trim_start_matches('\\');
        let setting = profile_setting(&c.value_name, sub);
        let entry = if sub.is_empty() {
            format!("{} = {} {}", c.value_name, c.value_type, c.data)
        } else {
            format!("{sub}\\{} = {}", c.value_name, c.data)
        };
        match groups.iter_mut().find(|(s, _)| s.0 == setting.0) {
            Some((_, v)) => v.push(entry),
            None => groups.push((setting, vec![entry])),
        }
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "VARSAYILAN RET PROFİLİ — YÖNETİCİ KONTROL LİSTESİ (yalnızca test sanal makinesi)\n\
         DEFAULT-DENY PROFILE — ADMINISTRATOR CHECKLIST (test virtual machine only)\n\n\
         RustWard bu ayarları uygulamaz. Önce VMware anlık görüntüsü alın.\n\
         RustWard does not apply these settings. Take a VMware snapshot first.\n\n\
         gpedit.msc > Bilgisayar Yapılandırması > Yönetim Şablonları > Sistem > Aygıt Yükleme > Aygıt Yükleme Kısıtlamaları\n\
         Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions\n"
    );
    for (i, ((tr, en, how), entries)) in groups.iter().enumerate() {
        let _ = writeln!(s, "{}. {tr}\n   {en}\n   {how}", i + 1);
        for e in entries {
            let _ = writeln!(s, "   - {e}");
        }
        s.push('\n');
    }
    let _ = writeln!(
        s,
        "Sonra yönetici komut isteminde: gpupdate /force — ardından RustWard'da \"Uygulamayı doğrula\".\n\
         Then in an administrator command prompt: gpupdate /force — then \"Verify application\" in RustWard.\n\n\
         Geri alma: yukarıdaki ayarların tümünü \"Yapılandırılmadı\" yapın, gpupdate /force, \"Geri almayı doğrula\".\n\
         Rollback: set every setting above to \"Not Configured\", gpupdate /force, \"Verify rollback\".\n"
    );
    let _ = writeln!(
        s,
        "SINIRLAR / LIMITS\n\
         - Sınıf kuralı geriye dönük DEĞİLDİR: zaten kurulu cihazlar erişilebilir kalır.\n  The class rule is NOT retroactive: already-installed devices stay accessible.\n\
         - Eşleşme cihazın kendi bildirdiği kimlik dizelerine dayanır; kimlik doğrulaması yoktur.\n  Matching relies on identity strings the device reports about itself; nothing is authenticated.\n\
         - Kurulum reddi, okuma/yazma engelinin kanıtı değildir.\n  An installation denial is not proof of a read/write denial.\n\
         - Yeni eklenen her dahili veya sanal disk de (izin listesinde değilse) engellenir.\n  Any newly added internal or virtual disk not on the allow list is blocked too."
    );
    if !not_covered.is_empty() {
        let _ = writeln!(
            s,
            "\nPROFİLİN ETKİLEMEDİĞİ, ZATEN KURULU VE POLİTİKANIN REDDETTİĞİ CİHAZLAR\nALREADY-INSTALLED DEVICES THE POLICY DENIES BUT THE PROFILE DOES NOT AFFECT"
        );
        for d in not_covered {
            let _ = writeln!(s, "   - {d}");
        }
    }
    s
}
