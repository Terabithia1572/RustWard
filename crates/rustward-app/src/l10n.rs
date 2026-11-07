//! Turkish rendering of user-facing backend text.
//!
//! The backend keeps English as the technical/stored language (audit records
//! are never rewritten). Every user-facing text gets a Turkish counterpart
//! here, derived from stable codes (issue codes, event kinds, change actions,
//! error codes) and the structured values in the English template. Technical
//! identifiers (USBSTOR IDs, VID/PID, registry names, codes) are kept as is.
//!
//! Anything this module cannot translate is returned with [`UNTRANSLATED`]
//! in front, so tests can prove that no English text reaches the Turkish UI.

use rustward_ipc::{ErrorCode, IpcError};
use rustward_storage::SecurityEvent;

/// Marker for text that has no Turkish rendering (tests fail on it).
pub const UNTRANSLATED: &str = "[çevrilmedi] ";

/// Brand id -> display name (current catalog; falls back to the id).
pub type Names<'a> = &'a dyn Fn(&str) -> String;

/// Quoted (`{:?}`) values in an English template, in order.
fn quoted(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    let mut esc = false;
    for c in s.chars() {
        if inside {
            if esc {
                cur.push(c);
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                out.push(std::mem::take(&mut cur));
                inside = false;
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            inside = true;
        }
    }
    out
}

/// Numbers in a text, in order.
fn numbers(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn nth(v: &[String], i: usize) -> &str {
    v.get(i).map_or("?", String::as_str)
}

fn technical(tr: &str, en: &str) -> String {
    format!("{tr} (Teknik ayrıntı: {en})")
}

/// Fixed and templated sentences (risks, gaps, notices, status lines,
/// feature lists). Returns the marked English text when unknown.
#[must_use]
pub fn text(en: &str) -> String {
    let t = |s: &str| s.to_string();
    let n = numbers(en);
    let q = quoted(en);
    let out = match en {
        "SIMULATION ONLY — enforcement is NOT ACTIVE." => {
            t("YALNIZCA SİMÜLASYON: RustWard uygulaması ETKİN DEĞİL.")
        }
        "RustWard service running" => t("RustWard hizmeti çalışıyor."),
        "development backend (in-process, not the Windows service)" => {
            t("Geliştirme arka ucu (uygulama içi; Windows hizmeti değil).")
        }
        "Policy unavailable; no plan can be computed." => {
            t("Politika kullanılamıyor; plan hesaplanamaz.")
        }
        "No OS mechanism selected: nothing can be enforced." => {
            t("İşletim sistemi mekanizması seçilmedi: hiçbir şey uygulanamaz.")
        }
        "Feature updates and storage-controller driver changes re-detect hardware; with a DiskDrive prevent rule the boot disk may be blocked (community-reported BSOD/Startup Repair). Suspend the policy during maintenance." => {
            t(
                "Özellik güncellemeleri ve depolama denetleyicisi sürücü değişiklikleri donanımı yeniden algılar; DiskDrive engelleme kuralıyla önyükleme diski engellenebilir (topluluk tarafından bildirilen mavi ekran/Başlangıç Onarımı). Bakım sırasında politikayı askıya alın.",
            )
        }
        "New internal disks, VHD/VHDX mounts, Storage Spaces and iSCSI disks are blocked until allowed." => {
            t(
                "Yeni dahili diskler, VHD/VHDX bağlamaları, Depolama Alanları ve iSCSI diskleri izin verilene kadar engellenir.",
            )
        }
        "A device reporting an approved INQUIRY vendor string is allowed even if not genuine (identifiers are not authenticated)." => {
            t(
                "Onaylı bir INQUIRY satıcı dizesi bildiren cihaz, gerçek olmasa bile izin alır (kimlikler doğrulanmaz).",
            )
        }
        "A local administrator can remove the policy; operators must be standard users." => t(
            "Yerel bir yönetici politikayı kaldırabilir; operatörler standart kullanıcı olmalıdır.",
        ),
        "some allow rules come from identifiers that are not lab-verified" => {
            t("Bazı izin kuralları laboratuvarda doğrulanmamış kimliklerden gelir.")
        }
        "SCSI\\Disk<vendor> allow rules also match internal/virtual disks with the same INQUIRY vendor; UASP enumeration must be validated on hardware" => {
            t(
                "SCSI\\Disk<satıcı> izin kuralları aynı INQUIRY satıcısına sahip dahili/sanal disklerle de eşleşir; UASP numaralandırması donanım üzerinde doğrulanmalıdır.",
            )
        }
        "no baseline snapshot supplied: existing system disks are not protected by instance-ID allow rules" => {
            t(
                "Temel envanter verilmedi: mevcut sistem diskleri örnek kimliği izin kurallarıyla korunmuyor.",
            )
        }
        "devices installed before the policy (including non-present ones) are NOT affected by install restrictions; a reviewed baseline cleanup is required (Phase 2)" => {
            t(
                "Politikadan önce kurulmuş cihazlar (bağlı olmayanlar dahil) kurulum kısıtlamalarından ETKİLENMEZ; incelenmiş bir temel temizlik gerekir (2. aşama).",
            )
        }
        "scope decisions pending: USB CD/DVD (CDROM class) and MTP/PTP (WPD class) are not covered by this plan" => {
            t(
                "Kapsam kararları bekliyor: USB CD/DVD (CDROM sınıfı) ve MTP/PTP (WPD sınıfı) bu planın kapsamında değil.",
            )
        }
        _ => String::new(),
    };
    if !out.is_empty() {
        return out;
    }
    if let Some(rest) = en.strip_prefix("inventory error: ") {
        return technical("Envanter hatası.", rest);
    }
    if en.starts_with("allowed brand ")
        && en.ends_with("contributes no allow rule; its devices will be blocked")
    {
        return format!(
            "İzin verilen \"{}\" markası hiçbir izin kuralı üretmiyor; cihazları engellenir.",
            nth(&q, 0)
        );
    }
    if en.starts_with("brand ") && q.len() == 1 && en.contains("\": ") {
        return technical(
            &format!("\"{}\" markası için kural üretilemedi.", nth(&q, 0)),
            en,
        );
    }
    if en.starts_with("inventory refreshed: ") {
        return format!(
            "Envanter yenilendi: {} cihaz kayıtlı, {} yeni, {} çıkarıldı.",
            nth(&n, 0),
            nth(&n, 1),
            nth(&n, 2)
        );
    }
    if en.starts_with("SYNTHETIC inventory loaded: ") {
        return format!("SENTETİK envanter yüklendi: {} cihaz kayıtlı.", nth(&n, 0));
    }
    if en.ends_with(" events removed by retention") {
        return format!("Saklama süresi nedeniyle {} olay silindi.", nth(&n, 0));
    }
    if let Some(rest) = en.strip_prefix("backup created: ") {
        return format!("Yedek oluşturuldu: {rest}");
    }
    if en.starts_with("backup ") && en.contains(" applied as policy v") {
        let file = en
            .trim_start_matches("backup ")
            .split(" applied")
            .next()
            .unwrap_or("?");
        let saved = en.rsplit("saved as ").next().unwrap_or("?");
        return format!(
            "{file} yedeği politika v{} olarak uygulandı; önceki durum {saved} olarak kaydedildi.",
            n.iter()
                .rev()
                .find(|x| en.contains(&format!("policy v{x}")))
                .map_or("?", String::as_str)
        );
    }
    if en.starts_with("policy restored from backup ") {
        let file = en
            .trim_start_matches("policy restored from backup ")
            .split(" (backup v")
            .next()
            .unwrap_or("?");
        return format!(
            "Politika {file} yedeğinden (yedek v{}) v{} olarak geri yüklendi.",
            nth(&n, n.len().saturating_sub(2)),
            n.last().map_or("?", String::as_str)
        );
    }
    for (prefix, tr) in [
        (
            "manufacturer added to catalog: ",
            "Kataloğa eklenecek üretici: ",
        ),
        (
            "manufacturer removed from catalog: ",
            "Katalogdan çıkarılacak üretici: ",
        ),
        (
            "manufacturer definition changed: ",
            "Tanımı değişecek üretici: ",
        ),
        ("would be ALLOWED: ", "İZİN VERİLECEK: "),
        ("would no longer be allowed: ", "Artık izin verilmeyecek: "),
        ("workstation id: ", "İş istasyonu kimliği: "),
        ("policy mode: ", "Politika modu: "),
    ] {
        if let Some(rest) = en.strip_prefix(prefix) {
            return format!("{tr}{rest}");
        }
    }
    if en
        == "application settings differ (theme, language, notifications, retention or refresh interval)"
    {
        return "Uygulama ayarları farklı (tema, dil, bildirimler, saklama süresi veya yenileme aralığı).".into();
    }
    if en.starts_with("Nothing has been changed yet. Applying stores") {
        return format!(
            "Henüz hiçbir şey değiştirilmedi. Uygulama, yedeğin politikasını ve ayarlarını YENİ politika v{} olarak kaydeder; önceki sürümler, değişiklik geçmişi ve denetim kaydı korunur, önce geri yükleme öncesi bir yedek alınır ve hiçbir işletim sistemi politikası değiştirilmez (uygulama devre dışı).",
            nth(&n, 0)
        );
    }
    format!("{UNTRANSLATED}{en}")
}

/// Validation issue (catalog or policy) by its stable code.
#[must_use]
pub fn issue(code: &str, detail: &str, names: Names<'_>) -> String {
    let q = quoted(detail);
    let n = numbers(detail);
    let brand = || names(nth(&q, 0));
    match code {
        "brand_not_enforceable" => format!(
            "{} için uygulanabilir donanım kimliği bulunamadı. Bu markaya ait cihazlar henüz güvenilir şekilde tanımlanamadığından erişim izni verilemez.",
            brand()
        ),
        "identifier_unverified" => format!(
            "{} markasının donanım kimlikleri henüz gerçek cihaz üzerinde doğrulanmadı.",
            brand()
        ),
        "alias_generic" => format!(
            "{}: \"{}\" takma adı ayrılmış genel bir satıcı adıdır; bir markayı tanımlamaz.",
            brand(),
            nth(&q, 1)
        ),
        "alias_shared" => format!(
            "\"{}\" adı birden fazla marka tarafından kullanılıyor ({}); bu ada dayalı ipuçları belirsizdir.",
            nth(&q, 0),
            q.iter()
                .skip(1)
                .map(|b| names(b))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "usb_vid_shared" => format!(
            "USB VID {} birden fazla marka için listelenmiş: {}.",
            detail.split_whitespace().nth(2).unwrap_or("?"),
            q.iter().map(|b| names(b)).collect::<Vec<_>>().join(", ")
        ),
        "schema_version" => format!("Desteklenmeyen şema sürümü {}.", nth(&n, 0)),
        "catalog_version" => "Katalog sürümü boş olamaz.".into(),
        "workstation_id" => format!(
            "İş istasyonu kimliği \"{}\" yalnızca harf, rakam, '_' ve '-' içerebilir (1-64 karakter).",
            nth(&q, 0)
        ),
        "policy_version" => "Politika sürümü en az 1 olmalıdır.".into(),
        "catalog_version_mismatch" => format!(
            "Politika \"{}\" kataloğunu hedefliyor ancak yüklü katalog \"{}\".",
            nth(&q, 0),
            nth(&q, 1)
        ),
        "brand_rule_duplicate" => format!("{} birden fazla kez listelenmiş.", brand()),
        "brand_rule_conflict" => format!(
            "{} hem izinli hem reddedilen olarak listelenmiş; kurallardan birini kaldırın.",
            brand()
        ),
        "brand_unknown" => format!("\"{}\" markası katalogda yok.", nth(&q, 0)),
        "brand_id" => format!(
            "Marka kimliği \"{}\" yalnızca küçük harf, rakam ve '-' içerebilir (1-32 karakter).",
            nth(&q, 0)
        ),
        "brand_id_duplicate" => format!("Yinelenen marka kimliği \"{}\".", nth(&q, 0)),
        "display_name" => format!("{} markasının görünen adı yok.", nth(&q, 0)),
        "identifier_source" => format!(
            "{}: \"{}\" kimliğinin kaynağı belirtilmemiş.",
            brand(),
            nth(&q, 1)
        ),
        "inquiry_vendor_invalid" => technical(
            &format!("{}: geçersiz INQUIRY satıcı değeri.", brand()),
            detail,
        ),
        "inquiry_vendor_generic" => format!(
            "{}: INQUIRY satıcısı \"{}\" ayrılmış genel bir değerdir ve bir markayı tanımlayamaz.",
            brand(),
            nth(&q, 1)
        ),
        "inquiry_vendor_ambiguous" => format!(
            "INQUIRY satıcısı \"{}\" hem {} hem {} tarafından talep ediliyor.",
            nth(&q, 0),
            names(nth(&q, 1)),
            names(nth(&q, 2))
        ),
        "usb_vid_invalid" => format!(
            "{}: \"{}\" 4 haneli onaltılık bir VID değil.",
            brand(),
            nth(&q, 1)
        ),
        "json" => technical("Veri JSON olarak okunamadı.", detail),
        _ => format!("{UNTRANSLATED}{code}: {detail}"),
    }
}

/// Policy change summary by its stable action code.
#[must_use]
pub fn change(action: &str, brand_id: &str, summary_en: &str, names: Names<'_>) -> String {
    let name = names(brand_id);
    match action {
        "manufacturer_added" | "add_manufacturer" if summary_en.ends_with("and allowed") => {
            format!("{name} üreticisi eklendi ve izin verilenler listesine alındı.")
        }
        "manufacturer_added" | "add_manufacturer" => format!("{name} üreticisi eklendi."),
        "manufacturer_updated" | "update_manufacturer" => format!("{name} üreticisi güncellendi."),
        "manufacturer_removed" | "remove_manufacturer" => format!("{name} üreticisi kaldırıldı."),
        "allowlist_changed" | "set_allowed" if summary_en.contains("added to") => {
            format!("{name} izin verilen üreticiler listesine eklendi.")
        }
        "allowlist_changed" | "set_allowed" => {
            format!("{name} izin verilen üreticiler listesinden çıkarıldı.")
        }
        "denylist_changed" | "set_denied" if summary_en.contains("added to") => {
            format!("{name} açıkça reddedilen üreticiler listesine eklendi.")
        }
        "denylist_changed" | "set_denied" => {
            format!("{name} açıkça reddedilen üreticiler listesinden çıkarıldı.")
        }
        "rule_enabled_changed" | "set_rule_enabled" if summary_en.ends_with("enabled") => {
            format!("{name} için izin kuralı etkinleştirildi.")
        }
        "rule_enabled_changed" | "set_rule_enabled" => {
            format!("{name} için izin kuralı devre dışı bırakıldı.")
        }
        "workstation_id_changed" | "set_workstation_id" => {
            let q = quoted(summary_en);
            format!(
                "İş istasyonu kimliği \"{}\" yerine \"{}\" olarak değiştirildi.",
                nth(&q, 0),
                nth(&q, 1)
            )
        }
        "policy_restored" | "initialize" | "restore" => text(summary_en),
        _ => format!("{UNTRANSLATED}{summary_en}"),
    }
}

fn category(code: &str) -> &'static str {
    match code {
        "usb_storage_disk" => "USB depolama diski",
        "usb_storage_other_type" => "USB depolama (diğer tür)",
        "usb_storage_interface" => "USB depolama arabirimi",
        "usb_portable_device" => "USB taşınabilir aygıt",
        "storage_attachment_unknown" => "bağlantı türü bilinmeyen disk",
        "system_or_non_usb_storage" => "sistem veya USB dışı depolama",
        "peripheral" => "çevre birimi",
        _ => "diğer",
    }
}

fn by_actor(actor: &str) -> String {
    format!("{actor} tarafından")
}

/// Turkish rendering of an audit event (the stored English record is kept).
#[must_use]
pub fn event(e: &SecurityEvent, names: Names<'_>) -> String {
    let m = e.message.as_str();
    let n = numbers(m);
    let q = quoted(m);
    let d = &e.details;
    let s = |k: &str| {
        d.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let after = |sep: &str| m.rsplit(sep).next().unwrap_or("").to_string();
    match e.kind.as_str() {
        "service_started" => "RustWard hizmet döngüsü başlatıldı.".into(),
        "service_stopping" => "RustWard hizmet döngüsü durduruluyor.".into(),
        "service_degraded" => "Envanter yenileme art arda başarısız oldu; cihaz algılama zayıfladı (uygulama durumu değişmedi, hâlâ doğrulanmadı).".into(),
        "service_recovered" => "Envanter yenileme yeniden çalışıyor.".into(),
        "backend_started" => format!(
            "RustWard arka ucu başlatıldı ({}).",
            if m.contains("windows_service") { "Windows hizmeti" } else { "geliştirme arka ucu" }
        ),
        "ipc_error" => technical("Adlandırılmış kanal (IPC) hatası.", m),
        "event_log_unavailable" => technical("Windows Olay Günlüğü kullanılamıyor.", m),
        "device_notifications_unavailable" => technical("Aygıt değişikliği bildirimleri kullanılamıyor; düzenli envanter yenilemeye geçildi.", m),
        "service_start_failed" => technical("Hizmet başlatılamadı.", m),
        "event_log_backfill_skipped" => format!(
            "{} denetim kaydı (kimlik {}..={}) Windows Olay Günlüğü'ne kopyalanmadı; RustWard veritabanında duruyor.",
            nth(&n, 0),
            nth(&n, 1),
            nth(&n, 2)
        ),
        "ipc_shutdown_incomplete" => technical("Adlandırılmış kanal kapatma işlemi süresinde tamamlanamadı.", m),
        "device_detected" => {
            let label = m.split(" detected (").next().unwrap_or(m);
            format!(
                "{label} algılandı ({}){}.",
                category(&s("category")),
                if m.ends_with("[SYNTHETIC]") { " [SENTETİK]" } else { "" }
            )
        }
        "device_removed" => format!("{} çıkarıldı.", m.trim_end_matches(" removed")),
        "device_reenumerated" => "USB aygıtı aynı bağlantı noktasında yeniden numaralandırıldı (örneğin şifreli sürücünün kilidi açıldı); yeni aygıt ayrıca değerlendirilir.".into(),
        "decision_simulated" => {
            let label = m.split(": ").next().unwrap_or(m);
            let summary = s("summary_tr");
            if summary.is_empty() {
                format!("{UNTRANSLATED}{m}")
            } else {
                format!("{label}: {summary} RustWard uygulaması ETKİN DEĞİL.")
            }
        }
        "decisions_reevaluated" => format!(
            "Simülasyon kararları politika v{} altında yeniden değerlendirildi; {} karar değişti.",
            nth(&n, 0),
            nth(&n, 1)
        ),
        "inventory_failed" => technical("Aygıt envanteri alınamadı.", m),
        "inventory_warnings" => format!("{} aygıt özelliği okunamadı.", nth(&n, 0)),
        "policy_initialized" => format!(
            "Politika v{}, {} için {} başlatıldı.",
            nth(&n, 0),
            m.split(" initialized for ").nth(1).and_then(|x| x.split(" by ").next()).unwrap_or("?"),
            by_actor(&after(" by "))
        ),
        "policy_changed" => {
            let summary = m.rsplit_once(" (by ").map_or(m, |(a, _)| a);
            let actor = m.rsplit_once(" (by ").map_or("?", |(_, b)| b.trim_end_matches(')'));
            let action = s("action");
            let brand = s("brand_id");
            let body = if action.is_empty() {
                change_from_text(summary, names)
            } else {
                change(&action, &brand, summary, names)
            };
            format!("{} ({})", body.trim_end_matches('.'), by_actor(actor))
        }
        "settings_changed" => format!("Ayarlar {} değiştirildi.", by_actor(&after(" by "))),
        "authorization_failed" => {
            let request = s("request");
            if m.contains("could not be identified") {
                technical(&format!("\"{request}\" isteği reddedildi: çağıran kimliği belirlenemedi."), m)
            } else {
                technical(&format!("\"{request}\" isteği yetki nedeniyle reddedildi."), m)
            }
        }
        "database_restored" => technical("Veritabanı geri yüklendi.", m),
        "backup_created" => format!(
            "{} yedeği oluşturuldu: {} ({}).",
            if m.starts_with("pre_restore") { "Geri yükleme öncesi" } else if m.starts_with("manual") { "Elle" } else { "Otomatik" },
            s("file_name"),
            by_actor(&after(" by "))
        ),
        "retention_applied" => format!("{} günden eski {} olay silindi.", nth(&n, 1), nth(&n, 0)),
        "audit_exported" => format!("{} olay {} dışa aktarıldı.", nth(&n, 0), by_actor(&after(" by "))),
        "restore_prepared" => format!(
            "{} geri yüklemesi (yedek v{}) {} hazırlandı; henüz uygulanmadı.",
            m.trim_start_matches("restore of ").split(" (backup").next().unwrap_or("?"),
            nth(&n, 0),
            by_actor(&after(" by ").replace("; not applied", ""))
        ),
        "restore_failed" => technical("Geri yükleme reddedildi veya başarısız oldu.", m),
        "policy_restored" => {
            let (summary, actor) = m.rsplit_once(" by ").unwrap_or((m, "?"));
            format!("{} ({})", text(summary).trim_end_matches('.'), by_actor(actor))
        }
        "audit_checkpoint" => format!(
            "Denetim kontrol noktası: zincir {}, {} kayıt, baş kayıt #{}, verilen en yüksek kimlik {}.",
            if m.contains("chain intact") { "sağlam" } else { "SORUNLU" },
            nth(&n, 0),
            nth(&n, 1),
            n.last().map_or("?", String::as_str)
        ),
        "audit_gap" | "events_missing" => technical("Denetim kayıtlarında eksik kimlikler var.", m),
        "windows_install_denied_observed" => format!(
            "{}: Windows bu cihazın kurulumunu engelledi (Kod {}), {} girdisi \"{}\". Kanıt: kurulum reddi; okuma/yazma yolları test edilmedi.",
            m.split(": Windows denied").next().unwrap_or("?"),
            d.get("problem_code").and_then(serde_json::Value::as_u64).unwrap_or_default(),
            s("policy_list"),
            s("rule_entry")
        ),
        "windows_install_denial_ended" => format!(
            "{}: daha önce gözlenen Windows kurulum engeli artık gözlenmiyor ({}).",
            m.split(": the earlier").next().unwrap_or("?"),
            match s("reason").as_str() {
                "device not connected" => "cihaz bağlı değil",
                "device installed despite the rule" => "kurala rağmen cihaz kurulu",
                "no matching Windows rule" => "eşleşen Windows kuralı yok",
                _ => "neden bilinmiyor",
            }
        ),
        k if k.starts_with("enforcement_session_") => crate::guided::event_tr(k, m, d),
        _ => {
            let _ = q;
            format!("{UNTRANSLATED}{m}")
        }
    }
}

/// Policy change summary when only the English text is known.
fn change_from_text(summary: &str, names: Names<'_>) -> String {
    let q = quoted(summary);
    let brand = nth(&q, 0);
    let action = if summary.starts_with("workstation id changed") {
        "set_workstation_id"
    } else if summary.contains(" the allowlist") {
        "set_allowed"
    } else if summary.contains(" the denylist") {
        "set_denied"
    } else if summary.starts_with("allowlist rule for") {
        "set_rule_enabled"
    } else if summary.ends_with(" removed") {
        "remove_manufacturer"
    } else if summary.ends_with(" updated") {
        "update_manufacturer"
    } else if summary.contains(" added") {
        "add_manufacturer"
    } else {
        return text(summary);
    };
    change(action, brand, summary, names)
}

/// Turkish message for an IPC error, when the message is a known one.
#[must_use]
pub fn error(e: &IpcError, names: Names<'_>) -> Option<String> {
    let m = e.message.as_str();
    let q = quoted(m);
    let n = numbers(m);
    let exact = match m {
        "backend state lock poisoned" => Some("İç durum kilidi bozuldu; hizmeti yeniden başlatın."),
        "invalid language" => Some("Geçersiz dil seçimi."),
        "invalid theme" => Some("Geçersiz tema seçimi."),
        "device not in the current inventory" => Some("Cihaz geçerli envanterde yok."),
        "no inventory collected yet" => Some("Henüz envanter toplanmadı."),
        "no prepared restore" => Some("Hazırlanmış bir geri yükleme yok."),
        "the service did not answer in time" => Some("Hizmet zamanında yanıt vermedi."),
        "no active policy" => Some("Etkin politika yok."),
        "the edit does not change anything" => Some("Bu düzenleme hiçbir şeyi değiştirmiyor."),
        "backups are not configured on this backend" => {
            Some("Bu arka uçta yedekleme yapılandırılmamış.")
        }
        "this channel accepts read-only requests only" => Some(
            "Bu bağlantı yalnızca salt okunur istekleri kabul eder; işlemi yönetici olarak (yükseltilmiş) başlatılan RustWard ile yapın.",
        ),
        "administrator rights (elevated) are required for this operation" => {
            Some("Bu işlem için yükseltilmiş yönetici hakları gerekir.")
        }
        "another enforcement session is active" => {
            Some("Başka bir yönetici kontrollü uygulama oturumu etkin.")
        }
        "no active enforcement session" => Some("Etkin bir uygulama oturumu yok."),
        "the Windows policy is unchanged; apply the checklist in Group Policy first" => Some(
            "Windows politikası değişmemiş; önce kontrol listesini Grup İlkesi Düzenleyicisi'nde uygulayın.",
        ),
        "the Windows policy differs from the saved baseline; restore it and verify the rollback instead" => {
            Some(
                "Windows politikası kaydedilen önceki durumdan farklı; iptal edilemez. Önce önceki durumu geri yükleyin ve geri almayı doğrulayın.",
            )
        }
        "session_id must be 16 hex characters" => {
            Some("Oturum kimliği 16 onaltılık karakter olmalıdır.")
        }
        "device_key must be 32 hex characters" => {
            Some("Cihaz anahtarı 32 onaltılık karakter olmalıdır.")
        }
        "not a USB storage disk" => Some(
            "Seçilen cihaz bir USB depolama diski değil; kural yalnızca USB depolama diskleri için oluşturulur.",
        ),
        "device not found in the inventory" => Some("Cihaz envanterde bulunamadı."),
        _ => None,
    };
    if let Some(t) = exact {
        return Some(t.into());
    }
    if m.starts_with("manufacturer ") && m.ends_with(" does not exist") {
        return Some(format!("\"{}\" üreticisi bulunamadı.", nth(&q, 0)));
    }
    if m.starts_with("manufacturer id ") && m.ends_with(" already exists") {
        return Some(format!("\"{}\" üretici kimliği zaten var.", nth(&q, 0)));
    }
    if m.starts_with("name ") && m.contains(" conflicts with manufacturer ") {
        return Some(format!(
            "\"{}\" adı {} üreticisiyle çakışıyor.",
            nth(&q, 0),
            names(nth(&q, 1))
        ));
    }
    if let Some(rest) = m.strip_prefix("validation failed: ") {
        let parts: Vec<String> = rest
            .split("; ")
            .map(|p| match p.split_once(": ") {
                Some((code, detail)) => issue(code, detail, names),
                None => format!("{UNTRANSLATED}{p}"),
            })
            .collect();
        return Some(format!("Doğrulama başarısız: {}", parts.join(" ")));
    }
    if let Some(rest) = m.strip_prefix("no specific hardware ID: ") {
        return Some(technical(
            "Cihazın belirli (satıcı + ürün) bir donanım kimliği yok; genel kimliklerle kural oluşturulmaz.",
            rest,
        ));
    }
    if let Some(rest) = m.strip_prefix("the rule would also affect: ") {
        return Some(technical(
            "Kural USB depolama olmayan başka cihazları da etkileyeceği için reddedildi.",
            rest,
        ));
    }
    if let Some(rest) = m.strip_prefix("an existing rule would keep the device allowed: ") {
        return Some(technical(
            "Mevcut bir izin kuralı bu engeli geçersiz kılar.",
            rest,
        ));
    }
    if let Some(rest) = m.strip_prefix("invalid input: ") {
        return Some(technical("Geçersiz giriş.", rest));
    }
    if m.starts_with("policy is at v") && m.contains("prepared for v") {
        return Some(format!(
            "Politika şu anda v{}; değişiklik v{} için hazırlanmıştı. Sayfayı yenileyip tekrar deneyin.",
            nth(&n, 0),
            nth(&n, 1)
        ));
    }
    if m.starts_with("policy version conflict") || m.contains("expected policy version") {
        return Some(format!(
            "Politika bu arada değişti (beklenen v{}, etkin v{}). Sayfayı yenileyip tekrar deneyin.",
            nth(&n, 0),
            nth(&n, 1)
        ));
    }
    if m.starts_with("backup rejected: ") || m.starts_with("backup ") {
        return Some(technical("Yedek reddedildi.", m));
    }
    if m.starts_with("policy not readable: ") {
        return Some(technical("Windows politikası okunamadı.", m));
    }
    match e.code {
        ErrorCode::Unauthorized => Some(technical(
            "Bu işlem için yükseltilmiş yönetici yetkisi gerekir.",
            m,
        )),
        ErrorCode::Internal => Some(technical("Beklenmeyen iç hata.", m)),
        ErrorCode::Unavailable => Some(technical("Hizmet veya kaynak şu anda kullanılamıyor.", m)),
        ErrorCode::InvalidRequest => Some(technical("Geçersiz istek.", m)),
        ErrorCode::NotFound => Some(technical("Kayıt bulunamadı.", m)),
        ErrorCode::Conflict => Some(technical("Çakışma: veriler bu arada değişti.", m)),
        ErrorCode::ValidationFailed => Some(technical("Doğrulama başarısız.", m)),
        ErrorCode::VersionMismatch => Some(technical("Uygulama ve hizmet sürümleri uyumsuz.", m)),
        ErrorCode::NotSupported => Some(technical("Bu işlem desteklenmiyor.", m)),
        ErrorCode::Timeout => Some(technical("Zaman aşımı.", m)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(id: &str) -> String {
        match id {
            "tubitak" => "TÜBİTAK BİLGEM".into(),
            "sandisk" => "SanDisk".into(),
            "kingston" => "Kingston".into(),
            other => other.into(),
        }
    }

    #[test]
    fn examples_from_the_owner_are_rendered_exactly() {
        assert_eq!(
            issue(
                "brand_not_enforceable",
                "brand \"tubitak\" has no enforceable identifier; its devices cannot be recognized and will be denied",
                &names
            ),
            "TÜBİTAK BİLGEM için uygulanabilir donanım kimliği bulunamadı. Bu markaya ait cihazlar henüz güvenilir şekilde tanımlanamadığından erişim izni verilemez."
        );
        assert_eq!(
            issue(
                "identifier_unverified",
                "brand \"sandisk\": identifiers [\"SanDisk\"] are not lab-verified",
                &names
            ),
            "SanDisk markasının donanım kimlikleri henüz gerçek cihaz üzerinde doğrulanmadı."
        );
        assert_eq!(
            change(
                "set_allowed",
                "kingston",
                "manufacturer \"kingston\" removed from the allowlist",
                &names
            ),
            "Kingston izin verilen üreticiler listesinden çıkarıldı."
        );
        assert_eq!(
            change(
                "denylist_changed",
                "kingston",
                "manufacturer \"kingston\" added to the denylist",
                &names
            ),
            "Kingston açıkça reddedilen üreticiler listesine eklendi."
        );
        assert_eq!(
            text("RustWard service running"),
            "RustWard hizmeti çalışıyor."
        );
        assert!(
            text("inventory refreshed: 8 stored devices, 1 arrived, 0 removed")
                .starts_with("Envanter yenilendi: 8")
        );
    }

    #[test]
    fn unknown_text_is_marked_never_silently_english() {
        assert!(text("some new English sentence").starts_with(UNTRANSLATED));
        assert!(issue("new_code", "x", &names).starts_with(UNTRANSLATED));
    }

    #[test]
    fn every_error_code_has_a_turkish_message_keeping_the_technical_detail() {
        for code in [
            ErrorCode::Unauthorized,
            ErrorCode::Internal,
            ErrorCode::Unavailable,
            ErrorCode::InvalidRequest,
            ErrorCode::NotFound,
            ErrorCode::Conflict,
            ErrorCode::ValidationFailed,
            ErrorCode::VersionMismatch,
            ErrorCode::NotSupported,
            ErrorCode::Timeout,
        ] {
            let t = error(&IpcError::new(code, "pipe busy (os error 231)"), &names).unwrap();
            assert!(
                t.contains("Teknik ayrıntı: pipe busy (os error 231)"),
                "{t}"
            );
        }
    }
}
