//! Administrator-guided Windows enforcement session.
//!
//! RustWard does NOT write Group Policy or the registry. This workflow makes
//! the administrator's manual change safe and verifiable:
//!
//! 1. prepare (administrator): pick one USB storage device, check the impact
//!    on every other device (checklist), save the current Windows policy as
//!    the baseline and the exact expected policy, audit both;
//! 2. the administrator applies the checklist in gpedit.msc;
//! 3. verify application (administrator): re-read the policy, require it to
//!    equal the expected policy (nothing else changed), observe the target
//!    device's real Windows state, audit the evidence;
//! 4. the administrator restores the previous configuration;
//! 5. verify rollback (administrator): require the policy to equal the
//!    baseline again, observe the device, audit and close the session.
//!
//! Sessions live in the hash-chained audit log (`enforcement_session_*`).

use std::collections::{BTreeMap, BTreeSet};

use rustward_enforcement::checklist::{device_deny_checklist, planned_deny_policy};
use rustward_enforcement::compound_policy::{
    compile_compound_policy, extract_observed_policy, is_generic_storage_id,
    validate_hardware_id, CompoundPolicyPlanView, ObservedWindowsPolicy,
};
use rustward_enforcement::device_install::RESTRICTIONS_KEY;
use rustward_enforcement::observer::EvidenceLevel;
use rustward_enforcement::policy_state::{PolicySnapshot, RegData};
use rustward_ipc::messages::{
    EnforcementSessionView, LadderStepView, ObservedDeviceView, SessionView, TextTrEn,
};
use rustward_ipc::{ClientIdentity, ErrorCode, IpcError, ResponseBody};
use rustward_storage::{
    ApprovedPolicyRecord, EventFilter, NewEvent, SecurityEvent, Severity, device_key,
    mask_instance_id, sha256_hex,
};

use super::{AppService, Inner, edit_err, empty_snapshot, storage_err};

const PREPARED: &str = "enforcement_session_prepared";
const APPLY_OK: &str = "enforcement_session_apply_verified";
const APPLY_BAD: &str = "enforcement_session_apply_mismatch";
const ROLLBACK_OK: &str = "enforcement_session_rollback_verified";
const ROLLBACK_BAD: &str = "enforcement_session_rollback_mismatch";
const CANCELLED: &str = "enforcement_session_cancelled";
/// Pseudo device key of a default-deny profile session.
pub(crate) const PROFILE_KEY: &str = "default_deny_profile";

/// Normalized policy: DWORDs and other values by name, list entries as an
/// upper-case set (Group Policy may renumber list entries).
pub fn normalize(p: &PolicySnapshot) -> BTreeMap<String, String> {
    let root = RESTRICTIONS_KEY.to_ascii_uppercase();
    let mut out = BTreeMap::new();
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (r, d) in &p.values {
        let sub = r
            .key
            .strip_prefix(&root)
            .unwrap_or(&r.key)
            .trim_start_matches('\\');
        match (sub.is_empty(), r.name.parse::<u32>(), d) {
            (false, Ok(_), RegData::Sz(s)) => lists
                .entry(format!("{sub}[]"))
                .or_default()
                .push(s.to_ascii_uppercase()),
            _ => {
                let name = if sub.is_empty() {
                    r.name.clone()
                } else {
                    format!("{sub}\\{}", r.name)
                };
                // "Also apply to installed devices" unchecked: Group Policy
                // may write 0 or nothing; both mean "not retroactive".
                if name.to_ascii_lowercase().ends_with("retroactive")
                    && matches!(d, RegData::Dword(0))
                {
                    continue;
                }
                let v = match d {
                    RegData::Dword(v) => v.to_string(),
                    RegData::Sz(s) => s.clone(),
                    RegData::MultiSz(v) => v.join("|"),
                    RegData::Other { reg_type, bytes } => format!("type {reg_type}, {bytes} bytes"),
                };
                out.insert(name, v);
            }
        }
    }
    for (k, mut v) in lists {
        v.sort();
        v.dedup();
        out.insert(k, v.join(" | "));
    }
    out
}

/// Differences `from` -> `to`, one line each.
pub fn diff(from: &BTreeMap<String, String>, to: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in to {
        match from.get(k) {
            None => out.push(format!("+ {k} = {v}")),
            Some(o) if o != v => out.push(format!("~ {k}: {o} -> {v}")),
            _ => {}
        }
    }
    for (k, v) in from {
        if !to.contains_key(k) {
            out.push(format!("- {k} = {v}"));
        }
    }
    out
}

fn map_of(v: &serde_json::Value) -> BTreeMap<String, String> {
    v.as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn s(d: &serde_json::Value, k: &str) -> String {
    d.get(k)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Turkish text of a session audit event.
#[must_use]
pub fn event_tr(kind: &str, _m: &str, d: &serde_json::Value) -> String {
    let id = s(d, "session_id");
    let name = s(d, "device_name");
    match kind {
        PREPARED => format!(
            "Yönetici kontrollü uygulama oturumu {id} hazırlandı: {name} ({}). Önceki Windows politikası kaydedildi; değişikliği yönetici Grup İlkesi Düzenleyicisi ile yapacak.",
            s(d, "hardware_id")
        ),
        APPLY_OK => format!(
            "Oturum {id}: Windows politikası beklenen değişiklikle birebir eşleşiyor{}.",
            match s(d, "evidence").as_str() {
                "install_denied" => format!(
                    "; Windows {name} cihazının kurulumunu engelledi (Kod {})",
                    d.get("problem_code")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or_default()
                ),
                "policy_only" => "; cihaz düzeyinde engel henüz gözlenmedi".into(),
                _ => "; cihaz gözlenemedi".into(),
            }
        ),
        APPLY_BAD => format!(
            "Oturum {id}: Windows politikası beklenen değişiklikle EŞLEŞMİYOR; uygulama hatası, inceleme gerekir."
        ),
        ROLLBACK_OK => format!(
            "Oturum {id}: önceki Windows politikası birebir geri yüklendi; oturum kapatıldı."
        ),
        ROLLBACK_BAD => format!(
            "Oturum {id}: geri alma doğrulanamadı; Windows politikası önceki durumdan farklı. Kurtarma gerekli."
        ),
        CANCELLED => format!("Oturum {id} iptal edildi; Windows politikası değiştirilmemişti."),
        _ => format!("{}{kind}", crate::l10n::UNTRANSLATED),
    }
}

struct Active {
    prepared: SecurityEvent,
    last_apply: Option<SecurityEvent>,
    last_rollback_bad: Option<SecurityEvent>,
}

fn blocker() -> TextTrEn {
    TextTrEn {
        tr: "Otomatik uygulama bu sürümde kullanılamaz: RustWard Windows Grup İlkesine veya kayıt defterine yazmaz. Değişikliği yönetici Grup İlkesi Düzenleyicisi (gpedit.msc) ile kendisi yapar; RustWard önceki durumu kaydeder, sonucu yeniden okuyup doğrular ve denetim kaydına yazar.".into(),
        en: "Automated application is not available in this build: RustWard does not write Group Policy or the registry. The administrator makes the change in the Group Policy Editor (gpedit.msc); RustWard saves the previous state, re-reads and verifies the result and audits it.".into(),
    }
}

/// Privileged Group Policy write abstraction so startup reconciliation and
/// third-party GPO preservation can be thoroughly tested alongside live Win32 COM calls.
pub trait GpoBackend: Send + Sync {
    /// Checks whether the Local GPO writer is ready for writes.
    fn check_capability(&self) -> Result<(), String>;
    /// Applies managed USB restrictions while preserving third-party entries.
    fn apply_compound_policy(
        &self,
        deny_ids: &[String],
        allow_ids: &[String],
        third_party_denies: &[String],
        third_party_allows: &[String],
        retroactive: bool,
    ) -> Result<(), String>;
    /// Removes RustWard-managed entries while keeping third-party GPO entries intact.
    fn restore_compound_policy(
        &self,
        third_party_denies: &[String],
        third_party_allows: &[String],
    ) -> Result<(), String>;
    /// Triggers targeted Win32 PnP restart for a newly allowed device instance.
    fn restart_device_instance(&self, instance_id: &str) -> Result<(), String>;
    /// Requests OS Group Policy refresh.
    fn trigger_refresh(&self);
    /// Requests OS PnP hardware rescan.
    fn trigger_rescan(&self);
}

#[derive(Debug, Default, Clone, Copy)]
struct RealWindowsGpoBackend;

impl GpoBackend for RealWindowsGpoBackend {
    fn check_capability(&self) -> Result<(), String> {
        #[cfg(windows)]
        {
            rustward_windows::gpo_writer::GpoPolicyWriter::check_capability()
        }
        #[cfg(not(windows))]
        {
            Err("Local Group Policy COM operations require Windows".into())
        }
    }

    fn apply_compound_policy(
        &self,
        deny_ids: &[String],
        allow_ids: &[String],
        third_party_denies: &[String],
        third_party_allows: &[String],
        retroactive: bool,
    ) -> Result<(), String> {
        #[cfg(windows)]
        {
            rustward_windows::gpo_writer::GpoPolicyWriter::apply_compound_policy_preserving(
                deny_ids,
                allow_ids,
                third_party_denies,
                third_party_allows,
                retroactive,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (deny_ids, allow_ids, third_party_denies, third_party_allows, retroactive);
            Err("Local Group Policy operations require Windows".into())
        }
    }

    fn restore_compound_policy(
        &self,
        third_party_denies: &[String],
        third_party_allows: &[String],
    ) -> Result<(), String> {
        #[cfg(windows)]
        {
            rustward_windows::gpo_writer::GpoPolicyWriter::restore_compound_policy_preserving(
                third_party_denies,
                third_party_allows,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (third_party_denies, third_party_allows);
            Err("Local Group Policy operations require Windows".into())
        }
    }

    fn restart_device_instance(&self, instance_id: &str) -> Result<(), String> {
        #[cfg(windows)]
        {
            rustward_windows::gpo_writer::GpoPolicyWriter::restart_device_instance(instance_id)
        }
        #[cfg(not(windows))]
        {
            let _ = instance_id;
            Err("pnputil requires Windows".into())
        }
    }

    fn trigger_refresh(&self) {
        #[cfg(windows)]
        rustward_windows::gpo_writer::GpoPolicyWriter::trigger_policy_refresh();
    }

    fn trigger_rescan(&self) {
        #[cfg(windows)]
        rustward_windows::gpo_writer::GpoPolicyWriter::trigger_device_rescan();
    }
}

static REAL_WINDOWS_GPO_BACKEND: RealWindowsGpoBackend = RealWindowsGpoBackend;

fn is_rustward_managed_entry(
    entry: &str,
    plan: &CompoundPolicyPlanView,
    previous_approved: Option<&ApprovedPolicyRecord>,
    v: &super::Validated,
) -> bool {
    if is_generic_storage_id(entry) {
        return true;
    }
    if plan
        .compiled
        .deny_hardware_ids
        .iter()
        .any(|id| id.eq_ignore_ascii_case(entry))
        || plan
            .compiled
            .allow_hardware_ids
            .iter()
            .any(|id| id.eq_ignore_ascii_case(entry))
    {
        return true;
    }
    if plan
        .manufacturers
        .iter()
        .any(|m| m.hardware_ids.iter().any(|h| h.eq_ignore_ascii_case(entry)))
    {
        return true;
    }
    if let Some(prev) = previous_approved
        && (prev.deny_ids.iter().any(|d| d.eq_ignore_ascii_case(entry))
            || prev.allow_ids.iter().any(|a| a.eq_ignore_ascii_case(entry)))
    {
        return true;
    }
    let inner_policy = v.policy.policy();
    if inner_policy
        .denied_devices
        .iter()
        .chain(inner_policy.allowed_devices.iter())
        .any(|d| d.hardware_id.trim().eq_ignore_ascii_case(entry))
    {
        return true;
    }
    let upper = entry.trim().to_ascii_uppercase();
    if upper.starts_with("USBSTOR\\") || upper.starts_with("SCSI\\DISK") {
        return true;
    }
    if upper.starts_with("USB\\") {
        return v.catalog.catalog().brands.iter().any(|b| {
            b.identifiers.iter().any(|i| {
                let val = i.value.trim().to_ascii_uppercase();
                !val.is_empty()
                    && match i.kind {
                        rustward_core::catalog::IdentifierKind::UsbVid => {
                            let needle = format!("VID_{val}");
                            upper.contains(&needle)
                        }
                        rustward_core::catalog::IdentifierKind::InquiryVendor => {
                            val.len() >= 4 && upper.contains(&val)
                        }
                    }
            })
        });
    }
    false
}

fn collect_preserved_third_party_entries(
    observed: Option<&ObservedWindowsPolicy>,
    plan: &CompoundPolicyPlanView,
    previous_approved: Option<&ApprovedPolicyRecord>,
    v: &super::Validated,
) -> (Vec<String>, Vec<String>) {
    let mut denies = BTreeSet::new();
    let mut allows = BTreeSet::new();

    if let Some(obs) = observed {
        for entry in &obs.active_denies {
            let trimmed = entry.trim();
            if !trimmed.is_empty() && !is_rustward_managed_entry(trimmed, plan, previous_approved, v) {
                denies.insert(trimmed.to_ascii_uppercase());
            }
        }
        for entry in &obs.active_allows {
            let trimmed = entry.trim();
            if !trimmed.is_empty() && !is_rustward_managed_entry(trimmed, plan, previous_approved, v) {
                allows.insert(trimmed.to_ascii_uppercase());
            }
        }
    } else if let Some(prev) = previous_approved {
        for entry in &prev.third_party_denies {
            let trimmed = entry.trim();
            if !trimmed.is_empty() {
                denies.insert(trimmed.to_ascii_uppercase());
            }
        }
    }

    (denies.into_iter().collect(), allows.into_iter().collect())
}

fn normalized_uppercase_set(a: &[String], b: &[String]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for item in a.iter().chain(b.iter()) {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_ascii_uppercase());
        }
    }
    set.into_iter().collect()
}

impl AppService {
    pub(crate) fn is_live_windows(&self) -> bool {
        self.policy_source.name() == "windows_registry_read_only"
    }

    fn effective_gpo_backend(&self) -> Option<&dyn GpoBackend> {
        if let Some(ref custom) = self.gpo_backend {
            Some(custom.as_ref())
        } else if self.is_live_windows() {
            Some(&REAL_WINDOWS_GPO_BACKEND)
        } else {
            None
        }
    }

    /// Verifies that the Local Group Policy COM API and policy store are functional.
    pub(crate) fn check_desktop_capability(&self) -> Result<(), TextTrEn> {
        let Some(backend) = self.effective_gpo_backend() else {
            return Err(blocker());
        };
        if let Err(e) = backend.check_capability() {
            return Err(TextTrEn {
                tr: format!("Windows Grup İlkesi (IGroupPolicyObject) COM sağlayıcısı başlatılamadı: {e}"),
                en: format!("Windows Group Policy (IGroupPolicyObject) COM provider failed to initialize: {e}"),
            });
        }
        Ok(())
    }

    fn latest(g: &Inner, kind: &str) -> Result<Option<SecurityEvent>, IpcError> {
        Ok(g.store
            .list_events(&EventFilter {
                kind: Some(kind.into()),
                limit: Some(1),
                ..EventFilter::default()
            })
            .map_err(storage_err)?
            .into_iter()
            .next())
    }

    fn active_session(g: &Inner) -> Result<Option<Active>, IpcError> {
        let Some(prepared) = Self::latest(g, PREPARED)? else {
            return Ok(None);
        };
        let id = s(&prepared.details, "session_id");
        let newer = |e: &Option<SecurityEvent>| {
            e.as_ref()
                .filter(|e| e.id > prepared.id && s(&e.details, "session_id") == id)
                .cloned()
        };
        if newer(&Self::latest(g, ROLLBACK_OK)?).is_some()
            || newer(&Self::latest(g, CANCELLED)?).is_some()
        {
            return Ok(None);
        }
        let ok = newer(&Self::latest(g, APPLY_OK)?);
        let bad = newer(&Self::latest(g, APPLY_BAD)?);
        let last_apply = match (ok, bad) {
            (Some(a), Some(b)) => Some(if a.id > b.id { a } else { b }),
            (a, b) => a.or(b),
        };
        Ok(Some(Active {
            last_rollback_bad: newer(&Self::latest(g, ROLLBACK_BAD)?),
            prepared,
            last_apply,
        }))
    }

    fn normalized_from(
        captured: &Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<BTreeMap<String, String>, IpcError> {
        let c = captured.as_ref().map_err(|e| {
            IpcError::new(ErrorCode::Unavailable, format!("policy not readable: {e}"))
        })?;
        Ok(normalize(&c.values))
    }

    fn require(g: &Inner, session_id: &str) -> Result<Active, IpcError> {
        match Self::active_session(g)? {
            Some(a) if s(&a.prepared.details, "session_id") == session_id => Ok(a),
            Some(_) => Err(IpcError::new(
                ErrorCode::Conflict,
                "another enforcement session is active",
            )),
            None => Err(IpcError::new(
                ErrorCode::NotFound,
                "no active enforcement session",
            )),
        }
    }

    fn session_event(
        &self,
        g: &mut Inner,
        severity: Severity,
        kind: &str,
        message: String,
        details: serde_json::Value,
    ) -> Result<(), IpcError> {
        g.store
            .append_event(&NewEvent {
                severity,
                kind: kind.into(),
                device_key: details
                    .get("device_key")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                message,
                simulated: false,
                enforcement_state: self.enforcement_state_code().into(),
                policy_version: None,
                details,
            })
            .map_err(storage_err)?;
        Ok(())
    }

    /// Prepare a session (administrator).
    pub(crate) fn prepare_session(
        &self,
        g: &mut Inner,
        key: &str,
        retroactive: bool,
        identity: &ClientIdentity,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<EnforcementSessionView, IpcError> {
        if Self::active_session(g)?.is_some() {
            return Err(IpcError::new(
                ErrorCode::Conflict,
                "another enforcement session is active",
            ));
        }
        let v = Self::validated(&g.store)?;
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        let rec = snap
            .devices
            .iter()
            .find(|d| device_key(&d.instance_id) == key)
            .cloned()
            .ok_or_else(|| {
                IpcError::new(ErrorCode::NotFound, "device not in the current inventory")
            })?;
        let captured = captured.map_err(|e| {
            IpcError::new(ErrorCode::Unavailable, format!("policy not readable: {e}"))
        })?;
        let checklist = device_deny_checklist(
            &snap,
            &v.policy,
            &v.catalog,
            &captured.values,
            &rec.instance_id,
            retroactive,
        )
        .map_err(|e| IpcError::new(ErrorCode::ValidationFailed, e.to_string()))?;
        let baseline = normalize(&captured.values);
        let expected = normalize(
            &planned_deny_policy(&captured.values, &checklist.hardware_id, retroactive).0,
        );
        let now = self.clock.now_ms();
        let id = sha256_hex(format!("{key}|{now}|{baseline:?}|{expected:?}").as_bytes())[..16]
            .to_string();
        let details = serde_json::json!({
            "session_id": id,
            "device_key": key,
            "device": mask_instance_id(&rec.instance_id),
            "device_name": checklist.device_name,
            "vid_pid": checklist.vid_pid,
            "hardware_id": checklist.hardware_id,
            "retroactive": retroactive,
            "baseline": baseline,
            "expected": expected,
            "expected_lines": checklist.expected_registry,
            "affected_devices": checklist.affected_devices,
            "prepared_by": identity.actor(),
            "applied_by": "administrator_gpedit_not_rustward",
        });
        self.session_event(
            g,
            Severity::Warning,
            PREPARED,
            format!(
                "enforcement session {id} prepared for {} ({}) by {}; previous policy saved; the administrator applies the checklist in Group Policy",
                checklist.device_name,
                checklist.hardware_id,
                identity.actor()
            ),
            details,
        )?;
        self.session_view(g, Ok(captured))
    }

    /// Prepare a default-deny profile session (administrator). Compiles the
    /// layered Device Installation Restrictions plan from the RustWard
    /// policy, saves the baseline and the exact expected policy and audits
    /// both. Writes nothing to Windows.
    pub(crate) fn prepare_profile_session(
        &self,
        g: &mut Inner,
        identity: &ClientIdentity,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<EnforcementSessionView, IpcError> {
        use rustward_enforcement::checklist::default_deny_profile_text;
        use rustward_enforcement::policy_state::{apply_ops, forward_ops, merge_plan};
        use rustward_enforcement::{EnforcementProvider as _, PlanInputs, PreconditionStatus};

        if Self::active_session(g)?.is_some() {
            return Err(IpcError::new(
                ErrorCode::Conflict,
                "another enforcement session is active",
            ));
        }
        let v = Self::validated(&g.store)?;
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        let captured = captured.map_err(|e| {
            IpcError::new(ErrorCode::Unavailable, format!("policy not readable: {e}"))
        })?;
        let mut env = Self::env_facts();
        env.os_build = captured.os.build.zip(captured.os.ubr);
        let inputs = PlanInputs {
            policy: &v.policy,
            catalog: &v.catalog,
            snapshot: &snap,
            env: &env,
        };
        let plan = merge_plan(&captured.values, &self.provider.plan(inputs));
        // Only the preconditions that make an administrator-applied profile
        // unsafe or meaningless block preparation; the remaining ones gate
        // automated activation, which stays BLOCKED anyway.
        const GUIDED_REQUIRED: [&str; 3] =
            ["edition", "layering_supported", "internal_disks_protected"];
        let unmet: Vec<String> = plan
            .preconditions
            .iter()
            .filter(|p| {
                GUIDED_REQUIRED.contains(&p.id.as_str()) && p.status == PreconditionStatus::NotMet
            })
            .map(|p| p.id.clone())
            .collect();
        if !unmet.is_empty() {
            return Err(IpcError::new(
                ErrorCode::ValidationFailed,
                format!(
                    "default-deny profile preconditions not met: {}",
                    unmet.join(", ")
                ),
            ));
        }
        let has = |name: &str| plan.changes.iter().any(|c| c.value_name == name);
        if !has("DenyDeviceClasses") || !has("AllowDenyLayered") {
            return Err(IpcError::new(
                ErrorCode::ValidationFailed,
                "the RustWard policy does not compile to a default-deny profile",
            ));
        }
        // Never retroactive class rules (the system disk is a DiskDrive).
        if plan
            .changes
            .iter()
            .any(|c| c.value_name.to_ascii_lowercase().ends_with("retroactive") && c.data != "0")
        {
            return Err(IpcError::new(
                ErrorCode::ValidationFailed,
                "the profile must not contain a retroactive rule",
            ));
        }
        let dry = self.provider.dry_run(&plan, inputs);
        let forward = forward_ops(&captured.values, &plan)
            .map_err(|e| IpcError::new(ErrorCode::ValidationFailed, e))?;
        let after = apply_ops(&captured.values, &forward);
        let baseline = normalize(&captured.values);
        let expected = normalize(&after);
        if expected == baseline {
            return Err(IpcError::new(
                ErrorCode::Conflict,
                "the Windows policy already equals the default-deny profile",
            ));
        }
        let lines: Vec<String> = plan
            .changes
            .iter()
            .map(|c| {
                format!(
                    "HKLM\\{}\\{} = {} {}",
                    c.key, c.value_name, c.value_type, c.data
                )
            })
            .collect();
        let not_covered: Vec<String> = dry
            .already_installed_denied
            .iter()
            .map(|i| mask_instance_id(i))
            .collect();
        let text = default_deny_profile_text(&plan.changes, &not_covered);
        let now = self.clock.now_ms();
        let id = sha256_hex(format!("{PROFILE_KEY}|{now}|{baseline:?}|{expected:?}").as_bytes())
            [..16]
            .to_string();
        let details = serde_json::json!({
            "session_id": id,
            "kind": PROFILE_KEY,
            "device_key": PROFILE_KEY,
            "device_name": "Varsayılan ret profili (Aygıt Yükleme Kısıtlamaları)",
            "hardware_id": "DiskDrive {4d36e967-e325-11ce-bfc1-08002be10318} prevent + allow list (layered)",
            "retroactive": false,
            "baseline": baseline,
            "expected": expected,
            "expected_lines": lines,
            "checklist_text": text,
            "already_installed_not_covered": not_covered,
            "enforcement_gaps": dry.enforcement_gaps.iter().map(|i| mask_instance_id(i)).collect::<Vec<_>>(),
            "over_blocking": dry.over_blocking.iter().map(|i| mask_instance_id(i)).collect::<Vec<_>>(),
            "prepared_by": identity.actor(),
            "applied_by": "administrator_gpedit_not_rustward",
        });
        self.session_event(
            g,
            Severity::Warning,
            PREPARED,
            format!(
                "enforcement session {id} prepared for the default-deny profile ({} planned values) by {}; previous policy saved; the administrator applies the checklist in Group Policy",
                plan.changes.len(),
                identity.actor()
            ),
            details,
        )?;
        self.session_view(g, Ok(captured))
    }

    /// Verify that the administrator's change matches the plan exactly.
    pub(crate) fn verify_applied(
        &self,
        g: &mut Inner,
        session_id: &str,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<EnforcementSessionView, IpcError> {
        let a = Self::require(g, session_id)?;
        let d = &a.prepared.details;
        let live = Self::normalized_from(&captured)?;
        let baseline = map_of(&d["baseline"]);
        let expected = map_of(&d["expected"]);
        if live == baseline {
            return Err(IpcError::new(
                ErrorCode::Conflict,
                "the Windows policy is unchanged; apply the checklist in Group Policy first",
            ));
        }
        let key = s(d, "device_key");
        if live == expected {
            let obs = self.enforcement_observation(g, captured.clone())?;
            let target = obs.devices.iter().find(|x| x.device_key == key);
            let denied_now = obs
                .devices
                .iter()
                .filter(|x| {
                    x.observed.present == Some(true)
                        && x.observed.evidence == EvidenceLevel::InstallDenied
                })
                .count();
            let evidence = if key == PROFILE_KEY {
                if denied_now > 0 {
                    "install_denied"
                } else {
                    "policy_only"
                }
            } else {
                target.map_or("not_observed", |t| match t.observed.evidence {
                    EvidenceLevel::InstallDenied => "install_denied",
                    EvidenceLevel::PolicyOnly => "policy_only",
                    EvidenceLevel::None => "none",
                })
            };
            self.session_event(
                g,
                Severity::Warning,
                APPLY_OK,
                format!("enforcement session {session_id}: Windows policy matches the expected change exactly; device evidence: {evidence}"),
                serde_json::json!({
                    "session_id": session_id,
                    "device_key": key,
                    "device_name": s(d, "device_name"),
                    "evidence": evidence,
                    "devices_denied_now": denied_now,
                    "problem_code": target.and_then(|t| t.observed.problem_code),
                    "read_write_tested": false,
                }),
            )?;
        } else {
            self.session_event(
                g,
                Severity::Critical,
                APPLY_BAD,
                format!("enforcement session {session_id}: Windows policy does NOT match the expected change"),
                serde_json::json!({
                    "session_id": session_id,
                    "device_key": key,
                    "differences_from_expected": diff(&expected, &live),
                }),
            )?;
        }
        self.session_view(g, captured)
    }

    /// Verify that the previous policy is back.
    pub(crate) fn verify_rollback(
        &self,
        g: &mut Inner,
        session_id: &str,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<EnforcementSessionView, IpcError> {
        let a = Self::require(g, session_id)?;
        let d = &a.prepared.details;
        let live = Self::normalized_from(&captured)?;
        let baseline = map_of(&d["baseline"]);
        let key = s(d, "device_key");
        if live == baseline {
            let obs = self.enforcement_observation(g, captured.clone())?;
            let status = obs
                .devices
                .iter()
                .find(|x| x.device_key == key)
                .map(|t| t.observed.label_status_tr.clone());
            self.session_event(
                g,
                Severity::Info,
                ROLLBACK_OK,
                format!("enforcement session {session_id}: previous Windows policy restored exactly; session closed"),
                serde_json::json!({
                    "session_id": session_id,
                    "device_key": key,
                    "device_status_tr": status,
                }),
            )?;
        } else {
            self.session_event(
                g,
                Severity::Critical,
                ROLLBACK_BAD,
                format!("enforcement session {session_id}: rollback NOT verified; policy differs from the saved baseline"),
                serde_json::json!({
                    "session_id": session_id,
                    "device_key": key,
                    "differences_from_baseline": diff(&baseline, &live),
                }),
            )?;
        }
        self.session_view(g, captured)
    }

    /// Cancel a session whose change was never applied.
    pub(crate) fn cancel_session(
        &self,
        g: &mut Inner,
        session_id: &str,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<EnforcementSessionView, IpcError> {
        let a = Self::require(g, session_id)?;
        let live = Self::normalized_from(&captured)?;
        if live != map_of(&a.prepared.details["baseline"]) {
            return Err(IpcError::new(
                ErrorCode::Conflict,
                "the Windows policy differs from the saved baseline; restore it and verify the rollback instead",
            ));
        }
        self.session_event(
            g,
            Severity::Info,
            CANCELLED,
            format!("enforcement session {session_id} cancelled; the Windows policy was not changed"),
            serde_json::json!({ "session_id": session_id, "device_key": s(&a.prepared.details, "device_key") }),
        )?;
        self.session_view(g, captured)
    }

    /// Apply an authorized Windows device block directly (administrator).
    /// Apply an authorized Windows device block directly (administrator).
    /// If device_key is provided, applies an additive device override into the
    /// persistent policy and enforces it via the compound policy compiler.
    /// Otherwise executes the guided session workflow for session_id.
    pub(crate) fn apply_device_block_direct(
        &self,
        session_id: Option<&str>,
        device_key: Option<&str>,
        retroactive: bool,
        identity: &ClientIdentity,
    ) -> Result<EnforcementSessionView, IpcError> {
        if !identity.is_administrator {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "administrator privileges required to apply device block",
            ));
        }

        // Additive device override workflow
        if let Some(dk) = device_key {
            let (hwid, inst, label) = {
                let g = self.lock()?;
                let snap = g.last.clone().unwrap_or_else(empty_snapshot);
                let rec = snap
                    .devices
                    .iter()
                    .find(|d| rustward_storage::device_key(&d.instance_id) == dk)
                    .cloned()
                    .ok_or_else(|| {
                        IpcError::new(
                            ErrorCode::NotFound,
                            format!("device not found for key {dk}"),
                        )
                    })?;

                let hwid = rec
                    .hardware_ids
                    .iter()
                    .find(|id| rustward_core::ids::validate_storage_hardware_id(id).is_ok())
                    .cloned()
                    .ok_or_else(|| {
                        IpcError::new(
                            ErrorCode::ValidationFailed,
                            "no specific, non-generic storage hardware ID found for device",
                        )
                    })?;

                (hwid, rec.instance_id.clone(), rec.friendly_name)
            };

            // 1. Commit PolicyEdit::SetDeviceDenied to store
            {
                let mut g = self.lock()?;
                let v = Self::validated(&g.store)?;
                let edit = rustward_core::policy_edit::PolicyEdit::SetDeviceDenied {
                    hardware_id: hwid.clone(),
                    instance_id: Some(inst.clone()),
                    label,
                    denied: true,
                };
                let outcome = rustward_core::policy_edit::apply_edit(&v.state, &edit)
                    .map_err(edit_err)?;
                g.store
                    .commit_policy_edit(&outcome, &identity.actor())
                    .map_err(storage_err)?;
                self.reevaluate_locked(&mut g)?;

                // Cancel any stale single-device session so no conflict remains
                if let Some(active) = Self::active_session(&g)? {
                    let active_sid = s(&active.prepared.details, "session_id");
                    let cap = self.capture_policy_unlocked();
                    let _ = self.cancel_session(&mut g, &active_sid, cap);
                }
            }

            // 2. Apply to Windows via GpoPolicyWriter if running on Windows
            let is_live_windows = self.is_live_windows();
            if is_live_windows {
                if let Err(cap_err) = self.check_desktop_capability() {
                    return Err(IpcError::new(
                        ErrorCode::Unavailable,
                        format!("GPO capability check failed: {}", cap_err.en),
                    ));
                }
                #[cfg(windows)]
                {
                    use rustward_windows::gpo_writer::GpoPolicyWriter;
                    let (plan, revision_id) = {
                        let captured = self.capture_policy_unlocked();
                        let snapshot_ref = captured.as_ref().ok().map(|c| &c.values);
                        let g = self.lock()?;
                        let v = Self::validated(&g.store)?;
                        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
                        let p = compile_compound_policy(
                            &v.policy,
                            &v.catalog,
                            &snap.devices,
                            snapshot_ref,
                            retroactive,
                        );
                        (p.clone(), p.compiled.revision_id.clone())
                    };

                    GpoPolicyWriter::apply_compound_policy(
                        &plan.compiled.deny_hardware_ids,
                        &plan.compiled.allow_hardware_ids,
                        retroactive,
                    )
                    .map_err(|e| {
                        IpcError::new(ErrorCode::Internal, format!("GPO write failed: {e}"))
                    })?;

                    GpoPolicyWriter::trigger_policy_refresh();
                    GpoPolicyWriter::trigger_device_rescan();
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    {
                        let mut g = self.lock()?;
                        self.session_event(
                            &mut g,
                            Severity::Warning,
                            "device_enforcement_applied",
                            format!(
                                "applied additive device block for {hwid}: {} total active denies",
                                plan.compiled.deny_hardware_ids.len()
                            ),
                            serde_json::json!({
                                "hardware_id": hwid,
                                "instance_id": inst,
                                "planned_denies": plan.compiled.deny_hardware_ids,
                                "retroactive": retroactive,
                                "revision_id": revision_id,
                                "actor": identity.actor(),
                            }),
                        )?;
                    }
                }
            }

            let _ = self.refresh_inventory();
            let captured = self.capture_policy_unlocked();
            let mut g = self.lock()?;
            return self.session_view(&mut g, captured);
        }

        // Legacy guided single-device session stepper path
        let captured = self.capture_policy_unlocked();
        let sid = {
            let g = self.lock()?;
            if let Some(id) = session_id {
                let a = Self::require(&g, id)?;
                s(&a.prepared.details, "session_id")
            } else {
                return Err(IpcError::new(
                    ErrorCode::InvalidRequest,
                    "either session_id or device_key is required",
                ));
            }
        };

        let (hwid, retro) = {
            let g = self.lock()?;
            let a = Self::require(&g, &sid)?;
            let hwid = s(&a.prepared.details, "hardware_id");
            let retro = a
                .prepared
                .details
                .get("retroactive")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(retroactive);
            (hwid, retro)
        };

        let is_live_windows = self.is_live_windows();
        if is_live_windows {
            if let Err(cap_err) = self.check_desktop_capability() {
                return Err(IpcError::new(
                    ErrorCode::Unavailable,
                    format!("GPO capability check failed: {}", cap_err.en),
                ));
            }
            #[cfg(windows)]
            {
                use rustward_windows::gpo_writer::GpoPolicyWriter;
                {
                    let mut g = self.lock()?;
                    self.session_event(
                        &mut g,
                        Severity::Warning,
                        "enforcement_mutation_started",
                        format!("privileged backend applying Windows Group Policy restriction for {hwid}"),
                        serde_json::json!({
                            "session_id": sid,
                            "hardware_id": hwid,
                            "retroactive": retro,
                            "actor": identity.actor(),
                        }),
                    )?;
                }

                let mut deny_ids = vec![hwid.clone()];
                if let Ok(cap) = &captured {
                    let observed = extract_observed_policy(&cap.values);
                    for active_id in observed.active_denies {
                        if !deny_ids.iter().any(|d| d.eq_ignore_ascii_case(&active_id)) {
                            deny_ids.push(active_id);
                        }
                    }
                }

                GpoPolicyWriter::apply_compound_policy(&deny_ids, &[], retro).map_err(|e| {
                    IpcError::new(ErrorCode::Internal, format!("GPO write failed: {e}"))
                })?;

                GpoPolicyWriter::trigger_policy_refresh();
                GpoPolicyWriter::trigger_device_rescan();
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }

        let _ = self.refresh_inventory();
        let captured = self.capture_policy_unlocked();
        let mut g = self.lock()?;
        self.verify_applied(&mut g, &sid, captured)
    }

    /// Restore previous policy from a session or device directly (administrator).
    /// If device_key is provided, removes the device override from persistent policy
    /// and updates Windows Group Policy.
    /// Otherwise executes guided rollback for session_id or active session.
    pub(crate) fn restore_device_policy_direct(
        &self,
        session_id: Option<&str>,
        device_key: Option<&str>,
        identity: &ClientIdentity,
    ) -> Result<EnforcementSessionView, IpcError> {
        if !identity.is_administrator {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "administrator privileges required to restore device policy",
            ));
        }

        // Targeted device unblock
        if let Some(dk) = device_key {
            let (hwid, inst) = {
                let g = self.lock()?;
                let snap = g.last.clone().unwrap_or_else(empty_snapshot);
                if let Some(dev) = snap
                    .devices
                    .iter()
                    .find(|d| rustward_storage::device_key(&d.instance_id) == dk)
                {
                    let hw = dev
                        .hardware_ids
                        .iter()
                        .find(|id| rustward_core::ids::validate_storage_hardware_id(id).is_ok())
                        .cloned()
                        .unwrap_or_else(|| dev.instance_id.clone());
                    (hw, Some(dev.instance_id.clone()))
                } else {
                    let v = Self::validated(&g.store)?;
                    if let Some(rule) = v.policy.policy().denied_devices.iter().find(|r| {
                        r.instance_id
                            .as_deref()
                            .map(rustward_storage::device_key)
                            .as_deref()
                            == Some(dk)
                    }) {
                        (rule.hardware_id.clone(), rule.instance_id.clone())
                    } else if let Some(rule) = v.policy.policy().denied_devices.last() {
                        (rule.hardware_id.clone(), rule.instance_id.clone())
                    } else {
                        return Err(IpcError::new(
                            ErrorCode::NotFound,
                            format!("target device {dk} not found in inventory or overrides"),
                        ));
                    }
                }
            };

            // 1. Commit PolicyEdit::SetDeviceDenied (denied = false) to store
            {
                let mut g = self.lock()?;
                let v = Self::validated(&g.store)?;
                let edit = rustward_core::policy_edit::PolicyEdit::SetDeviceDenied {
                    hardware_id: hwid.clone(),
                    instance_id: inst.clone(),
                    label: None,
                    denied: false,
                };
                let outcome = rustward_core::policy_edit::apply_edit(&v.state, &edit)
                    .map_err(edit_err)?;
                g.store
                    .commit_policy_edit(&outcome, &identity.actor())
                    .map_err(storage_err)?;
                self.reevaluate_locked(&mut g)?;

                // Cancel any stale single-device session so no conflict remains
                if let Some(active) = Self::active_session(&g)? {
                    let active_sid = s(&active.prepared.details, "session_id");
                    let cap = self.capture_policy_unlocked();
                    let _ = self.cancel_session(&mut g, &active_sid, cap);
                }
            }

            // 2. Update Windows GPO via GpoPolicyWriter if running on Windows
            let is_live_windows = self.is_live_windows();
            if is_live_windows {
                if let Err(cap_err) = self.check_desktop_capability() {
                    return Err(IpcError::new(
                        ErrorCode::Unavailable,
                        format!("GPO capability check failed: {}", cap_err.en),
                    ));
                }
                #[cfg(windows)]
                {
                    use rustward_windows::gpo_writer::GpoPolicyWriter;
                    let plan = {
                        let captured = self.capture_policy_unlocked();
                        let snapshot_ref = captured.as_ref().ok().map(|c| &c.values);
                        let g = self.lock()?;
                        let v = Self::validated(&g.store)?;
                        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
                        compile_compound_policy(
                            &v.policy,
                            &v.catalog,
                            &snap.devices,
                            snapshot_ref,
                            true,
                        )
                    };

                    if plan.compiled.deny_hardware_ids.is_empty() {
                        GpoPolicyWriter::restore_compound_policy().map_err(|e| {
                            IpcError::new(ErrorCode::Internal, format!("GPO restore failed: {e}"))
                        })?;
                    } else {
                        GpoPolicyWriter::apply_compound_policy(
                            &plan.compiled.deny_hardware_ids,
                            &plan.compiled.allow_hardware_ids,
                            true,
                        )
                        .map_err(|e| {
                            IpcError::new(ErrorCode::Internal, format!("GPO update failed: {e}"))
                        })?;
                    }

                    if let Some(inst_id) = &inst {
                        let _ = GpoPolicyWriter::restart_device_instance(inst_id);
                    }

                    GpoPolicyWriter::trigger_policy_refresh();
                    GpoPolicyWriter::trigger_device_rescan();
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    {
                        let mut g = self.lock()?;
                        self.session_event(
                            &mut g,
                            Severity::Info,
                            "device_enforcement_restored",
                            format!(
                                "restored device restriction for {hwid}: {} remaining active denies",
                                plan.compiled.deny_hardware_ids.len()
                            ),
                            serde_json::json!({
                                "hardware_id": hwid,
                                "instance_id": inst,
                                "remaining_denies": plan.compiled.deny_hardware_ids,
                                "actor": identity.actor(),
                            }),
                        )?;
                    }
                }
            }

            let _ = self.refresh_inventory();
            let captured = self.capture_policy_unlocked();
            let mut g = self.lock()?;
            return self.session_view(&mut g, captured);
        }

        // If no device_key provided, check if we should restore active session or device overrides
        let sid = {
            let g = self.lock()?;
            if let Some(id) = session_id {
                let a = Self::require(&g, id)?;
                s(&a.prepared.details, "session_id")
            } else if let Some(active) = Self::active_session(&g)? {
                s(&active.prepared.details, "session_id")
            } else {
                // If there are denied_devices overrides but no active session, unblock the last one
                let v = Self::validated(&g.store)?;
                if let Some(rule) = v.policy.policy().denied_devices.last() {
                    let last_inst = rule.instance_id.clone();
                    let last_dk = last_inst.as_deref().map(rustward_storage::device_key);
                    drop(g);
                    return self.restore_device_policy_direct(
                        None,
                        last_dk.as_deref(),
                        identity,
                    );
                }
                return Err(IpcError::new(
                    ErrorCode::NotFound,
                    "no active enforcement session found to restore",
                ));
            }
        };

        let hwid = {
            let g = self.lock()?;
            let a = Self::require(&g, &sid)?;
            s(&a.prepared.details, "hardware_id")
        };

        let is_live_windows = self.is_live_windows();
        if is_live_windows {
            if let Err(cap_err) = self.check_desktop_capability() {
                return Err(IpcError::new(
                    ErrorCode::Unavailable,
                    format!("GPO capability check failed: {}", cap_err.en),
                ));
            }
            #[cfg(windows)]
            {
                use rustward_windows::gpo_writer::GpoPolicyWriter;
                {
                    let mut g = self.lock()?;
                    self.session_event(
                        &mut g,
                        Severity::Info,
                        "enforcement_rollback_started",
                        format!("privileged backend restoring Windows Group Policy for {hwid}"),
                        serde_json::json!({
                            "session_id": sid,
                            "hardware_id": hwid,
                            "actor": identity.actor(),
                        }),
                    )?;
                }

                let captured_for_restore = self.capture_policy_unlocked();
                let mut remaining_denies = Vec::new();
                if let Ok(cap) = &captured_for_restore {
                    let observed = extract_observed_policy(&cap.values);
                    for active_id in observed.active_denies {
                        if !active_id.eq_ignore_ascii_case(&hwid) {
                            remaining_denies.push(active_id);
                        }
                    }
                }

                if remaining_denies.is_empty() {
                    GpoPolicyWriter::restore_compound_policy().map_err(|e| {
                        IpcError::new(ErrorCode::Internal, format!("GPO restore failed: {e}"))
                    })?;
                } else {
                    GpoPolicyWriter::apply_compound_policy(&remaining_denies, &[], true).map_err(|e| {
                        IpcError::new(ErrorCode::Internal, format!("GPO update failed: {e}"))
                    })?;
                }

                GpoPolicyWriter::trigger_policy_refresh();
                GpoPolicyWriter::trigger_device_rescan();
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }

        let _ = self.refresh_inventory();
        let captured = self.capture_policy_unlocked();
        let mut g = self.lock()?;
        self.verify_rollback(&mut g, &sid, captured)
    }

    /// Get the unified compound multi-manufacturer policy plan.
    pub(crate) fn get_compound_policy_plan(&self) -> Result<CompoundPolicyPlanView, IpcError> {
        let captured = self.capture_policy_unlocked();
        let snapshot_ref = captured.as_ref().ok().map(|c| &c.values);
        let g = self.lock()?;
        let v = Self::validated(&g.store)?;
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        let mut plan = compile_compound_policy(
            &v.policy,
            &v.catalog,
            &snap.devices,
            snapshot_ref,
            true,
        );
        if let Ok(Some(prev)) = g.store.approved_policy() {
            for active in &plan.observed.active_denies {
                let in_prev = prev.deny_ids.iter().any(|d| d.eq_ignore_ascii_case(active));
                let in_desired = plan
                    .compiled
                    .deny_hardware_ids
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(active));
                if in_prev && !in_desired && !plan.diff.removed_denies.iter().any(|r| r.eq_ignore_ascii_case(active)) {
                    plan.diff.removed_denies.push(active.clone());
                }
            }
            let has_conflict = plan.manufacturers.iter().any(|m| {
                m.windows_policy == rustward_enforcement::compound_policy::WindowsPolicyStatus::Conflict
            });
            plan.diff.is_synchronized = plan.diff.added_denies.is_empty()
                && plan.diff.removed_denies.is_empty()
                && !has_conflict;
            plan.is_applied = plan.diff.is_synchronized
                && plan.observed.raw_gpo_present
                && !plan.compiled.deny_hardware_ids.is_empty()
                && !has_conflict;
        }
        Ok(plan)
    }

    /// Apply the unified compound policy to Windows Group Policy (administrator).
    pub(crate) fn apply_compound_policy_direct(
        &self,
        retroactive: bool,
        expected_policy_version: u64,
        identity: &ClientIdentity,
        actor_override: Option<&str>,
    ) -> Result<CompoundPolicyPlanView, IpcError> {
        if !identity.is_administrator {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "administrator privileges required to apply compound Windows Group Policy",
            ));
        }

        let _ = self.refresh_inventory();
        let plan = self.get_compound_policy_plan()?;

        // Optimistic concurrency check
        if expected_policy_version != 0 && plan.policy_version != expected_policy_version {
            return Err(IpcError::new(
                ErrorCode::Conflict,
                format!(
                    "policy version conflict: expected {}, current is {}",
                    expected_policy_version, plan.policy_version
                ),
            ));
        }

        // Validate all hardware IDs strictly
        for hwid in &plan.compiled.deny_hardware_ids {
            validate_hardware_id(hwid).map_err(|e| {
                IpcError::new(
                    ErrorCode::ValidationFailed,
                    format!("invalid hardware ID in compound deny list: {hwid} ({e})"),
                )
            })?;
        }
        for hwid in &plan.compiled.allow_hardware_ids {
            validate_hardware_id(hwid).map_err(|e| {
                IpcError::new(
                    ErrorCode::ValidationFailed,
                    format!("invalid hardware ID in compound allow list: {hwid} ({e})"),
                )
            })?;
        }

        let actor_name = actor_override
            .map(str::to_owned)
            .unwrap_or_else(|| identity.actor());
        let windows_user = self.current_windows_user();
        let captured_before = self.capture_policy_unlocked();
        let observed_before = captured_before
            .as_ref()
            .ok()
            .map(|c| extract_observed_policy(&c.values));

        let (v, settings, previous_approved) = {
            let g = self.lock()?;
            let v = Self::validated(&g.store)?;
            let settings = g.store.settings().map_err(storage_err)?;
            let prev = g.store.approved_policy().ok().flatten();
            (v, settings, prev)
        };
        let computer_name = v.policy.policy().workstation_id.clone();

        let (third_party_denies, third_party_allows) = collect_preserved_third_party_entries(
            observed_before.as_ref(),
            &plan,
            previous_approved.as_ref(),
            &v,
        );

        if let Some(backend) = self.effective_gpo_backend() {
            if let Err(cap_err) = self.check_desktop_capability() {
                return Err(IpcError::new(
                    ErrorCode::Unavailable,
                    format!("GPO capability check failed: {}", cap_err.en),
                ));
            }

            {
                let mut g = self.lock()?;
                self.session_event(
                    &mut g,
                    Severity::Warning,
                    "compound_enforcement_mutation_started",
                    format!(
                        "privileged backend applying compound Windows Group Policy with {} deny rules",
                        plan.compiled.deny_hardware_ids.len()
                    ),
                    serde_json::json!({
                        "computer_name": computer_name,
                        "policy_revision": plan.compiled.revision_id,
                        "revision_id": plan.compiled.revision_id,
                        "deny_hardware_ids": plan.compiled.deny_hardware_ids,
                        "allow_hardware_ids": plan.compiled.allow_hardware_ids,
                        "third_party_denies_preserved": third_party_denies.len(),
                        "retroactive": retroactive,
                        "actor": identity.actor(),
                        "actor_username": actor_name,
                        "windows_user": windows_user,
                        "enforcement_outcome": "gpo_applying",
                    }),
                )?;
            }

            backend
                .apply_compound_policy(
                    &plan.compiled.deny_hardware_ids,
                    &plan.compiled.allow_hardware_ids,
                    &third_party_denies,
                    &third_party_allows,
                    retroactive,
                )
                .map_err(|e| {
                    IpcError::new(
                        ErrorCode::Internal,
                        format!("GPO compound write failed: {e}"),
                    )
                })?;

            backend.trigger_refresh();

            // Targeted recovery: for any connected USB storage device whose manufacturer
            // is configured as Allowed and which was in Code 28, trigger devnode restart
            let devices_to_recover: Vec<String> = {
                let g = self.lock()?;
                let snap = g.last.clone().unwrap_or_else(empty_snapshot);
                snap.devices
                    .into_iter()
                    .filter(|d| {
                        d.present == Some(true)
                            && d.problem_code == Some(28)
                            && plan.manufacturers.iter().any(|m| {
                                m.configured_intention
                                    == rustward_enforcement::compound_policy::ConfiguredIntention::Allowed
                                    && (m.hardware_ids.iter().any(|h| d.has_id(h))
                                        || d.friendly_name.as_deref().is_some_and(|f| {
                                            f.to_ascii_lowercase().contains(&m.brand_id.to_ascii_lowercase())
                                        }))
                            })
                    })
                    .map(|d| {
                        if d.instance_id.to_ascii_uppercase().starts_with("USB") {
                            d.instance_id
                        } else if let Some(parent) = d.parent_instance_id {
                            if parent.to_ascii_uppercase().starts_with("USB") {
                                parent
                            } else {
                                d.instance_id
                            }
                        } else {
                            d.instance_id
                        }
                    })
                    .collect()
            };

            for inst in &devices_to_recover {
                let _ = backend.restart_device_instance(inst);
            }

            backend.trigger_rescan();
            std::thread::sleep(std::time::Duration::from_millis(500));

            let approved_record = ApprovedPolicyRecord {
                policy_version: v.version,
                revision_id: plan.compiled.revision_id.clone(),
                catalog_version: v.catalog.catalog().catalog_version.clone(),
                deny_ids: plan.compiled.deny_hardware_ids.clone(),
                allow_ids: plan.compiled.allow_hardware_ids.clone(),
                third_party_denies: third_party_denies.clone(),
                retroactive,
                auto_reconcile: settings.reconcile_on_startup,
                approved_by: actor_name.clone(),
                approved_ms: self.clock.now_ms(),
            };
            let mut g = self.lock()?;
            g.store
                .save_approved_policy(&approved_record)
                .map_err(storage_err)?;
            g.startup_reconcile_status = Some("already_in_sync".into());
        }

        let _ = self.refresh_inventory();
        let updated_plan = self.get_compound_policy_plan()?;

        {
            let mut g = self.lock()?;
            self.session_event(
                &mut g,
                Severity::Info,
                "compound_enforcement_applied",
                format!(
                    "compound Windows Group Policy applied: {} active denies, sync={}",
                    updated_plan.observed.active_denies.len(),
                    updated_plan.diff.is_synchronized
                ),
                serde_json::json!({
                    "computer_name": computer_name,
                    "policy_revision": updated_plan.compiled.revision_id,
                    "revision_id": updated_plan.compiled.revision_id,
                    "active_denies": updated_plan.observed.active_denies,
                    "third_party_denies": third_party_denies,
                    "is_applied": updated_plan.is_applied,
                    "actor": identity.actor(),
                    "actor_username": actor_name,
                    "windows_user": windows_user,
                    "enforcement_outcome": "gpo_applied",
                }),
            )?;
        }

        Ok(updated_plan)
    }

    /// Targeted restart of a specific USB storage device (administrator).
    pub(crate) fn recover_device(
        &self,
        target_key: &str,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError> {
        if !identity.is_administrator {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "administrator privileges required to recover device",
            ));
        }

        let instance_id = {
            let g = self.lock()?;
            let snap = g.last.clone().unwrap_or_else(empty_snapshot);
            let dev = snap
                .devices
                .into_iter()
                .find(|d| rustward_storage::device_key(&d.instance_id) == target_key)
                .ok_or_else(|| {
                    IpcError::new(
                        ErrorCode::NotFound,
                        format!("device not found for key {target_key}"),
                    )
                })?;
            if dev.instance_id.to_ascii_uppercase().starts_with("USB") {
                dev.instance_id
            } else if let Some(parent) = dev.parent_instance_id {
                if parent.to_ascii_uppercase().starts_with("USB") {
                    parent
                } else {
                    dev.instance_id
                }
            } else {
                dev.instance_id
            }
        };

        if let Some(backend) = self.effective_gpo_backend() {
            backend
                .restart_device_instance(&instance_id)
                .map_err(|e| IpcError::new(ErrorCode::Internal, e))?;
            backend.trigger_rescan();
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        let _ = self.refresh_inventory();
        Ok(ResponseBody::Done {
            message: "Device restarted successfully".into(),
            message_tr: "Aygıt başarıyla yeniden başlatıldı".into(),
        })
    }

    /// Roll back compound policy restrictions from Windows Group Policy (administrator).
    pub(crate) fn rollback_compound_policy_direct(
        &self,
        identity: &ClientIdentity,
        actor_override: Option<&str>,
    ) -> Result<CompoundPolicyPlanView, IpcError> {
        if !identity.is_administrator {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "administrator privileges required to roll back Windows Group Policy",
            ));
        }

        let actor_name = actor_override
            .map(str::to_owned)
            .unwrap_or_else(|| identity.actor());
        let windows_user = self.current_windows_user();
        let captured_before = self.capture_policy_unlocked();
        let observed_before = captured_before
            .as_ref()
            .ok()
            .map(|c| extract_observed_policy(&c.values));
        let pre_plan = self.get_compound_policy_plan()?;
        let (v, previous_approved) = {
            let g = self.lock()?;
            let v = Self::validated(&g.store)?;
            let prev = g.store.approved_policy().ok().flatten();
            (v, prev)
        };
        let computer_name = v.policy.policy().workstation_id.clone();
        let (third_party_denies, third_party_allows) = collect_preserved_third_party_entries(
            observed_before.as_ref(),
            &pre_plan,
            previous_approved.as_ref(),
            &v,
        );

        if let Some(backend) = self.effective_gpo_backend() {
            if let Err(cap_err) = self.check_desktop_capability() {
                return Err(IpcError::new(
                    ErrorCode::Unavailable,
                    format!("GPO capability check failed: {}", cap_err.en),
                ));
            }

            {
                let mut g = self.lock()?;
                self.session_event(
                    &mut g,
                    Severity::Info,
                    "compound_enforcement_rollback_started",
                    "privileged backend restoring previous compound Windows Group Policy restrictions".to_string(),
                    serde_json::json!({
                        "computer_name": computer_name,
                        "third_party_denies_preserved": third_party_denies.len(),
                        "actor": identity.actor(),
                        "actor_username": actor_name,
                        "windows_user": windows_user,
                    }),
                )?;
            }

            backend
                .restore_compound_policy(&third_party_denies, &third_party_allows)
                .map_err(|e| IpcError::new(ErrorCode::Internal, format!("GPO rollback failed: {e}")))?;

            backend.trigger_refresh();
            backend.trigger_rescan();
            std::thread::sleep(std::time::Duration::from_millis(500));

            let mut g = self.lock()?;
            g.store.clear_approved_policy().map_err(storage_err)?;
            g.startup_reconcile_status = Some("none".into());
        }

        let _ = self.refresh_inventory();
        let updated_plan = self.get_compound_policy_plan()?;

        {
            let mut g = self.lock()?;
            self.session_event(
                &mut g,
                Severity::Info,
                "compound_enforcement_rollback_verified",
                format!(
                    "compound Windows Group Policy rollback verified: {} active denies remain",
                    updated_plan.observed.active_denies.len()
                ),
                serde_json::json!({
                    "computer_name": computer_name,
                    "active_denies": updated_plan.observed.active_denies,
                    "third_party_denies": third_party_denies,
                    "actor": identity.actor(),
                    "actor_username": actor_name,
                    "windows_user": windows_user,
                    "enforcement_outcome": "gpo_rolled_back",
                }),
            )?;
        }

        Ok(updated_plan)
    }

    /// Reconciles local Windows Group Policy at service startup against the last
    /// admin-approved policy snapshot while preserving third-party GPO entries.
    pub fn reconcile_startup(&self) -> Result<String, IpcError> {
        let windows_user = self.current_windows_user();
        let (approved_res, settings, computer_name) = {
            let g = self.lock()?;
            let settings = g.store.settings().map_err(storage_err)?;
            let approved_res = g.store.approved_policy();
            let computer_name = Self::validated(&g.store)
                .map(|v| v.policy.policy().workstation_id.clone())
                .unwrap_or_else(|_| "WORKSTATION".to_owned());
            (approved_res, settings, computer_name)
        };

        let approved = match approved_res {
            Ok(Some(rec)) => rec,
            Ok(None) => {
                let mut g = self.lock()?;
                g.startup_reconcile_status = Some("none".into());
                return Ok("none".into());
            }
            Err(e) => {
                let msg = format!("approved policy snapshot verification failed: {e}");
                let mut g = self.lock()?;
                g.startup_reconcile_status = Some("failed".into());
                let _ = self.session_event(
                    &mut g,
                    Severity::Critical,
                    "startup_reconcile_failed",
                    msg.clone(),
                    serde_json::json!({
                        "computer_name": computer_name,
                        "actor_username": "system_startup",
                        "windows_user": windows_user,
                        "enforcement_outcome": "reconcile_failed",
                    }),
                );
                return Err(IpcError::new(ErrorCode::Internal, msg));
            }
        };

        if !settings.reconcile_on_startup {
            let mut g = self.lock()?;
            g.startup_reconcile_status = Some("skipped_disabled".into());
            let _ = self.session_event(
                &mut g,
                Severity::Info,
                "startup_reconcile_skipped",
                "startup policy reconciliation skipped because reconcile_on_startup is disabled".into(),
                serde_json::json!({
                    "computer_name": computer_name,
                    "policy_revision": approved.revision_id,
                    "actor_username": "system_startup",
                    "windows_user": windows_user,
                }),
            );
            return Ok("skipped_disabled".into());
        }

        for hwid in &approved.deny_ids {
            if let Err(e) = validate_hardware_id(hwid) {
                let msg = format!("approved deny ID '{hwid}' failed validation: {e}");
                let mut g = self.lock()?;
                g.startup_reconcile_status = Some("failed".into());
                return Err(IpcError::new(ErrorCode::ValidationFailed, msg));
            }
        }
        for hwid in &approved.allow_ids {
            if let Err(e) = validate_hardware_id(hwid) {
                let msg = format!("approved allow ID '{hwid}' failed validation: {e}");
                let mut g = self.lock()?;
                g.startup_reconcile_status = Some("failed".into());
                return Err(IpcError::new(ErrorCode::ValidationFailed, msg));
            }
        }

        let Some(backend) = self.effective_gpo_backend() else {
            let mut g = self.lock()?;
            g.startup_reconcile_status = Some("none".into());
            return Ok("none".into());
        };

        let captured = self.capture_policy_unlocked();
        let observed = captured
            .as_ref()
            .ok()
            .map(|c| extract_observed_policy(&c.values));
        let plan_for_classification = self.get_compound_policy_plan()?;
        let v = {
            let g = self.lock()?;
            Self::validated(&g.store)?
        };
        let (live_third_denies, live_third_allows) = collect_preserved_third_party_entries(
            observed.as_ref(),
            &plan_for_classification,
            Some(&approved),
            &v,
        );
        let third_denies = normalized_uppercase_set(&approved.third_party_denies, &live_third_denies);
        let expected_denies = normalized_uppercase_set(&approved.deny_ids, &third_denies);
        let expected_allows = normalized_uppercase_set(&approved.allow_ids, &live_third_allows);

        let in_sync = observed.as_ref().is_some_and(|obs| {
            let obs_denies = normalized_uppercase_set(&obs.active_denies, &[]);
            let obs_allows = normalized_uppercase_set(&obs.active_allows, &[]);
            let needs_gpo_flag = !expected_denies.is_empty() || !expected_allows.is_empty();
            obs_denies == expected_denies
                && obs_allows == expected_allows
                && obs.retroactive == approved.retroactive
                && (!needs_gpo_flag || obs.raw_gpo_present)
        });

        if in_sync {
            let mut g = self.lock()?;
            g.startup_reconcile_status = Some("already_in_sync".into());
            let _ = self.session_event(
                &mut g,
                Severity::Info,
                "startup_reconcile_in_sync",
                format!(
                    "startup check verified Windows Group Policy matches approved revision {}",
                    approved.revision_id
                ),
                serde_json::json!({
                    "computer_name": computer_name,
                    "policy_revision": approved.revision_id,
                    "actor_username": "system_startup",
                    "windows_user": windows_user,
                    "enforcement_outcome": "gpo_in_sync",
                }),
            );
            return Ok("already_in_sync".into());
        }

        if let Err(e) = backend.check_capability() {
            let msg = format!("startup GPO capability check failed: {e}");
            let mut g = self.lock()?;
            g.startup_reconcile_status = Some("failed".into());
            let _ = self.session_event(
                &mut g,
                Severity::Critical,
                "startup_reconcile_failed",
                msg.clone(),
                serde_json::json!({
                    "computer_name": computer_name,
                    "policy_revision": approved.revision_id,
                    "actor_username": "system_startup",
                    "windows_user": windows_user,
                    "enforcement_outcome": "reconcile_failed",
                }),
            );
            return Err(IpcError::new(ErrorCode::Unavailable, msg));
        }

        let apply_res = if approved.deny_ids.is_empty()
            && approved.allow_ids.is_empty()
            && third_denies.is_empty()
            && live_third_allows.is_empty()
        {
            backend.restore_compound_policy(&[], &[])
        } else {
            backend.apply_compound_policy(
                &approved.deny_ids,
                &approved.allow_ids,
                &third_denies,
                &live_third_allows,
                approved.retroactive,
            )
        };

        if let Err(e) = apply_res {
            let msg = format!("startup GPO reconciliation failed: {e}");
            let mut g = self.lock()?;
            g.startup_reconcile_status = Some("failed".into());
            let _ = self.session_event(
                &mut g,
                Severity::Critical,
                "startup_reconcile_failed",
                msg.clone(),
                serde_json::json!({
                    "computer_name": computer_name,
                    "policy_revision": approved.revision_id,
                    "actor_username": "system_startup",
                    "windows_user": windows_user,
                    "enforcement_outcome": "reconcile_failed",
                }),
            );
            return Err(IpcError::new(ErrorCode::Internal, msg));
        }

        backend.trigger_refresh();
        backend.trigger_rescan();
        let _ = self.refresh_inventory();

        let mut g = self.lock()?;
        g.startup_reconcile_status = Some("reconciled".into());
        self.session_event(
            &mut g,
            Severity::Warning,
            "startup_reconcile_applied",
            format!(
                "startup reconciliation restored approved Windows Group Policy revision {} ({} deny rules)",
                approved.revision_id,
                approved.deny_ids.len()
            ),
            serde_json::json!({
                "computer_name": computer_name,
                "policy_revision": approved.revision_id,
                "deny_count": approved.deny_ids.len(),
                "third_party_preserved": third_denies.len(),
                "actor_username": "system_startup",
                "windows_user": windows_user,
                "enforcement_outcome": "gpo_reconciled",
            }),
        )?;

        Ok("reconciled".into())
    }

    /// Current session state (read-only towards Windows).
    pub(crate) fn session_view(
        &self,
        g: &mut Inner,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<EnforcementSessionView, IpcError> {
        let active = Self::active_session(g)?;
        let live = Self::normalized_from(&captured);
        let step = |code: &str, tr: &str, en: &str, status: &str| LadderStepView {
            code: code.into(),
            label_tr: tr.into(),
            label_en: en.into(),
            status: status.into(),
        };
        let Some(a) = active else {
            return Ok(EnforcementSessionView {
                state: "policy_simulation".into(),
                state_tr: "Politika simülasyonu: etkin bir Windows uygulama oturumu yok.".into(),
                state_en: "Policy simulation: no active Windows enforcement session.".into(),
                ladder: vec![
                    step(
                        "policy_simulation",
                        "Politika simülasyonu",
                        "Policy simulation",
                        "yes",
                    ),
                    step(
                        "windows_restriction_configured",
                        "Windows kısıtlaması yapılandırıldı",
                        "Windows restriction configured",
                        "no",
                    ),
                    step(
                        "windows_install_denied",
                        "Windows cihaz kurulumu engellendi",
                        "Windows device installation denied",
                        "no",
                    ),
                    step(
                        "read_write_verified",
                        "Okuma/yazma erişimi doğrulandı",
                        "Read/write access verified",
                        "not_verified",
                    ),
                    step(
                        "protection_inactive",
                        "Koruma etkin değil",
                        "Protection inactive",
                        "yes",
                    ),
                    step(
                        "enforcement_error",
                        "Uygulama hatası",
                        "Enforcement error",
                        "no",
                    ),
                    step(
                        "recovery_required",
                        "Kurtarma gerekli",
                        "Recovery required",
                        "no",
                    ),
                ],
                session: None,
                differences: Vec::new(),
                policy_error: live.err().map(|e| e.message),
                target: None,
                automated_apply_available: self.check_desktop_capability().is_ok(),
                automated_apply_blocker: match self.check_desktop_capability() {
                    Ok(()) => TextTrEn {
                        tr: "Masaüstü kontrollü uygulama etkin: RustWard yönetici onayıyla Windows Yerel Grup İlkesi (IGroupPolicyObject) kısıtlamasını doğrudan uygular ve kaldırır.".into(),
                        en: "Desktop-managed enforcement active: RustWard applies and restores Windows Local Group Policy (IGroupPolicyObject) restrictions directly with administrator approval.".into(),
                    },
                    Err(e) => e,
                },
            });
        };
        let d = a.prepared.details.clone();
        let baseline = map_of(&d["baseline"]);
        let expected = map_of(&d["expected"]);
        let key = s(&d, "device_key");
        let obs = self.enforcement_observation(g, captured)?;
        let profile = key == PROFILE_KEY;
        let any_denied = obs.devices.iter().any(|x| {
            x.observed.present == Some(true) && x.observed.evidence == EvidenceLevel::InstallDenied
        });
        let target: Option<ObservedDeviceView> =
            obs.devices.into_iter().find(|x| x.device_key == key);
        let (configured, at_baseline, differences, policy_error) = match &live {
            Ok(l) => (l == &expected, l == &baseline, diff(&expected, l), None),
            Err(e) => (false, false, Vec::new(), Some(e.message.clone())),
        };
        let denied = configured
            && if profile {
                any_denied
            } else {
                target
                    .as_ref()
                    .is_some_and(|t| t.observed.evidence == EvidenceLevel::InstallDenied)
            };
        let error = policy_error.is_none() && !configured && !at_baseline;
        let recovery = error || (a.last_rollback_bad.is_some() && !at_baseline);
        let yn = |b: bool| if b { "yes" } else { "no" };
        let (state, tr, en) = if recovery && a.last_rollback_bad.is_some() {
            (
                "recovery_required",
                "Kurtarma gerekli: Windows politikası kaydedilen önceki durumdan farklı.",
                "Recovery required: the Windows policy differs from the saved previous state.",
            )
        } else if error {
            (
                "enforcement_error",
                "Uygulama hatası: Windows politikası ne önceki durumla ne de beklenen değişiklikle eşleşiyor.",
                "Enforcement error: the Windows policy matches neither the previous state nor the expected change.",
            )
        } else if denied {
            (
                "windows_install_denied",
                "Windows cihaz kurulumu engellendi (gerçek Windows kanıtı). Okuma/yazma yolları ayrıca doğrulanmadı.",
                "Windows device installation denied (real Windows evidence). Read/write paths not verified separately.",
            )
        } else if configured {
            (
                "windows_restriction_configured",
                "Windows kısıtlaması yapılandırıldı; cihaz düzeyinde engel henüz gözlenmedi.",
                "Windows restriction configured; no device-level denial observed yet.",
            )
        } else if a.last_apply.is_some() && at_baseline {
            // Applied earlier and now back at the baseline: the administrator
            // rolled back; only the rollback verification is still missing.
            (
                "protection_inactive",
                "Koruma etkin değil: Windows politikası kaydedilen önceki duruma döndü. Geri almayı doğrulayın.",
                "Protection inactive: the Windows policy is back at the saved previous state. Verify the rollback.",
            )
        } else {
            (
                "protection_inactive",
                "Koruma etkin değil: oturum hazır, Windows politikası henüz değiştirilmedi.",
                "Protection inactive: session prepared, the Windows policy has not been changed yet.",
            )
        };
        let lines = d
            .get("expected_lines")
            .and_then(serde_json::Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(EnforcementSessionView {
            state: state.into(),
            state_tr: tr.into(),
            state_en: en.into(),
            ladder: vec![
                step(
                    "policy_simulation",
                    "Politika simülasyonu",
                    "Policy simulation",
                    "yes",
                ),
                step(
                    "windows_restriction_configured",
                    "Windows kısıtlaması yapılandırıldı",
                    "Windows restriction configured",
                    yn(configured),
                ),
                step(
                    "windows_install_denied",
                    "Windows cihaz kurulumu engellendi",
                    "Windows device installation denied",
                    yn(denied),
                ),
                step(
                    "read_write_verified",
                    "Okuma/yazma erişimi doğrulandı",
                    "Read/write access verified",
                    "not_verified",
                ),
                step(
                    "protection_inactive",
                    "Koruma etkin değil",
                    "Protection inactive",
                    yn(!configured),
                ),
                step(
                    "enforcement_error",
                    "Uygulama hatası",
                    "Enforcement error",
                    yn(error),
                ),
                step(
                    "recovery_required",
                    "Kurtarma gerekli",
                    "Recovery required",
                    yn(recovery),
                ),
            ],
            session: Some(SessionView {
                session_id: s(&d, "session_id"),
                prepared_ms: a.prepared.utc_ms,
                prepared_by: s(&d, "prepared_by"),
                device_key: key,
                device_name: s(&d, "device_name"),
                hardware_id: s(&d, "hardware_id"),
                retroactive: d
                    .get("retroactive")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                baseline: baseline.iter().map(|(k, v)| format!("{k} = {v}")).collect(),
                expected_lines: lines,
                kind: if profile {
                    PROFILE_KEY.into()
                } else {
                    "device_deny".into()
                },
                checklist_text: d
                    .get("checklist_text")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                last_verification: a.last_apply.as_ref().map(|e| e.kind.clone()),
                last_verification_ms: a.last_apply.as_ref().map(|e| e.utc_ms),
            }),
            differences: if configured || at_baseline {
                Vec::new()
            } else {
                differences
            },
            policy_error,
            target,
            automated_apply_available: self.check_desktop_capability().is_ok(),
            automated_apply_blocker: match self.check_desktop_capability() {
                Ok(()) => TextTrEn {
                    tr: "Masaüstü kontrollü uygulama etkin: RustWard yönetici onayıyla Windows Yerel Grup İlkesi (IGroupPolicyObject) kısıtlamasını doğrudan uygular ve kaldırır.".into(),
                    en: "Desktop-managed enforcement active: RustWard applies and restores Windows Local Group Policy (IGroupPolicyObject) restrictions directly with administrator approval.".into(),
                },
                Err(e) => e,
            },
        })
    }
}

impl AppService {
    /// Real Windows protection state (dashboard). Read-only.
    pub(crate) fn windows_protection(
        &self,
        g: &Inner,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<rustward_ipc::messages::WindowsProtectionView, IpcError> {
        use rustward_core::catalog::Verification;
        use rustward_core::policy::PolicyMode;
        use rustward_enforcement::assessment::AssessmentCategory as A;
        use rustward_enforcement::observer::{observe, restrictions_configured};
        use rustward_enforcement::policy_inspect::CapturedPolicy;
        use rustward_ipc::messages::{ProtectionBlockerView, StorageSummaryView};

        let blocker = |code: &str, kind: &str, tr: String, en: String| ProtectionBlockerView {
            code: code.into(),
            kind: kind.into(),
            tr,
            en,
        };
        let v = Self::validated(&g.store)?;
        let now = self.clock.now_ms();
        let readable = captured.is_ok();
        let cap = captured.unwrap_or(CapturedPolicy {
            captured_ms: now,
            ..CapturedPolicy::default()
        });
        let restrictions = readable && restrictions_configured(&cap.values);
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        let obs = observe(&snap, &v.policy, &v.catalog, &cap);

        // Phase 6 counts.
        let mut summary = StorageSummaryView::default();
        let mut installed_before_rule = 0u32;
        for d in &obs.devices {
            let Some(a) = &d.assessment else { continue };
            if d.present != Some(true) {
                summary.disconnected += 1;
                continue;
            }
            summary.connected += 1;
            match a.policy_category {
                A::AllowCandidate => summary.allow_candidates += 1,
                A::DenyCandidate => summary.deny_candidates += 1,
                A::UnverifiedIdentity => summary.unverified_identity += 1,
                A::UnsupportedDevice => summary.unsupported += 1,
                _ => {}
            }
            let policy_denies = matches!(
                a.policy_category,
                A::DenyCandidate | A::UnverifiedIdentity | A::UnsupportedDevice
            );
            match a.enforcement_category {
                Some(A::WindowsDenialVerified) if readable => summary.windows_denied += 1,
                _ if policy_denies => {
                    summary.denied_by_policy_only += 1;
                    if a.previously_installed {
                        installed_before_rule += 1;
                    }
                }
                _ => {}
            }
        }

        // Every reason the system is not in a verified protection state.
        let mut blockers = Vec::new();
        if !self.is_live_windows() {
            blockers.push(blocker(
                "automatic_apply_blocked",
                "blocked",
                "Otomatik politika uygulama ENGELLİ: RustWard Windows politikasını kendisi yazmaz; değişiklik yalnızca yönetici onayıyla, yönetici tarafından elle yapılır.".into(),
                "Automatic policy application is BLOCKED: RustWard never writes Windows policy itself; changes are made manually by an administrator with explicit approval.".into(),
            ));
        }
        if !readable {
            blockers.push(blocker(
                "policy_unreadable",
                "action",
                "Windows politikası okunamadı; gerçek durum belirlenemiyor.".into(),
                "The Windows policy could not be read; the real state cannot be determined.".into(),
            ));
        } else if !restrictions {
            blockers.push(blocker(
                "no_windows_rule",
                "action",
                "Windows'ta hiçbir Aygıt Yükleme Kısıtlaması kuralı yok; hiçbir cihaz Windows tarafından engellenmiyor.".into(),
                "No Device Installation Restriction rule exists in Windows; no device is denied by Windows.".into(),
            ));
        }
        if v.policy.policy().mode == PolicyMode::DryRun {
            blockers.push(blocker(
                "dry_run_mode",
                "action",
                "RustWard politikası kuru çalışma (simülasyon) modunda.".into(),
                "The RustWard policy is in dry-run (simulation) mode.".into(),
            ));
        }
        for rule in v
            .policy
            .policy()
            .allowed_brands
            .iter()
            .filter(|r| r.enabled)
        {
            let Some(brand) = v.catalog.brand(&rule.brand_id) else {
                continue;
            };
            let ids: Vec<_> = brand.enforceable_identifiers().collect();
            if ids.is_empty() {
                blockers.push(blocker(
                    "allowed_brand_without_identifier",
                    "limitation",
                    format!("İzinli üretici \"{}\" için doğrulanmış donanım kimliği yok; bu üreticinin cihazları da reddedilir.", brand.display_name),
                    format!("Allowed manufacturer \"{}\" has no verified hardware identifier; its devices are denied as well.", brand.display_name),
                ));
            } else if ids
                .iter()
                .any(|i| i.verification != Verification::LabVerified)
            {
                blockers.push(blocker(
                    "allowed_brand_unverified",
                    "action",
                    format!("İzinli üretici \"{}\" için donanım kimliği gerçek cihaz üzerinde doğrulanmadı.", brand.display_name),
                    format!("The hardware identifier of allowed manufacturer \"{}\" was not verified on a real device.", brand.display_name),
                ));
            }
        }
        blockers.push(blocker(
            "manufacturer_default_deny_unverified",
            "limitation",
            "Üretici genelinde varsayılan ret Windows'ta doğrulanmadı: Windows yalnızca cihazın kendi bildirdiği kimlik dizeleriyle eşleşir; doğrulanmış tek mekanizma tek cihaz kimliği reddidir.".into(),
            "Manufacturer-wide default deny is not verified in Windows: Windows matches only identity strings the device reports about itself; the only verified mechanism is a single device-ID deny.".into(),
        ));
        if summary.denied_by_policy_only > 0 {
            blockers.push(blocker(
                "denied_by_policy_only",
                "action",
                format!(
                    "Politikanın reddettiği {} bağlı cihaz Windows tarafından engellenmiyor.",
                    summary.denied_by_policy_only
                ),
                format!(
                    "{} connected device(s) the policy denies are not denied by Windows.",
                    summary.denied_by_policy_only
                ),
            ));
        }
        if installed_before_rule > 0 {
            blockers.push(blocker(
                "installed_before_rule",
                "limitation",
                format!("{installed_before_rule} cihaz zaten kurulu; geriye dönük olmayan bir kural kurulu cihazı etkilemez."),
                format!("{installed_before_rule} device(s) are already installed; a non-retroactive rule does not affect installed devices."),
            ));
        }
        if summary.unverified_identity > 0 {
            blockers.push(blocker(
                "unverified_identity_connected",
                "limitation",
                format!("{} bağlı cihazın kimliği genel, eksik veya çelişkili; üreticisi belirlenemiyor.", summary.unverified_identity),
                format!("{} connected device(s) report a generic, missing or conflicting identity; the manufacturer cannot be determined.", summary.unverified_identity),
            ));
        }
        let rsa = rustward_enforcement::removable_storage::removable_storage_state(
            &cap.removable_storage,
        );
        if readable && rsa.disks_restricted() {
            blockers.push(blocker(
                "removable_storage_class_wide",
                "limitation",
                "Çıkarılabilir Depolama Erişimi ilkesi tüm çıkarılabilir diskleri kısıtlıyor: üretici ayrımı yapamaz, izinli üreticilerin cihazları da kısıtlanır. Gerçek okuma/yazma reddi yalnızca yönetici gözlemiyle doğrulanır.".into(),
                "The Removable Storage Access policy restricts all removable disks: it cannot tell manufacturers apart, so allowed manufacturers' devices are restricted too. A real read/write denial is only confirmed by administrator observation.".into(),
            ));
        }
        blockers.push(blocker(
            "read_write_unverified",
            "limitation",
            "Okuma/yazma engeli doğrulanmadı: kurulum reddi tam okuma/yazma engeli kanıtı değildir.".into(),
            "Read/write denial is not verified: an installation denial is not proof of a complete read/write denial.".into(),
        ));

        let cap_res = self.check_desktop_capability();
        if let Err(err_text) = &cap_res {
            blockers.push(blocker(
                "gpo_provider_unavailable",
                "limitation",
                err_text.tr.clone(),
                err_text.en.clone(),
            ));
        }

        let is_auto_available = cap_res.is_ok();
        let mk = |state: &str, tr: &str, en: &str, dtr: String, den: String, n: u32| {
            rustward_ipc::messages::WindowsProtectionView {
                state: state.into(),
                label_tr: tr.into(),
                label_en: en.into(),
                detail_tr: dtr,
                detail_en: den,
                denied_now: n,
                automated_apply_available: is_auto_available,
                summary: summary.clone(),
                blockers: blockers.clone(),
            }
        };
        if !readable {
            return Ok(mk(
                "unknown",
                "Durum bilinmiyor",
                "State unknown",
                "Windows politikası okunamadı; gerçek koruma durumu belirlenemiyor.".into(),
                "The Windows policy could not be read; the real protection state is unknown."
                    .into(),
                0,
            ));
        }
        if !restrictions {
            return Ok(mk(
                "inactive",
                "Windows koruması etkin değil",
                "Windows protection inactive",
                "Windows'ta hiçbir Aygıt Yükleme Kısıtlaması kuralı yapılandırılmamış. RustWard kararları yalnızca simülasyondur.".into(),
                "No Device Installation Restriction rule is configured in Windows. RustWard's decisions are simulations only.".into(),
                0,
            ));
        }
        let denied: Vec<_> = obs
            .devices
            .iter()
            .filter(|d| d.evidence == EvidenceLevel::InstallDenied && d.present == Some(true))
            .collect();
        let n = u32::try_from(denied.len()).unwrap_or(u32::MAX);
        if denied.is_empty() {
            return Ok(mk(
                "configured_unverified",
                "Politika yapılandırılmış, doğrulanmadı",
                "Policy configured, not verified",
                "Windows'ta bir kısıtlama kuralı var ama bağlı hiçbir cihazda gerçek bir kurulum engeli gözlenmedi.".into(),
                "A Windows restriction rule exists, but no real installation denial is observed on a connected device.".into(),
                0,
            ));
        }
        let names: Vec<String> = denied.iter().map(|d| d.name.clone()).collect();

        // Check if compound policy is currently applied and active in Windows
        let compound_verified = {
            let snap_devices = snap.devices.clone();
            let plan = rustward_enforcement::compound_policy::compile_compound_policy(
                &v.policy,
                &v.catalog,
                &snap_devices,
                Some(&cap.values),
                true,
            );
            plan.is_applied && !plan.compiled.deny_hardware_ids.is_empty()
        };

        if compound_verified {
            return Ok(mk(
                "verified_active",
                "Windows üretici koruması doğrulandı (GPO kısıtlamaları etkin)",
                "Windows manufacturer protection verified (GPO restrictions active)",
                format!(
                    "Gerçek Windows kanıtı: RustWard tarafından uygulanan birleşik üretici politikası Windows Yerel Grup İlkesi'nde doğrulandı ve Windows şu cihazların kurulumunu engelliyor: {}. İzinli üreticilerin cihazları erişilebilirdir.",
                    names.join(", ")
                ),
                format!(
                    "Real Windows evidence: the unified manufacturer policy applied by RustWard was verified in Windows Local Group Policy and Windows denies installation of: {}. Allowed manufacturers' devices remain accessible.",
                    names.join(", ")
                ),
                n,
            ));
        }

        let mut profile_verified = false;
        let verified = Self::active_session(g)?.is_some_and(|a| {
            let key = s(&a.prepared.details, "device_key");
            let applied = a.last_apply.as_ref().is_some_and(|e| e.kind == APPLY_OK);
            if key == PROFILE_KEY {
                // Still compared live: the policy must equal the profile now.
                profile_verified = applied
                    && readable
                    && normalize(&cap.values) == map_of(&a.prepared.details["expected"]);
                profile_verified
            } else {
                applied && denied.iter().any(|d| device_key(&d.instance_id) == key)
            }
        });
        if verified && profile_verified {
            return Ok(mk(
                "verified_active",
                "Varsayılan ret profili doğrulandı (yalnızca yeni kurulumlar)",
                "Default-deny profile verified (new installations only)",
                format!(
                    "Gerçek Windows kanıtı: yönetici onaylı oturumda varsayılan ret profili birebir doğrulandı ve Windows şu cihazların kurulumunu engelliyor: {}. Zaten kurulu cihazlar etkilenmez; okuma/yazma yolları ayrıca doğrulanmadı; kimlikler cihazın kendi bildirdiği dizelerdir.",
                    names.join(", ")
                ),
                format!(
                    "Real Windows evidence: the default-deny profile was verified in an administrator-approved session and Windows denies installation of: {}. Already-installed devices are not affected; read/write paths not verified; identities are self-reported strings.",
                    names.join(", ")
                ),
                n,
            ));
        }
        if verified {
            Ok(mk(
                "verified_active",
                "Windows koruması doğrulandı (yalnızca hedef cihaz)",
                "Windows protection verified (target device only)",
                format!(
                    "Gerçek Windows kanıtı: yönetici onaylı oturumda politika birebir doğrulandı ve Windows şu cihazların kurulumunu engelliyor: {}. Okuma/yazma yolları ayrıca doğrulanmadı; üreticiye dayalı varsayılan ret yoktur.",
                    names.join(", ")
                ),
                format!(
                    "Real Windows evidence: the policy was verified in an administrator-approved session and Windows denies installation of: {}. Read/write paths not verified separately; there is no manufacturer-based default deny.",
                    names.join(", ")
                ),
                n,
            ))
        } else {
            Ok(mk(
                "denial_observed",
                "Windows cihaz kurulumunu engelliyor (RustWard oturumu dışında)",
                "Windows denies device installation (outside a RustWard session)",
                format!(
                    "Gerçek Windows kanıtı: Windows şu cihazların kurulumunu engelliyor: {}. Politika RustWard yönetici oturumuyla doğrulanmadı.",
                    names.join(", ")
                ),
                format!(
                    "Real Windows evidence: Windows denies installation of: {}. The policy was not verified through a RustWard administrator session.",
                    names.join(", ")
                ),
                n,
            ))
        }
    }
}
