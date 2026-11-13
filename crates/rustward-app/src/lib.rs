//! RustWard application service.
//!
//! Implements every [`rustward_ipc::Request`] over the SQLite store, the
//! manufacturer policy engine and the dry-run enforcement provider. The same
//! type runs inside the Windows service (behind named pipes) and, in debug
//! builds, inside the desktop app as the development backend.
//!
//! Detection is separate from enforcement: inventory refreshes record
//! detections and *simulated* decisions; the enforcement provider reports
//! its own state (`pending_validation`) and never claims protection.

#![forbid(unsafe_code)]

pub mod auth;
mod guided;
pub mod inventory;
pub mod l10n;
mod observation;
mod policy_source;
mod v11;

pub use guided::GpoBackend;
pub(crate) use rustward_enforcement::NOT_VALIDATED_BANNER_TR;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use rustward_core::catalog::{IdentifierKind, ValidatedCatalog};
use rustward_core::classify::{DeviceCategory, StorageScope, classify};
use rustward_core::device::{
    DeviceRecord, DeviceSnapshot, SNAPSHOT_SCHEMA_VERSION, SnapshotSource,
};
use rustward_core::diff::{correlate_reenumeration, diff_snapshots};
use rustward_core::evaluate::{Decision, Verdict, evaluate_device, evaluate_snapshot};
use rustward_core::explain::explain;
use rustward_core::ids::{StorageIdNamespace, vendor_level_hardware_id};
use rustward_core::policy::ValidatedPolicy;
use rustward_core::policy_edit::{
    EditError, PolicyEdit, PolicyState, apply_edit, combined_warnings,
};
use rustward_core::report::utc_date;
use rustward_enforcement::{
    DeviceInstallRestrictionProvider, EnforcementProvider, EnvironmentFacts, PlanInputs,
};
use rustward_ipc::messages::{
    ActualEnforcementView, AdapterView, BackupView, DashboardView, DatabaseHealthView, DeviceView,
    DiagnosticsView, EnforcementReadinessView, EnforcementView, EventLogView, EventQuery,
    EventView, ExplanationView, ExportFormat, ExportView, GateView, IdentifierView,
    ManufacturerView, ManufacturersView, MutationView, PolicyChangeView, PolicyHealthView,
    RecoveryReadinessView, RestorePreviewView, ServiceStatusView, SettingsView, SimulationView,
    TextTrEn,
};
use rustward_ipc::rpc::Handler;
use rustward_ipc::{ClientIdentity, ErrorCode, IpcError, Request, ResponseBody};
use rustward_storage::{
    AppSettings, BackupKind, BackupRecord, ChainStatus, Clock, DeviceRow, EventFilter,
    EventMetadata, EventObserver, Language, NewEvent, RestoreCandidate, SecurityEvent, Severity,
    StorageError, Store, Theme, UserRole, device_key, mask_instance_id, sha256_hex,
};

pub use inventory::{EmptyInventory, FixtureInventory, InventorySource, LiveInventory};
pub use policy_source::{
    LivePolicySource, PolicySource, StaticPolicySource, UnavailablePolicySource,
};

/// Which host runs the application service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// In-process development backend (desktop debug builds).
    DevBackend,
    /// Privileged Windows service.
    WindowsService,
}

impl BackendKind {
    fn code(self) -> &'static str {
        match self {
            Self::DevBackend => "dev_backend",
            Self::WindowsService => "windows_service",
        }
    }
}

/// Static configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Host kind.
    pub backend: BackendKind,
    /// Allow loading the bundled synthetic fixture.
    pub allow_synthetic: bool,
    /// Directory for database backups (service-owned).
    pub backup_dir: Option<PathBuf>,
    /// `dev_temp` | `program_data` | `memory`.
    pub database_location: String,
    /// Application version.
    pub app_version: String,
}

/// Result of an inventory refresh.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshSummary {
    /// Devnodes collected.
    pub devices: usize,
    /// Stored (relevant) devices.
    pub stored: usize,
    /// Arrivals.
    pub arrived: usize,
    /// Removals.
    pub removed: usize,
    /// Simulated denials among arrivals.
    pub simulated_denials: usize,
}

struct Inner {
    store: Store,
    inventory_kind: &'static str,
    perf: Perf,
    last: Option<DeviceSnapshot>,
    last_refresh_ms: Option<i64>,
    last_inventory_error: Option<String>,
    consecutive_failures: u32,
    auth_window_start_ms: i64,
    auth_recorded_in_window: u32,
    auth_suppressed: u64,
    staged_restore: Option<StagedRestore>,
    restore_counter: u64,
    auth: auth::AuthManager,
    startup_reconcile_status: Option<String>,
}

/// A verified backup waiting for `ApplyRestore`.
struct StagedRestore {
    restore_id: String,
    account: String,
    created_ms: i64,
    candidate: RestoreCandidate,
}

/// A prepared restore must be applied within this time.
pub const RESTORE_PREVIEW_TTL_MS: i64 = 10 * 60 * 1000;

/// At most this many authorization failures are written to the audit log
/// per [`AUTH_AUDIT_WINDOW_MS`]; further attempts are counted and reported
/// with the next recorded one (protects the log against request floods).
pub const AUTH_AUDIT_LIMIT: u32 = 20;
/// Authorization audit rate-limit window.
pub const AUTH_AUDIT_WINDOW_MS: i64 = 60_000;

/// The application service.
/// Timing measurements (monotonic clock) for diagnostics.
#[derive(Debug, Default, Clone)]
struct Perf {
    last_collect_ms: Option<u64>,
    last_apply_ms: Option<u64>,
    max_collect_ms: Option<u64>,
    refreshes: u64,
    last_devices: Option<u64>,
    first_refresh_done_ms: Option<i64>,
    last_observation_ms: Option<u64>,
    last_verification_ms: Option<u64>,
}

fn elapsed_ms(t: std::time::Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub struct AppService {
    inner: Mutex<Inner>,
    /// Separate from `inner`: Windows device enumeration runs without
    /// holding the state lock, so IPC requests are not blocked by it.
    /// Also serializes refreshes. Lock order: `inventory` before `inner`.
    inventory: Mutex<Box<dyn InventorySource>>,
    clock: Arc<dyn Clock>,
    config: AppConfig,
    provider: DeviceInstallRestrictionProvider,
    policy_source: Box<dyn PolicySource>,
    gpo_backend: Option<Arc<dyn guided::GpoBackend>>,
    windows_user_resolver: fn() -> Option<String>,
    started_ms: i64,
}

impl std::fmt::Debug for AppService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn internal(e: impl std::fmt::Display) -> IpcError {
    IpcError::new(ErrorCode::Internal, e.to_string())
}

fn storage_err(e: StorageError) -> IpcError {
    match e {
        StorageError::Invalid(m) => IpcError::new(ErrorCode::InvalidRequest, m),
        StorageError::VersionConflict { expected, active } => IpcError::new(
            ErrorCode::Conflict,
            format!(
                "policy changed meanwhile (expected v{expected}, active v{active}); reload and retry"
            ),
        ),
        StorageError::CorruptPolicy { .. } => IpcError::new(
            ErrorCode::Unavailable,
            format!(
                "{e}; policy changes are refused until the database is repaired (docs/RECOVERY-PLAN.md)"
            ),
        ),
        StorageError::BackupRejected(r) => IpcError::new(
            match r {
                rustward_storage::BackupRejection::Missing => ErrorCode::NotFound,
                _ => ErrorCode::ValidationFailed,
            },
            format!("backup rejected ({}): {r}", r.code()),
        ),
        other => internal(other),
    }
}

fn edit_err(e: EditError) -> IpcError {
    let code = match &e {
        EditError::NotFound { .. } => ErrorCode::NotFound,
        EditError::DuplicateId { .. } | EditError::NameConflict { .. } | EditError::NoChange => {
            ErrorCode::Conflict
        }
        EditError::InvalidInput { .. } => ErrorCode::InvalidRequest,
        EditError::Validation { .. } => ErrorCode::ValidationFailed,
    };
    IpcError::new(code, e.to_string())
}

fn json_code(v: &impl serde::Serialize, field: &str) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.get(field).and_then(|c| c.as_str()).map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn verdict_code(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::NotApplicable => "not_applicable",
    }
}

fn is_storage_category(code: &str) -> bool {
    matches!(
        code,
        "usb_storage_disk"
            | "usb_storage_other_type"
            | "usb_portable_device"
            | "storage_attachment_unknown"
    )
}

/// Categories persisted in the device inventory.
fn stored_category(c: &DeviceCategory) -> bool {
    use rustward_core::classify::PeripheralKind;
    match c {
        DeviceCategory::Other | DeviceCategory::UsbStorageInterface => false,
        DeviceCategory::Peripheral { peripheral } => !matches!(
            peripheral,
            PeripheralKind::Hub | PeripheralKind::CompositeParent
        ),
        _ => true,
    }
}

fn utc_iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let day = utc_date(u64::try_from(secs).unwrap_or(0));
    let t = secs.rem_euclid(86_400);
    format!(
        "{day}T{:02}:{:02}:{:02}Z",
        t / 3600,
        (t % 3600) / 60,
        t % 60
    )
}

/// CSV field with quoting and spreadsheet-formula neutralization.
fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_owned()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn device_label(rec: &DeviceRecord, dec: &Decision) -> String {
    rec.friendly_name.clone().unwrap_or_else(|| {
        dec.classification
            .inquiry
            .as_ref()
            .map(|i| {
                format!(
                    "{} {}",
                    i.vendor_display(),
                    i.product_display().unwrap_or_default()
                )
                .trim()
                .to_owned()
            })
            .unwrap_or_else(|| mask_instance_id(&rec.instance_id))
    })
}

pub(crate) fn decision_brand_id(
    reason: &rustward_core::evaluate::DecisionReason,
) -> Option<String> {
    match reason {
        rustward_core::evaluate::DecisionReason::BrandAllowed { brand_id }
        | rustward_core::evaluate::DecisionReason::BrandDenied { brand_id }
        | rustward_core::evaluate::DecisionReason::BrandNotAllowed { brand_id } => {
            Some(brand_id.clone())
        }
        _ => None,
    }
}

pub(crate) fn decision_transport(category: &DeviceCategory) -> Option<String> {
    match category {
        DeviceCategory::UsbStorageDisk { transport } => {
            Some(json_code(&serde_json::json!({ "t": transport }), "t"))
        }
        _ => None,
    }
}

fn row_from(
    dec: &Decision,
    rec: &DeviceRecord,
    now: i64,
    synthetic: bool,
    state: &str,
) -> DeviceRow {
    let category = json_code(&dec.classification.category, "kind");
    let transport = decision_transport(&dec.classification.category);
    let matched_brand = decision_brand_id(&dec.reason);
    DeviceRow {
        device_key: device_key(&rec.instance_id),
        display_id: mask_instance_id(&rec.instance_id),
        category,
        transport,
        vendor: dec
            .classification
            .inquiry
            .as_ref()
            .map(rustward_core::ids::InquiryIdentity::vendor_display),
        product: dec
            .classification
            .inquiry
            .as_ref()
            .and_then(rustward_core::ids::InquiryIdentity::product_display),
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
        friendly_name: rec.friendly_name.clone(),
        matched_brand,
        first_seen_ms: now,
        last_seen_ms: now,
        present: rec.present != Some(false),
        synthetic,
        last_verdict: verdict_code(dec.verdict).into(),
        last_reason: json_code(&dec.reason, "code"),
        last_policy_version: dec.policy_version,
        enforcement_state: state.into(),
    }
}

fn device_view(r: &DeviceRow) -> DeviceView {
    device_view_with_evidence(r, None, None)
}

fn device_view_with_evidence(
    r: &DeviceRow,
    policy: Option<&rustward_core::policy::ValidatedPolicy>,
    verified_denied_keys: Option<&HashSet<String>>,
) -> DeviceView {
    let override_status = policy.and_then(|p| {
        let hw = r.vendor_level_id.as_deref().unwrap_or(&r.display_id);
        if p.device_denied(hw) {
            Some("denied".to_string())
        } else if p.device_allowed(hw) {
            Some("allowed".to_string())
        } else {
            None
        }
    });
    let enforcement_verified =
        verified_denied_keys.is_some_and(|keys| keys.contains(&r.device_key));

    DeviceView {
        device_key: r.device_key.clone(),
        display_id: r.display_id.clone(),
        category: r.category.clone(),
        storage_type: r.transport.clone(),
        vendor: r.vendor.clone(),
        product: r.product.clone(),
        usb_vid_pid: r.usb_vid_pid.clone(),
        vendor_level_id: r.vendor_level_id.clone(),
        friendly_name: r.friendly_name.clone(),
        matched_brand: r.matched_brand.clone(),
        present: r.present,
        synthetic: r.synthetic,
        first_seen_ms: r.first_seen_ms,
        last_seen_ms: r.last_seen_ms,
        simulated_decision: r.last_verdict.clone(),
        reason: r.last_reason.clone(),
        policy_version: r.last_policy_version,
        enforcement_state: r.enforcement_state.clone(),
        enforcement_verified,
        device_override: override_status,
    }
}

/// Features that do not exist (English, Turkish).
const UNSUPPORTED: &[(&str, &str)] = &[
    (
        "OS-level USB blocking by RustWard: not implemented; RustWard does not write Group Policy (administrator-guided workflow only)",
        "RustWard tarafından işletim sistemi düzeyinde USB engelleme: uygulanmadı; RustWard Grup İlkesine yazmaz (yalnızca yönetici kontrollü iş akışı)",
    ),
    (
        "Verified read/write denial: not measured; only installation denial is observed",
        "Doğrulanmış okuma/yazma engeli: ölçülmüyor; yalnızca kurulum reddi gözlenir",
    ),
    (
        "Manufacturer-based default deny: not verified on Windows (new and previously installed devices)",
        "Üreticiye dayalı varsayılan ret: Windows üzerinde doğrulanmadı (yeni ve önceden kurulu cihazlar)",
    ),
    (
        "Desktop toast notifications outside the app window: not implemented (in-app notices only)",
        "Uygulama penceresi dışındaki masaüstü bildirimleri: uygulanmadı (yalnızca uygulama içi bildirimler)",
    ),
    (
        "MTP/PTP and optical drives: scope decision pending",
        "MTP/PTP cihazları ve optik sürücüler: kapsam kararı bekliyor",
    ),
];

/// Native tests still open (English, Turkish).
const PENDING_NATIVE: &[(&str, &str)] = &[
    (
        "Manufacturer-based default deny with layered evaluation in the test VM",
        "Test sanal makinesinde katmanlı değerlendirmeyle üreticiye dayalı varsayılan ret",
    ),
    (
        "Previously installed devices of other brands under a default-deny policy",
        "Varsayılan ret politikasında diğer markaların önceden kurulu cihazları",
    ),
    (
        "Windows 11 behaviour of the device installation restrictions",
        "Aygıt yükleme kısıtlamalarının Windows 11 davranışı",
    ),
    (
        "Named-pipe DACL inspection (AccessChk) and impostor-pipe test",
        "Adlandırılmış kanal DACL incelemesi (AccessChk) ve sahte kanal testi",
    ),
    (
        "Hardware-encrypted USB identification in isolated test environment",
        "Donanım şifreli USB cihazının test ortamında tanımlanması",
    ),
];

fn event_view(e: SecurityEvent, names: l10n::Names<'_>) -> EventView {
    let message_tr = l10n::event(&e, names);
    let meta = EventMetadata::from_details(&e.details);
    let policy_revision = meta
        .policy_revision
        .or_else(|| e.policy_version.map(|v| format!("v{v}")));
    EventView {
        message_tr,
        id: e.id,
        utc_ms: e.utc_ms,
        severity: e.severity.as_str().into(),
        kind: e.kind,
        device_key: e.device_key,
        message: e.message,
        simulated: e.simulated,
        enforcement_state: e.enforcement_state,
        policy_version: e.policy_version,
        computer_name: meta.computer_name,
        manufacturer_id: meta.manufacturer_id,
        device_name: meta.device_name,
        vid_pid: meta.vid_pid,
        transport: meta.transport,
        pnp_problem_code: meta.pnp_problem_code,
        effective_decision: meta.effective_decision,
        enforcement_outcome: meta.enforcement_outcome,
        actor_username: meta.actor_username,
        windows_user: meta.windows_user,
        policy_revision,
        details: e.details,
        prev_hash: e.prev_hash,
        hash: e.hash,
    }
}

fn settings_view(s: &AppSettings) -> SettingsView {
    SettingsView {
        theme: match s.theme {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
        .into(),
        language: match s.language {
            Language::Tr => "tr",
            Language::En => "en",
        }
        .into(),
        notifications_enabled: s.notifications_enabled,
        audit_retention_days: s.audit_retention_days,
        inventory_refresh_seconds: s.inventory_refresh_seconds,
        reconcile_on_startup: s.reconcile_on_startup,
        session_idle_timeout_minutes: s.session_idle_timeout_minutes,
        notify_on_blocked: s.notify_on_blocked,
        notify_on_unblocked_warning: s.notify_on_unblocked_warning,
    }
}

fn settings_from(v: &SettingsView) -> Result<AppSettings, IpcError> {
    let settings = AppSettings {
        theme: match v.theme.as_str() {
            "system" => Theme::System,
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            _ => return Err(IpcError::new(ErrorCode::InvalidRequest, "invalid theme")),
        },
        language: match v.language.as_str() {
            "tr" => Language::Tr,
            "en" => Language::En,
            _ => return Err(IpcError::new(ErrorCode::InvalidRequest, "invalid language")),
        },
        notifications_enabled: v.notifications_enabled,
        audit_retention_days: v.audit_retention_days,
        inventory_refresh_seconds: v.inventory_refresh_seconds,
        reconcile_on_startup: v.reconcile_on_startup,
        session_idle_timeout_minutes: v.session_idle_timeout_minutes,
        notify_on_blocked: v.notify_on_blocked,
        notify_on_unblocked_warning: v.notify_on_unblocked_warning,
    };
    settings
        .validate()
        .map_err(|e| IpcError::new(ErrorCode::InvalidRequest, e))?;
    Ok(settings)
}

fn event_filter(q: &EventQuery) -> Result<EventFilter, IpcError> {
    let min_severity = match q.min_severity.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Some(
            Severity::parse(s)
                .ok_or_else(|| IpcError::new(ErrorCode::InvalidRequest, "invalid min_severity"))?,
        ),
        None => None,
    };
    Ok(EventFilter {
        text: q.text.clone(),
        min_severity,
        kind: q.kind.clone(),
        device_key: None,
        since_ms: q.since_ms,
        until_ms: q.until_ms,
        simulated: q.simulated,
        manufacturer_id: q.manufacturer_id.clone(),
        device_query: q.device_query.clone(),
        windows_user: q.windows_user.clone(),
        effective_decision: q.effective_decision.clone(),
        actor_username: q.actor_username.clone(),
        limit: q.limit,
        offset: q.offset,
    })
}

fn default_windows_user_resolver() -> Option<String> {
    rustward_windows::wts::current_single_interactive_windows_user()
}

fn default_computer_name() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn empty_snapshot() -> DeviceSnapshot {
    DeviceSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::Synthetic {
            description: "no inventory collected yet".into(),
        },
        devices: Vec::new(),
    }
}

struct Validated {
    catalog: ValidatedCatalog,
    policy: ValidatedPolicy,
    state: PolicyState,
    version: u64,
    created_ms: i64,
}

impl AppService {
    /// Create the service: initialize the policy if the database is empty,
    /// record a start event. A corrupt stored policy does not prevent
    /// starting (diagnostics must remain available) but every policy-
    /// dependent request then fails closed.
    pub fn new(
        mut store: Store,
        clock: Arc<dyn Clock>,
        inventory: Box<dyn InventorySource>,
        config: AppConfig,
        initial_state: &PolicyState,
    ) -> Result<Self, IpcError> {
        store
            .initialize_policy(initial_state, "rustward-setup")
            .map_err(storage_err)?;
        store
            .sync_catalog_if_outdated(initial_state, "rustward-setup")
            .map_err(storage_err)?;
        let started_ms = clock.now_ms();
        store
            .append_event(&NewEvent {
                severity: Severity::Info,
                kind: "backend_started".into(),
                device_key: None,
                message: format!("RustWard backend started ({})", config.backend.code()),
                simulated: false,
                enforcement_state: "pending_validation".into(),
                policy_version: None,
                details: serde_json::json!({ "version": config.app_version, "inventory": inventory.kind() }),
            })
            .map_err(storage_err)?;
        Ok(Self {
            inner: Mutex::new(Inner {
                store,
                inventory_kind: inventory.kind(),
                perf: Perf::default(),
                last: None,
                last_refresh_ms: None,
                last_inventory_error: None,
                consecutive_failures: 0,
                auth_window_start_ms: started_ms,
                auth_recorded_in_window: 0,
                auth_suppressed: 0,
                staged_restore: None,
                restore_counter: 0,
                auth: auth::AuthManager::new(false),
                startup_reconcile_status: None,
            }),
            inventory: Mutex::new(inventory),
            clock,
            config,
            provider: DeviceInstallRestrictionProvider,
            policy_source: Box::new(LivePolicySource),
            gpo_backend: None,
            windows_user_resolver: default_windows_user_resolver,
            started_ms,
        })
    }

    /// Replace the read-only policy source (tests, development backend).
    #[must_use]
    pub fn with_policy_source(mut self, source: Box<dyn PolicySource>) -> Self {
        self.policy_source = source;
        self
    }

    /// Enable or disable application-level operator authentication enforcement.
    #[must_use]
    pub fn with_app_auth(self, enabled: bool) -> Self {
        if let Ok(mut g) = self.inner.lock() {
            g.auth.set_force_auth(enabled);
        }
        self
    }

    /// Replace the active GPO enforcement backend (used in deterministic tests).
    #[must_use]
    pub fn with_gpo_backend(mut self, backend: Arc<dyn guided::GpoBackend>) -> Self {
        self.gpo_backend = Some(backend);
        self
    }

    /// Replace the interactive Windows user resolver (used in deterministic tests).
    #[must_use]
    pub fn with_windows_user_resolver(mut self, resolver: fn() -> Option<String>) -> Self {
        self.windows_user_resolver = resolver;
        self
    }

    pub(crate) fn resolved_windows_user(&self) -> Option<String> {
        (self.windows_user_resolver)()
    }

    pub(crate) fn resolved_computer_name(&self) -> Option<String> {
        default_computer_name()
    }

    pub(crate) fn capture_policy_unlocked(
        &self,
    ) -> Result<rustward_enforcement::policy_inspect::CapturedPolicy, String> {
        self.policy_source.capture(self.clock.now_ms())
    }

    /// Read-only enforcement readiness. Captures the policy (read-only),
    /// builds the plan merged with it, evaluates the activation gates (all
    /// refused in this build), models recovery and assesses installed
    /// storage devices. Nothing is written anywhere.
    fn enforcement_readiness(
        &self,
        g: &Inner,
        identity: &ClientIdentity,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<EnforcementReadinessView, IpcError> {
        use rustward_enforcement::activation::{ActivationRequest, evaluate_gates};
        use rustward_enforcement::installed_assessment::{AssessmentInputs, assess};
        use rustward_enforcement::policy_inspect::inspect;
        use rustward_enforcement::policy_state::{
            PolicySnapshot, apply_ops, compare, forward_ops, merge_plan, rollback_ops, suspend_ops,
        };
        let v = Self::validated(&g.store)?;
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        let existing = captured
            .as_ref()
            .map_or_else(|_| PolicySnapshot::default(), |c| c.values.clone());
        let mut env = Self::env_facts();
        if let Ok(c) = &captured {
            env.os_build = c.os.build.zip(c.os.ubr);
        }
        let inputs = PlanInputs {
            policy: &v.policy,
            catalog: &v.catalog,
            snapshot: &snap,
            env: &env,
        };
        let plan = merge_plan(&existing, &self.provider.plan(inputs));
        let dry = self.provider.dry_run(&plan, inputs);
        let gates = evaluate_gates(
            &plan,
            &dry,
            &inputs,
            &ActivationRequest {
                caller_is_elevated_administrator: identity.is_administrator && identity.elevated,
                existing_policy: captured.as_ref().ok().map(|c| c.values.clone()),
                ..ActivationRequest::default()
            },
        );
        let forward = forward_ops(&existing, &plan).unwrap_or_default();
        let after = apply_ops(&existing, &forward);
        let rollback = rollback_ops(&existing, &forward);
        let suspend = suspend_ops(&after);
        let state = self.provider.status();
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let text = |tr: &str, en: &str| TextTrEn {
            tr: tr.into(),
            en: en.into(),
        };
        Ok(EnforcementReadinessView {
            actual_enforcement: ActualEnforcementView {
                state: state.code().into(),
                label_tr: state.label_tr().into(),
                label_en: state.label_en().into(),
                verified_protection: state.is_verified_protection(),
                activation_available: rustward_enforcement::ACTIVATION_ENABLED,
            },
            inspection_source: if captured.is_ok() {
                self.policy_source.name().into()
            } else {
                "unavailable".into()
            },
            inspection: captured.as_ref().ok().map(|c| inspect(c, Some(&plan))),
            inspection_error: captured.as_ref().err().cloned(),
            plan_fingerprint: gates.plan_fingerprint.clone(),
            conflicts: compare(&existing, &plan).conflicts,
            planned_changes: plan.changes.clone(),
            gates: gates
                .gates
                .iter()
                .map(|x| GateView {
                    code: x.id.code().into(),
                    status: x.status,
                    detail: x.detail.clone(),
                })
                .collect(),
            required_permissions: vec![
                text(
                    "Okuma: politika incelemesi ve envanter için standart kullanıcı yeterlidir (yalnızca KEY_READ).",
                    "Read: a standard user suffices for inspection and inventory (KEY_READ only).",
                ),
                text(
                    "Gelecekteki etkinleştirme: HKLM\\SOFTWARE\\Policies altına yazmak için SYSTEM veya yükseltilmiş yönetici gerekir. Bu sürümde yazma kodu yoktur.",
                    "Future activation: writing under HKLM\\SOFTWARE\\Policies needs SYSTEM or an elevated administrator. This build contains no write code.",
                ),
                text(
                    "Kurulu aygıtların kaldırılması: yalnızca yöneticinin Aygıt Yöneticisi'nde elle yapacağı bir işlemdir.",
                    "Removing installed devices: only a manual administrator action in Device Manager.",
                ),
            ],
            recovery: RecoveryReadinessView {
                steps: plan.recovery.clone(),
                rollback_modelled_exact: apply_ops(&after, &rollback) == existing,
                forward_operations: count(forward.len()),
                rollback_operations: count(rollback.len()),
                suspend_operations: count(suspend.len()),
            },
            installed: assess(&AssessmentInputs {
                snapshot: &snap,
                policy: &v.policy,
                catalog: &v.catalog,
                plan: &plan,
                existing: &existing,
                sanitize: true,
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, IpcError> {
        self.inner
            .lock()
            .map_err(|_| IpcError::new(ErrorCode::Internal, "backend state lock poisoned"))
    }

    /// Brand id -> display name from the active catalog (id when unknown).
    fn brand_names(store: &Store) -> impl Fn(&str) -> String + use<> {
        let map: HashMap<String, String> = Self::validated(store)
            .map(|v| Self::name_map(&v))
            .unwrap_or_default();
        move |id: &str| map.get(id).cloned().unwrap_or_else(|| id.to_string())
    }

    fn name_map(v: &Validated) -> HashMap<String, String> {
        v.state
            .catalog
            .brands
            .iter()
            .map(|b| (b.id.clone(), b.display_name.clone()))
            .collect()
    }

    /// Brand id -> display name for a validated state.
    fn names_from(v: &Validated) -> impl Fn(&str) -> String + use<> {
        let map = Self::name_map(v);
        move |id: &str| map.get(id).cloned().unwrap_or_else(|| id.to_string())
    }

    /// Turkish catalog + policy warnings (deduplicated).
    fn warnings_tr(v: &Validated, names: l10n::Names<'_>) -> Vec<String> {
        combined_warnings(&v.catalog, &v.policy)
            .into_iter()
            .map(|(code, detail)| l10n::issue(code, &detail, names))
            .collect()
    }

    fn validated(store: &Store) -> Result<Validated, IpcError> {
        let stored = store
            .active_policy()
            .map_err(storage_err)?
            .ok_or_else(|| IpcError::new(ErrorCode::Unavailable, "no active policy"))?;
        let v = stored.state.validate().map_err(edit_err)?;
        Ok(Validated {
            catalog: v.catalog,
            policy: v.policy,
            state: stored.state,
            version: stored.version,
            created_ms: stored.created_ms,
        })
    }

    fn enforcement_state_code(&self) -> &'static str {
        self.provider.status().code()
    }

    fn env_facts() -> EnvironmentFacts {
        EnvironmentFacts {
            is_windows: cfg!(windows),
            ..EnvironmentFacts::default()
        }
    }

    /// Record a host-level event (service lifecycle, IPC errors).
    pub fn record_event(
        &self,
        severity: Severity,
        kind: &str,
        message: &str,
    ) -> Result<(), IpcError> {
        let mut g = self.lock()?;
        g.store
            .append_event(&NewEvent {
                severity,
                kind: kind.into(),
                device_key: None,
                message: message.into(),
                simulated: false,
                enforcement_state: self.enforcement_state_code().into(),
                policy_version: None,
                details: serde_json::json!({ "backend": self.config.backend.code() }),
            })
            .map_err(storage_err)?;
        Ok(())
    }

    /// Mirror every committed audit event to `observer` (the Windows
    /// service attaches the Event Log writer here).
    pub fn set_event_observer(&self, observer: Arc<dyn EventObserver>) -> Result<(), IpcError> {
        let mut g = self.lock()?;
        g.store.set_event_observer(observer).map_err(storage_err)
    }

    /// Write a rate-limited refusal event (authorization failures, rejected
    /// restore attempts): at most [`AUTH_AUDIT_LIMIT`] per window; the rest
    /// are counted and reported with the next recorded one.
    fn record_refusal(
        &self,
        g: &mut Inner,
        kind: &str,
        message: String,
        mut details: serde_json::Value,
    ) {
        let now = self.clock.now_ms();
        if now.saturating_sub(g.auth_window_start_ms) >= AUTH_AUDIT_WINDOW_MS {
            g.auth_window_start_ms = now;
            g.auth_recorded_in_window = 0;
        }
        if g.auth_recorded_in_window >= AUTH_AUDIT_LIMIT {
            g.auth_suppressed = g.auth_suppressed.saturating_add(1);
            return;
        }
        g.auth_recorded_in_window += 1;
        let suppressed = std::mem::take(&mut g.auth_suppressed);
        let mut message = message;
        if suppressed > 0 {
            message.push_str(&format!(
                " ({suppressed} earlier refusals not recorded individually)"
            ));
        }
        if let Some(obj) = details.as_object_mut() {
            obj.insert("suppressed_before".into(), suppressed.into());
        }
        let _ = g.store.append_event(&NewEvent {
            severity: Severity::Warning,
            kind: kind.into(),
            device_key: None,
            message,
            simulated: false,
            enforcement_state: self.enforcement_state_code().into(),
            policy_version: None,
            details,
        });
    }

    fn record_authorization_failure(
        &self,
        request: &Request,
        identity: &ClientIdentity,
        error: &IpcError,
    ) {
        let Ok(mut g) = self.lock() else {
            return;
        };
        let message = format!(
            "{} refused for {}: {}",
            request.name(),
            identity.actor(),
            error.message
        );
        let details = serde_json::json!({
            "request": request.name(),
            "account": identity.account,
            "is_administrator": identity.is_administrator,
            "elevated": identity.elevated,
            "channel": identity.channel_max_access,
        });
        self.record_refusal(&mut g, "authorization_failed", message, details);
    }

    /// Record a failed restore attempt (any stage).
    fn record_restore_failure(
        &self,
        g: &mut Inner,
        identity: &ClientIdentity,
        stage: &str,
        reason: &str,
        target: &str,
        error: &IpcError,
    ) {
        let message = format!(
            "restore {stage} refused for {} ({target}): {reason}",
            identity.actor()
        );
        let details = serde_json::json!({
            "stage": stage,
            "reason": reason,
            "target": target,
            "account": identity.account,
            "error_code": error.code,
            "error": error.message,
        });
        self.record_refusal(g, "restore_failed", message, details);
    }

    fn backup_dir(&self) -> Result<PathBuf, IpcError> {
        self.config.backup_dir.clone().ok_or_else(|| {
            IpcError::new(
                ErrorCode::NotSupported,
                "backups are not configured on this backend",
            )
        })
    }

    fn list_backups(&self) -> Result<Vec<BackupView>, IpcError> {
        let dir = self.backup_dir()?;
        let g = self.lock()?;
        let records = g.store.list_backups().map_err(storage_err)?;
        Ok(records.into_iter().map(|r| backup_view(&dir, r)).collect())
    }

    fn prepare_restore(
        &self,
        file_name: &str,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError> {
        let dir = self.backup_dir()?;
        let mut g = self.lock()?;
        let candidate = match g.store.inspect_backup(&dir, file_name) {
            Ok(c) => c,
            Err(e) => {
                let reason = match &e {
                    StorageError::BackupRejected(r) => r.code().to_owned(),
                    other => format!("error: {other}"),
                };
                let err = storage_err(e);
                self.record_restore_failure(&mut g, identity, "prepare", &reason, file_name, &err);
                return Err(err);
            }
        };
        let current = Self::validated(&g.store)?;
        let now = self.clock.now_ms();
        g.restore_counter = g.restore_counter.wrapping_add(1);
        let restore_id: String = sha256_hex(
            format!(
                "{}|{now}|{}|{}|{}",
                candidate.record.sha256,
                g.restore_counter,
                identity.account,
                std::process::id()
            )
            .as_bytes(),
        )
        .chars()
        .take(32)
        .collect();
        let current_settings = g.store.settings().map_err(storage_err)?;
        let changes = restore_changes(&current.state, &current_settings, &candidate);
        let changes_tr = changes.iter().map(|c| l10n::text(c)).collect();
        let mut preview = RestorePreviewView {
            changes_tr,
            notice_tr: String::new(),
            restore_id: restore_id.clone(),
            file_name: candidate.record.file_name.clone(),
            sha256: candidate.record.sha256.clone(),
            backup_created_ms: candidate.record.created_ms,
            backup_policy_version: candidate.record.policy_version,
            current_policy_version: current.version,
            resulting_policy_version: current.version.saturating_add(1),
            backup_workstation_id: candidate.state.policy.workstation_id.clone(),
            changes,
            expires_ms: now.saturating_add(RESTORE_PREVIEW_TTL_MS),
            notice: format!(
                "Nothing has been changed yet. Applying stores the backup's policy and settings as NEW policy v{}; earlier versions, the change history and the audit log are kept, a pre-restore backup is taken first, and no operating-system policy is changed (enforcement is disabled).",
                current.version.saturating_add(1)
            ),
        };
        preview.notice_tr = l10n::text(&preview.notice);
        g.store
            .append_event(&NewEvent {
                severity: Severity::Info,
                kind: "restore_prepared".into(),
                device_key: None,
                message: format!(
                    "restore of {} (backup v{}) prepared by {}; not applied",
                    candidate.record.file_name,
                    candidate.record.policy_version,
                    identity.actor()
                ),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: Some(current.version),
                details: serde_json::json!({
                    "restore_id": restore_id,
                    "backup_file": candidate.record.file_name,
                    "backup_sha256": candidate.record.sha256,
                    "backup_policy_version": candidate.record.policy_version,
                    "current_policy_version": current.version,
                    "changes": preview.changes,
                }),
            })
            .map_err(storage_err)?;
        g.staged_restore = Some(StagedRestore {
            restore_id,
            account: identity.account.clone(),
            created_ms: now,
            candidate,
        });
        Ok(ResponseBody::RestorePreview(preview))
    }

    fn apply_restore(
        &self,
        restore_id: &str,
        expected: u64,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError> {
        let dir = self.backup_dir()?;
        let mut g = self.lock()?;
        // Single use: whatever happens next, this preview is consumed.
        let staged = g.staged_restore.take();
        let refusal = match &staged {
            None => Some(("no_prepared_restore", ErrorCode::NotFound)),
            Some(st) if st.restore_id != restore_id => {
                Some(("unknown_restore_id", ErrorCode::NotFound))
            }
            Some(st) if st.account != identity.account => {
                Some(("different_administrator", ErrorCode::Unauthorized))
            }
            Some(st)
                if self.clock.now_ms().saturating_sub(st.created_ms) > RESTORE_PREVIEW_TTL_MS =>
            {
                Some(("preview_expired", ErrorCode::Conflict))
            }
            Some(_) => None,
        };
        if let Some((reason, code)) = refusal {
            // Keep a valid preview for its owner if someone else tried to use it.
            if reason == "different_administrator" || reason == "unknown_restore_id" {
                g.staged_restore = staged;
            }
            let err = IpcError::new(
                code,
                format!("restore cannot be applied: {reason}; prepare it again"),
            );
            self.record_restore_failure(&mut g, identity, "apply", reason, restore_id, &err);
            return Err(err);
        }
        let Some(staged) = staged else {
            return Err(IpcError::new(ErrorCode::NotFound, "no prepared restore"));
        };
        let actor = identity.actor();
        let target = staged.candidate.record.file_name.clone();
        let attempt = (|| -> Result<(BackupRecord, u64), IpcError> {
            let active = Self::validated(&g.store)?.version;
            if active != expected {
                return Err(storage_err(StorageError::VersionConflict {
                    expected,
                    active,
                }));
            }
            let pre = g
                .store
                .create_backup(&dir, BackupKind::PreRestore, &actor)
                .map_err(storage_err)?;
            let v = g
                .store
                .apply_restored_state(&staged.candidate, expected, &staged.restore_id, &actor)
                .map_err(storage_err)?;
            Ok((pre, v))
        })();
        match attempt {
            Ok((pre, version)) => {
                self.reevaluate_locked(&mut g)?;
                Ok(ResponseBody::Mutation(MutationView {
                    policy_version: version,
                    catalog_version: staged.candidate.state.catalog.catalog_version.clone(),
                    summary_tr: l10n::text(&format!(
                        "backup {target} applied as policy v{version}; previous state saved as {}",
                        pre.file_name
                    )),
                    summary: format!(
                        "backup {target} applied as policy v{version}; previous state saved as {}",
                        pre.file_name
                    ),
                    warnings: Vec::new(),
                    warnings_tr: Vec::new(),
                }))
            }
            Err(err) => {
                let reason = format!("{:?}", err.code).to_lowercase();
                self.record_restore_failure(&mut g, identity, "apply", &reason, &target, &err);
                Err(err)
            }
        }
    }

    /// Apply audit retention (scheduled by the service).
    pub fn apply_retention(&self) -> Result<usize, IpcError> {
        let mut g = self.lock()?;
        g.store.apply_retention().map_err(storage_err)
    }

    /// Record an `audit_checkpoint` (chain head summary, mirrored to the
    /// Event Log). Called by the service at start and daily.
    pub fn record_audit_checkpoint(&self) -> Result<rustward_storage::AuditCheckpoint, IpcError> {
        let mut g = self.lock()?;
        g.store.record_audit_checkpoint().map_err(storage_err)
    }

    /// Retry Event Log delivery of pending events (no-op without a mirror).
    pub fn retry_event_mirror(&self) {
        if let Ok(mut g) = self.lock() {
            g.store.retry_mirror();
        }
    }

    /// Configured refresh interval in seconds (default on error).
    #[must_use]
    pub fn refresh_interval_seconds(&self) -> u32 {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.store.settings().ok())
            .map_or(30, |s| s.inventory_refresh_seconds)
    }

    /// Health of the backend loop.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.inner
            .lock()
            .map_or(u32::MAX, |g| g.consecutive_failures)
    }

    /// Collect the inventory, record detections and simulated or observed policy status.
    pub fn refresh_inventory(&self) -> Result<RefreshSummary, IpcError> {
        // Enumerate Windows devices and inspect Windows policy WITHOUT the state lock;
        // refreshes are serialized by the inventory lock.
        let mut inv = self
            .inventory
            .lock()
            .map_err(|_| IpcError::new(ErrorCode::Internal, "inventory lock poisoned"))?;
        let t = std::time::Instant::now();
        let collected = inv.collect();
        let collect_ms = elapsed_ms(t);
        drop(inv);
        let captured = self.capture_policy_unlocked();
        let mut g = self.lock()?;
        let t = std::time::Instant::now();
        let result = self.apply_collected(&mut g, collected, captured);
        let apply_ms = elapsed_ms(t);
        let now = self.clock.now_ms();
        let p = &mut g.perf;
        p.last_collect_ms = Some(collect_ms);
        p.last_apply_ms = Some(apply_ms);
        p.max_collect_ms = Some(p.max_collect_ms.unwrap_or(0).max(collect_ms));
        p.refreshes += 1;
        if p.first_refresh_done_ms.is_none() {
            p.first_refresh_done_ms = Some(now - self.started_ms);
        }
        if let Ok(s) = &result {
            p.last_devices = u64::try_from(s.devices).ok();
        }
        result
    }

    /// Inspect live Windows SetupAPI + GPO restrictions after background refresh so
    /// desktop notifications remain timely even when no UI window is open.
    pub fn observe_windows_enforcement(&self) -> Result<(), IpcError> {
        if !self.is_live_windows() {
            return Ok(());
        }
        let captured = self.capture_policy_unlocked();
        if captured.is_err() {
            return Ok(());
        }
        let mut g = self.lock()?;
        let synthetic = g
            .last
            .as_ref()
            .is_none_or(|s| matches!(s.source, SnapshotSource::Synthetic { .. }));
        if synthetic {
            return Ok(());
        }
        let _ = self.enforcement_observation(&mut g, captured)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn device_audit_details(
        rec: &DeviceRecord,
        dec: &Decision,
        computer_name: Option<&str>,
        windows_user: Option<&str>,
        policy_revision: Option<&str>,
        effective_decision: Option<&str>,
        enforcement_outcome: Option<&str>,
        extra: Option<(&str, serde_json::Value)>,
    ) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "category".into(),
            serde_json::json!(json_code(&dec.classification.category, "kind")),
        );
        map.insert(
            "display_id".into(),
            serde_json::json!(mask_instance_id(&rec.instance_id)),
        );
        if let Some(cn) = computer_name {
            map.insert("computer_name".into(), serde_json::json!(cn));
        }
        if let Some(m) = decision_brand_id(&dec.reason) {
            map.insert("manufacturer_id".into(), serde_json::json!(m));
        }
        let dev_name = device_label(rec, dec);
        map.insert("device_name".into(), serde_json::json!(dev_name));
        if let Some(u) = &dec.classification.usb_ancestor {
            map.insert(
                "vid_pid".into(),
                serde_json::json!(format!("{:04X}:{:04X}", u.ids.vid, u.ids.pid)),
            );
        }
        if let Some(transport) = decision_transport(&dec.classification.category) {
            map.insert("transport".into(), serde_json::json!(transport));
        }
        if let Some(code) = rec.problem_code {
            map.insert("pnp_problem_code".into(), serde_json::json!(code));
        }
        if let Some(wu) = windows_user {
            map.insert("windows_user".into(), serde_json::json!(wu));
        }
        if let Some(pr) = policy_revision {
            map.insert("policy_revision".into(), serde_json::json!(pr));
        }
        if let Some(ed) = effective_decision {
            map.insert("effective_decision".into(), serde_json::json!(ed));
        }
        if let Some(eo) = enforcement_outcome {
            map.insert("enforcement_outcome".into(), serde_json::json!(eo));
        }
        if let Some((k, v)) = extra {
            map.insert(k.to_owned(), v);
        }
        serde_json::Value::Object(map)
    }

    fn apply_collected(
        &self,
        g: &mut Inner,
        collected: Result<(DeviceSnapshot, Vec<String>), String>,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<RefreshSummary, IpcError> {
        let now = self.clock.now_ms();
        let state_code = self.enforcement_state_code();
        let (snap, warnings) = match collected {
            Ok(x) => x,
            Err(e) => {
                g.consecutive_failures = g.consecutive_failures.saturating_add(1);
                g.last_inventory_error = Some(e.clone());
                let _ = g.store.append_event(&NewEvent {
                    severity: Severity::Warning,
                    kind: "inventory_failed".into(),
                    device_key: None,
                    message: format!("device inventory failed: {e}"),
                    simulated: false,
                    enforcement_state: state_code.into(),
                    policy_version: None,
                    details: serde_json::json!({ "consecutive_failures": g.consecutive_failures }),
                });
                return Err(IpcError::new(
                    ErrorCode::Unavailable,
                    format!("inventory failed: {e}"),
                ));
            }
        };
        g.consecutive_failures = 0;
        g.last_inventory_error = None;
        let synthetic = matches!(snap.source, SnapshotSource::Synthetic { .. });
        let v = Self::validated(&g.store)?;
        let decisions = evaluate_snapshot(&snap, &v.policy, &v.catalog);
        let by_id: HashMap<String, &Decision> = decisions
            .iter()
            .map(|d| (d.instance_id.to_ascii_uppercase(), d))
            .collect();
        let windows_user = self.resolved_windows_user();
        let computer_name = Some(
            self.resolved_computer_name()
                .unwrap_or_else(|| v.state.policy.workstation_id.clone()),
        );
        let policy_revision = Some(format!("v{}", v.version));
        let verified_denied_keys: HashSet<String> = if !synthetic {
            if let Ok(ref cap) = captured {
                rustward_enforcement::observer::observe(&snap, &v.policy, &v.catalog, cap)
                    .devices
                    .into_iter()
                    .filter(|d| {
                        d.evidence == rustward_enforcement::observer::EvidenceLevel::InstallDenied
                    })
                    .map(|d| device_key(&d.instance_id))
                    .collect()
            } else {
                HashSet::new()
            }
        } else {
            HashSet::new()
        };
        let old = g.last.take().unwrap_or_else(empty_snapshot);
        let diff = diff_snapshots(&old, &snap);
        let mut summary = RefreshSummary {
            devices: snap.devices.len(),
            ..RefreshSummary::default()
        };

        let event = |store: &mut Store,
                     severity,
                     kind: &str,
                     key: Option<String>,
                     message: String,
                     simulated: bool,
                     details: serde_json::Value| {
            store.append_event(&NewEvent {
                severity,
                kind: kind.into(),
                device_key: key,
                message,
                simulated,
                enforcement_state: state_code.into(),
                policy_version: Some(v.version),
                details,
            })
        };

        for rec in &diff.arrived {
            let Some(dec) = by_id.get(&rec.instance_id.to_ascii_uppercase()) else {
                continue;
            };
            if !stored_category(&dec.classification.category) {
                continue;
            }
            summary.arrived += 1;
            let key = device_key(&rec.instance_id);
            let label = device_label(rec, dec);
            let category = json_code(&dec.classification.category, "kind");
            let eff_dec = match dec.verdict {
                Verdict::Allow => "allowed",
                Verdict::Deny => "blocked",
                Verdict::NotApplicable => "not_applicable",
            };
            let windows_blocked = verified_denied_keys.contains(&key);
            let outcome = if synthetic {
                "simulated"
            } else if dec.verdict == Verdict::Deny && windows_blocked {
                "windows_blocked_verified"
            } else if dec.verdict == Verdict::Deny && captured.is_ok() {
                "not_enforced"
            } else if dec.verdict == Verdict::Allow && captured.is_ok() {
                "allowed"
            } else {
                "unverified"
            };
            event(
                &mut g.store,
                Severity::Info,
                "device_detected",
                Some(key.clone()),
                format!(
                    "{label} detected ({category}){}",
                    if synthetic { " [SYNTHETIC]" } else { "" }
                ),
                synthetic,
                Self::device_audit_details(
                    rec,
                    dec,
                    computer_name.as_deref(),
                    windows_user.as_deref(),
                    policy_revision.as_deref(),
                    Some(eff_dec),
                    Some(outcome),
                    None,
                ),
            )
            .map_err(storage_err)?;
            if dec.classification.category.scope() != StorageScope::NotInScope {
                let deny = dec.verdict == Verdict::Deny;
                if deny {
                    summary.simulated_denials += 1;
                }
                let e = explain(dec);
                if synthetic || (deny && captured.is_err()) {
                    let mut det = Self::device_audit_details(
                        rec,
                        dec,
                        computer_name.as_deref(),
                        windows_user.as_deref(),
                        policy_revision.as_deref(),
                        Some(eff_dec),
                        Some("simulated"),
                        Some((
                            "reason",
                            serde_json::json!(json_code(&dec.reason, "code")),
                        )),
                    );
                    if let Some(obj) = det.as_object_mut() {
                        obj.insert("verdict".into(), serde_json::json!(verdict_code(dec.verdict)));
                        obj.insert("summary_tr".into(), serde_json::json!(e.summary_tr));
                    }
                    event(
                        &mut g.store,
                        if deny {
                            Severity::Warning
                        } else {
                            Severity::Info
                        },
                        "decision_simulated",
                        Some(key),
                        format!("{label}: {} — enforcement NOT ACTIVE", e.summary_en),
                        true,
                        det,
                    )
                    .map_err(storage_err)?;
                } else if deny && !windows_blocked {
                    event(
                        &mut g.store,
                        Severity::Warning,
                        "usb_deny_not_enforced",
                        Some(key),
                        format!(
                            "{label}: denied by RustWard policy, but Windows installation blocking is NOT currently verified (apply Group Policy or reconnect)."
                        ),
                        false,
                        Self::device_audit_details(
                            rec,
                            dec,
                            computer_name.as_deref(),
                            windows_user.as_deref(),
                            policy_revision.as_deref(),
                            Some("blocked"),
                            Some("not_enforced"),
                            Some(("summary_tr", serde_json::json!(e.summary_tr))),
                        ),
                    )
                    .map_err(storage_err)?;
                }
            }
        }
        if !diff.removed.is_empty() {
            let old_index = old.index();
            for rec in &diff.removed {
                // Removal events only for devices we track (category from the old tree).
                let cl = classify(&old_index, rec);
                if !stored_category(&cl.category) {
                    continue;
                }
                let old_dec = evaluate_device(cl, rec, &v.policy, &v.catalog);
                summary.removed += 1;
                event(
                    &mut g.store,
                    Severity::Info,
                    "device_removed",
                    Some(device_key(&rec.instance_id)),
                    format!("{} removed", device_label(rec, &old_dec)),
                    synthetic,
                    Self::device_audit_details(
                        rec,
                        &old_dec,
                        computer_name.as_deref(),
                        windows_user.as_deref(),
                        policy_revision.as_deref(),
                        None,
                        Some("disconnected"),
                        None,
                    ),
                )
                .map_err(storage_err)?;
            }
        }
        for link in correlate_reenumeration(&diff) {
            event(
                &mut g.store,
                Severity::Info,
                "device_reenumerated",
                Some(device_key(&link.arrived)),
                "USB device re-enumerated on the same port (e.g. encrypted drive unlocked); the new device is evaluated independently".into(),
                synthetic,
                serde_json::json!({ "removed": mask_instance_id(&link.removed), "arrived": mask_instance_id(&link.arrived) }),
            )
            .map_err(storage_err)?;
        }

        let mut present_keys = Vec::new();
        let mut rows = Vec::new();
        for (rec, dec) in snap.devices.iter().zip(decisions.iter()) {
            if !stored_category(&dec.classification.category) {
                continue;
            }
            let row = row_from(dec, rec, now, synthetic, state_code);
            if row.present {
                present_keys.push(row.device_key.clone());
            }
            rows.push(row);
            summary.stored += 1;
        }
        g.store.upsert_devices(&rows).map_err(storage_err)?;
        g.store
            .mark_absent_except(&present_keys)
            .map_err(storage_err)?;
        if !warnings.is_empty() {
            event(
                &mut g.store,
                Severity::Warning,
                "inventory_warnings",
                None,
                format!("{} device properties could not be read", warnings.len()),
                false,
                serde_json::json!({ "count": warnings.len() }),
            )
            .map_err(storage_err)?;
        }
        g.last = Some(snap);
        g.last_refresh_ms = Some(now);
        Ok(summary)
    }

    /// Re-evaluate stored devices after a policy change (no detection events).
    fn reevaluate_locked(&self, g: &mut Inner) -> Result<(), IpcError> {
        let Some(snap) = g.last.clone() else {
            return Ok(());
        };
        let v = Self::validated(&g.store)?;
        let synthetic = matches!(snap.source, SnapshotSource::Synthetic { .. });
        let now = self.clock.now_ms();
        let decisions = evaluate_snapshot(&snap, &v.policy, &v.catalog);
        let mut changed = 0u32;
        let existing: HashMap<String, DeviceRow> = g
            .store
            .list_devices(false)
            .map_err(storage_err)?
            .into_iter()
            .map(|r| (r.device_key.clone(), r))
            .collect();
        for (rec, dec) in snap.devices.iter().zip(decisions.iter()) {
            if !stored_category(&dec.classification.category) {
                continue;
            }
            let mut row = row_from(dec, rec, now, synthetic, self.enforcement_state_code());
            if let Some(old) = existing.get(&row.device_key) {
                row.first_seen_ms = old.first_seen_ms;
                row.last_seen_ms = old.last_seen_ms;
                if old.last_verdict != row.last_verdict {
                    changed += 1;
                }
            }
            g.store.upsert_device(&row).map_err(storage_err)?;
        }
        g.store
            .append_event(&NewEvent {
                severity: Severity::Info,
                kind: "decisions_reevaluated".into(),
                device_key: None,
                message: format!(
                    "simulated decisions re-evaluated under policy v{}; {changed} changed",
                    v.version
                ),
                simulated: true,
                enforcement_state: self.enforcement_state_code().into(),
                policy_version: Some(v.version),
                details: serde_json::json!({ "changed": changed }),
            })
            .map_err(storage_err)?;
        Ok(())
    }

    /// Replace the inventory source with the bundled synthetic fixture.
    pub fn load_synthetic(&self) -> Result<RefreshSummary, IpcError> {
        if !self.config.allow_synthetic {
            return Err(IpcError::new(
                ErrorCode::NotSupported,
                "synthetic inventory is disabled on this backend",
            ));
        }
        let fixture = FixtureInventory::bundled().map_err(internal)?;
        {
            let mut inv = self
                .inventory
                .lock()
                .map_err(|_| IpcError::new(ErrorCode::Internal, "inventory lock poisoned"))?;
            let kind = fixture.kind();
            *inv = Box::new(fixture);
            self.lock()?.inventory_kind = kind;
        }
        self.refresh_inventory()
    }

    fn service_status(&self, g: &Inner) -> ServiceStatusView {
        let healthy = g.consecutive_failures == 0;
        let mut view = ServiceStatusView {
            message_tr: String::new(),
            backend: self.config.backend.code().into(),
            state: if healthy { "running" } else { "degraded" }.into(),
            healthy,
            started_ms: Some(self.started_ms),
            last_refresh_ms: g.last_refresh_ms,
            message: match (&g.last_inventory_error, self.config.backend) {
                (Some(e), _) => format!("inventory error: {e}"),
                (None, BackendKind::DevBackend) => {
                    "development backend (in-process, not the Windows service)".into()
                }
                (None, BackendKind::WindowsService) => "RustWard service running".into(),
            },
        };
        view.message_tr = l10n::text(&view.message);
        view
    }

    pub(crate) fn event_view(e: SecurityEvent, names: l10n::Names<'_>) -> EventView {
        event_view(e, names)
    }

    pub(crate) fn event_filter(q: &EventQuery) -> Result<EventFilter, IpcError> {
        event_filter(q)
    }

    pub(crate) fn apply_edit_with_actor(
        &self,
        edit: &PolicyEdit,
        expected: u64,
        identity: &ClientIdentity,
        actor_override: Option<&str>,
    ) -> Result<ResponseBody, IpcError> {
        self.mutate_with_actor(edit, expected, identity, actor_override)
    }

    fn mutate_with_actor(
        &self,
        edit: &PolicyEdit,
        expected: u64,
        identity: &ClientIdentity,
        actor_override: Option<&str>,
    ) -> Result<ResponseBody, IpcError> {
        let actor_str = actor_override
            .map(str::to_owned)
            .unwrap_or_else(|| identity.actor());
        let mut g = self.lock()?;
        let v = Self::validated(&g.store)?;
        if v.version != expected {
            return Err(IpcError::new(
                ErrorCode::Conflict,
                format!(
                    "policy is at v{}, the change was prepared for v{expected}; reload and retry",
                    v.version
                ),
            ));
        }
        let outcome = apply_edit(&v.state, edit).map_err(edit_err)?;
        g.store
            .commit_policy_edit(&outcome, &actor_str)
            .map_err(storage_err)?;
        self.reevaluate_locked(&mut g)?;
        let names = Self::brand_names(&g.store);
        let summary_tr = l10n::change(
            &outcome.change.action,
            &outcome.change.brand_id,
            &outcome.change.summary,
            &names,
        );
        let warnings_tr = Self::validated(&g.store)
            .map(|v| Self::warnings_tr(&v, &names))
            .unwrap_or_default();
        Ok(ResponseBody::Mutation(MutationView {
            policy_version: outcome.state.policy.policy_version,
            catalog_version: outcome.state.catalog.catalog_version.clone(),
            summary: outcome.change.summary,
            warnings: outcome.warnings,
            summary_tr,
            warnings_tr,
        }))
    }

    fn verified_denied_keys(
        &self,
        g: &Inner,
        captured: &Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> HashSet<String> {
        let Ok(cap) = captured else {
            return HashSet::new();
        };
        let Ok(v) = Self::validated(&g.store) else {
            return HashSet::new();
        };
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        if matches!(snap.source, SnapshotSource::Synthetic { .. }) {
            return HashSet::new();
        }
        rustward_enforcement::observer::observe(&snap, &v.policy, &v.catalog, cap)
            .devices
            .into_iter()
            .filter(|d| d.evidence == rustward_enforcement::observer::EvidenceLevel::InstallDenied)
            .map(|d| device_key(&d.instance_id))
            .collect()
    }

    fn manufacturers(v: &Validated) -> ManufacturersView {
        let names = Self::names_from(v);
        let warnings: Vec<String> = combined_warnings(&v.catalog, &v.policy)
            .into_iter()
            .map(|(_, detail)| detail)
            .collect();
        let warnings_tr = Self::warnings_tr(v, &names);
        let manufacturers = v
            .state
            .catalog
            .brands
            .iter()
            .map(|b| {
                let rule = v
                    .state
                    .policy
                    .allowed_brands
                    .iter()
                    .find(|r| r.brand_id == b.id);
                let quoted = format!("{:?}", b.id);
                ManufacturerView {
                    id: b.id.clone(),
                    display_name: b.display_name.clone(),
                    aliases: b.aliases.clone(),
                    identifiers: b
                        .identifiers
                        .iter()
                        .map(|i| IdentifierView {
                            kind: json_code(&serde_json::json!({ "k": i.kind }), "k"),
                            value: i.value.clone(),
                            verification: json_code(
                                &serde_json::json!({ "v": i.verification }),
                                "v",
                            ),
                            source: i.source.clone(),
                            enforceable: i.kind.enforceable(),
                            vendor_level_ids: if i.kind == IdentifierKind::InquiryVendor {
                                StorageIdNamespace::ALL
                                    .iter()
                                    .filter_map(|ns| {
                                        vendor_level_hardware_id(*ns, "Disk", &i.value).ok()
                                    })
                                    .collect()
                            } else {
                                Vec::new()
                            },
                        })
                        .collect(),
                    notes: b.notes.clone(),
                    allowed: rule.is_some(),
                    enabled: rule.is_some_and(|r| r.enabled),
                    denied: v.policy.brand_denied(&b.id),
                    enforceable: b.enforceable_identifiers().next().is_some(),
                    issues: warnings
                        .iter()
                        .filter(|w| w.contains(&quoted))
                        .cloned()
                        .collect(),
                    issues_tr: warnings
                        .iter()
                        .zip(&warnings_tr)
                        .filter(|(w, _)| w.contains(&quoted))
                        .map(|(_, t)| t.clone())
                        .collect(),
                }
            })
            .collect();
        ManufacturersView {
            workstation_id: v.state.policy.workstation_id.clone(),
            policy_version: v.version,
            catalog_version: v.state.catalog.catalog_version.clone(),
            mode: json_code(&serde_json::json!({ "m": v.state.policy.mode }), "m"),
            manufacturers,
            warnings,
            warnings_tr,
            reserved_generic_vendors: v.state.catalog.reserved_generic_vendors.clone(),
        }
    }

    fn dashboard(
        &self,
        g: &Inner,
        captured: Result<rustward_enforcement::policy_inspect::CapturedPolicy, String>,
    ) -> Result<DashboardView, IpcError> {
        let state = self.provider.status();
        let devices = g.store.list_devices(false).map_err(storage_err)?;
        let names = Self::brand_names(&g.store);
        let mut warnings = Vec::new();
        let mut warnings_tr = Vec::new();
        let validated = match Self::validated(&g.store) {
            Ok(v) => Some(v),
            Err(e) => {
                warnings_tr.push(format!(
                    "Politika kullanılamıyor. (Teknik ayrıntı: {})",
                    e.message
                ));
                warnings.push(format!("policy unavailable: {}", e.message));
                None
            }
        };
        let (workstation_id, policy_version, catalog_version, last_update, allowed) =
            match &validated {
                Some(v) => {
                    warnings.extend(v.policy.warnings().iter().map(|w| w.detail.clone()));
                    warnings_tr.extend(
                        v.policy
                            .warnings()
                            .iter()
                            .map(|w| l10n::issue(w.code, &w.detail, &names)),
                    );
                    (
                        v.state.policy.workstation_id.clone(),
                        v.version,
                        v.state.catalog.catalog_version.clone(),
                        Some(v.created_ms),
                        u32::try_from(v.policy.enabled_brands().count()).unwrap_or(u32::MAX),
                    )
                }
                None => ("?".into(), 0, "?".into(), None, 0),
            };
        if let Some(e) = &g.last_inventory_error {
            warnings.push(format!("inventory error: {e}"));
            warnings_tr.push(l10n::text(&format!("inventory error: {e}")));
        }
        let synthetic_data_present = devices.iter().any(|d| d.synthetic);
        if synthetic_data_present {
            warnings.push("The inventory contains SYNTHETIC test devices.".into());
            warnings_tr.push("Envanter SENTETİK test cihazları içeriyor.".into());
        }
        let mut denied: Vec<&DeviceRow> = devices
            .iter()
            .filter(|d| d.last_verdict == "deny" && is_storage_category(&d.category))
            .collect();
        denied.sort_by_key(|d| std::cmp::Reverse(d.last_seen_ms));
        let events = g
            .store
            .list_events(&EventFilter {
                limit: Some(8),
                ..EventFilter::default()
            })
            .map_err(storage_err)?;
        let verified_denied_keys = self.verified_denied_keys(g, &captured);
        let compound_plan = validated.as_ref().map(|v| {
            let snap = g.last.clone().unwrap_or_else(empty_snapshot);
            let snapshot_ref = captured.as_ref().ok().map(|c| &c.values);
            rustward_enforcement::compound_policy::compile_compound_policy(
                &v.policy,
                &v.catalog,
                &snap.devices,
                snapshot_ref,
                true,
            )
        });
        let windows_protection = self.windows_protection(g, captured)?;
        let prot = v11::compute_dashboard_protection(
            self,
            &g.store,
            compound_plan.as_ref(),
            &windows_protection,
            synthetic_data_present,
            validated.as_ref(),
        );
        let policy_ref = validated.as_ref().map(|v| &v.policy);
        Ok(DashboardView {
            enforcement_state: state.code().into(),
            enforcement_label_tr: state.label_tr().into(),
            enforcement_label_en: state.label_en().into(),
            protection_verified: prot.protection_verified,
            not_validated_banner: prot.not_validated_banner,
            service: self.service_status(g),
            workstation_id,
            policy_version,
            catalog_version,
            last_policy_update_ms: last_update,
            allowed_manufacturers: allowed,
            connected_storage: u32::try_from(
                devices
                    .iter()
                    .filter(|d| d.present && is_storage_category(&d.category))
                    .count(),
            )
            .unwrap_or(u32::MAX),
            recent_denied: denied
                .into_iter()
                .take(5)
                .map(|d| device_view_with_evidence(d, policy_ref, Some(&verified_denied_keys)))
                .collect(),
            recent_events: events.into_iter().map(|e| event_view(e, &names)).collect(),
            windows_protection,
            warnings_tr,
            warnings,
            synthetic_data_present,
            protection_category: prot.protection_category,
            protection_detail_tr: prot.protection_detail_tr,
            protection_detail_en: prot.protection_detail_en,
            pending_policy_apply: prot.pending_policy_apply,
            approved_policy_version: prot.approved_policy_version,
            startup_reconcile_status: g.startup_reconcile_status.clone(),
        })
    }

    fn diagnostics(&self, g: &Inner) -> DiagnosticsView {
        let schema_version = g.store.schema_version().unwrap_or(0);
        let integrity_ok = g.store.integrity_check().is_ok();
        let (chain_status, chain_ok) = match g.store.verify_chain() {
            Ok(ChainStatus::Intact { entries }) => (format!("intact ({entries} entries)"), true),
            Ok(ChainStatus::Broken { first_bad_id }) => {
                (format!("BROKEN at event {first_bad_id}"), false)
            }
            Ok(ChainStatus::Missing {
                after_id, next_id, ..
            }) => (
                format!(
                    "EVENTS MISSING: ids {}..={} were removed",
                    after_id + 1,
                    next_id - 1
                ),
                false,
            ),
            Ok(ChainStatus::Truncated {
                entries,
                last_id,
                highest_issued,
            }) => (
                format!(
                    "TRUNCATED: newest events removed ({entries} entries remain, last #{last_id}, ids issued up to #{highest_issued})"
                ),
                false,
            ),
            Err(e) => (format!("error: {e}"), false),
        };
        let (policy, validated) = match Self::validated(&g.store) {
            Ok(v) => (
                PolicyHealthView {
                    valid: true,
                    errors: Vec::new(),
                    errors_tr: Vec::new(),
                    warnings_tr: Self::warnings_tr(&v, &Self::brand_names(&g.store)),
                    warnings: combined_warnings(&v.catalog, &v.policy)
                        .into_iter()
                        .map(|(_, detail)| detail)
                        .collect(),
                },
                Some(v),
            ),
            Err(e) => (
                PolicyHealthView {
                    valid: false,
                    errors_tr: vec![
                        l10n::error(&e, &|x: &str| x.to_string())
                            .unwrap_or_else(|| format!("{}{}", l10n::UNTRANSLATED, e.message)),
                    ],
                    errors: vec![e.message],
                    warnings: Vec::new(),
                    warnings_tr: Vec::new(),
                },
                None,
            ),
        };
        let env = Self::env_facts();
        let state = self.provider.status();
        let enforcement = match &validated {
            Some(v) => {
                let snap = g.last.clone().unwrap_or_else(empty_snapshot);
                let inputs = PlanInputs {
                    policy: &v.policy,
                    catalog: &v.catalog,
                    snapshot: &snap,
                    env: &env,
                };
                let plan = self.provider.plan(inputs);
                let dry = self.provider.dry_run(&plan, inputs);
                EnforcementView {
                    state: state.code().into(),
                    label_tr: state.label_tr().into(),
                    label_en: state.label_en().into(),
                    provider_id: self.provider.id().into(),
                    capabilities: self.provider.capabilities(&env),
                    planned_changes: u32::try_from(plan.changes.len()).unwrap_or(u32::MAX),
                    preconditions: plan.preconditions,
                    risks_tr: plan.risks.iter().map(|r| l10n::text(r)).collect(),
                    risks: plan.risks,
                    enforcement_gaps: dry
                        .enforcement_gaps
                        .iter()
                        .map(|i| mask_instance_id(i))
                        .collect(),
                }
            }
            None => EnforcementView {
                state: "error".into(),
                label_tr: "Hata — koruma doğrulanmadı".into(),
                label_en: "Error — protection not verified".into(),
                provider_id: self.provider.id().into(),
                capabilities: self.provider.capabilities(&env),
                planned_changes: 0,
                preconditions: Vec::new(),
                risks: vec!["Policy unavailable; no plan can be computed.".into()],
                risks_tr: vec![l10n::text("Policy unavailable; no plan can be computed.")],
                enforcement_gaps: Vec::new(),
            },
        };
        DiagnosticsView {
            service: self.service_status(g),
            database: DatabaseHealthView {
                schema_version,
                integrity_ok,
                chain_status,
                chain_ok,
                location_kind: self.config.database_location.clone(),
            },
            windows_adapter: AdapterView {
                platform: std::env::consts::OS.into(),
                live_inventory_available: cfg!(windows) && g.inventory_kind == "live",
                last_error: g.last_inventory_error.clone(),
            },
            policy,
            enforcement,
            event_log: {
                let m = g.store.mirror_status();
                EventLogView {
                    attached: m.attached,
                    delivered: m.delivered,
                    failures: m.failures,
                    pending: m.pending,
                    skipped: m.skipped,
                }
            },
            unsupported_features: UNSUPPORTED
                .iter()
                .map(|(en, _)| (*en).to_string())
                .collect(),
            unsupported_features_tr: UNSUPPORTED
                .iter()
                .map(|(_, tr)| (*tr).to_string())
                .collect(),
            pending_native_tests: PENDING_NATIVE
                .iter()
                .map(|(en, _)| (*en).to_string())
                .collect(),
            pending_native_tests_tr: PENDING_NATIVE
                .iter()
                .map(|(_, tr)| (*tr).to_string())
                .collect(),
            performance: rustward_ipc::messages::PerformanceView {
                last_inventory_collect_ms: g.perf.last_collect_ms,
                last_inventory_apply_ms: g.perf.last_apply_ms,
                max_inventory_collect_ms: g.perf.max_collect_ms,
                inventory_refreshes: g.perf.refreshes,
                last_inventory_devices: g.perf.last_devices,
                first_inventory_after_start_ms: g.perf.first_refresh_done_ms,
                last_observation_ms: g.perf.last_observation_ms,
                last_verification_ms: g.perf.last_verification_ms,
            },
            app_version: self.config.app_version.clone(),
        }
    }

    fn explain_device(&self, g: &Inner, key: &str) -> Result<ExplanationView, IpcError> {
        let snap = g
            .last
            .as_ref()
            .ok_or_else(|| IpcError::new(ErrorCode::NotFound, "no inventory collected yet"))?;
        let rec = snap
            .devices
            .iter()
            .find(|d| device_key(&d.instance_id) == key.to_ascii_lowercase())
            .ok_or_else(|| {
                IpcError::new(
                    ErrorCode::NotFound,
                    "device is not in the current inventory",
                )
            })?;
        let v = Self::validated(&g.store)?;
        let index = snap.index();
        let dec = evaluate_device(classify(&index, rec), rec, &v.policy, &v.catalog);
        let synthetic = matches!(snap.source, SnapshotSource::Synthetic { .. });
        let row = row_from(
            &dec,
            rec,
            self.clock.now_ms(),
            synthetic,
            self.enforcement_state_code(),
        );
        Ok(ExplanationView {
            device: device_view(&row),
            explanation: explain(&dec),
        })
    }

    fn export(
        &self,
        g: &mut Inner,
        q: &EventQuery,
        format: ExportFormat,
        identity: &ClientIdentity,
        actor_override: Option<&str>,
    ) -> Result<ExportView, IpcError> {
        let mut f = event_filter(q)?;
        f.limit = Some(q.limit.unwrap_or(5000).min(5000));
        let events = g.store.list_events(&f).map_err(storage_err)?;
        let names = Self::brand_names(&g.store);
        let count = u32::try_from(events.len()).unwrap_or(u32::MAX);
        let day = utc_date(u64::try_from(self.clock.now_ms() / 1000).unwrap_or(0)).replace('-', "");
        let (content, mime, ext) = match format {
            ExportFormat::Json => (
                serde_json::to_string_pretty(
                    &events
                        .into_iter()
                        .map(|e| event_view(e, &names))
                        .collect::<Vec<_>>(),
                )
                .map_err(internal)?,
                "application/json",
                "json",
            ),
            ExportFormat::Csv => {
                let mut s = String::from(
                    "id,utc,severity,kind,simulated,enforcement_state,policy_version,device_key,computer_name,manufacturer_id,device_name,vid_pid,transport,pnp_problem_code,effective_decision,enforcement_outcome,actor_username,windows_user,policy_revision,message\n",
                );
                for e in events {
                    let meta = EventMetadata::from_details(&e.details);
                    let policy_rev = meta
                        .policy_revision
                        .or_else(|| e.policy_version.map(|v| format!("v{v}")))
                        .unwrap_or_default();
                    let fields = [
                        e.id.to_string(),
                        utc_iso(e.utc_ms),
                        e.severity.as_str().to_owned(),
                        e.kind,
                        e.simulated.to_string(),
                        e.enforcement_state,
                        e.policy_version.map(|v| v.to_string()).unwrap_or_default(),
                        e.device_key.unwrap_or_default(),
                        meta.computer_name.unwrap_or_default(),
                        meta.manufacturer_id.unwrap_or_default(),
                        meta.device_name.unwrap_or_default(),
                        meta.vid_pid.unwrap_or_default(),
                        meta.transport.unwrap_or_default(),
                        meta.pnp_problem_code
                            .map(|c| c.to_string())
                            .unwrap_or_default(),
                        meta.effective_decision.unwrap_or_default(),
                        meta.enforcement_outcome.unwrap_or_default(),
                        meta.actor_username.unwrap_or_default(),
                        meta.windows_user.unwrap_or_default(),
                        policy_rev,
                        e.message,
                    ];
                    s.push_str(
                        &fields
                            .iter()
                            .map(|f| csv_field(f))
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                    s.push('\n');
                }
                (s, "text/csv", "csv")
            }
        };
        let actor_str = actor_override
            .map(str::to_owned)
            .unwrap_or_else(|| identity.actor());
        let windows_user = self.resolved_windows_user();
        let computer_name = self.resolved_computer_name();
        g.store
            .append_event(&NewEvent {
                severity: Severity::Info,
                kind: "audit_exported".into(),
                device_key: None,
                message: format!("{count} events exported by {actor_str}"),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::json!({
                    "format": ext,
                    "count": count,
                    "actor_username": actor_str,
                    "windows_user": windows_user,
                    "computer_name": computer_name,
                }),
            })
            .map_err(storage_err)?;
        Ok(ExportView {
            file_name: format!("rustward-audit-{day}.{ext}"),
            mime: mime.into(),
            content,
            count,
        })
    }
}

impl Handler for AppService {
    fn localize_error(&self, mut error: IpcError) -> IpcError {
        if error.message_tr.is_none() {
            let names = self.lock().map(|g| Self::brand_names(&g.store)).ok();
            let fallback = |id: &str| id.to_string();
            error.message_tr = match &names {
                Some(n) => l10n::error(&error, n),
                None => l10n::error(&error, &fallback),
            };
        }
        error
    }

    fn authorization_failed(&self, request: &Request, identity: &ClientIdentity, error: &IpcError) {
        self.record_authorization_failure(request, identity, error);
    }

    fn identification_failed(&self, request: &Request, reason: &str) {
        let Ok(mut g) = self.lock() else {
            return;
        };
        // Bounded: the reason comes from the OS but is not trusted text.
        let reason: String = reason.chars().take(200).collect();
        let message = format!(
            "{} refused: the caller could not be identified ({reason})",
            request.name()
        );
        let details = serde_json::json!({
            "request": request.name(),
            "account": serde_json::Value::Null,
            "identification_error": reason,
        });
        self.record_refusal(&mut g, "authorization_failed", message, details);
    }

    fn validation_failed(&self, request: &Request, identity: &ClientIdentity, error: &IpcError) {
        let target = match request {
            Request::PrepareRestore { file_name } => file_name.as_str(),
            Request::ApplyRestore { restore_id, .. } => restore_id.as_str(),
            _ => return,
        };
        let stage = if matches!(request, Request::PrepareRestore { .. }) {
            "prepare"
        } else {
            "apply"
        };
        // Bounded: the target is attacker-chosen text.
        let target: String = target.chars().take(80).collect();
        if let Ok(mut g) = self.lock() {
            self.record_restore_failure(&mut g, identity, stage, "invalid_request", &target, error);
        }
    }

    fn handle(
        &self,
        request: &Request,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError> {
        self.handle_with_token(request, identity, None)
    }

    fn handle_with_token(
        &self,
        request: &Request,
        identity: &ClientIdentity,
        auth_token: Option<&str>,
    ) -> Result<ResponseBody, IpcError> {
        let session_ctx = if Self::requires_authenticated_session(request) {
            let mut g = self.lock()?;
            if g.auth.is_enforced(&g.store).map_err(storage_err)? {
                let settings = g.store.settings().map_err(storage_err)?;
                let now_ms = self.clock.now_ms();
                let Some(sess) = g.auth.touch_authenticated_session(
                    auth_token,
                    settings.session_idle_timeout_minutes,
                    now_ms,
                ) else {
                    let has_users = g.store.has_any_users().map_err(storage_err)?;
                    let msg = if has_users {
                        "valid operator session required or session locked/expired"
                    } else {
                        "initial administrator setup required before accessing RustWard"
                    };
                    return Err(IpcError::new(ErrorCode::Unauthorized, msg));
                };
                if Self::requires_admin_role(request) && sess.role != UserRole::Admin {
                    let req_name = request.name();
                    drop(g);
                    self.record_authorization_failure(
                        request,
                        identity,
                        &IpcError::new(
                            ErrorCode::Unauthorized,
                            format!("administrator role in RustWard is required for {req_name}"),
                        ),
                    );
                    return Err(IpcError::new(
                        ErrorCode::Unauthorized,
                        "administrator role in RustWard is required for this operation",
                    ));
                }
                Some(sess)
            } else {
                None
            }
        } else {
            None
        };
        let actor_override = session_ctx.as_ref().map(|s| s.username.clone());
        let identity_actor = identity.actor();
        let effective_actor = actor_override.as_deref().unwrap_or(&identity_actor);

        match request {
            Request::GetAuthStatus => Ok(ResponseBody::AuthStatus(
                self.get_auth_status_view(auth_token, identity)?,
            )),
            Request::SetupInitialAdmin {
                username,
                display_name,
                password,
            } => Ok(ResponseBody::Login(self.setup_initial_admin(
                username,
                display_name,
                password,
                identity,
            )?)),
            Request::Login { username, password } => Ok(ResponseBody::Login(
                self.login_operator(username, password, identity)?,
            )),
            Request::Logout => Ok(ResponseBody::AuthStatus(
                self.logout_operator(auth_token, identity)?,
            )),
            Request::LockSession => Ok(ResponseBody::AuthStatus(
                self.lock_operator_session(auth_token, identity)?,
            )),
            Request::HeartbeatSession => Ok(ResponseBody::AuthStatus(
                self.get_auth_status_view(auth_token, identity)?,
            )),
            Request::ChangePassword {
                current_password,
                new_password,
            } => self.change_operator_password(
                session_ctx.as_ref(),
                current_password,
                new_password,
            ),
            Request::ResetPasswordWithRecovery {
                username,
                recovery_key,
                new_password,
            } => Ok(ResponseBody::RecoveryReset(
                self.reset_password_with_recovery(username, recovery_key, new_password, identity)?,
            )),
            Request::CreateAppUser {
                username,
                display_name,
                role,
                password,
            } => Ok(ResponseBody::Login(self.create_app_user_cmd(
                username,
                display_name,
                role,
                password,
                effective_actor,
            )?)),
            Request::ListAppUsers => Ok(ResponseBody::AppUsers(self.list_app_users_cmd()?)),
            Request::DeleteAppUser { username } => {
                self.delete_app_user_cmd(username, effective_actor)
            }
            Request::VerifyExitAuthorization { username, password } => Ok(
                ResponseBody::ExitAuthorized(self.verify_exit_authorization(username, password)?),
            ),
            Request::PreviewBulkManufacturers { action } => Ok(ResponseBody::BulkPreview(
                self.preview_bulk_manufacturers(*action)?,
            )),
            Request::ApplyBulkManufacturers {
                action,
                apply_to_windows,
                retroactive,
                expected_policy_version,
            } => Ok(ResponseBody::BulkApplyResult(
                self.apply_bulk_manufacturers(
                    *action,
                    *apply_to_windows,
                    *retroactive,
                    *expected_policy_version,
                    identity,
                    actor_override.as_deref(),
                )?,
            )),
            Request::GetNotificationFeed { after_event_id } => Ok(ResponseBody::NotificationFeed(
                self.get_notification_feed(*after_event_id)?,
            )),
            Request::QueryAuditEvents { query } => {
                Ok(ResponseBody::AuditPage(self.query_audit_events(query)?))
            }
            Request::VerifyAuditChain => Ok(ResponseBody::AuditChainVerification(
                self.verify_audit_chain_view()?,
            )),
            Request::GetAboutInfo => Ok(ResponseBody::AboutInfo(self.about_info())),
            Request::GetDashboard => {
                let captured = self.capture_policy_unlocked();
                let g = self.lock()?;
                Ok(ResponseBody::Dashboard(self.dashboard(&g, captured)?))
            }
            Request::ListDevices { include_absent } => {
                let captured = self.capture_policy_unlocked();
                let g = self.lock()?;
                let v = Self::validated(&g.store).ok();
                let verified = self.verified_denied_keys(&g, &captured);
                let rows = g.store.list_devices(!include_absent).map_err(storage_err)?;
                Ok(ResponseBody::Devices(
                    rows.iter()
                        .map(|r| {
                            device_view_with_evidence(
                                r,
                                v.as_ref().map(|x| &x.policy),
                                Some(&verified),
                            )
                        })
                        .collect(),
                ))
            }
            Request::ListManufacturers => {
                let g = self.lock()?;
                Ok(ResponseBody::Manufacturers(Self::manufacturers(
                    &Self::validated(&g.store)?,
                )))
            }
            Request::ExplainDevice { device_key } => {
                let g = self.lock()?;
                Ok(ResponseBody::Explanation(
                    self.explain_device(&g, device_key)?,
                ))
            }
            Request::ListBlocked { limit } => {
                let captured = self.capture_policy_unlocked();
                let g = self.lock()?;
                let v = Self::validated(&g.store).ok();
                let verified = self.verified_denied_keys(&g, &captured);
                let rows = g.store.list_devices(false).map_err(storage_err)?;
                Ok(ResponseBody::Devices(
                    rows.iter()
                        .filter(|d| d.last_verdict == "deny" && is_storage_category(&d.category))
                        .take(usize::try_from(*limit).unwrap_or(usize::MAX))
                        .map(|r| {
                            device_view_with_evidence(
                                r,
                                v.as_ref().map(|x| &x.policy),
                                Some(&verified),
                            )
                        })
                        .collect(),
                ))
            }
            Request::ListEvents { query } => {
                let g = self.lock()?;
                let names = Self::brand_names(&g.store);
                let events = g
                    .store
                    .list_events(&event_filter(query)?)
                    .map_err(storage_err)?;
                Ok(ResponseBody::Events(
                    events.into_iter().map(|e| event_view(e, &names)).collect(),
                ))
            }
            Request::ListPolicyChanges { limit } => {
                let g = self.lock()?;
                let rows = g.store.policy_changes(*limit).map_err(storage_err)?;
                let names = Self::brand_names(&g.store);
                Ok(ResponseBody::PolicyChanges(
                    rows.into_iter()
                        .map(|r| PolicyChangeView {
                            id: r.id,
                            utc_ms: r.utc_ms,
                            actor: r.actor,
                            action: r.action.clone(),
                            brand_id: r.brand_id.clone(),
                            summary_tr: l10n::change(&r.action, &r.brand_id, &r.summary, &names),
                            summary: r.summary,
                            from_version: r.from_version,
                            to_version: r.to_version,
                        })
                        .collect(),
                ))
            }
            Request::GetDiagnostics => {
                let g = self.lock()?;
                Ok(ResponseBody::Diagnostics(Box::new(self.diagnostics(&g))))
            }
            Request::GetEnforcementObservation => {
                let t = std::time::Instant::now();
                let captured = self.capture_policy_unlocked();
                let mut g = self.lock()?;
                let v = self.enforcement_observation(&mut g, captured)?;
                g.perf.last_observation_ms = Some(elapsed_ms(t));
                Ok(ResponseBody::EnforcementObservation(Box::new(v)))
            }
            Request::GetPolicyChecklist {
                device_key,
                retroactive,
            } => {
                let captured = self.capture_policy_unlocked();
                let g = self.lock()?;
                Ok(ResponseBody::PolicyChecklist(Box::new(
                    self.policy_checklist(&g, device_key, *retroactive, captured)?,
                )))
            }
            Request::GetEnforcementSession => {
                let captured = self.capture_policy_unlocked();
                let mut g = self.lock()?;
                Ok(ResponseBody::EnforcementSession(Box::new(
                    self.session_view(&mut g, captured)?,
                )))
            }
            Request::GetCompoundPolicyPlan => {
                let plan = self.get_compound_policy_plan()?;
                Ok(ResponseBody::CompoundPolicyPlan(Box::new(plan)))
            }
            Request::PrepareEnforcementSession {
                device_key,
                retroactive,
            } => {
                let captured = self.capture_policy_unlocked();
                let mut g = self.lock()?;
                Ok(ResponseBody::EnforcementSession(Box::new(
                    self.prepare_session(&mut g, device_key, *retroactive, identity, captured)?,
                )))
            }
            Request::PrepareDefaultDenySession => {
                let captured = self.capture_policy_unlocked();
                let mut g = self.lock()?;
                Ok(ResponseBody::EnforcementSession(Box::new(
                    self.prepare_profile_session(&mut g, identity, captured)?,
                )))
            }
            Request::VerifyEnforcementApplied { session_id } => {
                // Independent device evidence: re-enumerate Windows devices
                // and capture Windows policy first (outside the state lock).
                // A failed refresh leaves the last inventory; the view reports its time.
                let t = std::time::Instant::now();
                let _ = self.refresh_inventory();
                let captured = self.capture_policy_unlocked();
                let mut g = self.lock()?;
                let r = self.verify_applied(&mut g, session_id, captured);
                g.perf.last_verification_ms = Some(elapsed_ms(t));
                Ok(ResponseBody::EnforcementSession(Box::new(r?)))
            }
            Request::VerifyEnforcementRollback { session_id } => {
                // Independent device evidence: re-enumerate Windows devices
                // and capture Windows policy first (outside the state lock).
                // A failed refresh leaves the last inventory; the view reports its time.
                let t = std::time::Instant::now();
                let _ = self.refresh_inventory();
                let captured = self.capture_policy_unlocked();
                let mut g = self.lock()?;
                let r = self.verify_rollback(&mut g, session_id, captured);
                g.perf.last_verification_ms = Some(elapsed_ms(t));
                Ok(ResponseBody::EnforcementSession(Box::new(r?)))
            }
            Request::CancelEnforcementSession { session_id } => {
                let captured = self.capture_policy_unlocked();
                let mut g = self.lock()?;
                Ok(ResponseBody::EnforcementSession(Box::new(
                    self.cancel_session(&mut g, session_id, captured)?,
                )))
            }
            Request::GetEnforcementReadiness => {
                let captured = self.capture_policy_unlocked();
                let g = self.lock()?;
                Ok(ResponseBody::EnforcementReadiness(Box::new(
                    self.enforcement_readiness(&g, identity, captured)?,
                )))
            }
            Request::GetSettings => {
                let g = self.lock()?;
                Ok(ResponseBody::Settings(settings_view(
                    &g.store.settings().map_err(storage_err)?,
                )))
            }
            Request::RunSimulation => {
                let g = self.lock()?;
                let v = Self::validated(&g.store)?;
                let snap = g.last.clone().unwrap_or_else(empty_snapshot);
                let decisions = evaluate_snapshot(&snap, &v.policy, &v.catalog);
                let env = Self::env_facts();
                let inputs = PlanInputs {
                    policy: &v.policy,
                    catalog: &v.catalog,
                    snapshot: &snap,
                    env: &env,
                };
                let plan = self.provider.plan(inputs);
                let dry = self.provider.dry_run(&plan, inputs);
                let count = |verdict| {
                    u32::try_from(decisions.iter().filter(|d| d.verdict == verdict).count())
                        .unwrap_or(u32::MAX)
                };
                Ok(ResponseBody::Simulation(SimulationView {
                    evaluated: u32::try_from(decisions.len()).unwrap_or(u32::MAX),
                    simulated_allow: count(Verdict::Allow),
                    simulated_deny: count(Verdict::Deny),
                    not_applicable: count(Verdict::NotApplicable),
                    enforcement_gaps: dry
                        .enforcement_gaps
                        .iter()
                        .map(|i| mask_instance_id(i))
                        .collect(),
                    notice: "SIMULATION ONLY — enforcement is NOT ACTIVE.".into(),
                    notice_tr: l10n::text("SIMULATION ONLY — enforcement is NOT ACTIVE."),
                }))
            }
            Request::AddManufacturer {
                input,
                allowed,
                expected_policy_version,
            } => self.mutate_with_actor(
                &PolicyEdit::AddManufacturer {
                    input: input.clone(),
                    allowed: *allowed,
                },
                *expected_policy_version,
                identity,
                actor_override.as_deref(),
            ),
            Request::UpdateManufacturer {
                id,
                input,
                expected_policy_version,
            } => self.mutate_with_actor(
                &PolicyEdit::UpdateManufacturer {
                    id: id.clone(),
                    input: input.clone(),
                },
                *expected_policy_version,
                identity,
                actor_override.as_deref(),
            ),
            Request::RemoveManufacturer {
                id,
                expected_policy_version,
            } => self.mutate_with_actor(
                &PolicyEdit::RemoveManufacturer { id: id.clone() },
                *expected_policy_version,
                identity,
                actor_override.as_deref(),
            ),
            Request::SetManufacturerAllowed {
                id,
                allowed,
                expected_policy_version,
            } => self.mutate_with_actor(
                &PolicyEdit::SetAllowed {
                    id: id.clone(),
                    allowed: *allowed,
                },
                *expected_policy_version,
                identity,
                actor_override.as_deref(),
            ),
            Request::SetManufacturerDenied {
                id,
                denied,
                expected_policy_version,
            } => self.mutate_with_actor(
                &PolicyEdit::SetDenied {
                    id: id.clone(),
                    denied: *denied,
                },
                *expected_policy_version,
                identity,
                actor_override.as_deref(),
            ),
            Request::SetRuleEnabled {
                id,
                enabled,
                expected_policy_version,
            } => self.mutate_with_actor(
                &PolicyEdit::SetRuleEnabled {
                    id: id.clone(),
                    enabled: *enabled,
                },
                *expected_policy_version,
                identity,
                actor_override.as_deref(),
            ),
            Request::UpdateSettings { settings } => {
                let s = settings_from(settings)?;
                let mut g = self.lock()?;
                g.store
                    .save_settings(&s, effective_actor)
                    .map_err(storage_err)?;
                Ok(ResponseBody::Settings(settings_view(&s)))
            }
            Request::ExportEvents { query, format } => {
                let mut g = self.lock()?;
                Ok(ResponseBody::Export(self.export(
                    &mut g,
                    query,
                    *format,
                    identity,
                    actor_override.as_deref(),
                )?))
            }
            Request::ApplyRetention => {
                let mut g = self.lock()?;
                let n = g.store.apply_retention().map_err(storage_err)?;
                Ok(done(ResponseBody::Done {
                    message_tr: String::new(),
                    message: format!("{n} events removed by retention"),
                }))
            }
            Request::CreateBackup => {
                let dir = self.backup_dir()?;
                let mut g = self.lock()?;
                let rec = g
                    .store
                    .create_backup(&dir, BackupKind::Manual, effective_actor)
                    .map_err(storage_err)?;
                Ok(done(ResponseBody::Done {
                    message_tr: String::new(),
                    message: format!("backup created: {}", rec.file_name),
                }))
            }
            Request::ListBackups => Ok(ResponseBody::Backups(self.list_backups()?)),
            Request::PrepareRestore { file_name } => self.prepare_restore(file_name, identity),
            Request::ApplyRestore {
                restore_id,
                expected_policy_version,
            } => self.apply_restore(restore_id, *expected_policy_version, identity),
            Request::ApplyDeviceBlock {
                session_id,
                device_key,
                retroactive,
            } => {
                let r = self.apply_device_block_direct(
                    session_id.as_deref(),
                    device_key.as_deref(),
                    *retroactive,
                    identity,
                )?;
                Ok(ResponseBody::EnforcementSession(Box::new(r)))
            }
            Request::RestoreDevicePolicy {
                session_id,
                device_key,
            } => {
                let r = self.restore_device_policy_direct(
                    session_id.as_deref(),
                    device_key.as_deref(),
                    identity,
                )?;
                Ok(ResponseBody::EnforcementSession(Box::new(r)))
            }
            Request::ApplyCompoundPolicy {
                retroactive,
                expected_policy_version,
            } => {
                let plan = self.apply_compound_policy_direct(
                    *retroactive,
                    *expected_policy_version,
                    identity,
                    actor_override.as_deref(),
                )?;
                Ok(ResponseBody::CompoundPolicyPlan(Box::new(plan)))
            }
            Request::RollbackCompoundPolicy => {
                let plan =
                    self.rollback_compound_policy_direct(identity, actor_override.as_deref())?;
                Ok(ResponseBody::CompoundPolicyPlan(Box::new(plan)))
            }
            Request::RecoverDevice { device_key } => {
                self.recover_device(device_key, identity)
            }
            Request::SetWorkstationId {
                workstation_id,
                expected_policy_version,
            } => self.mutate_with_actor(
                &PolicyEdit::SetWorkstationId {
                    workstation_id: workstation_id.clone(),
                },
                *expected_policy_version,
                identity,
                actor_override.as_deref(),
            ),
            Request::RefreshInventory => {
                let s = self.refresh_inventory()?;
                Ok(done(ResponseBody::Done {
                    message_tr: String::new(),
                    message: format!(
                        "inventory refreshed: {} stored devices, {} arrived, {} removed",
                        s.stored, s.arrived, s.removed
                    ),
                }))
            }
            Request::LoadSyntheticInventory => {
                let s = self.load_synthetic()?;
                Ok(done(ResponseBody::Done {
                    message_tr: String::new(),
                    message: format!("SYNTHETIC inventory loaded: {} stored devices", s.stored),
                }))
            }
        }
    }
}

fn backup_view(dir: &std::path::Path, r: BackupRecord) -> BackupView {
    let file_present =
        std::fs::symlink_metadata(dir.join(&r.file_name)).is_ok_and(|m| m.file_type().is_file());
    BackupView {
        file_name: r.file_name,
        bytes: r.bytes,
        created_ms: r.created_ms,
        kind: r.kind.as_str().into(),
        policy_version: r.policy_version,
        sha256: r.sha256,
        actor: r.actor,
        file_present,
    }
}

/// Human-readable differences between the live state and a backup.
fn restore_changes(
    current: &PolicyState,
    current_settings: &AppSettings,
    candidate: &RestoreCandidate,
) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut out = Vec::new();
    let next = &candidate.state;
    if current.policy.workstation_id != next.policy.workstation_id {
        out.push(format!(
            "workstation id: {} -> {}",
            current.policy.workstation_id, next.policy.workstation_id
        ));
    }
    if current.policy.mode != next.policy.mode {
        out.push(format!(
            "policy mode: {:?} -> {:?}",
            current.policy.mode, next.policy.mode
        ));
    }
    let brands = |s: &PolicyState| -> BTreeSet<String> {
        s.catalog.brands.iter().map(|b| b.id.clone()).collect()
    };
    let (a, b) = (brands(current), brands(next));
    for id in b.difference(&a) {
        out.push(format!("manufacturer added to catalog: {id}"));
    }
    for id in a.difference(&b) {
        out.push(format!("manufacturer removed from catalog: {id}"));
    }
    for id in a.intersection(&b) {
        let x = current.catalog.brands.iter().find(|m| &m.id == id);
        let y = next.catalog.brands.iter().find(|m| &m.id == id);
        if x != y {
            out.push(format!("manufacturer definition changed: {id}"));
        }
    }
    let allowed = |s: &PolicyState| -> BTreeSet<String> {
        s.policy
            .allowed_brands
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.brand_id.clone())
            .collect()
    };
    let (a, b) = (allowed(current), allowed(next));
    for id in b.difference(&a) {
        out.push(format!("would be ALLOWED: {id}"));
    }
    for id in a.difference(&b) {
        out.push(format!("would no longer be allowed: {id}"));
    }
    if current_settings != &candidate.settings {
        out.push("application settings differ (theme, language, notifications, retention or refresh interval)".into());
    }
    out
}

/// The shipped default policy state (catalog + PC-01 example policy).
pub fn default_policy_state() -> Result<PolicyState, String> {
    Ok(PolicyState {
        catalog: serde_json::from_str(include_str!("../../../config/manufacturer-catalog.json"))
            .map_err(|e| e.to_string())?,
        policy: serde_json::from_str(include_str!("../../../config/policy.example.json"))
            .map_err(|e| e.to_string())?,
    })
}

/// Fill the Turkish rendering of an acknowledgement.
fn done(r: ResponseBody) -> ResponseBody {
    match r {
        ResponseBody::Done { message, .. } => ResponseBody::Done {
            message_tr: l10n::text(&message),
            message,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_are_quoted_and_formula_safe() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0");
        assert_eq!(csv_field("-1"), "'-1");
    }

    #[test]
    fn iso_time() {
        assert_eq!(
            utc_iso(1_793_836_800_000 + 3_723_000),
            "2026-11-05T01:02:03Z"
        );
    }
}
