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

pub mod inventory;

use std::collections::HashMap;
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
use rustward_core::policy_edit::{EditError, PolicyEdit, PolicyState, apply_edit};
use rustward_core::report::utc_date;
use rustward_enforcement::{
    DeviceInstallRestrictionProvider, EnforcementProvider, EnvironmentFacts,
    NOT_VALIDATED_BANNER_TR, PlanInputs,
};
use rustward_ipc::messages::{
    AdapterView, DashboardView, DatabaseHealthView, DeviceView, DiagnosticsView, EnforcementView,
    EventQuery, EventView, ExplanationView, ExportFormat, ExportView, IdentifierView,
    ManufacturerView, ManufacturersView, MutationView, PolicyChangeView, PolicyHealthView,
    ServiceStatusView, SettingsView, SimulationView,
};
use rustward_ipc::rpc::Handler;
use rustward_ipc::{ClientIdentity, ErrorCode, IpcError, Request, ResponseBody};
use rustward_storage::{
    AppSettings, ChainStatus, Clock, DeviceRow, EventFilter, Language, NewEvent, SecurityEvent,
    Severity, StorageError, Store, Theme, device_key, mask_instance_id,
};

pub use inventory::{EmptyInventory, FixtureInventory, InventorySource, LiveInventory};

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
    inventory: Box<dyn InventorySource>,
    last: Option<DeviceSnapshot>,
    last_refresh_ms: Option<i64>,
    last_inventory_error: Option<String>,
    consecutive_failures: u32,
}

/// The application service.
pub struct AppService {
    inner: Mutex<Inner>,
    clock: Arc<dyn Clock>,
    config: AppConfig,
    provider: DeviceInstallRestrictionProvider,
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
            format!("{e}; policy changes are refused until the database is restored"),
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

fn row_from(
    dec: &Decision,
    rec: &DeviceRecord,
    now: i64,
    synthetic: bool,
    state: &str,
) -> DeviceRow {
    let category = json_code(&dec.classification.category, "kind");
    let transport = match &dec.classification.category {
        DeviceCategory::UsbStorageDisk { transport } => {
            Some(json_code(&serde_json::json!({ "t": transport }), "t"))
        }
        _ => None,
    };
    let matched_brand = match &dec.reason {
        rustward_core::evaluate::DecisionReason::BrandAllowed { brand_id }
        | rustward_core::evaluate::DecisionReason::BrandNotAllowed { brand_id } => {
            Some(brand_id.clone())
        }
        _ => None,
    };
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
        // No runtime enforcement evidence exists in this build.
        enforcement_verified: false,
    }
}

fn event_view(e: SecurityEvent) -> EventView {
    EventView {
        id: e.id,
        utc_ms: e.utc_ms,
        severity: e.severity.as_str().into(),
        kind: e.kind,
        device_key: e.device_key,
        message: e.message,
        simulated: e.simulated,
        enforcement_state: e.enforcement_state,
        policy_version: e.policy_version,
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
    }
}

fn settings_from(v: &SettingsView) -> Result<AppSettings, IpcError> {
    Ok(AppSettings {
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
    })
}

fn event_filter(q: &EventQuery) -> EventFilter {
    EventFilter {
        text: q.text.clone(),
        min_severity: q.min_severity.as_deref().and_then(Severity::parse),
        kind: q.kind.clone(),
        device_key: None,
        since_ms: q.since_ms,
        until_ms: q.until_ms,
        simulated: q.simulated,
        limit: q.limit,
        offset: q.offset,
    }
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
                inventory,
                last: None,
                last_refresh_ms: None,
                last_inventory_error: None,
                consecutive_failures: 0,
            }),
            clock,
            config,
            provider: DeviceInstallRestrictionProvider,
            started_ms,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, IpcError> {
        self.inner
            .lock()
            .map_err(|_| IpcError::new(ErrorCode::Internal, "backend state lock poisoned"))
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

    /// Apply audit retention (scheduled by the service).
    pub fn apply_retention(&self) -> Result<usize, IpcError> {
        let mut g = self.lock()?;
        g.store.apply_retention().map_err(storage_err)
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

    /// Collect the inventory, record detections and simulated decisions.
    pub fn refresh_inventory(&self) -> Result<RefreshSummary, IpcError> {
        let mut g = self.lock()?;
        self.refresh_locked(&mut g)
    }

    fn refresh_locked(&self, g: &mut Inner) -> Result<RefreshSummary, IpcError> {
        let now = self.clock.now_ms();
        let state_code = self.enforcement_state_code();
        let (snap, warnings) = match g.inventory.collect() {
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
            event(
                &mut g.store,
                Severity::Info,
                "device_detected",
                Some(key.clone()),
                format!("{label} detected ({category}){}", if synthetic { " [SYNTHETIC]" } else { "" }),
                synthetic,
                serde_json::json!({ "category": category, "display_id": mask_instance_id(&rec.instance_id) }),
            )
            .map_err(storage_err)?;
            if dec.classification.category.scope() != StorageScope::NotInScope {
                let deny = dec.verdict == Verdict::Deny;
                if deny {
                    summary.simulated_denials += 1;
                }
                let e = explain(dec);
                event(
                    &mut g.store,
                    if deny { Severity::Warning } else { Severity::Info },
                    "decision_simulated",
                    Some(key),
                    format!("{label}: {} — enforcement NOT ACTIVE", e.summary_en),
                    true,
                    serde_json::json!({ "verdict": verdict_code(dec.verdict), "reason": json_code(&dec.reason, "code"), "summary_tr": e.summary_tr }),
                )
                .map_err(storage_err)?;
            }
        }
        for rec in &diff.removed {
            let Some(old_dec) = evaluate_snapshot(
                &DeviceSnapshot {
                    devices: vec![rec.clone()],
                    ..old.clone()
                },
                &v.policy,
                &v.catalog,
            )
            .into_iter()
            .next() else {
                continue;
            };
            // Removal events only for devices we track (category from the old tree).
            let old_index = old.index();
            let cat = classify(&old_index, rec).category;
            if !stored_category(&cat) {
                continue;
            }
            summary.removed += 1;
            event(
                &mut g.store,
                Severity::Info,
                "device_removed",
                Some(device_key(&rec.instance_id)),
                format!("{} removed", device_label(rec, &old_dec)),
                synthetic,
                serde_json::json!({}),
            )
            .map_err(storage_err)?;
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
        for (rec, dec) in snap.devices.iter().zip(decisions.iter()) {
            if !stored_category(&dec.classification.category) {
                continue;
            }
            let row = row_from(dec, rec, now, synthetic, state_code);
            if row.present {
                present_keys.push(row.device_key.clone());
            }
            g.store.upsert_device(&row).map_err(storage_err)?;
            summary.stored += 1;
        }
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
        let mut g = self.lock()?;
        g.inventory = Box::new(fixture);
        self.refresh_locked(&mut g)
    }

    fn service_status(&self, g: &Inner) -> ServiceStatusView {
        let healthy = g.consecutive_failures == 0;
        ServiceStatusView {
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
        }
    }

    fn mutate(
        &self,
        edit: &PolicyEdit,
        expected: u64,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError> {
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
            .commit_policy_edit(&outcome, &identity.actor())
            .map_err(storage_err)?;
        self.reevaluate_locked(&mut g)?;
        Ok(ResponseBody::Mutation(MutationView {
            policy_version: outcome.state.policy.policy_version,
            catalog_version: outcome.state.catalog.catalog_version.clone(),
            summary: outcome.change.summary,
            warnings: outcome.warnings,
        }))
    }

    fn manufacturers(v: &Validated) -> ManufacturersView {
        let warnings: Vec<String> = v
            .catalog
            .warnings()
            .iter()
            .map(|w| w.detail.clone())
            .chain(v.policy.warnings().iter().map(|w| w.detail.clone()))
            .collect();
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
                    enforceable: b.enforceable_identifiers().next().is_some(),
                    issues: warnings
                        .iter()
                        .filter(|w| w.contains(&quoted))
                        .cloned()
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
            reserved_generic_vendors: v.state.catalog.reserved_generic_vendors.clone(),
        }
    }

    fn dashboard(&self, g: &Inner) -> Result<DashboardView, IpcError> {
        let state = self.provider.status();
        let devices = g.store.list_devices(false).map_err(storage_err)?;
        let mut warnings = Vec::new();
        let (workstation_id, policy_version, catalog_version, last_update, allowed) =
            match Self::validated(&g.store) {
                Ok(v) => {
                    warnings.extend(v.policy.warnings().iter().map(|w| w.detail.clone()));
                    (
                        v.state.policy.workstation_id.clone(),
                        v.version,
                        v.state.catalog.catalog_version.clone(),
                        Some(v.created_ms),
                        u32::try_from(v.policy.enabled_brands().count()).unwrap_or(u32::MAX),
                    )
                }
                Err(e) => {
                    warnings.push(format!("policy unavailable: {}", e.message));
                    ("?".into(), 0, "?".into(), None, 0)
                }
            };
        if let Some(e) = &g.last_inventory_error {
            warnings.push(format!("inventory error: {e}"));
        }
        let synthetic_data_present = devices.iter().any(|d| d.synthetic);
        if synthetic_data_present {
            warnings.push("The inventory contains SYNTHETIC test devices.".into());
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
        Ok(DashboardView {
            enforcement_state: state.code().into(),
            enforcement_label_tr: state.label_tr().into(),
            enforcement_label_en: state.label_en().into(),
            protection_verified: state.is_verified_protection(),
            not_validated_banner: (!state.is_verified_protection())
                .then(|| NOT_VALIDATED_BANNER_TR.into()),
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
            recent_denied: denied.into_iter().take(5).map(device_view).collect(),
            recent_events: events.into_iter().map(event_view).collect(),
            warnings,
            synthetic_data_present,
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
            Err(e) => (format!("error: {e}"), false),
        };
        let (policy, validated) = match Self::validated(&g.store) {
            Ok(v) => (
                PolicyHealthView {
                    valid: true,
                    errors: Vec::new(),
                    warnings: v
                        .catalog
                        .warnings()
                        .iter()
                        .map(|w| w.detail.clone())
                        .chain(v.policy.warnings().iter().map(|w| w.detail.clone()))
                        .collect(),
                },
                Some(v),
            ),
            Err(e) => (
                PolicyHealthView {
                    valid: false,
                    errors: vec![e.message],
                    warnings: Vec::new(),
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
                live_inventory_available: cfg!(windows) && g.inventory.kind() == "live",
                last_error: g.last_inventory_error.clone(),
            },
            policy,
            enforcement,
            unsupported_features: vec![
                "OS-level USB blocking: activation disabled (dry-run only)".into(),
                "Verified enforcement: no runtime evidence exists".into(),
                "Real-time PnP notifications (CM_Register_Notification): periodic refresh is used"
                    .into(),
                "Windows named-pipe IPC: implemented, not verified on Windows".into(),
                "MTP/PTP and optical drives: scope decision pending".into(),
            ],
            pending_native_tests: vec![
                "W-01..W-05: native build, tests and live SetupAPI inventory".into(),
                "T-01..T-30: physical USB hardware acceptance".into(),
                "Named-pipe DACL, token identity and session-0 check".into(),
                "Windows service start/stop/recovery under the SCM".into(),
                "Offline MSI installation with the WebView2 offline runtime".into(),
            ],
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
    ) -> Result<ExportView, IpcError> {
        let mut f = event_filter(q);
        f.limit = Some(q.limit.unwrap_or(5000).min(5000));
        let events = g.store.list_events(&f).map_err(storage_err)?;
        let count = u32::try_from(events.len()).unwrap_or(u32::MAX);
        let day = utc_date(u64::try_from(self.clock.now_ms() / 1000).unwrap_or(0)).replace('-', "");
        let (content, mime, ext) = match format {
            ExportFormat::Json => (
                serde_json::to_string_pretty(
                    &events.into_iter().map(event_view).collect::<Vec<_>>(),
                )
                .map_err(internal)?,
                "application/json",
                "json",
            ),
            ExportFormat::Csv => {
                let mut s = String::from(
                    "id,utc,severity,kind,simulated,enforcement_state,policy_version,device_key,message\n",
                );
                for e in events {
                    let fields = [
                        e.id.to_string(),
                        utc_iso(e.utc_ms),
                        e.severity.as_str().to_owned(),
                        e.kind,
                        e.simulated.to_string(),
                        e.enforcement_state,
                        e.policy_version.map(|v| v.to_string()).unwrap_or_default(),
                        e.device_key.unwrap_or_default(),
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
        g.store
            .append_event(&NewEvent {
                severity: Severity::Info,
                kind: "audit_exported".into(),
                device_key: None,
                message: format!("{count} events exported by {}", identity.actor()),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::json!({ "format": ext, "count": count }),
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
    fn handle(
        &self,
        request: &Request,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError> {
        match request {
            Request::GetDashboard => {
                let g = self.lock()?;
                Ok(ResponseBody::Dashboard(self.dashboard(&g)?))
            }
            Request::ListDevices { include_absent } => {
                let g = self.lock()?;
                let rows = g.store.list_devices(!include_absent).map_err(storage_err)?;
                Ok(ResponseBody::Devices(
                    rows.iter().map(device_view).collect(),
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
                let g = self.lock()?;
                let rows = g.store.list_devices(false).map_err(storage_err)?;
                Ok(ResponseBody::Devices(
                    rows.iter()
                        .filter(|d| d.last_verdict == "deny" && is_storage_category(&d.category))
                        .take(usize::try_from(*limit).unwrap_or(usize::MAX))
                        .map(device_view)
                        .collect(),
                ))
            }
            Request::ListEvents { query } => {
                let g = self.lock()?;
                let events = g
                    .store
                    .list_events(&event_filter(query))
                    .map_err(storage_err)?;
                Ok(ResponseBody::Events(
                    events.into_iter().map(event_view).collect(),
                ))
            }
            Request::ListPolicyChanges { limit } => {
                let g = self.lock()?;
                let rows = g.store.policy_changes(*limit).map_err(storage_err)?;
                Ok(ResponseBody::PolicyChanges(
                    rows.into_iter()
                        .map(|r| PolicyChangeView {
                            id: r.id,
                            utc_ms: r.utc_ms,
                            actor: r.actor,
                            action: r.action,
                            brand_id: r.brand_id,
                            summary: r.summary,
                            from_version: r.from_version,
                            to_version: r.to_version,
                        })
                        .collect(),
                ))
            }
            Request::GetDiagnostics => {
                let g = self.lock()?;
                Ok(ResponseBody::Diagnostics(self.diagnostics(&g)))
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
                }))
            }
            Request::AddManufacturer {
                input,
                allowed,
                expected_policy_version,
            } => self.mutate(
                &PolicyEdit::AddManufacturer {
                    input: input.clone(),
                    allowed: *allowed,
                },
                *expected_policy_version,
                identity,
            ),
            Request::UpdateManufacturer {
                id,
                input,
                expected_policy_version,
            } => self.mutate(
                &PolicyEdit::UpdateManufacturer {
                    id: id.clone(),
                    input: input.clone(),
                },
                *expected_policy_version,
                identity,
            ),
            Request::RemoveManufacturer {
                id,
                expected_policy_version,
            } => self.mutate(
                &PolicyEdit::RemoveManufacturer { id: id.clone() },
                *expected_policy_version,
                identity,
            ),
            Request::SetManufacturerAllowed {
                id,
                allowed,
                expected_policy_version,
            } => self.mutate(
                &PolicyEdit::SetAllowed {
                    id: id.clone(),
                    allowed: *allowed,
                },
                *expected_policy_version,
                identity,
            ),
            Request::SetRuleEnabled {
                id,
                enabled,
                expected_policy_version,
            } => self.mutate(
                &PolicyEdit::SetRuleEnabled {
                    id: id.clone(),
                    enabled: *enabled,
                },
                *expected_policy_version,
                identity,
            ),
            Request::UpdateSettings { settings } => {
                let s = settings_from(settings)?;
                let mut g = self.lock()?;
                g.store
                    .save_settings(&s, &identity.actor())
                    .map_err(storage_err)?;
                Ok(ResponseBody::Settings(settings_view(&s)))
            }
            Request::ExportEvents { query, format } => {
                let mut g = self.lock()?;
                Ok(ResponseBody::Export(
                    self.export(&mut g, query, *format, identity)?,
                ))
            }
            Request::ApplyRetention => {
                let mut g = self.lock()?;
                let n = g.store.apply_retention().map_err(storage_err)?;
                Ok(ResponseBody::Done {
                    message: format!("{n} events removed by retention"),
                })
            }
            Request::CreateBackup => {
                let dir = self.config.backup_dir.clone().ok_or_else(|| {
                    IpcError::new(
                        ErrorCode::NotSupported,
                        "backups are not configured on this backend",
                    )
                })?;
                std::fs::create_dir_all(&dir).map_err(internal)?;
                let name = format!("rustward-backup-{}.db", self.clock.now_ms());
                let g = self.lock()?;
                g.store.backup_to(&dir.join(&name)).map_err(storage_err)?;
                Ok(ResponseBody::Done {
                    message: format!("backup created: {name}"),
                })
            }
            Request::RefreshInventory => {
                let s = self.refresh_inventory()?;
                Ok(ResponseBody::Done {
                    message: format!(
                        "inventory refreshed: {} stored devices, {} arrived, {} removed",
                        s.stored, s.arrived, s.removed
                    ),
                })
            }
            Request::LoadSyntheticInventory => {
                let s = self.load_synthetic()?;
                Ok(ResponseBody::Done {
                    message: format!("SYNTHETIC inventory loaded: {} stored devices", s.stored),
                })
            }
        }
    }
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
