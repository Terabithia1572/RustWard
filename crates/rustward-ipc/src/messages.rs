//! Typed request/response contract. The TypeScript mirror lives in
//! `apps/rustward-desktop/src/api/types.ts`; keep both in sync.

use rustward_core::explain::Explanation;
use rustward_core::policy_edit::ManufacturerInput;
use rustward_enforcement::installed_assessment::InstalledAssessment;
use rustward_enforcement::policy_inspect::PolicyInspection;
use rustward_enforcement::policy_state::PolicyConflict;
use rustward_enforcement::{
    CapabilityReport, PlannedChange, Precondition, PreconditionStatus, RecoveryStep,
};
use serde::{Deserialize, Serialize};

/// Event query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventQuery {
    /// Substring search.
    #[serde(default)]
    pub text: Option<String>,
    /// `info` | `warning` | `critical`.
    #[serde(default)]
    pub min_severity: Option<String>,
    /// Exact kind.
    #[serde(default)]
    pub kind: Option<String>,
    /// From (UTC ms, inclusive).
    #[serde(default)]
    pub since_ms: Option<i64>,
    /// Until (UTC ms, exclusive).
    #[serde(default)]
    pub until_ms: Option<i64>,
    /// Only simulated (`true`) / only real (`false`).
    #[serde(default)]
    pub simulated: Option<bool>,
    /// Page size.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Offset.
    #[serde(default)]
    pub offset: Option<u32>,
}

/// Export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// CSV (UTF-8 with header).
    Csv,
    /// JSON array.
    Json,
}

/// Settings exchanged with the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsView {
    /// `system` | `light` | `dark`.
    pub theme: String,
    /// `tr` | `en`.
    pub language: String,
    /// Notifications.
    pub notifications_enabled: bool,
    /// Retention days.
    pub audit_retention_days: u32,
    /// Service refresh interval.
    pub inventory_refresh_seconds: u32,
}

/// A request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    // ---- read-only -------------------------------------------------------
    /// Dashboard summary.
    GetDashboard,
    /// Device inventory.
    ListDevices {
        /// Include previously detected (absent) devices.
        include_absent: bool,
    },
    /// Catalog + allowlist.
    ListManufacturers,
    /// Why a device got its simulated decision.
    ExplainDevice {
        /// Device key.
        device_key: String,
    },
    /// Simulated denials.
    ListBlocked {
        /// Max rows.
        limit: u32,
    },
    /// Security events.
    ListEvents {
        /// Query.
        query: EventQuery,
    },
    /// Policy change history.
    ListPolicyChanges {
        /// Max rows.
        limit: u32,
    },
    /// Diagnostics.
    GetDiagnostics,
    /// Read-only enforcement readiness: policy inspection, planned changes,
    /// conflicts, prerequisites, recovery, installed-device assessment and
    /// the actual (inactive) enforcement status.
    GetEnforcementReadiness,
    /// Read-only Windows enforcement observer: live Device Installation
    /// Restriction policy correlated with the inventory's problem codes and
    /// RustWard's simulated decisions. Records a deduplicated audit event
    /// when an installation denial is newly observed (append-only, no
    /// Windows writes).
    GetEnforcementObservation,
    /// Generate a reviewable Group Policy checklist that would prevent the
    /// installation of one USB storage device. Nothing is applied.
    GetPolicyChecklist {
        /// Device key (32 hex).
        device_key: String,
        /// Include the "also apply to installed devices" option.
        retroactive: bool,
    },
    /// Administrator-guided Windows enforcement session state (read-only).
    GetEnforcementSession,
    /// Settings.
    GetSettings,
    /// Re-evaluate the current inventory under the current policy (no writes).
    RunSimulation,
    // ---- privileged (administrator) -------------------------------------
    /// Prepare a guided enforcement session for one USB storage device:
    /// impact check, baseline saved, expected policy recorded. Changes no
    /// Windows setting.
    PrepareEnforcementSession {
        /// Device key (32 hex).
        device_key: String,
        /// Include the "also apply to installed devices" option.
        retroactive: bool,
    },
    /// Prepare a guided session for the **default-deny profile**: the
    /// layered Device Installation Restrictions plan compiled from the
    /// RustWard policy (prevent DiskDrive class, never retroactive; allow
    /// the allowed brands' device IDs and the internal disks). Baseline and
    /// expected policy are saved; changes no Windows setting.
    PrepareDefaultDenySession,
    /// Verify the administrator's Group Policy change against the plan.
    VerifyEnforcementApplied {
        /// Session id (16 hex).
        session_id: String,
    },
    /// Verify that the previous Windows policy is back; closes the session.
    VerifyEnforcementRollback {
        /// Session id (16 hex).
        session_id: String,
    },
    /// Cancel a session whose change was never applied.
    CancelEnforcementSession {
        /// Session id (16 hex).
        session_id: String,
    },
    /// Add a manufacturer.
    AddManufacturer {
        /// Input.
        input: ManufacturerInput,
        /// Add to allowlist.
        allowed: bool,
        /// Optimistic concurrency.
        expected_policy_version: u64,
    },
    /// Update a manufacturer.
    UpdateManufacturer {
        /// Id.
        id: String,
        /// Input.
        input: ManufacturerInput,
        /// Optimistic concurrency.
        expected_policy_version: u64,
    },
    /// Remove a manufacturer.
    RemoveManufacturer {
        /// Id.
        id: String,
        /// Optimistic concurrency.
        expected_policy_version: u64,
    },
    /// Allowlist membership.
    SetManufacturerAllowed {
        /// Id.
        id: String,
        /// Allowed.
        allowed: bool,
        /// Optimistic concurrency.
        expected_policy_version: u64,
    },
    /// Explicit denylist membership (Phase 6). Denying removes the brand
    /// from the allowlist; allowing removes it from the denylist.
    SetManufacturerDenied {
        /// Id.
        id: String,
        /// Denied.
        denied: bool,
        /// Optimistic concurrency.
        expected_policy_version: u64,
    },
    /// Enable/disable a rule.
    SetRuleEnabled {
        /// Id.
        id: String,
        /// Enabled.
        enabled: bool,
        /// Optimistic concurrency.
        expected_policy_version: u64,
    },
    /// Save settings.
    UpdateSettings {
        /// Settings.
        settings: SettingsView,
    },
    /// Export events (authorized export).
    ExportEvents {
        /// Query.
        query: EventQuery,
        /// Format.
        format: ExportFormat,
    },
    /// Apply audit retention now.
    ApplyRetention,
    /// Create a database backup in the service's backup directory.
    CreateBackup,
    /// Refresh the live inventory now.
    RefreshInventory,
    /// Load the bundled SYNTHETIC device fixture (development backends only).
    LoadSyntheticInventory,
    /// Rename this workstation in its policy (versioned, audited).
    SetWorkstationId {
        /// New id, `[A-Za-z0-9_-]{1,64}`.
        workstation_id: String,
        /// Optimistic concurrency.
        expected_policy_version: u64,
    },
    /// List registered backups.
    ListBackups,
    /// Step 1 of a restore: verify a registered backup (name, registry,
    /// SHA-256, integrity, schema, policy) and return a preview. Changes
    /// nothing except the audit log.
    PrepareRestore {
        /// `rustward-backup-<digits>.db` or `rustward-pre-restore-<digits>.db`.
        file_name: String,
    },
    /// Step 2: apply the prepared backup as a NEW policy version. The
    /// current state is saved as a pre-restore backup first. Single use,
    /// bound to the administrator who prepared it, expires.
    ApplyRestore {
        /// Id returned by `PrepareRestore` (32 hex characters).
        restore_id: String,
        /// Optimistic concurrency: the active version shown in the preview.
        expected_policy_version: u64,
    },
}

/// Access level required by a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    /// Any authenticated local user.
    ReadOnly,
    /// Elevated member of BUILTIN\Administrators.
    Administrator,
}

impl Request {
    /// Required access level. Exhaustive match: a new request must be
    /// classified explicitly.
    #[must_use]
    pub fn access_level(&self) -> AccessLevel {
        match self {
            Self::GetDashboard
            | Self::ListDevices { .. }
            | Self::ListManufacturers
            | Self::ExplainDevice { .. }
            | Self::ListBlocked { .. }
            | Self::ListEvents { .. }
            | Self::ListPolicyChanges { .. }
            | Self::GetDiagnostics
            | Self::GetEnforcementReadiness
            | Self::GetEnforcementObservation
            | Self::GetPolicyChecklist { .. }
            | Self::GetEnforcementSession
            | Self::GetSettings
            | Self::RunSimulation => AccessLevel::ReadOnly,
            Self::PrepareEnforcementSession { .. }
            | Self::PrepareDefaultDenySession
            | Self::VerifyEnforcementApplied { .. }
            | Self::VerifyEnforcementRollback { .. }
            | Self::CancelEnforcementSession { .. }
            | Self::AddManufacturer { .. }
            | Self::UpdateManufacturer { .. }
            | Self::RemoveManufacturer { .. }
            | Self::SetManufacturerAllowed { .. }
            | Self::SetManufacturerDenied { .. }
            | Self::SetRuleEnabled { .. }
            | Self::UpdateSettings { .. }
            | Self::ExportEvents { .. }
            | Self::ApplyRetention
            | Self::CreateBackup
            | Self::RefreshInventory
            | Self::LoadSyntheticInventory
            | Self::SetWorkstationId { .. }
            | Self::ListBackups
            | Self::PrepareRestore { .. }
            | Self::ApplyRestore { .. } => AccessLevel::Administrator,
        }
    }

    /// Stable name for logs.
    #[must_use]
    pub fn name(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned))
            .unwrap_or_else(|| "unknown".into())
    }
}

/// Service status as seen by the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatusView {
    /// `dev_backend` (in-process, development) or `windows_service`.
    pub backend: String,
    /// `running` | `degraded` | `unreachable`.
    pub state: String,
    /// Healthy.
    pub healthy: bool,
    /// Started at.
    pub started_ms: Option<i64>,
    /// Last inventory refresh.
    pub last_refresh_ms: Option<i64>,
    /// Detail.
    pub message: String,
    /// Turkish rendering of `message`.
    #[serde(default)]
    pub message_tr: String,
}

/// Device as shown in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceView {
    /// Key.
    pub device_key: String,
    /// Masked instance ID.
    pub display_id: String,
    /// Category code.
    pub category: String,
    /// `bulk_only` | `uasp` | `unknown`.
    pub storage_type: Option<String>,
    /// INQUIRY vendor.
    pub vendor: Option<String>,
    /// INQUIRY product.
    pub product: Option<String>,
    /// USB VID:PID.
    pub usb_vid_pid: Option<String>,
    /// Vendor-level hardware ID.
    pub vendor_level_id: Option<String>,
    /// Friendly name.
    pub friendly_name: Option<String>,
    /// Matched brand.
    pub matched_brand: Option<String>,
    /// Present now.
    pub present: bool,
    /// From synthetic fixture.
    pub synthetic: bool,
    /// First seen.
    pub first_seen_ms: i64,
    /// Last seen.
    pub last_seen_ms: i64,
    /// `allow` | `deny` | `not_applicable` (SIMULATED).
    pub simulated_decision: String,
    /// Reason code.
    pub reason: String,
    /// Policy version.
    pub policy_version: u64,
    /// Enforcement state code at decision time.
    pub enforcement_state: String,
    /// True only with runtime enforcement evidence (never in this build).
    pub enforcement_verified: bool,
}

/// Dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardView {
    /// Enforcement state code.
    pub enforcement_state: String,
    /// Turkish label.
    pub enforcement_label_tr: String,
    /// English label.
    pub enforcement_label_en: String,
    /// Verified protection.
    pub protection_verified: bool,
    /// Banner shown until real validation succeeds.
    pub not_validated_banner: Option<String>,
    /// Service.
    pub service: ServiceStatusView,
    /// Workstation.
    pub workstation_id: String,
    /// Policy version.
    pub policy_version: u64,
    /// Catalog version.
    pub catalog_version: String,
    /// Last policy update.
    pub last_policy_update_ms: Option<i64>,
    /// Enabled allowlist rules.
    pub allowed_manufacturers: u32,
    /// Present USB storage devices.
    pub connected_storage: u32,
    /// Recent simulated denials.
    pub recent_denied: Vec<DeviceView>,
    /// Recent events.
    pub recent_events: Vec<EventView>,
    /// Warnings.
    /// Real Windows protection state (from Windows evidence only).
    #[serde(default)]
    pub windows_protection: WindowsProtectionView,
    pub warnings: Vec<String>,
    /// Turkish rendering of `warnings`.
    #[serde(default)]
    pub warnings_tr: Vec<String>,
    /// Synthetic data in the inventory.
    pub synthetic_data_present: bool,
}

/// Identifier view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifierView {
    /// `inquiry_vendor` | `usb_vid`.
    pub kind: String,
    /// Value.
    pub value: String,
    /// Verification level.
    pub verification: String,
    /// Source.
    pub source: String,
    /// Usable by the OS rule.
    pub enforceable: bool,
    /// Vendor-level hardware IDs this identifier compiles to.
    pub vendor_level_ids: Vec<String>,
}

/// Manufacturer view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManufacturerView {
    /// Id.
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Aliases.
    pub aliases: Vec<String>,
    /// Identifiers.
    pub identifiers: Vec<IdentifierView>,
    /// Notes.
    pub notes: Option<String>,
    /// In allowlist.
    pub allowed: bool,
    /// Rule enabled.
    pub enabled: bool,
    /// Explicitly denied (Phase 6 denylist).
    #[serde(default)]
    pub denied: bool,
    /// Has at least one enforceable identifier.
    pub enforceable: bool,
    /// Issues specific to this brand.
    pub issues: Vec<String>,
    /// Turkish rendering of `issues`.
    #[serde(default)]
    pub issues_tr: Vec<String>,
}

/// Catalog + allowlist view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManufacturersView {
    /// Workstation.
    pub workstation_id: String,
    /// Policy version.
    pub policy_version: u64,
    /// Catalog version.
    pub catalog_version: String,
    /// `dry_run` | `enforce`.
    pub mode: String,
    /// Manufacturers.
    pub manufacturers: Vec<ManufacturerView>,
    /// Global warnings.
    pub warnings: Vec<String>,
    /// Turkish rendering of `warnings`.
    #[serde(default)]
    pub warnings_tr: Vec<String>,
    /// Reserved generic vendors.
    pub reserved_generic_vendors: Vec<String>,
}

/// Event view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventView {
    /// Id.
    pub id: i64,
    /// Time.
    pub utc_ms: i64,
    /// Severity.
    pub severity: String,
    /// Kind.
    pub kind: String,
    /// Device.
    pub device_key: Option<String>,
    /// Message.
    pub message: String,
    /// Turkish rendering of `message` (the stored record stays as written).
    #[serde(default)]
    pub message_tr: String,
    /// Simulation flag.
    pub simulated: bool,
    /// Enforcement state.
    pub enforcement_state: String,
    /// Policy version.
    pub policy_version: Option<u64>,
}

/// Policy change view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChangeView {
    /// Id.
    pub id: i64,
    /// Time.
    pub utc_ms: i64,
    /// Actor.
    pub actor: String,
    /// Action.
    pub action: String,
    /// Brand.
    pub brand_id: String,
    /// Summary.
    pub summary: String,
    /// Turkish rendering of `summary`.
    #[serde(default)]
    pub summary_tr: String,
    /// From.
    pub from_version: u64,
    /// To.
    pub to_version: u64,
}

/// Explanation of a device decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplanationView {
    /// Device.
    pub device: DeviceView,
    /// Explanation.
    pub explanation: Explanation,
}

/// Database health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseHealthView {
    /// Schema version.
    pub schema_version: u32,
    /// Integrity check ok.
    pub integrity_ok: bool,
    /// Hash chain status text.
    pub chain_status: String,
    /// Chain intact.
    pub chain_ok: bool,
    /// `dev_temp` | `program_data` | `memory`.
    pub location_kind: String,
}

/// Windows adapter status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterView {
    /// Platform.
    pub platform: String,
    /// Live SetupAPI inventory available.
    pub live_inventory_available: bool,
    /// Last error.
    pub last_error: Option<String>,
}

/// Policy health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHealthView {
    /// Valid.
    pub valid: bool,
    /// Errors.
    pub errors: Vec<String>,
    /// Turkish rendering of `errors`.
    #[serde(default)]
    pub errors_tr: Vec<String>,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Turkish rendering of `warnings`.
    #[serde(default)]
    pub warnings_tr: Vec<String>,
}

/// Enforcement view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementView {
    /// State code.
    pub state: String,
    /// Turkish label.
    pub label_tr: String,
    /// English label.
    pub label_en: String,
    /// Provider.
    pub provider_id: String,
    /// Capabilities.
    pub capabilities: CapabilityReport,
    /// Planned (not applied) changes.
    pub planned_changes: u32,
    /// Preconditions.
    pub preconditions: Vec<Precondition>,
    /// Risks.
    pub risks: Vec<String>,
    /// Turkish rendering of `risks`.
    #[serde(default)]
    pub risks_tr: Vec<String>,
    /// Dry-run gaps.
    pub enforcement_gaps: Vec<String>,
}

/// Diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsView {
    /// Service.
    pub service: ServiceStatusView,
    /// Database.
    pub database: DatabaseHealthView,
    /// Windows adapter.
    pub windows_adapter: AdapterView,
    /// Policy.
    pub policy: PolicyHealthView,
    /// Enforcement.
    pub enforcement: EnforcementView,
    /// Windows Event Log mirroring.
    #[serde(default)]
    pub event_log: EventLogView,
    /// Unsupported / not implemented features.
    pub unsupported_features: Vec<String>,
    /// Turkish rendering of `unsupported_features`.
    #[serde(default)]
    pub unsupported_features_tr: Vec<String>,
    /// Native tests pending.
    pub pending_native_tests: Vec<String>,
    /// Turkish rendering of `pending_native_tests`.
    #[serde(default)]
    pub pending_native_tests_tr: Vec<String>,
    /// Application version.
    /// Timing measurements of this service process.
    #[serde(default)]
    pub performance: PerformanceView,
    pub app_version: String,
}

/// Result of a policy mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationView {
    /// New policy version.
    pub policy_version: u64,
    /// New catalog version.
    pub catalog_version: String,
    /// Summary.
    pub summary: String,
    /// Turkish rendering of `summary`.
    #[serde(default)]
    pub summary_tr: String,
    /// Warnings after the change.
    pub warnings: Vec<String>,
    /// Turkish rendering of `warnings`.
    #[serde(default)]
    pub warnings_tr: Vec<String>,
}

/// Export result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportView {
    /// Suggested file name.
    pub file_name: String,
    /// MIME type.
    pub mime: String,
    /// Content.
    pub content: String,
    /// Rows.
    pub count: u32,
}

/// Simulation summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationView {
    /// Evaluated devices.
    pub evaluated: u32,
    /// SIMULATED allow.
    pub simulated_allow: u32,
    /// SIMULATED deny.
    pub simulated_deny: u32,
    /// Not applicable.
    pub not_applicable: u32,
    /// Enforcement gaps.
    pub enforcement_gaps: Vec<String>,
    /// Statement.
    pub notice: String,
    /// Turkish rendering of `notice`.
    #[serde(default)]
    pub notice_tr: String,
}

/// A successful response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ResponseBody {
    /// Dashboard.
    Dashboard(DashboardView),
    /// Devices.
    Devices(Vec<DeviceView>),
    /// Manufacturers.
    Manufacturers(ManufacturersView),
    /// Explanation.
    Explanation(ExplanationView),
    /// Events.
    Events(Vec<EventView>),
    /// Policy changes.
    PolicyChanges(Vec<PolicyChangeView>),
    /// Diagnostics.
    Diagnostics(Box<DiagnosticsView>),
    /// Enforcement readiness (read-only).
    EnforcementReadiness(Box<EnforcementReadinessView>),
    /// Windows enforcement observation (read-only).
    EnforcementObservation(Box<EnforcementObservationView>),
    /// Administrator Group Policy checklist (generated, never applied).
    PolicyChecklist(Box<PolicyChecklistView>),
    /// Guided enforcement session state.
    EnforcementSession(Box<EnforcementSessionView>),
    /// Settings.
    Settings(SettingsView),
    /// Simulation.
    Simulation(SimulationView),
    /// Mutation result.
    Mutation(MutationView),
    /// Export.
    Export(ExportView),
    /// Generic acknowledgement.
    Done {
        /// Message.
        message: String,
        /// Turkish rendering of `message`.
        #[serde(default)]
        message_tr: String,
    },
    /// Backups, newest first.
    Backups(Vec<BackupView>),
    /// Restore preview (nothing applied yet).
    RestorePreview(RestorePreviewView),
}

/// A registered database backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupView {
    /// File name inside the backup directory.
    pub file_name: String,
    /// Size in bytes.
    pub bytes: u64,
    /// Creation time, UTC ms.
    pub created_ms: i64,
    /// `manual` or `pre_restore`.
    pub kind: String,
    /// Policy version captured in the backup.
    #[serde(default)]
    pub policy_version: u64,
    /// SHA-256 recorded at creation.
    #[serde(default)]
    pub sha256: String,
    /// Who created it.
    #[serde(default)]
    pub actor: String,
    /// The file is present in the backup directory.
    #[serde(default)]
    pub file_present: bool,
}

/// Result of `PrepareRestore`: what applying would change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePreviewView {
    /// Pass to `ApplyRestore`.
    pub restore_id: String,
    /// Backup file.
    pub file_name: String,
    /// Verified SHA-256.
    pub sha256: String,
    /// Backup creation time.
    pub backup_created_ms: i64,
    /// Policy version inside the backup.
    pub backup_policy_version: u64,
    /// Active policy version now (pass as `expected_policy_version`).
    pub current_policy_version: u64,
    /// Version the restored content would get.
    pub resulting_policy_version: u64,
    /// Workstation id inside the backup.
    pub backup_workstation_id: String,
    /// Human-readable differences (English; empty = identical content).
    pub changes: Vec<String>,
    /// Turkish rendering of `changes`.
    #[serde(default)]
    pub changes_tr: Vec<String>,
    /// Preview expiry, UTC ms.
    pub expires_ms: i64,
    /// Statement of what applying does and does not do.
    pub notice: String,
    /// Turkish rendering of `notice`.
    #[serde(default)]
    pub notice_tr: String,
}

/// Windows Event Log mirroring status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventLogView {
    /// A mirror is attached (Windows service only).
    pub attached: bool,
    /// Entries written.
    pub delivered: u64,
    /// Entries that could not be written.
    pub failures: u64,
    /// Committed audit events not yet written (delivered later, in order).
    #[serde(default)]
    pub pending: u64,
    /// Events not copied because the backlog exceeded the back-fill limit
    /// (recorded as `event_log_backfill_skipped`).
    #[serde(default)]
    pub skipped: u64,
}

/// Turkish and English text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextTrEn {
    /// Turkish.
    pub tr: String,
    /// English.
    pub en: String,
}

/// The real enforcement status (never inferred from configuration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActualEnforcementView {
    /// State code (e.g. `pending_validation`).
    pub state: String,
    /// Turkish label.
    pub label_tr: String,
    /// English label.
    pub label_en: String,
    /// Read/write denial verified. Always false in this build.
    pub verified_protection: bool,
    /// The build has an activation path. Always false in this build.
    pub activation_available: bool,
}

/// One activation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateView {
    /// Gate code.
    pub code: String,
    /// Status.
    pub status: PreconditionStatus,
    /// Detail (English, technical).
    pub detail: String,
}

/// Recovery readiness (model).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReadinessView {
    /// Documented recovery steps.
    pub steps: Vec<RecoveryStep>,
    /// Applying the plan and then its rollback to the captured policy
    /// restores it exactly (in-memory model).
    pub rollback_modelled_exact: bool,
    /// Registry operations the plan would perform (model; nothing is written).
    pub forward_operations: u32,
    /// Operations of the exact rollback.
    pub rollback_operations: u32,
    /// Operations of the feature-update suspend step.
    pub suspend_operations: u32,
}

/// Read-only enforcement readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReadinessView {
    /// The actual enforcement status.
    pub actual_enforcement: ActualEnforcementView,
    /// `windows_registry_read_only`, `fixture` or `unavailable`.
    pub inspection_source: String,
    /// Interpreted inspection (None when the policy could not be read).
    pub inspection: Option<PolicyInspection>,
    /// Why the inspection is missing.
    pub inspection_error: Option<String>,
    /// SHA-256 fingerprint of the (merged) plan.
    pub plan_fingerprint: String,
    /// Planned registry values (description only, never written).
    pub planned_changes: Vec<PlannedChange>,
    /// Conflicts between the captured policy and the plan.
    pub conflicts: Vec<PolicyConflict>,
    /// Activation prerequisites.
    pub gates: Vec<GateView>,
    /// Rights a future activation would need (none are used now).
    pub required_permissions: Vec<TextTrEn>,
    /// Recovery readiness.
    pub recovery: RecoveryReadinessView,
    /// Already-installed storage assessment (sanitised).
    pub installed: InstalledAssessment,
}

/// One observed USB storage device (instance ID masked).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedDeviceView {
    /// Device key.
    pub device_key: String,
    /// Kind of the latest non-simulated audit event for this device.
    #[serde(default)]
    pub last_event_kind: Option<String>,
    /// Time of that event (UTC ms).
    #[serde(default)]
    pub last_event_ms: Option<i64>,
    /// Observation (its `instance_id` is masked).
    pub observed: rustward_enforcement::observer::ObservedDevice,
}

/// Windows enforcement observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementObservationView {
    /// Policy source (`windows_registry_readonly`, ...) or `unavailable`.
    pub policy_source: String,
    /// Policy read error, when the policy could not be read.
    pub policy_error: Option<String>,
    /// Policy capture time (UTC ms).
    pub policy_captured_ms: i64,
    /// The Restrictions key exists.
    pub policy_key_present: bool,
    /// Any Device Installation Restriction rule is configured.
    pub windows_restrictions_configured: bool,
    /// Inventory capture time, if an inventory exists.
    pub inventory_collected_unix_seconds: Option<i64>,
    /// USB storage devices.
    pub devices: Vec<ObservedDeviceView>,
    /// Devices whose installation denial was newly observed (and audited)
    /// by this call.
    pub newly_observed_denials: Vec<String>,
    /// Always true: RustWard itself applies no restriction.
    pub rustward_applies_nothing: bool,
    /// Removable Storage Access policy (read-only interpretation;
    /// class-wide, never manufacturer-specific).
    #[serde(default)]
    pub removable_storage: rustward_enforcement::removable_storage::RemovableStorageState,
}

/// Group Policy checklist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChecklistView {
    /// Structured checklist.
    pub checklist: rustward_enforcement::checklist::PolicyChecklist,
    /// Plain-text rendering for copying.
    pub text: String,
}

/// One step of the honest enforcement-state ladder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderStepView {
    /// `policy_simulation`, `windows_restriction_configured`,
    /// `windows_install_denied`, `read_write_verified`, `protection_inactive`,
    /// `enforcement_error`, `recovery_required`.
    pub code: String,
    /// Turkish label.
    pub label_tr: String,
    /// English label.
    pub label_en: String,
    /// `yes`, `no` or `not_verified`.
    pub status: String,
}

/// A guided enforcement session (from the audit log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    /// Session id.
    pub session_id: String,
    /// Prepared at (UTC ms).
    pub prepared_ms: i64,
    /// Prepared by.
    pub prepared_by: String,
    /// Target device key.
    pub device_key: String,
    /// Target device name.
    pub device_name: String,
    /// Exact hardware ID of the rule.
    pub hardware_id: String,
    /// Retroactive option.
    pub retroactive: bool,
    /// Saved previous Windows policy (normalized lines).
    pub baseline: Vec<String>,
    /// Expected registry values after the change.
    pub expected_lines: Vec<String>,
    /// `device_deny` (one device) or `default_deny_profile`.
    #[serde(default)]
    pub kind: String,
    /// Administrator checklist text (default-deny profile only).
    #[serde(default)]
    pub checklist_text: Option<String>,
    /// Kind of the last application verification event, if any.
    pub last_verification: Option<String>,
    /// Its time.
    pub last_verification_ms: Option<i64>,
}

/// Guided enforcement state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementSessionView {
    /// State code (see [`LadderStepView::code`]).
    pub state: String,
    /// Turkish explanation.
    pub state_tr: String,
    /// English explanation.
    pub state_en: String,
    /// All states with their status.
    pub ladder: Vec<LadderStepView>,
    /// Active session.
    pub session: Option<SessionView>,
    /// Live policy differences from the expected policy (enforcement error).
    pub differences: Vec<String>,
    /// Policy read error.
    pub policy_error: Option<String>,
    /// Observed target device.
    pub target: Option<ObservedDeviceView>,
    /// Always false in this build.
    pub automated_apply_available: bool,
    /// Why automated application is not available.
    pub automated_apply_blocker: TextTrEn,
}

/// Service timing measurements (monotonic clock, milliseconds).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceView {
    /// Windows device enumeration of the last refresh (no state lock held).
    pub last_inventory_collect_ms: Option<u64>,
    /// Applying the last refresh (decisions, audit, database) under the lock.
    pub last_inventory_apply_ms: Option<u64>,
    /// Slowest enumeration since start.
    pub max_inventory_collect_ms: Option<u64>,
    /// Refreshes since start.
    pub inventory_refreshes: u64,
    /// Devices in the last enumeration.
    pub last_inventory_devices: Option<u64>,
    /// Service start until the first inventory was ready.
    pub first_inventory_after_start_ms: Option<i64>,
    /// Last enforcement observation request.
    pub last_observation_ms: Option<u64>,
    /// Last guided verification (including its fresh enumeration).
    pub last_verification_ms: Option<u64>,
}

/// Real Windows protection state for the dashboard. Derived only from the
/// live Windows policy, Device Manager states and the guided session; never
/// from RustWard's simulated decisions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProtectionView {
    /// `verified_active`, `denial_observed`, `configured_unverified`,
    /// `inactive`, `unknown`.
    pub state: String,
    /// Turkish label.
    pub label_tr: String,
    /// English label.
    pub label_en: String,
    /// Turkish detail (scope, evidence, what is missing).
    pub detail_tr: String,
    /// English detail.
    pub detail_en: String,
    /// Devices whose installation Windows denies right now.
    pub denied_now: u32,
    /// Automated policy application by RustWard is available.
    pub automated_apply_available: bool,
    /// Phase 6 assessment counts over USB storage in the inventory.
    #[serde(default)]
    pub summary: StorageSummaryView,
    /// Every condition that keeps the system out of a verified protection
    /// state, most fundamental first.
    #[serde(default)]
    pub blockers: Vec<ProtectionBlockerView>,
}

/// Counts of USB storage devices by Phase 6 category.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSummaryView {
    /// USB storage devices connected now.
    pub connected: u32,
    /// Connected `ALLOW_CANDIDATE`.
    pub allow_candidates: u32,
    /// Connected `DENY_CANDIDATE`.
    pub deny_candidates: u32,
    /// Connected `UNVERIFIED_IDENTITY`.
    pub unverified_identity: u32,
    /// Connected `UNSUPPORTED_DEVICE`.
    pub unsupported: u32,
    /// Connected `WINDOWS_DENIAL_VERIFIED`.
    pub windows_denied: u32,
    /// Connected devices the policy denies but Windows does not.
    pub denied_by_policy_only: u32,
    /// Known but disconnected USB storage devices.
    pub disconnected: u32,
}

/// One reason the system is not in a verified protection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionBlockerView {
    /// Stable code.
    pub code: String,
    /// `blocked` (cannot be resolved by RustWard), `action` (an
    /// administrator can resolve it) or `limitation` (inherent).
    pub kind: String,
    /// Turkish text.
    pub tr: String,
    /// English text.
    pub en: String,
}
