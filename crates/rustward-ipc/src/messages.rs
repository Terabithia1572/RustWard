//! Typed request/response contract. The TypeScript mirror lives in
//! `apps/rustward-desktop/src/api/types.ts`; keep both in sync.

use rustward_core::explain::Explanation;
use rustward_core::policy_edit::ManufacturerInput;
use rustward_enforcement::{CapabilityReport, Precondition};
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
    /// Settings.
    GetSettings,
    /// Re-evaluate the current inventory under the current policy (no writes).
    RunSimulation,
    // ---- privileged (administrator) -------------------------------------
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
            | Self::GetSettings
            | Self::RunSimulation => AccessLevel::ReadOnly,
            Self::AddManufacturer { .. }
            | Self::UpdateManufacturer { .. }
            | Self::RemoveManufacturer { .. }
            | Self::SetManufacturerAllowed { .. }
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
    pub warnings: Vec<String>,
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
    /// Has at least one enforceable identifier.
    pub enforceable: bool,
    /// Issues specific to this brand.
    pub issues: Vec<String>,
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
    /// Warnings.
    pub warnings: Vec<String>,
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
    /// Native tests pending.
    pub pending_native_tests: Vec<String>,
    /// Application version.
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
    /// Warnings after the change.
    pub warnings: Vec<String>,
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
    Diagnostics(DiagnosticsView),
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
    /// Preview expiry, UTC ms.
    pub expires_ms: i64,
    /// Statement of what applying does and does not do.
    pub notice: String,
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
