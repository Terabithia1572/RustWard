//! Typed request/response contract. The TypeScript mirror lives in
//! `apps/rustward-desktop/src/api/types.ts`; keep both in sync.

use rustward_core::explain::Explanation;
use rustward_core::policy_edit::{BulkManufacturerAction, ManufacturerInput};
pub use rustward_enforcement::compound_policy::{
    CompiledWindowsPolicy, CompoundPolicyDiff, CompoundPolicyPlanView, ConfiguredIntention,
    DeviceOutcomeStatus, DeviceOverrideView, IdentityCoverage, LocalizedText,
    ManufacturerPolicyView, ObservedWindowsPolicy, WindowsPolicyStatus,
};
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
    /// Filter by manufacturer/brand identifier.
    #[serde(default)]
    pub manufacturer_id: Option<String>,
    /// Filter by device key, device name, or VID:PID substring.
    #[serde(default)]
    pub device_query: Option<String>,
    /// Filter by Windows interactive account.
    #[serde(default)]
    pub windows_user: Option<String>,
    /// Filter by effective decision (`allowed`, `blocked`, etc.).
    #[serde(default)]
    pub effective_decision: Option<String>,
    /// Filter by RustWard authenticated actor username.
    #[serde(default)]
    pub actor_username: Option<String>,
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

const fn default_idle_timeout_minutes() -> u32 {
    15
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
    /// Re-apply the last admin-approved Windows USB GPO policy snapshot at Windows startup.
    #[serde(default = "default_true")]
    pub reconcile_on_startup: bool,
    /// Idle session auto-lock threshold in minutes.
    #[serde(default = "default_idle_timeout_minutes")]
    pub session_idle_timeout_minutes: u32,
    /// Desktop notification when Windows blocks a USB device.
    #[serde(default = "default_true")]
    pub notify_on_blocked: bool,
    /// Desktop warning when a denied USB device is not yet blocked in Windows.
    #[serde(default = "default_true")]
    pub notify_on_unblocked_warning: bool,
}

impl Default for SettingsView {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            language: "tr".into(),
            notifications_enabled: true,
            audit_retention_days: 365,
            inventory_refresh_seconds: 30,
            reconcile_on_startup: true,
            session_idle_timeout_minutes: default_idle_timeout_minutes(),
            notify_on_blocked: true,
            notify_on_unblocked_warning: true,
        }
    }
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
    /// Apply an authorized Windows device block via Local Group Policy COM API (administrator).
    ApplyDeviceBlock {
        /// Optional session id (16 hex).
        #[serde(default)]
        session_id: Option<String>,
        /// Target device key (32 hex) when applying without a prior prepare step.
        #[serde(default)]
        device_key: Option<String>,
        /// Include the "also apply to installed devices" option.
        #[serde(default)]
        retroactive: bool,
    },
    /// Restore previous Windows policy via Local Group Policy COM API (administrator).
    RestoreDevicePolicy {
        /// Session id (16 hex), or active session if omitted.
        #[serde(default)]
        session_id: Option<String>,
        /// Target device key (32 hex) when unblocking a specific device override.
        #[serde(default)]
        device_key: Option<String>,
    },
    /// Get the unified compound Windows policy plan (read-only).
    GetCompoundPolicyPlan,
    /// Apply the unified compound policy to Windows via Local Group Policy COM API (administrator).
    ApplyCompoundPolicy {
        /// Include the "also apply to installed devices" option.
        #[serde(default = "default_true")]
        retroactive: bool,
        /// Optimistic concurrency: the active version shown in the preview.
        expected_policy_version: u64,
    },
    /// Rollback compound policy restrictions in Windows Group Policy (administrator).
    RollbackCompoundPolicy,
    /// Targeted restart/recovery of an allowed USB device stuck in Code 28 (administrator).
    RecoverDevice {
        /// Device key (32 hex).
        device_key: String,
    },
    // ---- V1.1 auth, bulk policy, audit, notifications & about -----------
    /// Query authentication setup and session lock state (pre-login allowed).
    GetAuthStatus,
    /// Mandatory first-run initial administrator creation (when `app_users` is empty).
    SetupInitialAdmin {
        /// Admin username (`[A-Za-z0-9][A-Za-z0-9_.-]{2,63}`).
        username: String,
        /// Human display name.
        display_name: String,
        /// Password meeting minimum complexity requirements.
        password: String,
    },
    /// Authenticate an operator account and obtain an opaque session token.
    Login {
        /// Operator username.
        username: String,
        /// Plaintext password (verified via backend Argon2id).
        password: String,
    },
    /// Invalidate the active session token cleanly.
    Logout,
    /// Lock the active authenticated UI session cleanly.
    LockSession,
    /// Refresh session idle/activity deadline while authenticated.
    HeartbeatSession,
    /// Change the currently authenticated operator's password.
    ChangePassword {
        /// Current password for verification.
        current_password: String,
        /// New password meeting complexity rules.
        new_password: String,
    },
    /// Reset an administrator password using a valid DPAPI-sealed recovery key.
    ResetPasswordWithRecovery {
        /// Target administrator username.
        username: String,
        /// One-time administrator recovery key (`RWREC-...`).
        recovery_key: String,
        /// New password.
        new_password: String,
    },
    /// Create a new operator user (`admin` or `read_only`).
    CreateAppUser {
        /// Username.
        username: String,
        /// Display name.
        display_name: String,
        /// Role (`admin` | `read_only`).
        role: String,
        /// Initial password.
        password: String,
    },
    /// List configured operator accounts without secrets.
    ListAppUsers,
    /// Delete an operator account (never removes the last administrator).
    DeleteAppUser {
        /// Target username.
        username: String,
    },
    /// Verify administrator credentials prior to allowing normal application shutdown.
    VerifyExitAuthorization {
        /// Administrator username.
        username: String,
        /// Administrator password.
        password: String,
    },
    /// Preview manufacturer and USB device impact before confirming bulk operations.
    PreviewBulkManufacturers {
        /// Target bulk state (`allow_all` | `explicit_deny_all` | `unconfigured_all`).
        action: BulkManufacturerAction,
    },
    /// Atomically update all catalog manufacturers and optionally commit Windows GPO.
    ApplyBulkManufacturers {
        /// Target bulk state.
        action: BulkManufacturerAction,
        /// When `true`, also compiles and commits Windows GPO in the same operation.
        #[serde(default)]
        apply_to_windows: bool,
        /// Include retroactive device restriction when applying to Windows.
        #[serde(default = "default_true")]
        retroactive: bool,
        /// Optimistic concurrency version check.
        expected_policy_version: u64,
    },
    /// Read sanitized real enforcement notification feed for desktop toast notifier.
    GetNotificationFeed {
        /// Return items strictly newer than this event id when set.
        #[serde(default)]
        after_event_id: Option<i64>,
    },
    /// Paginated audit event query with exact total count and chain integrity summary.
    QueryAuditEvents {
        /// Structured audit filter.
        query: EventQuery,
    },
    /// Verify the cryptographic SHA-256 hash chain over `security_events`.
    VerifyAuditChain,
    /// Static and build-time metadata for the About page (`Hakkında`).
    GetAboutInfo,
}

const fn default_true() -> bool {
    true
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
            | Self::RunSimulation
            | Self::GetCompoundPolicyPlan
            | Self::GetAuthStatus
            | Self::Login { .. }
            | Self::Logout
            | Self::LockSession
            | Self::HeartbeatSession
            | Self::ChangePassword { .. }
            | Self::VerifyExitAuthorization { .. }
            | Self::PreviewBulkManufacturers { .. }
            | Self::GetNotificationFeed { .. }
            | Self::QueryAuditEvents { .. }
            | Self::VerifyAuditChain
            | Self::GetAboutInfo => AccessLevel::ReadOnly,
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
            | Self::ApplyRestore { .. }
            | Self::ApplyDeviceBlock { .. }
            | Self::RestoreDevicePolicy { .. }
            | Self::ApplyCompoundPolicy { .. }
            | Self::RollbackCompoundPolicy
            | Self::RecoverDevice { .. }
            | Self::SetupInitialAdmin { .. }
            | Self::ResetPasswordWithRecovery { .. }
            | Self::CreateAppUser { .. }
            | Self::ListAppUsers
            | Self::DeleteAppUser { .. }
            | Self::ApplyBulkManufacturers { .. } => AccessLevel::Administrator,
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
    /// Explicit device-level override status: "denied" | "allowed" | "none".
    #[serde(default)]
    pub device_override: Option<String>,
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
    /// Explicit Phase 13 protection category code.
    #[serde(default)]
    pub protection_category: String,
    /// Natural Turkish detail describing real Windows enforcement status.
    #[serde(default)]
    pub protection_detail_tr: String,
    /// English detail describing real Windows enforcement status.
    #[serde(default)]
    pub protection_detail_en: String,
    /// True when local draft manufacturer/device rules differ from approved Windows GPO.
    #[serde(default)]
    pub pending_policy_apply: bool,
    /// Policy version of the currently approved Windows GPO snapshot, if any.
    #[serde(default)]
    pub approved_policy_version: Option<u64>,
    /// Outcome of service startup reconciliation (`reconciled`, `already_in_sync`, `skipped_disabled`, `failed`, `none`).
    #[serde(default)]
    pub startup_reconcile_status: Option<String>,
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
    /// Local computer identifier.
    #[serde(default)]
    pub computer_name: Option<String>,
    /// Matched manufacturer id.
    #[serde(default)]
    pub manufacturer_id: Option<String>,
    /// Sanitized device display name.
    #[serde(default)]
    pub device_name: Option<String>,
    /// Sanitized VID:PID.
    #[serde(default)]
    pub vid_pid: Option<String>,
    /// Transport (`usbstor`, `uasp_scsi`, etc.).
    #[serde(default)]
    pub transport: Option<String>,
    /// Windows PnP ProblemCode.
    #[serde(default)]
    pub pnp_problem_code: Option<u32>,
    /// Effective decision (`allowed`, `blocked`, etc.).
    #[serde(default)]
    pub effective_decision: Option<String>,
    /// Real Windows enforcement outcome.
    #[serde(default)]
    pub enforcement_outcome: Option<String>,
    /// RustWard operator username.
    #[serde(default)]
    pub actor_username: Option<String>,
    /// Unambiguously attributed Windows interactive user, or `None`.
    #[serde(default)]
    pub windows_user: Option<String>,
    /// Policy revision id.
    #[serde(default)]
    pub policy_revision: Option<String>,
    /// Full structured audit payload JSON (sanitized).
    #[serde(default)]
    pub details: serde_json::Value,
    /// Previous SHA-256 chain hash.
    #[serde(default)]
    pub prev_hash: String,
    /// Current SHA-256 chain hash.
    #[serde(default)]
    pub hash: String,
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
    /// Compound Windows policy plan.
    CompoundPolicyPlan(Box<CompoundPolicyPlanView>),
    // ---- V1.1 responses ---------------------------------------------------
    /// Authentication setup and active session lock status.
    AuthStatus(AuthStatusView),
    /// Successful login / setup / token issuance response.
    Login(LoginResultView),
    /// Password reset result (includes rotated recovery key once when applicable).
    RecoveryReset(RecoveryResetView),
    /// Registered application operator accounts.
    AppUsers(Vec<AppUserView>),
    /// Exit authorization outcome with single-use exit nonce.
    ExitAuthorized(ExitAuthorizationView),
    /// Impact preview before applying bulk manufacturer update.
    BulkPreview(BulkManufacturerPreviewView),
    /// Result of atomic bulk manufacturer update (and optional GPO commit).
    BulkApplyResult(BulkManufacturerApplyResultView),
    /// Sanitized Windows notification feed for session-0-free desktop toast notifier.
    NotificationFeed(NotificationFeedView),
    /// Paginated audit log page with exact total count and chain integrity summary.
    AuditPage(AuditPageView),
    /// Hash-chain integrity verification report.
    AuditChainVerification(AuditChainVerificationView),
    /// Application About metadata (`Hakkında`).
    AboutInfo(AboutInfoView),
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

/// Public summary of the currently logged-in operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthUserView {
    /// Operator username.
    pub username: String,
    /// Operator display name.
    pub display_name: String,
    /// Role (`admin` | `read_only`).
    pub role: String,
    /// Account creation timestamp in UTC ms.
    pub created_ms: i64,
}

/// Authentication and session status returned by `GetAuthStatus` / `Logout` / `LockSession`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStatusView {
    /// True when no operator accounts exist yet and first-run admin setup is mandatory.
    pub setup_required: bool,
    /// True when backend requires valid session token authentication.
    pub auth_enforced: bool,
    /// True when a non-expired, unlocked session token was verified.
    pub authenticated: bool,
    /// True when session is currently locked (timed out or manually locked).
    pub locked: bool,
    /// Authenticated operator summary when `authenticated == true`.
    pub current_user: Option<AuthUserView>,
    /// Absolute session expiration UTC ms when authenticated.
    pub session_expires_at_ms: Option<i64>,
    /// Idle auto-lock threshold in minutes.
    pub idle_timeout_minutes: u32,
    /// Remaining seconds if client/account is locked due to failed logins.
    pub lockout_remaining_seconds: Option<u64>,
    /// True if caller is running on an elevated Windows Administrator IPC channel.
    #[serde(default)]
    pub windows_admin_channel: bool,
}

/// Login / initial admin setup result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResultView {
    /// Authenticated operator summary.
    pub user: AuthUserView,
    /// Opaque session token held natively by Rust client / Tauri state.
    pub session_token: String,
    /// Absolute session expiration UTC ms.
    pub expires_at_ms: i64,
    /// Configured idle timeout in minutes.
    pub idle_timeout_minutes: u32,
    /// Shown ONCE upon `SetupInitialAdmin` or admin creation, then discarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key_once: Option<String>,
}

/// Password recovery reset result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryResetView {
    /// Account whose password was reset.
    pub username: String,
    /// Newly rotated one-time replacement recovery key (display once to administrator).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_recovery_key_once: Option<String>,
    /// English status message.
    pub message: String,
    /// Turkish status message.
    pub message_tr: String,
}

/// Sanitized operator account row listed for administrators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUserView {
    /// Username.
    pub username: String,
    /// Display name.
    pub display_name: String,
    /// `admin` | `read_only`.
    pub role: String,
    /// Consecutive failed attempts.
    pub failed_attempts: u32,
    /// Lockout expiration UTC ms, if currently locked.
    pub locked_until_ms: Option<i64>,
    /// Creation timestamp UTC ms.
    pub created_ms: i64,
    /// True if account holds a DPAPI-sealed recovery verifier.
    pub has_recovery_key: bool,
}

/// Exit authorization result returned only after backend credential verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitAuthorizationView {
    /// True when administrator credentials succeeded.
    pub authorized: bool,
    /// Verifying administrator username.
    pub authorized_by: String,
    /// Single-use nonce verified by the native desktop shell before exit.
    pub exit_nonce: String,
    /// Turkish confirmation message.
    pub message_tr: String,
    /// English confirmation message.
    pub message_en: String,
}

/// Pre-confirmation impact summary before executing a bulk manufacturer change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkManufacturerPreviewView {
    /// Target bulk action (`allow_all` | `explicit_deny_all` | `unconfigured_all`).
    pub action: BulkManufacturerAction,
    /// Active policy version prior to edit.
    pub current_policy_version: u64,
    /// Total catalog manufacturers affected/present.
    pub total_manufacturers: u32,
    /// Manufacturers currently allowed.
    pub currently_allowed: u32,
    /// Manufacturers currently explicitly denied.
    pub currently_denied: u32,
    /// Manufacturers currently unconfigured.
    pub currently_unconfigured: u32,
    /// Number of manufacturers whose state will change.
    pub manufacturers_changing: u32,
    /// Currently connected USB storage devices observed in inventory.
    pub connected_storage_devices: u32,
    /// Connected USB storage devices whose effective policy verdict after change is denied.
    pub connected_likely_blocked: u32,
    /// Connected USB storage devices whose effective policy verdict after change is allowed.
    pub connected_likely_allowed: u32,
    /// Number of compiled hardware/device IDs that would be in Windows `DenyDeviceIDs`.
    pub compiled_deny_ids_count: u32,
    /// Number of compiled hardware/device IDs that would be in Windows `AllowDeviceIDs`.
    pub compiled_allow_ids_count: u32,
    /// Count of custom user-supplied catalog identifiers preserved intact.
    pub preserved_custom_identifiers_count: u32,
    /// Count of explicit per-device overrides (`denied_devices` + `allowed_devices`) preserved intact.
    pub preserved_device_overrides_count: u32,
}

/// Post-apply report after atomic bulk manufacturer update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkManufacturerApplyResultView {
    /// Applied bulk action.
    pub action: BulkManufacturerAction,
    /// New persisted policy version.
    pub policy_version: u64,
    /// Total manufacturers in catalog.
    pub total_manufacturers: u32,
    /// Count updated (or 0 if idempotent already in state).
    pub manufacturers_updated: u32,
    /// True if also committed to Windows Local Group Policy in the same flow.
    pub applied_to_windows: bool,
    /// Updated compound policy plan after edit.
    pub windows_plan: Option<CompoundPolicyPlanView>,
    /// Result of Windows GPO apply transaction when `applied_to_windows == true`.
    pub windows_apply_result: Option<MutationView>,
    /// Turkish warnings/advisories (e.g., pending Windows apply or active devices requiring reconnect).
    #[serde(default)]
    pub warnings_tr: Vec<String>,
    /// English warnings/advisories.
    #[serde(default)]
    pub warnings_en: Vec<String>,
}

/// Sanitized notification item streamed to the out-of-Session-0 desktop notifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationItemView {
    /// Audit event sequence id.
    pub event_id: i64,
    /// UTC milliseconds timestamp.
    pub utc_ms: i64,
    /// `blocked_verified` | `deny_not_enforced_warning`.
    pub category: String,
    /// Deterministic deduplication key across reconnect polls.
    pub dedup_key: String,
    /// Localized Turkish toast title.
    pub title_tr: String,
    /// Localized English toast title.
    pub title_en: String,
    /// Localized Turkish toast body.
    pub body_tr: String,
    /// Localized English toast body.
    pub body_en: String,
    /// Matched manufacturer display name if known.
    pub manufacturer_name: Option<String>,
    /// Sanitized device display name if known.
    pub device_name: Option<String>,
    /// Sanitized VID:PID if known.
    pub vid_pid: Option<String>,
    /// True ONLY when Windows PnP ProblemCode/GPO evidence proves block occurred.
    pub enforced_verified: bool,
}

/// Read-only notification feed returned over `PIPE_NAME_STATUS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationFeedView {
    /// Latest event id in `security_events` for incremental cursoring.
    pub latest_event_id: i64,
    /// Master notification toggle from settings.
    pub notifications_enabled: bool,
    /// Notify on real Windows USB blocks.
    pub notify_on_blocked: bool,
    /// Notify when a denied USB device was NOT enforced by Windows.
    pub notify_on_unblocked_warning: bool,
    /// Active UI language (`tr` | `en`).
    pub language: String,
    /// Eligible deduplicated notifications strictly newer than `after_event_id`.
    pub items: Vec<NotificationItemView>,
}

/// Paginated audit query result with exact matching total count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPageView {
    /// Matching rows in descending order.
    pub events: Vec<EventView>,
    /// Total rows matching filter before LIMIT/OFFSET.
    pub total_count: u64,
    /// Applied page size.
    pub limit: u32,
    /// Applied row offset.
    pub offset: u32,
    /// Hash chain intact status at query time.
    pub chain_ok: bool,
    /// Short chain status label (`intact`, `broken`, `missing`, `truncated`).
    pub chain_status: String,
}

/// Result of manual/UI hash-chain verification over `security_events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainVerificationView {
    /// True when the entire stored chain is intact.
    pub intact: bool,
    /// `intact` | `broken` | `missing` | `truncated`.
    pub status_code: String,
    /// Total checked entries.
    pub entries: u64,
    /// Turkish operator summary.
    pub summary_tr: String,
    /// English operator summary.
    pub summary_en: String,
    /// First invalid/missing event sequence id when tampered or truncated.
    pub first_bad_id: Option<i64>,
}

/// Build and attribution metadata for the About page (`Hakkında`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AboutInfoView {
    /// Product name (`RustWard`).
    pub app_name: String,
    /// Turkish subtitle.
    pub tagline_tr: String,
    /// English subtitle.
    pub tagline_en: String,
    /// Semantic version string (`1.1.0`).
    pub version: String,
    /// Build-time Git commit SHA (short/full or `unknown`).
    pub commit_sha: String,
    /// Build date/timestamp string.
    pub build_timestamp: String,
    /// Author name (`Yunus İNAN`).
    pub author: String,
    /// Repository URL.
    pub repository_url: String,
    /// License notice.
    pub license: String,
    /// Turkish copyright string.
    pub copyright_tr: String,
    /// English copyright string.
    pub copyright_en: String,
    /// Turkish architecture overview.
    pub architecture_summary_tr: String,
    /// English architecture overview.
    pub architecture_summary_en: String,
    /// Technology stack list.
    pub tech_stack: Vec<String>,
    /// Tested/verified OS environments.
    pub verified_environments: Vec<String>,
    /// Honest security boundaries/limits in Turkish.
    pub security_limits_tr: Vec<String>,
    /// Honest security boundaries/limits in English.
    pub security_limits_en: Vec<String>,
    /// Acknowledgments in Turkish.
    pub acknowledgments_tr: Vec<String>,
    /// Third-party notices.
    pub third_party_notices: Vec<String>,
}
