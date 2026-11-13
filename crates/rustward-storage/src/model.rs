//! Storage records and validated settings.

use serde::{Deserialize, Serialize};

/// UI theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    /// Follow Windows.
    #[default]
    System,
    /// Light.
    Light,
    /// Dark.
    Dark,
}

/// UI language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// Turkish (primary).
    #[default]
    Tr,
    /// English.
    En,
}

/// Minimum audit retention in days.
pub const MIN_RETENTION_DAYS: u32 = 30;
/// Maximum audit retention in days.
pub const MAX_RETENTION_DAYS: u32 = 3650;
/// Minimum session idle lock timeout in minutes.
pub const MIN_SESSION_IDLE_MINUTES: u32 = 1;
/// Maximum session idle lock timeout in minutes.
pub const MAX_SESSION_IDLE_MINUTES: u32 = 240;

const fn default_true() -> bool {
    true
}

const fn default_idle_timeout_minutes() -> u32 {
    15
}

/// Application settings (stored as one validated JSON document).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    /// Theme.
    pub theme: Theme,
    /// Language.
    pub language: Language,
    /// Desktop notifications for USB enforcement events.
    pub notifications_enabled: bool,
    /// Days to keep security events.
    pub audit_retention_days: u32,
    /// Background inventory refresh interval for the service, seconds.
    pub inventory_refresh_seconds: u32,
    /// Re-apply the last admin-approved Windows USB GPO snapshot when Windows / service starts.
    #[serde(default = "default_true")]
    pub reconcile_on_startup: bool,
    /// Idle session auto-lock threshold in minutes.
    #[serde(default = "default_idle_timeout_minutes")]
    pub session_idle_timeout_minutes: u32,
    /// Notify when Windows actively blocks a USB storage device (`ProblemCode` 28 + GPO match).
    #[serde(default = "default_true")]
    pub notify_on_blocked: bool,
    /// Warn when a denied device is not yet blocked in Windows (requires reconnect/reinstall or GPO refresh).
    #[serde(default = "default_true")]
    pub notify_on_unblocked_warning: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            language: Language::Tr,
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

impl AppSettings {
    /// Validate ranges.
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&self.audit_retention_days) {
            return Err(format!(
                "audit_retention_days must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}"
            ));
        }
        if !(5..=3600).contains(&self.inventory_refresh_seconds) {
            return Err("inventory_refresh_seconds must be between 5 and 3600".into());
        }
        if !(MIN_SESSION_IDLE_MINUTES..=MAX_SESSION_IDLE_MINUTES)
            .contains(&self.session_idle_timeout_minutes)
        {
            return Err(format!(
                "session_idle_timeout_minutes must be between {MIN_SESSION_IDLE_MINUTES} and {MAX_SESSION_IDLE_MINUTES}"
            ));
        }
        Ok(())
    }
}

/// Event severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational.
    Info,
    /// Needs attention.
    Warning,
    /// Security-relevant failure or denial.
    Critical,
}

impl Severity {
    /// Database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    /// Parse database text.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "info" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// A security event to append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewEvent {
    /// Severity.
    pub severity: Severity,
    /// Stable kind, e.g. `device_arrived`, `policy_changed`, `decision_simulated`.
    pub kind: String,
    /// Related device key, if any.
    pub device_key: Option<String>,
    /// Human-readable message (no serials, no file data, no PINs).
    pub message: String,
    /// True when the event describes a simulation (synthetic device or
    /// simulated decision). Stored and displayed; never dropped.
    pub simulated: bool,
    /// Enforcement state at the time of the event (e.g. `simulated`).
    pub enforcement_state: String,
    /// Policy version in force.
    pub policy_version: Option<u64>,
    /// Structured details (JSON object).
    pub details: serde_json::Value,
}

/// A stored security event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Sequence id.
    pub id: i64,
    /// UTC milliseconds since the Unix epoch.
    pub utc_ms: i64,
    /// Severity.
    pub severity: Severity,
    /// Kind.
    pub kind: String,
    /// Device key.
    pub device_key: Option<String>,
    /// Message.
    pub message: String,
    /// Simulation flag.
    pub simulated: bool,
    /// Enforcement state.
    pub enforcement_state: String,
    /// Policy version.
    pub policy_version: Option<u64>,
    /// Details.
    pub details: serde_json::Value,
    /// Previous chain hash.
    pub prev_hash: String,
    /// This entry's chain hash.
    pub hash: String,
}

/// Event query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFilter {
    /// Case-insensitive substring across sanitized message, kind, device, and actor columns.
    pub text: Option<String>,
    /// Minimum severity.
    pub min_severity: Option<Severity>,
    /// Exact kind.
    pub kind: Option<String>,
    /// Device key.
    pub device_key: Option<String>,
    /// From (inclusive), UTC ms.
    pub since_ms: Option<i64>,
    /// Until (exclusive), UTC ms.
    pub until_ms: Option<i64>,
    /// Only simulated / only non-simulated.
    pub simulated: Option<bool>,
    /// Filter by manufacturer/brand identifier.
    #[serde(default)]
    pub manufacturer_id: Option<String>,
    /// Substring match across device key, device name, or sanitized VID/PID.
    #[serde(default)]
    pub device_query: Option<String>,
    /// Filter by Windows user / interactive session account.
    #[serde(default)]
    pub windows_user: Option<String>,
    /// Filter by effective decision (`allowed`, `blocked`, etc.).
    #[serde(default)]
    pub effective_decision: Option<String>,
    /// Filter by RustWard authenticated actor username.
    #[serde(default)]
    pub actor_username: Option<String>,
    /// Page size (default 200, max 5000).
    pub limit: Option<u32>,
    /// Offset.
    pub offset: Option<u32>,
}

/// Device inventory row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRow {
    /// SHA-256-derived key of the instance ID (correlation without storing serials).
    pub device_key: String,
    /// Instance ID with the unique tail masked.
    pub display_id: String,
    /// Classification category (JSON tag).
    pub category: String,
    /// Storage transport, if storage.
    pub transport: Option<String>,
    /// INQUIRY vendor (display).
    pub vendor: Option<String>,
    /// INQUIRY product (display).
    pub product: Option<String>,
    /// USB VID:PID.
    pub usb_vid_pid: Option<String>,
    /// Vendor-level hardware ID.
    pub vendor_level_id: Option<String>,
    /// Friendly name.
    pub friendly_name: Option<String>,
    /// Matched catalog brand.
    pub matched_brand: Option<String>,
    /// First seen.
    pub first_seen_ms: i64,
    /// Last seen.
    pub last_seen_ms: i64,
    /// Currently present.
    pub present: bool,
    /// From a synthetic fixture.
    pub synthetic: bool,
    /// Last simulated verdict (`allow`, `deny`, `not_applicable`).
    pub last_verdict: String,
    /// Last decision reason code.
    pub last_reason: String,
    /// Policy version of the last decision.
    pub last_policy_version: u64,
    /// Enforcement state recorded with the decision.
    pub enforcement_state: String,
}

/// Stored policy change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChangeRow {
    /// Id.
    pub id: i64,
    /// Time.
    pub utc_ms: i64,
    /// Who (Windows account name or `dev-backend`).
    pub actor: String,
    /// Action.
    pub action: String,
    /// Brand.
    pub brand_id: String,
    /// Summary.
    pub summary: String,
    /// Versions.
    pub from_version: u64,
    /// Versions.
    pub to_version: u64,
    /// Full change record JSON.
    pub change: serde_json::Value,
}

/// Hash-chain verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChainStatus {
    /// All entries verified.
    Intact {
        /// Entries checked.
        entries: u64,
    },
    /// First broken entry.
    Broken {
        /// Event id.
        first_bad_id: i64,
    },
    /// Every remaining entry verifies, but ids are missing between two
    /// entries: events were removed and later events chained onto the
    /// remaining head (e.g. the newest events were deleted and the service
    /// then appended new ones). Ids are never reused and only retention
    /// deletes, and only from the oldest end.
    Missing {
        /// Entries checked up to the gap.
        entries: u64,
        /// Last id before the gap.
        after_id: i64,
        /// First id after the gap.
        next_id: i64,
    },
    /// Every remaining entry verifies, but the newest entries were removed:
    /// SQLite's `AUTOINCREMENT` counter (`sqlite_sequence`) has issued ids
    /// above the last remaining one. Retention never causes this (it deletes
    /// the oldest entries and then appends `retention_applied`).
    Truncated {
        /// Entries checked.
        entries: u64,
        /// Newest remaining id (0 = none).
        last_id: i64,
        /// Highest id ever issued.
        highest_issued: i64,
    },
}

/// Summary of the audit chain at one moment, recorded as an
/// `audit_checkpoint` event and mirrored to the Windows Event Log so that a
/// later truncation or rewrite can be detected by comparing with the copy
/// outside the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    /// Newest event before the checkpoint (0 = none).
    pub head_id: i64,
    /// Its hash (genesis/anchor when none).
    pub head_hash: String,
    /// Entries verified.
    pub entries: u64,
    /// Highest id ever issued before the checkpoint.
    pub highest_issued: i64,
    /// Chain status code (`intact`, `broken`, `truncated`).
    pub chain: String,
    /// Id of the checkpoint event itself.
    pub checkpoint_id: i64,
}

/// Result of comparing the database with a checkpoint copied from outside
/// it (Windows Event Log, a printed export).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CheckpointCheck {
    /// The event exists and its hash starts with the recorded prefix.
    Matches,
    /// The event exists but its hash differs: the chain was rewritten.
    HashDiffers {
        /// First 16 hex characters of the stored hash.
        stored_prefix: String,
    },
    /// The event id is above every remaining id or inside the remaining
    /// range but absent: events were removed.
    EventMissing,
    /// The event is older than the oldest remaining event (retention may
    /// have removed it legitimately; not verifiable).
    OlderThanRetention {
        /// Oldest remaining event id.
        oldest_id: i64,
    },
}

/// Why a backup was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupKind {
    /// Requested by an administrator.
    Manual,
    /// Taken automatically before a restore is applied.
    PreRestore,
}

impl BackupKind {
    /// Stable code (also the file-name prefix selector).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::PreRestore => "pre_restore",
        }
    }

    /// File-name prefix.
    #[must_use]
    pub const fn file_prefix(self) -> &'static str {
        match self {
            Self::Manual => "rustward-backup-",
            Self::PreRestore => "rustward-pre-restore-",
        }
    }
}

/// A registered backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecord {
    /// File name inside the backup directory.
    pub file_name: String,
    /// SHA-256 of the file as written.
    pub sha256: String,
    /// Size in bytes.
    pub bytes: u64,
    /// Creation time, UTC ms.
    pub created_ms: i64,
    /// Active policy version captured in the backup.
    pub policy_version: u64,
    /// Kind.
    pub kind: BackupKind,
    /// Who created it.
    pub actor: String,
}

/// Why a backup cannot be restored. Every rejection is audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum BackupRejection {
    /// Not a plain file name.
    #[error("not a plain backup file name")]
    InvalidName,
    /// Not created and registered by this RustWard installation.
    #[error("not a backup registered by this installation")]
    NotRegistered,
    /// The registered file is missing.
    #[error("backup file is missing")]
    Missing,
    /// Not a regular file (directory, link, device).
    #[error("backup is not a regular file")]
    NotRegularFile,
    /// Content differs from the registered SHA-256.
    #[error("backup content does not match its registered SHA-256")]
    HashMismatch,
    /// Not a valid SQLite database or `integrity_check` failed.
    #[error("backup failed the database integrity check")]
    Corrupt,
    /// Not a RustWard database.
    #[error("backup is not a RustWard database")]
    NotRustWard,
    /// Created by a newer RustWard.
    #[error("backup schema is newer than this build supports")]
    SchemaTooNew,
    /// No valid active policy inside (checksum or validation failure).
    #[error("backup contains no valid policy")]
    InvalidPolicy,
}

impl BackupRejection {
    /// Stable code for audit records.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::NotRegistered => "not_registered",
            Self::Missing => "missing",
            Self::NotRegularFile => "not_regular_file",
            Self::HashMismatch => "hash_mismatch",
            Self::Corrupt => "corrupt",
            Self::NotRustWard => "not_rustward",
            Self::SchemaTooNew => "schema_too_new",
            Self::InvalidPolicy => "invalid_policy",
        }
    }
}

/// A verified backup, read into memory. Applying it never reads the file
/// again, so the file cannot change between verification and use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreCandidate {
    /// Registry entry.
    pub record: BackupRecord,
    /// Policy state stored in the backup (checksum-verified, validated).
    pub state: rustward_core::policy_edit::PolicyState,
    /// Settings stored in the backup (validated).
    pub settings: AppSettings,
}

/// Structured indexed audit metadata extracted from `SecurityEvent.details`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Local computer / workstation identifier.
    pub computer_name: Option<String>,
    /// Matched manufacturer catalog identifier.
    pub manufacturer_id: Option<String>,
    /// Sanitized device display / product name.
    pub device_name: Option<String>,
    /// USB VID:PID (`XXXX:YYYY`) when available.
    pub vid_pid: Option<String>,
    /// Bus / storage transport (`usbstor`, `uasp_scsi`, etc.).
    pub transport: Option<String>,
    /// Windows PnP ProblemCode (`28`, `0`, etc.).
    pub pnp_problem_code: Option<u32>,
    /// Effective decision (`allowed`, `blocked`, `not_applicable`, etc.).
    pub effective_decision: Option<String>,
    /// Real enforcement outcome (`windows_blocked_verified`, `windows_allowed_verified`, `gpo_applied`, `not_enforced`, etc.).
    pub enforcement_outcome: Option<String>,
    /// Authenticated RustWard operator username (if action performed in-app).
    pub actor_username: Option<String>,
    /// Logged-in Windows interactive user (`DOMAIN\user` or `None` when ambiguous/unknown).
    pub windows_user: Option<String>,
    /// Policy revision / version identifier string.
    pub policy_revision: Option<String>,
}

fn first_nonempty_str(details: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = details.get(*key).and_then(|v| v.as_str()) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

impl EventMetadata {
    /// Extracts canonical indexed audit fields from an event's JSON `details` object.
    #[must_use]
    pub fn from_details(details: &serde_json::Value) -> Self {
        let pnp_problem_code = details
            .get("pnp_problem_code")
            .or_else(|| details.get("problem_code"))
            .and_then(|v| v.as_u64())
            .and_then(|u| u32::try_from(u).ok());
        Self {
            computer_name: first_nonempty_str(details, &["computer_name", "workstation_id"]),
            manufacturer_id: first_nonempty_str(details, &["manufacturer_id", "brand_id"]),
            device_name: first_nonempty_str(
                details,
                &["device_name", "friendly_name", "product", "label"],
            ),
            vid_pid: first_nonempty_str(details, &["vid_pid", "usb_vid_pid"]),
            transport: first_nonempty_str(details, &["transport"]),
            pnp_problem_code,
            effective_decision: first_nonempty_str(
                details,
                &["effective_decision", "decision", "verdict"],
            ),
            enforcement_outcome: first_nonempty_str(details, &["enforcement_outcome", "outcome"]),
            actor_username: first_nonempty_str(details, &["actor_username", "actor"]),
            windows_user: first_nonempty_str(details, &["windows_user"]),
            policy_revision: first_nonempty_str(details, &["policy_revision", "revision_id"]),
        }
    }
}

/// Persisted snapshot of the last admin-approved Windows USB GPO configuration.
///
/// Used at Windows / `RustWardService` startup to verify and deterministically
/// reconcile local Group Policy against the explicitly committed admin state,
/// preserving non-RustWard entries and respecting `auto_reconcile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedPolicyRecord {
    /// RustWard policy version that generated this Windows GPO snapshot.
    pub policy_version: u64,
    /// Stable revision identifier (`v{policy_version}-{hash_prefix}`).
    pub revision_id: String,
    /// Catalog version active when approved.
    pub catalog_version: String,
    /// Compiled RustWard-managed `DenyDeviceIDs` list.
    pub deny_ids: Vec<String>,
    /// Compiled RustWard-managed `AllowDeviceIDs` list.
    pub allow_ids: Vec<String>,
    /// Pre-existing non-RustWard entries observed/preserved in Windows GPO.
    pub third_party_denies: Vec<String>,
    /// Whether `DenyDeviceIDsRetroactive` was approved as enabled.
    pub retroactive: bool,
    /// Cached copy of auto-reconcile setting when saved.
    pub auto_reconcile: bool,
    /// Authenticated administrator who approved applying to Windows.
    pub approved_by: String,
    /// UTC milliseconds timestamp of approval.
    pub approved_ms: i64,
}

/// Role inside the RustWard management application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// Full policy configuration, Windows apply/rollback, user/password management, and authorized exit.
    Admin,
    /// Can inspect status, inventory, manufacturers (read-only), and audit logs without mutating policy or exiting.
    ReadOnly,
}

impl UserRole {
    /// Database text encoding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::ReadOnly => "read_only",
        }
    }

    /// Parses database text encoding.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "read_only" => Some(Self::ReadOnly),
            _ => None,
        }
    }
}

/// Public sanitized projection of a persisted `app_users` row (never contains hashes or sealed secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUserRecord {
    /// SQLite row id.
    pub id: i64,
    /// Unique lowercase-comparable login name.
    pub username: String,
    /// Operator display name.
    pub display_name: String,
    /// Assigned role.
    pub role: UserRole,
    /// Consecutive failed password attempts since last success.
    pub failed_attempts: u32,
    /// Lockout expiration timestamp in UTC milliseconds, if locked.
    pub locked_until_ms: Option<i64>,
    /// Creation timestamp in UTC ms.
    pub created_ms: i64,
    /// Last update timestamp in UTC ms.
    pub updated_ms: i64,
    /// Whether a DPAPI-sealed recovery verifier exists for this account.
    pub has_recovery_key: bool,
}

/// Result of verifying credentials against `app_users`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAttemptOutcome {
    /// Credentials verified; failed-attempt counter reset.
    Success(AppUserRecord),
    /// Account currently rate-limited until `locked_until_ms`.
    Locked {
        /// Account username if present.
        username: String,
        /// UTC milliseconds when lockout expires.
        locked_until_ms: i64,
        /// Current consecutive failures.
        failed_attempts: u32,
    },
    /// Invalid username or password.
    InvalidCredentials {
        /// Attempted username.
        username: String,
        /// Recorded failures for existing user (or 0 if user absent).
        failed_attempts: u32,
        /// Whether this failure triggered a temporary lockout.
        now_locked_until_ms: Option<i64>,
    },
}
