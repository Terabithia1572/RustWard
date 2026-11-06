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

/// Application settings (stored as one validated JSON document).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    /// Theme.
    pub theme: Theme,
    /// Language.
    pub language: Language,
    /// Desktop notifications for denied devices.
    pub notifications_enabled: bool,
    /// Days to keep security events.
    pub audit_retention_days: u32,
    /// Background inventory refresh interval for the service, seconds.
    pub inventory_refresh_seconds: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            language: Language::Tr,
            notifications_enabled: true,
            audit_retention_days: 365,
            inventory_refresh_seconds: 30,
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
    /// Case-insensitive substring in message or kind.
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
