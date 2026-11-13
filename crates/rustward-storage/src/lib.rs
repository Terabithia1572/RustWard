//! Local SQLite persistence for RustWard.
//!
//! - Versioned migrations ([`migrations`]).
//! - Policy state (catalog + allowlist) stored as versioned, SHA-256-checked
//!   JSON documents; exactly one active version; each edit is one
//!   transaction (state + change record + security event).
//! - Settings, device inventory, policy-change history.
//! - Security events in a SHA-256 hash chain (tamper-*evident*, not
//!   tamper-proof against an administrator), with retention that keeps the
//!   chain verifiable through an anchor.
//! - Backup / restore via the SQLite online backup API.
//!
//! Data minimization: devices are keyed by a hash of the instance ID and
//! stored with the unique tail masked. No file names, file contents or PINs
//! are ever stored.
//!
//! Deployment ACLs (documented, applied by the installer in Phase 8): the
//! database directory `%ProgramData%\RustWard` is restricted to SYSTEM and
//! Administrators; the desktop UI never opens the database directly.

#![forbid(unsafe_code)]

pub mod auth;
pub mod migrations;
pub mod model;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, params_from_iter};
use rustward_core::policy_edit::{ChangeRecord, EditOutcome, PolicyState};
use sha2::{Digest, Sha256};

pub use model::{
    AppSettings, AppUserRecord, ApprovedPolicyRecord, AuditCheckpoint, AuthAttemptOutcome,
    BackupKind, BackupRecord, BackupRejection, ChainStatus, CheckpointCheck, DeviceRow,
    EventFilter, EventMetadata, Language, NewEvent, PolicyChangeRow, RestoreCandidate,
    SecurityEvent, Severity, Theme, UserRole,
};

/// [`Store::check_checkpoint`] on a database file opened **read-only** (safe
/// while the service is running; WAL readers do not block the writer).
///
/// # Errors
/// See [`Store::check_checkpoint`]; also if the file cannot be opened.
pub fn check_checkpoint_file(
    path: &std::path::Path,
    head_id: i64,
    hash_prefix: &str,
) -> Result<CheckpointCheck, StorageError> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    check_checkpoint_conn(&conn, head_id, hash_prefix)
}

fn check_checkpoint_conn(
    conn: &Connection,
    head_id: i64,
    hash_prefix: &str,
) -> Result<CheckpointCheck, StorageError> {
    let prefix = hash_prefix
        .trim()
        .trim_end_matches('…')
        .to_ascii_lowercase();
    if prefix.len() < 16 || prefix.len() > 64 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StorageError::Invalid(
            "checkpoint hash must be 16 to 64 hexadecimal characters".into(),
        ));
    }
    if head_id <= 0 {
        return Err(StorageError::Invalid(
            "checkpoint head id must be positive".into(),
        ));
    }
    let stored: Option<String> = conn
        .query_row(
            "SELECT hash FROM security_events WHERE id = ?1",
            params![head_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(hash) = stored {
        return Ok(if hash.starts_with(&prefix) {
            CheckpointCheck::Matches
        } else {
            CheckpointCheck::HashDiffers {
                stored_prefix: hash.chars().take(16).collect(),
            }
        });
    }
    let oldest: Option<i64> =
        conn.query_row("SELECT MIN(id) FROM security_events", [], |r| r.get(0))?;
    Ok(match oldest {
        Some(oldest_id) if head_id < oldest_id => CheckpointCheck::OlderThanRetention { oldest_id },
        _ => CheckpointCheck::EventMissing,
    })
}

/// Genesis value of the event hash chain.
pub const CHAIN_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SETTINGS_KEY: &str = "app_settings";
const CHAIN_ANCHOR_KEY: &str = "event_chain_anchor";
/// Settings key of the persisted Event Log mirror cursor (last event id
/// delivered to the observer).
const MIRROR_CURSOR_KEY: &str = "event_log_mirror_cursor";
/// At most this many not-yet-mirrored events are delivered after a restart
/// or an outage; older ones are skipped and the gap is recorded.
pub const MIRROR_MAX_BACKFILL: i64 = 1000;
/// Events delivered per mirror pass.
const MIRROR_BATCH: i64 = 500;
/// Maximum message length stored for an event.
pub const MAX_MESSAGE_LEN: usize = 1000;

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// SQLite error.
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// JSON error.
    #[error("data encoding error: {0}")]
    Json(#[from] serde_json::Error),
    /// Database created by a newer RustWard.
    #[error("database schema {found} is newer than supported {supported}")]
    SchemaTooNew {
        /// Found.
        found: u32,
        /// Supported.
        supported: u32,
    },
    /// Stored policy failed its checksum or validation.
    #[error("stored policy version {version} is corrupt: {detail}")]
    CorruptPolicy {
        /// Version.
        version: u64,
        /// Detail.
        detail: String,
    },
    /// Input rejected.
    #[error("invalid data: {0}")]
    Invalid(String),
    /// `PRAGMA integrity_check` failed.
    #[error("database integrity check failed: {0}")]
    Integrity(String),
    /// Policy version conflict (stale edit).
    #[error("policy version conflict: expected {expected}, active is {active}")]
    VersionConflict {
        /// Version the edit was based on.
        expected: u64,
        /// Active version.
        active: u64,
    },
    /// A backup was rejected for restore.
    #[error("backup rejected: {0}")]
    BackupRejected(BackupRejection),
    /// File-system error (backups).
    #[error("file error: {0}")]
    Io(String),
}

/// Time source (injectable for tests).
pub trait Clock: Send + Sync {
    /// UTC milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
}

/// Wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }
}

/// Manually advanced clock for tests and deterministic simulations.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// Start at `ms`.
    #[must_use]
    pub fn new(ms: i64) -> Self {
        Self(AtomicI64::new(ms))
    }
    /// Advance by `ms`.
    pub fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// SHA-256 hex digest.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Correlation key for a device: first 32 hex chars of SHA-256 of the
/// upper-cased instance ID. The instance ID itself is not stored.
#[must_use]
pub fn device_key(instance_id: &str) -> String {
    sha256_hex(instance_id.to_ascii_uppercase().as_bytes())[..32].to_owned()
}

/// Mask the unique tail of an instance ID, keeping the last 4 characters:
/// `USBSTOR\Disk&Ven_SanDisk\4C530001230615110223&0` →
/// `USBSTOR\Disk&Ven_SanDisk\****0223&0` (the `&N` LUN suffix is kept).
#[must_use]
pub fn mask_instance_id(instance_id: &str) -> String {
    let Some(i) = instance_id.rfind('\\') else {
        return "****".into();
    };
    let (head, tail) = (&instance_id[..i], &instance_id[i + 1..]);
    let (body, lun) = match tail.rfind('&') {
        Some(j) if tail[j + 1..].chars().all(|c| c.is_ascii_digit()) && j + 1 < tail.len() => {
            (&tail[..j], &tail[j..])
        }
        _ => (tail, ""),
    };
    let keep: String = body
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let masked = if body.chars().count() > 4 {
        format!("****{keep}")
    } else {
        "****".into()
    };
    format!("{head}\\{masked}{lun}")
}

fn event_hash(prev: &str, utc_ms: i64, e: &NewEvent) -> Result<String, StorageError> {
    let details = serde_json::to_string(&e.details)?;
    let canonical = [
        prev.to_owned(),
        utc_ms.to_string(),
        e.severity.as_str().to_owned(),
        e.kind.clone(),
        e.device_key.clone().unwrap_or_default(),
        e.message.clone(),
        u8::from(e.simulated).to_string(),
        e.enforcement_state.clone(),
        e.policy_version.map(|v| v.to_string()).unwrap_or_default(),
        details,
    ]
    .join("\u{1f}");
    Ok(sha256_hex(canonical.as_bytes()))
}

fn to_i64(v: u64) -> Result<i64, StorageError> {
    i64::try_from(v).map_err(|_| StorageError::Invalid("value out of range".into()))
}

/// A stored policy version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicy {
    /// Policy version.
    pub version: u64,
    /// State.
    pub state: PolicyState,
    /// When it was stored.
    pub created_ms: i64,
}

/// Receives every security event after it has been committed to the
/// database (e.g. to mirror it into the Windows Event Log). Failures never
/// roll back or block the database write; they are counted.
pub trait EventObserver: Send + Sync {
    /// Called once per committed event, in id order.
    fn on_event(&self, event: &SecurityEvent) -> Result<(), String>;
}

/// Mirror status for diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MirrorStatus {
    /// An observer is attached.
    pub attached: bool,
    /// Events delivered successfully.
    pub delivered: u64,
    /// Delivery attempts the observer rejected.
    pub failures: u64,
    /// Last event id delivered (persisted across restarts).
    pub cursor: i64,
    /// Events committed but not yet delivered.
    pub pending: u64,
    /// Events skipped because more than [`MIRROR_MAX_BACKFILL`] were pending.
    pub skipped: u64,
}

/// The RustWard database.
pub struct Store {
    conn: Connection,
    clock: Arc<dyn Clock>,
    observer: Option<Arc<dyn EventObserver>>,
    last_mirrored_id: i64,
    mirror: MirrorStatus,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

/// Switch a file database to WAL.
///
/// Changing the journal mode needs an exclusive lock, and SQLite reports
/// `SQLITE_BUSY` for it **without** calling the busy handler when another
/// connection is opening the same new file at that moment (F-19 follow-up,
/// Phase 10). Retry for a bounded time (about the busy timeout), then fail.
fn enable_wal(conn: &Connection) -> Result<(), StorageError> {
    const ATTEMPTS: u32 = 100;
    const PAUSE: std::time::Duration = std::time::Duration::from_millis(50);
    let mut attempt = 0;
    loop {
        match conn.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => return Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseBusy && attempt < ATTEMPTS =>
            {
                attempt += 1;
                std::thread::sleep(PAUSE);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

impl Store {
    /// Open (or create) a database file and apply migrations.
    pub fn open(path: &Path, clock: Arc<dyn Clock>) -> Result<Self, StorageError> {
        Self::init(Connection::open(path)?, clock, true)
    }

    /// In-memory database (tests, dry runs).
    pub fn open_in_memory(clock: Arc<dyn Clock>) -> Result<Self, StorageError> {
        Self::init(Connection::open_in_memory()?, clock, false)
    }

    fn init(mut conn: Connection, clock: Arc<dyn Clock>, file: bool) -> Result<Self, StorageError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // FULL sync: survive abrupt power loss without losing committed edits.
        conn.pragma_update(None, "synchronous", "FULL")?;
        if file {
            enable_wal(&conn)?;
        }
        migrations::migrate(&mut conn, clock.now_ms())?;
        let mut store = Self {
            conn,
            clock,
            observer: None,
            last_mirrored_id: 0,
            mirror: MirrorStatus::default(),
        };
        store.last_mirrored_id = store.mirror_cursor()?.unwrap_or(0);
        Ok(store)
    }

    fn max_event_id(&self) -> Result<i64, StorageError> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(id), 0) FROM security_events",
            [],
            |r| r.get(0),
        )?)
    }

    fn mirror_cursor(&self) -> Result<Option<i64>, StorageError> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![MIRROR_CURSOR_KEY],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v.and_then(|v| v.parse().ok()))
    }

    fn save_mirror_cursor(&self, id: i64) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO settings (key, value, updated_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ms = excluded.updated_ms",
            params![MIRROR_CURSOR_KEY, id.to_string(), self.clock.now_ms()],
        )?;
        Ok(())
    }

    /// If more than [`MIRROR_MAX_BACKFILL`] events are pending, move the
    /// cursor forward and record the skipped range as an event (which is
    /// itself mirrored), so the gap is visible in the Event Log.
    fn bound_mirror_backlog(&mut self) -> Result<(), StorageError> {
        let max = self.max_event_id()?;
        if max - self.last_mirrored_id <= MIRROR_MAX_BACKFILL {
            return Ok(());
        }
        let first_skipped = self.last_mirrored_id + 1;
        let last_skipped = max - MIRROR_MAX_BACKFILL;
        let skipped = u64::try_from(last_skipped - first_skipped + 1).unwrap_or(0);
        self.last_mirrored_id = last_skipped;
        self.mirror.skipped = self.mirror.skipped.saturating_add(skipped);
        self.save_mirror_cursor(last_skipped)?;
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Warning,
                kind: "event_log_backfill_skipped".into(),
                device_key: None,
                message: format!(
                    "{skipped} audit events (ids {first_skipped}..={last_skipped}) were not copied to the Windows Event Log; they remain in the RustWard database"
                ),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::json!({
                    "first_skipped_id": first_skipped,
                    "last_skipped_id": last_skipped,
                    "skipped": skipped,
                }),
            },
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Attach an observer. Delivery resumes after the persisted cursor, so
    /// events written before the observer was attached (start-up) or while
    /// it was failing (Event Log outage) are delivered now, at most the
    /// newest [`MIRROR_MAX_BACKFILL`]; a skipped older range is recorded as
    /// an `event_log_backfill_skipped` event. Delivery is at-least-once: an
    /// event may be delivered twice if the process stops between delivery
    /// and saving the cursor (the audit id in the message identifies it).
    pub fn set_event_observer(
        &mut self,
        observer: Arc<dyn EventObserver>,
    ) -> Result<(), StorageError> {
        self.last_mirrored_id = self.mirror_cursor()?.unwrap_or(0);
        self.bound_mirror_backlog()?;
        self.observer = Some(observer);
        self.mirror.attached = true;
        self.mirror_new_events();
        Ok(())
    }

    /// Mirror counters.
    #[must_use]
    pub fn mirror_status(&self) -> MirrorStatus {
        let mut m = self.mirror;
        m.cursor = self.last_mirrored_id;
        m.pending = self.max_event_id().map_or(0, |max| {
            u64::try_from(max - self.last_mirrored_id).unwrap_or(0)
        });
        m
    }

    /// Retry delivery of pending events (e.g. after an Event Log outage).
    /// Called periodically by the service; never fails.
    pub fn retry_mirror(&mut self) {
        if self.observer.is_some() {
            if self.bound_mirror_backlog().is_err() {
                self.mirror.failures = self.mirror.failures.saturating_add(1);
            }
            self.mirror_new_events();
        }
    }

    /// Deliver events committed since the last delivery, in id order. Stops
    /// at the first rejected event so order is kept and nothing is lost; the
    /// next commit or [`Self::retry_mirror`] tries again. Never fails the
    /// write that triggered it.
    fn mirror_new_events(&mut self) {
        let Some(observer) = self.observer.clone() else {
            return;
        };
        let start = self.last_mirrored_id;
        // The backlog is bounded by `bound_mirror_backlog`, so this loop ends
        // after at most a few batches.
        'batches: loop {
            let Ok(events) = self.events_after(self.last_mirrored_id, MIRROR_BATCH) else {
                self.mirror.failures = self.mirror.failures.saturating_add(1);
                break;
            };
            if events.is_empty() {
                break;
            }
            for e in events {
                match observer.on_event(&e) {
                    Ok(()) => {
                        self.last_mirrored_id = e.id;
                        self.mirror.delivered = self.mirror.delivered.saturating_add(1);
                    }
                    Err(_) => {
                        self.mirror.failures = self.mirror.failures.saturating_add(1);
                        break 'batches;
                    }
                }
            }
        }
        if self.last_mirrored_id != start && self.save_mirror_cursor(self.last_mirrored_id).is_err()
        {
            self.mirror.failures = self.mirror.failures.saturating_add(1);
        }
    }

    fn events_after(&self, id: i64, limit: i64) -> Result<Vec<SecurityEvent>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, utc_ms, severity, kind, device_key, message, simulated, enforcement_state,
                    policy_version, details_json, prev_hash, hash FROM security_events
             WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![id, limit], event_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Current schema version.
    pub fn schema_version(&self) -> Result<u32, StorageError> {
        migrations::current_version(&self.conn)
    }

    /// `PRAGMA integrity_check`; `Ok(())` when the result is `ok`.
    pub fn integrity_check(&self) -> Result<(), StorageError> {
        let mut stmt = self.conn.prepare("PRAGMA integrity_check")?;
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        if rows.len() == 1 && rows[0] == "ok" {
            Ok(())
        } else {
            Err(StorageError::Integrity(rows.join("; ")))
        }
    }

    // ----------------------------------------------------------------- settings

    /// Settings (defaults when never saved).
    pub fn settings(&self) -> Result<AppSettings, StorageError> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![SETTINGS_KEY],
                |r| r.get(0),
            )
            .optional()?;
        match v {
            Some(json) => {
                let s: AppSettings = serde_json::from_str(&json)?;
                s.validate().map_err(StorageError::Invalid)?;
                Ok(s)
            }
            None => Ok(AppSettings::default()),
        }
    }

    /// Validate and save settings, with an audit event.
    pub fn save_settings(
        &mut self,
        settings: &AppSettings,
        actor: &str,
    ) -> Result<(), StorageError> {
        settings.validate().map_err(StorageError::Invalid)?;
        let now = self.clock.now_ms();
        let json = serde_json::to_string(settings)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO settings (key, value, updated_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ms = excluded.updated_ms",
            params![SETTINGS_KEY, json, now],
        )?;
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Info,
                kind: "settings_changed".into(),
                device_key: None,
                message: format!("settings changed by {actor}"),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::to_value(settings)?,
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(())
    }

    // ------------------------------------------------------------------- policy

    /// The active policy, verified against its checksum and re-validated.
    pub fn active_policy(&self) -> Result<Option<StoredPolicy>, StorageError> {
        let row: Option<(i64, String, String, i64)> = self
            .conn
            .query_row(
                "SELECT version, state_json, sha256, created_ms FROM policy_states WHERE active = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((version, json, sha, created_ms)) = row else {
            return Ok(None);
        };
        let version = u64::try_from(version).unwrap_or(0);
        if sha256_hex(json.as_bytes()) != sha {
            return Err(StorageError::CorruptPolicy {
                version,
                detail: "checksum mismatch".into(),
            });
        }
        let state: PolicyState =
            serde_json::from_str(&json).map_err(|e| StorageError::CorruptPolicy {
                version,
                detail: e.to_string(),
            })?;
        state.validate().map_err(|e| StorageError::CorruptPolicy {
            version,
            detail: e.to_string(),
        })?;
        if state.policy.policy_version != version {
            return Err(StorageError::CorruptPolicy {
                version,
                detail: "embedded policy_version differs from row".into(),
            });
        }
        Ok(Some(StoredPolicy {
            version,
            state,
            created_ms,
        }))
    }

    fn insert_state_tx(
        tx: &rusqlite::Transaction<'_>,
        state: &PolicyState,
        now: i64,
    ) -> Result<(), StorageError> {
        let json = serde_json::to_string(state)?;
        tx.execute("UPDATE policy_states SET active = 0 WHERE active = 1", [])?;
        tx.execute(
            "INSERT INTO policy_states (version, catalog_version, state_json, sha256, created_ms, active)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![
                to_i64(state.policy.policy_version)?,
                state.catalog.catalog_version,
                json,
                sha256_hex(json.as_bytes()),
                now
            ],
        )?;
        Ok(())
    }

    /// Store `state` as the first policy if none exists. Returns true if stored.
    pub fn initialize_policy(
        &mut self,
        state: &PolicyState,
        actor: &str,
    ) -> Result<bool, StorageError> {
        state
            .validate()
            .map_err(|e| StorageError::Invalid(e.to_string()))?;
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: i64 = tx.query_row("SELECT COUNT(*) FROM policy_states", [], |r| r.get(0))?;
        if existing > 0 {
            return Ok(false);
        }
        Self::insert_state_tx(&tx, state, now)?;
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Info,
                kind: "policy_initialized".into(),
                device_key: None,
                message: format!(
                    "policy v{} initialized for {} by {actor}",
                    state.policy.policy_version, state.policy.workstation_id
                ),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: Some(state.policy.policy_version),
                details: serde_json::json!({ "catalog_version": state.catalog.catalog_version }),
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(true)
    }

    /// Syncs the manufacturer catalog if the active policy uses an older catalog version.
    /// Preserves all existing allowlist and denylist configuration, bumps policy_version,
    /// and logs a catalog_upgraded audit event.
    pub fn sync_catalog_if_outdated(
        &mut self,
        latest_state: &PolicyState,
        actor: &str,
    ) -> Result<bool, StorageError> {
        let active = match self.active_policy() {
            Ok(Some(a)) => a,
            Ok(None) | Err(StorageError::CorruptPolicy { .. }) => return Ok(false),
            Err(e) => return Err(e),
        };
        if active.state.catalog.catalog_version >= latest_state.catalog.catalog_version {
            return Ok(false);
        }

        let now = self.clock.now_ms();
        let mut new_policy = active.state.policy.clone();
        new_policy.policy_version = new_policy.policy_version.saturating_add(1);
        new_policy.catalog_version = latest_state.catalog.catalog_version.clone();

        // Preserve any custom brands the administrator may have added
        let mut merged_brands = latest_state.catalog.brands.clone();
        for custom_brand in &active.state.catalog.brands {
            if !merged_brands.iter().any(|b| b.id == custom_brand.id) {
                merged_brands.push(custom_brand.clone());
            }
        }

        let mut merged_catalog = latest_state.catalog.clone();
        merged_catalog.brands = merged_brands;

        let new_state = PolicyState {
            catalog: merged_catalog,
            policy: new_policy,
        };
        new_state
            .validate()
            .map_err(|e| StorageError::Invalid(e.to_string()))?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::insert_state_tx(&tx, &new_state, now)?;
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Info,
                kind: "catalog_upgraded".into(),
                device_key: None,
                message: format!(
                    "Manufacturer catalog upgraded from {} to {} ({} brands available) by {actor}",
                    active.state.catalog.catalog_version,
                    new_state.catalog.catalog_version,
                    new_state.catalog.brands.len()
                ),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: Some(new_state.policy.policy_version),
                details: serde_json::json!({
                    "from_catalog_version": active.state.catalog.catalog_version,
                    "to_catalog_version": new_state.catalog.catalog_version,
                    "brand_count": new_state.catalog.brands.len(),
                }),
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(true)
    }

    /// Persist an applied edit atomically: new active state, change record
    /// and audit event. Fails with [`StorageError::VersionConflict`] if the
    /// active version is not the one the edit was based on.
    pub fn commit_policy_edit(
        &mut self,
        outcome: &EditOutcome,
        actor: &str,
    ) -> Result<(), StorageError> {
        let now = self.clock.now_ms();
        let change: &ChangeRecord = &outcome.change;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: Option<i64> = tx
            .query_row(
                "SELECT version FROM policy_states WHERE active = 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let active = active.and_then(|v| u64::try_from(v).ok()).unwrap_or(0);
        if active != change.from_policy_version {
            return Err(StorageError::VersionConflict {
                expected: change.from_policy_version,
                active,
            });
        }
        Self::insert_state_tx(&tx, &outcome.state, now)?;
        tx.execute(
            "INSERT INTO policy_changes (utc_ms, actor, action, brand_id, summary, from_version, to_version, change_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                now,
                actor,
                change.action,
                change.brand_id,
                change.summary,
                to_i64(change.from_policy_version)?,
                to_i64(change.to_policy_version)?,
                serde_json::to_string(change)?
            ],
        )?;
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Warning,
                kind: "policy_changed".into(),
                device_key: None,
                message: format!("{} (by {actor})", change.summary),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: Some(change.to_policy_version),
                details: serde_json::to_value(change)?,
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(())
    }

    /// Most recent policy changes first.
    pub fn policy_changes(&self, limit: u32) -> Result<Vec<PolicyChangeRow>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, utc_ms, actor, action, brand_id, summary, from_version, to_version, change_json
             FROM policy_changes ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.min(5000)], |r| {
            let json: String = r.get(8)?;
            Ok(PolicyChangeRow {
                id: r.get(0)?,
                utc_ms: r.get(1)?,
                actor: r.get(2)?,
                action: r.get(3)?,
                brand_id: r.get(4)?,
                summary: r.get(5)?,
                from_version: u64::try_from(r.get::<_, i64>(6)?).unwrap_or(0),
                to_version: u64::try_from(r.get::<_, i64>(7)?).unwrap_or(0),
                change: serde_json::from_str(&json).unwrap_or(serde_json::Value::Null),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ------------------------------------------------------------------ devices

    /// Insert or update a device row (keeps `first_seen_ms`).
    pub fn upsert_device(&mut self, d: &DeviceRow) -> Result<(), StorageError> {
        upsert_device_on(&self.conn, d)
    }

    /// Insert or update many device rows in ONE transaction (one fsync per
    /// inventory refresh instead of one per device).
    pub fn upsert_devices(&mut self, rows: &[DeviceRow]) -> Result<(), StorageError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for d in rows {
            upsert_device_on(&tx, d)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Mark every present device not in `present_keys` as absent.
    /// Returns the number of rows changed.
    pub fn mark_absent_except(&mut self, present_keys: &[String]) -> Result<usize, StorageError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS keep_keys (k TEXT PRIMARY KEY); DELETE FROM keep_keys;")?;
        for k in present_keys {
            tx.execute(
                "INSERT OR IGNORE INTO keep_keys (k) VALUES (?1)",
                params![k],
            )?;
        }
        let n = tx.execute(
            "UPDATE devices SET present = 0 WHERE present = 1 AND device_key NOT IN (SELECT k FROM keep_keys)",
            [],
        )?;
        tx.execute_batch("DELETE FROM keep_keys;")?;
        tx.commit()?;
        Ok(n)
    }

    /// Devices, most recently seen first.
    pub fn list_devices(&self, present_only: bool) -> Result<Vec<DeviceRow>, StorageError> {
        let sql = format!(
            "SELECT device_key, display_id, category, transport, vendor, product, usb_vid_pid, vendor_level_id,
                    friendly_name, matched_brand, first_seen_ms, last_seen_ms, present, synthetic, last_verdict,
                    last_reason, last_policy_version, enforcement_state
             FROM devices {} ORDER BY last_seen_ms DESC, device_key",
            if present_only { "WHERE present = 1" } else { "" }
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok(DeviceRow {
                device_key: r.get(0)?,
                display_id: r.get(1)?,
                category: r.get(2)?,
                transport: r.get(3)?,
                vendor: r.get(4)?,
                product: r.get(5)?,
                usb_vid_pid: r.get(6)?,
                vendor_level_id: r.get(7)?,
                friendly_name: r.get(8)?,
                matched_brand: r.get(9)?,
                first_seen_ms: r.get(10)?,
                last_seen_ms: r.get(11)?,
                present: r.get(12)?,
                synthetic: r.get(13)?,
                last_verdict: r.get(14)?,
                last_reason: r.get(15)?,
                last_policy_version: u64::try_from(r.get::<_, i64>(16)?).unwrap_or(0),
                enforcement_state: r.get(17)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ------------------------------------------------------------------- events

    fn last_hash(conn: &Connection) -> Result<String, StorageError> {
        let last: Option<String> = conn
            .query_row(
                "SELECT hash FROM security_events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(h) = last {
            return Ok(h);
        }
        let anchor: Option<String> = conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![CHAIN_ANCHOR_KEY],
                |r| r.get(0),
            )
            .optional()?;
        Ok(anchor.unwrap_or_else(|| CHAIN_GENESIS.to_owned()))
    }

    fn append_event_tx(conn: &Connection, now: i64, e: &NewEvent) -> Result<i64, StorageError> {
        if e.kind.is_empty()
            || e.kind.len() > 64
            || !e.kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        {
            return Err(StorageError::Invalid(format!(
                "invalid event kind {:?}",
                e.kind
            )));
        }
        if e.message.chars().count() > MAX_MESSAGE_LEN {
            return Err(StorageError::Invalid("event message too long".into()));
        }
        if !e.details.is_object() {
            return Err(StorageError::Invalid(
                "event details must be a JSON object".into(),
            ));
        }
        let prev = Self::last_hash(conn)?;
        let hash = event_hash(&prev, now, e)?;
        let meta = EventMetadata::from_details(&e.details);
        let pnp_problem_code = meta.pnp_problem_code.map(i64::from);
        conn.execute(
            "INSERT INTO security_events (
                 utc_ms, severity, kind, device_key, message, simulated,
                 enforcement_state, policy_version, details_json, prev_hash, hash,
                 computer_name, manufacturer_id, device_name, vid_pid, transport,
                 pnp_problem_code, effective_decision, enforcement_outcome,
                 actor_username, windows_user, policy_revision
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
            params![
                now,
                e.severity.as_str(),
                e.kind,
                e.device_key,
                e.message,
                e.simulated,
                e.enforcement_state,
                e.policy_version.map(to_i64).transpose()?,
                serde_json::to_string(&e.details)?,
                prev,
                hash,
                meta.computer_name,
                meta.manufacturer_id,
                meta.device_name,
                meta.vid_pid,
                meta.transport,
                pnp_problem_code,
                meta.effective_decision,
                meta.enforcement_outcome,
                meta.actor_username,
                meta.windows_user,
                meta.policy_revision
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Append a security event to the hash chain.
    pub fn append_event(&mut self, e: &NewEvent) -> Result<i64, StorageError> {
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = Self::append_event_tx(&tx, now, e)?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(id)
    }

    fn build_event_where(f: &EventFilter) -> (String, Vec<rusqlite::types::Value>) {
        let mut where_sql = String::from(" WHERE 1 = 1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(t) = f.text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            where_sql.push_str(
                " AND (instr(lower(message), lower(?)) > 0
                  OR instr(lower(kind), lower(?)) > 0
                  OR instr(lower(COALESCE(device_key, '')), lower(?)) > 0
                  OR instr(lower(COALESCE(manufacturer_id, '')), lower(?)) > 0
                  OR instr(lower(COALESCE(device_name, '')), lower(?)) > 0
                  OR instr(lower(COALESCE(vid_pid, '')), lower(?)) > 0
                  OR instr(lower(COALESCE(actor_username, '')), lower(?)) > 0
                  OR instr(lower(COALESCE(windows_user, '')), lower(?)) > 0
                  OR instr(lower(details_json), lower(?)) > 0)",
            );
            for _ in 0..9 {
                args.push(t.to_owned().into());
            }
        }
        if let Some(s) = f.min_severity {
            let allowed: Vec<&str> = [Severity::Info, Severity::Warning, Severity::Critical]
                .into_iter()
                .filter(|x| *x >= s)
                .map(Severity::as_str)
                .collect();
            where_sql.push_str(&format!(
                " AND severity IN ({})",
                vec!["?"; allowed.len()].join(",")
            ));
            args.extend(allowed.into_iter().map(|a| a.to_owned().into()));
        }
        if let Some(k) = f.kind.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            where_sql.push_str(" AND kind = ?");
            args.push(k.to_owned().into());
        }
        if let Some(d) = f.device_key.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            where_sql.push_str(" AND device_key = ?");
            args.push(d.to_owned().into());
        }
        if let Some(s) = f.since_ms {
            where_sql.push_str(" AND utc_ms >= ?");
            args.push(s.into());
        }
        if let Some(u) = f.until_ms {
            where_sql.push_str(" AND utc_ms < ?");
            args.push(u.into());
        }
        if let Some(sim) = f.simulated {
            where_sql.push_str(" AND simulated = ?");
            args.push(i64::from(sim).into());
        }
        if let Some(mfg) = f.manufacturer_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            where_sql.push_str(
                " AND (lower(COALESCE(manufacturer_id, '')) = lower(?)
                  OR instr(lower(details_json), lower(?)) > 0)",
            );
            args.push(mfg.to_owned().into());
            args.push(mfg.to_owned().into());
        }
        if let Some(dev) = f.device_query.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            where_sql.push_str(
                " AND (instr(lower(COALESCE(device_key, '')), lower(?)) > 0
                  OR instr(lower(COALESCE(device_name, '')), lower(?)) > 0
                  OR instr(lower(COALESCE(vid_pid, '')), lower(?)) > 0
                  OR instr(lower(details_json), lower(?)) > 0)",
            );
            for _ in 0..4 {
                args.push(dev.to_owned().into());
            }
        }
        if let Some(win) = f.windows_user.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            where_sql.push_str(
                " AND (instr(lower(COALESCE(windows_user, '')), lower(?)) > 0
                  OR instr(lower(details_json), lower(?)) > 0)",
            );
            args.push(win.to_owned().into());
            args.push(win.to_owned().into());
        }
        if let Some(dec) = f.effective_decision.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            where_sql.push_str(
                " AND (lower(COALESCE(effective_decision, '')) = lower(?)
                  OR instr(lower(details_json), lower(?)) > 0)",
            );
            args.push(dec.to_owned().into());
            args.push(dec.to_owned().into());
        }
        if let Some(actor) = f.actor_username.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            where_sql.push_str(
                " AND (instr(lower(COALESCE(actor_username, '')), lower(?)) > 0
                  OR instr(lower(details_json), lower(?)) > 0)",
            );
            args.push(actor.to_owned().into());
            args.push(actor.to_owned().into());
        }
        (where_sql, args)
    }

    /// Count events matching `f` without pagination limit/offset.
    pub fn count_events(&self, f: &EventFilter) -> Result<u64, StorageError> {
        let (where_sql, args) = Self::build_event_where(f);
        let sql = format!("SELECT COUNT(*) FROM security_events{where_sql}");
        let count: i64 = self
            .conn
            .query_row(&sql, params_from_iter(args.iter()), |r| r.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Query events, newest first.
    pub fn list_events(&self, f: &EventFilter) -> Result<Vec<SecurityEvent>, StorageError> {
        let (where_sql, mut args) = Self::build_event_where(f);
        let sql = format!(
            "SELECT id, utc_ms, severity, kind, device_key, message, simulated, enforcement_state,
                    policy_version, details_json, prev_hash, hash
             FROM security_events{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
        );
        args.push(i64::from(f.limit.unwrap_or(200).min(5000)).into());
        args.push(i64::from(f.offset.unwrap_or(0)).into());

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), event_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Verify the event hash chain from the anchor to the newest entry.
    pub fn verify_chain(&self) -> Result<ChainStatus, StorageError> {
        let anchor: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![CHAIN_ANCHOR_KEY],
                |r| r.get(0),
            )
            .optional()?;
        let mut prev = anchor.unwrap_or_else(|| CHAIN_GENESIS.to_owned());
        let mut stmt = self.conn.prepare(
            "SELECT id, utc_ms, severity, kind, device_key, message, simulated, enforcement_state,
                    policy_version, details_json, prev_hash, hash FROM security_events ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut n = 0u64;
        let mut last_id = 0i64;
        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let sev: String = r.get(2)?;
            let details: String = r.get(9)?;
            let stored_prev: String = r.get(10)?;
            let stored_hash: String = r.get(11)?;
            let Some(severity) = Severity::parse(&sev) else {
                return Ok(ChainStatus::Broken { first_bad_id: id });
            };
            let Ok(details) = serde_json::from_str::<serde_json::Value>(&details) else {
                return Ok(ChainStatus::Broken { first_bad_id: id });
            };
            let e = NewEvent {
                severity,
                kind: r.get(3)?,
                device_key: r.get(4)?,
                message: r.get(5)?,
                simulated: r.get(6)?,
                enforcement_state: r.get(7)?,
                policy_version: r
                    .get::<_, Option<i64>>(8)?
                    .and_then(|v| u64::try_from(v).ok()),
                details,
            };
            if last_id != 0 && id != last_id + 1 {
                return Ok(ChainStatus::Missing {
                    entries: n,
                    after_id: last_id,
                    next_id: id,
                });
            }
            let expected = event_hash(&prev, r.get(1)?, &e)?;
            if stored_prev != prev || stored_hash != expected {
                return Ok(ChainStatus::Broken { first_bad_id: id });
            }
            prev = stored_hash;
            n += 1;
            last_id = id;
        }
        let highest_issued = self.highest_issued_event_id()?;
        if highest_issued > last_id {
            return Ok(ChainStatus::Truncated {
                entries: n,
                last_id,
                highest_issued,
            });
        }
        Ok(ChainStatus::Intact { entries: n })
    }

    /// Highest event id SQLite has ever issued (`sqlite_sequence`); larger
    /// than the newest remaining id only if newest events were deleted.
    fn highest_issued_event_id(&self) -> Result<i64, StorageError> {
        let seq: Option<i64> = self
            .conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'security_events'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(seq.unwrap_or(0))
    }

    /// Compare the database with a checkpoint taken from outside it
    /// (`head #<id> <hash prefix>` in an `audit_checkpoint` Event Log entry).
    ///
    /// # Errors
    /// A prefix shorter than 16 or containing non-hex characters, or a
    /// database error.
    pub fn check_checkpoint(
        &self,
        head_id: i64,
        hash_prefix: &str,
    ) -> Result<CheckpointCheck, StorageError> {
        check_checkpoint_conn(&self.conn, head_id, hash_prefix)
    }

    /// Record an `audit_checkpoint` event describing the chain head (newest
    /// event before the checkpoint, its hash, the number of verified entries
    /// and the highest issued id). The event is part of the chain and is
    /// mirrored to the Windows Event Log; comparing a later database with
    /// these out-of-database copies reveals truncation or rewriting that the
    /// chain alone cannot (AUDIT-INTEGRITY.md §6). Severity is `warning` when
    /// the chain is not intact.
    pub fn record_audit_checkpoint(&mut self) -> Result<AuditCheckpoint, StorageError> {
        let status = self.verify_chain()?;
        let (chain, entries, severity) = match &status {
            ChainStatus::Intact { entries } => ("intact", *entries, Severity::Info),
            ChainStatus::Broken { .. } => ("broken", 0, Severity::Warning),
            ChainStatus::Missing { entries, .. } => ("missing", *entries, Severity::Warning),
            ChainStatus::Truncated { entries, .. } => ("truncated", *entries, Severity::Warning),
        };
        let head: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT id, hash FROM security_events ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (head_id, head_hash) = match head {
            Some(h) => h,
            None => (0, Self::last_hash(&self.conn)?),
        };
        let highest_issued = self.highest_issued_event_id()?;
        let short: String = head_hash.chars().take(16).collect();
        let checkpoint_id = self.append_event(&NewEvent {
            severity,
            kind: "audit_checkpoint".into(),
            device_key: None,
            message: format!(
                "audit checkpoint: chain {chain}, {entries} entries, head #{head_id} {short}…, highest issued id {highest_issued}"
            ),
            simulated: false,
            enforcement_state: "n/a".into(),
            policy_version: None,
            details: serde_json::json!({
                "head_id": head_id,
                "head_hash": head_hash,
                "entries": entries,
                "highest_issued": highest_issued,
                "chain": chain,
            }),
        })?;
        Ok(AuditCheckpoint {
            head_id,
            head_hash,
            entries,
            highest_issued,
            chain: chain.into(),
            checkpoint_id,
        })
    }

    /// Delete events older than the configured retention, moving the chain
    /// anchor forward so the remaining chain still verifies. Returns the
    /// number of deleted events. The purge itself is recorded as an event.
    pub fn apply_retention(&mut self) -> Result<usize, StorageError> {
        let days = self.settings()?.audit_retention_days;
        let now = self.clock.now_ms();
        let cutoff = now - i64::from(days) * 86_400_000;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last_purged: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, hash FROM security_events WHERE utc_ms < ?1 ORDER BY id DESC LIMIT 1",
                params![cutoff],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((last_id, anchor)) = last_purged else {
            return Ok(0);
        };
        tx.execute(
            "INSERT INTO retention_guard (cutoff_id) VALUES (?1)",
            params![last_id],
        )?;
        let n = tx.execute(
            "DELETE FROM security_events WHERE id <= ?1",
            params![last_id],
        )?;
        tx.execute("DELETE FROM retention_guard", [])?;
        tx.execute(
            "INSERT INTO settings (key, value, updated_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ms = excluded.updated_ms",
            params![CHAIN_ANCHOR_KEY, anchor, now],
        )?;
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Info,
                kind: "retention_applied".into(),
                device_key: None,
                message: format!("{n} events older than {days} days removed"),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::json!({ "deleted": n, "retention_days": days }),
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(n)
    }

    // ----------------------------------------------------------- backup/restore

    /// Write a consistent copy of the database to `path` (must not exist).
    /// Low-level: the copy is NOT registered and therefore cannot be
    /// restored through RustWard. Use [`Self::create_backup`].
    pub fn backup_to(&self, path: &Path) -> Result<(), StorageError> {
        if path.exists() {
            return Err(StorageError::Invalid(format!(
                "backup target {} already exists",
                path.display()
            )));
        }
        self.conn.backup(
            rusqlite::MAIN_DB,
            path,
            None::<fn(rusqlite::backup::Progress)>,
        )?;
        Ok(())
    }

    /// Create, hash and register a backup in `dir`. The file name is
    /// `<prefix><ms>.db`, never reused; an existing file is never
    /// overwritten. The registry row and the `backup_created` audit event are
    /// written in one transaction; if that fails the file is removed again.
    pub fn create_backup(
        &mut self,
        dir: &Path,
        kind: BackupKind,
        actor: &str,
    ) -> Result<BackupRecord, StorageError> {
        std::fs::create_dir_all(dir).map_err(|e| StorageError::Io(e.to_string()))?;
        let policy_version = self.active_policy()?.map_or(0, |p| p.version);
        let now = self.clock.now_ms();
        let mut chosen = None;
        for i in 0..1000i64 {
            let name = format!("{}{}.db", kind.file_prefix(), now.saturating_add(i));
            let registered: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM backups WHERE file_name = ?1",
                params![name],
                |r| r.get(0),
            )?;
            if registered == 0 && !dir.join(&name).exists() {
                chosen = Some(name);
                break;
            }
        }
        let name = chosen.ok_or_else(|| StorageError::Io("no free backup file name".into()))?;
        let path = dir.join(&name);
        self.backup_to(&path)?;
        let result = (|| {
            let bytes = std::fs::read(&path).map_err(|e| StorageError::Io(e.to_string()))?;
            let record = BackupRecord {
                file_name: name.clone(),
                sha256: sha256_hex(&bytes),
                bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                created_ms: now,
                policy_version,
                kind,
                actor: actor.to_owned(),
            };
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO backups (file_name, sha256, bytes, created_ms, policy_version, kind, actor)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.file_name,
                    record.sha256,
                    to_i64(record.bytes)?,
                    record.created_ms,
                    to_i64(record.policy_version)?,
                    kind.as_str(),
                    record.actor
                ],
            )?;
            Self::append_event_tx(
                &tx,
                now,
                &NewEvent {
                    severity: Severity::Info,
                    kind: "backup_created".into(),
                    device_key: None,
                    message: format!("{} backup {name} created by {actor}", kind.as_str()),
                    simulated: false,
                    enforcement_state: "n/a".into(),
                    policy_version: Some(policy_version),
                    details: serde_json::json!({
                        "file_name": record.file_name,
                        "sha256": record.sha256,
                        "bytes": record.bytes,
                        "kind": kind.as_str(),
                    }),
                },
            )?;
            tx.commit()?;
            Ok(record)
        })();
        match result {
            Ok(record) => {
                self.mirror_new_events();
                Ok(record)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                Err(e)
            }
        }
    }

    /// Registered backups, newest first.
    pub fn list_backups(&self) -> Result<Vec<BackupRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT file_name, sha256, bytes, created_ms, policy_version, kind, actor
             FROM backups ORDER BY created_ms DESC, file_name DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            let kind: String = r.get(5)?;
            Ok(BackupRecord {
                file_name: r.get(0)?,
                sha256: r.get(1)?,
                bytes: u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                created_ms: r.get(3)?,
                policy_version: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                kind: if kind == "pre_restore" {
                    BackupKind::PreRestore
                } else {
                    BackupKind::Manual
                },
                actor: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Verify a registered backup and read its policy and settings into
    /// memory. Checks, in order: plain file name, registry entry, regular
    /// file (not a link), SHA-256 against the registry, SQLite
    /// `integrity_check`, RustWard schema not newer than this build, policy
    /// checksum and validation, settings validation. The file is copied
    /// into memory first, so what was hashed is exactly what is parsed.
    /// Nothing in the live database changes.
    pub fn inspect_backup(
        &self,
        dir: &Path,
        file_name: &str,
    ) -> Result<RestoreCandidate, StorageError> {
        let reject = |r| StorageError::BackupRejected(r);
        let plain = Path::new(file_name)
            .file_name()
            .is_some_and(|n| n == std::ffi::OsStr::new(file_name))
            && !file_name.contains(['/', '\\', ':'])
            && file_name.starts_with("rustward-");
        if !plain {
            return Err(reject(BackupRejection::InvalidName));
        }
        let record = self
            .list_backups()?
            .into_iter()
            .find(|b| b.file_name == file_name)
            .ok_or_else(|| reject(BackupRejection::NotRegistered))?;
        let path = dir.join(file_name);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(reject(BackupRejection::Missing));
            }
            Err(e) => return Err(StorageError::Io(e.to_string())),
        };
        if !meta.file_type().is_file() {
            return Err(reject(BackupRejection::NotRegularFile));
        }
        let bytes = std::fs::read(&path).map_err(|e| StorageError::Io(e.to_string()))?;
        if sha256_hex(&bytes) != record.sha256 {
            return Err(reject(BackupRejection::HashMismatch));
        }
        // Parse the verified bytes from a private copy (never the original).
        let tmp_path = dir.join(format!(
            ".inspect-{}-{}.tmp",
            std::process::id(),
            self.clock.now_ms()
        ));
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .map_err(|e| StorageError::Io(e.to_string()))?;
            f.write_all(&bytes)
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }
        let parsed = (|| {
            let candidate =
                Connection::open_with_flags(&tmp_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(|_| reject(BackupRejection::Corrupt))?;
            let check: String = candidate
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .map_err(|_| reject(BackupRejection::Corrupt))?;
            if check != "ok" {
                return Err(reject(BackupRejection::Corrupt));
            }
            let v: Option<u32> = candidate
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
                    r.get(0)
                })
                .map_err(|_| reject(BackupRejection::NotRustWard))?;
            let v = v.ok_or_else(|| reject(BackupRejection::NotRustWard))?;
            if v > migrations::latest_version() {
                return Err(reject(BackupRejection::SchemaTooNew));
            }
            let tmp = Self {
                conn: candidate,
                clock: Arc::clone(&self.clock),
                observer: None,
                last_mirrored_id: 0,
                mirror: MirrorStatus::default(),
            };
            let policy = tmp
                .active_policy()
                .map_err(|_| reject(BackupRejection::InvalidPolicy))?
                .ok_or_else(|| reject(BackupRejection::InvalidPolicy))?;
            let settings = tmp
                .settings()
                .map_err(|_| reject(BackupRejection::InvalidPolicy))?;
            settings
                .validate()
                .map_err(|_| reject(BackupRejection::InvalidPolicy))?;
            Ok((policy.state, settings))
        })();
        let _ = std::fs::remove_file(&tmp_path);
        let (state, settings) = parsed?;
        Ok(RestoreCandidate {
            record,
            state,
            settings,
        })
    }

    /// Apply a verified backup as a NEW policy version (`active + 1`)
    /// together with its settings, in one transaction. Nothing is rolled
    /// back: older policy versions, the policy change history and the audit
    /// log stay intact. Fails with [`StorageError::VersionConflict`] if the
    /// active version is not `expected_active`.
    pub fn apply_restored_state(
        &mut self,
        candidate: &RestoreCandidate,
        expected_active: u64,
        restore_id: &str,
        actor: &str,
    ) -> Result<u64, StorageError> {
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: Option<i64> = tx
            .query_row(
                "SELECT version FROM policy_states WHERE active = 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let active = active.and_then(|v| u64::try_from(v).ok()).unwrap_or(0);
        if active != expected_active {
            return Err(StorageError::VersionConflict {
                expected: expected_active,
                active,
            });
        }
        let mut state = candidate.state.clone();
        state.policy.policy_version = active.saturating_add(1);
        state
            .validate()
            .map_err(|e| StorageError::Invalid(e.to_string()))?;
        candidate
            .settings
            .validate()
            .map_err(StorageError::Invalid)?;
        Self::insert_state_tx(&tx, &state, now)?;
        let to = state.policy.policy_version;
        let summary = format!(
            "policy restored from backup {} (backup v{}) as v{to}",
            candidate.record.file_name, candidate.record.policy_version
        );
        let details = serde_json::json!({
            "restore_id": restore_id,
            "backup_file": candidate.record.file_name,
            "backup_sha256": candidate.record.sha256,
            "backup_created_ms": candidate.record.created_ms,
            "backup_policy_version": candidate.record.policy_version,
            "from_policy_version": active,
            "to_policy_version": to,
            "workstation_id": state.policy.workstation_id,
            "catalog_version": state.catalog.catalog_version,
        });
        tx.execute(
            "INSERT INTO policy_changes (utc_ms, actor, action, brand_id, summary, from_version, to_version, change_json)
             VALUES (?1, ?2, 'policy_restored', '', ?3, ?4, ?5, ?6)",
            params![now, actor, summary, to_i64(active)?, to_i64(to)?, details.to_string()],
        )?;
        tx.execute(
            "INSERT INTO settings (key, value, updated_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ms = excluded.updated_ms",
            params![SETTINGS_KEY, serde_json::to_string(&candidate.settings)?, now],
        )?;
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Warning,
                kind: "policy_restored".into(),
                device_key: None,
                message: format!("{summary} by {actor}"),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: Some(to),
                details,
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(to)
    }

    // ------------------------------------------------------ approved snapshot

    fn approved_policy_signature(
        record: &ApprovedPolicyRecord,
        deny_json: &str,
        allow_json: &str,
        third_json: &str,
    ) -> String {
        let canonical = [
            record.policy_version.to_string(),
            record.revision_id.clone(),
            record.catalog_version.clone(),
            deny_json.to_owned(),
            allow_json.to_owned(),
            third_json.to_owned(),
            u8::from(record.retroactive).to_string(),
            u8::from(record.auto_reconcile).to_string(),
            record.approved_by.clone(),
            record.approved_ms.to_string(),
        ]
        .join("\u{1f}");
        sha256_hex(canonical.as_bytes())
    }

    /// Reads the last explicitly admin-approved Windows USB GPO policy snapshot.
    pub fn approved_policy(&self) -> Result<Option<ApprovedPolicyRecord>, StorageError> {
        struct RawApprovedRow {
            version_i64: i64,
            revision_id: String,
            catalog_version: String,
            deny_json: String,
            allow_json: String,
            third_json: String,
            retroactive: bool,
            auto_reconcile: bool,
            approved_by: String,
            approved_ms: i64,
            signature: String,
        }
        let row: Option<RawApprovedRow> = self
            .conn
            .query_row(
                "SELECT policy_version, revision_id, catalog_version, deny_ids_json,
                        allow_ids_json, third_party_denies_json, retroactive, auto_reconcile,
                        approved_by, approved_ms, signature_sha256
                 FROM approved_compound_policy WHERE id = 1",
                [],
                |r| {
                    Ok(RawApprovedRow {
                        version_i64: r.get(0)?,
                        revision_id: r.get(1)?,
                        catalog_version: r.get(2)?,
                        deny_json: r.get(3)?,
                        allow_json: r.get(4)?,
                        third_json: r.get(5)?,
                        retroactive: r.get(6)?,
                        auto_reconcile: r.get(7)?,
                        approved_by: r.get(8)?,
                        approved_ms: r.get(9)?,
                        signature: r.get(10)?,
                    })
                },
            )
            .optional()?;
        let Some(RawApprovedRow {
            version_i64,
            revision_id,
            catalog_version,
            deny_json,
            allow_json,
            third_json,
            retroactive,
            auto_reconcile,
            approved_by,
            approved_ms,
            signature,
        }) = row
        else {
            return Ok(None);
        };
        let policy_version = u64::try_from(version_i64)
            .map_err(|_| StorageError::Invalid("approved policy version negative".into()))?;
        let record = ApprovedPolicyRecord {
            policy_version,
            revision_id,
            catalog_version,
            deny_ids: serde_json::from_str(&deny_json)?,
            allow_ids: serde_json::from_str(&allow_json)?,
            third_party_denies: serde_json::from_str(&third_json)?,
            retroactive,
            auto_reconcile,
            approved_by,
            approved_ms,
        };
        let expected_sig =
            Self::approved_policy_signature(&record, &deny_json, &allow_json, &third_json);
        if !auth::constant_time_str_eq(&signature, &expected_sig) {
            return Err(StorageError::Invalid(
                "approved Windows policy snapshot failed integrity verification".into(),
            ));
        }
        Ok(Some(record))
    }

    /// Atomically stores the latest admin-approved Windows USB GPO policy snapshot.
    pub fn save_approved_policy(
        &mut self,
        record: &ApprovedPolicyRecord,
    ) -> Result<(), StorageError> {
        let deny_json = serde_json::to_string(&record.deny_ids)?;
        let allow_json = serde_json::to_string(&record.allow_ids)?;
        let third_json = serde_json::to_string(&record.third_party_denies)?;
        let signature =
            Self::approved_policy_signature(record, &deny_json, &allow_json, &third_json);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO approved_compound_policy (
                 id, policy_version, revision_id, catalog_version, deny_ids_json,
                 allow_ids_json, third_party_denies_json, retroactive, auto_reconcile,
                 approved_by, approved_ms, signature_sha256
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(id) DO UPDATE SET
                 policy_version = excluded.policy_version,
                 revision_id = excluded.revision_id,
                 catalog_version = excluded.catalog_version,
                 deny_ids_json = excluded.deny_ids_json,
                 allow_ids_json = excluded.allow_ids_json,
                 third_party_denies_json = excluded.third_party_denies_json,
                 retroactive = excluded.retroactive,
                 auto_reconcile = excluded.auto_reconcile,
                 approved_by = excluded.approved_by,
                 approved_ms = excluded.approved_ms,
                 signature_sha256 = excluded.signature_sha256",
            params![
                to_i64(record.policy_version)?,
                record.revision_id,
                record.catalog_version,
                deny_json,
                allow_json,
                third_json,
                record.retroactive,
                record.auto_reconcile,
                record.approved_by,
                record.approved_ms,
                signature,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Clears the persisted approved Windows policy snapshot (called on intentional GPO rollback).
    pub fn clear_approved_policy(&mut self) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM approved_compound_policy WHERE id = 1", [])?;
        Ok(())
    }

    // --------------------------------------------------------- operator auth

    /// Returns `true` once initial administrator setup has created at least one user.
    pub fn has_any_users(&self) -> Result<bool, StorageError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM app_users", [], |r| r.get(0))?;
        Ok(count > 0)
    }

    /// Lists all configured RustWard operator accounts without secret hashes.
    pub fn list_app_users(&self) -> Result<Vec<AppUserRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, username, display_name, role, failed_attempts, locked_until_ms,
                    created_ms, updated_ms, recovery_hash_sealed
             FROM app_users ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], user_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Creates the mandatory first administrator account only when `app_users` is empty.
    pub fn create_initial_admin(
        &mut self,
        username: &str,
        display_name: &str,
        password_hash: &str,
        recovery_hash_sealed: &str,
    ) -> Result<AppUserRecord, StorageError> {
        let username = auth::validate_username(username).map_err(StorageError::Invalid)?;
        let display_name = display_name.trim();
        if display_name.is_empty() || display_name.chars().count() > 80 {
            return Err(StorageError::Invalid(
                "display name must be 1 to 80 characters".into(),
            ));
        }
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: i64 = tx.query_row("SELECT COUNT(*) FROM app_users", [], |r| r.get(0))?;
        if existing > 0 {
            return Err(StorageError::Invalid(
                "initial administrator has already been created".into(),
            ));
        }
        tx.execute(
            "INSERT INTO app_users (
                 username, display_name, role, password_hash, recovery_hash_sealed,
                 failed_attempts, locked_until_ms, created_ms, updated_ms
             ) VALUES (?1, ?2, 'admin', ?3, ?4, 0, NULL, ?5, ?5)",
            params![username, display_name, password_hash, recovery_hash_sealed, now],
        )?;
        let id = tx.last_insert_rowid();
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Info,
                kind: "admin_initialized".into(),
                device_key: None,
                message: format!("initial RustWard administrator account '{username}' initialized"),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::json!({
                    "actor_username": username,
                    "role": "admin",
                }),
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(AppUserRecord {
            id,
            username,
            display_name: display_name.to_owned(),
            role: UserRole::Admin,
            failed_attempts: 0,
            locked_until_ms: None,
            created_ms: now,
            updated_ms: now,
            has_recovery_key: true,
        })
    }

    /// Creates an additional operator user (`admin` or `read_only`) and records an audit event.
    pub fn create_app_user(
        &mut self,
        username: &str,
        display_name: &str,
        role: UserRole,
        password_hash: &str,
        recovery_hash_sealed: Option<&str>,
        actor: &str,
    ) -> Result<AppUserRecord, StorageError> {
        let username = auth::validate_username(username).map_err(StorageError::Invalid)?;
        let display_name = display_name.trim();
        if display_name.is_empty() || display_name.chars().count() > 80 {
            return Err(StorageError::Invalid(
                "display name must be 1 to 80 characters".into(),
            ));
        }
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let dup: i64 = tx.query_row(
            "SELECT COUNT(*) FROM app_users WHERE lower(username) = lower(?1)",
            params![username],
            |r| r.get(0),
        )?;
        if dup > 0 {
            return Err(StorageError::Invalid(format!(
                "user '{username}' already exists"
            )));
        }
        tx.execute(
            "INSERT INTO app_users (
                 username, display_name, role, password_hash, recovery_hash_sealed,
                 failed_attempts, locked_until_ms, created_ms, updated_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6)",
            params![
                username,
                display_name,
                role.as_str(),
                password_hash,
                recovery_hash_sealed,
                now
            ],
        )?;
        let id = tx.last_insert_rowid();
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Info,
                kind: "user_created".into(),
                device_key: None,
                message: format!(
                    "operator account '{username}' (role={}) created by {actor}",
                    role.as_str()
                ),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::json!({
                    "actor_username": actor,
                    "target_username": username,
                    "role": role.as_str(),
                }),
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(AppUserRecord {
            id,
            username,
            display_name: display_name.to_owned(),
            role,
            failed_attempts: 0,
            locked_until_ms: None,
            created_ms: now,
            updated_ms: now,
            has_recovery_key: recovery_hash_sealed.is_some(),
        })
    }

    /// Removes an operator account, refusing to delete the last remaining `admin`.
    pub fn delete_app_user(&mut self, username: &str, actor: &str) -> Result<(), StorageError> {
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT id, username, role FROM app_users WHERE lower(username) = lower(?1)",
                params![username.trim()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((id, canonical_username, role_str)) = row else {
            return Err(StorageError::Invalid(format!(
                "user '{}' not found",
                username.trim()
            )));
        };
        if role_str == UserRole::Admin.as_str() {
            let admin_count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM app_users WHERE role = 'admin'",
                [],
                |r| r.get(0),
            )?;
            if admin_count <= 1 {
                return Err(StorageError::Invalid(
                    "cannot delete the last remaining administrator account".into(),
                ));
            }
        }
        tx.execute("DELETE FROM app_users WHERE id = ?1", params![id])?;
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: Severity::Warning,
                kind: "user_deleted".into(),
                device_key: None,
                message: format!(
                    "operator account '{canonical_username}' (role={role_str}) deleted by {actor}"
                ),
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::json!({
                    "actor_username": actor,
                    "target_username": canonical_username,
                    "role": role_str,
                }),
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(())
    }

    /// Verifies `username` + `password` using Argon2id and enforces per-account rate limiting.
    pub fn authenticate_user(
        &mut self,
        username: &str,
        password: &str,
        max_failures: u32,
        lockout_ms: i64,
    ) -> Result<AuthAttemptOutcome, StorageError> {
        const DUMMY_PHC: &str =
            "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let candidate_user = username.trim();
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        #[allow(clippy::type_complexity)]
        let row: Option<(
            i64,
            String,
            String,
            String,
            String,
            Option<String>,
            i64,
            Option<i64>,
            i64,
            i64,
        )> = tx
            .query_row(
                "SELECT id, username, display_name, role, password_hash, recovery_hash_sealed,
                        failed_attempts, locked_until_ms, created_ms, updated_ms
                 FROM app_users WHERE lower(username) = lower(?1)",
                params![candidate_user],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            id,
            canonical_user,
            display_name,
            role_str,
            stored_hash,
            recovery_sealed,
            prev_failures_i64,
            locked_until_ms,
            created_ms,
            _updated_ms,
        )) = row
        else {
            let _ = auth::verify_secret(password, DUMMY_PHC);
            return Ok(AuthAttemptOutcome::InvalidCredentials {
                username: candidate_user.to_owned(),
                failed_attempts: 0,
                now_locked_until_ms: None,
            });
        };
        let prev_failures = u32::try_from(prev_failures_i64).unwrap_or(0);
        if let Some(until) = locked_until_ms
            && now < until
        {
            return Ok(AuthAttemptOutcome::Locked {
                username: canonical_user,
                locked_until_ms: until,
                failed_attempts: prev_failures,
            });
        }
        let valid = auth::verify_secret(password, &stored_hash);
        if valid {
            tx.execute(
                "UPDATE app_users SET failed_attempts = 0, locked_until_ms = NULL, updated_ms = ?2 WHERE id = ?1",
                params![id, now],
            )?;
            tx.commit()?;
            let role = UserRole::parse(&role_str)
                .ok_or_else(|| StorageError::Invalid(format!("invalid user role '{role_str}'")))?;
            return Ok(AuthAttemptOutcome::Success(AppUserRecord {
                id,
                username: canonical_user,
                display_name,
                role,
                failed_attempts: 0,
                locked_until_ms: None,
                created_ms,
                updated_ms: now,
                has_recovery_key: recovery_sealed.is_some(),
            }));
        }
        let next_failures = if locked_until_ms.is_some_and(|until| now >= until) {
            1
        } else {
            prev_failures.saturating_add(1)
        };
        let new_lock_until = if next_failures >= max_failures {
            Some(now.saturating_add(lockout_ms))
        } else {
            None
        };
        tx.execute(
            "UPDATE app_users SET failed_attempts = ?2, locked_until_ms = ?3, updated_ms = ?4 WHERE id = ?1",
            params![id, i64::from(next_failures), new_lock_until, now],
        )?;
        tx.commit()?;
        Ok(AuthAttemptOutcome::InvalidCredentials {
            username: canonical_user,
            failed_attempts: next_failures,
            now_locked_until_ms: new_lock_until,
        })
    }

    /// Reads the stored sealed recovery envelope and role for `username`.
    pub fn get_recovery_sealed(
        &self,
        username: &str,
    ) -> Result<Option<(String, UserRole, Option<String>)>, StorageError> {
        let row: Option<(String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT username, role, recovery_hash_sealed FROM app_users WHERE lower(username) = lower(?1)",
                params![username.trim()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match row {
            Some((u, role_str, sealed)) => {
                let role = UserRole::parse(&role_str).ok_or_else(|| {
                    StorageError::Invalid(format!("invalid user role '{role_str}'"))
                })?;
                Ok(Some((u, role, sealed)))
            }
            None => Ok(None),
        }
    }

    /// Updates a user's `Argon2id` password hash (and optionally replaces the sealed recovery envelope).
    pub fn update_user_password(
        &mut self,
        username: &str,
        new_password_hash: &str,
        new_recovery_sealed: Option<&str>,
        via_recovery: bool,
        actor: &str,
    ) -> Result<(), StorageError> {
        let now = self.clock.now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let canonical: Option<String> = tx
            .query_row(
                "SELECT username FROM app_users WHERE lower(username) = lower(?1)",
                params![username.trim()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(canonical_user) = canonical else {
            return Err(StorageError::Invalid(format!(
                "user '{}' not found",
                username.trim()
            )));
        };
        tx.execute(
            "UPDATE app_users
             SET password_hash = ?2,
                 recovery_hash_sealed = COALESCE(?3, recovery_hash_sealed),
                 failed_attempts = 0,
                 locked_until_ms = NULL,
                 updated_ms = ?4
             WHERE lower(username) = lower(?1)",
            params![canonical_user, new_password_hash, new_recovery_sealed, now],
        )?;
        let kind = if via_recovery {
            "password_reset_with_recovery"
        } else {
            "password_changed"
        };
        let msg = if via_recovery {
            format!("password reset via recovery key for '{canonical_user}' by {actor}")
        } else {
            format!("password changed for '{canonical_user}' by {actor}")
        };
        Self::append_event_tx(
            &tx,
            now,
            &NewEvent {
                severity: if via_recovery {
                    Severity::Warning
                } else {
                    Severity::Info
                },
                kind: kind.into(),
                device_key: None,
                message: msg,
                simulated: false,
                enforcement_state: "n/a".into(),
                policy_version: None,
                details: serde_json::json!({
                    "actor_username": actor,
                    "target_username": canonical_user,
                    "via_recovery": via_recovery,
                    "recovery_rotated": new_recovery_sealed.is_some(),
                }),
            },
        )?;
        tx.commit()?;
        self.mirror_new_events();
        Ok(())
    }

    /// Raw connection for tests of corruption handling.
    #[doc(hidden)]
    pub fn connection_for_tests(&self) -> &Connection {
        &self.conn
    }
}

fn event_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SecurityEvent> {
    let sev: String = r.get(2)?;
    let details: String = r.get(9)?;
    Ok(SecurityEvent {
        id: r.get(0)?,
        utc_ms: r.get(1)?,
        severity: Severity::parse(&sev).unwrap_or(Severity::Critical),
        kind: r.get(3)?,
        device_key: r.get(4)?,
        message: r.get(5)?,
        simulated: r.get(6)?,
        enforcement_state: r.get(7)?,
        policy_version: r
            .get::<_, Option<i64>>(8)?
            .and_then(|v| u64::try_from(v).ok()),
        details: serde_json::from_str(&details).unwrap_or(serde_json::Value::Null),
        prev_hash: r.get(10)?,
        hash: r.get(11)?,
    })
}

fn user_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AppUserRecord> {
    let role_str: String = r.get(3)?;
    let role = UserRole::parse(&role_str).unwrap_or(UserRole::ReadOnly);
    let failed_i64: i64 = r.get(4)?;
    let recovery_sealed: Option<String> = r.get(8)?;
    Ok(AppUserRecord {
        id: r.get(0)?,
        username: r.get(1)?,
        display_name: r.get(2)?,
        role,
        failed_attempts: u32::try_from(failed_i64).unwrap_or(0),
        locked_until_ms: r.get(5)?,
        created_ms: r.get(6)?,
        updated_ms: r.get(7)?,
        has_recovery_key: recovery_sealed.is_some(),
    })
}

/// Shared device upsert (connection or transaction).
fn upsert_device_on(conn: &Connection, d: &DeviceRow) -> Result<(), StorageError> {
    conn.execute(
            "INSERT INTO devices (device_key, display_id, category, transport, vendor, product, usb_vid_pid,
                 vendor_level_id, friendly_name, matched_brand, first_seen_ms, last_seen_ms, present, synthetic,
                 last_verdict, last_reason, last_policy_version, enforcement_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
             ON CONFLICT(device_key) DO UPDATE SET
                 display_id = excluded.display_id, category = excluded.category, transport = excluded.transport,
                 vendor = excluded.vendor, product = excluded.product, usb_vid_pid = excluded.usb_vid_pid,
                 vendor_level_id = excluded.vendor_level_id, friendly_name = excluded.friendly_name,
                 matched_brand = excluded.matched_brand, last_seen_ms = excluded.last_seen_ms,
                 present = excluded.present, synthetic = excluded.synthetic,
                 last_verdict = excluded.last_verdict, last_reason = excluded.last_reason,
                 last_policy_version = excluded.last_policy_version,
                 enforcement_state = excluded.enforcement_state",
            params![
                d.device_key,
                d.display_id,
                d.category,
                d.transport,
                d.vendor,
                d.product,
                d.usb_vid_pid,
                d.vendor_level_id,
                d.friendly_name,
                d.matched_brand,
                d.first_seen_ms,
                d.last_seen_ms,
                d.present,
                d.synthetic,
                d.last_verdict,
                d.last_reason,
                to_i64(d.last_policy_version)?,
                d.enforcement_state
            ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking_keeps_lun_and_hides_serial() {
        assert_eq!(
            mask_instance_id("USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra\\4C530001230615110223&0"),
            "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra\\****0223&0"
        );
        assert_eq!(
            mask_instance_id("USB\\VID_0781&PID_5581\\ABC"),
            "USB\\VID_0781&PID_5581\\****"
        );
        assert_eq!(mask_instance_id("NOSLASH"), "****");
        assert_eq!(
            mask_instance_id("SCSI\\Disk&Ven_X\\7&2A3B4C5D&0&000000"),
            "SCSI\\Disk&Ven_X\\****5D&0&000000"
        );
    }

    #[test]
    fn device_key_is_case_insensitive_and_short() {
        assert_eq!(device_key("usb\\a"), device_key("USB\\A"));
        assert_eq!(device_key("X").len(), 32);
    }
}
