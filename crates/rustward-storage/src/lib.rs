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

pub mod migrations;
pub mod model;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use rustward_core::policy_edit::{ChangeRecord, EditOutcome, PolicyState};
use sha2::{Digest, Sha256};

pub use model::{
    AppSettings, ChainStatus, DeviceRow, EventFilter, Language, NewEvent, PolicyChangeRow,
    SecurityEvent, Severity, Theme,
};

/// Genesis value of the event hash chain.
pub const CHAIN_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SETTINGS_KEY: &str = "app_settings";
const CHAIN_ANCHOR_KEY: &str = "event_chain_anchor";
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

/// The RustWard database.
pub struct Store {
    conn: Connection,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
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
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        migrations::migrate(&mut conn, clock.now_ms())?;
        Ok(Self { conn, clock })
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
        let tx = self.conn.transaction()?;
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
        let tx = self.conn.transaction()?;
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
        let tx = self.conn.transaction()?;
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
        self.conn.execute(
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

    /// Mark every present device not in `present_keys` as absent.
    /// Returns the number of rows changed.
    pub fn mark_absent_except(&mut self, present_keys: &[String]) -> Result<usize, StorageError> {
        let tx = self.conn.transaction()?;
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
        conn.execute(
            "INSERT INTO security_events (utc_ms, severity, kind, device_key, message, simulated,
                 enforcement_state, policy_version, details_json, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                hash
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Append a security event to the hash chain.
    pub fn append_event(&mut self, e: &NewEvent) -> Result<i64, StorageError> {
        let now = self.clock.now_ms();
        let tx = self.conn.transaction()?;
        let id = Self::append_event_tx(&tx, now, e)?;
        tx.commit()?;
        Ok(id)
    }

    /// Query events, newest first.
    pub fn list_events(&self, f: &EventFilter) -> Result<Vec<SecurityEvent>, StorageError> {
        let mut sql = String::from(
            "SELECT id, utc_ms, severity, kind, device_key, message, simulated, enforcement_state,
                    policy_version, details_json, prev_hash, hash FROM security_events WHERE 1 = 1",
        );
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(t) = f.text.as_deref().filter(|t| !t.is_empty()) {
            sql.push_str(
                " AND (instr(lower(message), lower(?)) > 0 OR instr(lower(kind), lower(?)) > 0)",
            );
            args.push(t.to_owned().into());
            args.push(t.to_owned().into());
        }
        if let Some(s) = f.min_severity {
            let allowed: Vec<&str> = [Severity::Info, Severity::Warning, Severity::Critical]
                .into_iter()
                .filter(|x| *x >= s)
                .map(Severity::as_str)
                .collect();
            sql.push_str(&format!(
                " AND severity IN ({})",
                vec!["?"; allowed.len()].join(",")
            ));
            args.extend(allowed.into_iter().map(|a| a.to_owned().into()));
        }
        if let Some(k) = &f.kind {
            sql.push_str(" AND kind = ?");
            args.push(k.clone().into());
        }
        if let Some(d) = &f.device_key {
            sql.push_str(" AND device_key = ?");
            args.push(d.clone().into());
        }
        if let Some(s) = f.since_ms {
            sql.push_str(" AND utc_ms >= ?");
            args.push(s.into());
        }
        if let Some(u) = f.until_ms {
            sql.push_str(" AND utc_ms < ?");
            args.push(u.into());
        }
        if let Some(sim) = f.simulated {
            sql.push_str(" AND simulated = ?");
            args.push(i64::from(sim).into());
        }
        sql.push_str(" ORDER BY id DESC LIMIT ? OFFSET ?");
        args.push(i64::from(f.limit.unwrap_or(200).min(5000)).into());
        args.push(i64::from(f.offset.unwrap_or(0)).into());

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
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
        })?;
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
            let expected = event_hash(&prev, r.get(1)?, &e)?;
            if stored_prev != prev || stored_hash != expected {
                return Ok(ChainStatus::Broken { first_bad_id: id });
            }
            prev = stored_hash;
            n += 1;
        }
        Ok(ChainStatus::Intact { entries: n })
    }

    /// Delete events older than the configured retention, moving the chain
    /// anchor forward so the remaining chain still verifies. Returns the
    /// number of deleted events. The purge itself is recorded as an event.
    pub fn apply_retention(&mut self) -> Result<usize, StorageError> {
        let days = self.settings()?.audit_retention_days;
        let now = self.clock.now_ms();
        let cutoff = now - i64::from(days) * 86_400_000;
        let tx = self.conn.transaction()?;
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
        let n = tx.execute(
            "DELETE FROM security_events WHERE id <= ?1",
            params![last_id],
        )?;
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
        Ok(n)
    }

    // ----------------------------------------------------------- backup/restore

    /// Write a consistent copy of the database to `path` (must not exist).
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

    /// Replace the database content with a verified backup. The backup must
    /// pass `integrity_check`, carry a supported schema and a valid active
    /// policy; otherwise nothing is changed.
    pub fn restore_from(&mut self, path: &Path, actor: &str) -> Result<(), StorageError> {
        {
            let candidate =
                Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let check: String = candidate.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            if check != "ok" {
                return Err(StorageError::Integrity(check));
            }
            let v: Option<u32> = candidate
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
                    r.get(0)
                })
                .optional()?
                .flatten();
            let v = v.ok_or_else(|| StorageError::Invalid("not a RustWard database".into()))?;
            if v > migrations::latest_version() {
                return Err(StorageError::SchemaTooNew {
                    found: v,
                    supported: migrations::latest_version(),
                });
            }
            let tmp = Self {
                conn: candidate,
                clock: Arc::clone(&self.clock),
            };
            tmp.active_policy()?
                .ok_or_else(|| StorageError::Invalid("backup has no active policy".into()))?;
        }
        self.conn.restore(
            rusqlite::MAIN_DB,
            path,
            None::<fn(rusqlite::backup::Progress)>,
        )?;
        migrations::migrate(&mut self.conn, self.clock.now_ms())?;
        self.append_event(&NewEvent {
            severity: Severity::Warning,
            kind: "database_restored".into(),
            device_key: None,
            message: format!("database restored from backup by {actor}"),
            simulated: false,
            enforcement_state: "n/a".into(),
            policy_version: None,
            details: serde_json::json!({}),
        })?;
        Ok(())
    }

    /// Raw connection for tests of corruption handling.
    #[doc(hidden)]
    pub fn connection_for_tests(&self) -> &Connection {
        &self.conn
    }
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
