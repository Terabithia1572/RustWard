//! Versioned schema migrations. Migrations are append-only: never edit a
//! released migration, add a new one.

use rusqlite::{Connection, TransactionBehavior, params};

use crate::StorageError;

/// (version, SQL). Applied in order inside one transaction each.
pub const MIGRATIONS: &[(u32, &str)] = &[
    (
        1,
        r"
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE TABLE policy_states (
    version         INTEGER PRIMARY KEY,
    catalog_version TEXT NOT NULL,
    state_json      TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    created_ms      INTEGER NOT NULL,
    active          INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1))
);
CREATE UNIQUE INDEX policy_states_one_active ON policy_states(active) WHERE active = 1;
CREATE TABLE policy_changes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    utc_ms       INTEGER NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    brand_id     TEXT NOT NULL,
    summary      TEXT NOT NULL,
    from_version INTEGER NOT NULL,
    to_version   INTEGER NOT NULL,
    change_json  TEXT NOT NULL
);
CREATE TABLE devices (
    device_key          TEXT PRIMARY KEY,
    display_id          TEXT NOT NULL,
    category            TEXT NOT NULL,
    transport           TEXT,
    vendor              TEXT,
    product             TEXT,
    usb_vid_pid         TEXT,
    vendor_level_id     TEXT,
    friendly_name       TEXT,
    matched_brand       TEXT,
    first_seen_ms       INTEGER NOT NULL,
    last_seen_ms        INTEGER NOT NULL,
    present             INTEGER NOT NULL CHECK (present IN (0, 1)),
    synthetic           INTEGER NOT NULL CHECK (synthetic IN (0, 1)),
    last_verdict        TEXT NOT NULL,
    last_reason         TEXT NOT NULL,
    last_policy_version INTEGER NOT NULL,
    enforcement_state   TEXT NOT NULL
);
CREATE TABLE security_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    utc_ms            INTEGER NOT NULL,
    severity          TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    kind              TEXT NOT NULL,
    device_key        TEXT,
    message           TEXT NOT NULL,
    simulated         INTEGER NOT NULL CHECK (simulated IN (0, 1)),
    enforcement_state TEXT NOT NULL,
    policy_version    INTEGER,
    details_json      TEXT NOT NULL,
    prev_hash         TEXT NOT NULL,
    hash              TEXT NOT NULL
);
CREATE INDEX security_events_time ON security_events(utc_ms);
CREATE INDEX security_events_device ON security_events(device_key);
",
    ),
    (
        2,
        r"
-- Registry of backups created by the service. Only registered backups whose
-- SHA-256 still matches can be restored (rejects foreign or altered files).
CREATE TABLE backups (
    file_name      TEXT PRIMARY KEY,
    sha256         TEXT NOT NULL,
    bytes          INTEGER NOT NULL,
    created_ms     INTEGER NOT NULL,
    policy_version INTEGER NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('manual', 'pre_restore')),
    actor          TEXT NOT NULL
);

-- Retention writes the highest purgeable id here inside its transaction.
CREATE TABLE retention_guard (cutoff_id INTEGER NOT NULL);

-- Append-only guards. They stop software defects from rewriting history;
-- they do NOT stop an administrator with direct database access, who can
-- drop them (the hash chain and the Event Log mirror make that evident).
CREATE TRIGGER security_events_no_update BEFORE UPDATE ON security_events
BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END;
CREATE TRIGGER security_events_retention_only_delete BEFORE DELETE ON security_events
WHEN OLD.id > COALESCE((SELECT MAX(cutoff_id) FROM retention_guard), 0)
BEGIN SELECT RAISE(ABORT, 'security_events rows are removed only by retention'); END;
CREATE TRIGGER policy_changes_no_update BEFORE UPDATE ON policy_changes
BEGIN SELECT RAISE(ABORT, 'policy_changes is append-only'); END;
CREATE TRIGGER policy_changes_no_delete BEFORE DELETE ON policy_changes
BEGIN SELECT RAISE(ABORT, 'policy_changes is append-only'); END;
CREATE TRIGGER policy_states_immutable BEFORE UPDATE OF version, catalog_version, state_json, sha256, created_ms ON policy_states
BEGIN SELECT RAISE(ABORT, 'stored policy states are immutable'); END;
CREATE TRIGGER policy_states_no_delete BEFORE DELETE ON policy_states
BEGIN SELECT RAISE(ABORT, 'stored policy states are never deleted'); END;
CREATE TRIGGER backups_no_update BEFORE UPDATE ON backups
BEGIN SELECT RAISE(ABORT, 'backup registry is append-only'); END;
CREATE TRIGGER backups_no_delete BEFORE DELETE ON backups
BEGIN SELECT RAISE(ABORT, 'backup registry is append-only'); END;
",
    ),
    (
        3,
        r"
-- Last explicitly admin-approved Windows USB GPO policy snapshot for startup reconciliation.
CREATE TABLE approved_compound_policy (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    policy_version          INTEGER NOT NULL,
    revision_id             TEXT NOT NULL,
    catalog_version         TEXT NOT NULL,
    deny_ids_json           TEXT NOT NULL,
    allow_ids_json          TEXT NOT NULL,
    third_party_denies_json TEXT NOT NULL,
    retroactive             INTEGER NOT NULL CHECK (retroactive IN (0, 1)),
    auto_reconcile          INTEGER NOT NULL DEFAULT 1 CHECK (auto_reconcile IN (0, 1)),
    approved_by             TEXT NOT NULL,
    approved_ms             INTEGER NOT NULL,
    signature_sha256        TEXT NOT NULL
);

-- Application-level RBAC accounts (Argon2id + per-user CSPRNG salt, no hardcoded passwords).
CREATE TABLE app_users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT NOT NULL UNIQUE,
    display_name         TEXT NOT NULL,
    role                 TEXT NOT NULL CHECK (role IN ('admin', 'read_only')),
    password_hash        TEXT NOT NULL,
    recovery_hash_sealed TEXT,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until_ms      INTEGER,
    created_ms           INTEGER NOT NULL,
    updated_ms           INTEGER NOT NULL
);
CREATE UNIQUE INDEX app_users_username_nocase ON app_users(lower(username));

-- Indexed nullable audit metadata columns on security_events.
-- Existing pre-v3 rows remain NULL without triggering BEFORE UPDATE or altering hashes.
ALTER TABLE security_events ADD COLUMN computer_name TEXT;
ALTER TABLE security_events ADD COLUMN manufacturer_id TEXT;
ALTER TABLE security_events ADD COLUMN device_name TEXT;
ALTER TABLE security_events ADD COLUMN vid_pid TEXT;
ALTER TABLE security_events ADD COLUMN transport TEXT;
ALTER TABLE security_events ADD COLUMN pnp_problem_code INTEGER;
ALTER TABLE security_events ADD COLUMN effective_decision TEXT;
ALTER TABLE security_events ADD COLUMN enforcement_outcome TEXT;
ALTER TABLE security_events ADD COLUMN actor_username TEXT;
ALTER TABLE security_events ADD COLUMN windows_user TEXT;
ALTER TABLE security_events ADD COLUMN policy_revision TEXT;
CREATE INDEX security_events_mfg ON security_events(manufacturer_id);
CREATE INDEX security_events_decision ON security_events(effective_decision);
CREATE INDEX security_events_winuser ON security_events(windows_user);
CREATE INDEX security_events_actor ON security_events(actor_username);
",
    ),
];

/// Latest schema version known to this build.
#[must_use]
pub fn latest_version() -> u32 {
    MIGRATIONS.last().map_or(0, |(v, _)| *v)
}

/// Current schema version of a database (0 = empty).
pub fn current_version(conn: &Connection) -> Result<u32, StorageError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_ms INTEGER NOT NULL);",
    )?;
    let v: Option<u32> = conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
        r.get(0)
    })?;
    Ok(v.unwrap_or(0))
}

/// Apply pending migrations. Refuses databases newer than this build.
///
/// All pending migrations run in one `IMMEDIATE` transaction and the current
/// version is read **inside** it, so two processes opening a new database at
/// the same time serialise (the second waits on the busy timeout, then sees
/// the migrated schema) instead of both running the DDL (Phase 9B finding
/// F-19, found by the real-backend UI integration tests).
pub fn migrate(conn: &mut Connection, now_ms: i64) -> Result<u32, StorageError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = current_version(&tx)?;
    let latest = latest_version();
    if current > latest {
        return Err(StorageError::SchemaTooNew {
            found: current,
            supported: latest,
        });
    }
    for (version, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_ms) VALUES (?1, ?2)",
            params![version, now_ms],
        )?;
    }
    tx.commit()?;
    Ok(latest)
}
