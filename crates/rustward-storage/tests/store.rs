//! Storage integration tests (temporary databases only).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use rusqlite::params;
use rustward_core::policy_edit::{PolicyEdit, PolicyState, apply_edit};
use rustward_storage::{
    AppSettings, BackupKind, BackupRejection, ChainStatus, CheckpointCheck, DeviceRow, EventFilter,
    EventObserver, MIRROR_MAX_BACKFILL, ManualClock, NewEvent, SecurityEvent, Severity,
    StorageError, Store,
};

const CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
const POLICY: &str = include_str!("../../../config/policy.example.json");
const DAY: i64 = 86_400_000;

fn state() -> PolicyState {
    PolicyState {
        catalog: serde_json::from_str(CATALOG).unwrap(),
        policy: serde_json::from_str(POLICY).unwrap(),
    }
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "rustward-storage-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(1_793_836_800_000))
}

fn event(kind: &str, sev: Severity, simulated: bool) -> NewEvent {
    NewEvent {
        severity: sev,
        kind: kind.into(),
        device_key: Some("k1".into()),
        message: format!("{kind} message"),
        simulated,
        enforcement_state: "simulated".into(),
        policy_version: Some(1),
        details: serde_json::json!({ "a": 1 }),
    }
}

#[test]
fn migrations_are_applied_once_and_reported() {
    let s = Store::open_in_memory(clock()).unwrap();
    assert_eq!(
        s.schema_version().unwrap(),
        rustward_storage::migrations::latest_version()
    );
    s.integrity_check().unwrap();
}

#[test]
fn policy_edits_persist_across_restart_with_history_and_events() {
    let dir = TempDir::new("restart");
    let path = dir.0.join("rustward.db");
    let c = clock();
    {
        let mut s = Store::open(&path, c.clone()).unwrap();
        assert!(s.initialize_policy(&state(), "test").unwrap());
        assert!(!s.initialize_policy(&state(), "test").unwrap(), "only once");
        let active = s.active_policy().unwrap().unwrap();
        let out = apply_edit(
            &active.state,
            &PolicyEdit::SetAllowed {
                id: "kingston".into(),
                allowed: true,
            },
        )
        .unwrap();
        c.advance(1000);
        s.commit_policy_edit(&out, "DESKTOP\\admin").unwrap();
    }
    let s = Store::open(&path, c).unwrap();
    let active = s.active_policy().unwrap().unwrap();
    assert_eq!(active.version, 2);
    assert!(
        active
            .state
            .policy
            .allowed_brands
            .iter()
            .any(|r| r.brand_id == "kingston")
    );
    let changes = s.policy_changes(10).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].actor, "DESKTOP\\admin");
    assert_eq!((changes[0].from_version, changes[0].to_version), (1, 2));
    let kinds: Vec<_> = s
        .list_events(&EventFilter::default())
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, ["policy_changed", "policy_initialized"]);
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { entries: 2 }
    ));
}

#[test]
fn stale_edits_are_rejected_atomically() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let base = s.active_policy().unwrap().unwrap().state;
    let a = apply_edit(
        &base,
        &PolicyEdit::SetAllowed {
            id: "kingston".into(),
            allowed: true,
        },
    )
    .unwrap();
    let b = apply_edit(
        &base,
        &PolicyEdit::SetAllowed {
            id: "seagate".into(),
            allowed: true,
        },
    )
    .unwrap();
    s.commit_policy_edit(&a, "t").unwrap();
    assert!(matches!(
        s.commit_policy_edit(&b, "t"),
        Err(StorageError::VersionConflict {
            expected: 1,
            active: 2
        })
    ));
    assert_eq!(
        s.policy_changes(10).unwrap().len(),
        1,
        "failed edit left no history"
    );
    let active = s.active_policy().unwrap().unwrap();
    assert!(
        !active
            .state
            .policy
            .allowed_brands
            .iter()
            .any(|r| r.brand_id == "seagate")
    );
}

#[test]
fn tampered_policy_is_detected_as_corrupt() {
    let s = {
        let mut s = Store::open_in_memory(clock()).unwrap();
        s.initialize_policy(&state(), "t").unwrap();
        s
    };
    // An attacker with direct database access first drops the guard trigger.
    s.connection_for_tests()
        .execute_batch(
            "DROP TRIGGER policy_states_immutable;
             UPDATE policy_states SET state_json = replace(state_json, 'sandisk', 'kingston') WHERE active = 1;",
        )
        .unwrap();
    assert!(matches!(
        s.active_policy(),
        Err(StorageError::CorruptPolicy { .. })
    ));
}

#[test]
fn settings_are_validated_and_audited() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    assert_eq!(s.settings().unwrap(), AppSettings::default());
    let bad = AppSettings {
        audit_retention_days: 1,
        ..AppSettings::default()
    };
    assert!(matches!(
        s.save_settings(&bad, "t"),
        Err(StorageError::Invalid(_))
    ));
    let good = AppSettings {
        audit_retention_days: 90,
        ..AppSettings::default()
    };
    s.save_settings(&good, "t").unwrap();
    assert_eq!(s.settings().unwrap().audit_retention_days, 90);
    assert_eq!(
        s.list_events(&EventFilter::default()).unwrap()[0].kind,
        "settings_changed"
    );
}

fn device(key: &str, present: bool, t: i64) -> DeviceRow {
    DeviceRow {
        device_key: key.into(),
        display_id: format!("USBSTOR\\Disk&Ven_X\\****{key}"),
        category: "usb_storage_disk".into(),
        transport: Some("bulk_only".into()),
        vendor: Some("X".into()),
        product: None,
        usb_vid_pid: Some("0781:5581".into()),
        vendor_level_id: Some("USBSTOR\\DiskX_______".into()),
        friendly_name: None,
        matched_brand: None,
        first_seen_ms: t,
        last_seen_ms: t,
        present,
        synthetic: true,
        last_verdict: "deny".into(),
        last_reason: "unknown_manufacturer".into(),
        last_policy_version: 1,
        enforcement_state: "simulated".into(),
    }
}

#[test]
fn device_inventory_upserts_and_tracks_presence() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.upsert_device(&device("a", true, 10)).unwrap();
    s.upsert_device(&device("b", true, 20)).unwrap();
    s.upsert_device(&device("a", true, 30)).unwrap();
    let all = s.list_devices(false).unwrap();
    assert_eq!(all.len(), 2);
    let a = all.iter().find(|d| d.device_key == "a").unwrap();
    assert_eq!(
        (a.first_seen_ms, a.last_seen_ms),
        (10, 30),
        "first_seen preserved"
    );
    assert_eq!(s.mark_absent_except(&["a".into()]).unwrap(), 1);
    let present: Vec<_> = s
        .list_devices(true)
        .unwrap()
        .into_iter()
        .map(|d| d.device_key)
        .collect();
    assert_eq!(present, ["a"]);
}

#[test]
fn event_filters_work() {
    let c = clock();
    let mut s = Store::open_in_memory(c.clone()).unwrap();
    s.append_event(&event("device_arrived", Severity::Info, true))
        .unwrap();
    c.advance(1000);
    s.append_event(&event("decision_simulated", Severity::Critical, true))
        .unwrap();
    c.advance(1000);
    s.append_event(&event("service_started", Severity::Warning, false))
        .unwrap();

    let crit = s
        .list_events(&EventFilter {
            min_severity: Some(Severity::Warning),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(crit.len(), 2);
    let text = s
        .list_events(&EventFilter {
            text: Some("ARRIVED".into()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(text.len(), 1);
    let sim = s
        .list_events(&EventFilter {
            simulated: Some(false),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(sim[0].kind, "service_started");
    let window = s
        .list_events(&EventFilter {
            since_ms: Some(1_793_836_801_000),
            until_ms: Some(1_793_836_802_000),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(window.len(), 1);
    let page = s
        .list_events(&EventFilter {
            limit: Some(1),
            offset: Some(1),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(page[0].kind, "decision_simulated");
}

#[test]
fn invalid_events_are_rejected() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    for bad in [
        NewEvent {
            kind: "Bad Kind".into(),
            ..event("x", Severity::Info, false)
        },
        NewEvent {
            message: "m".repeat(2000),
            ..event("x", Severity::Info, false)
        },
        NewEvent {
            details: serde_json::json!([1, 2]),
            ..event("x", Severity::Info, false)
        },
    ] {
        assert!(matches!(
            s.append_event(&bad),
            Err(StorageError::Invalid(_))
        ));
    }
}

#[test]
fn hash_chain_detects_tampering() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    for k in ["a_event", "b_event", "c_event"] {
        s.append_event(&event(k, Severity::Info, false)).unwrap();
    }
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { entries: 3 }
    ));
    // Triggers are not a security boundary: an attacker can drop them. The
    // hash chain must still reveal the edit.
    s.connection_for_tests()
        .execute_batch(
            "DROP TRIGGER security_events_no_update;
             UPDATE security_events SET message = 'edited' WHERE kind = 'b_event';",
        )
        .unwrap();
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Broken { first_bad_id: 2 }
    ));
}

#[test]
fn retention_purges_old_events_and_keeps_chain_verifiable() {
    let c = clock();
    let mut s = Store::open_in_memory(c.clone()).unwrap();
    s.save_settings(
        &AppSettings {
            audit_retention_days: 30,
            ..AppSettings::default()
        },
        "t",
    )
    .unwrap();
    s.append_event(&event("old_event", Severity::Info, false))
        .unwrap();
    c.advance(40 * DAY);
    s.append_event(&event("new_event", Severity::Info, false))
        .unwrap();
    let purged = s.apply_retention().unwrap();
    assert_eq!(
        purged, 2,
        "settings_changed + old_event are older than 30 days"
    );
    let kinds: Vec<_> = s
        .list_events(&EventFilter::default())
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, ["retention_applied", "new_event"]);
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { entries: 2 }
    ));
    assert_eq!(s.apply_retention().unwrap(), 0);
}

#[test]
fn newer_schema_is_refused() {
    let dir = TempDir::new("schema");
    let path = dir.0.join("db.sqlite");
    {
        let _ = Store::open(&path, clock()).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_ms) VALUES (?1, 0)",
            params![999],
        )
        .unwrap();
    }
    assert!(matches!(
        Store::open(&path, clock()),
        Err(StorageError::SchemaTooNew { found: 999, .. })
    ));
}

#[derive(Default)]
struct Recorder {
    seen: std::sync::Mutex<Vec<(i64, String)>>,
    fail_kind: Option<&'static str>,
    /// Simulates an Event Log outage: every write fails while set.
    down: std::sync::atomic::AtomicBool,
}

impl EventObserver for Recorder {
    fn on_event(&self, event: &SecurityEvent) -> Result<(), String> {
        if self.down.load(std::sync::atomic::Ordering::SeqCst)
            || self.fail_kind == Some(event.kind.as_str())
        {
            return Err("sink unavailable".into());
        }
        self.seen
            .lock()
            .unwrap()
            .push((event.id, event.kind.clone()));
        Ok(())
    }
}

impl Recorder {
    fn kinds(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, k)| k.clone())
            .collect()
    }
    fn ids(&self) -> Vec<i64> {
        self.seen.lock().unwrap().iter().map(|(i, _)| *i).collect()
    }
}

#[test]
fn observer_receives_every_committed_event_once_in_order() {
    let c = clock();
    let mut s = Store::open_in_memory(c.clone()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    // Events written before the observer was attached (start-up) are
    // back-filled on attach (F-15), then delivery continues in order.
    let rec = Arc::new(Recorder::default());
    s.set_event_observer(rec.clone()).unwrap();
    assert!(s.mirror_status().attached);
    assert_eq!(
        rec.kinds(),
        ["policy_initialized"],
        "start-up event back-filled"
    );

    s.append_event(&event("device_arrived", Severity::Info, true))
        .unwrap();
    let base = s.active_policy().unwrap().unwrap().state;
    let out = apply_edit(
        &base,
        &PolicyEdit::SetAllowed {
            id: "kingston".into(),
            allowed: true,
        },
    )
    .unwrap();
    s.commit_policy_edit(&out, "t").unwrap();
    let mut settings = s.settings().unwrap();
    settings.audit_retention_days = 30;
    s.save_settings(&settings, "t").unwrap();
    c.advance(40 * DAY);
    s.apply_retention().unwrap();

    let seen = rec.seen.lock().unwrap().clone();
    let kinds: Vec<_> = seen.iter().map(|(_, k)| k.as_str()).collect();
    assert_eq!(kinds[..2], ["policy_initialized", "device_arrived"]);
    assert!(kinds.contains(&"settings_changed"));
    assert_eq!(kinds.last(), Some(&"retention_applied"));
    assert!(
        kinds.len() >= 4,
        "policy edit event mirrored too: {kinds:?}"
    );
    let ids: Vec<_> = seen.iter().map(|(i, _)| *i).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids, sorted, "each event once, ascending");
    assert_eq!(s.mirror_status().delivered as usize, seen.len());
    assert_eq!(s.mirror_status().failures, 0);
    assert_eq!(s.mirror_status().pending, 0);
}

#[test]
fn observer_failures_never_block_or_roll_back_writes_and_keep_order() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let rec = Arc::new(Recorder::default());
    s.set_event_observer(rec.clone()).unwrap();
    rec.down.store(true, std::sync::atomic::Ordering::SeqCst);
    s.append_event(&event("device_arrived", Severity::Warning, true))
        .unwrap();
    s.append_event(&event("device_removed", Severity::Info, true))
        .unwrap();
    let stored = s
        .list_events(&EventFilter {
            kind: Some("device_arrived".into()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(stored.len(), 1, "event is stored despite the sink failure");
    let st = s.mirror_status();
    assert_eq!(st.delivered, 1, "only the back-filled start-up event");
    assert_eq!(st.failures, 2, "one failed attempt per commit, then stop");
    assert_eq!(st.pending, 2, "nothing is skipped while the sink is down");
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { .. }
    ));

    // Event Log back: the next retry delivers the backlog in order.
    rec.down.store(false, std::sync::atomic::Ordering::SeqCst);
    s.retry_mirror();
    assert_eq!(
        rec.kinds(),
        ["policy_initialized", "device_arrived", "device_removed"]
    );
    assert_eq!(s.mirror_status().pending, 0);
}

#[test]
fn mirror_cursor_survives_restart_and_backfills_events_written_while_detached() {
    let dir = TempDir::new("mirror-cursor");
    let path = dir.0.join("m.db");
    let c = clock();
    let first = Arc::new(Recorder::default());
    {
        let mut s = Store::open(&path, c.clone()).unwrap();
        s.initialize_policy(&state(), "t").unwrap();
        s.set_event_observer(first.clone()).unwrap();
        s.append_event(&event("device_arrived", Severity::Info, true))
            .unwrap();
    }
    // Service restarts; events are written before the mirror is attached
    // (start-up) - previously these never reached the Event Log.
    let second = Arc::new(Recorder::default());
    {
        let mut s = Store::open(&path, c.clone()).unwrap();
        assert_eq!(
            s.mirror_status().cursor,
            first.ids().last().copied().unwrap()
        );
        s.append_event(&event("service_started", Severity::Info, false))
            .unwrap();
        s.append_event(&event("backend_started", Severity::Info, false))
            .unwrap();
        s.set_event_observer(second.clone()).unwrap();
        assert_eq!(second.kinds(), ["service_started", "backend_started"]);
        assert_eq!(s.mirror_status().pending, 0);
    }
    // Nothing delivered twice across the restart.
    let mut all = first.ids();
    all.extend(second.ids());
    let mut dedup = all.clone();
    dedup.dedup();
    assert_eq!(all, dedup);
}

#[test]
fn mirror_backlog_is_bounded_and_the_gap_is_recorded() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let total = MIRROR_MAX_BACKFILL + 25;
    for _ in 1..total {
        s.append_event(&event("device_arrived", Severity::Info, true))
            .unwrap();
    }
    let rec = Arc::new(Recorder::default());
    s.set_event_observer(rec.clone()).unwrap();
    let st = s.mirror_status();
    assert_eq!(st.skipped, 25);
    assert_eq!(st.pending, 0);
    let kinds = rec.kinds();
    assert_eq!(
        kinds.last().map(String::as_str),
        Some("event_log_backfill_skipped")
    );
    // The newest MIRROR_MAX_BACKFILL events plus the gap record.
    assert_eq!(kinds.len() as i64, MIRROR_MAX_BACKFILL + 1);
    let gap = s
        .list_events(&EventFilter {
            kind: Some("event_log_backfill_skipped".into()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(gap.len(), 1);
    assert_eq!(gap[0].details["skipped"], 25);
    assert_eq!(gap[0].details["first_skipped_id"], 1);
}

#[test]
fn removing_the_newest_events_is_detected_as_truncation() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    for _ in 0..4 {
        s.append_event(&event("device_arrived", Severity::Info, true))
            .unwrap();
    }
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { entries: 5 }
    ));
    // Attacker with file access: drop the guard, delete the newest two.
    s.connection_for_tests()
        .execute_batch(
            "DROP TRIGGER security_events_retention_only_delete;
             DELETE FROM security_events WHERE id > 3;",
        )
        .unwrap();
    assert_eq!(
        s.verify_chain().unwrap(),
        ChainStatus::Truncated {
            entries: 3,
            last_id: 3,
            highest_issued: 5
        }
    );
    // New events chained onto the remaining head: the id gap reveals it.
    s.append_event(&event("device_removed", Severity::Info, true))
        .unwrap();
    assert_eq!(
        s.verify_chain().unwrap(),
        ChainStatus::Missing {
            entries: 3,
            after_id: 3,
            next_id: 6
        }
    );
    // Deleting everything is detected too.
    s.connection_for_tests()
        .execute_batch("DELETE FROM security_events;")
        .unwrap();
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Truncated {
            last_id: 0,
            highest_issued: 6,
            ..
        }
    ));
}

#[test]
fn retention_is_not_mistaken_for_truncation() {
    let c = clock();
    let mut s = Store::open_in_memory(c.clone()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    s.append_event(&event("device_arrived", Severity::Info, true))
        .unwrap();
    let mut settings = s.settings().unwrap();
    settings.audit_retention_days = 30;
    s.save_settings(&settings, "t").unwrap();
    c.advance(40 * DAY);
    assert!(s.apply_retention().unwrap() > 0);
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { .. }
    ));
}

#[test]
fn audit_checkpoint_records_the_head_and_reflects_chain_damage() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    s.append_event(&event("device_arrived", Severity::Info, true))
        .unwrap();
    let head = s
        .list_events(&EventFilter::default())
        .unwrap()
        .into_iter()
        .max_by_key(|e| e.id)
        .unwrap();
    let cp = s.record_audit_checkpoint().unwrap();
    assert_eq!(cp.chain, "intact");
    assert_eq!(
        (cp.head_id, cp.head_hash.as_str()),
        (head.id, head.hash.as_str())
    );
    assert_eq!(cp.entries, 2);
    assert_eq!(cp.highest_issued, head.id);
    assert_eq!(cp.checkpoint_id, head.id + 1);
    let stored = s
        .list_events(&EventFilter {
            kind: Some("audit_checkpoint".into()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(stored[0].severity, Severity::Info);
    assert_eq!(stored[0].details["head_hash"], head.hash);
    // The checkpoint is itself part of the verified chain.
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { entries: 3 }
    ));

    // After truncation the next checkpoint says so, as a warning.
    s.connection_for_tests()
        .execute_batch(
            "DROP TRIGGER security_events_retention_only_delete;
             DELETE FROM security_events WHERE kind = 'audit_checkpoint';",
        )
        .unwrap();
    let cp2 = s.record_audit_checkpoint().unwrap();
    assert_eq!(cp2.chain, "truncated");
    let latest = s
        .list_events(&EventFilter {
            kind: Some("audit_checkpoint".into()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(latest[0].severity, Severity::Warning);
}

// ------------------------------------------------------------ backup/restore

fn kingston_allowed(s: &mut Store) {
    let base = s.active_policy().unwrap().unwrap().state;
    let out = apply_edit(
        &base,
        &PolicyEdit::SetAllowed {
            id: "kingston".into(),
            allowed: true,
        },
    )
    .unwrap();
    s.commit_policy_edit(&out, "t").unwrap();
}

fn event_count(s: &Store) -> usize {
    s.list_events(&EventFilter {
        limit: Some(5000),
        ..EventFilter::default()
    })
    .unwrap()
    .len()
}

fn rejection(e: StorageError) -> BackupRejection {
    match e {
        StorageError::BackupRejected(r) => r,
        other => panic!("expected a backup rejection, got {other:?}"),
    }
}

#[test]
fn backups_are_registered_hashed_and_audited() {
    let dir = TempDir::new("backup-reg");
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let rec = s
        .create_backup(&dir.0, BackupKind::Manual, "PC-01\\admin")
        .unwrap();
    assert!(rec.file_name.starts_with("rustward-backup-") && rec.file_name.ends_with(".db"));
    let bytes = std::fs::read(dir.0.join(&rec.file_name)).unwrap();
    assert_eq!(rec.sha256, rustward_storage::sha256_hex(&bytes));
    assert_eq!(rec.policy_version, 1);
    let second = s.create_backup(&dir.0, BackupKind::Manual, "t").unwrap();
    assert_ne!(
        rec.file_name, second.file_name,
        "same-millisecond backups get distinct names"
    );
    assert_eq!(s.list_backups().unwrap().len(), 2);
    let ev = s
        .list_events(&EventFilter {
            kind: Some("backup_created".into()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[1].details["sha256"], rec.sha256);
}

#[test]
fn restore_applies_backup_as_a_new_version_without_losing_history_or_audit() {
    let dir = TempDir::new("restore-new");
    let c = clock();
    let mut s = Store::open_in_memory(c.clone()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let rec = s.create_backup(&dir.0, BackupKind::Manual, "t").unwrap();
    c.advance(1_000);
    kingston_allowed(&mut s);
    let mut st = s.settings().unwrap();
    st.audit_retention_days = 90;
    s.save_settings(&st, "t").unwrap();
    let events_before = event_count(&s);
    let changes_before = s.policy_changes(100).unwrap().len();

    let cand = s.inspect_backup(&dir.0, &rec.file_name).unwrap();
    assert_eq!(cand.record, rec);
    assert_eq!(cand.state.policy.policy_version, 1);
    assert_eq!(
        s.active_policy().unwrap().unwrap().version,
        2,
        "inspection changes nothing"
    );

    let new_version = s
        .apply_restored_state(&cand, 2, "r-1", "PC-01\\admin")
        .unwrap();
    assert_eq!(
        new_version, 3,
        "restored content becomes v3, versions never go back"
    );
    let active = s.active_policy().unwrap().unwrap();
    assert_eq!(active.version, 3);
    assert!(
        !active
            .state
            .policy
            .allowed_brands
            .iter()
            .any(|r| r.brand_id == "kingston"),
        "content is the backup's"
    );
    assert_eq!(
        s.settings().unwrap().audit_retention_days,
        365,
        "settings restored"
    );
    let changes = s.policy_changes(100).unwrap();
    assert_eq!(changes.len(), changes_before + 1);
    assert_eq!(changes[0].action, "policy_restored");
    assert_eq!(event_count(&s), events_before + 1, "audit log only grows");
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { .. }
    ));
    let restored = s
        .list_events(&EventFilter {
            kind: Some("policy_restored".into()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(restored[0].details["restore_id"], "r-1");
    assert_eq!(restored[0].details["backup_sha256"], rec.sha256);
    assert_eq!(restored[0].details["from_policy_version"], 2);
}

#[test]
fn stale_restore_is_refused_atomically() {
    let dir = TempDir::new("restore-stale");
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let rec = s.create_backup(&dir.0, BackupKind::Manual, "t").unwrap();
    let cand = s.inspect_backup(&dir.0, &rec.file_name).unwrap();
    kingston_allowed(&mut s);
    let before = event_count(&s);
    assert!(matches!(
        s.apply_restored_state(&cand, 1, "r", "t"),
        Err(StorageError::VersionConflict {
            expected: 1,
            active: 2
        })
    ));
    assert_eq!(s.active_policy().unwrap().unwrap().version, 2);
    assert_eq!(event_count(&s), before);
}

#[test]
fn foreign_altered_missing_and_traversal_backups_are_rejected() {
    let dir = TempDir::new("restore-reject");
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let rec = s.create_backup(&dir.0, BackupKind::Manual, "t").unwrap();

    for bad in [
        "../rustward-backup-1.db",
        "..\\x.db",
        "C:rustward-backup-1.db",
        "sub/rustward-backup-1.db",
        "other.db",
    ] {
        assert_eq!(
            rejection(s.inspect_backup(&dir.0, bad).unwrap_err()),
            BackupRejection::InvalidName,
            "{bad}"
        );
    }
    // A valid-looking RustWard database that this installation did not register.
    let foreign = dir.0.join("rustward-backup-42.db");
    s.backup_to(&foreign).unwrap();
    assert_eq!(
        rejection(
            s.inspect_backup(&dir.0, "rustward-backup-42.db")
                .unwrap_err()
        ),
        BackupRejection::NotRegistered
    );
    // Altered after registration.
    let path = dir.0.join(&rec.file_name);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        rejection(s.inspect_backup(&dir.0, &rec.file_name).unwrap_err()),
        BackupRejection::HashMismatch
    );
    // Replaced by a directory, then missing.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(
        rejection(s.inspect_backup(&dir.0, &rec.file_name).unwrap_err()),
        BackupRejection::NotRegularFile
    );
    std::fs::remove_dir(&path).unwrap();
    assert_eq!(
        rejection(s.inspect_backup(&dir.0, &rec.file_name).unwrap_err()),
        BackupRejection::Missing
    );
    // No temporary inspection copies are left behind.
    assert!(
        std::fs::read_dir(&dir.0).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp"))
    );
}

fn register_raw(s: &Store, dir: &std::path::Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).unwrap();
    s.connection_for_tests()
        .execute(
            "INSERT INTO backups (file_name, sha256, bytes, created_ms, policy_version, kind, actor)
             VALUES (?1, ?2, ?3, 0, 1, 'manual', 'test')",
            params![name, rustward_storage::sha256_hex(bytes), bytes.len() as i64],
        )
        .unwrap();
}

#[test]
fn registered_but_invalid_backups_are_rejected() {
    let dir = TempDir::new("restore-invalid");
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    register_raw(
        &s,
        &dir.0,
        "rustward-backup-1.db",
        b"this is not sqlite at all, not even close......",
    );
    assert_eq!(
        rejection(
            s.inspect_backup(&dir.0, "rustward-backup-1.db")
                .unwrap_err()
        ),
        BackupRejection::Corrupt
    );

    let plain = dir.0.join("plain.sqlite");
    rusqlite::Connection::open(&plain)
        .unwrap()
        .execute_batch("CREATE TABLE x (a);")
        .unwrap();
    register_raw(
        &s,
        &dir.0,
        "rustward-backup-2.db",
        &std::fs::read(&plain).unwrap(),
    );
    assert_eq!(
        rejection(
            s.inspect_backup(&dir.0, "rustward-backup-2.db")
                .unwrap_err()
        ),
        BackupRejection::NotRustWard
    );

    let empty_rw = dir.0.join("empty-rw.sqlite");
    drop(Store::open(&empty_rw, clock()).unwrap());
    register_raw(
        &s,
        &dir.0,
        "rustward-backup-3.db",
        &std::fs::read(&empty_rw).unwrap(),
    );
    assert_eq!(
        rejection(
            s.inspect_backup(&dir.0, "rustward-backup-3.db")
                .unwrap_err()
        ),
        BackupRejection::InvalidPolicy
    );

    let newer = dir.0.join("newer.sqlite");
    {
        let mut n = Store::open(&newer, clock()).unwrap();
        n.initialize_policy(&state(), "t").unwrap();
        n.connection_for_tests()
            .execute(
                "INSERT INTO schema_migrations (version, applied_ms) VALUES (999, 0)",
                [],
            )
            .unwrap();
        n.connection_for_tests()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }
    register_raw(
        &s,
        &dir.0,
        "rustward-backup-4.db",
        &std::fs::read(&newer).unwrap(),
    );
    assert_eq!(
        rejection(
            s.inspect_backup(&dir.0, "rustward-backup-4.db")
                .unwrap_err()
        ),
        BackupRejection::SchemaTooNew
    );
}

#[test]
fn audit_and_history_tables_are_append_only_for_application_code() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    s.append_event(&event("device_detected", Severity::Info, true))
        .unwrap();
    kingston_allowed(&mut s);
    let conn = s.connection_for_tests();
    for sql in [
        "UPDATE security_events SET message = 'x'",
        "DELETE FROM security_events",
        "UPDATE policy_changes SET actor = 'x'",
        "DELETE FROM policy_changes",
        "UPDATE policy_states SET state_json = '{}'",
        "DELETE FROM policy_states",
    ] {
        let err = conn.execute(sql, []).unwrap_err().to_string();
        assert!(
            err.contains("append-only")
                || err.contains("immutable")
                || err.contains("never deleted")
                || err.contains("only by retention"),
            "{sql}: {err}"
        );
    }
    // Switching the active flag (a normal policy commit) remains possible.
    assert_eq!(s.active_policy().unwrap().unwrap().version, 2);
}

#[test]
fn v1_database_upgrades_to_v2_keeping_data_and_gaining_guards() {
    let dir = TempDir::new("migrate-v1");
    let path = dir.0.join("v1.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_ms INTEGER NOT NULL);",
        )
        .unwrap();
        conn.execute_batch(rustward_storage::migrations::MIGRATIONS[0].1)
            .unwrap();
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_ms) VALUES (1, 0)",
            [],
        )
        .unwrap();
    }
    {
        // Write v1-era data with the v1 schema only (no triggers yet).
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO security_events (utc_ms, severity, kind, device_key, message, simulated, enforcement_state, policy_version, details_json, prev_hash, hash)
             VALUES (1, 'info', 'legacy_event', NULL, 'from v1', 0, 'n/a', NULL, '{}', 'x', 'y')",
            [],
        )
        .unwrap();
    }
    let s = Store::open(&path, clock()).unwrap();
    assert_eq!(s.schema_version().unwrap(), 2);
    let ev = s
        .list_events(&EventFilter {
            kind: Some("legacy_event".into()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(ev.len(), 1, "v1 events are kept");
    assert!(s.list_backups().unwrap().is_empty());
    assert!(
        s.connection_for_tests()
            .execute("DELETE FROM security_events", [])
            .is_err(),
        "guards are active after the upgrade"
    );
}

#[test]
fn external_checkpoints_reveal_rewrites_truncation_and_resequencing() {
    let dir = TempDir::new("checkpoint");
    let db = dir.0.join("rustward.db");
    let mut s = Store::open(&db, clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    for _ in 0..3 {
        s.append_event(&event("device_arrived", Severity::Info, true))
            .unwrap();
    }
    let cp = s.record_audit_checkpoint().unwrap();
    let prefix: String = cp.head_hash.chars().take(16).collect();
    assert_eq!(
        s.check_checkpoint(cp.head_id, &prefix).unwrap(),
        CheckpointCheck::Matches
    );
    // The value as Event Viewer shows it ("…" suffix) is accepted.
    assert_eq!(
        s.check_checkpoint(cp.head_id, &format!("{prefix}…"))
            .unwrap(),
        CheckpointCheck::Matches
    );
    // Read-only check of the file (as run while the service holds it open).
    assert_eq!(
        rustward_storage::check_checkpoint_file(&db, cp.head_id, &prefix).unwrap(),
        CheckpointCheck::Matches
    );

    // Malformed input is refused, not treated as a mismatch.
    for bad in ["", "abc", "zzzzzzzzzzzzzzzz", "0123456789abcde"] {
        assert!(matches!(
            s.check_checkpoint(cp.head_id, bad),
            Err(StorageError::Invalid(_))
        ));
    }
    assert!(s.check_checkpoint(0, &prefix).is_err());

    // Attacker with file access rewrites history consistently: deletes the
    // newest events, resets the AUTOINCREMENT counter and recomputes nothing
    // else. The internal chain verifies again, but the external checkpoint
    // does not.
    s.connection_for_tests()
        .execute_batch(&format!(
            "DROP TRIGGER security_events_retention_only_delete;
             DELETE FROM security_events WHERE id >= {};
             UPDATE sqlite_sequence SET seq = {} WHERE name = 'security_events';",
            cp.head_id,
            cp.head_id - 1
        ))
        .unwrap();
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { .. }
    ));
    assert_eq!(
        s.check_checkpoint(cp.head_id, &prefix).unwrap(),
        CheckpointCheck::EventMissing
    );
    // Then appends a forged event with the same id: hash differs.
    s.append_event(&event("device_removed", Severity::Info, true))
        .unwrap();
    assert!(matches!(
        s.check_checkpoint(cp.head_id, &prefix).unwrap(),
        CheckpointCheck::HashDiffers { .. }
    ));
    // Events older than the oldest remaining one cannot be judged.
    s.connection_for_tests()
        .execute_batch("DELETE FROM security_events WHERE id <= 2;")
        .unwrap();
    assert_eq!(
        s.check_checkpoint(1, &prefix).unwrap(),
        CheckpointCheck::OlderThanRetention { oldest_id: 3 }
    );
}

#[test]
fn concurrent_first_opens_of_a_new_database_serialise_cleanly() {
    // F-19: two processes (service + a second instance, or service + tool)
    // creating the database at the same time used to race on the DDL.
    for round in 0..5 {
        let dir = TempDir::new(&format!("race{round}"));
        let db = dir.0.join("rustward.db");
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (db, barrier) = (db.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut s = Store::open(&db, clock())?;
                    s.initialize_policy(&state(), "t")
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for r in &results {
            assert!(r.is_ok(), "round {round}: {r:?}");
        }
        let created = results.iter().filter(|r| matches!(r, Ok(true))).count();
        assert_eq!(created, 1, "exactly one opener initialises the policy");
        let s = Store::open(&db, clock()).unwrap();
        let versions: i64 = s
            .connection_for_tests()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(versions, 2, "each migration recorded once");
        assert!(matches!(
            s.verify_chain().unwrap(),
            ChainStatus::Intact { entries: 1 }
        ));
    }
}
