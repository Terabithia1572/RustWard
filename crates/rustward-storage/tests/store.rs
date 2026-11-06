//! Storage integration tests (temporary databases only).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use rusqlite::params;
use rustward_core::policy_edit::{PolicyEdit, PolicyState, apply_edit};
use rustward_storage::{
    AppSettings, ChainStatus, DeviceRow, EventFilter, EventObserver, ManualClock, NewEvent,
    SecurityEvent, Severity, StorageError, Store,
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
    s.connection_for_tests()
        .execute(
            "UPDATE policy_states SET state_json = replace(state_json, 'sandisk', 'kingston') WHERE active = 1",
            [],
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
    s.connection_for_tests()
        .execute(
            "UPDATE security_events SET message = 'edited' WHERE kind = 'b_event'",
            [],
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
fn backup_and_restore_round_trip_and_reject_bad_files() {
    let dir = TempDir::new("backup");
    let c = clock();
    let mut s = Store::open_in_memory(c.clone()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let backup = dir.0.join("backup.db");
    s.backup_to(&backup).unwrap();
    assert!(
        s.backup_to(&backup).is_err(),
        "never overwrite an existing file"
    );

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
    assert_eq!(s.active_policy().unwrap().unwrap().version, 2);

    s.restore_from(&backup, "t").unwrap();
    assert_eq!(s.active_policy().unwrap().unwrap().version, 1);
    assert_eq!(
        s.list_events(&EventFilter::default()).unwrap()[0].kind,
        "database_restored"
    );

    let junk = dir.0.join("junk.db");
    std::fs::write(&junk, b"this is not sqlite").unwrap();
    assert!(s.restore_from(&junk, "t").is_err());
    let empty = dir.0.join("empty.db");
    rusqlite::Connection::open(&empty)
        .unwrap()
        .execute_batch("CREATE TABLE x (a);")
        .unwrap();
    assert!(s.restore_from(&empty, "t").is_err());
    assert_eq!(
        s.active_policy().unwrap().unwrap().version,
        1,
        "failed restores change nothing"
    );
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
}

impl EventObserver for Recorder {
    fn on_event(&self, event: &SecurityEvent) -> Result<(), String> {
        self.seen
            .lock()
            .unwrap()
            .push((event.id, event.kind.clone()));
        if self.fail_kind == Some(event.kind.as_str()) {
            Err("sink unavailable".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn observer_receives_every_committed_event_once_in_order() {
    let c = clock();
    let mut s = Store::open_in_memory(c.clone()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    // History before attaching is not replayed.
    let rec = Arc::new(Recorder::default());
    s.set_event_observer(rec.clone()).unwrap();
    assert!(s.mirror_status().attached);

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
    assert_eq!(kinds[0], "device_arrived");
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
}

#[test]
fn observer_failures_never_block_or_roll_back_writes() {
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    let rec = Arc::new(Recorder {
        fail_kind: Some("device_arrived"),
        ..Recorder::default()
    });
    s.set_event_observer(rec.clone()).unwrap();
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
    assert_eq!((st.delivered, st.failures), (1, 1));
    assert!(matches!(
        s.verify_chain().unwrap(),
        ChainStatus::Intact { .. }
    ));
}

#[test]
fn restore_does_not_replay_restored_history_into_the_observer() {
    let dir = TempDir::new("mirror-restore");
    let mut s = Store::open_in_memory(clock()).unwrap();
    s.initialize_policy(&state(), "t").unwrap();
    for _ in 0..5 {
        s.append_event(&event("device_arrived", Severity::Info, true))
            .unwrap();
    }
    let backup = dir.0.join("b.db");
    s.backup_to(&backup).unwrap();
    let rec = Arc::new(Recorder::default());
    s.set_event_observer(rec.clone()).unwrap();
    s.restore_from(&backup, "t").unwrap();
    let kinds: Vec<_> = rec
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(_, k)| k.clone())
        .collect();
    assert_eq!(kinds, ["database_restored"]);
}
