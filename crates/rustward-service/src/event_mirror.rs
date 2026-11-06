//! Mirrors committed audit events into the Windows Event Log.
//!
//! The mapping (entry type, event ID, message) is platform-neutral and
//! tested here with a fake writer; the real writer is
//! `rustward_windows::event_log::WindowsEventLog` (Windows only, NOT
//! VERIFIED). A failing writer never affects the SQLite audit log.

use rustward_storage::{EventObserver, SecurityEvent, Severity};
use rustward_windows::eventlog_map::{EventLevel, event_id, render_message};

/// Something that can write one Event Log entry.
pub trait EventWriter: Send + Sync {
    /// Write an entry.
    fn write(&self, level: EventLevel, event_id: u32, message: &str) -> Result<(), String>;
}

#[cfg(any(windows, feature = "host-typecheck"))]
impl EventWriter for rustward_windows::event_log::WindowsEventLog {
    fn write(&self, level: EventLevel, event_id: u32, message: &str) -> Result<(), String> {
        self.report(level, event_id, message)
            .map_err(|e| e.to_string())
    }
}

/// [`EventObserver`] that forwards to an [`EventWriter`].
#[derive(Debug)]
pub struct EventLogMirror<W> {
    writer: W,
}

impl<W: EventWriter> EventLogMirror<W> {
    /// Wrap a writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

fn level(s: Severity) -> EventLevel {
    match s {
        Severity::Info => EventLevel::Info,
        Severity::Warning => EventLevel::Warning,
        Severity::Critical => EventLevel::Critical,
    }
}

impl<W: EventWriter> EventObserver for EventLogMirror<W> {
    fn on_event(&self, e: &SecurityEvent) -> Result<(), String> {
        let message = render_message(
            &e.kind,
            &e.message,
            e.simulated,
            &e.enforcement_state,
            e.policy_version,
            e.id,
        );
        self.writer
            .write(level(e.severity), event_id(&e.kind), &message)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Fake {
        entries: Mutex<Vec<(EventLevel, u32, String)>>,
        fail: bool,
    }

    impl EventWriter for Fake {
        fn write(&self, level: EventLevel, event_id: u32, message: &str) -> Result<(), String> {
            if self.fail {
                return Err("ReportEventW failed".into());
            }
            self.entries
                .lock()
                .unwrap()
                .push((level, event_id, message.to_owned()));
            Ok(())
        }
    }

    fn event(kind: &str, severity: Severity, simulated: bool) -> SecurityEvent {
        SecurityEvent {
            id: 42,
            utc_ms: 0,
            severity,
            kind: kind.into(),
            device_key: Some("k".into()),
            message: "Kingston DataTraveler denied".into(),
            simulated,
            enforcement_state: "simulated".into(),
            policy_version: Some(3),
            details: serde_json::json!({}),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn maps_severity_id_and_simulation_marker() {
        let m = EventLogMirror::new(Fake::default());
        m.on_event(&event("decision_simulated", Severity::Warning, true))
            .unwrap();
        m.on_event(&event("authorization_failed", Severity::Warning, false))
            .unwrap();
        m.on_event(&event("service_degraded", Severity::Critical, false))
            .unwrap();
        let e = m.writer.entries.lock().unwrap();
        assert_eq!((e[0].0, e[0].1), (EventLevel::Warning, 2100));
        assert!(
            e[0].2
                .starts_with("[SIMULATION] decision_simulated: Kingston")
        );
        assert!(e[0].2.contains("audit id: 42"));
        assert_eq!(e[1].1, 4000);
        assert!(!e[1].2.contains("[SIMULATION]"));
        assert_eq!(e[2].0, EventLevel::Critical);
        assert!(e.iter().all(|x| x.2.contains("NOT VERIFIED")));
    }

    #[test]
    fn writer_errors_are_returned_to_the_store() {
        let m = EventLogMirror::new(Fake {
            fail: true,
            ..Fake::default()
        });
        assert!(
            m.on_event(&event("policy_changed", Severity::Info, false))
                .is_err()
        );
    }
}
