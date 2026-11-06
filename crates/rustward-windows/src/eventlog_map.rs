//! Platform-neutral mapping of RustWard audit events to Windows Event Log
//! entries: entry type, a stable event ID per event kind, and a bounded
//! message that always states whether the event is a simulation and that
//! enforcement is not verified.
//!
//! The Event Log is a *complement* to the hash-chained SQLite audit log, not
//! a replacement. Entries are written under the source [`EVENT_SOURCE`];
//! registering that source (and a message file) in the registry is an
//! installer task (see `docs/OFFLINE-DEPLOYMENT.md`) and is never done by
//! RustWard at runtime.

use windows_sys::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

/// Event source name.
pub const EVENT_SOURCE: &str = "RustWard";

/// Maximum characters in one Event Log string (the API limit is 31 839).
pub const MAX_EVENT_MESSAGE_CHARS: usize = 4_000;

/// Severity independent of the storage crate (avoids a dependency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Critical / error.
    Critical,
}

/// Event Log entry type for a level.
#[must_use]
pub fn entry_type(level: EventLevel) -> REPORT_EVENT_TYPE {
    match level {
        EventLevel::Info => EVENTLOG_INFORMATION_TYPE,
        EventLevel::Warning => EVENTLOG_WARNING_TYPE,
        EventLevel::Critical => EVENTLOG_ERROR_TYPE,
    }
}

/// Stable event IDs. Never renumber: administrators may filter on them.
pub const EVENT_IDS: &[(&str, u32)] = &[
    ("service_started", 1000),
    ("service_stopping", 1001),
    ("service_degraded", 1002),
    ("service_recovered", 1003),
    ("backend_started", 1004),
    ("ipc_error", 1005),
    ("event_log_unavailable", 1006),
    ("device_notifications_unavailable", 1007),
    ("device_detected", 2000),
    ("device_removed", 2001),
    ("device_reenumerated", 2002),
    ("decision_simulated", 2100),
    ("decisions_reevaluated", 2101),
    ("inventory_failed", 2200),
    ("inventory_warnings", 2201),
    ("policy_initialized", 3000),
    ("policy_changed", 3001),
    ("settings_changed", 3100),
    ("authorization_failed", 4000),
    ("database_restored", 5000),
    ("backup_created", 5001),
    ("retention_applied", 5002),
    ("audit_exported", 5003),
    ("audit_history_replaced", 5004),
];

/// Event ID used for kinds not in [`EVENT_IDS`].
pub const EVENT_ID_OTHER: u32 = 9000;

/// Event ID for a kind.
#[must_use]
pub fn event_id(kind: &str) -> u32 {
    EVENT_IDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(EVENT_ID_OTHER, |(_, id)| *id)
}

/// Render the single message string of an entry. Control characters are
/// replaced and the length is bounded.
#[must_use]
pub fn render_message(
    kind: &str,
    message: &str,
    simulated: bool,
    enforcement_state: &str,
    policy_version: Option<u64>,
    audit_id: i64,
) -> String {
    let marker = if simulated { "[SIMULATION] " } else { "" };
    let version = policy_version.map_or_else(|| "-".to_owned(), |v| v.to_string());
    let raw = format!(
        "{marker}{kind}: {message}\r\nenforcement: {enforcement_state} (RustWard enforcement NOT VERIFIED)\r\npolicy version: {version}\r\naudit id: {audit_id}"
    );
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_control() && c != '\r' && c != '\n' {
                ' '
            } else {
                c
            }
        })
        .collect();
    if cleaned.chars().count() <= MAX_EVENT_MESSAGE_CHARS {
        cleaned
    } else {
        let mut t: String = cleaned.chars().take(MAX_EVENT_MESSAGE_CHARS - 3).collect();
        t.push_str("...");
        t
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn levels_map_to_event_types() {
        assert_eq!(entry_type(EventLevel::Info), EVENTLOG_INFORMATION_TYPE);
        assert_eq!(entry_type(EventLevel::Warning), EVENTLOG_WARNING_TYPE);
        assert_eq!(entry_type(EventLevel::Critical), EVENTLOG_ERROR_TYPE);
    }

    #[test]
    fn event_ids_are_unique_and_stable() {
        let ids: HashSet<_> = EVENT_IDS.iter().map(|(_, i)| *i).collect();
        let kinds: HashSet<_> = EVENT_IDS.iter().map(|(k, _)| *k).collect();
        assert_eq!(ids.len(), EVENT_IDS.len());
        assert_eq!(kinds.len(), EVENT_IDS.len());
        assert!(!ids.contains(&EVENT_ID_OTHER));
        assert_eq!(event_id("device_detected"), 2000);
        assert_eq!(event_id("something_new"), EVENT_ID_OTHER);
    }

    #[test]
    fn messages_mark_simulation_and_unverified_enforcement() {
        let m = render_message(
            "decision_simulated",
            "Kingston denied (simulated)",
            true,
            "simulated",
            Some(4),
            17,
        );
        assert!(m.starts_with("[SIMULATION] decision_simulated: "));
        assert!(m.contains("NOT VERIFIED"));
        assert!(m.contains("policy version: 4"));
        assert!(m.contains("audit id: 17"));
        assert!(
            !m.to_lowercase().contains("engellenmi"),
            "never the verified-block notice"
        );
        let real = render_message("policy_changed", "x", false, "n/a", None, 1);
        assert!(!real.contains("[SIMULATION]"));
        assert!(real.contains("policy version: -"));
    }

    #[test]
    fn messages_are_bounded_and_sanitized() {
        let long = "x".repeat(10_000);
        let m = render_message("k", &long, false, "n/a", None, 1);
        assert_eq!(m.chars().count(), MAX_EVENT_MESSAGE_CHARS);
        assert!(m.ends_with("..."));
        let c = render_message("k", "a\u{0}b\u{7}c", false, "n/a", None, 1);
        assert!(c.contains("a b c"));
    }
}
