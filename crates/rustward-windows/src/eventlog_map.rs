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
    ("service_start_failed", 1008),
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
    ("restore_prepared", 5005),
    ("restore_failed", 5006),
    ("policy_restored", 5007),
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

/// Text of every message-table entry: the event's single insertion
/// string. [`render_message`] already produces a complete, self-describing
/// text (kind, message, simulation marker, enforcement state, policy
/// version, audit id), so Event Viewer shows it verbatim instead of the
/// "description for Event ID … cannot be found" preamble.
pub const MESSAGE_TEXT: &str = "%1\r\n";

/// `MESSAGE_RESOURCE_UNICODE`.
const MESSAGE_RESOURCE_UNICODE: u16 = 0x0001;

/// Every event ID RustWard can write, sorted and unique.
#[must_use]
pub fn message_table_ids() -> Vec<u32> {
    let mut ids: Vec<u32> = EVENT_IDS.iter().map(|(_, id)| *id).collect();
    ids.push(EVENT_ID_OTHER);
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Build the binary `MESSAGETABLE` resource (`MESSAGE_RESOURCE_DATA`) for
/// [`message_table_ids`]. Embedded into `rustward-service.exe` by its
/// `build.rs` on Windows; the installer registers that executable as the
/// `EventMessageFile` of the `RustWard` source.
///
/// Layout: `u32` block count; per block `{u32 low, u32 high, u32 offset}`;
/// then per ID a `MESSAGE_RESOURCE_ENTRY {u16 length, u16 flags, text}`
/// with UTF-16LE NUL-terminated text, each entry padded to 4 bytes.
#[must_use]
pub fn message_table_resource() -> Vec<u8> {
    let ids = message_table_ids();
    // Contiguous ranges.
    let mut blocks: Vec<(u32, u32)> = Vec::new();
    for id in ids {
        match blocks.last_mut() {
            Some((_, high)) if *high + 1 == id => *high = id,
            _ => blocks.push((id, id)),
        }
    }
    let mut text: Vec<u8> = MESSAGE_TEXT
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    while !(4 + text.len()).is_multiple_of(4) {
        text.push(0);
    }
    let entry_len = 4 + text.len();
    let mut entry = Vec::with_capacity(entry_len);
    entry.extend_from_slice(&u16::try_from(entry_len).unwrap_or(u16::MAX).to_le_bytes());
    entry.extend_from_slice(&MESSAGE_RESOURCE_UNICODE.to_le_bytes());
    entry.extend_from_slice(&text);

    let header_len = 4 + 12 * blocks.len();
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(blocks.len()).unwrap_or(0).to_le_bytes());
    let mut offset = header_len;
    for (low, high) in &blocks {
        out.extend_from_slice(&low.to_le_bytes());
        out.extend_from_slice(&high.to_le_bytes());
        out.extend_from_slice(&u32::try_from(offset).unwrap_or(0).to_le_bytes());
        offset += entry_len * usize::try_from(high - low + 1).unwrap_or(0);
    }
    for (low, high) in &blocks {
        for _ in *low..=*high {
            out.extend_from_slice(&entry);
        }
    }
    out
}

/// Resource script for `embed-resource` (message tables are resource type
/// 11, conventionally with ID 1).
#[must_use]
pub fn message_table_rc(bin_file_name: &str) -> String {
    format!("1 11 \"{bin_file_name}\"\r\n")
}

/// Look an ID up in a `MESSAGE_RESOURCE_DATA` blob the way `FormatMessage`
/// does (used by tests to validate [`message_table_resource`]).
#[must_use]
pub fn message_table_lookup(data: &[u8], id: u32) -> Option<String> {
    let u32_at = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
    };
    let u16_at = |o: usize| -> Option<u16> {
        Some(u16::from_le_bytes(data.get(o..o + 2)?.try_into().ok()?))
    };
    let count = usize::try_from(u32_at(0)?).ok()?;
    for b in 0..count {
        let base = 4 + 12 * b;
        let (low, high) = (u32_at(base)?, u32_at(base + 4)?);
        if !(low..=high).contains(&id) {
            continue;
        }
        let mut o = usize::try_from(u32_at(base + 8)?).ok()?;
        for _ in low..id {
            o += usize::from(u16_at(o)?);
        }
        let len = usize::from(u16_at(o)?);
        if u16_at(o + 2)? != MESSAGE_RESOURCE_UNICODE || len < 4 || !len.is_multiple_of(4) {
            return None;
        }
        let units: Vec<u16> = data
            .get(o + 4..o + len)?
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|u| *u != 0)
            .collect();
        return String::from_utf16(&units).ok();
    }
    None
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
    fn message_table_resolves_every_event_id_and_nothing_else() {
        let data = message_table_resource();
        assert_eq!(data.len() % 4, 0);
        let ids = message_table_ids();
        assert!(ids.contains(&EVENT_ID_OTHER) && ids.contains(&1008));
        for id in &ids {
            assert_eq!(
                message_table_lookup(&data, *id).as_deref(),
                Some(MESSAGE_TEXT),
                "id {id}"
            );
        }
        for missing in [0, 999, 1009, 4001, 5004, 8999, 9001] {
            assert_eq!(message_table_lookup(&data, missing), None, "{missing}");
        }
        // Blocks are contiguous ranges: 1000-1008, 2000-2002, 2100-2101, ...
        let blocks = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(blocks, 10);
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1000);
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 1008);
        assert_eq!(
            u32::from_le_bytes(data[12..16].try_into().unwrap()),
            4 + 12 * blocks,
            "first entries follow the block table"
        );
        assert_eq!(message_table_rc("m.bin"), "1 11 \"m.bin\"\r\n");
    }

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
