//! Windows Event Log writer (`RegisterEventSourceW` / `ReportEventW`).
//! **NOT VERIFIED ON WINDOWS** (type-checked on other hosts with
//! `host-typecheck`).
//!
//! Writes only to the Application log under [`EVENT_SOURCE`]. It never
//! creates registry keys: if the installer has not registered the source,
//! Windows still records the entry but Event Viewer shows a "description
//! not found" prefix before the message string. Entry types, event IDs and
//! the message text come from [`crate::eventlog_map`].

use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW,
};

use crate::eventlog_map::{EVENT_SOURCE, EventLevel, entry_type};

/// Event Log errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{api} failed with Win32 error {code}")]
pub struct EventLogError {
    /// Function.
    pub api: &'static str,
    /// `GetLastError()`.
    pub code: u32,
}

/// An open event source handle (deregistered on drop).
pub struct WindowsEventLog {
    handle: HANDLE,
}

// SAFETY: event source handles may be used from any thread; ReportEventW is
// thread-safe and the handle is only closed in Drop.
unsafe impl Send for WindowsEventLog {}
// SAFETY: as above; `report` takes `&self` and performs one independent call.
unsafe impl Sync for WindowsEventLog {}

impl std::fmt::Debug for WindowsEventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsEventLog").finish_non_exhaustive()
    }
}

fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl WindowsEventLog {
    /// Open the RustWard event source on the local computer.
    pub fn open() -> Result<Self, EventLogError> {
        let source = wide(EVENT_SOURCE);
        // SAFETY: null server name means the local computer; `source` is a
        // NUL-terminated UTF-16 string valid for the call.
        let handle = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
        if handle.is_null() {
            return Err(EventLogError {
                api: "RegisterEventSourceW",
                code: last_error(),
            });
        }
        Ok(Self { handle })
    }

    /// Write one entry with a single message string.
    pub fn report(
        &self,
        level: EventLevel,
        event_id: u32,
        message: &str,
    ) -> Result<(), EventLogError> {
        let text = wide(message);
        let strings = [text.as_ptr()];
        // SAFETY: `self.handle` is a live event source handle; `strings`
        // holds one valid NUL-terminated UTF-16 pointer that outlives the
        // call; no user SID and no raw data are passed.
        let ok = unsafe {
            ReportEventW(
                self.handle,
                entry_type(level),
                0,
                event_id,
                ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                ptr::null(),
            )
        };
        if ok == 0 {
            Err(EventLogError {
                api: "ReportEventW",
                code: last_error(),
            })
        } else {
            Ok(())
        }
    }
}

impl Drop for WindowsEventLog {
    fn drop(&mut self) {
        // SAFETY: `handle` came from a successful RegisterEventSourceW and
        // is deregistered exactly once.
        unsafe {
            DeregisterEventSource(self.handle);
        }
    }
}
