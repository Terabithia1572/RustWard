//! Read-only Windows Terminal Services (WTS) interactive session enumeration.
//!
//! Used by `rustward-service` / `rustward-app` to attribute USB audit events to
//! a logged-on Windows user ONLY when an active interactive user session is
//! unambiguously identified. If zero or multiple active interactive sessions
//! exist simultaneously, [`resolve_single_interactive_user`] returns `None` so
//! the audit log never guesses an identity.

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSDomainName,
    WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
};

/// One interactive or console Windows session discovered via WTS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveSession {
    /// Numeric Windows session ID (`0` is Session 0 services).
    pub session_id: u32,
    /// Windows account username, if associated with the session.
    pub username: String,
    /// Optional domain or workstation authority name.
    pub domain: Option<String>,
    /// Whether the session is currently in `WTSActive` state.
    pub is_active: bool,
}

/// Resolves an unambiguous active interactive Windows account (`DOMAIN\user` or
/// `user`). Returns `None` when zero active user sessions exist or when two or
/// more distinct active interactive accounts are logged in simultaneously.
#[must_use]
pub fn resolve_single_interactive_user(sessions: &[InteractiveSession]) -> Option<String> {
    let mut resolved: Option<String> = None;
    let mut resolved_key: Option<String> = None;
    for session in sessions {
        if session.session_id == 0 || !session.is_active {
            continue;
        }
        let user = session.username.trim();
        if user.is_empty() {
            continue;
        }
        let formatted = match session.domain.as_deref().map(str::trim) {
            Some(dom) if !dom.is_empty() => format!("{dom}\\{user}"),
            _ => user.to_owned(),
        };
        let key = formatted.to_ascii_lowercase();
        match &resolved_key {
            None => {
                resolved_key = Some(key);
                resolved = Some(formatted);
            }
            Some(existing) if existing == &key => {}
            Some(_) => return None,
        }
    }
    resolved
}

#[cfg(windows)]
struct WtsBuffer(*mut c_void);

#[cfg(windows)]
impl Drop for WtsBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Pointer came from `WTSEnumerateSessionsW` or `WTSQuerySessionInformationW`
            // and is freed once via `WTSFreeMemory`.
            unsafe {
                WTSFreeMemory(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

#[cfg(windows)]
fn query_wts_string(session_id: u32, info_class: i32) -> Option<String> {
    let mut raw: *mut u16 = ptr::null_mut();
    let mut bytes: u32 = 0;
    // SAFETY: Queries read-only WTS string property; buffer freed by `WtsBuffer::drop`.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            info_class,
            &mut raw,
            &mut bytes,
        )
    };
    let _guard = WtsBuffer(raw.cast());
    if ok == 0 || raw.is_null() || bytes < 2 {
        return None;
    }
    let units = usize::try_from(bytes / 2).ok()?;
    // SAFETY: `WTSQuerySessionInformationW` guarantees at least `bytes` valid bytes at `raw`.
    let slice = unsafe { std::slice::from_raw_parts(raw, units) };
    let nul_pos = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    let decoded = String::from_utf16_lossy(&slice[..nul_pos]);
    let trimmed = decoded.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Enumerates Windows sessions via `WTSEnumerateSessionsW` and returns non-Session-0
/// sessions that have an associated username.
///
/// # Errors
/// Returns an error off Windows or if `WTSEnumerateSessionsW` fails.
pub fn enumerate_interactive_sessions() -> Result<Vec<InteractiveSession>, String> {
    #[cfg(windows)]
    {
        let mut raw: *mut WTS_SESSION_INFOW = ptr::null_mut();
        let mut count: u32 = 0;
        // SAFETY: Read-only enumeration against current local server; memory freed by `WtsBuffer`.
        let ok = unsafe {
            WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut raw, &mut count)
        };
        let _guard = WtsBuffer(raw.cast());
        if ok == 0 {
            return Err("WTSEnumerateSessionsW failed".to_owned());
        }
        if raw.is_null() || count == 0 {
            return Ok(Vec::new());
        }
        let len = usize::try_from(count).map_err(|_| "WTS session count overflow".to_owned())?;
        // SAFETY: `WTSEnumerateSessionsW` populated `count` valid `WTS_SESSION_INFOW` structs.
        let infos = unsafe { std::slice::from_raw_parts(raw, len) };
        let mut out = Vec::new();
        for info in infos {
            if info.SessionId == 0 {
                continue;
            }
            let Some(username) = query_wts_string(info.SessionId, WTSUserName) else {
                continue;
            };
            let domain = query_wts_string(info.SessionId, WTSDomainName);
            out.push(InteractiveSession {
                session_id: info.SessionId,
                username,
                domain,
                is_active: info.State == WTSActive,
            });
        }
        Ok(out)
    }
    #[cfg(not(windows))]
    {
        Err("WTS session enumeration requires Windows".to_owned())
    }
}

/// Returns the unambiguous active interactive Windows account (`DOMAIN\user` or
/// `user`), or `None` when none or multiple distinct active sessions exist.
#[must_use]
pub fn current_single_interactive_windows_user() -> Option<String> {
    enumerate_interactive_sessions()
        .ok()
        .and_then(|sessions| resolve_single_interactive_user(&sessions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_single_active_user_and_ignores_session_zero_and_ambiguous() {
        assert_eq!(resolve_single_interactive_user(&[]), None);

        // Session 0 is ignored even if active.
        assert_eq!(
            resolve_single_interactive_user(&[InteractiveSession {
                session_id: 0,
                username: "SYSTEM".into(),
                domain: Some("NT AUTHORITY".into()),
                is_active: true,
            }]),
            None
        );

        // Disconnected user + single active user resolves deterministically.
        assert_eq!(
            resolve_single_interactive_user(&[
                InteractiveSession {
                    session_id: 1,
                    username: "bob".into(),
                    domain: Some("PC01".into()),
                    is_active: false,
                },
                InteractiveSession {
                    session_id: 2,
                    username: "alice".into(),
                    domain: Some("CORP".into()),
                    is_active: true,
                },
            ]),
            Some("CORP\\alice".into())
        );

        // Multiple active accounts must return None rather than guessing.
        assert_eq!(
            resolve_single_interactive_user(&[
                InteractiveSession {
                    session_id: 1,
                    username: "alice".into(),
                    domain: Some("CORP".into()),
                    is_active: true,
                },
                InteractiveSession {
                    session_id: 2,
                    username: "bob".into(),
                    domain: Some("CORP".into()),
                    is_active: true,
                },
            ]),
            None
        );
    }
}
