//! `rustward-notifier` — Out-of-Session-0 per-user desktop notification agent.
//!
//! Security boundary:
//! - Runs strictly in the logged-on user's desktop session with zero elevation.
//! - Connects ONLY to `PIPE_NAME_STATUS` (`AccessLevel::ReadOnly`) and calls ONLY
//!   `Request::GetNotificationFeed`.
//! - Persists cursor and user preferences strictly per user under `%LOCALAPPDATA%\RustWard\notifier-prefs.json`.
//! - Continues notifying whenever `RustWardService` runs, even when the desktop UI is closed.

#![cfg_attr(windows, windows_subsystem = "windows")]

mod poller;
mod prefs;
mod toast_win32;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustward_ipc::messages::{NotificationFeedView, Request, ResponseBody};

use crate::poller::{FeedClient, NotifierEngine};
use crate::prefs::NotifierPrefs;
use crate::toast_win32::Win32ToastPresenter;

struct StatusPipeClient;

impl FeedClient for StatusPipeClient {
    fn fetch_feed(&mut self, after_event_id: Option<i64>) -> Result<NotificationFeedView, String> {
        #[cfg(windows)]
        {
            use rustward_ipc::PIPE_NAME_STATUS;
            use rustward_ipc::pipe::PipeConnection;
            use rustward_ipc::rpc::{Client, DEFAULT_TIMEOUT};

            let conn = PipeConnection::connect(PIPE_NAME_STATUS, Duration::from_secs(3))
                .map_err(|e| format!("status pipe unavailable: {e}"))?;
            let resp = Client::new(conn, DEFAULT_TIMEOUT)
                .call(Request::GetNotificationFeed { after_event_id })
                .map_err(|e| e.into_ipc_error().message)?;
            match resp {
                ResponseBody::NotificationFeed(feed) => Ok(feed),
                other => Err(format!("unexpected response on status pipe: {other:?}")),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = after_event_id;
            Err("Windows status pipe requires Windows".into())
        }
    }
}

struct CliArgs {
    once: bool,
    poll_interval: Duration,
    prefs_override: Option<PathBuf>,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut once = false;
    let mut poll_ms: u64 = 2000;
    let mut prefs_override = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--once" => once = true,
            "--poll-ms" => {
                let raw = it.next().ok_or("--poll-ms requires a millisecond value")?;
                poll_ms = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid --poll-ms value")?
                    .clamp(500, 60_000);
            }
            "--prefs" => {
                let raw = it.next().ok_or("--prefs requires a path")?;
                prefs_override = Some(PathBuf::from(raw));
            }
            "--help" | "-h" => {
                return Err(
                    "Usage: rustward-notifier [--once] [--poll-ms MS] [--prefs PATH]".into(),
                );
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(CliArgs {
        once,
        poll_interval: Duration::from_millis(poll_ms),
        prefs_override,
    })
}

fn now_utc_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(windows)]
struct SingleInstanceGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl SingleInstanceGuard {
    fn acquire_per_user() -> Option<Self> {
        use std::ptr;
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
        use windows_sys::Win32::System::Threading::CreateMutexW;

        let name: Vec<u16> = "Local\\RustWard.Notifier.PerUser"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: Valid NUL-terminated UTF-16 mutex name in `Local\` per-session namespace.
        let handle = unsafe { CreateMutexW(ptr::null(), 1, name.as_ptr()) };
        if handle.is_null() {
            return None;
        }
        // SAFETY: Immediately read GetLastError after CreateMutexW on the same thread.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: Close duplicate mutex handle before exiting quietly.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return None;
        }
        Some(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Closing the mutex handle acquired in `acquire_per_user`.
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let args = parse_args()?;
    #[cfg(windows)]
    let _instance_guard = if args.once {
        None
    } else {
        match SingleInstanceGuard::acquire_per_user() {
            Some(g) => Some(g),
            None => return Ok(ExitCode::SUCCESS),
        }
    };

    let prefs_path = args.prefs_override.or_else(NotifierPrefs::default_path);
    let prefs = prefs_path
        .as_deref()
        .map(NotifierPrefs::load)
        .unwrap_or_default();
    let presenter = Win32ToastPresenter::create()?;
    let mut engine = NotifierEngine::new(StatusPipeClient, presenter, prefs, prefs_path);

    if args.once {
        let _ = engine.poll_once(now_utc_ms())?;
        return Ok(ExitCode::SUCCESS);
    }

    let sleep_slice = Duration::from_millis(200);
    loop {
        if !engine.presenter_mut().is_alive() {
            break;
        }
        let _ = engine.poll_once(now_utc_ms());

        let mut elapsed = Duration::ZERO;
        while elapsed < args.poll_interval {
            if !engine.presenter_mut().is_alive() {
                return Ok(ExitCode::SUCCESS);
            }
            std::thread::sleep(sleep_slice);
            elapsed += sleep_slice;
        }
    }
    Ok(ExitCode::SUCCESS)
}

trait AliveCheck {
    fn is_alive(&mut self) -> bool;
}

impl AliveCheck for Win32ToastPresenter {
    fn is_alive(&mut self) -> bool {
        self.pump_messages()
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("rustward-notifier: {e}");
            ExitCode::FAILURE
        }
    }
}
