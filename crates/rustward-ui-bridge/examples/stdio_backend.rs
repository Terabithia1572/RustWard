//! Development-only test harness: the real RustWard backend (`AppService`
//! over a SQLite file, same validation and authorization as the service)
//! answering newline-delimited JSON on stdin/stdout. Used by the frontend
//! integration tests (`apps/rustward-desktop/src/test/*.integration.test.tsx`)
//! so the React pages run against real data instead of a fake.
//!
//! Usage: `stdio_backend <data-dir> [admin|user]`
//! Input lines: a `Request` JSON object. Output lines:
//! `{"ok": ResponseBody}` or `{"err": IpcError}`.
//!
//! Compiled only in debug builds with the `dev-backend` feature; never part
//! of a release or an installer.

#[cfg(all(debug_assertions, feature = "dev-backend"))]
fn main() -> std::process::ExitCode {
    use std::io::{BufRead, Write};

    use rustward_ui_bridge::{Bridge, DevCaller};

    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: stdio_backend <data-dir> [admin|user]");
        return std::process::ExitCode::from(2);
    };
    let caller = match args.next().as_deref() {
        None | Some("admin") => DevCaller::ElevatedAdministrator,
        Some("user") => DevCaller::StandardUser,
        Some(other) => {
            eprintln!("unknown caller {other:?}");
            return std::process::ExitCode::from(2);
        }
    };
    let bridge = match Bridge::dev_at_as(std::path::Path::new(&dir), caller) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot open backend: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    let mut session_token: Option<String> = None;
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<rustward_ipc::Request>(&line) {
            // Same path as the Tauri `ipc_call` command.
            Ok(request) => {
                let clears = matches!(
                    request,
                    rustward_ipc::Request::Logout
                        | rustward_ipc::Request::LockSession
                        | rustward_ipc::Request::ResetPasswordWithRecovery { .. }
                );
                match bridge.call_with_token(request, session_token.clone()) {
                    Ok(body) => {
                        if let rustward_ipc::ResponseBody::Login(ref login) = body {
                            session_token = Some(login.session_token.clone());
                        } else if clears {
                            session_token = None;
                        }
                        serde_json::json!({ "ok": body })
                    }
                    Err(e) => serde_json::json!({ "err": e }),
                }
            }
            Err(e) => serde_json::json!({
                "err": { "code": "invalid_request", "message": format!("malformed request: {e}") }
            }),
        };
        if writeln!(out, "{reply}").and_then(|()| out.flush()).is_err() {
            break;
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(all(debug_assertions, feature = "dev-backend")))]
fn main() {
    eprintln!("stdio_backend needs a debug build with --features dev-backend");
}
