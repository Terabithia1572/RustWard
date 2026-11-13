//! RustWard desktop shell.
//!
//! The webview can call exactly one command, `ipc_call`, which forwards a
//! typed [`Request`] to the selected backend:
//! * release builds: the RustWard Windows service over named pipes, where the
//!   service authorizes every privileged request against the caller's Windows
//!   token (elevated administrator). The UI grants nothing by itself.
//! * debug builds with `dev-backend`: an in-process backend over a temporary
//!   development database, using the same validation and authorization code.
//!
//! STATUS: compiled, clippy-checked and tested (Tauri mock runtime) on Linux
//! with webkit2gtk in the development container (`scripts/verify-all.sh`).
//! The Windows build (WebView2, MSI) is NOT VERIFIED and must be done on
//! Windows 10 Pro x64.
// Release builds, and the debug "preview" build made by
// scripts\windows\Build-RustWard.ps1 (feature `gui-subsystem`), open as a
// normal Windows GUI app without a console window.
#![cfg_attr(
    any(not(debug_assertions), feature = "gui-subsystem"),
    windows_subsystem = "windows"
)]

use std::sync::{Arc, Mutex};

use rustward_ipc::messages::{Request, ResponseBody};
use rustward_ipc::{ErrorCode, IpcError};
use rustward_ui_bridge::Bridge;
use tauri::{Emitter, Manager, WindowEvent};

struct AppState {
    bridge: Arc<Bridge>,
    session_token: Mutex<Option<String>>,
    approved_exit_nonce: Mutex<Option<String>>,
}

/// The single command exposed to the webview.
#[tauri::command]
async fn ipc_call<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: tauri::State<'_, AppState>,
    request: Request,
) -> Result<ResponseBody, IpcError> {
    let bridge = Arc::clone(&state.bridge);
    let token = state.session_token.lock().ok().and_then(|g| g.clone());
    let clears_session = matches!(
        request,
        Request::Logout | Request::LockSession | Request::ResetPasswordWithRecovery { .. }
    );
    let is_verify_exit = matches!(request, Request::VerifyExitAuthorization { .. });

    // Pipe I/O and SQLite are blocking; keep them off the async runtime.
    let result = tauri::async_runtime::spawn_blocking(move || bridge.call_with_token(request, token))
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, format!("backend worker failed: {e}")))?;

    match &result {
        Ok(ResponseBody::Login(login)) => {
            if let Ok(mut guard) = state.session_token.lock() {
                *guard = Some(login.session_token.clone());
            }
        }
        Ok(ResponseBody::ExitAuthorized(exit)) if exit.authorized && !exit.exit_nonce.is_empty() => {
            if let Ok(mut guard) = state.approved_exit_nonce.lock() {
                *guard = Some(exit.exit_nonce.clone());
            }
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.close();
            }
        }
        Ok(_) if clears_session => {
            if let Ok(mut guard) = state.session_token.lock() {
                *guard = None;
            }
        }
        Err(err) if !is_verify_exit && err.code == ErrorCode::Unauthorized => {
            let lower = err.message.to_ascii_lowercase();
            if lower.contains("session") || lower.contains("authentication required") {
                if let Ok(mut guard) = state.session_token.lock() {
                    *guard = None;
                }
            }
        }
        _ => {}
    }

    result
}

fn context<R: tauri::Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

fn with_backend<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    bridge: Bridge,
) -> tauri::Builder<R> {
    builder
        .manage(AppState {
            bridge: Arc::new(bridge),
            session_token: Mutex::new(None),
            approved_exit_nonce: Mutex::new(None),
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<AppState>();
                let authorized = state
                    .approved_exit_nonce
                    .lock()
                    .ok()
                    .and_then(|mut g| g.take())
                    .is_some();
                if !authorized {
                    api.prevent_close();
                    let _ = window.emit("rustward://exit-requested", ());
                }
            }
        })
        .invoke_handler(tauri::generate_handler![ipc_call])
}

fn main() {
    let bridge = Bridge::select();
    eprintln!("RustWard desktop: backend = {}", bridge.name());
    let result = with_backend(tauri::Builder::default(), bridge).run(context());
    if let Err(e) = result {
        eprintln!("RustWard desktop failed to start: {e}");
        std::process::exit(1);
    }
}

/// Drives `ipc_call` through Tauri's real IPC layer (mock runtime), including
/// the capability/ACL check from `capabilities/default.json`, into the
/// development backend. Runs on any host with the webview dev libraries; it is
/// NOT evidence of Windows behaviour.
#[cfg(all(test, debug_assertions, feature = "dev-backend"))]
mod tests {
    use serde_json::{json, Value};
    use tauri::ipc::{CallbackFn, InvokeBody};
    use tauri::test::{get_ipc_response, mock_builder, INVOKE_KEY};
    use tauri::webview::InvokeRequest;
    use tauri::WebviewWindowBuilder;

    use super::{context, with_backend, Bridge};

    struct Harness {
        _dir: TempDir,
        webview: tauri::WebviewWindow<tauri::test::MockRuntime>,
        _app: tauri::App<tauri::test::MockRuntime>,
    }

    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn harness(name: &str) -> Harness {
        let dir =
            std::env::temp_dir().join(format!("rustward-tauri-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bridge = Bridge::dev_at(&dir).unwrap();
        let app = with_backend(mock_builder(), bridge)
            .build(context())
            .unwrap();
        let webview = WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .unwrap();
        Harness {
            _dir: TempDir(dir),
            webview,
            _app: app,
        }
    }

    fn invoke(h: &Harness, cmd: &str, body: Value) -> Result<Value, Value> {
        let url = if cfg!(windows) {
            "http://tauri.localhost"
        } else {
            "tauri://localhost"
        };
        get_ipc_response(
            &h.webview,
            InvokeRequest {
                cmd: cmd.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: url.parse().unwrap(),
                body: InvokeBody::Json(body),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.to_string(),
            },
        )
        .map(|r| r.deserialize::<Value>().unwrap())
    }

    #[test]
    fn dashboard_round_trip_reports_unverified_protection() {
        let h = harness("dash");
        // Unauthenticated requests are blocked while mandatory setup is pending.
        let unauth = invoke(
            &h,
            "ipc_call",
            json!({ "request": { "type": "get_dashboard" } }),
        )
        .unwrap_err();
        assert_eq!(unauth["code"], "unauthorized");

        setup_admin(&h);
        let v = invoke(
            &h,
            "ipc_call",
            json!({ "request": { "type": "get_dashboard" } }),
        )
        .unwrap();
        assert_eq!(v["type"], "dashboard");
        assert_eq!(v["data"]["protection_verified"], false);
        assert_eq!(
            v["data"]["not_validated_banner"],
            "Koruma henüz gerçek Windows ortamında doğrulanmadı."
        );
        assert_eq!(v["data"]["service"]["backend"], "dev_backend");
    }

    fn setup_admin(h: &Harness) {
        let res = invoke(
            h,
            "ipc_call",
            json!({
                "request": {
                    "type": "setup_initial_admin",
                    "username": "secadmin",
                    "display_name": "Güvenlik Yöneticisi",
                    "password": "Strong!Admin#2026"
                }
            }),
        )
        .unwrap();
        assert_eq!(res["type"], "login");
    }

    #[test]
    fn policy_mutation_persists_and_checks_version() {
        let h = harness("mut");
        setup_admin(&h);
        let m = invoke(
            &h,
            "ipc_call",
            json!({ "request": { "type": "list_manufacturers" } }),
        )
        .unwrap();
        let version = m["data"]["policy_version"].as_u64().unwrap();
        let id = m["data"]["manufacturers"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let allowed = m["data"]["manufacturers"][0]["allowed"].as_bool().unwrap();
        let req = |v: u64| json!({ "request": { "type": "set_manufacturer_allowed", "id": id, "allowed": !allowed, "expected_policy_version": v } });
        let ok = invoke(&h, "ipc_call", req(version)).unwrap();
        assert_eq!(ok["type"], "mutation");
        assert_eq!(ok["data"]["policy_version"].as_u64(), Some(version + 1));
        let stale = invoke(&h, "ipc_call", req(version)).unwrap_err();
        assert_eq!(stale["code"], "conflict");
    }

    #[test]
    fn protected_close_requires_admin_exit_verification() {
        let h = harness("exit");
        let setup_missing = invoke(
            &h,
            "ipc_call",
            json!({
                "request": {
                    "type": "verify_exit_authorization",
                    "username": "secadmin",
                    "password": "Strong!Admin#2026"
                }
            }),
        )
        .unwrap_err();
        assert_eq!(setup_missing["code"], "unauthorized");

        setup_admin(&h);

        // Wrong password is rejected.
        let bad_pw = invoke(
            &h,
            "ipc_call",
            json!({
                "request": {
                    "type": "verify_exit_authorization",
                    "username": "secadmin",
                    "password": "Wrong!Password1"
                }
            }),
        )
        .unwrap_err();
        assert_eq!(bad_pw["code"], "unauthorized");

        // Correct admin password issues single-use exit authorization.
        let ok = invoke(
            &h,
            "ipc_call",
            json!({
                "request": {
                    "type": "verify_exit_authorization",
                    "username": "secadmin",
                    "password": "Strong!Admin#2026"
                }
            }),
        )
        .unwrap();
        assert_eq!(ok["type"], "exit_authorized");
        assert_eq!(ok["data"]["authorized"], true);
    }

    #[test]
    fn malformed_requests_are_rejected() {
        let h = harness("bad");
        assert!(invoke(
            &h,
            "ipc_call",
            json!({ "request": { "type": "drop_all_tables" } })
        )
        .is_err());
        assert!(invoke(
            &h,
            "ipc_call",
            json!({ "request": { "type": "list_blocked", "limit": "x" } })
        )
        .is_err());
        let invalid = invoke(
            &h,
            "ipc_call",
            json!({ "request": { "type": "explain_device", "device_key": "" } }),
        )
        .unwrap_err();
        assert!(invalid["code"].is_string(), "{invalid}");
    }

    #[test]
    fn only_ipc_call_is_exposed() {
        let h = harness("acl");
        assert!(invoke(
            &h,
            "plugin:fs|read_file",
            json!({ "path": "C:/Windows/win.ini" })
        )
        .is_err());
        assert!(invoke(&h, "not_a_command", json!({})).is_err());
    }
}
