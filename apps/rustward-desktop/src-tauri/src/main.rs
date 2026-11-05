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
//! STATUS: NOT COMPILED in the development container (no WebView2/webkit2gtk);
//! must be built and verified on Windows 10 Pro x64.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;

use rustward_ipc::messages::{Request, ResponseBody};
use rustward_ipc::{ErrorCode, IpcError};
use rustward_ui_bridge::Bridge;

struct AppState {
    bridge: Arc<Bridge>,
}

/// The single command exposed to the webview.
#[tauri::command]
async fn ipc_call(
    state: tauri::State<'_, AppState>,
    request: Request,
) -> Result<ResponseBody, IpcError> {
    let bridge = Arc::clone(&state.bridge);
    // Pipe I/O and SQLite are blocking; keep them off the async runtime.
    tauri::async_runtime::spawn_blocking(move || bridge.call(request))
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, format!("backend worker failed: {e}")))?
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

    #[test]
    fn policy_mutation_persists_and_checks_version() {
        let h = harness("mut");
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
