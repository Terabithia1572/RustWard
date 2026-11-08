//! Backend selection for the desktop UI.
//!
//! - **Service** (production): requests go to the RustWard Windows service
//!   over named pipes — read-only requests on the status pipe, privileged
//!   requests on the admin pipe, where the service checks the caller's
//!   Windows token. The UI process itself holds no privilege.
//! - **Dev** (development only): an in-process [`AppService`] over a
//!   temporary database. Compiled only with `debug_assertions` **and** the
//!   `dev-backend` feature, so release builds cannot contain it. Requests
//!   still pass the same validation and authorization code as the service
//!   ([`rustward_ipc::rpc::process`]).

#![forbid(unsafe_code)]

use rustward_ipc::{IpcError, Request, ResponseBody};

#[cfg(all(debug_assertions, feature = "dev-backend"))]
mod dev {
    use std::sync::Arc;

    use rustward_app::{
        AppConfig, AppService, BackendKind, EmptyInventory, InventorySource, LiveInventory,
        default_policy_state,
    };
    use rustward_ipc::messages::AccessLevel;
    use rustward_ipc::rpc::process;
    use rustward_ipc::{
        ClientIdentity, ErrorCode, IdentitySource, IpcError, PROTOCOL_VERSION, Request,
        RequestEnvelope, ResponseBody,
    };
    use rustward_storage::{Clock, Store, SystemClock};

    /// In-process development backend.
    #[derive(Debug)]
    pub struct DevBackend {
        app: Arc<AppService>,
        identity: ClientIdentity,
        next_id: std::sync::atomic::AtomicU64,
    }

    /// Who the development backend pretends the caller is. The service
    /// determines this from the Windows token; here tests choose it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DevCaller {
        /// Elevated member of Administrators (the default for developers).
        ElevatedAdministrator,
        /// Standard user on the read-only channel.
        StandardUser,
    }

    impl DevBackend {
        /// Open (or create) the development database in `dir`.
        pub fn open(dir: &std::path::Path) -> Result<Self, String> {
            Self::open_as(dir, DevCaller::ElevatedAdministrator)
        }

        /// Open as a chosen caller (integration tests).
        pub fn open_as(dir: &std::path::Path, caller: DevCaller) -> Result<Self, String> {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let store = Store::open(&dir.join("rustward-dev.db"), Arc::clone(&clock))
                .map_err(|e| e.to_string())?;
            let force_empty = std::env::var("RUSTWARD_DEV_INVENTORY")
                .is_ok_and(|v| v.eq_ignore_ascii_case("empty"));
            let inventory: Box<dyn InventorySource> = if cfg!(windows) && !force_empty {
                Box::new(LiveInventory)
            } else {
                Box::new(EmptyInventory)
            };
            let app = AppService::new(
                store,
                clock,
                inventory,
                AppConfig {
                    backend: BackendKind::DevBackend,
                    allow_synthetic: true,
                    backup_dir: Some(dir.join("backups")),
                    database_location: "dev_temp".into(),
                    app_version: env!("CARGO_PKG_VERSION").into(),
                },
                &default_policy_state()?,
            )
            .map_err(|e| e.to_string())?;
            // Development only: a SYNTHETIC policy capture file (or explicit
            // "unavailable" sentinel for hermetic integration tests) can stand
            // in for the read-only Windows registry capture. Never used by the
            // service or a release build.
            let app = match std::env::var_os("RUSTWARD_DEV_POLICY_CAPTURE") {
                Some(val) if val.to_string_lossy().eq_ignore_ascii_case("unavailable") => app
                    .with_policy_source(Box::new(rustward_app::UnavailablePolicySource(
                        "policy inspection requires Windows (disabled in isolated test)".into(),
                    ))),
                Some(path) => {
                    let text = std::fs::read_to_string(&path)
                        .map_err(|e| format!("RUSTWARD_DEV_POLICY_CAPTURE: {e}"))?;
                    let captured = serde_json::from_str(&text)
                        .map_err(|e| format!("RUSTWARD_DEV_POLICY_CAPTURE: {e}"))?;
                    app.with_policy_source(Box::new(rustward_app::StaticPolicySource(captured)))
                }
                None => app,
            };
            let account = std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_else(|_| "developer".into());
            let admin = caller == DevCaller::ElevatedAdministrator;
            Ok(Self {
                app: Arc::new(app),
                identity: ClientIdentity {
                    account,
                    sid: None,
                    // Development only: the local developer acts as
                    // administrator unless a test asks for a standard user.
                    is_administrator: admin,
                    elevated: admin,
                    source: IdentitySource::DevBackend,
                    channel_max_access: if admin {
                        AccessLevel::Administrator
                    } else {
                        AccessLevel::ReadOnly
                    },
                },
                next_id: std::sync::atomic::AtomicU64::new(1),
            })
        }

        /// Process a request through the same validation/authorization path
        /// the service uses.
        pub fn call(&self, request: Request) -> Result<ResponseBody, IpcError> {
            let env = RequestEnvelope {
                version: PROTOCOL_VERSION,
                request_id: self
                    .next_id
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                request,
            };
            let reply = process(&env, &self.identity, self.app.as_ref());
            if reply.request_id != env.request_id {
                return Err(IpcError::new(ErrorCode::Internal, "response id mismatch"));
            }
            reply.result
        }
    }
}

#[cfg(all(debug_assertions, feature = "dev-backend"))]
pub use dev::DevCaller;

/// The selected backend.
#[derive(Debug)]
pub enum Bridge {
    /// Windows service over named pipes.
    Service,
    /// In-process development backend (debug + `dev-backend` only).
    #[cfg(all(debug_assertions, feature = "dev-backend"))]
    Dev(dev::DevBackend),
}

impl Bridge {
    /// Select the backend. Release builds always use the service.
    /// Debug builds with `dev-backend` use the dev backend unless
    /// `RUSTWARD_BACKEND=service`.
    #[must_use]
    pub fn select() -> Self {
        #[cfg(all(debug_assertions, feature = "dev-backend"))]
        {
            if std::env::var("RUSTWARD_BACKEND").as_deref() != Ok("service") {
                let dir = std::env::temp_dir().join("rustward-dev-ui");
                match dev::DevBackend::open(&dir) {
                    Ok(d) => return Self::Dev(d),
                    Err(e) => eprintln!(
                        "dev backend unavailable ({e}); falling back to the service backend"
                    ),
                }
            }
        }
        Self::Service
    }

    /// Development backend over a database in `dir` (tests, debug builds).
    ///
    /// # Errors
    /// When the development database cannot be opened.
    #[cfg(all(debug_assertions, feature = "dev-backend"))]
    pub fn dev_at(dir: &std::path::Path) -> Result<Self, String> {
        dev::DevBackend::open(dir).map(Self::Dev)
    }

    /// Development backend for a chosen caller (integration tests).
    ///
    /// # Errors
    /// When the development database cannot be opened.
    #[cfg(all(debug_assertions, feature = "dev-backend"))]
    pub fn dev_at_as(dir: &std::path::Path, caller: DevCaller) -> Result<Self, String> {
        dev::DevBackend::open_as(dir, caller).map(Self::Dev)
    }

    /// Backend name shown in diagnostics.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Service => "windows_service",
            #[cfg(all(debug_assertions, feature = "dev-backend"))]
            Self::Dev(_) => "dev_backend",
        }
    }

    /// Execute a request.
    pub fn call(&self, request: Request) -> Result<ResponseBody, IpcError> {
        match self {
            Self::Service => call_service(request),
            #[cfg(all(debug_assertions, feature = "dev-backend"))]
            Self::Dev(d) => d.call(request),
        }
    }
}

#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
fn call_service_pipe(request: Request) -> Result<ResponseBody, IpcError> {
    use std::time::Duration;

    use rustward_ipc::messages::AccessLevel;
    use rustward_ipc::pipe::PipeConnection;
    use rustward_ipc::rpc::{Client, DEFAULT_TIMEOUT};
    use rustward_ipc::transport::TransportError;
    use rustward_ipc::{PIPE_NAME_ADMIN, PIPE_NAME_STATUS};

    let pipe = match request.access_level() {
        AccessLevel::ReadOnly => PIPE_NAME_STATUS,
        AccessLevel::Administrator => PIPE_NAME_ADMIN,
    };
    let timeout = match &request {
        Request::RefreshInventory
        | Request::VerifyEnforcementApplied { .. }
        | Request::VerifyEnforcementRollback { .. } => Duration::from_secs(25),
        _ => DEFAULT_TIMEOUT,
    };
    let conn = PipeConnection::connect(pipe, Duration::from_secs(5)).map_err(|e| match e {
        TransportError::Disconnected => unreachable_reason(pipe == PIPE_NAME_ADMIN),
        other => rustward_ipc::rpc::ClientError::Transport(other).into_ipc_error(),
    })?;
    Client::new(conn, timeout)
        .call(request)
        .map_err(rustward_ipc::rpc::ClientError::into_ipc_error)
}

/// Why the pipe could not be opened, from a read-only SCM query. The
/// bracketed tag lets the UI show a precise, translated reason; the code
/// stays `unavailable`, so nothing reads a missing service as protection.
#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
fn unreachable_reason(admin_pipe: bool) -> IpcError {
    use rustward_ipc::SERVICE_NAME;
    use rustward_ipc::pipe::{ServiceState, service_state};
    let message = match service_state(SERVICE_NAME) {
        Ok(ServiceState::NotInstalled) => {
            format!(
                "[service_not_installed] the RustWard service ({SERVICE_NAME}) is not installed"
            )
        }
        Ok(ServiceState::Stopped) => {
            format!(
                "[service_stopped] the RustWard service ({SERVICE_NAME}) is installed but stopped"
            )
        }
        Ok(ServiceState::StartPending) => {
            "[service_starting] the RustWard service is starting".to_owned()
        }
        Ok(ServiceState::StopPending) => {
            "[service_stopping] the RustWard service is stopping".to_owned()
        }
        Ok(ServiceState::Running { .. }) if admin_pipe => {
            "[admin_required] the RustWard service is running, \
             but this account is not an elevated administrator"
                .to_owned()
        }
        Ok(ServiceState::Running { .. } | ServiceState::Other(_)) => {
            "[service_unreachable] the RustWard service is running but its pipe did not answer"
                .to_owned()
        }
        Err(e) => format!("[service_unreachable] the RustWard service is not reachable ({e})"),
    };
    IpcError::new(rustward_ipc::ErrorCode::Unavailable, message)
}

fn call_service(request: Request) -> Result<ResponseBody, IpcError> {
    #[cfg(windows)]
    {
        call_service_pipe(request)
    }
    #[cfg(not(windows))]
    {
        let _ = request;
        Err(IpcError::new(
            rustward_ipc::ErrorCode::Unavailable,
            "the service backend requires Windows",
        ))
    }
}

/// The Tauri shell shares one `Bridge` across worker threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Bridge>();
};

#[cfg(test)]
mod tests {
    use super::*;

    // Runs on every target. Before Phase 11, no test in this module was
    // compiled for a Windows debug build without `dev-backend`, so
    // `use super::*` was unused and `clippy -D warnings` failed there
    // (found by the Phase 11 Windows-target check).
    #[test]
    fn service_backend_name_is_stable() {
        assert_eq!(Bridge::Service.name(), "windows_service");
    }

    #[cfg(not(windows))]
    #[test]
    fn service_backend_is_unavailable_off_windows() {
        let e = Bridge::Service.call(Request::GetDashboard).unwrap_err();
        assert_eq!(e.code, rustward_ipc::ErrorCode::Unavailable);
    }

    #[cfg(all(debug_assertions, feature = "dev-backend"))]
    #[test]
    fn dev_backend_round_trip_uses_server_validation() {
        let dir = std::env::temp_dir().join(format!("rustward-bridge-test-{}", std::process::id()));
        let b = Bridge::Dev(dev::DevBackend::open(&dir).unwrap());
        assert_eq!(b.name(), "dev_backend");
        assert!(matches!(
            b.call(Request::GetDashboard).unwrap(),
            ResponseBody::Dashboard(_)
        ));
        // Invalid input is rejected by the shared validator, not by the UI.
        let e = b
            .call(Request::RemoveManufacturer {
                id: "../x".into(),
                expected_policy_version: 1,
            })
            .unwrap_err();
        assert_eq!(e.code, rustward_ipc::ErrorCode::InvalidRequest);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Release builds must never select the in-process backend, even with
    /// the `dev-backend` feature on and no environment override.
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_always_uses_the_service() {
        assert_eq!(Bridge::select().name(), "windows_service");
    }
}
