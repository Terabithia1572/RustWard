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

    impl DevBackend {
        /// Open (or create) the development database in `dir`.
        pub fn open(dir: &std::path::Path) -> Result<Self, String> {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let store = Store::open(&dir.join("rustward-dev.db"), Arc::clone(&clock))
                .map_err(|e| e.to_string())?;
            let inventory: Box<dyn InventorySource> = if cfg!(windows) {
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
            let account = std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_else(|_| "developer".into());
            Ok(Self {
                app: Arc::new(app),
                identity: ClientIdentity {
                    account,
                    sid: None,
                    // Development only: the local developer acts as administrator.
                    is_administrator: true,
                    elevated: true,
                    source: IdentitySource::DevBackend,
                    channel_max_access: AccessLevel::Administrator,
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
    let conn = PipeConnection::connect(pipe, Duration::from_secs(5)).map_err(|e| match e {
        TransportError::Disconnected => IpcError::new(
            rustward_ipc::ErrorCode::Unavailable,
            if pipe == PIPE_NAME_ADMIN {
                "the RustWard service is not reachable or this account is not an elevated administrator"
            } else {
                "the RustWard service is not reachable"
            },
        ),
        other => rustward_ipc::rpc::ClientError::Transport(other).into_ipc_error(),
    })?;
    Client::new(conn, DEFAULT_TIMEOUT)
        .call(request)
        .map_err(rustward_ipc::rpc::ClientError::into_ipc_error)
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

    #[cfg(not(windows))]
    #[test]
    fn service_backend_is_unavailable_off_windows() {
        let e = Bridge::Service.call(Request::GetDashboard).unwrap_err();
        assert_eq!(e.code, rustward_ipc::ErrorCode::Unavailable);
        assert_eq!(Bridge::Service.name(), "windows_service");
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
