//! Pipe-server pool policy for the service (platform-independent).
//!
//! The Windows-only [`crate::ipc_server`] instantiates this with
//! `rustward_ipc::pipe::PipeListener`; tests use the in-memory
//! `MockListener`. Phase 9A findings F-13 (one client at a time) and F-14
//! (threads not joined at stop) are resolved here in logic; the named-pipe
//! behaviour itself is **NOT VERIFIED ON WINDOWS**.

use std::sync::Arc;
use std::time::Duration;

use rustward_app::AppService;
use rustward_ipc::server::{
    AcceptErrorHook, Listener, ServerConfig, ServerHandle, ShutdownReport, spawn_server,
};
use rustward_storage::Severity;

/// A connection with no request for this long is closed.
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// Concurrent callers on the read-only pipe (any authenticated user).
pub const MAX_STATUS_CONNECTIONS: usize = 8;
/// Concurrent callers on the administrative pipe (administrators only, so a
/// standard user can never occupy these slots).
pub const MAX_ADMIN_CONNECTIONS: usize = 4;
/// Time allowed at service stop for in-flight requests to finish. Well below
/// the SCM stop wait hint.
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(3);
/// Pause after a failed accept.
pub const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// Configuration for one pipe.
#[must_use]
pub fn config(max_connections: usize) -> ServerConfig {
    ServerConfig {
        max_connections,
        idle_timeout: CONNECTION_IDLE_TIMEOUT,
        accept_error_backoff: ACCEPT_ERROR_BACKOFF,
    }
}

/// Accept errors are audited rate-limited: the first of a run and every 60th.
fn accept_error_hook(app: &Arc<AppService>, pipe: &'static str) -> AcceptErrorHook {
    let app = Arc::clone(app);
    Arc::new(move |e, consecutive| {
        if consecutive == 1 || consecutive.is_multiple_of(60) {
            let _ = app.record_event(
                Severity::Warning,
                "ipc_error",
                &format!("pipe {pipe}: {e} ({consecutive} consecutive failures)"),
            );
        }
    })
}

/// Running pipe servers.
pub struct PipeServers {
    servers: Vec<(&'static str, ServerHandle)>,
}

impl std::fmt::Debug for PipeServers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeServers")
            .field(
                "pipes",
                &self.servers.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Start one pooled server per `(name, listener, max_connections)`.
pub fn spawn<L: Listener>(
    app: &Arc<AppService>,
    pipes: Vec<(&'static str, Arc<L>, usize)>,
) -> PipeServers {
    PipeServers {
        servers: pipes
            .into_iter()
            .map(|(name, listener, max)| {
                let handle = spawn_server(
                    listener,
                    Arc::clone(app),
                    config(max),
                    accept_error_hook(app, name),
                );
                (name, handle)
            })
            .collect(),
    }
}

impl PipeServers {
    /// Stop every server, joining all threads within [`SHUTDOWN_DEADLINE`]
    /// per pipe. An incomplete shutdown is audited (`ipc_shutdown_incomplete`)
    /// instead of being silently ignored.
    pub fn shutdown(self, app: &AppService) -> Vec<(&'static str, ShutdownReport)> {
        let reports: Vec<_> = self
            .servers
            .into_iter()
            .map(|(name, h)| (name, h.shutdown(SHUTDOWN_DEADLINE)))
            .collect();
        for (name, r) in &reports {
            record_if_incomplete(app, name, r);
        }
        reports
    }
}

/// Audit an incomplete shutdown of one pipe.
fn record_if_incomplete(app: &AppService, name: &str, r: &ShutdownReport) -> bool {
    if r.is_complete() {
        return false;
    }
    let _ = app.record_event(
        Severity::Warning,
        "ipc_shutdown_incomplete",
        &format!(
            "pipe {name}: acceptor stopped: {}, {} connection thread(s) joined, {} still running at the {} s deadline",
            r.acceptor_stopped,
            r.connections_joined,
            r.connections_abandoned,
            SHUTDOWN_DEADLINE.as_secs()
        ),
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustward_app::{AppConfig, BackendKind, EmptyInventory, default_policy_state};
    use rustward_ipc::messages::{AccessLevel, Request};
    use rustward_ipc::rpc::{Client, Handler};
    use rustward_ipc::transport::mock_listener;
    use rustward_ipc::{ClientIdentity, IdentitySource};
    use rustward_storage::{ManualClock, Store};

    fn app() -> Arc<AppService> {
        let clock = Arc::new(ManualClock::new(1_793_836_800_000));
        Arc::new(
            AppService::new(
                Store::open_in_memory(clock.clone()).unwrap(),
                clock,
                Box::new(EmptyInventory),
                AppConfig {
                    backend: BackendKind::WindowsService,
                    allow_synthetic: false,
                    backup_dir: None,
                    database_location: "test".into(),
                    app_version: "test".into(),
                },
                &default_policy_state().unwrap(),
            )
            .unwrap(),
        )
    }

    fn user() -> ClientIdentity {
        ClientIdentity {
            account: "PC-01\\operator".into(),
            sid: None,
            is_administrator: false,
            elevated: false,
            source: IdentitySource::Test,
            channel_max_access: AccessLevel::ReadOnly,
        }
    }

    #[test]
    fn limits_reserve_admin_capacity_and_fit_the_stop_wait_hint() {
        const { assert!(MAX_STATUS_CONNECTIONS >= 2 && MAX_ADMIN_CONNECTIONS >= 2) };
        assert!(CONNECTION_IDLE_TIMEOUT > rustward_ipc::rpc::STOP_POLL);
        // Both pipes are shut down one after the other while the SCM is told
        // to wait WAIT_HINT_MS.
        let hint = Duration::from_millis(u64::from(rustward_windows::svc_control::WAIT_HINT_MS));
        assert!(SHUTDOWN_DEADLINE * 2 < hint);
        assert_eq!(crate::paths::SERVICE_NAME, rustward_ipc::SERVICE_NAME);
    }

    #[test]
    fn pooled_service_serves_concurrent_callers_and_stops_cleanly() {
        let app = app();
        let (connector, listener) = mock_listener();
        let servers = spawn(
            &app,
            vec![("status", Arc::new(listener), MAX_STATUS_CONNECTIONS)],
        );
        // An idle caller holds a slot; another caller is still served.
        let _idle = connector.connect(user()).unwrap();
        let mut active = Client::new(connector.connect(user()).unwrap(), Duration::from_secs(2));
        assert!(active.call(Request::GetDashboard).is_ok());
        let started = std::time::Instant::now();
        let reports = servers.shutdown(&app);
        assert!(
            started.elapsed() < SHUTDOWN_DEADLINE,
            "{:?}",
            started.elapsed()
        );
        assert_eq!(reports.len(), 1);
        assert!(reports[0].1.is_complete(), "{:?}", reports[0].1);
        assert!(!kinds(&app).iter().any(|k| k == "ipc_shutdown_incomplete"));
    }

    #[test]
    fn incomplete_shutdowns_are_audited() {
        let app = app();
        let complete = ShutdownReport {
            acceptor_stopped: true,
            connections_joined: 2,
            connections_abandoned: 0,
        };
        assert!(!record_if_incomplete(&app, "status", &complete));
        let stuck = ShutdownReport {
            connections_abandoned: 1,
            ..complete
        };
        assert!(record_if_incomplete(&app, "status", &stuck));
        assert_eq!(
            kinds(&app)
                .iter()
                .filter(|k| *k == "ipc_shutdown_incomplete")
                .count(),
            1
        );
    }

    fn kinds(app: &AppService) -> Vec<String> {
        let admin = ClientIdentity {
            account: "PC-01\\admin".into(),
            sid: None,
            is_administrator: true,
            elevated: true,
            source: IdentitySource::Test,
            channel_max_access: AccessLevel::Administrator,
        };
        match app
            .handle(
                &Request::ListEvents {
                    query: rustward_ipc::messages::EventQuery {
                        limit: Some(1000),
                        ..Default::default()
                    },
                },
                &admin,
            )
            .unwrap()
        {
            rustward_ipc::messages::ResponseBody::Events(e) => {
                e.into_iter().map(|e| e.kind).collect()
            }
            other => panic!("{other:?}"),
        }
    }
}
