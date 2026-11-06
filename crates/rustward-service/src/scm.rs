//! Windows service entry point. **NOT VERIFIED ON WINDOWS**: compiled on
//! Windows and type-checked elsewhere with `host-typecheck`; never run.
//!
//! The SCM protocol is implemented in `rustward_windows::service_host`
//! (windows-sys), so this crate stays free of `unsafe`. The service is never
//! installed by this program.

use std::sync::Arc;
use std::sync::mpsc;

use rustward_app::BackendKind;
use rustward_storage::Severity;
use rustward_windows::device_notify::DeviceChangeSubscription;
use rustward_windows::event_log::WindowsEventLog;
use rustward_windows::eventlog_map::{EventLevel, event_id, render_message};
use rustward_windows::service_host::{self, ServiceContext};

use crate::event_mirror::EventLogMirror;
use crate::paths::{SERVICE_NAME, ServicePaths};

/// Hand the process to the SCM dispatcher (blocks until the service stops).
pub fn run_dispatcher() -> Result<(), String> {
    service_host::run_dispatcher(SERVICE_NAME, run_service).map_err(|e| e.to_string())
}

fn run_service(ctx: ServiceContext) -> Result<(), String> {
    let result = run_service_inner(ctx);
    if let Err(e) = &result {
        // The SQLite audit log may be the thing that failed, so report the
        // start/run failure to the Event Log directly (best effort). Without
        // this a service that cannot open its database stops silently.
        if let Ok(log) = WindowsEventLog::open() {
            let text = render_message("service_start_failed", e, false, "unknown", None, 0);
            let _ = log.report(
                EventLevel::Critical,
                event_id("service_start_failed"),
                &text,
            );
        }
    }
    result
}

fn run_service_inner(ctx: ServiceContext) -> Result<(), String> {
    let paths = ServicePaths::production().ok_or("ProgramData is not set")?;
    let (runtime, app) =
        crate::build_runtime(&paths, false, BackendKind::WindowsService, "program_data")?;

    // Event Log mirroring is best effort: the SQLite audit log is primary.
    match WindowsEventLog::open() {
        Ok(log) => {
            if let Err(e) = app.set_event_observer(Arc::new(EventLogMirror::new(log))) {
                let _ = app.record_event(Severity::Warning, "event_log_unavailable", &e.message);
            }
        }
        Err(e) => {
            let _ = app.record_event(Severity::Warning, "event_log_unavailable", &e.to_string());
        }
    }

    // Device-change notifications only make the next refresh happen sooner.
    let (tx, rx) = mpsc::channel();
    let subscription = match DeviceChangeSubscription::register(tx) {
        Ok(s) => Some(s),
        Err(e) => {
            let _ = app.record_event(
                Severity::Warning,
                "device_notifications_unavailable",
                &format!("{e}; falling back to periodic inventory refresh"),
            );
            None
        }
    };
    let mut runtime = runtime.with_stop_handle(Arc::clone(&ctx.stop));
    if subscription.is_some() {
        runtime = runtime.with_wake_source(Box::new(rx));
    }

    let pipes = crate::ipc_server::spawn_pipe_servers(&app);
    ctx.report_running();
    runtime.run(None, None);
    // Join the pipe threads (in-flight requests are answered first); an
    // incomplete shutdown is audited as `ipc_shutdown_incomplete`.
    let _ = pipes.shutdown(&app);
    drop(subscription);
    Ok(())
}
