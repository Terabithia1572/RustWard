//! Windows Service Control Manager host (windows-service 0.8).
//! **NOT VERIFIED ON WINDOWS**: this module compiles only on Windows and has
//! not been built or run yet. The service is never installed by this build.

use std::ffi::OsString;
use std::time::Duration;

use rustward_app::BackendKind;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::paths::{SERVICE_NAME, ServicePaths};

define_windows_service!(ffi_service_main, service_main);

/// Hand the process to the SCM dispatcher (blocks until the service stops).
pub fn run_dispatcher() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| e.to_string())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("RustWard service failed: {e}");
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service() -> Result<(), String> {
    let paths = ServicePaths::production().ok_or("ProgramData is not set")?;
    let (mut runtime, app) =
        crate::build_runtime(&paths, false, BackendKind::WindowsService, "program_data")?;
    let stop = runtime.stop_handle();
    let stop_for_handler = std::sync::Arc::clone(&stop);
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop_for_handler.store(true, std::sync::atomic::Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|e| e.to_string())?;

    handle
        .set_service_status(status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            0,
        ))
        .map_err(|e| e.to_string())?;
    let _pipes = crate::ipc_server::spawn_pipe_servers(&app, &stop);
    handle
        .set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
        ))
        .map_err(|e| e.to_string())?;

    runtime.run(None, None);

    handle
        .set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            0,
        ))
        .map_err(|e| e.to_string())?;
    Ok(())
}
