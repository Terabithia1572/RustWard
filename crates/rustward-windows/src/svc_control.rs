//! Platform-neutral Service Control Manager logic: which controls are
//! accepted, how each control is answered, and the status fields reported
//! for each lifecycle state. The FFI host in `service_host.rs` only moves
//! these values across the Win32 boundary, so all decisions are tested here
//! on any OS.

use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::Services::{
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};

/// Lifecycle states RustWard reports to the SCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceLifecycle {
    /// Initialising (database, policy, pipes).
    StartPending,
    /// Main loop running.
    Running,
    /// Stop requested; finishing the current iteration.
    StopPending,
    /// Stopped.
    Stopped,
}

/// Fields of a `SERVICE_STATUS` structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFields {
    /// `dwServiceType`.
    pub service_type: u32,
    /// `dwCurrentState`.
    pub current_state: u32,
    /// `dwControlsAccepted`.
    pub controls_accepted: u32,
    /// `dwWin32ExitCode`.
    pub win32_exit_code: u32,
    /// `dwCheckPoint`.
    pub checkpoint: u32,
    /// `dwWaitHint` in milliseconds.
    pub wait_hint_ms: u32,
}

/// Wait hint reported while starting or stopping. The runtime honours a
/// stop request within ~100 ms plus at most one inventory refresh.
pub const WAIT_HINT_MS: u32 = 15_000;

/// Win32 exit code reported when the service body fails
/// (`ERROR_SERVICE_SPECIFIC_ERROR` semantics are not used: the detailed
/// reason is in the audit log and Event Log).
pub const EXIT_CODE_FAILURE: u32 = 1;

/// Status for a lifecycle state. Controls are accepted only while running,
/// as the SCM documentation requires for pending states.
#[must_use]
pub fn status_fields(state: ServiceLifecycle, checkpoint: u32, exit_code: u32) -> StatusFields {
    let (current_state, controls_accepted, wait_hint_ms, checkpoint) = match state {
        ServiceLifecycle::StartPending => (SERVICE_START_PENDING, 0, WAIT_HINT_MS, checkpoint),
        ServiceLifecycle::Running => (
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            0,
            0,
        ),
        ServiceLifecycle::StopPending => (SERVICE_STOP_PENDING, 0, WAIT_HINT_MS, checkpoint),
        ServiceLifecycle::Stopped => (SERVICE_STOPPED, 0, 0, 0),
    };
    StatusFields {
        service_type: SERVICE_WIN32_OWN_PROCESS,
        current_state,
        controls_accepted,
        win32_exit_code: if state == ServiceLifecycle::Stopped {
            exit_code
        } else {
            NO_ERROR
        },
        checkpoint,
        wait_hint_ms,
    }
}

/// How the control handler answers one control code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlDecision {
    /// Value returned from the handler.
    pub handler_result: u32,
    /// Set the stop flag.
    pub request_stop: bool,
    /// Report `StopPending` immediately.
    pub report_stop_pending: bool,
}

/// Decide how to answer a control code.
#[must_use]
pub fn decide_control(control: u32) -> ControlDecision {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => ControlDecision {
            handler_result: NO_ERROR,
            request_stop: true,
            report_stop_pending: true,
        },
        SERVICE_CONTROL_INTERROGATE => ControlDecision {
            handler_result: NO_ERROR,
            request_stop: false,
            report_stop_pending: false,
        },
        _ => ControlDecision {
            handler_result: ERROR_CALL_NOT_IMPLEMENTED,
            request_stop: false,
            report_stop_pending: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::Services::{
        SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_POWEREVENT, SERVICE_CONTROL_PRESHUTDOWN,
    };

    use super::*;

    #[test]
    fn controls_are_accepted_only_while_running() {
        for s in [
            ServiceLifecycle::StartPending,
            ServiceLifecycle::StopPending,
            ServiceLifecycle::Stopped,
        ] {
            assert_eq!(status_fields(s, 1, 0).controls_accepted, 0, "{s:?}");
        }
        let r = status_fields(ServiceLifecycle::Running, 7, 0);
        assert_eq!(
            r.controls_accepted,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        );
        assert_eq!((r.checkpoint, r.wait_hint_ms), (0, 0));
        assert_eq!(r.service_type, SERVICE_WIN32_OWN_PROCESS);
    }

    #[test]
    fn pending_states_carry_checkpoint_and_wait_hint() {
        let p = status_fields(ServiceLifecycle::StartPending, 3, 0);
        assert_eq!(
            (p.current_state, p.checkpoint, p.wait_hint_ms),
            (SERVICE_START_PENDING, 3, WAIT_HINT_MS)
        );
        let p = status_fields(ServiceLifecycle::StopPending, 1, 0);
        assert_eq!(p.current_state, SERVICE_STOP_PENDING);
    }

    #[test]
    fn exit_code_is_reported_only_when_stopped() {
        assert_eq!(
            status_fields(ServiceLifecycle::Running, 0, EXIT_CODE_FAILURE).win32_exit_code,
            NO_ERROR
        );
        let s = status_fields(ServiceLifecycle::Stopped, 9, EXIT_CODE_FAILURE);
        assert_eq!(
            (s.current_state, s.win32_exit_code, s.checkpoint),
            (SERVICE_STOPPED, EXIT_CODE_FAILURE, 0)
        );
    }

    #[test]
    fn stop_and_shutdown_request_a_stop_and_others_do_not() {
        for c in [SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN] {
            let d = decide_control(c);
            assert!(d.request_stop && d.report_stop_pending);
            assert_eq!(d.handler_result, NO_ERROR);
        }
        let i = decide_control(SERVICE_CONTROL_INTERROGATE);
        assert!(!i.request_stop);
        assert_eq!(i.handler_result, NO_ERROR);
        for c in [
            SERVICE_CONTROL_PAUSE,
            SERVICE_CONTROL_PRESHUTDOWN,
            SERVICE_CONTROL_POWEREVENT,
            0xFFFF,
        ] {
            let d = decide_control(c);
            assert!(!d.request_stop, "control {c} must not stop the service");
            assert_eq!(d.handler_result, ERROR_CALL_NOT_IMPLEMENTED);
        }
    }
}
