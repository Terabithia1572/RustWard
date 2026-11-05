//! Named-pipe servers for the admin and status channels.
//! **NOT VERIFIED ON WINDOWS** (type-checked only).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use rustward_app::AppService;
use rustward_ipc::messages::AccessLevel;
use rustward_ipc::pipe::PipeListener;
use rustward_ipc::rpc::serve_connection;
use rustward_ipc::{PIPE_NAME_ADMIN, PIPE_NAME_STATUS, SDDL_ADMIN, SDDL_STATUS};
use rustward_storage::Severity;

/// Idle timeout per connection; short because each pipe serves one client
/// at a time.
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

fn serve_pipe(app: &AppService, stop: &AtomicBool, name: &str, sddl: &str, level: AccessLevel) {
    let listener = PipeListener::new(name, sddl, level);
    let mut errors = 0u64;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut conn, identity)) => {
                errors = 0;
                let _ = serve_connection(&mut conn, &identity, app, CONNECTION_IDLE_TIMEOUT);
            }
            Err(e) => {
                errors += 1;
                // Rate-limited: first error and every 60th afterwards.
                if errors == 1 || errors.is_multiple_of(60) {
                    let _ = app.record_event(
                        Severity::Warning,
                        "ipc_error",
                        &format!("pipe {name}: {e}"),
                    );
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// Start both pipe servers on background threads.
pub fn spawn_pipe_servers(app: &Arc<AppService>, stop: &Arc<AtomicBool>) -> Vec<JoinHandle<()>> {
    [
        (PIPE_NAME_ADMIN, SDDL_ADMIN, AccessLevel::Administrator),
        (PIPE_NAME_STATUS, SDDL_STATUS, AccessLevel::ReadOnly),
    ]
    .into_iter()
    .map(|(name, sddl, level)| {
        let app = Arc::clone(app);
        let stop = Arc::clone(stop);
        std::thread::spawn(move || serve_pipe(&app, &stop, name, sddl, level))
    })
    .collect()
}
