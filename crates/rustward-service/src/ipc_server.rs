//! Named-pipe servers for the admin and status channels.
//! **NOT VERIFIED ON WINDOWS** (type-checked only). Pool policy, limits and
//! shutdown are platform-independent and tested in [`crate::ipc_pool`].

use std::sync::Arc;

use rustward_app::AppService;
use rustward_ipc::messages::AccessLevel;
use rustward_ipc::pipe::PipeListener;
use rustward_ipc::{PIPE_NAME_ADMIN, PIPE_NAME_STATUS, SDDL_ADMIN, SDDL_STATUS};

use crate::ipc_pool::{MAX_ADMIN_CONNECTIONS, MAX_STATUS_CONNECTIONS, PipeServers};

/// Start both pooled pipe servers. Call [`PipeServers::shutdown`] after the
/// runtime loop ends, before reporting `SERVICE_STOPPED`.
pub fn spawn_pipe_servers(app: &Arc<AppService>) -> PipeServers {
    crate::ipc_pool::spawn(
        app,
        vec![
            (
                PIPE_NAME_ADMIN,
                Arc::new(PipeListener::new(
                    PIPE_NAME_ADMIN,
                    SDDL_ADMIN,
                    AccessLevel::Administrator,
                )),
                MAX_ADMIN_CONNECTIONS,
            ),
            (
                PIPE_NAME_STATUS,
                Arc::new(PipeListener::new(
                    PIPE_NAME_STATUS,
                    SDDL_STATUS,
                    AccessLevel::ReadOnly,
                )),
                MAX_STATUS_CONNECTIONS,
            ),
        ],
    )
}
