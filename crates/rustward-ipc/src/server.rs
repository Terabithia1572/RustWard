//! Connection-pooled IPC server loop (platform-independent).
//!
//! Used by the service for both named pipes; tested here with the in-memory
//! [`crate::transport::MockListener`]. Phase 9A findings addressed:
//!
//! - **F-13** (one client at a time): up to `max_connections` callers are
//!   served concurrently, each on its own thread, so an idle or slow client
//!   no longer blocks everyone else. Beyond the limit a new connection is
//!   closed immediately (the client sees "service unavailable" and retries).
//!   A local user can still occupy every slot until the idle timeout; that
//!   residual is documented (KNOWN-LIMITATIONS L-26).
//! - **F-14** (threads not joined at stop): [`ServerHandle::shutdown`] sets
//!   the stop flag, wakes the blocked `accept`, lets in-flight requests
//!   finish, and joins every thread within a deadline, reporting any thread
//!   it had to abandon.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::ClientIdentity;
use crate::rpc::{Handler, serve_connection_until};
use crate::transport::{MockListener, MockServerConn, Transport, TransportError};

/// A source of incoming connections.
pub trait Listener: Send + Sync + 'static {
    /// Connection type.
    type Conn: Transport + Send + 'static;
    /// Block until a client connects.
    fn accept(&self) -> Result<Self::Conn, TransportError>;
    /// Unblock a pending [`Self::accept`] (best effort; may be called
    /// repeatedly during shutdown).
    fn wake(&self);
    /// Identify the caller of the request just read from `conn`.
    fn identify(&self, conn: &Self::Conn) -> Result<ClientIdentity, TransportError>;
}

impl Listener for MockListener {
    type Conn = MockServerConn;
    fn accept(&self) -> Result<MockServerConn, TransportError> {
        self.accept_blocking()
    }
    fn wake(&self) {
        self.wake_blocking();
    }
    fn identify(&self, conn: &MockServerConn) -> Result<ClientIdentity, TransportError> {
        Ok(conn.identity().clone())
    }
}

/// Server limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    /// Connections served concurrently.
    pub max_connections: usize,
    /// A connection with no request for this long is closed.
    pub idle_timeout: Duration,
    /// Pause after a failed accept.
    pub accept_error_backoff: Duration,
}

/// Counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Connections handed to a worker.
    pub accepted: u64,
    /// Connections closed because all slots were busy.
    pub rejected_busy: u64,
    /// Failed accepts.
    pub accept_errors: u64,
}

/// Result of [`ServerHandle::shutdown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// The accept loop ended.
    pub acceptor_stopped: bool,
    /// Connection threads that ended and were joined.
    pub connections_joined: usize,
    /// Connection threads still running at the deadline (detached).
    pub connections_abandoned: usize,
}

impl ShutdownReport {
    /// Everything stopped within the deadline.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.acceptor_stopped && self.connections_abandoned == 0
    }
}

/// Callback for failed accepts: error and consecutive-failure count.
pub type AcceptErrorHook = Arc<dyn Fn(&TransportError, u64) + Send + Sync>;

/// A running server.
pub struct ServerHandle {
    stop: Arc<AtomicBool>,
    wake: Arc<dyn Fn() + Send + Sync>,
    acceptor: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    active: Arc<AtomicUsize>,
    stats: Arc<Mutex<ServerStats>>,
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle")
            .field("active", &self.active.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// Decrements the active-connection count even if a worker unwinds.
struct ActiveGuard(Arc<AtomicUsize>);
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn reap(workers: &Mutex<Vec<JoinHandle<()>>>) {
    if let Ok(mut w) = workers.lock() {
        let (done, running): (Vec<_>, Vec<_>) = w.drain(..).partition(JoinHandle::is_finished);
        *w = running;
        for h in done {
            let _ = h.join();
        }
    }
}

/// Start serving `listener` with `handler`.
pub fn spawn_server<L, H>(
    listener: Arc<L>,
    handler: Arc<H>,
    config: ServerConfig,
    on_accept_error: AcceptErrorHook,
) -> ServerHandle
where
    L: Listener,
    H: Handler + Send + Sync + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let active = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(Mutex::new(ServerStats::default()));
    let wake: Arc<dyn Fn() + Send + Sync> = {
        let l = Arc::clone(&listener);
        Arc::new(move || l.wake())
    };

    let acceptor = {
        let (stop, workers, active, stats) = (
            Arc::clone(&stop),
            Arc::clone(&workers),
            Arc::clone(&active),
            Arc::clone(&stats),
        );
        thread::spawn(move || {
            let mut consecutive_errors = 0u64;
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok(conn) => {
                        consecutive_errors = 0;
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        reap(&workers);
                        if active.load(Ordering::SeqCst) >= config.max_connections {
                            if let Ok(mut s) = stats.lock() {
                                s.rejected_busy += 1;
                            }
                            drop(conn);
                            continue;
                        }
                        active.fetch_add(1, Ordering::SeqCst);
                        if let Ok(mut s) = stats.lock() {
                            s.accepted += 1;
                        }
                        let guard = ActiveGuard(Arc::clone(&active));
                        let (l, h, st) = (
                            Arc::clone(&listener),
                            Arc::clone(&handler),
                            Arc::clone(&stop),
                        );
                        let worker = thread::spawn(move || {
                            let _guard = guard;
                            let mut conn = conn;
                            let identify = |c: &L::Conn| l.identify(c);
                            let _ = serve_connection_until(
                                &mut conn,
                                &identify,
                                h.as_ref(),
                                config.idle_timeout,
                                &st,
                            );
                        });
                        if let Ok(mut w) = workers.lock() {
                            w.push(worker);
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        if let Ok(mut s) = stats.lock() {
                            s.accept_errors += 1;
                        }
                        on_accept_error(&e, consecutive_errors);
                        let until = Instant::now() + config.accept_error_backoff;
                        while Instant::now() < until && !stop.load(Ordering::SeqCst) {
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            }
        })
    };

    ServerHandle {
        stop,
        wake,
        acceptor: Some(acceptor),
        workers,
        active,
        stats,
    }
}

impl ServerHandle {
    /// Connections currently being served.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Counters so far.
    #[must_use]
    pub fn stats(&self) -> ServerStats {
        self.stats.lock().map(|s| *s).unwrap_or_default()
    }

    /// Stop accepting, let in-flight requests finish, and join all threads
    /// within `deadline`.
    #[must_use]
    pub fn shutdown(mut self, deadline: Duration) -> ShutdownReport {
        let end = Instant::now() + deadline;
        self.stop.store(true, Ordering::SeqCst);
        let mut acceptor_stopped = true;
        if let Some(acceptor) = self.acceptor.take() {
            // Wake repeatedly: the first wake may race with the acceptor
            // entering `accept`.
            while !acceptor.is_finished() && Instant::now() < end {
                (self.wake)();
                thread::sleep(Duration::from_millis(50));
            }
            if acceptor.is_finished() {
                let _ = acceptor.join();
            } else {
                acceptor_stopped = false;
            }
        }
        let mut pending: Vec<JoinHandle<()>> = self
            .workers
            .lock()
            .map(|mut w| w.drain(..).collect())
            .unwrap_or_default();
        let mut joined = 0usize;
        loop {
            let (done, running): (Vec<_>, Vec<_>) =
                pending.into_iter().partition(JoinHandle::is_finished);
            for h in done {
                let _ = h.join();
                joined += 1;
            }
            pending = running;
            if pending.is_empty() || Instant::now() >= end {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        ShutdownReport {
            acceptor_stopped,
            connections_joined: joined,
            connections_abandoned: pending.len(),
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        // Not shut down explicitly: at least stop accepting.
        if self.acceptor.is_some() {
            self.stop.store(true, Ordering::SeqCst);
            (self.wake)();
        }
    }
}
