//! Connection-pool server tests (F-13 concurrency, F-14 shutdown) over the
//! in-memory listener. The Windows named-pipe listener plugs into the same
//! pool; its OS behaviour is NOT covered here (WINDOWS-VM-ACCEPTANCE.md C7–C13).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rustward_ipc::messages::{AccessLevel, Request, ResponseBody};
use rustward_ipc::rpc::{Client, ClientError, Handler};
use rustward_ipc::server::{ServerConfig, spawn_server};
use rustward_ipc::transport::{TransportError, mock_listener};
use rustward_ipc::{ClientIdentity, IdentitySource, IpcError};

#[derive(Default)]
struct SlowHandler {
    calls: AtomicUsize,
    delay_ms: u64,
}

impl Handler for SlowHandler {
    fn handle(
        &self,
        request: &Request,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError> {
        thread::sleep(Duration::from_millis(self.delay_ms));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ResponseBody::Done {
            message: format!("{} by {}", request.name(), identity.account),
            message_tr: String::new(),
        })
    }
}

fn user(name: &str) -> ClientIdentity {
    ClientIdentity {
        account: format!("PC-01\\{name}"),
        sid: None,
        is_administrator: false,
        elevated: false,
        source: IdentitySource::Test,
        channel_max_access: AccessLevel::ReadOnly,
    }
}

fn config(max: usize, idle_secs: u64) -> ServerConfig {
    ServerConfig {
        max_connections: max,
        idle_timeout: Duration::from_secs(idle_secs),
        accept_error_backoff: Duration::from_millis(50),
    }
}

fn no_errors() -> rustward_ipc::server::AcceptErrorHook {
    Arc::new(|_: &TransportError, _: u64| {})
}

#[test]
fn idle_clients_do_not_block_other_callers() {
    let (connector, listener) = mock_listener();
    let handler = Arc::new(SlowHandler::default());
    let server = spawn_server(
        Arc::new(listener),
        Arc::clone(&handler),
        config(4, 30),
        no_errors(),
    );
    // Three connections that never send anything (the F-13 attack against
    // a one-instance pipe).
    let hogs: Vec<_> = (0..3)
        .map(|i| connector.connect(user(&format!("hog{i}"))).unwrap())
        .collect();
    let mut client = Client::new(
        connector.connect(user("operator")).unwrap(),
        Duration::from_secs(2),
    );
    match client.call(Request::GetDashboard).unwrap() {
        ResponseBody::Done { message, .. } => {
            assert_eq!(message, "get_dashboard by PC-01\\operator")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
    drop((hogs, client));
    let report = server.shutdown(Duration::from_secs(3));
    assert!(report.is_complete(), "{report:?}");
}

#[test]
fn connections_beyond_the_limit_are_refused_and_slots_are_reused() {
    let (connector, listener) = mock_listener();
    let handler = Arc::new(SlowHandler::default());
    let server = spawn_server(
        Arc::new(listener),
        Arc::clone(&handler),
        config(2, 30),
        no_errors(),
    );
    let hog_a = connector.connect(user("a")).unwrap();
    let hog_b = connector.connect(user("b")).unwrap();
    // Wait until both occupy a slot.
    let until = Instant::now() + Duration::from_secs(2);
    while server.active_connections() < 2 && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    let mut third = Client::new(
        connector.connect(user("c")).unwrap(),
        Duration::from_secs(2),
    );
    match third.call(Request::GetDashboard) {
        Err(ClientError::Transport(TransportError::Disconnected)) => {}
        other => panic!("expected an immediate close, got {other:?}"),
    }
    assert_eq!(server.stats().rejected_busy, 1);
    // A slot frees up: the next caller is served.
    drop(hog_a);
    let until = Instant::now() + Duration::from_secs(2);
    while server.active_connections() > 1 && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    let mut fourth = Client::new(
        connector.connect(user("d")).unwrap(),
        Duration::from_secs(2),
    );
    assert!(fourth.call(Request::GetDashboard).is_ok());
    drop((hog_b, fourth, third));
    assert!(server.shutdown(Duration::from_secs(3)).is_complete());
}

#[test]
fn idle_connections_end_after_the_idle_timeout() {
    let (connector, listener) = mock_listener();
    let server = spawn_server(
        Arc::new(listener),
        Arc::new(SlowHandler::default()),
        ServerConfig {
            idle_timeout: Duration::from_millis(400),
            ..config(1, 0)
        },
        no_errors(),
    );
    let _hog = connector.connect(user("hog")).unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    while server.active_connections() == 0 && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(server.active_connections(), 1);
    thread::sleep(Duration::from_millis(900));
    assert_eq!(server.active_connections(), 0, "the hog was disconnected");
    assert!(server.shutdown(Duration::from_secs(3)).is_complete());
}

#[test]
fn shutdown_joins_every_thread_promptly_even_with_idle_clients() {
    let (connector, listener) = mock_listener();
    let server = spawn_server(
        Arc::new(listener),
        Arc::new(SlowHandler::default()),
        config(8, 600),
        no_errors(),
    );
    let idle: Vec<_> = (0..5)
        .map(|i| connector.connect(user(&format!("u{i}"))).unwrap())
        .collect();
    let until = Instant::now() + Duration::from_secs(2);
    while server.active_connections() < 5 && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    let started = Instant::now();
    let report = server.shutdown(Duration::from_secs(5));
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.connections_joined, 5);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "idle connections notice the stop within the poll interval, not the 600 s idle timeout"
    );
    drop(idle);
}

#[test]
fn shutdown_lets_an_in_flight_request_finish_and_answers_it() {
    let (connector, listener) = mock_listener();
    let handler = Arc::new(SlowHandler {
        delay_ms: 400,
        ..SlowHandler::default()
    });
    let server = spawn_server(
        Arc::new(listener),
        Arc::clone(&handler),
        config(2, 30),
        no_errors(),
    );
    let mut client = Client::new(
        connector.connect(user("op")).unwrap(),
        Duration::from_secs(3),
    );
    let call = thread::spawn(move || client.call(Request::GetDashboard));
    thread::sleep(Duration::from_millis(150));
    let report = server.shutdown(Duration::from_secs(3));
    assert!(report.is_complete(), "{report:?}");
    assert!(
        call.join().unwrap().is_ok(),
        "the request in flight was answered"
    );
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn shutdown_reports_threads_it_could_not_join() {
    let (connector, listener) = mock_listener();
    let handler = Arc::new(SlowHandler {
        delay_ms: 1500,
        ..SlowHandler::default()
    });
    let server = spawn_server(
        Arc::new(listener),
        Arc::clone(&handler),
        config(2, 30),
        no_errors(),
    );
    let mut client = Client::new(
        connector.connect(user("op")).unwrap(),
        Duration::from_secs(5),
    );
    let call = thread::spawn(move || client.call(Request::GetDashboard));
    thread::sleep(Duration::from_millis(150));
    let report = server.shutdown(Duration::from_millis(300));
    assert!(report.acceptor_stopped);
    assert_eq!(report.connections_abandoned, 1);
    assert!(!report.is_complete());
    let _ = call.join();
}

#[test]
fn accept_errors_are_reported_with_a_consecutive_count_and_backoff() {
    use rustward_ipc::server::Listener;
    use std::sync::Mutex;

    struct Failing {
        inner: rustward_ipc::transport::MockListener,
        remaining: AtomicUsize,
    }
    impl Listener for Failing {
        type Conn = rustward_ipc::transport::MockServerConn;
        fn accept(&self) -> Result<Self::Conn, TransportError> {
            if self.remaining.load(Ordering::SeqCst) > 0 {
                self.remaining.fetch_sub(1, Ordering::SeqCst);
                return Err(TransportError::Io("CreateNamedPipeW failed".into()));
            }
            self.inner.accept_blocking()
        }
        fn wake(&self) {
            self.inner.wake_blocking();
        }
        fn identify(&self, c: &Self::Conn) -> Result<ClientIdentity, TransportError> {
            Ok(c.identity().clone())
        }
    }
    let (connector, inner) = mock_listener();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let hook = {
        let seen = Arc::clone(&seen);
        Arc::new(move |e: &TransportError, n: u64| seen.lock().unwrap().push((e.to_string(), n)))
    };
    let server = spawn_server(
        Arc::new(Failing {
            inner,
            remaining: AtomicUsize::new(3),
        }),
        Arc::new(SlowHandler::default()),
        config(2, 30),
        hook,
    );
    let mut client = Client::new(
        connector.connect(user("op")).unwrap(),
        Duration::from_secs(3),
    );
    assert!(
        client.call(Request::GetDashboard).is_ok(),
        "recovers after the errors"
    );
    let counts: Vec<u64> = seen.lock().unwrap().iter().map(|(_, n)| *n).collect();
    assert_eq!(counts, [1, 2, 3]);
    assert_eq!(server.stats().accept_errors, 3);
    drop(client);
    assert!(server.shutdown(Duration::from_secs(3)).is_complete());
}
