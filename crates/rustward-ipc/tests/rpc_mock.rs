//! End-to-end RPC tests over the in-memory transport.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rustward_ipc::frame;
use rustward_ipc::messages::{AccessLevel, Request, ResponseBody};
use rustward_ipc::rpc::{
    Client, ClientError, Handler, SessionEnd, serve_connection, serve_connection_identified,
};
use rustward_ipc::transport::{Transport, TransportError, mock_pair};
use rustward_ipc::{
    ClientIdentity, ErrorCode, IdentitySource, IpcError, PROTOCOL_VERSION, RequestEnvelope,
    ResponseEnvelope,
};

#[derive(Default)]
struct CountingHandler {
    calls: AtomicUsize,
    rejected: std::sync::Mutex<Vec<String>>,
    unidentified: std::sync::Mutex<Vec<String>>,
}

impl Handler for CountingHandler {
    fn handle(
        &self,
        request: &Request,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match request {
            Request::GetSettings => Err(IpcError::new(ErrorCode::NotFound, "no settings")),
            _ => Ok(ResponseBody::Done {
                message: format!("{} by {}", request.name(), identity.actor()),
            }),
        }
    }

    fn authorization_failed(&self, request: &Request, identity: &ClientIdentity, error: &IpcError) {
        assert_eq!(error.code, ErrorCode::Unauthorized);
        self.rejected
            .lock()
            .unwrap()
            .push(format!("{} by {}", request.name(), identity.actor()));
    }

    fn identification_failed(&self, request: &Request, reason: &str) {
        self.unidentified
            .lock()
            .unwrap()
            .push(format!("{}: {reason}", request.name()));
    }
}

fn identity(admin: bool, channel: AccessLevel) -> ClientIdentity {
    ClientIdentity {
        account: "PC-01\\operator".into(),
        sid: None,
        is_administrator: admin,
        elevated: admin,
        source: IdentitySource::Test,
        channel_max_access: channel,
    }
}

fn spawn_server(
    id: ClientIdentity,
    handler: Arc<CountingHandler>,
) -> (
    rustward_ipc::transport::MockEnd,
    thread::JoinHandle<SessionEnd>,
) {
    let (client_end, mut server_end) = mock_pair();
    let h = thread::spawn(move || {
        serve_connection(
            &mut server_end,
            &id,
            handler.as_ref(),
            Duration::from_secs(2),
        )
    });
    (client_end, h)
}

#[test]
fn read_only_request_round_trip_and_error_propagation() {
    let handler = Arc::new(CountingHandler::default());
    let (end, server) = spawn_server(identity(false, AccessLevel::ReadOnly), handler.clone());
    let mut client = Client::new(end, Duration::from_secs(2));
    match client.call(Request::GetDashboard).unwrap() {
        ResponseBody::Done { message } => assert_eq!(message, "get_dashboard by PC-01\\operator"),
        other => panic!("{other:?}"),
    }
    match client.call(Request::GetSettings) {
        Err(ClientError::Server(e)) => assert_eq!(e.code, ErrorCode::NotFound),
        other => panic!("{other:?}"),
    }
    drop(client);
    assert_eq!(server.join().unwrap(), SessionEnd::Disconnected);
    assert_eq!(handler.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn privileged_requests_are_refused_before_reaching_the_handler() {
    let handler = Arc::new(CountingHandler::default());
    let (end, _server) = spawn_server(identity(false, AccessLevel::Administrator), handler.clone());
    let mut client = Client::new(end, Duration::from_secs(2));
    let r = client.call(Request::RemoveManufacturer {
        id: "sandisk".into(),
        expected_policy_version: 1,
    });
    match r {
        Err(ClientError::Server(e)) => assert_eq!(e.code, ErrorCode::Unauthorized),
        other => panic!("{other:?}"),
    }
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *handler.rejected.lock().unwrap(),
        ["remove_manufacturer by PC-01\\operator"],
        "the refused attempt is reported for auditing"
    );
}

#[test]
fn invalid_requests_are_not_reported_as_authorization_failures() {
    let handler = Arc::new(CountingHandler::default());
    let (end, _server) = spawn_server(identity(false, AccessLevel::ReadOnly), handler.clone());
    let mut client = Client::new(end, Duration::from_secs(2));
    let _ = client.call(Request::PrepareRestore {
        file_name: "..\\..\\evil.db".into(),
    });
    let _ = client.call(Request::GetDashboard);
    assert!(handler.rejected.lock().unwrap().is_empty());
}

#[test]
fn admin_on_read_only_channel_is_refused() {
    let handler = Arc::new(CountingHandler::default());
    let (end, _server) = spawn_server(identity(true, AccessLevel::ReadOnly), handler.clone());
    let mut client = Client::new(end, Duration::from_secs(2));
    let r = client.call(Request::ApplyRetention);
    assert!(matches!(
        r,
        Err(ClientError::Server(IpcError {
            code: ErrorCode::Unauthorized,
            ..
        }))
    ));
}

#[test]
fn invalid_input_is_rejected_server_side() {
    let handler = Arc::new(CountingHandler::default());
    let (end, _server) = spawn_server(identity(true, AccessLevel::Administrator), handler.clone());
    let mut client = Client::new(end, Duration::from_secs(2));
    let r = client.call(Request::RemoveManufacturer {
        id: "../../x".into(),
        expected_policy_version: 1,
    });
    assert!(matches!(
        r,
        Err(ClientError::Server(IpcError {
            code: ErrorCode::InvalidRequest,
            ..
        }))
    ));
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn version_mismatch_is_reported() {
    let handler = Arc::new(CountingHandler::default());
    let (mut end, _server) = spawn_server(identity(true, AccessLevel::Administrator), handler);
    let f = frame::encode(&RequestEnvelope {
        version: 99,
        request_id: 5,
        request: Request::GetDashboard,
    })
    .unwrap();
    end.send(&f).unwrap();
    let reply: ResponseEnvelope =
        frame::decode(&end.recv(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(reply.request_id, 5);
    assert_eq!(reply.version, PROTOCOL_VERSION);
    assert!(matches!(
        reply.result,
        Err(IpcError {
            code: ErrorCode::VersionMismatch,
            ..
        })
    ));
}

#[test]
fn malformed_frame_closes_the_connection() {
    let handler = Arc::new(CountingHandler::default());
    let (mut end, server) = spawn_server(identity(true, AccessLevel::Administrator), handler);
    let bogus = frame::encode(&serde_json::json!({"version": 1, "request_id": 1, "request": {"type": "exec", "cmd": "calc.exe"}})).unwrap();
    end.send(&bogus).unwrap();
    let reply: ResponseEnvelope =
        frame::decode(&end.recv(Duration::from_secs(2)).unwrap()).unwrap();
    assert!(matches!(
        reply.result,
        Err(IpcError {
            code: ErrorCode::InvalidRequest,
            ..
        })
    ));
    assert!(matches!(
        server.join().unwrap(),
        SessionEnd::ProtocolViolation(_)
    ));
    assert_eq!(
        end.recv(Duration::from_millis(100)),
        Err(TransportError::Disconnected)
    );
}

#[test]
fn client_times_out_and_server_idles_out() {
    let (end, _peer) = mock_pair();
    let mut client = Client::new(end, Duration::from_millis(50));
    assert_eq!(
        client.call(Request::GetDashboard),
        Err(ClientError::Transport(TransportError::Timeout))
    );
    let e = ClientError::Transport(TransportError::Timeout).into_ipc_error();
    assert_eq!(e.code, ErrorCode::Timeout);

    let (_client_end, mut server_end) = mock_pair();
    let handler = CountingHandler::default();
    let end = serve_connection(
        &mut server_end,
        &identity(false, AccessLevel::ReadOnly),
        &handler,
        Duration::from_millis(50),
    );
    assert_eq!(end, SessionEnd::IdleTimeout);
}

#[test]
fn disconnected_service_maps_to_unavailable() {
    let (end, peer) = mock_pair();
    drop(peer);
    let mut client = Client::new(end, Duration::from_millis(50));
    let e = client
        .call(Request::GetDashboard)
        .unwrap_err()
        .into_ipc_error();
    assert_eq!(e.code, ErrorCode::Unavailable);
}

#[test]
fn mismatched_response_id_is_a_protocol_violation() {
    let (end, mut peer) = mock_pair();
    let t = thread::spawn(move || {
        let _ = peer.recv(Duration::from_secs(2)).unwrap();
        let f = frame::encode(&ResponseEnvelope {
            version: PROTOCOL_VERSION,
            request_id: 999,
            result: Ok(ResponseBody::Done {
                message: "spoof".into(),
            }),
        })
        .unwrap();
        peer.send(&f).unwrap();
        peer
    });
    let mut client = Client::new(end, Duration::from_secs(2));
    assert!(matches!(
        client.call(Request::GetDashboard),
        Err(ClientError::Protocol(_))
    ));
    let _ = t.join();
}

#[test]
fn caller_is_identified_for_every_request_after_it_is_read() {
    // The identity source changes between requests (e.g. a different token
    // context on the same pipe): each request must be judged on its own.
    let handler = Arc::new(CountingHandler::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let (client_end, mut server_end) = mock_pair();
    let server = {
        let handler = Arc::clone(&handler);
        let calls = Arc::clone(&calls);
        thread::spawn(move || {
            let identify = move |_: &rustward_ipc::transport::MockEnd| {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                Ok(identity(n == 1, AccessLevel::Administrator))
            };
            serve_connection_identified(
                &mut server_end,
                &identify,
                handler.as_ref(),
                Duration::from_secs(2),
            )
        })
    };
    let mut client = Client::new(client_end, Duration::from_secs(2));
    let privileged = || Request::RemoveManufacturer {
        id: "kingston".into(),
        expected_policy_version: 1,
    };
    assert!(matches!(
        client.call(privileged()),
        Err(ClientError::Server(e)) if e.code == ErrorCode::Unauthorized
    ));
    assert!(
        client.call(privileged()).is_ok(),
        "second request by an admin"
    );
    assert!(matches!(
        client.call(privileged()),
        Err(ClientError::Server(e)) if e.code == ErrorCode::Unauthorized
    ));
    drop(client);
    assert_eq!(server.join().unwrap(), SessionEnd::Disconnected);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "one identification per request"
    );
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
    assert_eq!(handler.rejected.lock().unwrap().len(), 2);
}

#[test]
fn a_caller_that_cannot_be_identified_is_refused_and_disconnected() {
    let handler = Arc::new(CountingHandler::default());
    let (client_end, mut server_end) = mock_pair();
    let server = {
        let handler = Arc::clone(&handler);
        thread::spawn(move || {
            let identify = |_: &rustward_ipc::transport::MockEnd| {
                Err(TransportError::Io(
                    "OpenThreadToken failed with Win32 error 1368".into(),
                ))
            };
            serve_connection_identified(
                &mut server_end,
                &identify,
                handler.as_ref(),
                Duration::from_secs(2),
            )
        })
    };
    let mut client = Client::new(client_end, Duration::from_secs(2));
    // Even a read-only request is refused without an identity.
    match client.call(Request::GetDashboard) {
        Err(ClientError::Server(e)) => assert_eq!(e.code, ErrorCode::Unauthorized),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        server.join().unwrap(),
        SessionEnd::IdentificationFailed(r) if r.contains("1368")
    ));
    assert_eq!(
        handler.calls.load(Ordering::SeqCst),
        0,
        "handler never reached"
    );
    let unidentified = handler.unidentified.lock().unwrap();
    assert_eq!(unidentified.len(), 1);
    assert!(unidentified[0].starts_with("get_dashboard"));
}
