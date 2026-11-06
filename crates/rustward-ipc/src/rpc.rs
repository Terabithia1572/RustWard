//! Client and server loops over any [`Transport`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::frame::{self, FrameError};
use crate::transport::{Transport, TransportError};
use crate::validate::validate_request;
use crate::{
    ClientIdentity, ErrorCode, IpcError, PROTOCOL_VERSION, Request, RequestEnvelope, ResponseBody,
    ResponseEnvelope, authorize,
};

/// Default client timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle timeout after which the server closes a connection.
pub const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Handles validated, authorized requests.
pub trait Handler {
    /// Process one request.
    fn handle(
        &self,
        request: &Request,
        identity: &ClientIdentity,
    ) -> Result<ResponseBody, IpcError>;

    /// Called when a request is refused by authorization (before `handle`),
    /// so the server can audit the attempt. Must not fail or block for long.
    fn authorization_failed(
        &self,
        _request: &Request,
        _identity: &ClientIdentity,
        _error: &IpcError,
    ) {
    }

    /// Called when a request fails server-side validation (before
    /// authorization and `handle`). Must not fail or block for long.
    fn validation_failed(&self, _request: &Request, _identity: &ClientIdentity, _error: &IpcError) {
    }

    /// Called when the transport could not establish who sent a request
    /// (e.g. the Windows token could not be read). The request is refused
    /// with `Unauthorized` before validation, authorization and `handle`.
    fn identification_failed(&self, _request: &Request, _reason: &str) {}
}

/// Client-side errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    /// Transport failure.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// Bad frame from the server.
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    /// Server returned an error.
    #[error("server: {0}")]
    Server(IpcError),
    /// Response did not match the request.
    #[error("protocol violation: {0}")]
    Protocol(String),
}

impl ClientError {
    /// Map to an [`IpcError`] for the UI.
    #[must_use]
    pub fn into_ipc_error(self) -> IpcError {
        match self {
            Self::Server(e) => e,
            Self::Transport(TransportError::Timeout) => {
                IpcError::new(ErrorCode::Timeout, "the service did not answer in time")
            }
            Self::Transport(TransportError::Disconnected) => IpcError::new(
                ErrorCode::Unavailable,
                "the RustWard service is not reachable",
            ),
            Self::Transport(TransportError::PeerRejected(m)) => IpcError::new(
                ErrorCode::Unavailable,
                format!("service identity could not be verified: {m}"),
            ),
            other => IpcError::new(ErrorCode::Internal, other.to_string()),
        }
    }
}

/// IPC client.
#[derive(Debug)]
pub struct Client<T: Transport> {
    transport: T,
    next_id: u64,
    timeout: Duration,
}

impl<T: Transport> Client<T> {
    /// New client.
    pub fn new(transport: T, timeout: Duration) -> Self {
        Self {
            transport,
            next_id: 1,
            timeout,
        }
    }

    /// Send a request and wait for its response.
    pub fn call(&mut self, request: Request) -> Result<ResponseBody, ClientError> {
        let request_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let frame = frame::encode(&RequestEnvelope {
            version: PROTOCOL_VERSION,
            request_id,
            request,
        })?;
        self.transport.send(&frame)?;
        let reply = self.transport.recv(self.timeout)?;
        let env: ResponseEnvelope = frame::decode(&reply)?;
        if env.version != PROTOCOL_VERSION {
            return Err(ClientError::Protocol(format!(
                "server protocol version {}",
                env.version
            )));
        }
        if env.request_id != request_id {
            return Err(ClientError::Protocol(format!(
                "response id {} does not match request id {request_id}",
                env.request_id
            )));
        }
        env.result.map_err(ClientError::Server)
    }
}

/// Process one decoded request: version check, validation, authorization,
/// then the handler. Never panics on bad input.
pub fn process(
    env: &RequestEnvelope,
    identity: &ClientIdentity,
    handler: &dyn Handler,
) -> ResponseEnvelope {
    let result = if env.version == PROTOCOL_VERSION {
        validate_request(&env.request)
            .inspect_err(|e| handler.validation_failed(&env.request, identity, e))
            .and_then(|()| {
                authorize(&env.request, identity).inspect_err(|e| {
                    handler.authorization_failed(&env.request, identity, e);
                })
            })
            .and_then(|()| handler.handle(&env.request, identity))
    } else {
        Err(IpcError::new(
            ErrorCode::VersionMismatch,
            format!(
                "protocol version {} is not supported (server {PROTOCOL_VERSION})",
                env.version
            ),
        ))
    };
    ResponseEnvelope {
        version: PROTOCOL_VERSION,
        request_id: env.request_id,
        result,
    }
}

/// How a server connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// Client disconnected.
    Disconnected,
    /// Idle timeout.
    IdleTimeout,
    /// A malformed frame was received; connection closed defensively.
    ProtocolViolation(String),
    /// Transport error.
    TransportError(String),
    /// The caller of a request could not be identified; the request was
    /// refused and the connection closed.
    IdentificationFailed(String),
    /// The server is shutting down (checked between requests and while
    /// waiting for the next one).
    Shutdown,
}

/// How often a waiting connection checks for a shutdown request. Transports
/// must return [`TransportError::Timeout`] only when no part of a frame was
/// consumed, so waiting in slices never splits a frame.
pub const STOP_POLL: Duration = Duration::from_millis(200);

/// Serve one connection with a fixed identity (mock transports, in-process
/// backends and tests).
pub fn serve_connection<T: Transport>(
    transport: &mut T,
    identity: &ClientIdentity,
    handler: &dyn Handler,
    idle_timeout: Duration,
) -> SessionEnd {
    serve_connection_identified(transport, &|_| Ok(identity.clone()), handler, idle_timeout)
}

/// Serve one connection, identifying the caller **for every request**,
/// after its frame has been read. Windows impersonates "the security context
/// of the last message read from the pipe", so identity is only taken once
/// a request has actually been read. If identification fails, that request
/// is answered with `Unauthorized`, reported through
/// [`Handler::identification_failed`], and the connection is closed: no
/// request is ever processed without an established identity.
pub fn serve_connection_identified<T: Transport>(
    transport: &mut T,
    identify: &dyn Fn(&T) -> Result<ClientIdentity, TransportError>,
    handler: &dyn Handler,
    idle_timeout: Duration,
) -> SessionEnd {
    let never = AtomicBool::new(false);
    serve_connection_until(transport, identify, handler, idle_timeout, &never)
}

/// [`serve_connection_identified`] that also ends with
/// [`SessionEnd::Shutdown`] once `stop` is set: between requests, and within
/// [`STOP_POLL`] while waiting for the next request. A request that is
/// already being processed is completed and answered first.
pub fn serve_connection_until<T: Transport>(
    transport: &mut T,
    identify: &dyn Fn(&T) -> Result<ClientIdentity, TransportError>,
    handler: &dyn Handler,
    idle_timeout: Duration,
    stop: &AtomicBool,
) -> SessionEnd {
    loop {
        let mut idle = Duration::ZERO;
        let frame = loop {
            if stop.load(Ordering::SeqCst) {
                return SessionEnd::Shutdown;
            }
            let slice = STOP_POLL.min(idle_timeout.saturating_sub(idle));
            if slice.is_zero() {
                return SessionEnd::IdleTimeout;
            }
            match transport.recv(slice) {
                Ok(f) => break f,
                Err(TransportError::Timeout) => idle += slice,
                Err(TransportError::Disconnected) => return SessionEnd::Disconnected,
                Err(e) => return SessionEnd::TransportError(e.to_string()),
            }
        };
        let env: RequestEnvelope = match frame::decode(&frame) {
            Ok(e) => e,
            Err(e) => {
                let reply = ResponseEnvelope {
                    version: PROTOCOL_VERSION,
                    request_id: 0,
                    result: Err(IpcError::new(
                        ErrorCode::InvalidRequest,
                        "malformed request",
                    )),
                };
                if let Ok(f) = frame::encode(&reply) {
                    let _ = transport.send(&f);
                }
                return SessionEnd::ProtocolViolation(e.to_string());
            }
        };
        let identity = match identify(transport) {
            Ok(identity) => identity,
            Err(e) => {
                let reason = e.to_string();
                handler.identification_failed(&env.request, &reason);
                let reply = ResponseEnvelope {
                    version: PROTOCOL_VERSION,
                    request_id: env.request_id,
                    result: Err(IpcError::new(
                        ErrorCode::Unauthorized,
                        "the caller could not be identified",
                    )),
                };
                if let Ok(f) = frame::encode(&reply) {
                    let _ = transport.send(&f);
                }
                return SessionEnd::IdentificationFailed(reason);
            }
        };
        let reply = process(&env, &identity, handler);
        let encoded = frame::encode(&reply).or_else(|e| {
            frame::encode(&ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: env.request_id,
                result: Err(IpcError::new(
                    ErrorCode::Internal,
                    format!("response could not be encoded: {e}"),
                )),
            })
        });
        match encoded {
            Ok(f) => {
                if let Err(e) = transport.send(&f) {
                    return SessionEnd::TransportError(e.to_string());
                }
            }
            Err(e) => return SessionEnd::TransportError(e.to_string()),
        }
    }
}
