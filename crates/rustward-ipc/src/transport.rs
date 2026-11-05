//! Transport abstraction and an in-memory mock.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

use crate::frame::{MAX_FRAME_BYTES, payload_len};

/// Transport errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    /// No complete frame within the timeout.
    #[error("timed out")]
    Timeout,
    /// Peer disconnected.
    #[error("peer disconnected")]
    Disconnected,
    /// Frame exceeds the limit.
    #[error("frame too large")]
    FrameTooLarge,
    /// Peer verification failed (e.g. pipe server not in session 0).
    #[error("peer verification failed: {0}")]
    PeerRejected(String),
    /// OS error.
    #[error("I/O error: {0}")]
    Io(String),
}

/// A bidirectional frame transport.
pub trait Transport {
    /// Send one complete frame (header + payload).
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError>;
    /// Receive one complete frame (header + payload).
    fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError>;
}

/// One end of an in-memory connection. Dropping it disconnects the peer.
#[derive(Debug)]
pub struct MockEnd {
    tx: Option<Sender<Vec<u8>>>,
    rx: Receiver<Vec<u8>>,
}

/// Create a connected pair.
#[must_use]
pub fn mock_pair() -> (MockEnd, MockEnd) {
    let (a_tx, b_rx) = channel();
    let (b_tx, a_rx) = channel();
    (
        MockEnd {
            tx: Some(a_tx),
            rx: a_rx,
        },
        MockEnd {
            tx: Some(b_tx),
            rx: b_rx,
        },
    )
}

impl MockEnd {
    /// Close the sending side (simulates a peer that stops writing).
    pub fn close(&mut self) {
        self.tx = None;
    }
}

impl Transport for MockEnd {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > MAX_FRAME_BYTES + 4 {
            return Err(TransportError::FrameTooLarge);
        }
        self.tx
            .as_ref()
            .ok_or(TransportError::Disconnected)?
            .send(frame.to_vec())
            .map_err(|_| TransportError::Disconnected)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        let frame = match self.rx.recv_timeout(timeout) {
            Ok(f) => f,
            Err(RecvTimeoutError::Timeout) => return Err(TransportError::Timeout),
            Err(RecvTimeoutError::Disconnected) => return Err(TransportError::Disconnected),
        };
        let header: [u8; 4] = frame
            .get(..4)
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| TransportError::Io("short frame".into()))?;
        payload_len(header).map_err(|_| TransportError::FrameTooLarge)?;
        Ok(frame)
    }
}
