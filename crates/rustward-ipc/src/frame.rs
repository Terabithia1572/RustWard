//! Length-prefixed JSON frames: `u32 little-endian length` + UTF-8 JSON.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Maximum frame payload (4 MiB; exports are paged below this).
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Framing errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// Payload larger than [`MAX_FRAME_BYTES`].
    #[error("frame of {0} bytes exceeds the limit")]
    TooLarge(usize),
    /// Fewer bytes than the header announces.
    #[error("truncated frame")]
    Truncated,
    /// JSON error.
    #[error("invalid frame payload: {0}")]
    Payload(String),
}

/// Encode a value as one frame.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(value).map_err(|e| FrameError::Payload(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(body.len()))?;
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse the 4-byte header.
pub fn payload_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = usize::try_from(u32::from_le_bytes(header))
        .map_err(|_| FrameError::TooLarge(usize::MAX))?;
    if len > MAX_FRAME_BYTES {
        Err(FrameError::TooLarge(len))
    } else {
        Ok(len)
    }
}

/// Decode one complete frame (header + payload).
pub fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    let header: [u8; 4] = frame
        .get(..4)
        .and_then(|h| h.try_into().ok())
        .ok_or(FrameError::Truncated)?;
    let len = payload_len(header)?;
    let body = frame.get(4..4 + len).ok_or(FrameError::Truncated)?;
    if frame.len() != 4 + len {
        return Err(FrameError::Payload("trailing bytes after frame".into()));
    }
    serde_json::from_slice(body).map_err(|e| FrameError::Payload(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PROTOCOL_VERSION, Request, RequestEnvelope};

    #[test]
    fn round_trip() {
        let env = RequestEnvelope {
            version: PROTOCOL_VERSION,
            request_id: 7,
            request: Request::ListDevices {
                include_absent: true,
            },
            auth_token: None,
        };
        let f = encode(&env).unwrap();
        assert_eq!(decode::<RequestEnvelope>(&f).unwrap(), env);
    }

    #[test]
    fn rejects_malformed_frames() {
        assert_eq!(
            decode::<RequestEnvelope>(&[1, 0]),
            Err(FrameError::Truncated)
        );
        let huge = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_le_bytes();
        assert!(matches!(
            decode::<RequestEnvelope>(&huge),
            Err(FrameError::TooLarge(_))
        ));
        let mut f = encode(&serde_json::json!({"x": 1})).unwrap();
        f.push(b' ');
        assert!(matches!(
            decode::<serde_json::Value>(&f),
            Err(FrameError::Payload(_))
        ));
        let mut short = encode(&serde_json::json!({"x": 1})).unwrap();
        short.pop();
        assert_eq!(
            decode::<serde_json::Value>(&short),
            Err(FrameError::Truncated)
        );
        let not_json = [3, 0, 0, 0, b'a', b'b', b'c'];
        assert!(matches!(
            decode::<serde_json::Value>(&not_json),
            Err(FrameError::Payload(_))
        ));
        // Unknown request type is rejected, never coerced.
        let unknown = encode(&serde_json::json!({"version": 1, "request_id": 1, "request": {"type": "run_shell", "cmd": "x"}})).unwrap();
        assert!(matches!(
            decode::<RequestEnvelope>(&unknown),
            Err(FrameError::Payload(_))
        ));
    }
}
