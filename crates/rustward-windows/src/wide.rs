//! Platform-neutral decoding of Windows property buffers.
//!
//! Kept separate from the FFI code so it can be unit-tested on any host.

use windows_sys::Win32::Devices::Properties::{
    DEVPROP_TYPE_BOOLEAN, DEVPROP_TYPE_GUID, DEVPROP_TYPE_STRING, DEVPROP_TYPE_STRING_LIST,
    DEVPROP_TYPE_UINT32, DEVPROPTYPE,
};

/// A decoded device property value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropValue {
    /// `DEVPROP_TYPE_STRING`.
    String(String),
    /// `DEVPROP_TYPE_STRING_LIST` (REG_MULTI_SZ layout).
    StringList(Vec<String>),
    /// `DEVPROP_TYPE_GUID`, formatted `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` lower-case.
    Guid(String),
    /// `DEVPROP_TYPE_BOOLEAN`.
    Bool(bool),
    /// `DEVPROP_TYPE_UINT32`.
    U32(u32),
    /// Any other type, or a malformed buffer. Holds the property type.
    Unsupported(DEVPROPTYPE),
}

impl PropValue {
    /// String value, if this is a string.
    #[must_use]
    pub fn into_string(self) -> Option<String> {
        match self {
            Self::String(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }

    /// String list, if this is a list (a single string becomes a 1-element list).
    #[must_use]
    pub fn into_string_list(self) -> Vec<String> {
        match self {
            Self::StringList(v) => v,
            Self::String(s) if !s.is_empty() => vec![s],
            _ => Vec::new(),
        }
    }

    /// GUID string.
    #[must_use]
    pub fn into_guid(self) -> Option<String> {
        match self {
            Self::Guid(g) => Some(g),
            _ => None,
        }
    }

    /// Boolean.
    #[must_use]
    pub fn into_bool(self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(b),
            _ => None,
        }
    }

    /// u32.
    #[must_use]
    pub fn into_u32(self) -> Option<u32> {
        match self {
            Self::U32(v) => Some(v),
            _ => None,
        }
    }
}

/// Little-endian bytes → UTF-16 code units (a trailing odd byte is ignored).
#[must_use]
pub fn bytes_to_u16(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// UTF-16 up to the first NUL, lossily converted.
#[must_use]
pub fn utf16_until_nul(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// Parse a REG_MULTI_SZ-style buffer (`a\0b\0\0`). Stops at the first
/// empty string.
#[must_use]
pub fn parse_multi_sz(units: &[u16]) -> Vec<String> {
    units
        .split(|&u| u == 0)
        .take_while(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// Format a 16-byte GUID buffer (Data1/2/3 little-endian).
#[must_use]
pub fn guid_bytes_to_string(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.get(..16)?.try_into().ok()?;
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    Some(format!(
        "{{{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// Decode a property buffer by its `DEVPROPTYPE`.
#[must_use]
pub fn decode_property(prop_type: DEVPROPTYPE, bytes: &[u8]) -> PropValue {
    match prop_type {
        DEVPROP_TYPE_STRING => PropValue::String(utf16_until_nul(&bytes_to_u16(bytes))),
        DEVPROP_TYPE_STRING_LIST => PropValue::StringList(parse_multi_sz(&bytes_to_u16(bytes))),
        DEVPROP_TYPE_GUID => {
            guid_bytes_to_string(bytes).map_or(PropValue::Unsupported(prop_type), PropValue::Guid)
        }
        DEVPROP_TYPE_BOOLEAN => match bytes.first() {
            Some(&v) => PropValue::Bool(v != 0),
            None => PropValue::Unsupported(prop_type),
        },
        DEVPROP_TYPE_UINT32 => match bytes.get(..4) {
            Some(b) => PropValue::U32(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            None => PropValue::Unsupported(prop_type),
        },
        other => PropValue::Unsupported(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn decodes_strings_and_lists() {
        assert_eq!(
            decode_property(DEVPROP_TYPE_STRING, &wide_bytes("SanDisk\0junk")),
            PropValue::String("SanDisk".into())
        );
        let list = decode_property(
            DEVPROP_TYPE_STRING_LIST,
            &wide_bytes("USBSTOR\\DiskSanDisk_\0GenDisk\0\0trailing"),
        );
        assert_eq!(
            list.into_string_list(),
            vec!["USBSTOR\\DiskSanDisk_".to_string(), "GenDisk".to_string()]
        );
        assert!(
            decode_property(DEVPROP_TYPE_STRING_LIST, &[])
                .into_string_list()
                .is_empty()
        );
        assert_eq!(
            decode_property(DEVPROP_TYPE_STRING, &wide_bytes("TÜBİTAK\0")).into_string(),
            Some("TÜBİTAK".into())
        );
    }

    #[test]
    fn decodes_disk_drive_class_guid() {
        // {4d36e967-e325-11ce-bfc1-08002be10318} in memory layout.
        let bytes = [
            0x67, 0xe9, 0x36, 0x4d, 0x25, 0xe3, 0xce, 0x11, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1,
            0x03, 0x18,
        ];
        assert_eq!(
            decode_property(DEVPROP_TYPE_GUID, &bytes)
                .into_guid()
                .as_deref(),
            Some(rustward_core::class_guids::DISK_DRIVE)
        );
        assert_eq!(
            decode_property(DEVPROP_TYPE_GUID, &bytes[..15]),
            PropValue::Unsupported(DEVPROP_TYPE_GUID)
        );
    }

    #[test]
    fn decodes_bool_and_u32_and_rejects_short_buffers() {
        assert_eq!(
            decode_property(DEVPROP_TYPE_BOOLEAN, &[0xFF]).into_bool(),
            Some(true)
        );
        assert_eq!(
            decode_property(DEVPROP_TYPE_BOOLEAN, &[0]).into_bool(),
            Some(false)
        );
        assert_eq!(
            decode_property(DEVPROP_TYPE_UINT32, &[28, 0, 0, 0]).into_u32(),
            Some(28)
        );
        assert_eq!(
            decode_property(DEVPROP_TYPE_UINT32, &[1, 0]).into_u32(),
            None
        );
        assert_eq!(
            decode_property(0x1234, &[1]),
            PropValue::Unsupported(0x1234)
        );
    }

    #[test]
    fn odd_byte_and_missing_nul_are_tolerated() {
        assert_eq!(utf16_until_nul(&bytes_to_u16(&[0x41, 0x00, 0x42])), "A");
        assert_eq!(
            parse_multi_sz(&bytes_to_u16(&wide_bytes("A"))),
            vec!["A".to_string()]
        );
    }
}
