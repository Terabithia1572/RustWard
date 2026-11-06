//! Pure decoding of registry value data captured by
//! [`crate::policy_reader`] (platform-independent, unit-tested everywhere).

use rustward_enforcement::policy_state::RegData;

/// `REG_SZ`.
pub const T_SZ: u32 = 1;
/// `REG_EXPAND_SZ` (kept verbatim, never expanded).
pub const T_EXPAND_SZ: u32 = 2;
/// `REG_DWORD` (little-endian).
pub const T_DWORD: u32 = 4;
/// `REG_MULTI_SZ`.
pub const T_MULTI_SZ: u32 = 7;
/// Largest value data the reader accepts (larger values are reported, not read).
pub const MAX_VALUE_BYTES: usize = 64 * 1024;

fn utf16(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn until_nul(units: &[u16]) -> String {
    let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// Decode registry data of type `reg_type`.
#[must_use]
pub fn decode(reg_type: u32, bytes: &[u8]) -> RegData {
    match reg_type {
        T_DWORD if bytes.len() == 4 => {
            RegData::Dword(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        T_SZ | T_EXPAND_SZ => RegData::Sz(until_nul(&utf16(bytes))),
        T_MULTI_SZ => RegData::MultiSz(
            utf16(bytes)
                .split(|u| *u == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect(),
        ),
        other => RegData::Other {
            reg_type: other,
            bytes: bytes.len(),
        },
    }
}

/// NUL-terminated UTF-16 for Win32 calls.
#[must_use]
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decode a UTF-16 name buffer of `len` units.
#[must_use]
pub fn name(buf: &[u16], len: usize) -> String {
    String::from_utf16_lossy(&buf[..len.min(buf.len())])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn decodes_the_registry_types_used_by_device_install_policy() {
        assert_eq!(decode(T_DWORD, &1u32.to_le_bytes()), RegData::Dword(1));
        assert_eq!(
            decode(T_SZ, &w("USBSTOR\\DiskSanDisk_")),
            RegData::Sz("USBSTOR\\DiskSanDisk_".into())
        );
        assert_eq!(
            decode(T_EXPAND_SZ, &w("%SystemRoot%")),
            RegData::Sz("%SystemRoot%".into()),
            "never expanded"
        );
        let mut multi = w("a");
        multi.extend(w("b"));
        multi.extend([0, 0]);
        assert_eq!(
            decode(T_MULTI_SZ, &multi),
            RegData::MultiSz(vec!["a".into(), "b".into()])
        );
        // Malformed / other types are reported, not interpreted.
        assert_eq!(
            decode(T_DWORD, &[1, 0]),
            RegData::Other {
                reg_type: T_DWORD,
                bytes: 2
            }
        );
        assert_eq!(
            decode(3, &[1, 2, 3]),
            RegData::Other {
                reg_type: 3,
                bytes: 3
            }
        );
        // Missing terminator and odd byte counts are tolerated.
        assert_eq!(
            decode(T_SZ, &[0x41, 0, 0x42, 0, 0x43]),
            RegData::Sz("AB".into())
        );
        assert_eq!(name(&[0x52, 0x57, 0x20], 2), "RW");
    }
}
