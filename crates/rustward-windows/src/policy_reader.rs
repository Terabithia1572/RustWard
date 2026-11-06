//! **Read-only** capture of the Device Installation Restrictions policy and
//! OS version facts. **NOT VERIFIED ON WINDOWS** (type-checked only).
//!
//! Every value under `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`
//! and one level of its subkeys is read verbatim; interpretation (which
//! names are documented) happens in `rustward_enforcement::policy_inspect`.
//!
//! Read-only by construction:
//! - keys are opened with `KEY_READ | KEY_WOW64_64KEY` only;
//! - the only registry functions used are `RegOpenKeyExW`, `RegEnumKeyExW`,
//!   `RegEnumValueW`, `RegGetValueW` and `RegCloseKey` (enforced by the
//!   crate test `policy_reader_is_read_only`);
//! - OS facts come from `RtlGetVersion` and `GetProductInfo` (documented);
//!   the update revision comes from the `UBR` value under
//!   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, which no Microsoft
//!   API documents. It is reported as such and never used to enable anything.

use std::ptr;

use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RRF_RT_REG_DWORD, RegCloseKey,
    RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW,
};
use windows_sys::Win32::System::SystemInformation::{GetProductInfo, OSVERSIONINFOW};

use rustward_enforcement::device_install::RESTRICTIONS_KEY;
use rustward_enforcement::policy_inspect::{CapturedPolicy, OsFacts};
use rustward_enforcement::policy_state::{PolicySnapshot, ValueRef};

use crate::regdecode::{MAX_VALUE_BYTES, decode, name, to_wide};

/// Values and subkeys read per key at most.
const MAX_ENTRIES: u32 = 4096;
/// Registry name limit (value names: 16383 characters).
const NAME_UNITS: usize = 16_384;

/// Registry key handle, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegOpenKeyExW and is closed once.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

/// Open `path` under HKLM for reading. `Ok(None)` if it does not exist.
fn open_read(path: &str) -> Result<Option<Key>, String> {
    let wide = to_wide(path);
    let mut h: HKEY = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `h` is a valid out-pointer. Access is
    // KEY_READ only.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut h,
        )
    };
    match rc {
        ERROR_SUCCESS => Ok(Some(Key(h))),
        ERROR_FILE_NOT_FOUND => Ok(None),
        e => Err(format!("RegOpenKeyExW({path}) failed with Win32 error {e}")),
    }
}

/// Read every value of an open key into `out` under `key_path`.
fn read_values(key: &Key, key_path: &str, out: &mut PolicySnapshot, errors: &mut Vec<String>) {
    let mut name_buf = vec![0u16; NAME_UNITS];
    let mut data = vec![0u8; MAX_VALUE_BYTES];
    for index in 0..MAX_ENTRIES {
        let mut name_len = u32::try_from(name_buf.len()).unwrap_or(u32::MAX);
        let mut data_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let mut reg_type = 0u32;
        // SAFETY: buffers and their lengths are valid and writable; the
        // reserved pointer is null as required.
        let rc = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                ptr::null(),
                &mut reg_type,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        match rc {
            ERROR_SUCCESS => {
                let value_name = name(&name_buf, name_len as usize);
                let bytes = &data[..(data_len as usize).min(data.len())];
                out.values.insert(
                    ValueRef::new(key_path, &value_name),
                    decode(reg_type, bytes),
                );
            }
            ERROR_NO_MORE_ITEMS => return,
            e => {
                errors.push(format!(
                    "{key_path}: value #{index} not read (Win32 error {e})"
                ));
                return;
            }
        }
    }
    errors.push(format!(
        "{key_path}: more than {MAX_ENTRIES} values; rest not read"
    ));
}

/// Names of the direct subkeys of an open key.
fn subkeys(key: &Key, key_path: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut names = Vec::new();
    let mut buf = vec![0u16; 256];
    for index in 0..MAX_ENTRIES {
        let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` and `len` are valid; class and time pointers may be null.
        let rc = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                buf.as_mut_ptr(),
                &mut len,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        match rc {
            ERROR_SUCCESS => names.push(name(&buf, len as usize)),
            ERROR_NO_MORE_ITEMS => break,
            e => {
                errors.push(format!(
                    "{key_path}: subkey #{index} not read (Win32 error {e})"
                ));
                break;
            }
        }
    }
    names
}

fn os_facts() -> OsFacts {
    // SAFETY: OSVERSIONINFOW is plain data; all-zero is valid before the
    // size field is set.
    let mut v: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = u32::try_from(size_of::<OSVERSIONINFOW>()).unwrap_or(276);
    // SAFETY: `v` is a valid, sized OSVERSIONINFOW.
    let ok = unsafe { RtlGetVersion(&mut v) } >= 0;
    let (major, minor, build) = if ok {
        (
            Some(v.dwMajorVersion),
            Some(v.dwMinorVersion),
            Some(v.dwBuildNumber),
        )
    } else {
        (None, None, None)
    };
    let mut product = 0u32;
    // SAFETY: `product` is a valid out-pointer.
    let product_type = (ok
        && unsafe { GetProductInfo(v.dwMajorVersion, v.dwMinorVersion, 0, 0, &mut product) } != 0)
        .then_some(product);
    // Undocumented but widely used: reported as such by the inspection.
    let mut ubr = 0u32;
    let mut size = 4u32;
    let path = to_wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    let value = to_wide("UBR");
    // SAFETY: NUL-terminated strings; `ubr` holds 4 bytes; RRF_RT_REG_DWORD
    // restricts the type. Read-only API.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&raw mut ubr).cast(),
            &mut size,
        )
    };
    OsFacts {
        is_windows: true,
        major,
        minor,
        build,
        ubr: (rc == ERROR_SUCCESS).then_some(ubr),
        product_type,
    }
}

/// Capture the Restrictions key (values + one level of subkeys) and OS facts.
///
/// # Errors
/// When the key exists but cannot be opened for reading.
pub fn capture(now_ms: i64) -> Result<CapturedPolicy, String> {
    let mut out = CapturedPolicy {
        captured_ms: now_ms,
        os: os_facts(),
        ..CapturedPolicy::default()
    };
    let Some(root) = open_read(RESTRICTIONS_KEY)? else {
        return Ok(out);
    };
    out.key_present = true;
    read_values(
        &root,
        RESTRICTIONS_KEY,
        &mut out.values,
        &mut out.read_errors,
    );
    for sub in subkeys(&root, RESTRICTIONS_KEY, &mut out.read_errors) {
        let path = format!(r"{RESTRICTIONS_KEY}\{sub}");
        match open_read(&path) {
            Ok(Some(k)) => read_values(&k, &path, &mut out.values, &mut out.read_errors),
            Ok(None) => {}
            Err(e) => out.read_errors.push(e),
        }
    }
    Ok(out)
}
