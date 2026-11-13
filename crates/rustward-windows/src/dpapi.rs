//! Windows DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`) helpers for sealing local-machine secrets.
//!
//! Used by `rustward-service` / `rustward-storage` to seal sensitive local secrets
//! (such as recovery verifier material) so plain bytes are never stored at rest.

#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};

#[cfg(windows)]
const DPAPI_ENTROPY: &[u8] = b"RustWard-LocalMachine-DPAPI-v1";

#[cfg(windows)]
struct LocalAllocBlob(CRYPT_INTEGER_BLOB);

#[cfg(windows)]
impl Drop for LocalAllocBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: `pbData` was allocated by `CryptProtectData` / `CryptUnprotectData`
            // and is freed exactly once with `LocalFree`.
            unsafe {
                LocalFree(self.0.pbData.cast());
            }
            self.0.pbData = ptr::null_mut();
            self.0.cbData = 0;
        }
    }
}

/// Encrypts `plaintext` with Windows DPAPI bound to `CRYPTPROTECT_LOCAL_MACHINE`.
///
/// Never prompts for UI (`CRYPTPROTECT_UI_FORBIDDEN`).
///
/// # Errors
/// Returns an error on non-Windows hosts or if `CryptProtectData` fails.
pub fn seal_machine_secret(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        let mut input = plaintext.to_vec();
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(input.len()).map_err(|_| "secret too large for DPAPI".to_owned())?,
            pbData: if input.is_empty() {
                ptr::null_mut()
            } else {
                input.as_mut_ptr()
            },
        };
        let mut entropy_buf = DPAPI_ENTROPY.to_vec();
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(entropy_buf.len())
                .map_err(|_| "entropy length overflow".to_owned())?,
            pbData: entropy_buf.as_mut_ptr(),
        };
        let mut guard = LocalAllocBlob(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        });
        // SAFETY: All pointers reference valid stack/Vec buffers for the duration of
        // `CryptProtectData`; output `pbData` is freed via `LocalAllocBlob::drop`.
        let ok = unsafe {
            CryptProtectData(
                &data_in,
                ptr::null(),
                &entropy,
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut guard.0,
            )
        };
        for b in &mut input {
            // SAFETY: volatile zeroization of stack Vec copy before drop.
            unsafe { ptr::write_volatile(b, 0) };
        }
        if ok == 0 {
            return Err("CryptProtectData failed".to_owned());
        }
        let len = usize::try_from(guard.0.cbData)
            .map_err(|_| "DPAPI output length overflow".to_owned())?;
        if guard.0.pbData.is_null() && len > 0 {
            return Err("DPAPI returned null buffer with non-zero length".to_owned());
        }
        let sealed = if len == 0 {
            Vec::new()
        } else {
            // SAFETY: `CryptProtectData` succeeded and guaranteed `cbData` readable bytes at `pbData`.
            unsafe { std::slice::from_raw_parts(guard.0.pbData, len) }.to_vec()
        };
        Ok(sealed)
    }
    #[cfg(not(windows))]
    {
        let _ = plaintext;
        Err("Windows DPAPI is only available on Windows".to_owned())
    }
}

/// Decrypts bytes produced by [`seal_machine_secret`] using Windows DPAPI.
///
/// # Errors
/// Returns an error on non-Windows hosts or if `CryptUnprotectData` fails.
pub fn unseal_machine_secret(sealed: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        if sealed.is_empty() {
            return Err("sealed DPAPI payload is empty".to_owned());
        }
        let mut input = sealed.to_vec();
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(input.len())
                .map_err(|_| "sealed secret too large for DPAPI".to_owned())?,
            pbData: input.as_mut_ptr(),
        };
        let mut entropy_buf = DPAPI_ENTROPY.to_vec();
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(entropy_buf.len())
                .map_err(|_| "entropy length overflow".to_owned())?,
            pbData: entropy_buf.as_mut_ptr(),
        };
        let mut guard = LocalAllocBlob(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        });
        // SAFETY: All pointers reference live valid buffers; decrypted buffer is owned by
        // `LocalAllocBlob`, wiped, and freed via `LocalFree` on drop.
        let ok = unsafe {
            CryptUnprotectData(
                &data_in,
                ptr::null_mut(),
                &entropy,
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut guard.0,
            )
        };
        if ok == 0 {
            return Err("CryptUnprotectData failed".to_owned());
        }
        let len = usize::try_from(guard.0.cbData)
            .map_err(|_| "DPAPI output length overflow".to_owned())?;
        if guard.0.pbData.is_null() && len > 0 {
            return Err("DPAPI returned null plaintext buffer".to_owned());
        }
        let plaintext = if len == 0 {
            Vec::new()
        } else {
            // SAFETY: `CryptUnprotectData` guaranteed `cbData` readable bytes at `pbData`.
            let slice = unsafe { std::slice::from_raw_parts_mut(guard.0.pbData, len) };
            let out = slice.to_vec();
            for b in slice {
                // SAFETY: volatile zeroization of DPAPI plaintext buffer before `LocalFree`.
                unsafe { ptr::write_volatile(b, 0) };
            }
            out
        };
        Ok(plaintext)
    }
    #[cfg(not(windows))]
    {
        let _ = sealed;
        Err("Windows DPAPI is only available on Windows".to_owned())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip_machine_secret() -> Result<(), String> {
        let secret = b"rustward-dpapi-roundtrip-check";
        let sealed = seal_machine_secret(secret)?;
        assert_ne!(sealed.as_slice(), secret);
        let unsealed = unseal_machine_secret(&sealed)?;
        assert_eq!(unsealed.as_slice(), secret);
        Ok(())
    }
}
