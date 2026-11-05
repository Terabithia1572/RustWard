//! Windows named-pipe transport. **NOT VERIFIED ON WINDOWS** — compiled
//! and type-checked only; native tests are deferred to the VM phase.
//!
//! Security design:
//! - The server creates every instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`
//!   (one instance at a time), so it fails instead of sharing a name that
//!   another process pre-created (pipe squatting).
//! - `PIPE_REJECT_REMOTE_CLIENTS`; DACL from SDDL ([`crate::SDDL_ADMIN`] /
//!   [`crate::SDDL_STATUS`]).
//! - The client identity comes from the client's Windows token
//!   (`ImpersonateNamedPipeClient` → `OpenThreadToken`), checked with
//!   `CheckTokenMembership(BUILTIN\Administrators)` and `TokenElevation`.
//!   Impersonation is always reverted; failure to revert aborts the process.
//! - Clients connect with `SECURITY_IDENTIFICATION` (the server can identify
//!   but not act as the user) and verify that the server process runs in
//!   session 0 (services), rejecting user-session impostors.
//! - Reads never block indefinitely: data availability is polled with
//!   `PeekNamedPipe` against a deadline.

use std::ffi::c_void;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, LookupAccountSidW,
    PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_ELEVATION,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerSessionId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::frame::payload_len;
use crate::transport::{Transport, TransportError};
use crate::{AccessLevel, ClientIdentity, IdentitySource};

const PIPE_BUFFER: u32 = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Large enough for any SID (SECURITY_MAX_SID_SIZE is 68).
const SID_BUFFER_BYTES: usize = 128;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetLastError() }
}

fn os_err(api: &str) -> TransportError {
    TransportError::Io(format!("{api} failed with Win32 error {}", last_error()))
}

/// Owned kernel handle, closed on drop.
#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: the handle is owned exclusively by this value and
            // closed exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Security descriptor allocated by `ConvertStringSecurityDescriptor…`,
/// freed with `LocalFree`.
struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW,
            // which documents LocalFree as the release function.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

/// Reverts impersonation on drop. If reverting fails the thread would keep
/// running as the client, so the process is aborted.
struct RevertOnDrop;

impl Drop for RevertOnDrop {
    fn drop(&mut self) {
        // SAFETY: no preconditions; called on the impersonating thread.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn security_descriptor(sddl: &str) -> Result<LocalSecurityDescriptor, TransportError> {
    let sddl_w = wide(sddl);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `sddl_w` is a NUL-terminated UTF-16 string that outlives the
    // call; `sd` is a valid out-pointer; the size out-pointer may be null.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(os_err(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    Ok(LocalSecurityDescriptor(sd))
}

/// Query `DOMAIN\user` of a token. Best effort.
fn token_account(token: HANDLE) -> Option<String> {
    let mut needed: u32 = 0;
    // SAFETY: size query with a null buffer of length 0 is documented.
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    // u64 storage guarantees alignment for TOKEN_USER (pointer-aligned).
    let words = usize::try_from(needed).ok()?.div_ceil(8);
    let mut buf = vec![0u64; words];
    let buf_len = u32::try_from(words * 8).ok()?;
    // SAFETY: `buf` provides `buf_len` writable, suitably aligned bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            buf_len,
            &mut needed,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER structure.
    let sid: PSID = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = 256u32;
    let mut domain_len = 256u32;
    let mut use_: SID_NAME_USE = 0;
    // SAFETY: `sid` points into `buf`, which is alive; output buffers have
    // the lengths passed in.
    let ok = unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        )
    };
    if ok == 0 {
        return None;
    }
    let n = String::from_utf16_lossy(&name[..usize::try_from(name_len).ok()?.min(name.len())]);
    let d =
        String::from_utf16_lossy(&domain[..usize::try_from(domain_len).ok()?.min(domain.len())]);
    Some(format!("{d}\\{n}"))
}

/// Establish the identity of the client connected to `pipe`.
fn client_identity(
    pipe: HANDLE,
    channel_max_access: AccessLevel,
) -> Result<ClientIdentity, TransportError> {
    // SAFETY: `pipe` is a connected server pipe handle.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(os_err("ImpersonateNamedPipeClient"));
    }
    let _revert = RevertOnDrop;
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentThread returns a pseudo-handle; `raw` is a valid
    // out-pointer. OpenAsSelf = TRUE uses the process context for the check.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        return Err(os_err("OpenThreadToken"));
    }
    let token = OwnedHandle(raw);

    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    let elev_size = u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(4);
    // SAFETY: `elevation` is a writable TOKEN_ELEVATION of `elev_size` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&raw mut elevation).cast::<c_void>(),
            elev_size,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(os_err("GetTokenInformation(TokenElevation)"));
    }

    let mut sid_buf = [0u64; SID_BUFFER_BYTES / 8];
    let mut sid_len = u32::try_from(SID_BUFFER_BYTES).unwrap_or(128);
    let sid: PSID = sid_buf.as_mut_ptr().cast::<c_void>();
    // SAFETY: `sid` points to `sid_len` writable, aligned bytes.
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid,
            &mut sid_len,
        )
    } == 0
    {
        return Err(os_err("CreateWellKnownSid"));
    }
    let mut is_member = 0;
    // SAFETY: `token` is an impersonation token opened above; `sid` is a
    // valid SID in `sid_buf`, alive for the call.
    if unsafe { CheckTokenMembership(token.0, sid, &mut is_member) } == 0 {
        return Err(os_err("CheckTokenMembership"));
    }

    Ok(ClientIdentity {
        account: token_account(token.0).unwrap_or_else(|| "unknown".into()),
        sid: None,
        is_administrator: is_member != 0,
        elevated: elevation.TokenIsElevated != 0,
        source: IdentitySource::NamedPipeToken,
        channel_max_access,
    })
}

/// Pipe server for one pipe name.
#[derive(Debug)]
pub struct PipeListener {
    name: Vec<u16>,
    sddl: String,
    max_access: AccessLevel,
}

impl PipeListener {
    /// New listener (no OS object is created until [`Self::accept`]).
    #[must_use]
    pub fn new(name: &str, sddl: &str, max_access: AccessLevel) -> Self {
        Self {
            name: wide(name),
            sddl: sddl.to_owned(),
            max_access,
        }
    }

    /// Create a pipe instance, wait for one client and identify it.
    pub fn accept(&self) -> Result<(PipeConnection, ClientIdentity), TransportError> {
        let sd = security_descriptor(&self.sddl)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(24),
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // SAFETY: `self.name` is NUL-terminated UTF-16; `sa` and the security
        // descriptor it points to outlive the call.
        let h = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(os_err("CreateNamedPipeW (possible pipe-name squatting)"));
        }
        let handle = OwnedHandle(h);
        // SAFETY: `handle` is a valid pipe handle; synchronous connect.
        if unsafe { ConnectNamedPipe(handle.0, ptr::null_mut()) } == 0
            && last_error() != ERROR_PIPE_CONNECTED
        {
            return Err(os_err("ConnectNamedPipe"));
        }
        let identity = client_identity(handle.0, self.max_access)?;
        Ok((
            PipeConnection {
                handle,
                server_side: true,
            },
            identity,
        ))
    }
}

/// A connected pipe end.
#[derive(Debug)]
pub struct PipeConnection {
    handle: OwnedHandle,
    server_side: bool,
}

impl PipeConnection {
    /// Connect to a RustWard pipe as a client, verifying the server runs in
    /// session 0.
    pub fn connect(name: &str, timeout: Duration) -> Result<Self, TransportError> {
        let name_w = wide(name);
        let deadline = Instant::now() + timeout;
        loop {
            // SAFETY: `name_w` is NUL-terminated UTF-16; other pointer
            // arguments are null as permitted.
            let h = unsafe {
                CreateFileW(
                    name_w.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                let conn = Self {
                    handle: OwnedHandle(h),
                    server_side: false,
                };
                conn.verify_server()?;
                return Ok(conn);
            }
            let err = last_error();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if err != ERROR_PIPE_BUSY || remaining.is_zero() {
                return Err(TransportError::Disconnected);
            }
            let ms = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
            // SAFETY: `name_w` is NUL-terminated UTF-16.
            unsafe { WaitNamedPipeW(name_w.as_ptr(), ms) };
        }
    }

    fn verify_server(&self) -> Result<(), TransportError> {
        let mut session = u32::MAX;
        // SAFETY: valid client pipe handle and out-pointer.
        if unsafe { GetNamedPipeServerSessionId(self.handle.0, &mut session) } == 0 {
            return Err(os_err("GetNamedPipeServerSessionId"));
        }
        if session == 0 {
            Ok(())
        } else {
            Err(TransportError::PeerRejected(format!(
                "pipe server runs in session {session}, expected the service session 0"
            )))
        }
    }

    fn available(&self) -> Result<u32, TransportError> {
        let mut avail = 0u32;
        // SAFETY: valid pipe handle; only the total-available out-pointer is
        // requested.
        let ok = unsafe {
            PeekNamedPipe(
                self.handle.0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut avail,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            let e = last_error();
            return if e == ERROR_BROKEN_PIPE || e == ERROR_NO_DATA {
                Err(TransportError::Disconnected)
            } else {
                Err(TransportError::Io(format!(
                    "PeekNamedPipe failed with Win32 error {e}"
                )))
            };
        }
        Ok(avail)
    }

    /// Read exactly `out.len()` bytes before `deadline`, never blocking on
    /// an empty pipe.
    fn read_exact_until(&self, out: &mut [u8], deadline: Instant) -> Result<(), TransportError> {
        let mut filled = 0usize;
        while filled < out.len() {
            let avail = self.available()?;
            if avail == 0 {
                if Instant::now() >= deadline {
                    return Err(TransportError::Timeout);
                }
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
            let want = (out.len() - filled).min(usize::try_from(avail).unwrap_or(usize::MAX));
            let want_u32 = u32::try_from(want).unwrap_or(u32::MAX);
            let mut read = 0u32;
            // SAFETY: the destination range `out[filled..filled + want]` is
            // in bounds and writable; at least `want` bytes are available so
            // the call does not block.
            let ok = unsafe {
                ReadFile(
                    self.handle.0,
                    out[filled..].as_mut_ptr(),
                    want_u32,
                    &mut read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                let e = last_error();
                return Err(if e == ERROR_BROKEN_PIPE {
                    TransportError::Disconnected
                } else {
                    TransportError::Io(format!("ReadFile failed with Win32 error {e}"))
                });
            }
            filled += usize::try_from(read).unwrap_or(0);
        }
        Ok(())
    }
}

impl Transport for PipeConnection {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        let mut sent = 0usize;
        while sent < frame.len() {
            let chunk = u32::try_from(frame.len() - sent).unwrap_or(u32::MAX);
            let mut written = 0u32;
            // SAFETY: the source range is in bounds and readable.
            let ok = unsafe {
                WriteFile(
                    self.handle.0,
                    frame[sent..].as_ptr(),
                    chunk,
                    &mut written,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                let e = last_error();
                return Err(if e == ERROR_BROKEN_PIPE || e == ERROR_NO_DATA {
                    TransportError::Disconnected
                } else {
                    TransportError::Io(format!("WriteFile failed with Win32 error {e}"))
                });
            }
            sent += usize::try_from(written).unwrap_or(0);
        }
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + timeout;
        let mut header = [0u8; 4];
        self.read_exact_until(&mut header, deadline)?;
        let len = payload_len(header).map_err(|_| TransportError::FrameTooLarge)?;
        let mut frame = vec![0u8; 4 + len];
        frame[..4].copy_from_slice(&header);
        self.read_exact_until(&mut frame[4..], deadline)?;
        Ok(frame)
    }
}

impl Drop for PipeConnection {
    fn drop(&mut self) {
        if self.server_side {
            // SAFETY: valid server pipe handle; flush then disconnect before
            // the OwnedHandle closes it.
            unsafe {
                FlushFileBuffers(self.handle.0);
                DisconnectNamedPipe(self.handle.0);
            }
        }
    }
}
