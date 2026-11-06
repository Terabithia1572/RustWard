//! Windows named-pipe transport. **NOT VERIFIED ON WINDOWS** — compiled
//! and type-checked only; native tests are deferred to the VM phase.
//!
//! Security design:
//! - Multiple instances (Phase 9B, F-13): [`PipeListener`] always keeps one
//!   listening instance. The first instance of the pipe is created with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE`, so the server fails instead of joining
//!   a pipe another process pre-created (squatting); further instances are
//!   created only right after one of ours connected, while our pipe object
//!   provably exists. If the listening instance cannot be replaced, the next
//!   accept starts over with `FILE_FLAG_FIRST_PIPE_INSTANCE`.
//! - The DACL never grants `FILE_CREATE_PIPE_INSTANCE` to non-administrators
//!   (it equals `FILE_APPEND_DATA` and is part of `FILE_GENERIC_WRITE`):
//!   the status pipe grants Authenticated Users `FILE_GENERIC_READ |
//!   FILE_WRITE_DATA` only, and clients open with exactly those rights
//!   (Phase 9B finding F-18).
//! - `PIPE_REJECT_REMOTE_CLIENTS`; DACL from SDDL ([`crate::SDDL_ADMIN`] /
//!   [`crate::SDDL_STATUS`]).
//! - The client identity comes from the client's Windows token
//!   (`ImpersonateNamedPipeClient` → `OpenThreadToken`), checked with
//!   `CheckTokenMembership(BUILTIN\Administrators)` and `TokenElevation`.
//!   It is taken **per request, after the request frame was read**
//!   ([`PipeConnection::client_identity`] via
//!   `rpc::serve_connection_identified`): Windows impersonates "the security
//!   context of the last message read from the pipe", and identifying before
//!   any read could fail (`ERROR_CANNOT_IMPERSONATE`) or describe a stale
//!   context (Phase 9A finding F-04). A failed identification refuses the
//!   request and closes the connection.
//!   Impersonation is always reverted; failure to revert aborts the process.
//! - Clients connect with `SECURITY_IDENTIFICATION` (the server can identify
//!   but not act as the user) and verify the server before sending anything:
//!   the pipe object must be **owned by LocalSystem** (the server sets
//!   `O:SY` in its SDDL; a standard user cannot assign SYSTEM as owner) and
//!   the server process must run in session 0. The session check alone is
//!   not sufficient: a standard user can run code in session 0 through a
//!   scheduled task ("run whether user is logged on or not") and squat the
//!   pipe name while the service is stopped (Phase 9A finding F-03).
//!   Additionally (Phase 9B) the server process id
//!   (`GetNamedPipeServerProcessId`) must equal the process id the Service
//!   Control Manager reports for the RustWard service, which also rejects an
//!   instance created by another process on our own pipe.
//! - Reads never block indefinitely: data availability is polled with
//!   `PeekNamedPipe` against a deadline.

use std::ffi::c_void;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, GENERIC_READ, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, LookupAccountSidW,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES,
    SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
    WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_WRITE_DATA, FlushFileBuffers, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
    GetNamedPipeServerSessionId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, PeekNamedPipe,
    WaitNamedPipeW,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::frame::payload_len;
use crate::transport::{Transport, TransportError};
use crate::{AccessLevel, ClientIdentity, IdentitySource};

const PIPE_BUFFER: u32 = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Once the first byte of a frame has arrived, the rest must follow within
/// this time (otherwise the frame is incomplete and the connection closed).
const FRAME_COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);
/// Rights a client needs: read, write data. Never `GENERIC_WRITE`, which
/// includes `FILE_CREATE_PIPE_INSTANCE`.
const CLIENT_ACCESS: u32 = GENERIC_READ | FILE_WRITE_DATA;
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

// SAFETY: a kernel handle is a process-wide value, not tied to the thread
// that created it; `OwnedHandle` owns it exclusively, so moving it to another
// thread (a pooled connection worker) cannot cause a double close. It is not
// `Sync`: shared access goes through `Mutex` (PipeListener) or `&mut`
// (Transport).
unsafe impl Send for OwnedHandle {}

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

/// String form (`S-1-…`) of a SID.
///
/// # Safety
/// `sid` must point to a valid SID for the duration of the call.
unsafe fn sid_to_string(sid: PSID) -> Option<String> {
    let mut out: windows_sys::core::PWSTR = ptr::null_mut();
    // SAFETY: `sid` is valid per the caller; `out` receives a LocalAlloc'd
    // NUL-terminated string that is freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 || out.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: `out` is NUL-terminated.
    while unsafe { *out.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` UTF-16 units are readable at `out`.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(out, len) }).ok();
    // SAFETY: allocated by ConvertSidToStringSidW with LocalAlloc.
    unsafe {
        LocalFree(out.cast::<c_void>() as HLOCAL);
    }
    text
}

/// Service Control Manager handle, closed on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and is
            // closed exactly once.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

/// Process id of a running service, from the SCM (`None` if not running).
fn service_process_id(service: &str) -> Result<Option<u32>, TransportError> {
    // SAFETY: null machine and database names select the local active
    // database; SC_MANAGER_CONNECT is granted to authenticated users.
    let scm = ScHandle(unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) });
    if scm.0.is_null() {
        return Err(os_err("OpenSCManagerW"));
    }
    let name = wide(service);
    // SAFETY: `scm` is a live SCM handle; `name` is NUL-terminated UTF-16.
    let svc = ScHandle(unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_QUERY_STATUS) });
    if svc.0.is_null() {
        return Err(os_err("OpenServiceW"));
    }
    // SAFETY: SERVICE_STATUS_PROCESS is plain data; all-zero is valid.
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let size = u32::try_from(size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(36);
    let mut needed = 0u32;
    // SAFETY: `status` is a writable SERVICE_STATUS_PROCESS of `size` bytes.
    let ok = unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast::<u8>(),
            size,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(os_err("QueryServiceStatusEx"));
    }
    Ok((status.dwProcessId != 0).then_some(status.dwProcessId))
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

/// Pipe server for one pipe name. Keeps one listening instance at all
/// times while serving (see the module documentation).
pub struct PipeListener {
    name: Vec<u16>,
    sddl: String,
    max_access: AccessLevel,
    /// Next listening instance, created right after the previous one
    /// connected.
    next: std::sync::Mutex<Option<OwnedHandle>>,
}

impl std::fmt::Debug for PipeListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeListener")
            .field("max_access", &self.max_access)
            .finish_non_exhaustive()
    }
}

impl PipeListener {
    /// New listener (no OS object is created until [`Self::accept`]).
    #[must_use]
    pub fn new(name: &str, sddl: &str, max_access: AccessLevel) -> Self {
        Self {
            name: wide(name),
            sddl: sddl.to_owned(),
            max_access,
            next: std::sync::Mutex::new(None),
        }
    }

    fn create_instance(&self, first: bool) -> Result<OwnedHandle, TransportError> {
        let sd = security_descriptor(&self.sddl)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(24),
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let open_mode = if first {
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            PIPE_ACCESS_DUPLEX
        };
        // SAFETY: `self.name` is NUL-terminated UTF-16; `sa` and the security
        // descriptor it points to outlive the call.
        let h = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            let e = last_error();
            return Err(TransportError::Io(if first && e == ERROR_ACCESS_DENIED {
                "CreateNamedPipeW: the pipe name already exists (possible pipe-name squatting)"
                    .into()
            } else {
                format!("CreateNamedPipeW failed with Win32 error {e}")
            }));
        }
        Ok(OwnedHandle(h))
    }

    /// Wait for one client on the listening instance, then create the next
    /// listening instance before returning the connection.
    pub fn accept(&self) -> Result<PipeConnection, TransportError> {
        let pending = self
            .next
            .lock()
            .map_err(|_| TransportError::Io("pipe listener poisoned".into()))?
            .take();
        let handle = match pending {
            Some(h) => h,
            None => self.create_instance(true)?,
        };
        // SAFETY: `handle` is a valid pipe handle; synchronous connect.
        if unsafe { ConnectNamedPipe(handle.0, ptr::null_mut()) } == 0
            && last_error() != ERROR_PIPE_CONNECTED
        {
            return Err(os_err("ConnectNamedPipe"));
        }
        // `handle` is connected, so our pipe object exists: a further
        // instance joins it (never another process's pipe).
        // If this fails, the next accept starts over with
        // FILE_FLAG_FIRST_PIPE_INSTANCE, which fails (and is audited as an
        // accept error) while our connected instances exist: fail closed.
        if let (Ok(next), Ok(mut slot)) = (self.create_instance(false), self.next.lock()) {
            *slot = Some(next);
        }
        Ok(PipeConnection {
            handle,
            server_side: true,
            max_access: self.max_access,
        })
    }

    /// Unblock a pending [`Self::accept`] by connecting to our own pipe and
    /// closing at once (used at shutdown).
    pub fn wake(&self) {
        // SAFETY: `self.name` is NUL-terminated UTF-16; the returned handle
        // is closed immediately by OwnedHandle.
        let h = unsafe {
            CreateFileW(
                self.name.as_ptr(),
                CLIENT_ACCESS,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        drop(OwnedHandle(h));
    }
}

impl crate::server::Listener for PipeListener {
    type Conn = PipeConnection;
    fn accept(&self) -> Result<PipeConnection, TransportError> {
        PipeListener::accept(self)
    }
    fn wake(&self) {
        PipeListener::wake(self);
    }
    fn identify(&self, conn: &PipeConnection) -> Result<ClientIdentity, TransportError> {
        conn.client_identity()
    }
}

/// A connected pipe end.
#[derive(Debug)]
pub struct PipeConnection {
    handle: OwnedHandle,
    server_side: bool,
    /// Channel of the listener (server side only).
    max_access: AccessLevel,
}

impl PipeConnection {
    /// Identity of the client, from the security context of the last
    /// message read (server side only). Call after each request frame.
    pub fn client_identity(&self) -> Result<ClientIdentity, TransportError> {
        if !self.server_side {
            return Err(TransportError::Io(
                "client_identity is only available on the server end".into(),
            ));
        }
        client_identity(self.handle.0, self.max_access)
    }

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
                    CLIENT_ACCESS,
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
                    max_access: AccessLevel::ReadOnly,
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
        self.verify_server_owner()?;
        self.verify_server_process()?;
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

    /// The process serving this pipe instance must be the RustWard service
    /// process according to the SCM.
    fn verify_server_process(&self) -> Result<(), TransportError> {
        let mut server_pid = 0u32;
        // SAFETY: valid client pipe handle and out-pointer.
        if unsafe { GetNamedPipeServerProcessId(self.handle.0, &mut server_pid) } == 0 {
            return Err(os_err("GetNamedPipeServerProcessId"));
        }
        match service_process_id(crate::SERVICE_NAME)? {
            Some(pid) if pid == server_pid => Ok(()),
            Some(pid) => Err(TransportError::PeerRejected(format!(
                "pipe served by process {server_pid}, but {} runs as process {pid}",
                crate::SERVICE_NAME
            ))),
            None => Err(TransportError::PeerRejected(format!(
                "{} is not running; refusing a pipe served by process {server_pid}",
                crate::SERVICE_NAME
            ))),
        }
    }

    /// The pipe object must be owned by LocalSystem.
    fn verify_server_owner(&self) -> Result<(), TransportError> {
        let mut owner: PSID = ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: valid pipe handle opened with GENERIC_READ (includes
        // READ_CONTROL); `owner` and `sd` are valid out-pointers; the other
        // out-pointers may be null. On success `sd` must be freed with
        // LocalFree and `owner` points into it.
        let rc = unsafe {
            GetSecurityInfo(
                self.handle.0,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(TransportError::Io(format!(
                "GetSecurityInfo failed with Win32 error {rc}"
            )));
        }
        let sd = LocalSecurityDescriptor(sd);
        let owner_sid = if owner.is_null() {
            None
        } else {
            // SAFETY: `owner` points into `sd`, which is alive until the
            // `drop(sd)` below.
            unsafe { sid_to_string(owner) }
        };
        drop(sd);
        match owner_sid {
            Some(sid) if crate::service_sid::is_trusted_pipe_owner(&sid) => Ok(()),
            other => Err(TransportError::PeerRejected(format!(
                "pipe owner {} is neither LocalSystem nor the RustWard service; refusing to talk to a possible impostor",
                other.as_deref().unwrap_or("unknown")
            ))),
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
        // Wait for the first byte without consuming anything, so a Timeout
        // never splits a frame (contract of `rpc::serve_connection_until`).
        let wait_until = Instant::now() + timeout;
        while self.available()? == 0 {
            if Instant::now() >= wait_until {
                return Err(TransportError::Timeout);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let deadline = Instant::now() + FRAME_COMPLETION_TIMEOUT;
        let incomplete = |e: TransportError| match e {
            TransportError::Timeout => TransportError::Io("incomplete frame".into()),
            other => other,
        };
        let mut header = [0u8; 4];
        self.read_exact_until(&mut header, deadline)
            .map_err(incomplete)?;
        let len = payload_len(header).map_err(|_| TransportError::FrameTooLarge)?;
        let mut frame = vec![0u8; 4 + len];
        frame[..4].copy_from_slice(&header);
        self.read_exact_until(&mut frame[4..], deadline)
            .map_err(incomplete)?;
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
