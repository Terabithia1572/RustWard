# Security Model

## Privilege separation (target design)

| Component | Runs as | May | Must not |
|---|---|---|---|
| Desktop UI (Tauri) | Logged-on user, unelevated | Show status, request actions over IPC | Open the DB, change policy directly, run commands |
| Service | `LocalSystem` initially; evaluate a virtual service account + specific rights in Phase 7 | Read device state, apply/verify the enforcement provider, write audit | Accept unauthenticated requests |
| Enforcement | Windows OS policy | Enforce independently of RustWard processes | — |

## IPC — implemented, NOT Windows-verified

- Two pipes: `\\.\pipe\RustWard.Status.v1` (SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)`,
  read-only requests) and `\\.\pipe\RustWard.Admin.v1` (SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`).
- `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`. The client checks with
  `GetNamedPipeServerSessionId` that the pipe server runs in session 0 (the service), to
  reject an impostor server created in a user session.
- Per request, not per connection: `ImpersonateNamedPipeClient` → `CheckTokenMembership`
  (Administrators) + `TokenElevation`; impersonation is always reverted or the process aborts.
  Clients connect with `SECURITY_IDENTIFICATION`.
- Versioned envelopes; length-prefixed JSON frames ≤ 4 MiB; reads bounded with `PeekNamedPipe`;
  every field validated server-side (`rustward-ipc::validate`).
- No generic "execute", "write file" or "set registry" request exists; the 21 request types
  are fixed by a golden contract test.
- Authorization never depends on the UI. A frontend password prompt would not be a boundary
  and is not used; the Windows token of the caller decides.

## Tauri 2 hardening — implemented, NOT Windows-verified

- One command (`ipc_call`); capability `default` grants only `allow-ipc-call` to window
  `main`; no core, shell, fs, http, opener or updater plugins. Tested on Linux: other
  commands are rejected by the ACL.
- CSP `default-src 'self'; script-src 'self'; style-src 'self'; connect-src ipc: http://ipc.localhost; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
  `freezePrototype: true`; `withGlobalTauri: false`.
- No devtools feature; release builds have no devtools and no development backend.
- All assets local (system font stack, bundled lucide icons).

## Data protection

- Policy, catalog and SQLite DB under `%ProgramData%\RustWard` with ACL `SYSTEM:F, Administrators:F`, users no access.
- Audit records: no PINs, no file names or contents, no document data.
- Hash-chained audit entries + Windows Event Log; described as tamper-*evident*.

## Guarantees checked by automated tests

- `rustward-windows` imports only five read-only Win32 functions; a unit test fails if
  any other `SetupDi*`, `CM_*`, `Reg*`, `DeviceIoControl` or class-installer API appears.
- `rustward-core`, `rustward-enforcement` and `rustward-inventory` forbid `unsafe`.
- No component can report `EnforcedVerified` without `VerificationEvidence`, which has no
  public constructor.
- The blocked notification "USB engellenmiştir. İşlem kayıt altına alınmıştır." is only
  selected with verified state **and** device evidence.
