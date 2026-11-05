# Security Model

## Privilege separation (target design)

| Component | Runs as | May | Must not |
|---|---|---|---|
| Desktop UI (Tauri) | Logged-on user, unelevated | Show status, request actions over IPC | Open the DB, change policy directly, run commands |
| Service | `LocalSystem` initially; evaluate a virtual service account + specific rights in Phase 7 | Read device state, apply/verify the enforcement provider, write audit | Accept unauthenticated requests |
| Enforcement | Windows OS policy | Enforce independently of RustWard processes | — |

## IPC (Phase 5)

- Named pipe with a DACL allowing only `SYSTEM` and `BUILTIN\Administrators` for privileged
  operations, and a separate read-only pipe for status (Authenticated Users, read).
- `PIPE_REJECT_REMOTE_CLIENTS`; server verifies the client token (`ImpersonateNamedPipeClient`
  + group check) for every privileged request, not once per connection.
- Versioned request/response contracts; strict size limits; schema validation on the service side.
- No generic "execute"/"write file"/"set registry" requests exist in the protocol.
- Administrator confirmation (UAC-elevated helper or re-authentication) for policy changes;
  no stored reusable passwords.

## Tauri 2 hardening (Phase 6)

- Capabilities: only the RustWard IPC commands; no shell, fs, http or updater plugins.
- Strict CSP (`default-src 'self'`), no remote URLs, bundled fonts/assets only.
- Devtools disabled in release builds.

## Data protection

- Policy, catalog and SQLite DB under `%ProgramData%\RustWard` with ACL `SYSTEM:F, Administrators:F`, users no access.
- Audit records: no PINs, no file names or contents, no document data.
- Hash-chained audit entries + Windows Event Log; described as tamper-*evident*.

## Phase 1 guarantees (verifiable today)

- `rustward-windows` imports only five read-only Win32 functions; a unit test fails if
  any other `SetupDi*`, `CM_*`, `Reg*`, `DeviceIoControl` or class-installer API appears.
- `rustward-core`, `rustward-enforcement` and `rustward-inventory` forbid `unsafe`.
- No component can report `EnforcedVerified` without `VerificationEvidence`, which has no
  public constructor.
- The blocked notification "USB engellenmiştir. İşlem kayıt altına alınmıştır." is only
  selected with verified state **and** device evidence.
