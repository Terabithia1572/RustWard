# Security Model

## Privilege separation (target design)

| Component | Runs as | May | Must not |
|---|---|---|---|
| Desktop UI (Tauri) | Logged-on user, unelevated | Show status, request actions over IPC | Open the DB, change policy directly, run commands |
| Service | `LocalSystem`; a `NT SERVICE\RustWardService` virtual-account variant is prepared (Phase 9B, F-16) and decided in VM step C16 | Read device state, apply/verify the enforcement provider, write audit | Accept unauthenticated requests |
| Enforcement | Windows OS policy | Enforce independently of RustWard processes | — |

## IPC — implemented, NOT Windows-verified

- Two pipes: `\\.\pipe\RustWard.Status.v1` (SDDL `O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;AU)`,
  read-only requests) and `\\.\pipe\RustWard.Admin.v1` (SDDL `O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)`).
  Authenticated Users get `FILE_GENERIC_READ | FILE_WRITE_DATA` only, never `GENERIC_WRITE`,
  which on pipes includes `FILE_CREATE_PIPE_INSTANCE` (Phase 9B finding F-18). Clients open
  with exactly those rights.
- Pooled servers (Phase 9B): one listening instance is always kept; the first instance uses
  `FILE_FLAG_FIRST_PIPE_INSTANCE`, later ones are created only while one of ours is connected.
  Up to 8 (status) / 4 (admin) concurrent callers, 15 s idle timeout, joined at service stop.
  `PIPE_REJECT_REMOTE_CLIENTS`.
- Before sending anything the client checks that the pipe object is **owned by LocalSystem**
  (or the RustWard service SID, for the prepared virtual-account variant), that the serving
  process is the process the SCM reports for `RustWardService` (`GetNamedPipeServerProcessId`
  + `QueryServiceStatusEx`), and that it runs in session 0. The session check alone was
  insufficient: a standard user can run a process in session 0 via a scheduled task and squat
  the pipe name while the service is stopped (Phase 9A finding F-03).
- Per request, after the request frame was read (Phase 9A F-04): `ImpersonateNamedPipeClient` → `CheckTokenMembership`
  (Administrators) + `TokenElevation`; impersonation is always reverted or the process aborts.
  Clients connect with `SECURITY_IDENTIFICATION`.
- Versioned envelopes; length-prefixed JSON frames ≤ 4 MiB; reads bounded with `PeekNamedPipe`;
  every field validated server-side (`rustward-ipc::validate`).
- No generic "execute", "write file" or "set registry" request exists; the 25 request types
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
- All assets local (system font stack, bundled lucide icons). `scripts/check-offline-assets.mjs`
  fails the build on any external URL, non-local reference or network API in `dist/`; a Rust
  test asserts the CSP lists only local sources (Phase 9B, F-20).

## Data protection

- Policy, catalog and SQLite DB under `%ProgramData%\RustWard` with ACL `SYSTEM:F, Administrators:F`, users no access.
- Audit records: no PINs, no file names or contents, no document data.
- Hash-chained audit entries, mirrored to the Windows Event Log by the service after each
  commit (Event Log failures never block or roll back the database write); described as
  tamper-*evident*.
- Refused privileged requests are audited (`authorization_failed`, request, account,
  admin/elevation flags), at most 20 per minute with a suppressed-count summary.
- Backups are registered (name, SHA-256, size, policy version, kind, actor) in the same
  transaction as their `backup_created` audit event.
- Restore is two-step and non-destructive (docs/AUDIT-INTEGRITY.md): *prepare* verifies the
  registered hash and the database contents and returns a preview; *apply* (same
  administrator, single use, 10-minute expiry, version check) saves a pre-restore backup and
  stores the backup's policy as a **new** version in one transaction. The audit log is never
  replaced or rolled back; successful and failed attempts are audited.
- Restore accepts only `rustward-backup-<digits>.db` / `rustward-pre-restore-<digits>.db`
  file names inside the service's backup directory — no paths.
- Audit, policy-history and backup-registry tables are append-only for application code
  (SQLite triggers). This guards against bugs, not against administrators.

## Guarantees checked by automated tests

- `rustward-windows`'s inventory backend imports only five read-only Win32 functions, and a
  crate-wide test fails if any module references device-changing, driver, registry,
  service-configuration, `DeviceIoControl` or `CreateFile` APIs.
- Phase 10: the only registry access is `policy_reader`, which has its own allowlist test
  (`RegOpenKeyExW`, `RegEnumValueW`, `RegEnumKeyExW`, `RegGetValueW`, `RegCloseKey`;
  access mask `KEY_READ | KEY_WOW64_64KEY` only). `rustward-enforcement`'s scan covers
  `policy_eval`, `policy_inspect` and `installed_assessment`. `GetEnforcementReadiness` is a
  read-only request; nothing in RustWard writes the Restrictions key.
- `rustward-core`, `rustward-enforcement` and `rustward-inventory` forbid `unsafe`.
- No component can report `VerifiedProtected` without `VerificationEvidence`, which has no
  public constructor and is not `Deserialize` (cannot be forged from IPC or files).
- Activation stays refused: `activation::request_activation` returns `ActivationDisabled`
  while `ACTIVATION_ENABLED = false`, even with every gate met or a forged readiness.
- Every privileged request is refused for non-admin, unelevated and read-only-channel
  callers through the real server pipeline, with no state change (`ipc_security.rs`).
- The installer fragment, service name, event source and versions agree
  (`rustward-service` packaging tests).
- The blocked notification "USB engellenmiştir. İşlem kayıt altına alınmıştır." is only
  selected with verified state **and** device evidence.
