# Security Audit — Phase 9A

> **Update:** the dispositions of the open findings F-12 to F-16, and new findings F-18 to F-21, are in [SECURITY-AUDIT-PHASE-9B.md](SECURITY-AUDIT-PHASE-9B.md).

Date: 2026-11-06 · Baseline: `4909958` · Auditor: repository review plus automated tests,
Linux development container only.

**Scope:** policy engine, Windows Service host, Windows API adapters, IPC authorization,
SQLite persistence, audit logging, backup/restore, Tauri command permissions, the Windows
installer draft and the enforcement activation gates.

**Method:**

- Every source file in these areas was read.
- Claims from earlier phases were re-checked against the code. The test counts and the
  per-request authorization statement were checked; the latter was false (F-04).
- Each reproducible defect got a regression test.

**Limits:** nothing was executed on Windows. Findings marked **verify on Windows** are
fixed in code that compiles and type-checks against `windows-sys` 0.61.2, and has never run.

Severity uses this project's threat model (THREAT-MODEL.md): standard-user operators are
untrusted, local administrators are trusted, and USB identifiers are not authenticated.

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| F-01 | **High** | Backup/restore | Restore replaced the whole database: newer audit history left the live log, and the active policy rolled back to the backup's version | Fixed + tests |
| F-02 | Medium | Backup/restore | Backup files were not authenticated: any SQLite file with a valid name in the backup directory was accepted | Fixed + tests |
| F-03 | Medium | IPC (client) | The client checked only that the pipe server ran in session 0; a standard user can run a session-0 process and squat the pipe name | Fixed, **verify on Windows** |
| F-04 | Medium | IPC (server) | The caller was identified once per connection, before any data was read, which contradicted the documented per-request design; impersonation is defined on "the last message read" | Fixed + tests, **verify on Windows** |
| F-05 | Medium | Service | If the database could not be opened, the service stopped with no Event Log entry | Fixed, **verify on Windows** |
| F-06 | Medium | Event Log / installer | No event source registration and no message resource, so Event Viewer showed "description … cannot be found" | Fixed + tests, **verify on Windows** |
| F-07 | Low | Audit | Failed restore attempts and invalid restore requests were not audited | Fixed + tests |
| F-08 | Low | Audit | Audit, policy-history and backup tables could be changed by any application SQL (no guard against bugs) | Fixed (triggers) + tests |
| F-09 | Low | Enforcement | `VerificationEvidence` and `EnforcementState` derived `Deserialize`, so a "verified protection" state could be built from JSON | Fixed |
| F-10 | Info | Release | No dependency inventory and no licence or advisory check | Fixed: `deny.toml`, inventory; both lockfiles pass |
| F-11 | Info | Docs/config | Stale statements: Tauri shell "not compiled", sc.exe failure actions different from WiX, SECURITY-MODEL "per request" | Fixed |
| F-12 | Medium | Audit | Local administrators can defeat local audit integrity | Open, by design (L-24); documented |
| F-13 | Low | IPC | Single-instance pipes: a standard user can occupy the status pipe (local DoS of the dashboard) | Open (L-26) |
| F-14 | Low | Service | Pipe threads are not joined at stop | Open (L-27) |
| F-15 | Low | Event Log | Mirror cursor is in memory; events from before attach or from a log outage are not back-filled | Open (L-25) |
| F-16 | Low | Service | Runs as LocalSystem | Open (L-28) |
| F-17 | Info | Activation | No controlled activation workflow existed; only a constant | Designed + implemented as gates; activation still refused |

No Critical findings. No path found that blocks or unblocks a device, writes the
registry or Group Policy, or reports protection as active. The crate-wide forbidden-API
scans and the activation tests enforce this.

## Details

### F-01 Restore replaced audit history and rolled the policy back — High — Fixed

**Before:**

- `Store::restore_from` copied the backup over the live database.
- A pre-restore copy and an `audit_history_replaced` event existed, but every event
  after the backup was gone from the live log.
- The active policy version went *back* to the backup's version, so an older,
  more permissive allowlist became active again without a fresh decision.

**After:**

- Two-step restore (`PrepareRestore` gives a verified preview; `ApplyRestore` is single
  use, tied to the same administrator, expires after 10 minutes and checks the version).
- The backup's content is saved as a **new** policy version, in one transaction with the
  history row, the settings and the `policy_restored` audit event.
- A registered pre-restore backup is taken first.
- The audit log is never replaced.

**Tests:**

- `restore_applies_backup_as_a_new_version_without_losing_history_or_audit`
- `stale_restore_is_refused_atomically`
- `restore_is_two_step_and_never_rolls_back_versions_history_or_audit`
- `prepared_restores_are_single_use_bound_to_the_admin_and_expire`

See AUDIT-INTEGRITY.md.

### F-02 Unauthenticated backup files — Medium — Fixed

A new `backups` registry (migration v2) records each backup in the same transaction as its
`backup_created` event: name, SHA-256, size, policy version, kind and actor.

Restore first checks:

- the name is registered;
- the file is a regular file, not a symlink;
- size and hash match the registry.

It then copies the file to a private temporary file, opens it read-only and checks:

- `integrity_check`;
- the schema version;
- that the RustWard tables are present;
- that the policy and settings are valid.

Each rejection has a stable code.

**Tests:**

- `foreign_altered_missing_and_traversal_backups_are_rejected`
- `registered_but_invalid_backups_are_rejected`
- `foreign_altered_and_traversal_restores_are_refused_and_audited`

### F-03 Pipe impostor via session 0 — Medium — Fixed, verify on Windows

**Problem:**

- `PipeConnection::connect` trusted any server running in session 0.
- A standard user can create a scheduled task ("Run whether user is logged on or not")
  whose process runs non-interactively in session 0.
- The pipe server creates each instance only after the previous connection ends, so the
  name is free between connections and whenever the service is stopped.
- An impostor in that window could feed the UI false status, or receive an
  administrator's policy edits. The client uses `SECURITY_IDENTIFICATION`, so it could
  not *act* as the administrator.

**Fix:**

- Both pipe SDDLs set owner `O:SY`.
- Before sending anything, the client requires the pipe object's owner to be LocalSystem
  (`GetSecurityInfo` + `IsWellKnownSid(WinLocalSystemSid)`), in addition to the session
  check.
- A standard user cannot set SYSTEM as owner.

**Tests:**

- `pipe_sddl_owner_is_system_and_dacls_are_minimal` (SDDL structure).
- The runtime check needs Windows: WINDOWS-VM-ACCEPTANCE.md C12.

### F-04 Identity taken before any read, once per connection — Medium — Fixed, verify on Windows

**Problem:**

- `PipeListener::accept` impersonated the client right after `ConnectNamedPipe`, before
  reading anything, and used that identity for the whole connection.
- `ImpersonateNamedPipeClient` impersonates "the security context of the last message
  read from the pipe" ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/desktop/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)).
- With no message read, the documented outcome is unclear. Win32 has
  `ERROR_CANNOT_IMPERSONATE` (1368, "Unable to impersonate using a named pipe until data
  has been read from that pipe").
- SECURITY-MODEL.md claimed per-request identification, but the code did not do it.

**Fix:**

- New `rpc::serve_connection_identified` identifies the caller **after each request frame
  is read**, through `PipeConnection::client_identity`.
- If identification fails, the request is refused with `Unauthorized`, audited as
  `authorization_failed` ("could not be identified"), and the connection is closed.
- No request is ever handled without an identity, read-only requests included.

**Tests:**

- `caller_is_identified_for_every_request_after_it_is_read`
- `a_caller_that_cannot_be_identified_is_refused_and_disconnected`
- `unidentified_callers_are_refused_audited_and_change_nothing`

### F-05 Silent service start failure — Medium — Fixed, verify on Windows

**Problem:**

- When `build_runtime` failed (database unreadable, newer schema, ProgramData missing),
  `run_service` returned an error to the SCM host.
- Nothing was logged, because the SQLite audit log was the component that failed.

**Fix:**

- `scm.rs` writes Event Log ID **1008 `service_start_failed`** (Error) with the reason,
  directly through `WindowsEventLog`.

**Tests:** acceptance step D4.

### F-06 Event Viewer could not format RustWard events — Medium — Fixed, verify on Windows

**Fix:**

- `eventlog_map::message_table_resource()` generates a `MESSAGETABLE`
  (`MESSAGE_RESOURCE_DATA`, Unicode entries `%1`) for every ID in `EVENT_IDS` plus 9000.
- `rustward-service/build.rs` embeds it with `embed-resource` on Windows targets.
- The WiX fragment registers `util:EventSource` (Application log, source `RustWard`,
  `EventMessageFile` = the service exe). Uninstall removes it.
- RustWard never registers the source at runtime.

**Tests:**

- `message_table_resolves_every_event_id_and_nothing_else` parses the blob the way
  `FormatMessage` resolves IDs.
- `installer_fragment_matches_runtime_constants` checks the fragment.

### F-07 Unaudited restore failures — Low — Fixed

The following attempts are now recorded:

- every rejected prepare or apply (`restore_failed` with stage, reason, target truncated
  to 80 characters, and account);
- invalid restore requests, through `Handler::validation_failed`;
- authorization refusals, through the existing rate-limited `authorization_failed`.

### F-08 Mutable audit tables — Low — Fixed

Triggers (migration v2):

- `security_events`: no UPDATE; DELETE only through the retention guard.
- `policy_changes`: no UPDATE, no DELETE.
- `policy_states`: content immutable; no DELETE.
- `backups`: no UPDATE, no DELETE.

This protects against bugs, not against administrators (F-12).

**Tests:**

- `audit_and_history_tables_are_append_only_for_application_code`
- `v1_database_upgrades_to_v2_keeping_data_and_gaining_guards`

### F-09 Forgeable verification types — Low — Fixed

**Problem:** no deserialization site existed, but deriving `Deserialize` left a path for
forged evidence if a future IPC or file format had carried it.

**Fix:**

- `Deserialize` removed from `VerificationEvidence` and `EnforcementState`.
- `AppliedPolicyReceipt` (new) is not `Deserialize` either.

### F-10 Dependency hygiene — Info — Fixed

**Changes:**

- `deny.toml` sets licence allowlist, `yanked = "deny"`, crates.io only, no wildcards,
  and the target `x86_64-pc-windows-msvc`.
- `cargo deny check` passes for the workspace and for the Tauri shell (2026-11-06).
- The only advisory, RUSTSEC-2024-0370 (`proc-macro-error`, unmaintained), comes from
  the Linux-only GTK stack used to compile the shell in the container. It is not in the
  Windows build.
- `docs/DEPENDENCY-INVENTORY.md` is generated by `scripts/dependency-inventory.sh`:
  - 38 crates for service and libraries;
  - 233 crates for the desktop shell;
  - 5 npm production packages.
- `build-release.ps1` ships it with the artifacts, under `SHA256SUMS.txt`.

### F-11 Stale statements — Info — Fixed

- The src-tauri `main.rs` header now says the shell is compiled and tested on Linux, and
  the Windows build is unverified.
- `INSTALL_PLAN` failure actions now match WiX: 5 s × 3.
- The "per request" statement is now true (F-04).
- A version-consistency test was added: Cargo, `tauri.conf.json` and `package.json` all
  give 0.1.0.

### F-12 Local administrator vs. audit — Medium — Open by design

An administrator can:

- drop the triggers;
- recompute the unkeyed chain and the anchor;
- delete backups;
- clear the Event Log.

The chain cannot detect truncation of its newest records.

**Decision:** documented as tamper-*evident* only (AUDIT-INTEGRITY.md §6). A separate
SQLite audit store was evaluated and rejected: it gives no atomicity with policy commits
and no additional protection.

**Recommended organisational control:** periodic export to write-once media.

### F-13 to F-16 — Open, tracked in KNOWN-LIMITATIONS

| ID | Limitation | Note |
|---|---|---|
| F-13 | L-26 | `nMaxInstances = 1`; the idle timeout is 15 s, so a standard user can keep reconnecting. There is no policy impact; the admin pipe is unaffected. |
| F-14 | L-27 | Threads stay in `ConnectNamedPipe`. The process exits after `SERVICE_STOPPED`. Each request is a single transaction, so no partial changes. |
| F-15 | L-25 | — |
| F-16 | L-28 | A virtual service account needs coordinated changes to the pipe owner, the ACLs and the Event Log message file permissions. Evaluate in the VM. |

### F-17 Controlled activation workflow — Info — Implemented as gates

`rustward-enforcement::activation` adds the following:

- **Six typed stages:** detection → classification → simulated authorization → planned
  enforcement → activated policy → verified read/write denial.
  - Only the last stage claims protection.
  - The activated and verified stages need values with no public constructor and no
    `Deserialize`.
- **Thirteen gates.**
- **A SHA-256 plan fingerprint**, which binds the dry-run review, the change confirmation
  and the final approval to the exact registry values.
- **A computed system-disk gate.** It requires:
  - an `AllowInstanceIDs` rule for every internal disk;
  - no disk with unknown attachment;
  - at least one internal disk;
  - a non-retroactive class rule.

`request_activation` returns `ActivationDisabled` while `ACTIVATION_ENABLED = false`, even
with a forged "all gates met" readiness. The provider's `activate` refuses as well.

Gates that are NotMet in this build regardless of operator input:

- `build_permits_activation`;
- `windows_compatibility_verified` (`vm_validation` is hard-wired NotMet);
- `policy_validated` (no planned value is confirmed against Microsoft documentation yet,
  and the example policy is dry-run).

The synthetic fixture also keeps `system_disks_protected` shut, because one disk has a
broken parent chain. That is fail-closed and intended.

**Tests:** 6 in `activation.rs`.

## Reviewed with no defect found

| Area | Checked |
|---|---|
| Policy engine | Default deny; generic vendors rejected; unknown attachment in scope (fail-closed); internal disks never in scope; brand matching only on documented identifier kinds; 69 core tests. |
| Privileged IPC | All 15 privileged request types are refused for five caller kinds through the real pipeline: non-admin, unelevated admin, elevated non-admin, and admin or non-admin on the status pipe. No state changes and every refusal is audited (`ipc_security.rs`). Replays of versioned mutations give `conflict`, and exactly one of several captured requests applies. An interrupted connection applies a change at most once. Malformed, oversized, wrong-version and out-of-range requests are refused before the handler. |
| Frontend bypass | The UI holds no authority. The Tauri shell exposes one command (`ipc_call`); the capability grants only `allow-ipc-call`; CSP is `default-src 'self'`; no global Tauri object. Release builds cannot contain the dev backend (release-mode test). There is no frontend password. |
| Export | Returns content over IPC; there is no client-chosen path. |
| Retention | 30–3650 days, validated both client- and server-side. Audited and mirrored. Chain stays verifiable. |
| Data directory | WiX `PermissionEx` `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, permanent (test). |
| Unsafe code | `rustward-core`, `-enforcement`, `-inventory`, `-service` forbid `unsafe`. The `unsafe` blocks in `rustward-windows` and `rustward-ipc::pipe` each carry a SAFETY comment (clippy `undocumented_unsafe_blocks = deny`). |

## Not verifiable here

- Named-pipe DACLs, owner and impersonation behaviour (F-03, F-04).
- SCM start, stop and recovery.
- Event Log formatting (F-05, F-06).
- SetupAPI on real devices.
- WebView2.
- The MSI.

Procedure: WINDOWS-VM-ACCEPTANCE.md, Stages A–E.
