# Security Audit — Phase 9B

**Date:** 2026-11-06. **Baseline:** `056923b`.

**Environment and method:**

- Linux development container only.
- Before any change, `056923b` was re-verified from a clean worktree: 212 Rust and 39 Vitest tests passed, and every Linux-feasible check in `scripts/verify-all.sh` was green.
- Nothing ran on Windows. **Verify on Windows** marks a finding whose fix compiles and type-checks against `windows-sys` 0.61.2 but has never executed.
- The working copy also held unfinished, uncommitted Phase 9B work from an interrupted earlier session: the pooled pipe server, the persisted mirror cursor, truncation detection and the pipe DACL change. That work was reviewed line by line, completed, tested and committed together with the rest of this phase.

## 1. The five findings left open by Phase 9A

| ID | Severity | Component | Can it be resolved without Windows? | Disposition |
|---|---|---|---|---|
| F-12 | Medium | Local audit integrity against administrators | No (a local administrator controls the machine) | **Partially mitigated, open by design.** |
| F-13 | Low | Named-pipe server: one client at a time | Logic: yes. Pipe behaviour: no | **Fixed in logic.** The pipe behaviour must be verified on Windows. A small residual remains (§1.2). |
| F-14 | Low | Service stop: pipe threads not joined | Logic: yes. Wake-up of `ConnectNamedPipe`: no | **Fixed in logic.** Verify on Windows. |
| F-15 | Low | Event Log mirror cursor in memory | Yes, except actual Event Log delivery | **Fixed.** Event Log delivery is still unverified on Windows. |
| F-16 | Low | Service runs as LocalSystem | No | **Prepared, not switched; stays open.** |

### 1.1 F-12: local administrator versus the audit log

**What changed**

- **Truncation detection.** `verify_chain` now reports `Truncated` when SQLite's `AUTOINCREMENT` counter has issued ids above the newest remaining event. It reports `Missing` when ids are missing inside the chain. Both used to verify as intact. Retention is not mistaken for truncation (test `retention_is_not_mistaken_for_truncation`).
- **`audit_checkpoint` events (Event ID 5008).**
  - Recorded at service start and then daily.
  - Each one carries the head id, head hash, entry count and highest issued id.
  - Because they are mirrored to the Windows Event Log, a copy exists outside the database.
- **`rustward-service verify-checkpoint --head-id N --hash HEX [--db PATH]`.**
  - Opens the database read-only, so it is safe while the service runs.
  - Compares the database with a checkpoint copied from Event Viewer.
  - Exit codes: 0 = match; 3 = rewritten or removed; 4 = older than retention.
  - Test `external_checkpoints_reveal_rewrites_truncation_and_resequencing` shows a *consistent* rewrite going undetected internally and being caught by the external checkpoint. That rewrite deletes the newest events, resets `sqlite_sequence` and appends a forged event.

**Why it stays open.** An administrator can also clear the Event Log, delete exported checkpoints, and stop the service. RustWard makes tampering **evident** when an out-of-database copy survives, such as Event Log entries, exports kept on write-once media, or a printed checkpoint. It cannot make tampering **impossible** (AUDIT-INTEGRITY.md §6).

### 1.2 F-13: one client at a time

**What changed**

- `rustward-ipc::server` is a platform-independent connection pool:
  - each caller has its own thread;
  - a busy limit refuses extra connections;
  - slots are reused;
  - an idle timeout applies;
  - accept errors back off and are counted.
- `PipeListener` keeps one listening instance at all times.
  - The first instance uses `FILE_FLAG_FIRST_PIPE_INSTANCE`.
  - Further instances are created only while one of ours is connected, so they always join our pipe object and never a squatter's.
- Limits:
  - status pipe: 8 connections;
  - admin pipe: 4 connections, which standard users cannot open at all;
  - idle timeout: 15 s.
- Tests: `tests/server_pool.rs` (7) and `ipc_pool` (3).

**Residual.** A standard user can still hold all 8 status slots by reconnecting repeatedly. Each held connection is dropped after 15 s idle. The admin pipe and policy are unaffected (L-26).

### 1.3 F-14: shutdown

**What changed**

- `ServerHandle::shutdown`:
  - sets the stop flag;
  - wakes the blocked accept by connecting to our own pipe;
  - lets an in-flight request finish and be answered;
  - joins every thread within 3 s per pipe.
- Idle connections notice the stop within 200 ms.
- Threads that cannot be joined are reported, and the service audits `ipc_shutdown_incomplete` (Event ID 1010) instead of ignoring them.
- `scm.rs` shuts the pipes down before reporting `SERVICE_STOPPED`. The SCM wait hint is 15 s; both pipes need at most 6 s (test).

### 1.4 F-15: Event Log mirror cursor

**What changed**

- The cursor (the last event id delivered) is persisted in `settings`.
- When the mirror attaches:
  - events written before attachment (start-up) are delivered, as are events written while the Event Log was failing;
  - at most the newest 1000 pending events are delivered;
  - an older skipped range is recorded as `event_log_backfill_skipped` (Event ID 1009), which is itself mirrored.
- Delivery keeps id order and stops at the first rejected event. The service retries on every tick.
- Delivery is **at-least-once**: an event can be written twice if the process stops between writing and saving the cursor. Each entry carries its audit id, so duplicates are identifiable.
- Diagnostics shows *pending* and *skipped* counts (Turkish and English).
- Tests in `store.rs` and `app_flows.rs`.

### 1.5 F-16: LocalSystem

**What changed (prepared only)**

- `rustward-ipc::service_sid` derives the `NT SERVICE\RustWardService` SID. The derivation is checked against the well-known SID of `NT SERVICE\TrustedInstaller`.
- It also builds the pipe and data-directory SDDL for LocalSystem or the virtual account. The LocalSystem builders produce exactly the shipped constants (test).
- Clients accept a pipe owner of LocalSystem **or** the RustWard service SID, and nothing else.
- Clients additionally require the pipe-serving process to be the process the SCM reports for `RustWardService` (`GetNamedPipeServerProcessId` + `QueryServiceStatusEx`).

**Why it is not switched**

- A virtual account must first be validated on Windows for SetupAPI enumeration, `CM_Register_Notification`, Event Log writes and named-pipe impersonation.
- A future enforcement write path writes `HKLM\SOFTWARE\Policies\…`, which a virtual account cannot do. That path would need LocalSystem or a separate privileged step.
- Decision deferred to VM Stage C (WINDOWS-VM-ACCEPTANCE.md C16).

## 2. New findings in Phase 9B

| ID | Severity | Component | Finding | Status |
|---|---|---|---|---|
| F-18 | Medium | Status-pipe DACL | Authenticated Users had `GENERIC_WRITE`, which on pipes includes `FILE_CREATE_PIPE_INSTANCE` | Fixed, **verify on Windows** |
| F-19 | Low | SQLite storage | Two processes opening a new database at the same time could fail ("database is locked" / "table … already exists") | Fixed + regression test |
| F-20 | Info | Frontend bundle | Vite's module-preload polyfill contained the bundle's only `fetch()` | Fixed + offline-asset check |
| F-21 | Info | Developer toolchain | The Vitest 3.2.7 test runner has published advisories (tinypool, @vitest/mocker) | Open (dev-only; not shipped) |

### F-18: `FILE_CREATE_PIPE_INSTANCE` granted to standard users (Medium)

**Problem**

- The status pipe granted Authenticated Users `GENERIC_WRITE`.
- Microsoft: "Because FILE_APPEND_DATA and FILE_CREATE_PIPE_INSTANCE have the same definition, so FILE_GENERIC_WRITE enables permission to create the pipe. To avoid this problem, use the individual rights instead of using FILE_GENERIC_WRITE." ([Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights))
- A standard user could therefore create extra server instances of `RustWard.Status.v1` while the service was running.

**Fix**

- Authenticated Users now get `0x12008b` (`FILE_GENERIC_READ | FILE_WRITE_DATA`), and clients open pipes with exactly those rights.
- The client checks were already defence in depth (owner = LocalSystem from F-03) and now also include the server-PID match with the SCM.
- Test: `pipe_sddl_owner_is_system_and_dacls_are_minimal` decodes the mask and forbids `FILE_CREATE_PIPE_INSTANCE`, `WRITE_DAC`, `WRITE_OWNER` and `FILE_WRITE_ATTRIBUTES`.
- Runtime check: Windows acceptance step C17.

### F-19: concurrent first open (Low)

**Problem**

- Migrations and every write used deferred transactions that read and then write.
- When two processes created the database at the same moment, the second failed instead of waiting.
- Found by the new real-backend UI integration tests, which start two backend processes on one database.
- In production only the service writes the database, so the practical impact was a failed start if a second instance or tool created the database simultaneously.

**Fix**

- All write transactions are `IMMEDIATE`.
- All pending migrations run in one transaction that re-reads the schema version inside it.

**Regression test:** `concurrent_first_opens_of_a_new_database_serialise_cleanly`. It runs 8 threads × 5 rounds and **fails without the fix**: reverting to deferred transactions reproduced "database is locked".

### F-20: `fetch()` in the bundle (Info)

**Problem.** The polyfill only fetched local `<link rel="modulepreload">` files, but it was the one network API in the shipped JavaScript.

**Fix.** The polyfill is disabled (WebView2 supports module preload natively). `scripts/check-offline-assets.mjs` now fails the build on:

- any external URL other than XML namespace identifiers and React's error-text links;
- any non-local `src`/`href`/`@import`;
- `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource` or `sendBeacon`.

A Rust test asserts that the Tauri CSP lists only local sources.

### F-21: test-runner advisories (Info, open)

`npm audit` shows 0 vulnerabilities in production dependencies. The test runner itself (Vitest 3.2.7 → tinypool 1.1.1, @vitest/mocker) has advisories:

- GHSA-5gmw-xhrv-c9v3 and GHSA-85c8-ppgw-ccpr (tinypool);
- GHSA-82fw-gwwq-j7x9 and GHSA-qxg6-89mg-rqv8 (@vitest/mocker).

They need attacker-controlled input to the local test runner. They are not reachable from the application, the MSI or the workstations. The upgrade to Vitest 4.1.12 failed in this container with an npm 10.9.9 internal error (`Cannot read properties of null (reading 'edgesOut')` in arborist).

**Action:** upgrade on the build machine in a separate change, then re-run all tests.

## 3. Security regression checklist

| Property | Evidence (automated) | Limitation outside Windows |
|---|---|---|
| Unauthorized IPC requests are denied | `ipc_security.rs`: 15 privileged requests × 5 caller kinds; real-backend UI tests as a standard user | Caller kinds are constructed; real token reading (C9–C11) not run |
| Caller identity is verified at the right boundary | Per request after the frame is read (`rpc_mock.rs`, `server_pool.rs`); unidentifiable callers refused | `ImpersonateNamedPipeClient`, owner, session and PID checks are Windows-only |
| Policy changes require administrative authorization | `ipc_security.rs`, `realBackend.integration.test.tsx` ("cannot change brands from the UI") | as above |
| Restores preserve audit history | `store.rs`, `app_flows.rs`, real-backend UI restore test (events only grow) | — |
| Restore cannot traverse paths | `foreign_altered_missing_and_traversal_*`, validator tests, stdio harness | NTFS-specific names (ADS `:`, reserved names) are rejected by the strict name pattern; not exercised on NTFS |
| Failed operations are audited | `restore_failed`, `authorization_failed` (rate-limited), unidentified callers, `ipc_shutdown_incomplete` | Event Log copy not verified |
| Simulated decisions are never shown as verified protection | `VerificationEvidence` / `AppliedPolicyReceipt` not constructible or deserialisable; UI tests forbid "engellenmiştir" against both fake and real backends | — |
| Unknown manufacturers are not authorized automatically | core `evaluate` tests (default deny), real-backend devices test (SİMÜLE RET) | — |
| Essential peripherals are excluded | core classification tests (keyboard, mouse, printer, hubs never in scope); the plan never denies peripheral classes | Real hardware not inventoried |
| Service shutdown is not read as protection | Pages test "Service unavailable": banner stays, error shown; dashboard `protection_verified` false without evidence; the service only reports `pending_validation` | — |
