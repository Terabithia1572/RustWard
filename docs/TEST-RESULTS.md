# Test Results

Last run: **2026-11-06**, after the service-host / telemetry / audit work (see `PHASE-STATUS.md`). Reproduced from a clean clone of `e3f9bde` before changes: 153 Rust + 30 Vitest PASS.

Vocabulary: **PASS** · **FAIL** · **NOT RUN** · **DEFERRED** (postponed by the project
owner to the final Windows acceptance stage).

> Every result below was produced on **Linux**. A successful Linux build or test run does
> **not** prove Windows compatibility, and a simulated denial is **not** operating-system
> enforcement. RustWard currently blocks nothing.

## 1. Environment

| Item | Value |
|---|---|
| OS | Ubuntu 24.04.5 LTS, x86_64 (cloud build workspace) |
| Rust | rustc 1.97.0, cargo 1.97.0, clippy, rustfmt (workspace MSRV 1.90) |
| Node / npm | Node 22.23.4, npm 10.9.9 |
| Webview libs | webkit2gtk-4.1 2.52.6, GTK 3.24.41 (installed only to compile the Tauri shell on Linux) |
| Windows target | Not available (`x86_64-pc-windows-msvc` std could not be downloaded). Windows-only code is type-checked through the `host-typecheck` feature. |

Reproduce: `./scripts/verify-all.sh` (prints PASS / FAIL / NOT RUN per check).

## 2. Automated tests — PASS

| Suite | Tests | Result |
|---|---:|---|
| `rustward-core` unit (ids, device, catalog, policy, classify, evaluate, plan, report, names, policy_edit incl. workstation-ID edit, explain, diff) | 47 | PASS |
| `rustward-core` `tests/fixture_eval.rs` (51-device synthetic snapshot, end-to-end) | 19 | PASS |
| `rustward-core` `tests/encrypted_lifecycle.rs` (synthetic placeholder IDs, re-enumeration) | 3 | PASS |
| `rustward-windows` unit (property decoding, enumeration engine with failure injection, snapshot assembly, read-only inventory API allowlist, crate-wide forbidden-API scan, SCM control decisions and status fields, device-change decoding, Event Log mapping) | 27 | PASS |
| `rustward-enforcement` unit (activation compiled out, never claims protection, blocked message needs verified state + device evidence, dry-run plan never retroactive and keeps internal disks, preconditions, no system-modification APIs) | 10 | PASS |
| `rustward-inventory` unit | 4 | PASS |
| `rustward-storage` unit + `tests/store.rs` (migrations, newer schema refused, stale edits rejected atomically, tampered policy detected, hash chain tamper detection, retention keeps chain verifiable, backup/restore, event observer receives every committed event once and in order, observer failures never block writes, restore does not replay history) | 2 + 15 | PASS |
| `rustward-ipc` unit + `tests/rpc_mock.rs` (framing, authorization matrix, field validation incl. backup file names that cannot escape the backup directory and workstation IDs; privileged requests refused before the handler and reported to the audit hook, invalid requests not reported as authorization failures, admin on read-only channel refused, protocol version mismatch, malformed frames, timeouts, response-id mismatch) | 8 + 10 | PASS |
| `rustward-ipc` `tests/contract.rs` (golden request contract, round-trip, naming) | 3 | PASS |
| `rustward-app` unit + `tests/app_flows.rs` (CRUD persists across restart, conflict codes, synthetic simulation, arrival/removal events, degraded health + recovery, export/backup/retention, corrupt policy fails closed, dashboard never claims protection, workstation-ID edit, restore with pre-restore copy and undo, bad backups refused, backup audit, authorization-failure audit with rate limit, Event Log observer + diagnostics) | 2 + 17 | PASS |
| `rustward-service` unit (console mode on a temp DB with synthetic inventory, degradation/recovery, daily retention, stop handling, external stop handle, device-change wake-up with burst coalescing, disconnected wake source does not spin, Event Log mirror mapping and error propagation, paths) | 12 | PASS |
| `rustward-ui-bridge` unit (debug + `dev-backend`) | 2 | PASS |
| **Rust workspace total** (`cargo test --workspace --all-features`) | **181** | **PASS** |
| `rustward-ui-bridge` in **release** mode with `dev-backend` on: always selects the service | 2 | PASS |
| `src-tauri` Tauri mock-runtime IPC tests: `ipc_call` through the real Tauri IPC + capability ACL into the dev backend; stale version → `conflict`; malformed requests rejected; other commands rejected | 4 | PASS |
| Vitest: i18n completeness/placeholders/forbidden "blocked" claims, IPC contract vs Rust golden file, API client error mapping, page behaviour (banner, explanation, manufacturer CRUD + client validation + conflict, blocked wording, audit filter/export, diagnostics simulation and Event Log status, settings/theme/authorization error, workstation-ID validation and save, restore only after confirmation, cancel changes nothing), in-app notifier (no notice for pre-existing denials, one honest notice per new denial, dismiss, allows ignored, no polling when disabled) | 38 | PASS |

## 3. Static checks — PASS

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` (deny unwrap/expect/panic/undocumented unsafe) | PASS |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` (includes `host-typecheck`: SetupAPI, named pipes, pipe servers, service pipe client type-checked against windows-sys 0.61.2) | PASS |
| `tsc -b --noEmit` (strict, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) | PASS |
| `vite build` — bundle contains no external URLs except XML namespace strings and React's error-doc string (not fetched) | PASS |
| `src-tauri`: `cargo fmt --check`, `cargo clippy --all-targets -D warnings` (Linux/webkit2gtk) | PASS |
| SCM host, `CM_Register_Notification` subscription, Event Log writer, service entry (`scm.rs`) — compiled with `host-typecheck` in the all-features clippy run (confirmed by planting a type error, which was reported) | PASS (type-check only; never executed) |

## 4. Offline build preparation — PASS on Linux

| Check | Result |
|---|---|
| `scripts/vendor-offline.sh`: 413 crates vendored (597 MB), npm cache 76 MB incl. win32-x64 native packages | PASS |
| `cargo build --offline --locked` of `rustward-service` + `rustward-inventory` with an **empty** `CARGO_HOME` and vendored sources | PASS |
| `cargo check --offline --locked` of the Tauri shell with vendored sources | PASS |
| `npm ci --offline` from the cache (linux-x64, and `--os=win32 --cpu=x64`) | PASS |
| Same steps on Windows (`scripts/build-release.ps1 -Offline`) | **NOT RUN** |

## 5. Visual check of the UI — done with a test-only fake backend

The production frontend refuses to render outside the Tauri shell. For a visual check the
pages were rendered in headless Chromium against `src/test/fakeBackend.ts` (test code, not
bundled): Dashboard (dark), Allowed Manufacturers, Devices with explanation (light),
Diagnostics. No console errors. This is not a test of WebView2 on Windows.

## 6. DEFERRED / NOT RUN

Postponed by the project owner to the final Windows acceptance stage. None of these may be
reported as passed until executed on the isolated Windows 10 Pro x64 acceptance VM.

| Area | Items | Status |
|---|---|---|
| Native build | `cargo build/test` with the MSVC toolchain (TEST-PLAN W-01, W-02); `scm.rs` compile | DEFERRED |
| Native inventory | Live SetupAPI enumeration, non-present devices, real USBSTOR IDs (W-03..W-05); `tests/native_windows.rs` | DEFERRED |
| Service | SCM registration, start/stop, failure restart, LocalSystem runtime, `%ProgramData%\RustWard` ACL | DEFERRED |
| IPC | Named-pipe DACLs, `PIPE_REJECT_REMOTE_CLIENTS`, impersonation + elevation check, session-0 check, standard-user denial (T-22) | DEFERRED |
| Desktop app | Tauri on WebView2, CSP in WebView2, release build without dev backend, elevation UX | DEFERRED |
| Packaging | MSI build, WiX service fragment, offline WebView2 install, install/repair/uninstall, offline install (T-25) | DEFERRED |
| Enforcement | Any Device Installation Restriction validation; every physical USB test T-01..T-30 | DEFERRED |
| Hardware identity | TÜBİTAK SIR II inspection (T-04..T-07) | DEFERRED — blocking for SIR II |
