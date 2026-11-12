# Test Results

**Phase 5 — native build and VM, 2026-11-07 (`77b7794`).**

The native build ran on the Windows 11 host (build only; nothing installed there).

| Artifact | Size (bytes) | SHA-256 |
|---|---|---|
| `dist\RustWard.exe` | 4,082,176 | `1324dccd211b3baa7e9e9cdb9e5f85ef175fbb0d04e44910263d82281856eaf2` |
| `dist\service\rustward-service.exe` | 3,358,208 | `542913a45c50a0774e58f62eb0bfbbc4fda9ee995f52b535c49ff7d0440da4af` |
| `dist\installer\RustWard_0.1.0_x64_tr-TR.msi` | 219,127,808 | `b1fa823f51c5df928de2c23aba50b38c551f8c4bf8034f5ef366ea55572973de` |

The MSI was delivered on `dist\vm\rustward-test-6.iso`, SHA-256 `2d914f4e…62e4`.

**VM setup.** The VM is Windows 10 19045. Snapshot `rustward-before-phase5-8dfecd1` was taken at 20:50:01 before the upgrades. Two MSI upgrades were run: `8dfecd1`, then `77b7794`. Both PASS: the service restarted, and policy v6 and the audit chain were kept (186, then 208 entries intact).

**VM observations:**
- Dashboard "Koruma durumu": "Windows koruması etkin değil", "Gerçek engel kanıtı yok", "Otomatik uygulama: kullanılamıyor". This matches the real state: no Restrictions key.
- Devices page:
  - Kingston 0951:1666 and the VendorC/VendorC-reported 346D:5678 are shown as "Bildirilen (doğrulanmamış)" with "Kriptografik kimlik doğrulaması yok".
  - The hardware ID and "Son olay" are shown.
  - The Kingston's 19:58 denial is shown as history only.
- Performance (Diagnostics, VM):
  - SetupAPI enumeration of 217 devices: 51–52 ms, longest 69 ms.
  - Processing and storage: 1 ms.
  - Service start to first inventory: 371 ms and 549 ms (after the two upgrades).
  - Windows observation: 1 ms.
  - UI IPC round trip: 26 ms (`get_diagnostics`), max 59 ms over 6 calls. On the second install it was 617 ms (`get_diagnostics`, which includes the integrity check), the maximum over 50 calls.
  - Page render: 29 ms and 620 ms.
  - The 15–40 s delays of the previous build were not reproduced. Policy verification time was not measured (no guided session run on this build).
- Detection: Kingston disconnect/reconnect through VMware.
  - Audit `device_removed` 20:56:55 and 21:09:49; `device_detected` 20:59:28 and 21:10:35. Each was within about 1–2 s of the VMware action (clock-level comparison, 1 s resolution).
  - With `77b7794`, the Devices page updated by itself (no manual refresh) 3–9 s after the reconnect. That time includes the VM's USB re-enumeration.
  - No duplicate notices.
- Not re-run on this build: a real Windows denial. It is unchanged from the guided Kingston run at 19:50–20:02, build `66ed480`.

**Side effects.**
- While disconnected from the VM, the Kingston was attached to the host. Windows AutoPlay offered to scan it; this was not acted on.
- Nothing was written to either stick, and no policy was changed.
- The VM CD setting was restored afterwards to its previous (missing) Acronis ISO path, not connected.

**Phase 5 — real Windows status, performance, terminology, 2026-11-07 (Linux, automated).**
- **Backend:**
  - The inventory is collected outside the application lock (SetupAPI enumeration no longer blocks IPC).
  - Device rows are stored in one transaction instead of one autocommit per device.
  - Diagnostics expose service timings.
  - Verify actions re-read the inventory first.
  - The dashboard carries `windows_protection` (unknown, inactive, configured_unverified, denial_observed, verified_active), derived only from the policy re-read plus device problem codes.
  - Each observed device carries its latest non-simulated audit event.
  - After an administrator rollback, the guided headline asks for the rollback verification.
- **UI:**
  - "Koruma durumu" panel.
  - Blocked page: real Windows denials first; simulated decisions separate.
  - Devices page: "Bildirilen (doğrulanmamış)" vendor, policy match, last event, hardware ID.
  - Diagnostics: performance card with the UI-measured IPC round trip and render time.
  - Guided progress messages.
  - Turkish terms: İzinli cihazlar, Engellenen cihazlar, Olay kayıtları, Gerçek Windows kanıtı, Yönetici onayı, Geri alma.
- **New tests:**
  - `a_slow_windows_enumeration_does_not_block_other_requests`: 1.5 s fake enumeration, dashboard and observation answered in under 700 ms.
  - `dashboard_protection_state_follows_real_windows_evidence_only`.
  - `realStatus.test.tsx` (9 tests).
- **Result:** 317 Rust tests, 72 Vitest, 16 integration; `verify-all` 18 PASS, 0 FAIL. At `77b7794` (live device watcher): 74 Vitest, `verify-all` 18 PASS.
- **Not run:** native Windows checks (see the VM entry, when recorded).

**Turkish localization + administrator-guided Windows enforcement, 2026-11-07 (`66ed480`, native build + VM).** Native build (Windows 11 23H2 host, build only): `dist\RustWard.exe` 4,044,800 B `a7946f2bebeaf3f5e0542cdb38713e493f6119ff51e0149f66164070a870b02f`; `dist\service\rustward-service.exe` 3,339,776 B `2c05b87c30f16d24cc7568c0721f861ab6ff7616403559e9920ae1a8b0f82bc9`; `dist\service\rustward-inventory.exe` `a112ed03a4b3d8823f5176c7af5a709d6d5e3d0a0a8813b051fea3bdaeaea7f2`; `dist\installer\RustWard_0.1.0_x64_tr-TR.msi` 219,099,136 B `ce836b65350d2813e5804b65556ebae245a3bc422d9e39a5dff5e07ecf982311` (Turkish installer UI). VM (Windows 10 19045, snapshot `rustward-observer-before-guided-test` taken first): MSI upgrade PASS, policy v5 and audit chain kept; backend text (service status, audit messages, errors) shown in Turkish. Guided session (elevated app): prepare 19:50:27 (baseline: no Restrictions key) → owner applied the Kingston-only device-ID policy (retroactive) in gpedit → RustWard "Uygulamayı doğrula" 19:58:15: policy equal to the expected values, Kingston Code 1 "forbidden by system policy", state "Windows cihaz kurulumu engellendi", read/write "Doğrulanmadı"; notice "USB engellenmiştir. İşlem kayıt altına alınmıştır." shown once with the evidence qualifier; independently: Device Manager Code 1, E:/F: gone, VendorC G: readable. Owner rolled back → "Geri almayı doğrula" 20:02:22: policy equal to the baseline, session closed; Kingston reinstalled (E:/F: back), shown as history only. Audit: prepared, windows_install_denied_observed (once), apply_verified, windows_install_denial_ended, rollback_verified. RustWard wrote no policy: the change was made by the administrator. Slow: first requests after a service start and the verify actions took 15–40 s. Linux suite: 308 workspace + 3 + 4 Rust, 63 Vitest, 16 integration; `verify-all` 18 PASS.

**Real Windows enforcement observer, 2026-11-07 (`f49a545`, native build + VM).** Native Windows build (BUILD-RUSTWARD.cmd, Windows 11 23H2 22631, rustc 1.92): `dist\RustWard.exe` `132159e0…78df`, `dist\service\rustward-service.exe` `762911c1…6b82`, `dist\service\rustward-inventory.exe` `613b9ac4…514f`, `dist\installer\RustWard_0.1.0_x64_en-US.msi` (218,984,448 bytes) `276f31e268d9edf0c571a538a9fc4a477409b714fd42d9700ae3b231743755ed`; MSI tables checked read-only. MSI upgrade in the VM: PASS (service, policy v4 and audit chain kept). App started unelevated: the observer works over the read-only status pipe. Readiness "Gerçek Windows gözlemi": Restrictions key absent, no rule; Kingston 0951:1666 and VendorC-reported VendorC 346D:5678 both "Kural uygulanmamış / Erişilebilir / Gerçek engel kanıtı yok" (the manual 13:31 block predates the observer and is not shown as current). Checklist generated from the live VM inventory: only the Kingston affected, expected values identical to the verified experiment. Devices page column "Gerçek Windows durumu": PASS. Not run in the VM: a live denial seen by the observer (requires re-applying the policy). Linux suite: 300 workspace + 3 release + 4 src-tauri Rust, 58 Vitest, 16 integration, `verify-all` 18 PASS.

**Real Windows USB block 2026-11-07 (VM, policy applied manually by the owner): see [WINDOWS-VM-KINGSTON-BLOCK-2026-11-07.md](WINDOWS-VM-KINGSTON-BLOCK-2026-11-07.md).** Kingston blocked (Code 1, then Code 28 after reconnect), VendorC/internal disk/input devices unaffected, rollback PASS. RustWard read the policy; it did not apply it.

**Read-only hardware identification 2026-11-07 (VM): see [BRAND-IDENTIFICATION.md](BRAND-IDENTIFICATION.md#observed-hardware-vm-2026-11-07-read-only).** Kingston 0951:1666 identified; the VendorC USB stick reports `VendorC` 346D:5678 (corrected label; no SanDisk stick available). 8 regression tests on the sanitized observations (`vm_observed_hardware.rs`); all decisions are simulated. Linux suite: 285 Rust workspace + 3 release + 4 src-tauri, 50 Vitest, 16 integration — PASS; `verify-all` 18 PASS, 0 FAIL.

**Native Windows VM test 2026-11-06 (service installed from the complete MSI): see [WINDOWS-VM-TEST-2026-11-06.md](WINDOWS-VM-TEST-2026-11-06.md)** — IPC, LocalSystem service, SCM stop/start/restart/crash recovery, elevation-based authorization, SQLite persistence across reinstall, real SetupAPI inventory, Event Log writes and uninstall PASS; caller identity FAIL then fixed and PASS; formatted Event Viewer messages NOT VERIFIED; scripted pipe-ACL/impostor tests NOT RUN. Linux suite at `de4c6b4`: 277 Rust workspace + 3 release + 4 src-tauri, 50 Vitest, 16 integration — PASS.

Earlier entry — Last run: **2026-11-06**, **Phase 11** (native Windows build preparation). **No native Windows test was executed** (no Windows execution environment or disposable VM was available; PHASE-11-NATIVE-VALIDATION.md).

After Phase 11 (Linux): **276 workspace + 3 release-mode + 4 src-tauri = 283 Rust; 43 Vitest + 16 Vitest integration — PASS, 0 failed, 0 ignored.** `scripts/verify-all.sh` with `RUSTWARD_PWSH` and `RUSTWARD_WINDOWS_TARGET_CHECK=1`: **19 PASS**, 0 FAIL, 4 NOT RUN (native Windows, pipes/service runtime, native SetupAPI, physical USB).

| Phase 11 check | Result |
|---|---|
| `crates/rustward-service/tests/acceptance_scripts.rs` (5): no script changes Windows configuration; only the MSI script runs msiexec, behind the VM guard, typed confirmation and hash check; stage scripts guarded and marked never executed; Stage E exports before and after | PASS (Linux, static) |
| `rustward-ui-bridge` `service_backend_name_is_stable` (+1, also in release mode) | PASS |
| PowerShell 7.4.22 parser on all 8 scripts; PSScriptAnalyzer 1.25.0 (0 errors, 0 warnings; informational only) | PASS (not executed) |
| `scripts/windows-target-check.sh`: clippy `x86_64-pc-windows-gnu` (default, all features, release), link of all test binaries and both executables, Tauri shell clippy (`RUSTWARD_WINDOWS_CHECK_TAURI=1`), import-table scan | PASS — **compiled on Linux, not a native build, nothing executed** |
| Defects found by it: D-11-1, D-11-2 (Windows-only `clippy -D warnings` failures) | Fixed |
| `native_windows.rs` (5), named pipes, SCM, Event Log, WebView2, MSI | **NOT RUN** |

Phase 10 run (kept for history): **Phase 10** (read-only policy inspection, installed-device assessment, readiness UI, mock policy backend). After Phase 10: **270 workspace + 2 release-mode + 4 src-tauri = 276 Rust; 43 Vitest + 16 Vitest integration (real backend) = 59 — PASS, 0 failed, 0 ignored.** All 17 Linux-feasible checks of `scripts/verify-all.sh` PASS (final run after the Step 4 commit's changes). The 5 tests in `rustward-windows/tests/native_windows.rs` compile only on Windows: **NOT RUN** (type-checked on Linux by temporarily enabling the file under `host-typecheck`).

Phase 10 regressions found and fixed during Step 4 (both intermittent, both now repeated 30× / 6× without a failure):

- `rustward-storage` `concurrent_first_opens_of_a_new_database_serialise_cleanly` failed about 1 run in 5 with `database is locked`. Cause: `PRAGMA journal_mode=WAL` on a brand-new file returns `SQLITE_BUSY` without calling the busy handler while another connection opens the same file. Fix: bounded retry (100 × 50 ms) for that statement only (`enable_wal`).
- Vitest integration: an unhandled `SyntaxError` when `close()` killed the backend mid-reply and readline flushed a truncated line. Fix (test harness only): ignore output after close; reject an unparseable reply instead of throwing.

Phase 9B run (kept for history): Baseline re-verified first from a clean worktree of `056923b`: 206 + 2 + 4 = **212 Rust**, **39 Vitest** — PASS. After Phase 9B: **241 workspace + 2 release-mode + 4 src-tauri = 247 Rust; 40 Vitest + 13 Vitest integration (real backend) = 53 — PASS, 0 failed, 0 ignored.** All 17 Linux-feasible checks of `scripts/verify-all.sh` PASS.

Phase 9A run (kept for history): Baseline re-verified first from a clean worktree of `4909958`: 181 workspace Rust tests + 2 release-mode + 4 src-tauri = **187 Rust**, **38 Vitest** — PASS, matching the earlier report. After Phase 9A: **206 + 2 + 4 = 212 Rust, 39 Vitest — PASS, 0 failed, 0 ignored.**

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
| `rustward-windows` unit (**Phase 10: registry value decoding (`regdecode`): DWORD, SZ, EXPAND_SZ (never expanded), MULTI_SZ; malformed and other types reported, not interpreted; missing terminator and odd byte counts tolerated; the policy reader uses only `RegOpenKeyExW`/`RegEnumValueW`/`RegEnumKeyExW`/`RegGetValueW`/`RegCloseKey` with `KEY_READ \| KEY_WOW64_64KEY`;** property decoding, enumeration engine with failure injection, snapshot assembly, read-only inventory API allowlist, crate-wide forbidden-API scan, SCM control decisions and status fields, device-change decoding, Event Log mapping, **MESSAGETABLE generator resolves every event ID and nothing else**) | 30 | PASS |
| `rustward-windows` `tests/native_windows.rs` (Windows only: live enumeration, non-present superset, handle leak, internal-disk exclusion, **Phase 10: policy capture read-only and repeatable**) | 5 | **NOT RUN** (Linux) |
| `rustward-enforcement` unit (Phase 9A cases, plus **Phase 9B `policy_state`: plan values well-formed, clean-machine forward + exact rollback, existing lists collide until merged and are then preserved (idempotent), hazardous existing policy (DenyUnspecified, retroactive, deny-ID and deny-instance overlaps; removable-devices not a conflict), invalid data is a conflict, suspend/resume round trip, staleness on new/removed/unknown disks, OS build and policy version; gates `existing_policy_compatible` and `plan_current`**; **Phase 10: snapshot JSON round trip; `policy_eval` layer order (instance > device > class), prevent wins within a layer, unlayered prevent beats allow, DenyUnspecified catches everything not described, disabled lists ignored, compatible-ID match; `policy_inspect` documented/unresolved/unrecognised labels, layering by build/UBR, empty machine reported as no policy, conflicts and plan presence; `installed_assessment` installed denied brands stay accessible and get manual remediation, not-installed (problem 28) denied devices would be prevented, allowed brands incl. UASP and unseen models, internal disks never remediated and peripherals ignored, sanitized reports hide serials, existing policy can turn the plan into a hazard**) | 40 | PASS |
| `rustward-enforcement` `tests/mock_policy_backend.rs` (**Phase 10, in-memory registry with fault injection — test-only, no real writes: interrupted application detected as partial and rolled back exactly at every stop point × 4 baselines; interrupted rollback resumable; unrelated values never touched; plan approved before a policy change is stale and activation stays refused; authorization failures keep the admin gate shut; "values present" is never verified protection; dropped/overwritten values reported; installed assessment reads only and covers storage only**) | 8 | PASS |
| `rustward-inventory` unit (**Phase 10: `policy-inspect` reads a capture file and reports without writing; `assess-installed` writes a reviewable manual report**) | 6 | PASS |
| `rustward-storage` unit + `tests/store.rs` (Phase 9A cases, plus **mirror outage reported as pending and recovered in order, mirror cursor survives restart and back-fills, bounded backlog with recorded gap, newest-event removal detected as truncation/missing, retention not mistaken for truncation, checkpoint reflects chain damage, external checkpoint reveals rewrite/truncation/resequencing, concurrent first opens serialise (F-19, fails without the fix)**) | 2 + 27 | PASS |
| `rustward-ipc` unit + `tests/rpc_mock.rs` (Phase 9A cases; **status-pipe DACL mask excludes create-instance/WRITE_DAC/WRITE_OWNER/write-attributes; service SID derivation matches NT SERVICE\\TrustedInstaller; LocalSystem SDDL builders equal the shipped constants; virtual-account descriptors keep users out; only SYSTEM and the service SID are trusted owners**) | 13 + 12 | PASS |
| `rustward-ipc` `tests/contract.rs` (golden request contract — **26** request types (Phase 10: `GetEnforcementReadiness`, read-only), round-trip, naming) | 3 | PASS |
| `rustward-ipc` `tests/server_pool.rs` (**F-13/F-14: idle clients do not block others, busy refusal and slot reuse, idle timeout, prompt shutdown with idle clients, in-flight request answered at shutdown, abandoned threads reported, accept-error backoff and count**) | 7 | PASS |
| `rustward-app` unit + `tests/app_flows.rs` (CRUD persists across restart, conflict codes, synthetic simulation, arrival/removal events, degraded health + recovery, export/backup/retention, corrupt policy fails closed, dashboard never claims protection, workstation-ID edit, **two-step restore never rolls back versions/history/audit, prepared restores single-use + bound to the admin + expire, foreign/altered/traversal restores refused and audited**, authorization-failure audit with rate limit, Event Log observer + diagnostics, **truncated chain reported and checkpointed, mirror pending/skipped in diagnostics**; **Phase 10: enforcement readiness is read-only, reports the fixture inspection, conflicts, gates and the sanitized assessment, and never claims enforcement**) | 2 + 21 | PASS |
| `rustward-app` `tests/ipc_security.rs` — **all 15 privileged requests × 5 refused caller kinds through `rpc::process` with no state change and every refusal audited; read-only requests for standard users change nothing; replayed mutations rejected (exactly one of four captured requests applies); interrupted connection applies a change at most once; duplicate unversioned admin requests harmless; malformed / wrong-version envelopes refused; unidentified callers refused and audited** | 7 | PASS |
| `rustward-service` unit (Phase 9A cases, plus **audit checkpoint on first tick then daily, pool limits fit the SCM wait hint and service names agree, pooled service serves concurrent callers and stops cleanly, incomplete shutdowns audited, `verify-checkpoint` arguments/outcomes and read-only check of a real database, desktop CSP allows no remote origin**) | 21 | PASS |
| `rustward-ui-bridge` unit (debug + `dev-backend`) | 2 | PASS |
| **Rust workspace total** (`cargo test --workspace --all-features`) | **270** | **PASS** |
| `rustward-ui-bridge` in **release** mode with `dev-backend` on: always selects the service | 2 | PASS |
| `src-tauri` Tauri mock-runtime IPC tests: `ipc_call` through the real Tauri IPC + capability ACL into the dev backend; stale version → `conflict`; malformed requests rejected; other commands rejected | 4 | PASS |
| Vitest unit (43; +3 in Phase 10: **readiness page shows the real status, keeps activation disabled and never claims blocking; explains conflicts, unresolved names, prerequisites and manual remediation in Turkish; states plainly when the policy cannot be read**; +1 in Phase 9B: **service unavailable never read as protection**): i18n completeness/placeholders/forbidden "blocked" claims, IPC contract vs Rust golden file, API client error mapping, page behaviour (banner, explanation, manufacturer CRUD + client validation + conflict, blocked wording, audit filter/export, diagnostics simulation and Event Log status, settings/theme/authorization error, workstation-ID validation and save, **two-step restore: preview (hash, changes) before apply, cancel changes nothing, missing backup file badge**), in-app notifier (no notice for pre-existing denials, one honest notice per new denial, dismiss, allows ignored, no polling when disabled) | 43 | PASS |

| **Vitest integration** (`vitest.integration.config.ts`, 16; +3 in Phase 10: **readiness against the real backend with the synthetic policy capture (merged around the existing admin entry, unrecognised value shown, activation disabled, manual remediation only); off Windows the policy is plainly unreadable; a standard user can read it and the administrator gate is not met**): the real React app against the **real backend** (AppService + SQLite file, the service's validation and authorization) through the dev-only `stdio_backend` harness — dashboard banner and simulated labels, device list + explanation, brand add/allow as new versions with history, real version conflict, blocked list not enforced, audit records + export, diagnostics chain intact + Event Log not attached + simulation, backup → two-step restore as a new version with growing audit log, workstation rename, settings persisted, **standard user: dashboard readable, backup and brand changes refused in Turkish with no state change** | 16 | PASS |

Reproduce the integration run: `cargo build -p rustward-ui-bridge --features dev-backend --example stdio_backend`, then
`cd apps/rustward-desktop && RUSTWARD_STDIO_BACKEND=$PWD/../../target/debug/examples/stdio_backend npx vitest run --config vitest.integration.config.ts`.

## 3. Static checks — PASS

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` (deny unwrap/expect/panic/undocumented unsafe) | PASS |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` (includes `host-typecheck`: SetupAPI, named pipes, pipe servers, service pipe client type-checked against windows-sys 0.61.2) | PASS |
| `tsc -b --noEmit` (strict, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) | PASS |
| `vite build` + `scripts/check-offline-assets.mjs` — no external URL except XML namespace strings and React's error-doc text, no non-local reference, no fetch/XHR/WebSocket/EventSource/sendBeacon (module-preload polyfill disabled) | PASS |
| `tsc -p tsconfig.integration.json --noEmit` (integration tests with Node types; app code stays without Node types) | PASS |
| `npm audit --omit=dev` | 0 vulnerabilities (dev-only test runner advisories: L-30) |
| `src-tauri`: `cargo fmt --check`, `cargo clippy --all-targets -D warnings` (Linux/webkit2gtk) | PASS |
| SCM host, `CM_Register_Notification` subscription, Event Log writer, service entry (`scm.rs`, incl. start-failure entry), pipe owner check and per-request identification — compiled with `host-typecheck` in the all-features clippy run | PASS (type-check only; never executed) |
| `cargo deny check` (licences, advisories, sources, bans) for `Cargo.lock` and `src-tauri/Cargo.lock`, target `x86_64-pc-windows-msvc` | PASS (src-tauri: 10 duplicate-version warnings) |
| `build.rs` generates the message table on Linux (embedding needs Windows `rc.exe`: NOT RUN) | PASS (generation only) |

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
| IPC | Named-pipe DACLs and owner, client owner check (impostor test C12), `PIPE_REJECT_REMOTE_CLIENTS`, per-request impersonation + elevation check, session-0 check, standard-user denial (T-22) | DEFERRED |
| Desktop app | Tauri on WebView2, CSP in WebView2, release build without dev backend, elevation UX | DEFERRED |
| Packaging | MSI build, WiX service fragment, embedded message table (`rc.exe`), event source registration and Event Viewer formatting, offline WebView2 install, install/repair/uninstall, offline install (T-25) | DEFERRED |
| Enforcement | Any Device Installation Restriction validation; every physical USB test T-01..T-30 | DEFERRED |
| Hardware identity | Hardware-Encrypted USB inspection (T-04..T-07) | DEFERRED — blocking for Hardware-Encrypted USB |

Stage-by-stage procedure for every DEFERRED item: [`WINDOWS-VM-ACCEPTANCE.md`](WINDOWS-VM-ACCEPTANCE.md).
