# ARGON 4 — Automated Test, Static Analysis, Benchmark, and Packaging Results

**Workspace**: Isolated `RustWard2` (`experiment/argon4-vm-enforcement`, branched from `9ba61b5`)
**Platform**: Windows x64 (`x86_64-pc-windows-msvc`, `rustc 1.92.0`, Node.js `24.17.0`, WebView2 `157.0.4341.42`)
**Host Safety**: Zero Windows policies, registry keys, services, drivers, or MSI installations modified on the host machine.

---

## 1. Automated Verification Summary (`450 / 450` Passed)

| Suite | Command | Passed | Failed | Ignored | Verification Category |
| --- | --- | ---: | ---: | ---: | --- |
| Rust workspace unit & integration tests (9 crates) | `cargo test --workspace` | 342 | 0 | 0 | `AUTOMATED TEST VERIFIED` + `NATIVE WINDOWS VERIFIED` |
| Tauri 2 shell IPC boundary tests (`src-tauri`) | `cargo test --manifest-path apps/rustward-desktop/src-tauri/Cargo.toml` | 4 | 0 | 0 | `AUTOMATED TEST VERIFIED` |
| Frontend Vitest unit & localization suites (9 files) | `npm test -- --run` | 87 | 0 | 0 | `AUTOMATED TEST VERIFIED` |
| Real-backend stdio + SQLite + Windows registry integration suite | `npx vitest -c vitest.integration.config.ts run` | 17 | 0 | 0 | `AUTOMATED TEST VERIFIED` + `NATIVE WINDOWS VERIFIED` |
| **Total Automated Tests** | — | **450** | **0** | **0** | **`AUTOMATED TEST VERIFIED`** |

### Static Analysis & Formatting Gates

| Gate | Command | Result |
| --- | --- | --- |
| Rust formatting (workspace) | `cargo fmt --all -- --check` | `PASS` (exit code 0) |
| Rust formatting (`src-tauri`) | `cargo fmt --manifest-path apps/rustward-desktop/src-tauri/Cargo.toml -- --check` | `PASS` (exit code 0) |
| Rust Clippy lints (workspace, all targets) | `cargo clippy --workspace --all-targets -- -D warnings` | `PASS` (0 warnings, exit code 0) |
| Rust Clippy lints (`src-tauri`, all targets) | `cargo clippy --manifest-path apps/rustward-desktop/src-tauri/Cargo.toml --all-targets -- -D warnings` | `PASS` (0 warnings, exit code 0) |
| TypeScript strict check | `npx tsc --noEmit` | `PASS` (0 errors, exit code 0) |
| Production Vite bundle | `npm run build` | `PASS` (exit code 0) |

---

## 2. New Regression & Native Windows Tests Added in Argon 4

1. **`rustward-core` / `rustward-app` (`tests/app_flows.rs`)**:
   - `denylist_matched_brand_conflicting_vid_and_deduplicated_warnings`: Verifies explicit denylist populates `DeviceView::matched_brand`, conflicting `INQUIRY` vendor (`SanDisk`) vs foreign catalog USB `VID` (`0951` Kingston) fails closed with `DecisionReason::ConflictingIdentifiers` and localized `"SİMÜLE RET: Kimlik çelişkisi: ..."`, and `combined_warnings` emits `"brand_not_enforceable"` for `"tubitak"` once without duplication.
   - `live_policy_source_reads_windows_registry_read_only_without_mutating_anything` (`#[cfg(windows)]`): Verifies read-only inspection of `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` via `LivePolicySource`.
2. **`rustward-windows` (`src/engine.rs`)**:
   - `reads_property_larger_than_stack_probe_via_heap_growth`: Verifies `SetupDiGetDevicePropertyW` falls back from the 512-byte stack probe to exact-size heap allocation when a property exceeds 512 bytes.
3. **`rustward-ipc` (`src/pipe.rs`, `#[cfg(windows)]`)**:
   - `windows_named_pipe_impersonation_squatting_and_roundtrip_latency`: Exercises real Win32 named-pipe server/client round-trips, caller token SID extraction, first-instance squatting rejection (`FILE_FLAG_FIRST_PIPE_INSTANCE`), and sub-5ms frame latency.
   - `production_connect_rejects_non_service_pipe_impostor`: Confirms `NamedPipeChannel::connect` rejects a pipe server whose PID is not owned by the SCM `RustWardService` (`GetNamedPipeServerProcessId` + `QueryServiceStatusEx` PID cross-check).
4. **Frontend (`localized.test.tsx`, `realStatus.test.tsx`, `realBackend.integration.test.tsx`)**:
   - Bug A `retroactive: false` vs `retroactive: true` round-trip confirmation and client-side mismatch safety halt (`retroactive-mismatch-error` disables `"Uygulamayı doğrula"`).
   - Bug C & Bug D four-section `BlockedPage` verification: active denial in `blocked-real`, rolled-back denial moved to `blocked-history` (`GERİ ALMA TAMAMLANDI`) and absent from `blocked-real`, simulated denials in `blocked-sim` (`SIMÜLASYON`), and unverified/conflicting IDs in `blocked-unknown`.
   - `DevicesPage` `BOT (USBSTOR)` / `UASP (SCSI)` transport labels and live SetupAPI problem-code / driver-installed badges.
   - Native Windows integration test (`reads live Windows DeviceInstall\Restrictions read-only on Windows without mutating anything`) + deterministic Windows temp directory cleanup (`0` `EBUSY` / `EPIPE` errors).

---

## 3. Native Windows `--release` Performance Benchmarks (Before vs After)

Measured via `cargo test --release -p rustward-app --test perf_benchmarks` and `target\release\rustward-inventory.exe`:

| Benchmark | Workload | Baseline (`9ba61b5`) | Argon 4 (`experiment/argon4-vm-enforcement`) | Improvement |
| --- | --- | ---: | ---: | --- |
| `PERF_LIVE_SETUPAPI` (`IncludeNonPresent`) | Live Win32 SetupAPI enumeration (453 devices, 5-run mean / min) | `220.23 ms` (min `217.51 ms`) | `114.36 ms` (min `112.05 ms`) | **1.93× faster (`-48.1%`)** |
| `PERF_LIVE_SETUPAPI` (`PresentOnly`) | Live Win32 SetupAPI enumeration (205 devices, 5-run mean / min) | `94.49 ms` (min `93.21 ms`) | `46.23 ms` (min `45.45 ms`) | **2.04× faster (`-51.1%`)** |
| `rustward-inventory.exe` CLI | Cold process `scan --include-non-present --sanitize --json` (median of 5) | `249.1 ms` (`242.0–272.1 ms`) | `158.4 ms` (`145.7–165.7 ms`) | **1.57× faster (`-36.4%`)** |
| `PERF_COMPOSITE_REMOVAL_1500` | Removing 15-node composite USB device from 1,500-device snapshot | `11.06 ms` (`11,064 µs`) | `3.26 ms` (`3,258 µs`) | **3.40× faster (`-70.6%`)** |
| `PERF_CONCURRENT_IPC` (wall clock) | 4 concurrent IPC requests while 3 capture policy (`25 ms` simulated registry read) | `86.42 ms` | `35.54 ms` | **2.43× faster (`-58.9%`)** |
| `PERF_CONCURRENT_IPC` (`list_devices` latency) | Unrelated `list_devices` latency during concurrent policy captures | `83.90 ms` | `0.22 ms` | **381× faster (`-99.7%`)** |
| `PERF_NAMED_PIPE_20_CALLS` | 20 sequential RPC calls over real Win32 named pipe | `215.99–307.42 ms` (`10.8–15.4 ms/call`) | `28.83 ms` (`1.44 ms/call`) | **7.5×–10.7× faster** |

---

## 4. Isolated Native Windows Release Artifacts & MSI Verification

Built via `scripts\windows\Build-RustWard.ps1` inside `RustWard2\dist\` (**not installed on host**):

| Artifact | Path (relative to repo) | Subsystem / PE Check | Size (bytes) | SHA-256 |
| --- | --- | --- | ---: | --- |
| Production Desktop Client | `dist/RustWard.exe` | PE32+ x64 GUI (`OK`, no `setupapi.dll` / no `dev-backend`) | `4,158,464` | `2a80ffd49fe0cb54199d89c4cb564ca00f1464512e6898f16981e265c27a331d` |
| Isolated Dev Preview Client | `dist/RustWard-Onizleme.exe` | PE32+ x64 GUI (`OK`, `debug_assertions + dev-backend`) | `21,952,000` | `a254aee88790a74cb44834cb93a4233591c3fcd8cd24a26d3b4e9187176e978e` |
| Windows Service | `dist/service/rustward-service.exe` | PE32+ x64 Console (`OK`, `RT_MESSAGETABLE` type 11 embedded = `True`) | `3,436,032` | `7ee9f2ea25e6b628a6e0651f751e3169d62cc9769a0e5d3d9d5dd828ef687308` |
| Read-Only Inventory CLI | `dist/service/rustward-inventory.exe` | PE32+ x64 Console (`OK`, read-only SetupAPI/WinReg imports only) | `794,112` | `93932949a5a2603c9015342c4b9f530d55faa6b9a700d3b1017b7a8b65fe2b34` |
| Offline Turkish MSI Installer | `dist/installer/RustWard_0.1.0_x64_tr-TR.msi` | Read-only MSI COM check (`OK`, offline WebView2 embedded) | `219,189,248` | `5e7d0d70a3e720c336e53cc585bcd7ec8729e53b12b654d246f2c0679bf06192` |

### Read-Only MSI Table Inspection (`OpenDatabase(..., 0)`)

- `ServiceInstall`: `RustWardService` running as `LocalSystem` with argument `service` (`True`)
- `File`: `rustward-service.exe` (`True`) + desktop client executable (`True`)
- `ServiceControl`: `RustWardService` start/stop/remove lifecycle (`True`)
- `Registry`: `SYSTEM\CurrentControlSet\Services\EventLog\Application\RustWard` (`True`)
- `MsiLockPermissionsEx`: `%ProgramData%\RustWard` ACL `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (`SYSTEM` + `Administrators` full control, inheritance disabled)
- Host service collision check: `RustWardService` not installed on host (`clean`).

---

## 5. Pending Live VM & Physical Hardware Gates

| Stage | Scope | Status |
| --- | --- | --- |
| Stage A | Isolated Windows 10 VM (`Windows 10 x64.vmx`) snapshot + MSI install + Kingston (`0951:1666`) specific block & rollback re-verification | `USER ACCEPTANCE PENDING` (awaiting explicit user approval to boot/mutate VM) |
| Stage B | VM default-deny layered `DiskDrive` (`{4d36e967-e325-11ce-bfc1-08002be10318}`) profile + internal NVMe (`PCI\VEN_15AD&DEV_07F0`) + peripheral safety | `USER ACCEPTANCE PENDING` (gated on Stage A pass + explicit user approval) |
| Stage C | Real physical SanDisk USB storage allow verification under active Stage B default-deny policy | `BLOCKED` (no verified physical SanDisk `0781` hardware attached yet; `346D:5678` `VendorC` is intentionally denied) |
| Stage D | Genuine Hardware-Encrypted USB (Unverified Profile) pre-unlock & post-PIN hardware capture and allow verification | `BLOCKED` (no genuine Hardware-Encrypted USB hardware inspected yet; identifiers never invented) |
