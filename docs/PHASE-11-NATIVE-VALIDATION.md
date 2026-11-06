# Phase 11: Native Windows Build and Integration Validation

Date: 2026-11-06. Start HEAD: `81a4e13`.

> **No native Windows validation was executed in Phase 11.** This session had no Windows
> execution environment and no authorized disposable Windows 10 Pro VM. RustWard is **not
> production-ready** and **does not block any USB device**. `ACTIVATION_ENABLED = false`.
> Stage F was not attempted.

## 1. Environment actually used

| Item | Fact |
|---|---|
| Build/verification workspace | Ubuntu 24.04 cloud container, rustc 1.97.0 (`2d8144b`), Node 22 |
| Linked computer | The developer's Windows PC (`C:\Users\Yunus\Desktop\RustWard`). It is reachable only through an **Ubuntu 22.04 VM shell** with the repository folder mounted. There is no `cmd.exe`, PowerShell, MSVC or Windows binary execution. It was used only to sync the git repository. |
| Developer PC as a test machine | Not used, and not allowed for Stages B–E: it is neither the disposable VM nor a production workstation. RustWard was never installed or run on it. |
| Disposable Windows 10 Pro VM | **Not provided** |
| Physical test hardware | **Not provided** |

## 2. What was done instead

1. **Windows-target compilation on Linux** (`scripts/windows-target-check.sh`). Labelled everywhere as **not a native build**.
   - Target `x86_64-pc-windows-gnu`, MinGW-w64 linker. std is built from the rustc 1.97.0 library sources (`-Zbuild-std`), because the prebuilt Windows std could not be downloaded.
   - All `cfg(windows)` code is compiled against the real `windows-sys` bindings: SetupAPI, the policy reader, named pipes, the SCM host, Event Log, and `native_windows.rs`.
   - Executables and all test binaries are linked. Nothing is run.
   - The import tables of `rustward-service.exe` and `rustward-inventory.exe` are then scanned.
   - The service's `build.rs` refuses cross-compiling by design, because a release exe must embed the MESSAGETABLE with `rc.exe`. The script therefore works on a copy of the tree and disables the embedding only in that copy. The repository is unchanged, and the executables produced are **check artifacts that must never be shipped** (R-11-2).
2. **Two real defects** found by that check and fixed (§4).
3. **Packaging review** against the tauri-bundler 2.10.4 template (shipped with `@tauri-apps/cli` 2.12.4) and the WiX 3 compiler source (§6).
4. **Reviewed PowerShell scripts** for Stages A–E (§7).
   - Parsed with the PowerShell 7.4.22 parser and analysed with PSScriptAnalyzer 1.25.0: 0 errors, 0 warnings.
   - Guarded by a Rust test (`crates/rustward-service/tests/acceptance_scripts.rs`).
   - **Not executed on Windows.**

## 3. Results (PASS / FAIL / BLOCKED / NOT RUN)

| # | Item | Result | Note |
|---|---|---|---|
| 1 | Native Windows environment | **BLOCKED** | No Windows execution and no disposable VM in this session |
| 2 | Native MSVC build (Stage A: fmt, check, clippy, tests, native tests, release build, `rc.exe` resource) | **NOT RUN** | `scripts\run-native-validation.ps1` is prepared |
| 2a | Windows-target compile on Linux: clippy default + all features, release, link of all test binaries and executables | **PASS** (not native) | 0 errors, 0 warnings, after the two fixes in §4 |
| 2b | Tauri shell compile for the Windows target on Linux (clippy, WebView2 code compiled) | **PASS** (not native) | Not run; WebView2 untested |
| 2c | Import tables of the service and inventory executables | **PASS** (static) | Registry: only `RegOpenKeyExW`, `RegEnumValueW`, `RegEnumKeyExW`, `RegGetValueW`, `RegCloseKey`. No device, driver or service-configuration API. `CreateFileW` comes from std/SQLite (files). The source test still forbids it in `rustward-windows`. |
| 3 | Windows-specific tests (`native_windows.rs`, 5 tests) | **NOT RUN** | Compiled and linked for the Windows target |
| 4 | Desktop application on WebView2 (Stage B items of the brief: startup, Turkish UI, SQLite, manufacturers, simulation, audit, backup/restore, admin authorization, restart) | **BLOCKED** | Needs the VM. Linux results: TEST-RESULTS.md |
| 5 | Windows Service / SCM (start, stop, restart, recovery, privileges) | **BLOCKED** | Needs the VM; checklist C1–C6 |
| 6 | Named-pipe IPC authentication and authorization | **BLOCKED** | Needs the VM; checklist C7–C18 |
| 7 | Event Log source, messages, mirroring, failure events, offline recovery, device notifications | **BLOCKED** | Needs the VM; checklist C19–C27 |
| 8 | Read-only policy inspection on a real registry | **BLOCKED** | Needs the VM; checklist E1–E10 |
| 9 | MSI build | **NOT RUN** | Needs Windows (WiX, `rc.exe`) and network for WebView2 |
| 9a | MSI installation / repair / uninstall | **BLOCKED** | Needs the VM; checklist D1–D10 |
| 10 | Stage F | **NOT RUN** (excluded) | See §9 |

## 4. Defects found and fixed

Both would have made **Stage A2 fail** on native Windows (`clippy -D warnings`). Linux never showed them because the code involved is compiled differently there.

| ID | Defect | Fix |
|---|---|---|
| D-11-1 | `rustward-ui-bridge` test module: on a Windows debug build without `dev-backend`, no test is compiled, so `use super::*` is unused. | Platform-independent test `service_backend_name_is_stable` |
| D-11-2 | `rustward-service::runtime`: `wake_refreshes`, `stop_handle` and `app` are used only by tests. The module's `allow(dead_code)` applies only off Windows, so on Windows these were dead code. | The three methods are `#[cfg(test)]`. The SCM host already passes its flag through `with_stop_handle`. |

## 5. Hardware safety review (before any later enforcement experiment)

| Topic | Current design | Assessment |
|---|---|---|
| Boot-critical internal disks | DiskDrive class prevent, **never retroactive**. Every baseline internal disk gets an `AllowInstanceIDs` entry (highest layer). The `system_disks_protected` gate requires it. A plan goes stale on any internal-disk change. Rollback is exact. | Sound as a model; unverified on Windows |
| **R-11-1** Boot disk re-enumeration | *New in Phase 11.* An internal disk can get a **new instance ID without a disk being added**: AHCI ↔ RAID/Intel VMD controller mode switch, a different SATA port, a storage driver stack change (vendor NVMe driver ↔ `stornvme`), cloning to a new disk, or a VM controller type change. The new devnode is not in the allow list and falls under the DiskDrive prevent. Whether Windows applies install restrictions to the boot disk during boot (risk: unbootable system) is **unverified**. | Stage F prerequisite: (a) a documented "suspend before any firmware/controller/disk change" procedure for the five workstations; (b) a deliberate re-enumeration test on the VM (change the virtual disk controller) with WinRE recovery rehearsed (RECOVERY-PLAN.md). |
| Already-installed storage | Install-time rules are not retroactive. Assessment and manual remediation only (Phase 10). | Unchanged: L-05 |
| Brand recognition | Vendor-level hardware IDs and INQUIRY vendor strings. Generic bridge chips, OEM rebrands, and models that report a different vendor are not recognised as the brand. | **Not reliable for all commercial models.** Each model must be inspected (Stage B). |
| Authenticity | USB VID and SCSI INQUIRY vendor strings are **self-reported by the device and not cryptographically authenticated**. A device can claim any vendor (the fixture's spoof case shows SanDisk). | By design of the Windows mechanism; L-01/L-02 |
| TÜBİTAK SIR II | **Unresolved.** The catalog has no identifiers, and none may be added without lab evidence. Both locked and unlocked states must be captured in Stage B: an encrypted drive may present a different device or class (e.g. a CD-ROM-class unlock volume, then a disk LUN) before and after unlocking. The unlock prompt must keep working (B6). | Blocks a TÜBİTAK allow rule; never guess |

## 6. Packaging review (static; MSI not built)

| Item | Finding | Status |
|---|---|---|
| Offline WebView2 | `webviewInstallMode = offlineInstaller`, silent. The MSI embeds the standalone runtime installer. The **build** machine needs network access (L-18); the target machines do not. | As documented; unverified |
| Service registration | WiX `ServiceInstall`: LocalSystem, auto start, `Arguments="service"`. `util:ServiceConfig` restart ×3 / 5 s / reset 1 day. `ServiceControl` start on install, stop on install/uninstall, remove on uninstall. | Unverified (C1, C2) |
| Event Log source | `util:EventSource` Application/RustWard. `EventMessageFile` = the service exe (embedded MESSAGETABLE). Errors, warnings and informationals give TypesSupported 7. Removed with the component. | Unverified (C19, C20) |
| Data permissions | `%ProgramData%\RustWard`, `PermissionEx Sddl="D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"` → `MsiLockPermissionsEx`. **R-11-3:** the tauri-bundler 2.10.4 template declares `InstallerVersion="450"`, but `MsiLockPermissionsEx` is a Windows Installer 5.0 table. The WiX 3 compiler accepts it without a check. Windows 10 ships Windows Installer 5.0, so the table is expected to apply, but this is **unverified**. | Verify in C3 (the Stage C script records the SDDL) |
| Database initialization | Created by the service on first start (schema v2, F-19 fix). | Unverified (C4) |
| Uninstall | Service and event source removed. The data folder component is `Permanent="yes"`, so audit records are kept. | Unverified (D7, D8) |
| Offline runtime dependencies | SQLite bundled (static). The frontend uses no CDN (offline-asset check). WebView2 is the only runtime dependency, carried by the MSI. MinGW cross-check executables are not release builds. | Linux checks PASS; native unverified |

## 7. Scripts for the project owner (prepared, NOT executed)

All scripts write evidence to `C:\rw-evidence\<stage>\<timestamp>\`. They record exit codes; **an exit code is not a PASS**. The tester decides each item with `WINDOWS-ACCEPTANCE-CHECKLIST.md`. The one exception is E10, an exact before/after file comparison.

| Order | Script | Machine | Changes the machine? | Checklist |
|---|---|---|---|---|
| 1 | `scripts\run-native-validation.ps1 [-TauriBuild]` | Build machine | No (build output only; `-TauriBuild` needs network) | A1–A11, B1–B2 |
| 2 | `scripts\build-release.ps1 -WithService` | Connected build machine | No | A10 |
| 3 | `scripts\windows\Invoke-StageB-DeviceInspection.ps1 -BinDir … -PhysicalTestMachine` | Test hardware / VM | No | B1–B9 |
| 4 | `scripts\windows\Invoke-AcceptanceMsi.ps1 -Action Install -Msi … -DisposableVm` | **Disposable VM only** | **Yes**: installs RustWard after a typed confirmation, and refuses on a non-VM or an MSI hash mismatch | D1, D4 |
| 5 | `scripts\windows\Invoke-StageC-ServiceInspection.ps1 -DisposableVm` | Disposable VM | No (queries only) | C1–C4, C7, C15, C19–C21, C24 |
| 6 | Manual items (authorization matrix, impostor pipe, stop/kill, Event Log outage) | Disposable VM | As described per item | C5–C27 |
| 7 | `scripts\windows\Invoke-StageE-PolicyInspection.ps1 -BinDir … -DisposableVm` | Disposable VM / test hardware | No; it compares the policy key before and after | E1–E10 |
| 8 | `Invoke-AcceptanceMsi.ps1 -Action Repair` / `Uninstall` | Disposable VM | **Yes**, with typed confirmation | D6–D8 |

Automated guarantees (`acceptance_scripts.rs`, 5 tests):
- No script contains registry-write, policy, device, driver, disk, ACL, BitLocker or service-control commands.
- Only `Invoke-AcceptanceMsi.ps1` runs `msiexec`. It checks the machine and the confirmation before writing anything, and it checks the hash.
- Every stage script calls the machine guard and states that it was never executed.
- The Stage E script exports the policy key before and after the RustWard tools run.

## 8. Remaining real enforcement blockers

1. No native execution of anything (Stages A–E).
2. No activation path exists in the code (`ACTIVATION_ENABLED = false`, no registry write path). This is by design until Stage F is authorized.
3. Unresolved: the list-entry layout, the `*Retroactive` names, the UBR source (Phase 10).
4. TÜBİTAK SIR II descriptors are unknown (locked and unlocked).
5. R-11-1: the boot-disk re-enumeration behaviour is unverified.
6. F-16 (LocalSystem vs. the virtual service account) is undecided until C15.
7. No read/write-denial evidence exists, so `VerifiedProtected` is impossible.

## 9. Stage F readiness

**Not ready.** Stage F may be requested only after:
- Stages A–E PASS on the VM and on physical hardware identical to the five workstations;
- E5/E6 are resolved;
- SIR II is inspected;
- R-11-1 is tested and the suspend procedure is written;
- F-16 is decided;
- written authorization names the machine, the date and the plan fingerprint.
