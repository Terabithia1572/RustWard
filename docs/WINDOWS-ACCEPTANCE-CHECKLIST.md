# Windows Acceptance Checklist (after Phase 9B)

This is the tickable list for the controlled Windows 10 Pro validation stage. Procedures,
preparation and the Hyper-V limits are in [WINDOWS-VM-ACCEPTANCE.md](WINDOWS-VM-ACCEPTANCE.md).

**Rules:**

- Record every item as PASS, FAIL or NOT RUN, with the evidence file in `C:\rw-evidence\<stage>\`.
- Nothing may be reported as passed without evidence.
- **Stage F is excluded.** It needs a separate written authorization and a build that has an activation path. This build has none.

Build under test: commit ____ · MSI SHA-256 ____ · VM checkpoint ____ · Date ____ · Tester ____

## Stage A: native build and static checks

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| A1 | `scripts\run-native-validation.ps1` | all steps exit 0 | | |
| A2 | `cargo clippy --workspace --all-targets --locked -- -D warnings` (MSVC) | clean; the real pipe, SCM, SetupAPI and Event Log code compiles | | |
| A3 | `cargo test --workspace --locked` | same counts as TEST-RESULTS.md, plus the native tests | | |
| A4 | `cargo build --release -p rustward-service` | `build.rs` embeds the MESSAGETABLE (needs `rc.exe` from the Windows SDK) | | |
| A5 | `dumpbin /headers rustward-service.exe` | `.rsrc` present; MESSAGETABLE type 11, ID 1 | | |
| A6 | `npm ci`; `npx tsc -b --noEmit`; `npx vitest run` | PASS (40) | | |
| A7 | `cargo build -p rustward-ui-bridge --features dev-backend --example stdio_backend`, then the integration Vitest run (see TEST-RESULTS.md) | PASS (13) on Windows | | |
| A8 | `npx vite build`; `node scripts\check-offline-assets.mjs` | "offline assets OK" | | |
| A9 | `cd src-tauri; cargo clippy …; cargo test` | PASS on WebView2 | | |
| A10 | `scripts\build-release.ps1 -WithService` (connected build machine) | MSI, exes, BUILD-INFO.txt, DEPENDENCY-INVENTORY.md, SHA256SUMS.txt | | |
| A11 | `cargo deny check` (both lockfiles) | advisories, bans, licenses and sources all ok | | |

## Stage B: application, SQLite, UI

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| B1 | `rustward-service console --db C:\rw-test\b.db --synthetic --iterations 3` | 3 iterations; schema v2 | | |
| B2 | Same, live inventory | completes; warnings only | | |
| B3 | Start two console instances on one new database at the same moment | both start (F-19) | | |
| B4 | MSI without service, run as `rwuser` | WebView2 UI loads; banner "Koruma henüz gerçek Windows ortamında doğrulanmadı."; service shown unavailable, never protected | | |
| B5 | Disconnect network, start app | no network attempt (Resource Monitor / firewall log) | | |

## Stage C: service, pipes, authorization

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| C1 | `sc.exe qc RustWardService` | auto start, LocalSystem, `"…\rustward-service.exe" service` | | |
| C2 | `sc.exe qfailure RustWardService` | restart ×3 after 5 s, reset after 1 day | | |
| C3 | `Get-Acl $env:ProgramData\RustWard` | protected; SYSTEM and Administrators only | | |
| C4 | Service RUNNING within 30 s; `rustward.db` created | yes | | |
| C5 | Stop/start ×3 | STOPPED within the 15 s wait hint; no `ipc_shutdown_incomplete` event | | |
| C6 | `taskkill /F` the service | SCM restarts it after about 5 s | | |
| C7 | AccessChk on both pipes | admin pipe: SY+BA, owner SYSTEM. Status pipe: AU has read + write-data only, **no** create-instance | | |
| C8 | `rwuser`: dashboard, devices, events | work | | |
| C9 | `rwuser`: add/remove brand, rename workstation, backup, restore | refused in Turkish; `authorization_failed` recorded | | |
| C10 | `rwadmin` unelevated: same as C9 | refused | | |
| C11 | `rwadmin` elevated: add/remove brand, rename, backup, two-step restore | succeed; versions only increase; `policy_restored` with a restore id | | |
| C12 | Service stopped; `rwuser` scheduled task serves `RustWard.Status.v1` | client refuses (owner / PID check) | | |
| C13 | Kill the UI during a policy edit | applied at most once; retry gets "conflict" | | |
| C14 | Uninstall | service and event source removed; data kept | | |
| C15 | Reinstall over the kept data | chain intact; history kept | | |
| C16 | **F-16 decision:** test install with `NT SERVICE\RustWardService` (variant, on a separate checkpoint) | inventory, notifications, Event Log and pipes work, or a documented failure; decision recorded | | |
| C17 | **F-18:** while the service runs, `rwuser` attempts `CreateNamedPipe("\\.\pipe\RustWard.Status.v1")` | ERROR_ACCESS_DENIED | | |
| C18 | **F-13:** 8 idle `rwuser` connections plus the UI | UI still served on the admin pipe; extra status connections refused; slots freed after 15 s | | |
| C19 | **F-14:** stop the service with an active idle connection | stops within about 3 s; threads joined | | |

## Stage D: Event Log and device notifications

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| D1 | `HKLM\…\EventLog\Application\RustWard` | EventMessageFile = service exe; TypesSupported 7 | | |
| D2 | Event Viewer entries | formatted text, no "description cannot be found" | | |
| D3 | IDs after Stage C | 1000, 1001, 1004, 3001, 4000, 5001, 5005, 5007, **5008 audit_checkpoint** | | |
| D4 | Unreadable or newer-schema database at start | Event 1008, service stops | | |
| D5 | Device plug/unplug | refresh within seconds | | |
| D6 | `rustward-service verify-checkpoint --head-id <id> --hash <prefix>`, values from a 5008 entry | "MATCH", exit 0 | | |
| D7 | Delete the newest events on a **copy** of the database (attacker simulation), rerun D6 on the copy | "MISSING" or "MISMATCH", exit 3; Diagnostics shows TRUNCATED/MISSING | | |
| D8 | Make the Event Log unavailable (stop the Windows Event Log service briefly on the test VM), create events, restore it | pending > 0 in Diagnostics, then delivered in order; no gap unless more than 1000 (then Event 1009) | | |
| D9 | `wevtutil epl Application app.evtx` | saved | | |

## Stage E: read-only real USB inventory

Physical hardware, or a hypervisor with real USB passthrough. Hyper-V is not sufficient.

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| E1 | `rustward-inventory capture --include-non-present` | succeeds unelevated | | |
| E2 | `rustward-inventory report` | sanitized; serial numbers redacted | | |
| E3 | Each test device: IDs, VID/PID, parent chain, classification | matches BRAND-IDENTIFICATION.md | | |
| E4 | Devices page → explanation | labelled "SİMÜLE" only | | |
| E5 | Encrypted drive unlock prompt | unaffected | | |
| E6 | Keyboard, mouse, printer | peripherals; never in scope | | |
| E7 | UASP drive | `SCSI\Disk…` namespace, USB parent chain resolved | | |
| E8 | Export the existing Restrictions key (`reg export … /y`) | evidence for the future `PolicySnapshot` capture; no change made | | |

## Exit

Stages A–E PASS (or FAIL with an accepted explanation) means the build is ready for physical-hardware acceptance and for writing the Stage F authorization request.
