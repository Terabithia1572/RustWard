# Windows 10 Pro Acceptance Checklist: Stages A–F (Phase 10)

This is the tickable list for the controlled Windows 10 Pro validation. Procedures, preparation,
evidence layout and the Hyper-V limits are in [WINDOWS-VM-ACCEPTANCE.md](WINDOWS-VM-ACCEPTANCE.md).

**Status: no stage has been executed.** Every result column below is empty on purpose.

**Rules:**

- Record every item as PASS, FAIL or NOT RUN, with the evidence file in `C:\rw-evidence\<stage>\`.
- Nothing may be reported as passed without evidence.
- Stages A–E are **read-only for the system**. They install RustWard (from Stage C), but change no device, driver, registry policy or Group Policy.
- **Stage F is not part of this checklist run.**
  - It needs a separate written authorization and a build that has an activation path.
  - This build has none: `ACTIVATION_ENABLED = false`, and no RustWard code writes the Restrictions key.

The Phase 10 stage layout replaces the Phase 9B one:

| Phase 9B items | Phase 10 location |
|---|---|
| old B (app/SQLite/UI) | B and C |
| old D (Event Log, notifications) | C |
| old E (USB inventory) | B |
| old E8 (`reg export`) | E |
| MSI items (old B4, C14, C15) | D |

**Phase 11 scripts** (prepared, syntax-checked, **never executed**; PHASE-11-NATIVE-VALIDATION.md §7):

| Script | Covers |
|---|---|
| `scripts\run-native-validation.ps1` | A1–A9 (A10 with `-TauriBuild`), A11, B1–B2 |
| `scripts\windows\Invoke-StageB-DeviceInspection.ps1` | B1–B8 (B9: rerun offline) |
| `scripts\windows\Invoke-AcceptanceMsi.ps1` | D1, D4, D6, D7 (**changes the VM**, typed confirmation) |
| `scripts\windows\Invoke-StageC-ServiceInspection.ps1` | C1–C4, C7, C15, C19–C21, C24 (read-only) |
| `scripts\windows\Invoke-StageE-PolicyInspection.ps1` | E1, E2, E4, E7, E10 (decides E10 itself) |

Before Phase 11, A2 would have **failed** on native Windows (D-11-1, D-11-2: Windows-only `clippy -D warnings` errors). Both are fixed; the Linux Windows-target check is clean.

Build under test: commit ____ · MSI SHA-256 ____ · VM checkpoint ____ · Windows build.UBR ____ · Edition ____ · Date ____ · Tester ____

## Stage A: native compilation

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| A1 | `scripts\run-native-validation.ps1` | all steps exit 0 | | |
| A2 | `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings` (MSVC) | clean; the real pipe, SCM, SetupAPI, Event Log **and policy reader** code compiles natively | | |
| A3 | `cargo test --workspace --locked` | Linux counts from TEST-RESULTS.md, plus the 5 native tests in `rustward-windows/tests/native_windows.rs` | | |
| A4 | `cargo build --release --locked -p rustward-service -p rustward-inventory` | `build.rs` embeds the MESSAGETABLE (needs `rc.exe` from the Windows SDK) | | |
| A5 | `dumpbin /headers target\release\rustward-service.exe` | `.rsrc` present; MESSAGETABLE type 11, ID 1 | | |
| A6 | `npm ci`; `npx tsc -b --noEmit`; `npx vitest run` | PASS (43) | | |
| A7 | `cargo build -p rustward-ui-bridge --features dev-backend --example stdio_backend`, then the integration Vitest run (TEST-RESULTS.md) | PASS (16) on Windows | | |
| A8 | `npx vite build`; `node scripts\check-offline-assets.mjs` | "offline assets OK" | | |
| A9 | `cd src-tauri; cargo clippy --all-targets --locked -- -D warnings; cargo test --locked` | PASS on WebView2 | | |
| A10 | `scripts\build-release.ps1 -WithService` (connected build machine) | MSI, exes, BUILD-INFO.txt, DEPENDENCY-INVENTORY.md, SHA256SUMS.txt | | |
| A11 | `cargo deny check` (both lockfiles) | advisories, bans, licenses and sources all ok | | |

## Stage B: read-only system and device inspection

Real USB storage needs physical hardware or a hypervisor with USB pass-through. Hyper-V is not sufficient.

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| B1 | `rustward-inventory capture --include-non-present --out …\raw-inventory.json` | succeeds unelevated | | |
| B2 | `rustward-inventory report --snapshot … --out-dir …\report` | sanitized; serial numbers redacted | | |
| B3 | Each test device: IDs, VID/PID, parent chain, classification | matches BRAND-IDENTIFICATION.md; vendor strings recorded | | |
| B4 | UASP drive | `SCSI\Disk…` namespace; USB parent chain resolved | | |
| B5 | Keyboard, mouse, printer, USB hub | classified as peripherals; never in scope | | |
| B6 | Encrypted drive unlock prompt (vendor app or hardware PIN) | unaffected | | |
| B7 | Internal/boot disk | `SystemOrNonUsbStorage`; native test `internal_disks_are_classified_as_system_storage_on_this_machine` PASS | | |
| B8 | `rustward-service console --db C:\rw-test\b.db --synthetic --iterations 3`, then the same without `--synthetic` | 3 iterations; schema v2; live run gives warnings only | | |
| B9 | Disconnect the network, run B1 and B8 | no network attempt (Resource Monitor or firewall log) | | |

## Stage C: Windows Service and IPC

Requires the acceptance MSI (`-WithService`), checkpoint CP-C.

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| C1 | `sc.exe qc RustWardService` | auto start, LocalSystem, `"…\rustward-service.exe" service` | | |
| C2 | `sc.exe qfailure RustWardService` | restart ×3 after 5 s, reset after 1 day | | |
| C3 | `Get-Acl $env:ProgramData\RustWard` | protected; SYSTEM and Administrators only (**R-11-3**: confirms `MsiLockPermissionsEx` applied despite the template's InstallerVersion 450) | | |
| C4 | Service RUNNING within 30 s; `rustward.db` created | yes | | |
| C5 | Stop/start ×3 | STOPPED within the 15 s wait hint; no `ipc_shutdown_incomplete` event | | |
| C6 | `taskkill /F` the service | SCM restarts it after about 5 s | | |
| C7 | AccessChk on both pipes | admin pipe: SY+BA, owner SYSTEM. Status pipe: AU has read + write-data only, **no** create-instance | | |
| C8 | `rwuser`: dashboard, devices, events, **Uygulama Hazırlığı** page | work; the readiness page loads over the status pipe (read-only request) | | |
| C9 | `rwuser`: add/remove brand, rename workstation, backup, restore | refused in Turkish; `authorization_failed` recorded | | |
| C10 | `rwadmin` unelevated: same as C9 | refused | | |
| C11 | `rwadmin` elevated: add/remove brand, rename, backup, two-step restore | succeed; versions only increase; `policy_restored` with a restore id | | |
| C12 | Service stopped; a `rwuser` scheduled task serves `RustWard.Status.v1` | client refuses (owner / PID check) | | |
| C13 | Kill the UI during a policy edit | applied at most once; retry gets "conflict" | | |
| C14 | Two console instances on one new database at the same moment | both start (F-19) | | |
| C15 | **F-16:** test install with `NT SERVICE\RustWardService` (separate checkpoint) | inventory, notifications, Event Log, pipes **and policy capture** work, or a documented failure; decision recorded | | |
| C16 | **F-18:** while the service runs, `rwuser` attempts `CreateNamedPipe("\\.\pipe\RustWard.Status.v1")` | ERROR_ACCESS_DENIED | | |
| C17 | **F-13:** 8 idle `rwuser` connections plus the UI | UI still served on the admin pipe; extra status connections refused; slots freed after 15 s | | |
| C18 | **F-14:** stop the service with an active idle connection | stops within about 3 s; threads joined | | |
| C19 | `HKLM\…\EventLog\Application\RustWard` | EventMessageFile = service exe; TypesSupported 7 | | |
| C20 | Event Viewer entries | formatted text, no "description cannot be found" | | |
| C21 | IDs after C1–C13 | 1000, 1001, 1004, 3001, 4000, 5001, 5005, 5007, 5008 | | |
| C22 | Unreadable or newer-schema database at start | Event 1008; the service stops | | |
| C23 | Device plug/unplug | refresh within seconds | | |
| C24 | `rustward-service verify-checkpoint --head-id <id> --hash <prefix>` (values from a 5008 entry) | "MATCH", exit 0 | | |
| C25 | Delete the newest events on a **copy** of the database; rerun C24 on the copy | "MISSING" or "MISMATCH", exit 3; Diagnostics shows TRUNCATED/MISSING | | |
| C26 | Stop the Windows Event Log service briefly (test VM only), create events, restore it | pending > 0, then delivered in order; more than 1000 pending gives Event 1009 | | |
| C27 | `wevtutil epl Application app.evtx` | saved | | |

## Stage D: MSI installation and recovery

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| D1 | `Get-FileHash` of every file in `release-out\` against `SHA256SUMS.txt` | all match | | |
| D2 | MSI **without** the service fragment on CP0, start as `rwuser` | WebView2 UI loads; banner "Koruma henüz gerçek Windows ortamında doğrulanmadı."; service shown unavailable, never protected | | |
| D3 | Uninstall (D2) | program files removed | | |
| D4 | Install the acceptance MSI with logging (`msiexec /i … /l*v install.log`) | exit 0; service registered; event source registered | | |
| D5 | Elevated: create a backup; change the policy; two-step restore of the backup | restored policy equals the backup; the pre-restore backup is listed | | |
| D6 | MSI repair (`msiexec /fa …`) | service and data intact | | |
| D7 | Uninstall | service and event source removed; `%ProgramData%\RustWard` **kept** | | |
| D8 | Reinstall over the kept data | chain intact; history kept | | |
| D9 | Restore checkpoint CP0, then reinstall from scratch | clean install works (recovery by image) | | |
| D10 | RECOVERY-PLAN.md "Corrupted RustWard DB/config" row: stop the service, move `rustward.db` aside, copy the latest verified backup in, start | service starts; Diagnostics chain status OK; the incident is recorded outside RustWard | | |

## Stage E: read-only policy inspection

Nothing in Stage E writes the registry. Do **not** create test values in the Restrictions key on this checkpoint. Any pre-existing values must come from the image as delivered.

| ID | Check | Expected | Result | Evidence |
|---|---|---|---|---|
| E1 | `reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall" …\deviceinstall-before.reg /y` | exported | | |
| E2 | `rustward-inventory policy-capture --out …\policy-capture.json` (unelevated, then elevated) | succeeds; `os.build` / `os.ubr` / `os.product_type` match `winver` and the edition (0x30 = Professional) | | |
| E3 | Compare E2 with E1, value by value | every value in the `.reg` export is in the capture with the same type and data; `read_errors` explained | | |
| E4 | `rustward-inventory policy-inspect --policy-capture … --snapshot …\raw-inventory.json` | documented / unresolved / unrecognised labels; layering: Windows 10 shows `Unresolved` ("confirm with winver") when UBR ≥ 1151, `NotSupported` below; record `winver`; conflicts listed | | |
| E5 | **Unresolved list layout:** inspect E1 for any list policy present (for example `DenyDeviceIDs`) | record whether entries are a subkey of numbered `REG_SZ` values. Confirm only from the image or official documentation; do not create values to test it | | |
| E6 | **Unresolved retroactive names:** inspect E1 for `*Retroactive` values | record names found; otherwise "not observed" (stays unresolved) | | |
| E7 | `rustward-inventory assess-installed --live --include-non-present --policy-capture … --sanitize --out-dir …\assess` | report written; only disk-class devices; internal disks protected with no remediation; already-installed denied devices listed for **manual** review | | |
| E8 | Elevated UI → **Uygulama Hazırlığı** | "Gerçek uygulama durumu" not verified (`verified_protection = false`); inspection source `windows_registry_read_only`; gates NotMet; **"Politikayı etkinleştir" disabled** | | |
| E9 | Native test `device_install_policy_capture_is_read_only_and_repeatable` | PASS | | |
| E10 | `reg export` again (`deviceinstall-after.reg`); `fc /b` with E1 | **identical**: E2–E9 changed nothing | | |

## Stage F: controlled enforcement (separately authorized, NOT executed)

**Not runnable in this build.** Recorded here only so the gate list is complete.

| ID | Prerequisite | State in this build |
|---|---|---|
| F0 | Written authorization naming machine, date, plan fingerprint | not requested |
| F1 | A reviewed build with an activation path (`build_permits_activation`) | **absent**: `ACTIVATION_ENABLED = false`, no write path implemented |
| F2 | Stages A–E PASS on **physical** hardware identical to the five workstations | not run |
| F3 | E5/E6 resolved from documentation or observation | unresolved |
| F4 | All 15 activation gates Met (WINDOWS-VM-ACCEPTANCE.md, Stage F) | NotMet |

## Exit

Stages A–E PASS (or FAIL with an accepted explanation) and E10 identical means the build is ready for physical-hardware acceptance and for writing the Stage F authorization request. It does **not** mean RustWard protects anything.
