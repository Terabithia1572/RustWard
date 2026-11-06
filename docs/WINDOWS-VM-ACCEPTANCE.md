# Windows VM Acceptance Workflow

Status: **procedure only. No stage has been executed.** Every result is recorded as
PASS / FAIL / NOT RUN in an evidence folder; nothing here may be reported as passed without
that evidence.

Scope: a **disposable** Windows 10 Pro x64 22H2 virtual machine (Hyper-V, VMware or
VirtualBox), never the developer workstation and never one of the five production
workstations. Stages A–E are **non-destructive**: they install RustWard (C onwards), but
they change no device, driver, registry policy or Group Policy. **Stage F is separate.**
It requires its own written authorization and a recoverable test environment. It never runs
as part of A–E, and in this build it cannot run at all (`ACTIVATION_ENABLED = false`).

## 0. Preparation (once)

| Step | Detail |
|---|---|
| VM | Windows 10 Pro x64 22H2, latest cumulative update recorded (`winver`, `Get-ComputerInfo OsBuildNumber,OsHardwareAbstractionLayer`). 4 vCPU, 8 GB RAM, 80 GB disk. Network **disconnected** after the build tools are installed (Stages B–E run offline). |
| Accounts | `rwadmin` (member of Administrators) and `rwuser` (standard user). |
| Checkpoint | Take checkpoint **CP0-clean** before anything is installed. Every stage below starts from a named checkpoint, so it can be repeated. |
| Build tools (only if building in the VM) | Rust (MSVC toolchain, `x86_64-pc-windows-msvc`), Visual Studio Build Tools with the **Windows 10/11 SDK** (`rc.exe` is needed to embed the Event Log message table), Node 22 LTS, WiX 3.14 in `%LOCALAPPDATA%\tauri\WixTools314`. Alternatively build on a separate connected build machine and copy `release-out\` (OFFLINE-DEPLOYMENT.md §3). |
| Evidence | `C:\rw-evidence\<stage>\<yyyymmdd-hhmm>\`: console transcripts (`Start-Transcript`), screenshots, `SHA256SUMS.txt` check, exported Event Log (`wevtutil epl Application app.evtx`). Raw inventories contain serial numbers: keep them inside the VM / on approved media. |

## Stage A — Native build and static validation

Goal: the code compiles and its tests pass with the MSVC toolchain. Nothing is installed.

| # | Command (repository root, unelevated PowerShell) | Expect |
|---|---|---|
| A1 | `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-native-validation.ps1` | `evidence\native\<stamp>\summary.txt`, all steps exit 0 |
| A2 | `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings` | clean (on Windows this compiles the real pipe, SCM and SetupAPI code, not just the type-check build) |
| A3 | `cargo test --workspace --locked` | same counts as TEST-RESULTS.md (Windows adds `tests/native_windows.rs`) |
| A4 | `cargo build --release --locked -p rustward-service -p rustward-inventory` | builds; `build.rs` embeds the message table (fails loudly if `rc.exe` is missing) |
| A5 | Resource check: `dumpbin /headers target\release\rustward-service.exe` (VS Developer prompt) or any PE resource viewer | `.rsrc` section present; resource type MESSAGETABLE (11), ID 1 |
| A6 | `cd apps\rustward-desktop; npm ci; npm run typecheck; npm test; npx vite build` | PASS |
| A7 | `cd src-tauri; cargo clippy --all-targets --locked -- -D warnings; cargo test --locked` | PASS on WebView2 build |
| A8 | `.\scripts\build-release.ps1 -WithService` (connected build machine) | `release-out\` with MSI, exes, `BUILD-INFO.txt`, `DEPENDENCY-INVENTORY.md`, `SHA256SUMS.txt` |
| A9 | `cargo deny check` (both lockfiles) | `advisories ok, bans ok, licenses ok, sources ok` |

Exit: A1–A9 PASS. Record the commit (`BUILD-INFO.txt`) and the MSI hash.

## Stage B — Application start, SQLite, UI and IPC (no service yet)

Goal: the desktop app and the IPC stack work on Windows. Use the console backend so the SCM
is not involved yet.

| # | Step | Expect |
|---|---|---|
| B1 | As `rwadmin`, elevated: `rustward-service.exe console --db C:\rw-test\b.db --synthetic --iterations 3` | 3 iterations; DB created with migrations v1–v2 |
| B2 | Same with a live inventory (omit `--synthetic`) | iterations complete; `inventory_warnings` only, no failure |
| B3 | Console mode does **not** open the named pipes (only the SCM entry point does), so pipe and authorization tests are in Stage C | — |
| B4 | Install the MSI **without** the service fragment (plain `tauri build` MSI) on checkpoint CP0, start RustWard as `rwuser` | UI loads in WebView2; banner "Koruma henüz gerçek Windows ortamında doğrulanmadı."; backend shown as unavailable (no service) — never as protected |
| B5 | DevTools are not available in the release build; CSP violations are absent (no console) | — |
| B6 | Uninstall the MSI | program files removed |

## Stage C — Windows Service registration and lifecycle

Checkpoint **CP-C** first. Install the acceptance MSI (`-WithService`) as `rwadmin`.

| # | Step | Expect |
|---|---|---|
| C1 | `sc.exe qc RustWardService` | `SERVICE_AUTO_START`, `LocalSystem`, binary path `"…\rustward-service.exe" service` |
| C2 | `sc.exe qfailure RustWardService` | restart ×3, 5 s, reset 86400 s |
| C3 | `Get-Acl $env:ProgramData\RustWard \| Format-List` | protected, SYSTEM + Administrators full control, no Users |
| C4 | `sc.exe query RustWardService` | `RUNNING` within 30 s; `rustward.db` exists |
| C5 | `Stop-Service RustWardService`; `Start-Service` ×3 | clean stops (`STOPPED` within the wait hint), no orphaned processes (`Get-Process rustward-service`) |
| C6 | `taskkill /F /IM rustward-service.exe` | SCM restarts it after ~5 s (`sc.exe queryex`) |
| C7 | Pipe ACLs: `[System.IO.Directory]::GetFiles('\\.\pipe\') \| sls RustWard`; `Get-Acl \\.\pipe\RustWard.Admin.v1` (PowerShell 7) or AccessChk `accesschk -p RustWard` | Admin pipe: SYSTEM, Administrators only; owner SYSTEM. Status pipe: + Authenticated Users read/write |
| C8 | As `rwuser`: UI reads dashboard, devices, events | works (status pipe) |
| C9 | As `rwuser`: try to add/remove a manufacturer, change workstation ID, create/restore a backup | refused "elevated administrator required"; one `authorization_failed` event each (≤ 20/min) |
| C10 | As `rwadmin` **unelevated**: same | refused (not elevated) |
| C11 | As `rwadmin` elevated ("Run as administrator"): add a test brand, then remove it; rename workstation; create backup; prepare + apply restore of that backup | succeed; policy versions increase; `policy_restored` with restore id; pre-restore backup listed |
| C12 | Impostor test: stop the service; as `rwuser` create a scheduled task (run whether logged on or not) that runs a pipe server named `RustWard.Status.v1`; start the UI | client refuses: "pipe is not owned by LocalSystem" (finding F-03). Delete the task afterwards. |
| C13 | Kill the UI mid-request (Task Manager) during a policy edit; reopen | change applied at most once; a retry with the old version gets `conflict` |
| C14 | Uninstall the MSI | service stopped and deleted; `%ProgramData%\RustWard` **kept**; Event Log source key removed (`Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\RustWard` → False) |
| C15 | Reinstall over the kept data | existing DB opened, chain status OK, history intact |

## Stage D — Event Log and device notifications

| # | Step | Expect |
|---|---|---|
| D1 | `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\RustWard` | `EventMessageFile` = path of `rustward-service.exe`, `TypesSupported` = 7 |
| D2 | Event Viewer → Application → source RustWard | Entries display the RustWard text **without** "The description for Event ID … cannot be found" |
| D3 | IDs present after Stage C actions | 1000 service_started, 1001 service_stopping, 1004 backend_started, 3001 policy_changed, 4000 authorization_failed, 5001 backup_created, 5005 restore_prepared, 5007 policy_restored, 2000/2001 device events |
| D4 | Rename `%ProgramData%\RustWard\rustward.db` to an unreadable copy (deny SYSTEM read on a copy, or put a newer-schema file) and start the service | service fails to start; Event Log **1008 service_start_failed** (Error) with the reason; restore the file afterwards |
| D5 | Plug/unplug a virtual or redirected device that creates a PnP node (Stage E covers storage) | next inventory refresh happens within seconds (`CM_Register_Notification` wake-up), not after the full interval |
| D6 | `wevtutil epl Application C:\rw-evidence\D\app.evtx` | evidence saved |

Full ID list: `rustward-windows/src/eventlog_map.rs` (`EVENT_IDS`, 9000 = other).

## Stage E — Read-only real USB inventory

No enforcement, no ejection, no mounting changes.

| # | Step | Expect |
|---|---|---|
| E1 | `rustward-inventory capture --include-non-present --out C:\rw-evidence\E\raw-inventory.json` | succeeds unelevated |
| E2 | `rustward-inventory report --snapshot … --out-dir C:\rw-evidence\E\report` | sanitized report (serials redacted) |
| E3 | For each test device: hardware IDs (`USBSTOR\Disk<vendor>…`, `SCSI\Disk…` for UASP), VID/PID, parent chain, classification | matches BRAND-IDENTIFICATION.md; record vendor strings |
| E4 | UI → Devices → Explain | simulated verdict only, labelled "SİMÜLE" |
| E5 | Encrypted drive: unlock prompt (vendor app / hardware PIN) appears normally | RustWard does not interfere |
| E6 | Keyboard, mouse, printer | classified as peripherals, never in scope |

### Hyper-V limitation (important)

Hyper-V has **no generic USB pass-through** ([Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/virtualization/usb-device-hyper-v-virtual-machine)):

- **Enhanced Session / RDP redirection** shows a host drive as an RDP-redirected drive
  (`\\tsclient\…`), not as a `USBSTOR` device node in the guest. It exercises nothing that
  RustWard classifies.
- **Offline pass-through disk** (take the disk offline on the host, attach it to the VM's
  SCSI controller, [Microsoft archive](https://learn.microsoft.com/en-us/archive/blogs/hollis/accessing-usb-drives-in-a-hyper-v-vm)) shows it as a Hyper-V virtual SCSI disk. USB
  VID/PID, `USBSTOR` IDs and the USB parent chain are gone. Removable flash drives often
  cannot be taken offline at all.

So **Stage E on Hyper-V can only verify inventory of non-USB devices**. Real USB storage
needs either a hypervisor with USB pass-through (VMware Workstation / VirtualBox: the guest
sees the real VID/PID and INQUIRY strings, but through an emulated xHCI host controller)
or, for acceptance, **physical hardware** identical to the five workstations. Enforcement
results (Stage F) are accepted **only on physical hardware**.

## Stage F — Controlled USB access enforcement (separate authorization)

**Not runnable in this build.** Activation is refused by `activation::request_activation`
because `ACTIVATION_ENABLED = false`, and several gates are hard-wired NotMet. Stage F needs
a later build, a separate written authorization from the security owner naming the machine,
date and plan fingerprint, and a recoverable test environment (checkpoint/disk image tested
by one restore).

Gates evaluated by `rustward-enforcement::activation::evaluate_gates` (all must be Met):

| Gate | Met when |
|---|---|
| `build_permits_activation` | a reviewed build with an activation path exists (not this one) |
| `windows_compatibility_verified` | edition, build ≥ 19041.1151 (layered evaluation), `vm_validation` precondition met, Stage A–E acceptance record id |
| `administrator_authorized` | service-side token check: elevated Administrators |
| `test_environment_confirmed` | operator typed `I CONFIRM THIS IS A DISPOSABLE TEST MACHINE <workstation-id>` |
| `baseline_saved` | baseline inventory (incl. non-present) captured and a registered backup named |
| `recovery_procedure_ready` | RECOVERY-PLAN.md printed/acknowledged; plan has recovery steps |
| `policy_validated` | policy in `enforce` mode; plan version and workstation match; every planned value confirmed against Microsoft documentation |
| `system_disks_protected` | every internal disk in the baseline has an `AllowInstanceIDs` rule, no disk with unknown attachment, at least one internal disk, class rule not retroactive |
| `dry_run_reviewed` | dry-run of **this plan fingerprint** reviewed; no enforcement gaps / over-blocking; installed denied devices reviewed |
| `exact_changes_confirmed` | operator confirmed the exact registry values, bound to the plan fingerprint |
| `explicit_approval` | separate final approval bound to the plan fingerprint |
| `post_activation_verification_ready` | approved and unapproved test devices on hand; read/write probe procedure ready |
| `rollback_ready` | removal of every written value tested in the VM for this build |

Stages reported to operators (never conflated): device detection → manufacturer
classification → simulated authorization → planned enforcement → activated Windows policy
(not yet verified) → **verified read/write denial** (the only stage that claims protection,
and only with `VerificationEvidence` for the current plan).

Stage F verification (future): plug an unapproved drive → install refused (Device Manager
shows the policy problem code), no volume appears, write and read attempts fail. Plug an
approved drive → works. Keyboard/mouse/printer and internal disks unaffected after reboot.
Then roll back and confirm the baseline is restored. Ejecting after mount is **never** an
accepted blocking mechanism.

## Exit criteria for "ready for physical-hardware acceptance"

Stages A–E PASS with evidence, the C12 impostor test refused, D2 shows formatted
descriptions, and every finding in SECURITY-AUDIT-PHASE-9A.md marked "verify on Windows" has
a result.
