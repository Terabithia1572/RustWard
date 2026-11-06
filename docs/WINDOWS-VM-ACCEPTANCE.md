# Windows VM Acceptance Workflow: Stages A–F (Phase 10)

Status: **procedure only. No stage has been executed.** The tickable list is
[WINDOWS-ACCEPTANCE-CHECKLIST.md](WINDOWS-ACCEPTANCE-CHECKLIST.md); it carries the expected result for every item. This
document gives the order, the checkpoints and the evidence rules. Every result is recorded as
PASS / FAIL / NOT RUN in an evidence folder; nothing may be reported as passed without that evidence.

Scope: a **disposable** Windows 10 Pro x64 22H2 virtual machine (Hyper-V, VMware or
VirtualBox), never the developer workstation and never one of the five production
workstations. Stages A–E are **non-destructive**: they install RustWard (from Stage C), but
they change no device, driver, registry policy or Group Policy. **Stage F is separate.**
It requires its own written authorization and a recoverable test environment. It never runs
as part of A–E, and in this build it cannot run at all (`ACTIVATION_ENABLED = false`; no
code writes the Restrictions key).

| Stage | Name | System changes | Checkpoint |
|---|---|---|---|
| A | Native compilation | none (build outputs only) | CP0-clean + build tools |
| B | Read-only system and device inspection | none | CP0-clean |
| C | Windows Service and IPC | installs RustWard (service, event source, `%ProgramData%\RustWard`) | CP-C |
| D | MSI installation and recovery | install / repair / uninstall / reinstall of RustWard only | CP-D |
| E | Read-only policy inspection | none: `reg export` before and after must be identical | CP-E |
| F | Controlled enforcement | **not executed**; separately authorized; impossible in this build | — |

Phase 11 adds one script per stage (see the checklist header and PHASE-11-NATIVE-VALIDATION.md §7). They refuse to run unless `-DisposableVm` (on a detected VM) or `-PhysicalTestMachine` is given and confirmed. The only script that changes the machine, `Invoke-AcceptanceMsi.ps1`, runs only on a detected VM, after the computer name is typed and the MSI hash is checked.

## 0. Preparation (once)

| Step | Detail |
|---|---|
| VM | Windows 10 Pro x64 22H2, latest cumulative update recorded (`winver`, `Get-ComputerInfo OsBuildNumber,OsHardwareAbstractionLayer`). 4 vCPU, 8 GB RAM, 80 GB disk. Network **disconnected** after the build tools are installed (Stages B–E run offline). |
| Accounts | `rwadmin` (member of Administrators) and `rwuser` (standard user). |
| Checkpoint | Take checkpoint **CP0-clean** before anything is installed. Every stage below starts from a named checkpoint, so it can be repeated. |
| Build tools (only if building in the VM) | Rust (MSVC toolchain, `x86_64-pc-windows-msvc`), Visual Studio Build Tools with the **Windows 10/11 SDK** (`rc.exe` is needed to embed the Event Log message table), Node 22 LTS, WiX 3.14 in `%LOCALAPPDATA%\tauri\WixTools314`. Alternatively build on a separate connected build machine and copy `release-out\` (OFFLINE-DEPLOYMENT.md §3). |
| Evidence | `C:\rw-evidence\<stage>\<yyyymmdd-hhmm>\`: console transcripts (`Start-Transcript`), screenshots, `SHA256SUMS.txt` check, exported Event Log (`wevtutil epl Application app.evtx`). Raw inventories contain serial numbers: keep them inside the VM / on approved media. |

## Stage A — Native compilation

Goal: the code compiles natively with the MSVC toolchain and every test passes, including the
Windows-only tests in `crates/rustward-windows/tests/native_windows.rs` (read-only device
enumeration, handle-leak check, internal-disk classification and, since Phase 10,
`device_install_policy_capture_is_read_only_and_repeatable`). Nothing is installed.
Items A1–A11. `scripts\run-native-validation.ps1` runs A1–A9 and writes `evidence\native\<stamp>\summary.txt`.

Exit: A1–A11 PASS. Record the commit (`BUILD-INFO.txt`) and the MSI hash.

## Stage B — Read-only system and device inspection

Goal: the inventory and classification match real hardware. No enforcement, no ejection, no
mounting change, nothing installed (the tools run from `release-out\`).

1. Unelevated: `rustward-inventory capture --include-non-present`, then `report` (B1, B2).
2. Plug each test device in turn (approved brand, unapproved brand, UASP drive, encrypted
   drive, keyboard, mouse, printer) and record IDs, parent chain and classification (B3–B7).
3. `rustward-service console --synthetic`, then live (B8). Console mode opens no pipes.
4. Repeat B1/B8 with the network disconnected (B9).

Raw inventories contain serial numbers: keep them inside the VM / on approved media; only the
sanitized report leaves it.

## Stage C — Windows Service and IPC

Checkpoint **CP-C** first. Install the acceptance MSI (`-WithService`) as `rwadmin`. Items:

- C1–C6: SCM registration, recovery actions, data-directory ACL, start/stop and crash restart.
- C7–C13: pipe ACLs, the user/admin/elevation authorization matrix, the impostor-server test (C12) and at-most-once edits (C13). C8 includes the read-only **Uygulama Hazırlığı** page (`GetEnforcementReadiness`, a read-only request served on the status pipe).
- C14–C18: Phase 9B findings F-19, F-16, F-18, F-13 and F-14.
- C19–C27: Event Log registration, formatted messages, the event ID set, the start failure (1008), device notifications, checkpoint verification against a tampered copy, and queued delivery while the Event Log service is stopped.

C12 procedure: stop the service; as `rwuser` create a scheduled task that runs a pipe server
named `RustWard.Status.v1`; start the UI. The client must refuse, because the pipe owner is not
LocalSystem / the RustWard service, or the serving process is not the SCM's RustWardService
process. Delete the task afterwards.

C15 (F-16 virtual account) runs on a **separate** checkpoint: `ServiceInstall
Account="NT SERVICE\RustWardService"`, data-dir ACL from `service_sid::data_dir_sddl(VirtualAccount)`,
pipe SDDL from `admin_pipe_sddl/status_pipe_sddl(VirtualAccount)`. Also check that the virtual
account can read the Restrictions key (policy capture through the readiness page).

Full event ID list: `rustward-windows/src/eventlog_map.rs` (`EVENT_IDS`, 9000 = other).

## Stage D — MSI installation and recovery

Checkpoint **CP-D**. Items D1–D10: hash check of `release-out\`, the UI-only MSI on a clean
image (the banner "Koruma henüz gerçek Windows ortamında doğrulanmadı." must be visible and the
service shown as unavailable, never protected), the logged install, backup/two-step restore,
repair, uninstall (data kept, event source removed), reinstall over kept data, a reinstall
after restoring CP0, and the "Corrupted RustWard DB/config" recovery row of RECOVERY-PLAN.md.
An installer is only reported as working after D4–D8 PASS on native Windows.

## Stage E — Read-only policy inspection

Checkpoint **CP-E** (RustWard installed from Stage D). **Do not create, change or delete any
value under `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall`** on this checkpoint,
not even to test the reader. Pre-existing values must come from the image as delivered, so
that the capture is compared with a real administrator configuration.

1. `reg export … deviceinstall-before.reg /y` (E1).
2. `rustward-inventory policy-capture --out …\policy-capture.json`, unelevated then elevated
   (E2). The reader opens the key with `RegOpenKeyExW(KEY_READ | KEY_WOW64_64KEY)` only, reads
   one level of subkeys, and records OS facts from `RtlGetVersion`, `GetProductInfo` and the
   `UBR` value (undocumented; reported as such).
3. Compare value by value with the `.reg` export (E3).
4. `policy-inspect` with the Stage B inventory (E4). Every value is labelled *documented*
   (Policy CSP mapping table), *unresolved* or *unrecognised*. Layering support is
   `Supported` for Windows 11 (build ≥ 22000). On Windows 10 19041–19045 it is `NotSupported`
   when UBR < 1151, and otherwise `Unresolved` with "confirm with winver", because the UBR comes
   from an undocumented value. Record the `winver` output next to it. Older builds are `NotSupported`.
5. **E5/E6 — the two unresolved items.** The list-entry layout (a subkey named after the
   policy holding numbered `REG_SZ` values) and the `*Retroactive` value names are not in the
   Policy CSP mapping table. Record what the delivered image shows; if the image has no list
   policies, record "not observed". They stay **unresolved** until confirmed from official
   documentation or a real export. Do not create values to find out.
6. `assess-installed --live --include-non-present --policy-capture … --sanitize` (E7). The
   report is **manual-only**: RustWard never uninstalls a device or removes a PnP instance.
7. Readiness page as elevated `rwadmin` (E8): the activation button is permanently disabled.
8. Native test E9; then `reg export … deviceinstall-after.reg` and `fc /b` with the "before"
   export (E10). Any difference fails Stage E.

### Hyper-V limitation (important)

Hyper-V has **no generic USB pass-through** ([Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/virtualization/usb-device-hyper-v-virtual-machine)):

- **Enhanced Session / RDP redirection** shows a host drive as an RDP-redirected drive
  (`\\tsclient\…`), not as a `USBSTOR` device node in the guest. It exercises nothing that
  RustWard classifies.
- **Offline pass-through disk** (take the disk offline on the host, attach it to the VM's
  SCSI controller, [Microsoft archive](https://learn.microsoft.com/en-us/archive/blogs/hollis/accessing-usb-drives-in-a-hyper-v-vm)) shows it as a Hyper-V virtual SCSI disk. USB
  VID/PID, `USBSTOR` IDs and the USB parent chain are gone. Removable flash drives often
  cannot be taken offline at all.

So **Stage B on Hyper-V can only verify inventory of non-USB devices** (Stage E, policy inspection, works on any hypervisor). Real USB storage
needs either a hypervisor with USB pass-through (VMware Workstation / VirtualBox: the guest
sees the real VID/PID and INQUIRY strings, but through an emulated xHCI host controller)
or, for acceptance, **physical hardware** identical to the five workstations. Enforcement
results (Stage F) are accepted **only on physical hardware**.

## Stage F — Controlled enforcement (separately authorized, NOT executed)

**Not runnable in this build.** Activation is refused by `activation::request_activation`
because `ACTIVATION_ENABLED = false`, and several gates are hard-wired NotMet. Stage F needs
a later build, a separate written authorization from the security owner naming the machine,
date and plan fingerprint, and a recoverable test environment (checkpoint/disk image tested
by one restore).

Gates evaluated by `rustward-enforcement::activation::evaluate_gates` (all must be Met):

| Gate | Met when |
|---|---|
| `build_permits_activation` | a reviewed build with an activation path exists (not this one) |
| `windows_compatibility_verified` | edition, build ≥ 19041.1151 (layered evaluation), `vm_validation` precondition met, Stage A–E acceptance record id (including E5/E6 resolved) |
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
| `existing_policy_compatible` (Phase 9B) | the Restrictions key captured read-only shows no conflict with the plan (`policy_state::compare`) |
| `plan_current` (Phase 9B) | no hardware, OS-build or policy change since the baseline (`policy_state::staleness`) |

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

Stages A–E PASS with evidence; C12 impostor test refused; C20 shows formatted descriptions; E10
exports identical; every finding in SECURITY-AUDIT-PHASE-9A.md and SECURITY-AUDIT-PHASE-9B.md
marked "verify on Windows" has a result. This is a readiness statement for further testing,
**not** a statement that RustWard is production-ready or that it blocks anything.
