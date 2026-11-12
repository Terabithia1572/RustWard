# ARGON Security Review & Threat Model

**Workspace:** `<workspace>` (`experiment/argon4-vm-enforcement`)  
**Deployment Context:** Standalone Windows 10 Pro workstations operating completely offline.

---

## 1. Preserved Security Boundaries

| Security Invariant | Implementation & Verification |
|---|---|
| **No automated privileged OS policy mutation (`B1`)** | `rustward_enforcement::ACTIVATION_ENABLED == false`. Source-scan unit tests (`no_system_modification_apis_in_this_crate`, `no_module_references_state_changing_apis`, `policy_reader_is_read_only`) guarantee zero calls to registry-write, GPO-write, driver-install, or device-disable Win32 APIs. Not circumvented via PowerShell, `reg.exe`, or helper processes. |
| **Zero internet / cloud dependency** | Tauri CSP (`connect-src 'self'`), zero HTTP/network crates in workspace, offline SQLite WAL + Windows SetupAPI + local registry `KEY_READ`. |
| **Authenticated dual-pipe IPC & UAC authorization** | `\\.\pipe\RustWard\v1\status` (read-only) and `admin` (`SY` + `BA` SDDL), `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`. Server impersonates client token (`TokenElevation` + `WinBuiltinAdministratorsSid`); client verifies server owner SID + SCM `RustWardService` PID + Session `0` (`PipeConnection::connect`). |
| **Strict input validation & no command execution** | Frame cap `MAX_FRAME_BYTES = 4 MiB`, unknown request tags rejected (`#[serde(deny_unknown_fields)]` / tagged enum), control characters and oversized strings rejected in `validate.rs`, zero `std::process::Command` usage in service or Tauri runtime. |
| **No raw disk access & no PIN capture** | RustWard never opens `\\.\PhysicalDriveN` or volume handles and never prompts for, intercepts, or logs hardware-token PINs. |
| **Workspace & host isolation** | All work isolated to `<workspace>` (`experiment/argon4-vm-enforcement`); Windows 11 host policies, services, and original `RustWard` repository untouched. |

---

## 2. Offline Endpoint Threat Analysis (13 Required Threat Vectors)

| # | Threat Vector | Fail-Closed / Fail-Open Behavior | RustWard + Windows 10 Pro Control & Residual Gap |
|---|---|---|---|
| 1 | **Unapproved USB storage (Kingston, Seagate, unlisted flash/HDD/SSD)** | **Core policy:** Fail-closed (`Verdict::Deny`).<br>**OS enforcement:** Only active when Windows `DeviceInstall\Restrictions` rules are applied. | Explicit denylist (`kingston`, `seagate`) + default-deny for unlisted brands. In Windows, narrow `DenyDeviceIDs` (Stage A) or layered `DenyDeviceClasses = DiskDrive` prevents PnP installation (`Code 1` / `Code 28`). |
| 2 | **Spoofed manufacturer descriptors (BadUSB / custom firmware)** | **Conflicting VID vs INQUIRY:** Fail-closed (`ConflictingIdentifiers` → `Verdict::Deny`).<br>**Full VID + INQUIRY clone:** **Fail-open at OS/USB protocol level** (residual limitation). | Phase 3 enforces fail-closed denial when USB `VID` and SCSI `INQUIRY` disagree across catalog brands (e.g. `VID_0951` + `SanDisk`). However, USB Mass Storage lacks cryptographic attestation; a device cloning **both** `VID_0781` and `INQUIRY SanDisk` cannot be distinguished by software (`authenticated = false`). Requires physical media custody. |
| 3 | **Already-installed storage devices** | **Non-retroactive class rule:** **Fail-open** for cached PnP instances.<br>**Narrow `DenyDeviceIDsRetroactive = 1`:** Fail-closed. | Windows `DenyDeviceClasses` with `Retroactive = 0` leaves prior installs working (while `Retroactive = 1` on `DiskDrive` risks boot failure and is forbidden). RustWard enumerates `IncludeNonPresent`, surfaces every `denied_but_installed` disk on `Uygulama Hazırlığı`, and provides manual Device Manager cleanup steps or narrow device-ID retroactive checklists. |
| 4 | **USB-to-SATA / NVMe bridge adapters** | **Core policy:** Fail-closed (`GenericVendorIdentity` → `Verdict::Deny`). | Bridge chips (`ASMT`, `JMicron`, `Realtek`, `SMI`, `Phison`, `Generic`, `VendorC`) are reserved generic identities rejected by both catalog validation and policy evaluation. Under `DiskDrive` class prevent, unapproved bridged drives fail PnP install. |
| 5 | **UASP (`uaspstor`) external SSDs & HDDs** | **Core policy & `DiskDrive` class rule:** Fail-closed. | Disabling `USBSTOR` fails open against UASP (`SCSI\Disk...`). RustWard walks the PnP parent chain to detect USB ancestors above `SCSI\Disk...` nodes (`UsbTransport::Uasp`) and targets setup class `DiskDrive`, which governs both BOT and UASP disks. |
| 6 | **Composite USB devices (HID + Storage / CD-ROM)** | **Per-interface evaluation:** Storage child fail-closed; HID child allowed (`Peripheral`). | Composite parent (`usbccgp`) is not blocked, preserving keyboard/mouse HID interfaces. Child `DiskDrive` is evaluated independently. Non-disk functions (`CDROM`, `WPD`/MTP) are flagged explicitly as `UsbStorageOtherType` / `UsbPortableDevice` (`ScopeDecisionPending` / enforcement gap) until their setup classes are added. |
| 7 | **Local administrator override** | **By design of Windows:** Local Administrators hold ultimate machine control. | When `AllowAdminInstall` is unset/`0`, PnP installation rules apply to admins too, **but** an elevated admin can edit `gpedit.msc`, `Registry.pol`, or stop `RustWardService`. Production deployments require operators to use Standard User accounts. |
| 8 | **Offline attacks & physical removal of system disk** | **Out of scope of OS PnP policy alone.** | Booting from external media or removing the internal NVMe/SATA drive bypasses the offline Windows OS completely. Requires **UEFI Secure Boot + firmware admin password + BitLocker full-disk encryption (TPM + PIN)**. |
| 9 | **Windows policy tampering (`Registry.pol` / registry drift)** | **Detected continuously** (`POLICY_MISMATCH` / session verification diff). | RustWard's read-only observer re-reads `HKLM\...\Restrictions` and `RemovableStorageDevices` and compares live values against prepared session expectations, surfacing drift immediately without silently claiming protection. |
| 10 | **Device identity changes after PIN unlocking (e.g. Hardware-Encrypted USB)** | **Unverified IDs:** Fail-closed (`Verdict::Deny`). | Hardware-encrypted drives may switch PID or expose `DiskDrive` only after hardware/pad unlock. `CM_Register_Notification` + `correlate_reenumeration` catches post-unlock arrival and evaluates the new `DiskDrive` devnode without touching PINs. |
| 11 | **Service startup failures / crashes** | **OS policy persists independently; observation degrades visibly.** | Local Group Policy restrictions are enforced by the Windows kernel/PnP manager (`gpsvc`), **not** by `RustWardService` being alive — so applied Windows blocks stay active even if `RustWardService` stops! Meanwhile, WiX configures SCM auto-restart (5s delay) and the desktop UI's `ConnectionBar` immediately alerts `"Hizmet bağlantısı yok"`. |
| 12 | **Policy persistence failures (direct registry edit overwritten by GPO)** | **Prevented by architectural rule (`B3`).** | Direct `RegSetValueExW` under `Policies\...` is overwritten by `gpsvc` from `Registry.pol`. RustWard never writes direct registry keys; administrator changes go through `gpedit.msc` (`Registry.pol`), and future automated writing is restricted to `IGroupPolicyObject::Save`. |
| 13 | **Audit log tampering / local DB corruption** | **Tamper-evident (not tamper-proof against `SYSTEM`/Admin); fail-safe DB integrity checks.** | Append-only SQLite triggers + SHA-256 hash chain + `sqlite_sequence` truncation check + daily Event Log `audit_checkpoint` (`Event 1008`). Corrupted backups are rejected in memory before touching live state (`inspect_backup`). |

---

## 3. ARGON Security Improvements Implemented

1. **Core Policy Fail-Closed on Conflicting USB `VID` vs. SCSI `INQUIRY` (`rustward-core`)**:
   - Closed defect **D-02**: previously, a malicious or bridged USB stick presenting Kingston's `VID_0951` (or any conflicting catalog brand `VID`) alongside a spoofed `SanDisk` SCSI `INQUIRY` string received `Verdict::Allow` from `evaluate_device()`. Now `evaluate_device()` cross-checks catalog `UsbVid` claims on the USB ancestor against `InquiryVendor` claims and returns `Verdict::Deny` with `DecisionReason::ConflictingIdentifiers` and exact supporting evidence.
2. **Explicit Denylist Brand Attribution (`rustward-app`)**:
   - Closed defect **D-01**: `DecisionReason::BrandDenied { brand_id }` now preserves `matched_brand` in SQLite `devices` and `DeviceView` so audit/UI records accurately attribute Kingston and Seagate blocks.
3. **Retroactive Parameter Round-Trip Guard (`GuidedSession.tsx`)**:
   - Closed defect **D-03 (Bug A)**: Prepared sessions display the exact persisted `retroactive` flag from the service and block verification if the service-persisted `retroactive` or `device_key` ever diverges from the administrator's UI selection.
4. **Elimination of Misleading Active/Simulated UI Badges**:
   - Closed defect **D-05**: Historical rolled-back blocks never appear as active blocks (`Bug C`), simulated rows never misstate live Windows state, and distinct Turkish status badges (`Bug D`) separate simulation from verified Windows installation denial.
