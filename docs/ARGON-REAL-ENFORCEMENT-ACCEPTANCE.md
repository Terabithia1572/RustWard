# ARGON Staged Real-Enforcement Acceptance Plan & Evidence Ledger

**Target VM:** `<test-vm>.vmx` (Windows 10 Pro 22H2, Build `19045.6466`)  
**Workspace:** `<workspace>` (`experiment/argon4-vm-enforcement`)

---

## 1. Stage Status Overview

| Stage | Scope | Current Verification Category | Gate / Evidence Summary |
|---|---|---|---|
| **Stage A — Existing Kingston-specific denial & rollback** | Revalidate narrow `USBSTOR\DiskKingstonDataTraveler_3.0____` retroactive `DenyDeviceIDs` rule, live `Code 1`/`28` denial, `E:`/`F:` removal, peripheral/NVMe/VendorC safety, and full rollback in `RustWard2`. | `USER ACCEPTANCE PENDING` *(previously `PHYSICAL HARDWARE VERIFIED` on `66ed480` / `2858e6d`, 2026-11-07)* | Preflight complete (`ARGON-VM-PREFLIGHT.md`); updated `RustWard2` MSI & ISO prepared; awaiting explicit user approval to boot VM, take snapshot, upgrade service, apply Stage A GPO, verify, and roll back. |
| **Stage B — Manufacturer allowlist validation (SanDisk & Hardware-Encrypted USB)** | Inspect genuine SanDisk BOT & UASP sticks and genuine Hardware-Encrypted USB hardware (pre- and post-unlock) before broad default-deny activation. | `BLOCKED` | No genuine SanDisk physical drive attached to VM (`346D:5678` is generic `VendorC`, **never** substituted for SanDisk); no physical Hardware-Encrypted USB hardware available yet. |
| **Stage C — Default-deny profile feasibility & non-retroactive test** | Layered `AllowDenyLayered = 1` + `DenyDeviceClasses = DiskDrive` (`Retroactive = 0`) + Layer-1 `AllowInstanceIDs` (NVMe boot disk) + Layer-2 `AllowDeviceIDs` (`SanDisk`). | `IMPLEMENTED` / `USER ACCEPTANCE PENDING` | Profile compiler, preflight checks, and guided session (`DefaultDenyProfileCard`) implemented and unit-tested; requires explicit separate user authorization after Stage A & Stage B. |
| **Stage D — Previously installed devices handling** | Verify behavior of devices cached in `Enum\USBSTOR` before policy activation (`assess-installed` manual cleanup vs narrow per-device retroactive rule). | `IMPLEMENTED` / `AUTOMATED TEST VERIFIED` | `installed_assessment.rs` + `Uygulama Hazırlığı` table implemented; class-wide `Retroactive = 1` permanently prohibited to protect boot disk. |
| **Stage E — Windows reboot & rollback persistence** | Verify service auto-start, policy persistence across guest reboot, rollback accuracy, device restoration, and zero impact on NVMe/HID/Hubs. | `USER ACCEPTANCE PENDING` | Scheduled immediately after approved Stage A / Stage C execution inside snapshot-protected VM. |

---

## 2. Stage A — Controlled Execution Runbook (Upon User Approval)

### Pre-Flight & Snapshot (Mandatory Step 0)
1. Take fresh host-side VMware snapshot before starting or mutating guest:
   ```powershell
   & "vmrun.exe" -T ws snapshot "<test-vm>.vmx" "rustward2-argon4-before-acceptance"
   ```
2. Boot `<test-vm>.vmx` and perform **read-only live baseline capture**:
   - Confirm OS build (`winver` / `Get-ComputerInfo`), NVMe boot disk (`PCI\VEN_15AD&DEV_07F0` → `SCSI\DISK&VEN_NVME&PROD_VMWARE_VIRTUAL_N\...`), HID keyboard/mouse, USB hubs, Kingston (`0951:1666`), and VendorC (`346D:5678`).
   - Record current `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`, `RemovableStorageDevices`, `RustWardService` status, and `%ProgramData%\RustWard\rustward.db` state.
3. Install the isolated `RustWard2` Turkish MSI (`RustWard_0.1.0_x64_tr-TR.msi` from `<workspace>\dist\installer\`) and verify `RustWardService` restarts cleanly while preserving existing policy versions and audit hash chain.

### Stage A Execution & Independent Windows Evidence Collection
1. In elevated `RustWard.exe` → `Uygulama Hazırlığı`, select Kingston (`0951:1666`), enable **Kurulu cihazlara da uygula (geriye dönük)** (`retroactive = true`), click **Oturumu hazırla**, and confirm the round-trip badge displays `retroactive: true` (`POLİTİKA HAZIR`).
2. Apply the single-entry `DenyDeviceIDs` policy (`USBSTOR\DiskKingstonDataTraveler_3.0____`, `DenyDeviceIDsRetroactive = 1`) in `gpedit.msc` and run `gpupdate /force`.
3. Collect **independent OS evidence** (never relying solely on RustWard UI):
   - `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /s`
   - `Get-PnpDevice | Where-Object { $_.InstanceId -match '0951|KINGSTON|346D|VENDORC|NVME' } | Format-Table Status, Class, FriendlyName, InstanceId`
   - `Get-Volume | Format-Table DriveLetter, FileSystemLabel, DriveType, HealthStatus, Size`
   - Kernel-PnP Event Log entries (`Microsoft-Windows-Kernel-PnP/Configuration` / `DriverFrameworks-UserMode`).
4. Click **Uygulamayı doğrula** in RustWard and verify:
   - Status transitions to **`WINDOWS ENGELİ DOĞRULANDI`** (with explicit `ERİŞİM DOĞRULANAMADI` scope qualifier).
   - Kingston appears under **Şu An Windows Tarafından Engellenen Cihazlar** (`Code 1` or `Code 28`, volumes `E:`/`F:` absent).
   - VendorC (`346D:5678`, `G:`), NVMe boot disk (`C:`), and USB HID input remain `OK`.
5. Execute **Tier R1 Rollback** (`gpedit.msc` → *Not Configured* + `gpupdate /force`), click **Geri almayı doğrula** in RustWard, and confirm:
   - Status shows **`GERİ ALMA TAMAMLANDI`**.
   - `Restrictions` registry key matches baseline.
   - Kingston (`0951:1666`) returns to `Status = OK`, volumes `E:`/`F:` reappear untouched, and Kingston moves strictly to **Geçmiş Windows Engelleri** (never shown as an active block).

---

## 3. Historical Real-Windows Evidence Reference (2026-11-07 VM Run)

Recorded in [WINDOWS-VM-KINGSTON-BLOCK-2026-11-07.md](WINDOWS-VM-KINGSTON-BLOCK-2026-11-07.md):
- **Target:** `USB\VID_0951&PID_1666` (`USBSTOR\DiskKingstonDataTraveler_3.0____`), `DenyDeviceIDs = 1`, `DenyDeviceIDsRetroactive = 1`.
- **Observed Denial:** Device Manager `Code 1` (*installation of this device is forbidden by system policy*) at `13:31:10`, `Code 28` upon reconnect; volumes `E:` and `F:` removed from Explorer and Disk Management.
- **Selectivity & Safety:** VendorC `346D:5678` (`G:`), internal NVMe `Disk 0` (`C:`), and USB HID mouse/keyboard remained healthy throughout.
- **Observed Rollback:** Setting policy to *Not Configured* + `gpupdate /force` restored Kingston (`OK`, `E:`/`F:` mounted) with zero residual restriction.
