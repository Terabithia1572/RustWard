# ARGON Rollback & Emergency Recovery Plan

**Scope:** Windows 10 Pro Acceptance VM (`D:\Windows10VM\Windows 10 x64.vmx`) and future standalone offline Windows 10 Pro workstations.  
**Core Rule:** Never write to, format, repartition, or delete files on attached physical USB media; VMware snapshots protect the guest NVMe disk (`nvme0:0`), **not** external USB flash drives.

---

## 1. Four-Tier Recovery Hierarchy (Fastest to Deepest)

### Tier R1 — Normal In-Guest Policy Rollback & RustWard Verification (~15 seconds)
Use whenever the Windows 10 guest desktop is responsive (standard Stage A / Stage E completion):
1. Open elevated `gpedit.msc` → `Computer Configuration` → `Administrative Templates` → `System` → `Device Installation` → `Device Installation Restrictions`.
2. Return every modified setting (for Stage A: *Prevent installation of devices that match any of these device IDs*) to **Not Configured** (*Yapılandırılmadı*).
3. In an elevated Command Prompt, run:
   ```cmd
   gpupdate /force
   ```
4. Independently verify in elevated PowerShell/CMD that the policy key is clean:
   ```cmd
   reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
   ```
   *(Expected when baseline had no restrictions: `ERROR: The system was unable to find the specified registry key or value` or empty default state matching baseline.)*
5. In elevated **RustWard** → `Uygulama Hazırlığı`, click **Geri almayı doğrula** (`VerifyEnforcementRollback`):
   - Confirm status transitions to **`GERİ ALMA TAMAMLANDI`** and the guided session closes cleanly.
   - Confirm `Dashboard` and `Engellenen Cihazlar` show **zero** active Windows denials (any earlier Kingston denial appears strictly under **Geçmiş Windows Engelleri**, never as an active block).

### Tier R2 — Device Node Re-Enumeration (~10 seconds)
Use if Tier R1 succeeded (`Restrictions` key cleared) but a previously blocked USB storage device still displays `Code 28` or lacks its drive letter:
1. Run `pnputil /scan-devices` in an elevated Command Prompt (or click *Scan for hardware changes* in Device Manager, or disconnect/reconnect the USB device to the VM).
2. Confirm via `Get-PnpDevice -PresentOnly` and `Get-Volume` that `Status == OK` (`CM_PROB == 0`) and volumes mount read-only healthy without touching files on the USB stick.

### Tier R3 — Host-Side VMware Snapshot Revert (~20 seconds, Guaranteed Boot Recovery)
Use immediately if **any** unexpected impact occurs on the VM boot disk (`C:`), keyboard/mouse input, unrelated devices, or service stability:
1. From the Windows 11 host (requires zero guest responsiveness):
   ```powershell
   & "D:\VmWare\vmrun.exe" -T ws revertToSnapshot "D:\Windows10VM\Windows 10 x64.vmx" "rustward2-argon4-before-acceptance"
   ```
   *(Or revert to pre-existing `rustward-phase6-before-kingston-retest` / `rustward-phase6-before-profile-test`.)*
2. Restores guest NVMe disk (`nvme0:0`), registry hives, `Registry.pol`, and installed `RustWardService` to the exact byte-for-byte pre-test state.

### Tier R4 — Bare-Metal / Offline WinRE Recovery (For Physical Workstations Without VM Snapshots)
Documented for standalone physical Windows 10 Pro endpoints if an administrator ever misconfigures a broad Device Installation Restriction:
1. Boot into **Windows Recovery Environment (WinRE)** → *Troubleshoot* → *Advanced options* → *Command Prompt*.
2. Identify the OS volume (e.g. `C:\Windows` or `D:\Windows`) and load the offline `SOFTWARE` hive:
   ```cmd
   reg load HKLM\OFFLINE_SW C:\Windows\System32\config\SOFTWARE
   reg delete "HKLM\OFFLINE_SW\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /f
   reg unload HKLM\OFFLINE_SW
   ```
3. Neutralize the Local Group Policy store so `gpsvc` does not re-apply the deleted restriction at boot:
   ```cmd
   ren C:\Windows\System32\GroupPolicy\Machine\Registry.pol Registry.pol.rustward-recovery-bak
   ```
4. Reboot normally (`wpeutil reboot`), verify internal storage and peripherals, then re-establish non-conflicting local machine policies via `gpedit.msc`.

---

## 2. Mandatory Abort Triggers During VM Acceptance

Immediately halt the current test stage and execute **Tier R3** (or **Tier R1** if minor) if any of the following occur:
- `PCI\VEN_15AD&DEV_07F0` or `SCSI\DISK&VEN_NVME&PROD_VMWARE_VIRTUAL_N\...` reports any non-zero `Problem` code or `C:` shows I/O errors.
- VMware USB HID keyboard/mouse or USB root hubs report a policy block or stop responding.
- In Stage A (Kingston-only rule), the negative-control device (`346D:5678` `VendorC`, volume `G:`) loses its driver or volume.
- RustWard UI reports a round-trip mismatch on `retroactive` during session preparation (`Bug A` guard).
