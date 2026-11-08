# ARGON Phase 2 — Windows 10 Pro USB Storage Enforcement Feasibility

**Target OS:** Standalone offline Windows 10 Pro 22H2 (Build `19045.x`, 64-bit)  
**Primary Sources:** Microsoft Learn — *Manage device installation with Group Policy*, *Policy CSP — DeviceInstallation*, *Removable Storage Access*, *IGroupPolicyObject Interface (`gpedit.h`)*.

---

## 1. Candidate Windows 10 Pro Mechanisms — 11-Point Evaluation Matrix

| Dimension | M1: Device-ID / Instance-ID Deny (`DenyDeviceIDs` / `DenyInstanceIDs`) | M2: Layered Setup-Class Default-Deny + Device/Instance Allow (`AllowDenyLayered = 1` + `DenyDeviceClasses` `DiskDrive` + `AllowDeviceIDs` / `AllowInstanceIDs`) | M3: Prevent Removable Devices (`DenyRemovableDevices`) | M4: Removable Storage Access (`RemovableStorageDevices` Read/Write/Execute Deny) | M5: Disabling `USBSTOR` Driver (`Services\USBSTOR\Start = 4`) |
|---|---|---|---|---|---|
| **Supported Windows versions** | Windows Vista+ / Windows 10 Pro 22H2 (19045) | Windows 10 Pro with layered evaluation update (21H2 KB5007253+ / 22H2 Build 19045) & Windows 11 | Windows Vista+ / Windows 10 Pro | Windows Vista+ / Windows 10 Pro | Windows XP+ / Windows 10 Pro |
| **Required privileges** | Local Administrator / `SYSTEM` (`Local GPO` via `IGroupPolicyObject` or `gpedit.msc`) | Local Administrator / `SYSTEM` (`IGroupPolicyObject` or `gpedit.msc`) | Local Administrator / `SYSTEM` | Local Administrator / `SYSTEM` | Local Administrator / `SYSTEM` |
| **Enforcement before first access?** | **Yes** — PnP manager aborts driver installation/configuration (`CM_PROB_FAILED_INSTALL = 28` / `CM_PROB_NOT_CONFIGURED = 1`) before disk/volume mount | **Yes** for newly connected/uninstalled devices; PnP blocks `disk.inf` installation before volume mount | **Yes** for newly connected bus-removable devices | **Yes** at filesystem/storage I/O layer for removable volumes | **Partial** — blocks `USBSTOR` driver load for new BOT devices only |
| **Already-installed devices affected?** | **Only if** `DenyDeviceIDsRetroactive = 1` (proven safe for narrow USB `USBSTOR\Disk...` / `USB\VID_...` prefixes) | **No** when `DenyDeviceClassesRetroactive = 0`. Setting `DenyDeviceClassesRetroactive = 1` is **UNSAFE** (boot-disk hazard!) | **Only if** `DenyRemovableDevicesRetroactive = 1` (hits non-storage removable USB peripherals!) | **Yes** — applies to already-installed removable volumes on policy refresh/remount | **Partial / inconsistent** if driver already loaded in memory; **misses UASP completely** |
| **Manufacturer exceptions supported?** | Denylist only (blocks listed vendor/model prefixes like `USBSTOR\DiskKingston`) | **Yes (best available in built-in Win10 Pro)** — Layer 1 `AllowInstanceIDs` & Layer 2 `AllowDeviceIDs` (`USBSTOR\DiskSanDisk_`, `SCSI\DiskSanDisk_`) override Layer 3 `DenyDeviceClasses` (`DiskDrive`) | **Poor** — hits keyboards/mice/printers/cameras if bus marks port removable unless every peripheral class/ID is allowlisted | **No** — strictly class-wide (`{53f5630d-...}`); cannot allow SanDisk while denying Kingston | **No** — disables `USBSTOR.SYS` globally for all vendors |
| **Could internal disks be affected?** | **No**, provided rules only target `USBSTOR\...` or `USB\VID_...` prefixes | **Existing boot disk protected** when `DenyDeviceClassesRetroactive = 0` AND Layer-1 `AllowInstanceIDs` covers internal NVMe/SATA disks. **New/replacement internal disks, Storage Spaces, VHD/VHDX mounts, or controller-slot changes ARE blocked** until suspended/allowed | Internal PCIe/SATA disks marked non-removable are unaffected, unless hot-plug SATA marks port removable | Non-removable fixed disks unaffected; USB HDDs/SSDs presenting `RemovableMedia = false` (fixed disk bit) **bypass** Removable Disks RSA! | Internal NVMe/SATA unaffected |
| **External USB HDDs & SSDs covered?** | Only if their vendor/model IDs are in `DenyDeviceIDs` | **Yes** — both USB BOT (`USBSTOR`) and USB UASP (`uaspstor` / `SCSI\Disk...`) enumerate in setup class `DiskDrive` (`{4d36e967-e325-11ce-bfc1-08002be10318}`) | Depends on hub/bridge `CM_DEVCAP_REMOVABLE` bit (some USB-SATA bridges report non-removable) | **Incomplete** — many external USB HDDs/SSDs report `RMB = 0` ("Fixed Disk" / Local Disk) and are NOT covered by `Removable Disks` (`{53f5630d-...}`)! | **No** — UASP external SSDs/HDDs use `uaspstor.sys` (`SCSI\Disk...`), completely bypassing `USBSTOR`! |
| **Read & write independently restricted?** | **No** — installation is all-or-nothing | **No** — installation is all-or-nothing | **No** — installation is all-or-nothing | **Yes** (`Deny_Read`, `Deny_Write`, `Deny_Execute`), **but class-wide only** (no brand allowlist) | **No** |
| **Survives restart?** | **Yes** when written via Local GPO (`Registry.pol`) | **Yes** when written via Local GPO (`Registry.pol`) | **Yes** via Local GPO | **Yes** via Local GPO | **Yes** (until overridden) |
| **Rollback reliable?** | **Yes** — setting policy to *Not Configured* + `gpupdate /force` restores device automatically (VM-verified 2026-11-07) | **Yes** when non-retroactive (setting 4 GPOs to *Not Configured* + `gpupdate /force`); VM snapshot / WinRE `Registry.pol` rename provides offline recovery | **Yes** via GPO rollback | **Yes** via GPO rollback | Requires re-enabling `Start = 3` + rescan |
| **Operates 100% offline?** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |

*Note on Microsoft Defender for Endpoint (MDE) Device Control:* MDE supports granular per-VID/PID/serial/INQUIRY read/write/execute policies on Windows 10, **but** requires MDE commercial licensing/onboarding components not present on standalone unmanaged Windows 10 Pro installations using only built-in OS facilities.

---

## 2. Deep Technical Analysis of Critical Windows PnP & Storage Behaviors

### 2.1 Layered Evaluation Order (`AllowDenyLayered = 1`)
Without `AllowDenyLayered = 1`, Windows evaluates **every** Prevent rule ahead of **every** Allow rule (`DenyDeviceClasses` for `DiskDrive` overrides `AllowDeviceIDs` for `SanDisk`). With `AllowDenyLayered = 1` on Windows 10 Pro 22H2 (`19045`), Microsoft's documented specificity order is:
1. **Layer 1 — Device Instance IDs** (`AllowInstanceIDs` / `DenyInstanceIDs`) — most specific; used to pin existing internal system disks (`SCSI\DISK&VEN_NVME&PROD_VMWARE_VIRTUAL_N\5&25A13950&0&000000`).
2. **Layer 2 — Device IDs** (`AllowDeviceIDs` / `DenyDeviceIDs`, matching Hardware IDs and Compatible IDs) — used for vendor-level storage prefixes (`USBSTOR\DiskSanDisk_`, `SCSI\DiskSanDisk_`).
3. **Layer 3 — Device Setup Classes** (`AllowDeviceClasses` / `DenyDeviceClasses`) — used to block unapproved `DiskDrive` (`{4d36e967-e325-11ce-bfc1-08002be10318}`).
4. **Layer 4 — Removable Devices** (`DenyRemovableDevices`).

*Critical Caveat:* Generic compatible IDs (`USBSTOR\GenDisk`, `GenDisk`, `SCSI\GenDisk`) appear on **every** disk drive. Placing any generic ID into `AllowDeviceIDs` would allow all USB drives; placing `GenDisk` into `DenyDeviceIDs` at Layer 2 would sit at the **same layer** as `AllowDeviceIDs` (`USBSTOR\DiskSanDisk_`), where same-layer precedence is undocumented/deny-biased. Therefore, default-deny **must** place the broad block at **Layer 3** (`DenyDeviceClasses = DiskDrive`) and the specific manufacturer/internal-disk exceptions at **Layers 1–2**.

### 2.2 Classic BOT (`USBSTOR`) vs. UASP (`uaspstor` / `SCSI\Disk...`) & External SSDs/HDDs
- **USB Bulk-Only Transport (BOT)**: Enumerates `USB\VID_xxxx&PID_yyyy\<serial>` (`service = USBSTOR`) → child disk `USBSTOR\Disk<Vendor8><Product16><Rev4>\<serial>&0` in class `DiskDrive`.
- **USB Attached SCSI Protocol (UASP / UAS)**: High-speed external NVMe/SATA SSD enclosures enumerate `USB\VID_xxxx&PID_yyyy\<serial>` (`service = uaspstor`, class `SCSIAdapter`) → child disk `SCSI\Disk<Vendor8><Product16><Rev4>\...` in class `DiskDrive`.
- **Implication**:
  1. Blocking `USBSTOR` alone misses all UASP external SSDs/HDDs. Blocking setup class `DiskDrive` (`{4d36e967-e325-11ce-bfc1-08002be10318}`) covers **both** BOT flash drives and UASP external SSDs/HDDs while leaving keyboards (`Keyboard`), mice (`Mouse`), HID (`HIDClass`), printers (`Printer`), and USB hubs (`USB`) untouched.
  2. Conversely, `SCSI\Disk<Vendor8>` is shared between UASP USB drives and internal SATA/SAS/NVMe-translation disks. Allowing `SCSI\DiskSanDisk_` permits internal SanDisk SSDs too (benign), whereas USB-SATA bridge chips that report generic INQUIRY strings (`ASMT`, `JMicron`, `Realtek`, `Generic`, `VendorC`) **cannot** be allowlisted at brand level without allowing all enclosures using that bridge chip. RustWard rejects reserved generic vendor strings (`RESERVED_GENERIC_VENDORS`) fail-closed.

### 2.3 Already-Installed Devices & Retroactive Hazard
- By design in Windows PnP, `DenyDeviceClasses` with `DenyDeviceClassesRetroactive = 0` prevents **new** driver installations and driver updates, leaving **already-installed** USB drives cached in the PnP tree (`HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\...`) functional when reconnected.
- Enabling `DenyDeviceClassesRetroactive = 1` on `DiskDrive` instructs Windows to tear down already-installed disks — Microsoft explicitly warns this can block access to the **OS boot disk** if any mismatch or early-boot evaluation edge case occurs. **RustWard strictly forbids `DenyDeviceClassesRetroactive = 1`.**
- To block an **already-installed** unauthorized USB drive safely on Windows 10 Pro:
  - **Option A (Verified Safe in VM)**: Apply a **narrow, device-specific** `DenyDeviceIDs` rule (`USBSTOR\DiskKingston...`) with `DenyDeviceIDsRetroactive = 1` (never touches `PCI\...` / `NVME` system disks).
  - **Option B (Manual Cleanup before Non-Retroactive Class Profile)**: Administrator manually uninstalls unauthorized `USBSTOR` / USB `DiskDrive` devnodes in Device Manager (`assess-installed` / Readiness checklist) before or after enabling the non-retroactive `DiskDrive` class profile; subsequent reconnects are then treated as new installations and blocked (`Code 28`).

### 2.4 Administrator Override & Policy Persistence (`AllowAdminInstall` & `Registry.pol`)
- **`AllowAdminInstall`**: When *Not Configured* or *Disabled* (`0`), Device Installation Restrictions apply equally to standard users and local Administrators during PnP installation. However, any user with local Administrator privileges can open `gpedit.msc` or edit `Registry.pol` to remove the policy. Endpoint enforcement therefore requires workstation operators to run as **Standard Users**, with Administrator credentials held separately.
- **Why Direct Registry Writes Are Defective (`B3`)**: Writing `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` via `RegSetValueExW` without updating `%SystemRoot%\System32\GroupPolicy\Machine\Registry.pol` via COM `IGroupPolicyObject` leaves the Local GPO store out of sync: `gpedit.msc` shows *Not Configured*, and background Group Policy refresh (`gpsvc` / `gpupdate`) overwrites or deletes the keys.
- **Security Review Gate Preserved (`B1`)**: Automated privileged policy writing remains intentionally disabled (`ACTIVATION_ENABLED = false`). RustWard provides read-only inspection, safety preflight, exact administrator checklists, session baseline capture, live `CM_PROB_*` denial observation, and rollback verification without circumventing the security review boundary.

---

## 3. Distinction Between Identity, Installation & Data-Access Claims

Per Sections 2 & 7, RustWard enforces and documents five distinct concepts:

1. **Reported Manufacturer String**: Unauthenticated text read from USB descriptors or 8-byte SCSI `INQUIRY` vendor fields (e.g. `Kingston`, `SanDisk`, `VendorC`). Trivially forgeable by programmable USB microcontroller firmware (BadUSB / custom mass-storage firmware).
2. **Matching Hardware-ID Rule**: Prefix match performed by Windows PnP against `DEVPKEY_Device_HardwareIds` / `CompatibleIds` (e.g. `USBSTOR\DiskKingstonDataTraveler_3.0____`). Proves syntactic string match only.
3. **Verified Manufacturer Identity**: Cryptographic hardware authentication (e.g. signed device certificate / smart-card APDU attestation). **Not supported** by standard USB Mass Storage (`BOT`/`UASP`) or Windows Device Installation Restrictions (`authenticated` is always `false`).
4. **Successfully Installed Device**: Windows PnP matched an INF (`disk.inf`), started the function driver (`disk.sys`), and reported `CM_PROB == 0` (`DN_STARTED`).
5. **Genuinely Blocked Data Access**: When Windows aborts `DiskDrive` installation (`Code 1` / `Code 28`), `disk.sys` never attaches, no `\Device\HarddiskN` or `Volume` object is created, and Explorer/Win32 filesystem paths (`E:\`, `F:\`) do not exist. However, PnP installation denial alone does **not** prove that raw USB control/bulk transfers via custom `WinUSB`/`libusb` drivers or non-`DiskDrive` composite interfaces (HID, MTP/WPD, CD-ROM CDFS partition) were tested unless separately verified.
