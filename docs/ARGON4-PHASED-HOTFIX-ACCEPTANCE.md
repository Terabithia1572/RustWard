# RustWard 2 — Phase D Hotfix Acceptance Report (PASS)

## Milestone Overview

- **Milestone:** Phase D Hotfix — SanDisk UASP (SCSI) & Kingston USBSTOR Simultaneous Enforcement
- **Date Verified:** 2026-11-12
- **Result:** **PASS (100% Verified in Windows 10 VM)**
- **Verification Environment:** Windows 10 Pro 22H2 x64 (Isolated Test VM)

---

## 1. Problem Statement & Root Cause

### Reported Defect
When SanDisk was configured as DENIED in the manufacturer management policy, Windows 10 continued to permit access to the SanDisk USB storage volume (`ACRONIS_MEDIA`).

### Root Cause Analysis
1. **Transport & Enumerator Difference:** Standard USB flash drives use the `USBSTOR` enumerator (`USBSTOR.sys`), producing hardware IDs with `USBSTOR\Disk...` prefix. The physical SanDisk 3.2Gen1 device utilizes the USB Attached SCSI Protocol (`UASPStor.sys`), enumerated by Windows under the `SCSI` device class with IDs formatted as `SCSI\Disk...`.
2. **Generic SCSI Vendor Padding:** In SCSI INQUIRY responses, the device returned padded generic vendor string `_____USB`, with the brand name located in the product field (`SanDisk 3.2Gen1`). Windows PnP therefore generated hardware IDs such as `SCSI\Disk_____USB_SanDisk_3.2Gen1`.
3. **Policy Compiler Gap:** The compound policy compiler previously generated only `USBSTOR\DiskSanDisk_` identifiers, causing a string mismatch in Windows Device Installation Restrictions (`DenyDeviceIDs`).

---

## 2. Technical Solution

1. **UASP Hardware ID Generation:** Added SCSI-namespace identifiers (`SCSI\DiskSanDisk_`, `SCSI\Disk_____USB_SanDisk_`, `SCSI\_____USB_SanDisk_`) to `crates/rustward-enforcement/src/compound_policy.rs`.
2. **Generic ID Safeguards:** Enhanced `is_generic_storage_id` to strictly reject generic SCSI vendor IDs (`SCSI\DISK_____USB`, `SCSI\DISKUSB`, `SCSI\_____USB`, `SCSI\Disk`, `SCSI\RAW`) from enterring deny lists.
3. **System Disk & Input Safety Invariants:** Enforced that internal NVMe/SCSI system disks, VMware disks, and HID input devices can never be targeted or restarted.
4. **Core Identity Resolution:** Updated `crates/rustward-core/src/evaluate.rs` to correlate brand identity from product strings and USB ancestor VIDs when INQUIRY vendor is generic `_____USB`.
5. **GPO Writer Alignment:** Unified GPO hardware ID validation with compound policy safety rules.
6. **Targeted Recovery:** Improved `crates/rustward-app/src/guided.rs` to restart parent USB devnodes (`USB\VID_...`) when child UASP disks require recovery.
7. **UI Status Consistency:** Reconciled contradictory protection badges and notifications in desktop frontend.

---

## 3. Verified Acceptance Evidence

| Scenario | Target Device | Effective Windows Policy | Windows PnP State | SetupAPI Engine Result | Storage Access |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Both Denied** | SanDisk (UASP `0781:55A3`)<br>Kingston (USBSTOR `0951:1666`) | `DenyDeviceIDs` (18 rules)<br>`DenyDeviceIDsRetroactive = 1` | `DIF_REMOVE`<br>Problem Code 28 | `exit(0xe0000248)`<br>(`ERROR_POLICY_DENIED`) | Volumes unmounted and completely inaccessible |
| **SanDisk Allowed** | SanDisk (UASP `0781:55A3`) | Purged from `DenyDeviceIDs`; added to `AllowDeviceIDs` | Status `OK` (Code 0)<br>`UASPStor.sys` loaded | `exit(0x00000000)` | Volume mounted and accessible (Read-only listing OK) |
| **Kingston Denied** | Kingston (USBSTOR `0951:1666`) | Retained in `DenyDeviceIDs` | Blocked / Code 28 | `exit(0xe0000248)` | Inaccessible; Windows toast: *"Installation forbidden by system policy"* |
| **SanDisk Reconnect** | SanDisk (UASP `0781:55A3`) | Unchanged | Status `OK` (Code 0) | `exit(0x00000000)` | Accessible |
| **Clean Rollback** | All devices | `DeviceInstall_Restrictions`: Absent | Baseline restored | Restrictions absent | All volumes accessible; Windows AutoPlay functional |

---

## 4. Invariants & Safety Verification

- **System Disk:** Internal NVMe disk (`C:`) remained healthy and online throughout all test cycles.
- **Input Peripherals:** HID keyboard and mouse remained functional without interruption.
- **Zero Host Impact:** All live tests executed exclusively inside the isolated Windows 10 guest.
- **Audit Integrity:** Policy mutation and observation events recorded in RustWard audit log.
