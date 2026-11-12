# ARGON Phase 6 — Windows 10 Pro VM Read-Only Preflight Report

**Date:** 2026-11-08  
**Inspection Mode:** 100% Read-Only (host-side `.vmx` / `.vmsd` / `vmrun list` / `vmrun listSnapshots` + prior verified VM inventory; **zero** VM power state, hardware, registry, policy, or disk changes executed)

---

## 1. Identified Target Virtual Machine & Host Isolation

| Property | Verified Value |
|---|---|
| Host OS | Windows 11 Pro 25H2 (64-bit, build `26200.8037`) — **untouched** |
| VMware Workstation | `17.6.4` (`vmrun.exe`) |
| Currently running VMs | `0` (`Total running VMs: 0`) |
| Target VM configuration file | `<test-vm>.vmx` (`displayName = "Windows 10 x64"`) |
| Secondary VM found on disk | `<secondary-vm>.vmx` (`0` snapshots — **not** the acceptance target) |
| Guest OS & Build (`.vmx` `guestInfo.detailed.data`) | `Windows 10 Pro, 64-bit (Build 19045.6466)` (`22H2`) |
| Firmware / CPU / Memory | UEFI (`firmware = "efi"`), 2 vCPUs, 2048 MB RAM |
| Clean shutdown / checkpoint state | `cleanShutdown = "TRUE"`, current snapshot `uid = 8` (`rustward-phase6-before-kingston-retest`), active delta disk `Windows 10 x64-000008.vmdk` |

### Critical Isolation Finding in `.vmx` (`sata0:1.fileName`)
Line 44 of `<test-vm>.vmx` currently reads:
```ini
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = "<baseline-workspace>\dist\vm\rustward-test-7.iso"
sata0:1.present = "TRUE"
```
This references the **original** `RustWard` folder's ISO! Per Section 1 & Section 11:
- We **did not modify** `Windows 10 x64.vmx` or `<baseline-workspace>`.
- All new packages and any VM transfer ISO built in this workstream reside strictly inside `<workspace>\dist\`.
- Mounting a `RustWard2` ISO or transferring the updated `RustWard2` MSI into the guest via `vmrun CopyFileFromHostToGuest` will be performed **only after** explicit user approval.

---

## 2. Virtual Storage, Boot Chain & Peripheral Topology

| Component | `.vmx` / PnP Evidence | Risk Under Storage Restrictions |
|---|---|---|
| **Boot / System Disk** | `nvme0:0` (`Windows 10 x64-000008.vmdk`, `nvme0:0.redo = ""`, non-independent — **included in VMware snapshots**). Guest PnP instance: `SCSI\DISK&VEN_NVME&PROD_VMWARE_VIRTUAL_N\5&25A13950&0&000000` under PCIe NVMe controller `PCI\VEN_15AD&DEV_07F0&SUBSYS_07F015AD&REV_00\...`. | **Unaffected** by narrow `USBSTOR\DiskKingston...` device-ID rules. Under a layered `DiskDrive` class rule, requires `DenyDeviceClassesRetroactive = 0` + Layer-1 `AllowInstanceIDs` entry. **Never** run retroactive class-wide `DiskDrive` restrictions. |
| **SATA CD/DVD Drive** | `sata0:1` (`NECVMWar VMware SATA CD01`, class `CDROM`) under `Standard SATA AHCI Controller` (`hdc`). | Outside `DiskDrive` class; unaffected. |
| **USB Controllers & Hubs** | `usb` (UHCI, PCI slot 32), `ehci` (USB 2.0, slot 34), `usb_xhci` (USB 3.x, slot 192) + 3 root hubs (`class = USB`). | RustWard never generates rules for class `USB`; hubs and host controllers remain untouched. |
| **Keyboard & Mouse** | `usb_xhci:4` (`hid`), VMware PS/2 & USB Composite HID input devices (`Keyboard`, `Mouse`, `HIDClass`). | Outside `DiskDrive` class; unaffected. |
| **Known USB Mass Storage Test Sticks** | (1) **Kingston DataTraveler 3.0**: `USB\VID_0951&PID_1666`, `USBSTOR\DiskKingstonDataTraveler_3.0____` (must be reconfirmed live in guest before applying any rule).<br>(2) **VendorC / VendorC USB stick**: `USB\VID_346D&PID_5678`, `USBSTOR\DiskVendorC_ProductCode____3.20` (generic descriptor; never allowlisted). | Target of Stage A (Kingston only); VendorC serves as the negative-selectivity control (must remain unaffected during Stage A Kingston-specific block, and must **never** be formatted or written to). |

---

## 3. Verified VMware Snapshot Chain (`Windows 10 x64.vmsd`)

All 8 snapshots form a clean linear chain covering `nvme0:0`:

1. `uid=1`: `Snapshot 1` (`Windows 10 x64.vmdk`)
2. `uid=2`: `before-rustward-install` (`Windows 10 x64-000001.vmdk`)
3. `uid=3`: `rustward-working-before-kingston-test` (`Windows 10 x64-000002.vmdk`)
4. `uid=4`: `rustward-observer-before-guided-test` (`Windows 10 x64-000003.vmdk`)
5. `uid=5`: `rustward-before-phase5-8dfecd1` (`Windows 10 x64-000004.vmdk`)
6. `uid=6`: `rustward-before-phase6-c9b6c0e` (`Windows 10 x64-000005.vmdk`)
7. `uid=7`: `rustward-phase6-before-profile-test` (`Windows 10 x64-000006.vmdk`)
8. `uid=8` *(Current parent)*: `rustward-phase6-before-kingston-retest` (`Windows 10 x64-000007.vmdk`)

*Historical Note (Recheck Mandatory on Live Boot):* Snapshot 8 was taken prior to a Kingston retest where a session at `01:48:17` may have been prepared in SQLite (`%ProgramData%\RustWard\rustward.db`). Once the user authorizes booting the VM for live read-only inspection, the live guest registry (`HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`), `RemovableStorageDevices`, installed `RustWardService` binary hash, SQLite policy version, and any active/stale guided session **must** be queried live before any mutating step.

---

## 4. Seven-Point Pre-Mutation Safety Gate (Status Before User Authorization)

| # | Mandatory Requirement (Section 11) | Status |
|---|---|---|
| 1 | Produce read-only preflight report | **MET** (this document) |
| 2 | Confirm a new usable VM snapshot (`rustward2-argon4-before-acceptance`) before any MSI upgrade or GPO edit | **READY** — `vmrun snapshot "<test-vm>.vmx" "rustward2-argon4-before-acceptance"` upon approval |
| 3 | Confirm VM system disk is protected by recovery options | **MET** — `nvme0:0` is non-independent (snapshot-backed) + PCI NVMe (`VEN_15AD&DEV_07F0`, non-USB) + 4-tier rollback plan (`ARGON-ROLLBACK-PLAN.md`) |
| 4 | Confirm exact target USB device on live guest | **PENDING LIVE GUEST READ-ONLY CHECK** — reconfirm `USB\VID_0951&PID_1666` & `USBSTOR\DiskKingstonDataTraveler_3.0____` via `rustward-inventory.exe` / `Get-PnpDevice` |
| 5 | Confirm no unapproved device is affected | **MET BY DESIGN FOR STAGE A** — narrow `USBSTOR\DiskKingstonDataTraveler_3.0____` prefix matches zero PCI/NVMe/HID/Hub/VendorC hardware IDs |
| 6 | Confirm exact procedure to restore original Windows policy | **MET** — `gpedit.msc` → *Not Configured* + `gpupdate /force` + RustWard *Geri almayı doğrula* + independent `reg query` check (fallback: snapshot revert) |
| 7 | Obtain explicit user approval for VM boot, snapshot, `RustWard2` MSI upgrade, and Stage A Kingston GPO test | **AWAITING USER APPROVAL** |
