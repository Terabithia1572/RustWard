# Phase 6 — Preflight safety assessment (VM, read-only)

**Date:** 2026-11-08, 01:29–01:36 (Europe/Istanbul).

**Authorization:** the owner authorized read-only analysis and VM snapshot
preparation only. **Not authorized:** the four Group Policy changes, device
uninstallation, and the read-deny test. **None of them were performed.**

Target: the authorized VMware VM "Windows 10 x64", Windows 10 Pro 22H2,
build 19045. Nothing was changed on the Windows 11 host or any production
machine.

## 1. Storage inventory of the VM

Sources: Device Manager in the VM (view by type, **hidden devices shown**),
device properties (Details tab, read-only), VMware VM settings (viewed, then
closed with Cancel), and RustWard's SetupAPI inventory.

### Virtual hardware (VMware)

| Device | Setting |
|---|---|
| Hard disk | NVMe 0:0, 60 GB, file `D:\Windows10VM\Windows 10 x64-000007.vmdk` (snapshot delta). Mode: **not independent**, so it is included in snapshots. Host free space 663 GB. |
| CD/DVD | SATA, ISO-backed |
| USB controller | Present (USB 3.x) |

### Windows devices

| Class | Device | Notes |
|---|---|---|
| **Disk drives** (`DiskDrive {4d36e967-…}`) | VMware Virtual NVMe Disk | **System/boot disk.** Instance `SCSI\DISK&VEN_NVME&PROD_VMWARE_VIRTUAL_N\5&25A13950&0&000000`; parent `PCI\VEN_15AD&DEV_07F0&SUBSYS_07F015AD&REV_00\…` (VMware NVMe controller). Not on USB. |
| Disk drives | Kingston DataTraveler 3.0 USB Device | USB, parent `USB\VID_0951&PID_1666&REV_0001` |
| Disk drives | VendorC ProductCode USB Device | USB, parent `USB\VID_346D&PID_5678&REV_0320` |
| Disk drives, hidden (non-present) | **none** | No stale disk instances that could reappear |
| Storage controllers (`SCSIAdapter`) | Standard NVM Express Controller; Microsoft Storage Spaces Controller | Not DiskDrive class. No Storage Spaces virtual disks exist. |
| IDE ATA/ATAPI controllers (`hdc`) | Standard SATA AHCI Controller; Intel 82371AB/EB PCI Bus Master IDE Controller; ATA Channel 0/1 | Not DiskDrive class |
| DVD/CD-ROM (`CDROM`) | NECVMWar VMware SATA CD01 | Not DiskDrive class |
| USB controllers (`USB`) | USB 3.20 xHCI host controller; EHCI; UHCI; 3 root hubs; USB Composite Device (VMware virtual keyboard/mouse); 2 × USB Mass Storage Device | Not DiskDrive class |
| Storage volumes (`Volume`) | 9 entries (some non-present) | Not DiskDrive class; they exist only on top of an installed disk |
| Portable devices (`WPD`) | E:\, VTOYEFI (×n) | Created for removable volumes |
| Keyboard, mouse, HID | VMware PS/2 and USB HID devices | Classes Keyboard, Mouse, HIDClass |

## 2. Policy precedence and the effect on critical disks

According to Microsoft Learn (*Manage device installation with Group
Policy*; Policy CSP DeviceInstallation):

1. **Precedence with layered evaluation on:** device instance IDs > device
   IDs > device setup class > removable devices. The more specific match wins.
   Without layering, every *Prevent* policy wins over every *Allow* policy.
   Microsoft does not document what happens when an allow and a prevent
   match at the **same** layer. The proposed profile has no same-layer
   conflict: the allows are device IDs and instance IDs, and the prevent is a
   class.
2. **Class prevent scope.** Users "can't install **or update** devices" of
   the listed class. **Existing installs are not affected** unless "also apply
   to matching devices that are already installed" is checked. After an
   uninstall, the device cannot be reinstalled.
3. **Retroactive warning (Microsoft):** "Preventing retroactive all Disk
   Drives could block the access to the disk on which the OS boots with."
   RustWard never sets it. The profile writes `DenyDeviceClassesRetroactive = 0`,
   and preparation is refused otherwise.
4. **Matching uses hardware IDs and compatible IDs.** The VendorC/Kingston
   disks also carry the generic IDs `USBSTOR\GenDisk` / `GenDisk`. RustWard's
   allow list contains neither, and RustWard refuses generic IDs in any list
   it generates.
5. "Allow administrators to override Device Installation Restriction
   policies" is **not configured** in the baseline. Administrators are
   therefore subject to the rules as well.

### Effect of the proposed profile, per device

| Device | Install state | Proposed profile | Expected effect |
|---|---|---|---|
| NVMe system disk | Installed | DiskDrive class prevent (layer 3) **and** instance-ID allow (layer 1) | **Not affected.** The rule is not retroactive, and the instance allow outranks the class for updates and reinstalls. |
| A new or replacement internal disk, a VHD/VHDX mount, a Storage Spaces virtual disk | Not installed | Class prevent, no allow | **Blocked.** This is a known limitation, and nothing like it exists in the VM. |
| The same NVMe disk under a new instance ID (controller type or slot change) | — | Class prevent, no allow | **Blocked.** Boot-risk scenario (L-34). Avoided by not changing the VM's controller during the test; the snapshot is the recovery. |
| CD/DVD, controllers, hubs, volumes, WPD, keyboards, mice, printers | Installed | Not DiskDrive class | Not affected |
| Kingston, VendorC sticks | **Installed** | Class prevent, no allow | **Not affected** (installed before the rule). Denial only appears after an uninstall or for a new stick. |

**Conclusion.** With layered evaluation on, the class rule not retroactive,
and the NVMe instance allow in place, the existing system disk is outside the
effective scope, by Microsoft's documented precedence. This is a documented
expectation, **not an observation**. It becomes evidence only after the
authorized experiment.

## 3. Identity of the stick said to be SanDisk

| Source | Value |
|---|---|
| USB VID/PID, revision | `346D:5678`, `0320` |
| USB bus-reported product string | `Disk 20` |
| SCSI INQUIRY vendor / product / revision | `VendorC` / `ProductCode` / `3.20` |
| Windows hardware IDs | `USBSTOR\DiskVendorC_ProductCode____3.20`, `USBSTOR\DiskVendorC_ProductCode____`, **`USBSTOR\DiskVendorC_`**, `USBSTOR\VendorC_ProductCode____3`, `VendorC_ProductCode____3`, `USBSTOR\GenDisk`, `GenDisk` |
| SanDisk registry VIDs (public usb.ids) | `0781`, `0871`. **Not 346D.** |

Every source the device reports is generic. Nothing identifies SanDisk.

- The proposed allow IDs `USBSTOR\DiskSanDisk_` / `SCSI\DiskSanDisk_` **do
  not match** this stick. Under the profile it would be **denied** once it is
  reinstalled.
- The owner earlier corrected the physical label of this stick to ASELSAN.
  Either way, its electronic identity is not SanDisk.
- **No genuine SanDisk device has been inspected.** The SanDisk allow IDs
  remain unverified.

## 4. Snapshots and rollback

### Snapshot chain (VMware Snapshot Manager)

The chain is linear and intact:

1. Snapshot 1
2. before-rustward-install
3. rustward-working-before-kingston-test
4. rustward-observer-before-guided-test
5. rustward-before-phase5-8dfecd1
6. rustward-before-phase6-c9b6c0e (01:12:20)
7. **rustward-phase6-before-profile-test (2026-11-08 01:22:26, with memory)**
8. You Are Here

The NVMe disk is not independent, so it is covered.

The VM state at the last snapshot:

- RustWard Phase 6 build installed
- RustWard policy v11 (target policy)
- a default-deny profile session prepared (audit only)
- **no** Device Installation Restrictions key
- Removable Storage Access not configured

Since then only Device Manager views were opened. One accidental click hit a
power-management checkbox label in a device's properties. The dialog was
closed with **Cancel**, so nothing was applied; the checkbox shows unchecked.

### Rollback levels (fastest first)

| Level | When | Procedure |
|---|---|---|
| R1 — RustWard-verified rollback | The guest works | In the VM, run `gpedit.msc` and set the 4 settings to **Not Configured**, then run `gpupdate /force`, then RustWard **Geri almayı doğrula** (compares the live policy with the saved baseline: no Restrictions key) |
| R2 — Reinstall | A stick stays in Code 28 after R1 | Reconnect it, or use Device Manager › Scan for hardware changes (the VM-observed Kingston reinstalled automatically after rollback, 2026-11-07) |
| R3 — VMware snapshot revert (offline, host side) | Anything unexpected, including no boot | VMware › VM › Snapshot › Revert to **rustward-phase6-before-profile-test**. This works without the guest. USB stick contents are not part of the snapshot, but nothing is written to them. |
| R4 — Offline guest repair (if a snapshot were unusable) | The guest does not boot | Boot into WinRE, then a command prompt: `reg load HKLM\OFF C:\Windows\System32\config\SOFTWARE` → `reg delete "HKLM\OFF\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /f` → `reg unload HKLM\OFF`. **Also** neutralize the local GPO, which re-applies the values at boot: `ren C:\Windows\System32\GroupPolicy\Machine\Registry.pol Registry.pol.rustward-bak`. This also removes any other local machine policies; restore them later. |

R1–R2 were VM-verified for the single-device rule on 2026-11-07. R3 is the
primary safety net; it has not been executed in this phase. R4 is documented
only and not rehearsed.

## 5. Feasibility of the actual requirement

| Requirement | Achievable in Windows 10 Pro? | Evidence | Status |
|---|---|---|---|
| Deny Kingston | **Yes**, by device-ID deny (vendor-level `USBSTOR\DiskKingston`, retroactive) or via the class profile for new installs | Model-level ID verified in the VM (Code 1/28, rollback OK) | Model-level verified; vendor-level not yet |
| Deny Seagate | Yes, same mechanism | No Seagate hardware | Unverified |
| Deny all other or unknown USB storage | **Only for new installations** (class profile). Already-installed sticks need per-device retroactive rules or an administrator uninstall. | Planned and preflight-checked | **Not verified** (experiment not authorized) |
| Allow SanDisk | Expressible as `USBSTOR\DiskSanDisk_` / `SCSI\DiskSanDisk_`; trusts a firmware string | No genuine SanDisk available; the 346D stick is not SanDisk | **Unverified** |
| Allow TÜBİTAK / SIR II | **Not possible today:** no identifier is known | SIR II not inspected | **Blocked** by missing data |
| Keyboards, mice, printers unaffected | Yes: different classes, no USB/HID class rules | Device-ID rule: verified in the VM | Profile: not verified |
| Internal disks unaffected | Yes for existing disks (non-retroactive + instance allow). **No** for new or replacement disks. | Documented precedence | Not verified |
| Read/write blocking per manufacturer | **No.** Removable Storage Access is class-wide; there is no per-brand read/write control without Defender for Endpoint (cloud/licence) or a custom filter driver. | — | Not achievable offline with built-in tools |
| Authenticated manufacturer | **No.** All identifiers are self-reported. | — | Not achievable |

## 6. What prevents RustWard from managing the policy from its interface

| # | Blocker | Kind | What would lift it |
|---|---|---|---|
| B1 | An earlier implementation of an automated privileged policy writer was **stopped by a safety review**. The owner then ruled out bypassing it through another API, registry writer, PowerShell, service, scheduled task or indirect mechanism. | Safety boundary (**BLOCKED**) | A decision outside this workstream, with its own security review. Not something this project can work around. |
| B2 | `ACTIVATION_ENABLED = false`; activation gates such as `vm_validation` are hard-wired NotMet. | Design gate | Only meaningful after B1 |
| B3 | Writing `HKLM\SOFTWARE\Policies\…` directly bypasses the local GPO store (`Registry.pol`). Group Policy can overwrite or remove such values at the next refresh, and gpedit would not show them. A correct implementation needs the Local Group Policy API (`IGroupPolicyObject`). | Technical | Design work, after B1 |
| B4 | The default-deny profile has not been verified in the VM: no observed denial and no observed internal-disk safety. | Evidence | The authorized experiment (4 settings, uninstall, rollback) |
| B5 | Identity: no TÜBİTAK identifiers, no genuine SanDisk, and the 346D stick is generic | Data | Physical inspection of SIR II and genuine SanDisk units |
| B6 | Already-installed unauthorized sticks are not covered by the class profile. | Mechanism | Per-device retroactive rules or administrator uninstall, each authorized |
| B7 | Unsigned binaries; no in-app elevation (app must be started "as administrator") | Deployment | Code signing; an elevation helper |
| B8 | The VM still has catalog `2026.11.05-phase1`; MSI upgrades do not update an existing catalog. | Product gap | A catalog update path |

## 7. Simulation stays separate

In the VM, the *Engellenen cihazlar* page shows "Şu an Windows'un kurulumunu
reddettiği bağlı cihaz yok". The Kingston appears only as **past** evidence
(7.11.2026 19:58, Code 1). Both sticks are listed under **Simüle edilen
retler (uygulanmadı)** as "Uygulanmadı — yalnızca simüle karar".

The dashboard shows "Windows koruması etkin değil". The notice "USB
engellenmiştir…" requires a connected device with real Windows denial
evidence, and none exists. This matches the real state: no Windows rule is
configured.
