# Phase 6 — Windows enforcement feasibility (Windows 10 Pro)

**Question:** can Windows 10 Pro, offline and without Active Directory, enforce
the target policy?

> **ALLOW** SanDisk and TÜBİTAK. **DENY** Kingston, Seagate, unknown and every
> other USB storage manufacturer. Keyboards, mice and printers unaffected.

**Answer: only partially, and never as an authenticated manufacturer check.**

- No built-in mechanism matches on an *authenticated* manufacturer. Every
  mechanism matches identity strings the device reports about itself (USB
  VID/PID, SCSI INQUIRY vendor/product). A device can report another vendor's
  values.
- The closest supported design is the layered *Device Installation
  Restrictions* profile (section 2.1). It denies **new installations** of
  every disk except the allowed vendor IDs and the internal disks. It does
  **not** affect devices that are already installed, and it does **not**
  deny read/write access as such.
- **Automatic application by RustWard is BLOCKED.** It is not implemented, and it
  is not reimplemented through another API, registry writer, PowerShell, a
  service or a scheduled task. Every Windows change is made by an
  administrator in `gpedit.msc`; RustWard verifies and audits it.

## 1. Feasibility matrix

| Mechanism | Windows versions (Pro) | Privilege | Exact scope | Identity matching | Already-installed devices | Rollback | System disk impact | Keyboard / mouse / printer impact | Manufacturer-wide default deny? |
|---|---|---|---|---|---|---|---|---|---|
| **A. Device ID deny** (`DenyDeviceIDs`) | Win10 1703+ | Local admin (gpedit) | Devices whose hardware/compatible IDs match a listed string | Self-reported strings; vendor-level `USBSTOR\Disk<Vendor8>` possible | Only with "also apply to installed devices" (retroactive): VM-observed Code 1, then Code 28 on reconnect | Not Configured + `gpupdate /force`; VM-observed: the device reinstalls itself | None if the ID is USB-specific | None if the ID is storage-specific | **Deny-list only** (Kingston, Seagate). Cannot deny "everything else". |
| **B. Instance ID deny** (`DenyInstanceIDs`) | Win10 2004+ | Local admin | One physical device (instance ID includes the serial) | Per device, not per manufacturer | Retroactive option, as A | As A | None | None | No (per-device) |
| **C. Setup-class deny** (`DenyDeviceClasses`, DiskDrive `{4d36e967-…}`) | Win10 1703+ | Local admin | **Every** new disk: USB, internal, virtual (VHD) | None (class only) | Not retroactive in RustWard's plan. Retroactive would target the system disk, so it is **never** used. | As A | **High if retroactive**; non-retroactive blocks new or reinstalled internal disks unless they are allowed by instance ID | None (keyboards/mice/printers are other classes) | Only combined with D + E |
| **D. Device ID allow** (`AllowDeviceIDs`) | Win10 1809+ | Local admin | Devices matching listed IDs, e.g. `USBSTOR\DiskSanDisk_`, `SCSI\DiskSanDisk_` | **Self-reported INQUIRY vendor**; a cloned/rebadged stick can claim "SanDisk" | n/a (allow) | As A | `SCSI\Disk<vendor>` also matches internal disks with the same vendor | None | Provides the **allow** half |
| **E. Layered evaluation** (`AllowDenyLayered`) | Win10 1809 + KB5005102; 1903 build 18362.1714; 2004–22H2 build 19041.1151+; Win11 | Local admin | Order: instance ID > device ID > setup class | n/a | n/a | As A | n/a | n/a | Required so that D overrides C |
| **C+D+E profile** (RustWard "default-deny profile") | As E | Local admin | New disk installations denied except allowed vendor IDs and internal disks (instance-ID allow) | Self-reported | **Not affected.** Unauthorized sticks installed before the profile keep working. They need A or B (retroactive) or an administrator uninstall. | All values Not Configured; RustWard verifies against the saved baseline | Internal disks allowed by instance ID; any **new** internal/virtual disk is blocked until allowed | None expected (other classes); VM check pending | **Closest available.** Installation-time only; identity unauthenticated. |
| **F. Removable Storage Access** (`RemovableStorageDevices\{53f5630d-…}\Deny_Read` / `Deny_Write`, `Deny_All`) | GPO since Vista; Device-scope CSP: Win10 2004 + KB5005101 | Local admin | **All** removable disks (per storage class), regardless of manufacturer | None | Applies to installed devices (access-time check) | Not Configured; may need re-plug or reboot | Internal fixed disks not affected (fixed vs removable); USB HDDs that report "fixed" may not be covered | None | **No.** Cannot allow SanDisk while denying Kingston. Only useful as an all-or-nothing read/write control. |
| **G. Microsoft Defender for Endpoint device control** | Win10/11 with Defender client 4.18.2103.3+ | Licence (MDE Plan 1/2 or Defender for Business) + management | VID/PID/serial/instance, read/write/execute | Self-reported | Yes (access-time) | Policy removal | Configurable | Configurable | **Not available** for an offline, non-onboarded Windows 10 Pro. Not evaluated. |
| **H. Custom filter driver** | — | Kernel driver signing | — | — | — | — | — | — | Out of scope; not attempted |

Sources: Microsoft Learn — Policy CSP DeviceInstallation; *Manage device
installation with Group Policy*; Policy CSP ADMX_RemovableStorage; *Device
control in Microsoft Defender for Endpoint*. Born's Tech and Windows World
(2025-07-07) reports that Removable Storage Access enforcement broke after the
April 2025 cumulative updates on Windows 10 22H2 and Windows 11 23H2, and that
Microsoft acknowledged it. **Do not assume F works on a given patch level
without a VM test.**

## 2. What each requirement maps to

| Requirement | Mechanism | Status |
|---|---|---|
| Deny Kingston | A (vendor-level `USBSTOR\DiskKingston`, retroactive) or the C+D+E profile (new installations) | A verified in the VM for the model-level ID `USBSTOR\DiskKingstonDataTraveler_3.0____` (2026-11-07). Vendor-level ID and profile: **not yet verified** |
| Deny Seagate | As Kingston | No Seagate hardware available. **Not verified** |
| Deny unknown/other manufacturers | C+D+E profile | **Not verified** (VM experiment pending authorization) |
| Allow SanDisk | D with `USBSTOR\DiskSanDisk_` / `SCSI\DiskSanDisk_` | **Not verified**: no genuine SanDisk device. The SanDisk-labelled stick reports `VendorC`/`346D:5678`, so the profile would deny it, which is correct for an unverified identity. |
| Allow TÜBİTAK / SIR II | D | **Impossible today**: no TÜBİTAK identifier is known. SIR II inspection is deferred, and RustWard does not invent identifiers. |
| Keyboards, mice, printers unaffected | A/C/D only target disk IDs and the DiskDrive class | Verified for A (VM). Profile: VM check pending. |
| Read/write denial | F (class-wide) | **Not verified.** An installation denial (Code 1/28) is not treated as read/write proof. |
| Local administrator cannot bypass | — | **Not achievable.** A local administrator can always change or remove these policies. RustWard detects and audits the change (policy re-read, mismatch, rollback verification) but cannot prevent it. |

## 3. Already-installed devices

Install-time rules (A–E) are evaluated when Windows installs a driver for a
device node.

- A stick that was already installed keeps working after a non-retroactive
  rule, even after reconnection, because its device node and driver remain.
- Retroactive A/B removes and blocks the existing node: VM-observed, Code 1
  immediately, Code 28 after reconnect.
- The profile is deliberately **not** retroactive, because a retroactive
  DiskDrive rule would target the system disk.
- RustWard therefore lists every already-installed device the policy denies
  as *not covered* in the profile checklist and in the readiness blockers.
  The administrator decides about each one.

## 4. Offline operation

All mechanisms A–F are local Group Policy. They need no network, domain or
cloud service. G needs cloud onboarding and is excluded.

## 5. Conclusion

Manufacturer-wide **default deny** is technically expressible with the C+D+E
profile, with three hard limits:

1. **Identity is unauthenticated.** "SanDisk" means "reports SanDisk".
2. **Installation-time only.** Already-installed devices need separate
   retroactive device rules. Read/write is not denied as such.
3. **Not tamper-proof against local administrators.**

RustWard presents the profile as an administrator-guided **VM experiment**,
never as active protection. It reports "verified" only while the live policy
equals the verified profile **and** Windows is observed denying a device.
