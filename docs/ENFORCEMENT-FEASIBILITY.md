# Enforcement Feasibility — Phase 0

Status: **research complete, nothing tested on Windows yet.** Date: 2026-11-05.

This document answers one question: *which Windows 10 Pro mechanism can stop
unauthorized USB storage before data can be read or written, while letting
approved brands through without per-device registration?*

Labels used below:

- **[DOC]** stated in Microsoft documentation (sources at the end).
- **[ASSUMPTION]** engineering reasoning not yet confirmed on hardware.
- **[UNKNOWN]** must be measured in the lab.

---

## 1. The core constraint: what "brand" means to Windows

Windows never sees a "brand". It sees identifiers reported by device firmware:

| Identifier | Where it comes from | Brand-level? | Usable by Windows policy? |
|---|---|---|---|
| USB VID (`USB\VID_0781&PID_5581`) | USB device descriptor; VID assigned by USB-IF to a company | Yes (per company) | **Only with PID.** There is no VID-only hardware ID [DOC: USBSTOR identifiers list only `USB\VID_v(4)&PID_d(4)&REV_r(4)`]. Allowing a brand by VID means listing every PID — a model allowlist. |
| SCSI INQUIRY vendor (`USBSTOR\DiskSanDisk_`) | 8-byte ASCII field in the storage firmware | Yes, if the firmware reports the brand | **Yes.** USBSTOR generates a vendor-level hardware ID `USBSTOR\t*v(8)`, documented example `USBSTOR\DiskSEAGATE_` [DOC]. |
| Manufacturer string / friendly name | INF file or firmware text | Inconsistent | Not matchable by policy; display only. |
| Serial number / instance ID | Firmware / PnP | No (per device) | Yes, but that is per-device registration, which the requirement rules out. |

**Consequence:** the only identifier that is both brand-level and enforceable by a
supported Windows mechanism is the **SCSI INQUIRY vendor field**, exposed as the
vendor-level hardware ID. It is:

- not authenticated: any device (including a BadUSB-style or reprogrammed
  controller) can report `SanDisk`;
- not guaranteed per brand: some products report a controller or bridge-chip
  vendor (e.g. `JMicron`, `ASMT`, `Generic`) instead of the brand;
- **unknown for Hardware-Encrypted USB** until physically inspected (locked and unlocked).

No supported mechanism offers a stronger identity. Microsoft Defender for
Endpoint device control also matches on VID/PID/serial/instance/friendly-name
strings, which are equally unauthenticated.

---

## 2. Candidate mechanisms

### A. Device Installation Restrictions (Group Policy / DeviceInstallation CSP)

Facts:

- Available on **Pro**, Enterprise, Education [DOC: Policy CSP – DeviceInstallation "Applies to"].
- `EnableInstallationPolicyLayering` ("Apply layered order of evaluation") evaluates
  **Device instance IDs > Device IDs > Device setup class > Removable devices**; more
  specific criteria supersede less specific ones [DOC]. Windows 10 2004 needs KB5004296
  (build 19041.1151) or later [DOC]; 22H2 (19045) builds that are patched include it.
- Allow-by-device-ID matches when "Plug and Play hardware ID or compatible ID appears
  in the list", unless a prevent rule at the same or higher layer matches [DOC].
- Prevent rules have an optional **retroactive** flag (`DeviceInstall_*_Deny_Retroactive`)
  [DOC]. Without it, **already-installed devices are not affected** [ASSUMPTION
  consistent with docs; must be verified].
- The old "not described by other policy settings" catch-all is deprecated in favour of
  layering [DOC].

Candidate configuration (computed by `rustward-core::plan`, **never applied in Phase 1**):

1. Enable layered evaluation.
2. Prevent setup class **DiskDrive** `{4d36e967-e325-11ce-bfc1-08002be10318}`, **not retroactive**
   (retroactive would include the system disk).
3. Allow device IDs `USBSTOR\Disk<vendor8>` (bulk-only) and `SCSI\Disk<vendor8>` (UASP) for
   each allowed brand's INQUIRY vendor.
4. Allow device **instance** IDs of every existing non-USB disk (baseline), so internal disks
   stay installable after driver updates.

Why it blocks *before* access: if the disk devnode cannot install, no disk driver
binds, no partition/volume is created and there is nothing to read or write
[ASSUMPTION — the central claim to test in Phase 2].

Problems:

| # | Problem | Severity |
|---|---|---|
| A1 | **Previously installed devices** keep working (install-time control). Every unauthorized USB disk ever connected — present or not — must be removed from the PnP database under a reviewed baseline procedure, or the retroactive option used on a narrower rule. | High |
| A2 | Brand identity = INQUIRY vendor: spoofable; may be generic; unknown for Hardware-Encrypted USB. | High (residual) |
| A3 | `SCSI\Disk<vendor>` IDs are shared with internal SATA/NVMe and virtual disks. Allowing `SCSI\DiskSanDisk_` also allows an internal SanDisk SSD (harmless), and a UASP device reporting the vendor of an allowed internal disk would pass. Vendor-level padding in the SCSI namespace is [UNKNOWN]. | Medium |
| A4 | DiskDrive prevent also blocks new internal disks, VHD/VHDX mounts, iSCSI/Storage Spaces disks until allowed. | Medium (operational) |
| A5 | USB CD/DVD (CDROM class) and MTP/PTP phones (WPD class) are separate classes; not covered unless explicitly added (scope decision). The decision engine flags both as `enforcement_gap`. | Medium |
| A6 | A local administrator can remove the policy. Protection assumes operators are standard users. | Inherent |
| A7 | Behaviour for devices that re-enumerate (Hardware-Encrypted USB unlock) or devices without serial numbers on new ports must be measured. | [UNKNOWN] |

### B. Removable Storage Access policies

- Deny read/write/execute per category: CD/DVD, floppy, **removable drives** (USB/1394, "both
  hard disk drives and flash memory drives"), tape, WPD, and custom setup-class GUIDs [DOC].
- Granularity is the **whole category or setup class**; there is no per-vendor or per-device
  exception [DOC: no exception mechanism is described].
- **Verdict: cannot express "allow SanDisk, deny Kingston".** A global deny would also block
  approved brands, which the requirement forbids. Not usable as the primary mechanism. Could
  be a backstop only if paired with a mechanism that grants exceptions — none exists natively.

### C. File-system minifilter (custom kernel driver)

- Can deny `IRP_MJ_CREATE` per volume before any read/write; can enforce read-only; works on
  already-installed devices at runtime.
- Identity source is the same INQUIRY/USB data (`STORAGE_DEVICE_DESCRIPTOR` vendor/product), so
  **no better brand identity** than A.
- Raw-disk access (`\\.\PhysicalDriveN`) bypasses volume filters; covering it needs a disk
  filter driver as well. Raw access requires administrator rights by default.
- Signing: since Windows 10 1607 new kernel drivers must be signed through the Windows
  Hardware Dev Center; an **EV code-signing certificate** is required to open the dashboard
  account; attestation signing (no HLK) is accepted on Windows 10 client [DOC]. Requires an
  online signing step at build time (deployment can stay offline).
- Rust: `windows-drivers-rs` states it "is not yet recommended for production use"; the
  crates.io crates support KMDF 1.33 only and nothing documents minifilter support. A
  production minifilter should be written in C/C++ with the WDK. **The WDK is not installed**
  on the development machine.
- Kernel bugs crash the workstation (BSOD); needs Driver Verifier, HLK-style stress testing,
  and a safe-mode/WinRE recovery path.
- **Verdict:** technically the strongest pre-access control, highest cost and risk. Fallback
  only if A fails acceptance (especially A1/A7).

### D. Microsoft Defender for Endpoint device control

- Matches VID, PID, VID_PID (wildcards), serial, instance path, hardware ID, friendly name;
  read/write/execute granularity; covers removable SSD/UAS [DOC].
- Requires an MDE Plan 1/Plan 2 or Defender for Business license [DOC]; device must run
  anti-malware client 4.18.2103.3+ [DOC].
- MDE minimum requirements: "Internet connectivity on devices is required either directly or
  through a proxy" [DOC]. Air-gapped onboarding is not documented. Whether GPO-deployed device
  control works on a never-onboarded machine is **not documented** [UNKNOWN]; relying on it
  would be a licensing and support risk.
- **Verdict: not viable** for five air-gapped standalone PCs unless the organization already
  holds MDE licenses *and* Microsoft confirms offline device-control support in writing.

### E. User-mode reaction (service disables the device on arrival)

- `CM_Disable_DevNode`/`SetupDiChangeState` after an arrival notification.
- Races the storage stack: the volume can mount and be read before the service reacts;
  fails open if the service is stopped. Violates non-negotiable rules 3 and 10.
- **Verdict: rejected** as an enforcement mechanism. Arrival notifications
  (`CM_Register_Notification`) are used only for telemetry.

### F. BitLocker To Go write policy (considered for completeness)

- "Deny write access to removable drives not protected by BitLocker", optionally restricted to
  drives with the organization's identification field.
- Blocks **write only**; reads remain possible; identity is BitLocker metadata, not brand;
  would conflict with Hardware-Encrypted USB hardware encryption. **Rejected.**

---

## 3. Feasibility matrix

| Criterion | A. Device Install Restrictions | B. Removable Storage Access | C. Minifilter driver | D. MDE device control | E. User-mode disable |
|---|---|---|---|---|---|
| Windows 10 Pro | Yes [DOC] | Yes | Yes (signed driver) | Yes, with MDE license | Yes |
| Brand-level allowlist | **Partial**: INQUIRY vendor only; spoofable; generic vendors impossible | **No** | Partial (same identity data) | Partial (VID wildcard; spoofable) | Partial |
| Pre-access blocking | Yes for new installs [ASSUMPTION, Phase 2 test] | Yes, but all-or-nothing | Yes | Yes [DOC] | **No** (race) |
| Previously installed devices | **No** without baseline cleanup or retroactive rule | Yes | Yes | Yes | Yes (reactive) |
| New devices | Yes | Yes | Yes | Yes | Reactive |
| Offline | Yes (local policy) | Yes | Yes (signing step online at build time) | **No/undocumented** | Yes |
| Privileges | Admin to configure | Admin to configure | Admin + driver install | Admin + license | SYSTEM service |
| Driver required | No | No | **Yes**, Microsoft-signed | No (Defender) | No |
| Survives UI/service stop, reboot | Yes (OS policy) | Yes | Yes (boot/system start) | Yes | **No** |
| Main limitations | A1–A7 above | No exceptions | Kernel risk; signing; raw-disk bypass needs extra filter | License + cloud | Fails open |
| Complexity | Medium | Low | **Very high** | Low technically, high commercially | Medium |
| Testing needed | Full hardware matrix | n/a | Matrix + Driver Verifier + stress | n/a | n/a |
| Operational risk | Medium (blocks new disks/VHDs; admin recovery needed) | Low | High (BSOD, update breakage) | Medium | High (false sense of security) |

---

## 4. Blockers to true, pre-access, brand-based read/write denial

1. **No authenticated brand identity exists** in USB or SCSI. Every mechanism (A–E) can be
   defeated by a device that reports an approved vendor string. This is a residual risk, not
   something software can fix. → requires written risk acceptance.
2. **Brand ≠ INQUIRY vendor for all products.** Products reporting a controller/bridge vendor
   cannot be allowed at brand level without also allowing every product using that controller.
   Such products must be denied (or handled by an explicit, documented model-level exception
   that the business owner approves — not done silently).
3. **Hardware-Encrypted USB identifiers are unknown.** If its INQUIRY vendor is generic, brand-level
   allowlisting of Hardware-Encrypted USB is impossible with mechanism A and the requirement cannot be met
   for that brand.
4. **Previously installed devices** are not re-evaluated by mechanism A (A1).
5. SCSI-namespace vendor-level ID format and UASP behaviour are unverified (A3).
6. Scope of CD/DVD, MTP/PTP, Thunderbolt/PCIe enclosures must be decided explicitly (A5).
7. **Windows 10 lifecycle:** Windows 10 support ended 2025-10-14; consumer ESU covers until
   October 2026 and commercial ESU can extend to 2027/2028 for a fee. A security product on
   unpatched Windows 10 inherits that exposure. Confirm the ESU status or Windows 11 plan for
   the five workstations.

---

## 5. Decision

- **Candidate mechanism: A — Device Installation Restrictions with layered evaluation**,
  allowing vendor-level INQUIRY hardware IDs and preventing the DiskDrive class, plus a
  reviewed baseline cleanup of already-installed USB disks.
- **Fallback:** C (C/C++ minifilter, attestation-signed) only if A fails acceptance on
  previously installed devices or Hardware-Encrypted USB re-enumeration, and only with separate approval.
- **Rejected:** B (no exceptions), D (licensing/connectivity), E (race, fail-open), F.

**Recommendation: CONDITIONAL GO** for a Phase 2 *test-only* proof of concept of A on an
isolated, sacrificial Windows 10 Pro 22H2 machine. **NO-GO** for any claim of
"unspoofable" or "all models of a brand" protection, and no production deployment until the
Phase 2 conditions below are met.

Phase 2 GO conditions:

1. Hardware-Encrypted USB inspected (locked and unlocked) and its INQUIRY vendor is distinctive, non-generic.
2. At least three SanDisk models of different capacity/generation report the same INQUIRY vendor.
3. A denied device produces no disk, no volume and no readable file (Explorer, `CreateFile`,
   volume path, mount point), verified on a new install **and** after baseline cleanup.
4. Keyboard, mouse, printer and internal disks are unaffected across reboot.
5. The rollback procedure in `RECOVERY-PLAN.md` restores the baseline exactly.
6. The business owner accepts residual risks L-01..L-05 in `KNOWN-LIMITATIONS.md` in writing.

---

## Sources

- Microsoft, *Policy CSP – DeviceInstallation*: https://learn.microsoft.com/windows/client-management/mdm/policy-csp-deviceinstallation
- Microsoft, *Identifiers Generated by USBSTOR*: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-generated-by-usbstor-sys
- Microsoft, *Manage Device Installation with Group Policy*: https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy (could not be fetched from this environment; the CSP page above covers the same policies)
- Microsoft, *Control Read or Write Access to Removable Devices or Media* (archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc730808(v=ws.10)
- Microsoft, *Device control overview (MDE)*: https://learn.microsoft.com/en-us/defender-endpoint/device-control-overview
- Microsoft, *Device control policies (MDE)*: https://learn.microsoft.com/en-GB/defender-endpoint/device-control-policies
- Microsoft, *Minimum requirements for MDE*: https://learn.microsoft.com/en-us/defender-endpoint/minimum-requirements
- Microsoft, *Deploy device control using Group Policy*: https://learn.microsoft.com/en-us/defender-endpoint/device-control-deploy-manage-gpo
- Microsoft, *Kernel-mode code signing policy*: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-
- Microsoft, `windows-drivers-rs` README: https://github.com/microsoft/windows-drivers-rs
- Windows Central, Windows 10 ESU pricing/dates: https://www.windowscentral.com/software-apps/windows-10/windows-10-extended-support-pricing-revealed
- Tauri, *Windows Installer*: https://v2.tauri.app/distribute/windows-installer/
- Public USB ID registry: https://github.com/usbids/usbids
