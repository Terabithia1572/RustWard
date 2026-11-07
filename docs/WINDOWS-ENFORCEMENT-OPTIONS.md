# Windows 10 Pro USB storage enforcement options (Phase 5 review)

Status of **automatic policy application by RustWard: BLOCKED.** An earlier
attempt to implement a privileged policy writer was stopped by a safety
review. It is not reimplemented through any other API, executable, service,
registry path or indirect mechanism. The supported path stays the verified
**administrator-guided workflow**: the administrator applies the policy in
`gpedit.msc`, and RustWard saves the baseline, re-reads, verifies, audits and
verifies the rollback.

Everything below is read from Microsoft documentation (sources at the end) or
observed in the authorized Windows 10 Pro VM. It is marked accordingly.

## 1. Device Installation Restrictions (Group Policy) — the only verified mechanism

Path: Computer Configuration → Administrative Templates → System → Device
Installation → Device Installation Restrictions.

| Item | Detail |
|---|---|
| **Settings** | "Prevent installation of devices that match any of these device IDs" (`DenyDeviceIDs`). Optional settings: device instance IDs (`DenyInstanceIDs`), setup classes (`DenyDeviceClasses`), Allow lists, and "Apply layered order of evaluation…" (`AllowDenyLayered`). |
| **Windows versions** (Policy CSP) | Device IDs: 1703+. Setup classes: 1703+. Allow device IDs: 1809+. Instance IDs: 2004+. Layered evaluation: 1809 with KB5005102, 1903 (18362.1714), 2004 with KB5004296, Windows 11 21H2 and later. Configurable on Pro through the local Group Policy Editor. |
| **Privileges** | Local administrator (elevated `gpedit.msc`, `gpupdate /force`). Values land under `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`. RustWard only **reads** them. |
| **Previously installed devices** | Not affected unless "Also apply to matching devices that are already installed" (`…Retroactive`) is enabled. **VM-observed:** retroactive gives Code 1 immediately; reconnecting gives Code 28; the volumes disappear. Without retroactive, an installed device keeps working until it is reinstalled. |
| **Identity limits** | Matches **hardware/compatible IDs or instance IDs reported by the device**: VID/PID, or `USBSTOR\Disk<Vendor><Product>` strings. These are **self-reported and not cryptographically verified**; a device can claim another vendor's ID. Brand-wide allow-by-vendor is **not** expressible safely: a deny-by-default needs class rules plus allow-lists and layered evaluation, which RustWard does not generate (see below). |
| **Impact on internal disks and peripherals** | A narrow `USBSTOR\Disk…` device ID affects only matching USB mass-storage devices. **VM-observed:** the ASELSAN-labelled stick, the system disk, keyboard and mouse were unaffected. Class rules (DiskDrive `{4d36e967-…}`, retroactive) would also hit internal and boot disks, so RustWard never generates them. |
| **Rollback** | Set the policy to *Not Configured*, then run `gpupdate /force`. **VM-observed:** the Kingston reinstalled by itself and its volume returned. RustWard verifies that the policy is byte-for-byte equal to the saved baseline. There is no rollback guarantee when the administrator changes other policies at the same time. RustWard then reports a mismatch or "Kurtarma gerekli" (recovery required). |
| **Auditing and verification** | Proof that Windows denies the device = the policy re-read **and** the device problem code (1/28) from SetupAPI. RustWard records one deduplicated audit event per denial episode (`windows_install_denied_observed` / `_ended`), plus session events. **An installation denial is not proof that every read/write path is denied.** Only volumes created through the denied driver stack are prevented; this was not tested further. |

## 2. Removable Storage Access (Group Policy)

"Removable Disks: Deny read/write access", under System → Removable Storage
Access, is supported on Pro.

- **Scope:** it is class-wide, with **no vendor or device granularity**, so it cannot express "allow approved brands". It applies to every removable disk, including approved ones.
- **Effect:** it denies access to devices that are already installed. Existing handles may need a reboot, or the "Time to force reboot" setting.
- **Status:** not implemented and not tested; documented as an option only.

## 3. Microsoft Defender for Endpoint device control

- **What it offers:** VID/PID/serial-based removable storage access control, with read/write/execute granularity.
- **Requirements:** a Defender for Endpoint Plan 1/2 or Defender for Business licence; Windows 10/11 with anti-malware client 4.18.2103.3 or later.
- **Management:** through Intune, the Defender portal or Group Policy.
- **Fit for RustWard:** reporting is cloud-based. Microsoft documentation does not confirm operation on an offline, non-onboarded Windows 10 Pro machine. **Unsupported for RustWard's air-gapped target**; not tested.

## 4. What RustWard supports today

| Capability | Status |
|---|---|
| Read the Device Installation Restrictions policy | **Real** (registry, read-only) |
| Enumerate the USB storage inventory, problem codes and hardware IDs | **Real** (SetupAPI) |
| Detect arrival and removal | **Real**: `WM_DEVICECHANGE` wake plus a 30 s periodic refresh |
| Correlate the policy with the device outcome; protection state | **Real** (observer, `windows_protection`) |
| Guided session: baseline, checklist, verify apply, verify rollback | **Real**, VM-verified on the Kingston |
| Generate a narrow per-device checklist | **Real**. Generic IDs, non-USB devices, class rules and collateral damage are refused. |
| Apply or remove a Windows policy automatically | **BLOCKED** (see top) |
| Manufacturer-based default deny | **Not supported** (simulation only) |
| Read/write denial verification | **Not verified** |
| Cryptographic device identity | **Not available**: USB descriptors are self-reported |

## Sources

- [Policy CSP – DeviceInstallation (Microsoft Learn)](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-deviceinstallation)
- [Manage device installation with Group Policy (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy)
- [Device control in Microsoft Defender for Endpoint (Microsoft Learn)](https://learn.microsoft.com/en-us/defender-endpoint/device-control-overview)
- VM evidence: `docs/WINDOWS-VM-KINGSTON-BLOCK-2026-11-07.md`
