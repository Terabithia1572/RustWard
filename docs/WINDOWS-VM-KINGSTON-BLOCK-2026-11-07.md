# Real Windows USB block: Kingston, VM, 2026-11-07

**Result: a supported Windows policy, applied manually by the owner in the
authorized test VM, prevented the Kingston stick from being used. RustWard
did not apply it; RustWard read it back.** RustWard's own enforcement stays
disabled (`ACTIVATION_ENABLED = false`); its decisions are still simulations.

## Setup

| Item | Value |
|---|---|
| Machine | VMware Workstation "Windows 10 x64" test VM, Windows 10 build 19045.6466 |
| Snapshots | `before-rustward-install`, `rustward-working-before-kingston-test` (taken before the change; both kept) |
| Baseline | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` absent; all Device Installation Restrictions policies Not Configured |
| Policy (applied by the owner in gpedit, then `gpupdate /force`) | Computer Configuration → Administrative Templates → System → Device Installation → Device Installation Restrictions → **Prevent installation of devices that match any of these device IDs** = Enabled |
| Value (only entry) | `USBSTOR\DiskKingstonDataTraveler_3.0____` (Kingston's first hardware ID, copied from Device Manager) |
| Retroactive | "Also apply to matching devices that are already installed" = ticked |
| Registry read back by RustWard | `DenyDeviceIDs` = 1 (1 entry), `DenyDeviceIDsRetroactive` = 1; nothing else set |
| System disk chain | ACPI → PCI bus → PCIe root port → Standard NVM Express controller → VMware Virtual NVMe Disk (no USB) |
| USB chain | USB 3.2 xHCI → root hub → {VMware composite input device (2 HID), Kingston mass storage, VendorC mass storage} |

## Observed results

| Check | Result | Evidence |
|---|---|---|
| Kingston (0951:1666) after the policy | **BLOCKED** | Device Manager: "Code 1: device not configured correctly" + "installation of this device is forbidden by system policy"; device events: *deleted* 13:31:09, *blocked (disk.inf)*, "configuration blocked by policy" 13:31:10 |
| Kingston volumes E:, F: | **Gone** | Not in This PC; Disk Management lists Disk 0 and Disk 2 only (no Disk 1). No disk or volume exists to open, so no filesystem access is possible. A raw read was not attempted. |
| Kingston after VMware disconnect + reconnect | **Still blocked** | "Code 28: drivers not installed" + "forbidden by system policy"; E:/F: absent |
| VendorC USB stick (346D:5678, VendorC) | **Unaffected** | "Working properly"; G: lists its 9 root entries (read-only); healthy in Disk Management |
| Internal disk | **Unaffected** | Disk 0 online, C: healthy (boot) |
| Keyboard / mouse | **Unaffected** | VMware USB input devices without errors; mouse used throughout; owner typed in gpedit/cmd |
| RustWard service | **Running** | Dashboard "Çalışıyor"; app connected |
| RustWard reads the real policy | **Yes** | Readiness page shows the values above and warns about the retroactive flag |
| Rollback (owner: Not Configured + `gpupdate /force`) | **PASS** | Restrictions key absent again, all flags unset; Kingston reinstalled automatically ("working properly"), E:/F: back; G: unchanged; service running |

Tests ran under the VM's administrator account (no standard user exists);
an installation restriction applies to every user.

## What this proves, and what it does not

- Proves: a narrow device-ID deny via Local Group Policy blocks a specific USB
  storage model on Windows 10 19045, including an already-installed device
  when the retroactive option is set, survives reconnection, leaves other
  devices alone, and rolls back cleanly. RustWard's install model predicts the
  same outcome (`vm_observed_hardware.rs`).
- Does not prove: manufacturer-based default deny (class deny + layered allow
  rules), protection of internal disks under a class rule, behaviour on
  Windows 11, or resistance to a local administrator removing the policy.
  Device IDs are not authenticated (the VendorC USB stick reports
  VendorC).

Screenshots (22) were delivered to the owner and are not committed: they show
the machine name and the Kingston serial.
