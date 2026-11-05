# Device Classification

Implemented in `rustward-core::classify`. Classification uses the enumerator,
service, setup class, hardware/compatible IDs and the **parent chain**, never the
top-level USB class alone. Composite devices are classified per function.

## Categories

| Category | Detection (summary) | Policy scope |
|---|---|---|
| `usb_storage_disk` / `bulk_only` | enumerator `USBSTOR`, type Disk/SFloppy (or unknown → treated as disk, fail-closed) | **In scope** |
| `usb_storage_disk` / `uasp` | enumerator `SCSI` with a USB ancestor whose service is `UASPStor` | **In scope** |
| `usb_storage_disk` / `unknown` | DiskDrive class below any USB ancestor via another stack | **In scope** (fail-closed) |
| `usb_storage_other_type` | USBSTOR/SCSI-on-USB with type CdRom, Sequential, Changer… | Scope decision pending (default deny in simulation) |
| `usb_portable_device` | USB node with WPD class (MTP/PTP phones, cameras) | Scope decision pending |
| `usb_storage_interface` | USB function bound to `USBSTOR`/`UASPStor` | Not evaluated itself; the child disk is |
| `system_or_non_usb_storage` | DiskDrive/SCSI disk with no USB ancestor (SATA, NVMe, virtual) | **Never touched** |
| `peripheral` | keyboard, mouse, HID, printer, hub, composite parent, other USB | **Never targeted** |
| `other` | everything else (volumes, system devices) | Not in scope |

## Peripheral impact matrix (candidate mechanism A)

| Device | Setup class | Affected by DiskDrive prevent rule? | Expected |
|---|---|---|---|
| USB keyboard | HIDClass / Keyboard | No | Works |
| USB mouse | HIDClass / Mouse | No | Works |
| USB printer | USB / Printer | No | Works |
| USB hub | USB | No | Works |
| Composite keyboard+storage | USB, HIDClass, DiskDrive | Only the storage function | Keyboard works, storage per policy |
| Internal SATA/NVMe disk (installed) | DiskDrive | Not retroactive; instance-ID allow in baseline | Works, including driver updates |
| New internal disk / VHD mount | DiskDrive | **Yes** | Blocked until allowed (L-09) |
| USB CD/DVD | CDROM | No | **Not blocked** (L-08) |
| MTP phone | WPD | No | **Not blocked** (L-08) |
| Thunderbolt/PCIe NVMe enclosure | DiskDrive (no USB ancestor) | Yes (class rule) | Blocked; but classified as non-USB → simulation says n/a. **Gap to resolve** |

These are model predictions, verified only by the Phase 2/9 hardware tests.

## Explicit scope decisions required

1. USB optical drives: block (add CDROM class prevent) or allow?
2. MTP/PTP phones and cameras: block (WPD class) or allow?
3. Thunderbolt/USB4 PCIe storage: how to recognise it as external (no USB ancestor)?
4. SD card readers: internal readers enumerate like disks; external USB readers report the reader's vendor (usually generic → denied).
5. Multi-LUN devices: each LUN is its own USBSTOR devnode; all must pass.

## Recovery before enforcement

See `RECOVERY-PLAN.md`. No policy is applied before a peripheral baseline is captured
with `rustward-inventory capture --include-non-present`.
