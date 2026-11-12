# Test fixtures

`synthetic-lab-snapshot.json` is **synthetic**. It was not captured from real
hardware. USBSTOR identifier strings follow Microsoft's documented format;
SCSI/UASP strings, serial numbers and product names are illustrative.

It deliberately contains no unverified encrypted-drive data: those descriptors are unknown
until physical inspection, and inventing them would hide the real gap.

Devices modelled: two SanDisk models, Kingston (present and previously installed),
Seagate UASP HDD, JMicron-bridged SSD, generic flash drive, a spoofed device
reporting "SanDisk" with an unrelated VID, a disk with unreadable hardware IDs,
USB DVD drive, MTP phone, composite keyboard+storage device, keyboard, mouse,
printer, internal SATA and NVMe disks, controllers, hub and a volume.

Real snapshots captured with `rustward-inventory capture` must be reviewed before
being committed: they contain serial numbers and the computer name.

## `vm-observed-usb-2026-11-07.json` (real, sanitized)

Observed on 2026-11-06/07 in the authorized VMware "Windows 10 x64" test VM
(build 19045) with two USB sticks passed through. Read-only: RustWard's
inventory page and the guest's Device Manager (Details tab). Nothing was
written to either stick and no file on them was read.

- Hardware and compatible IDs, VID:PID and friendly names are copied from
  Device Manager and the RustWard inventory exactly as shown.
- **Redacted:** every serial number and instance-ID suffix
  (`SERIAL-REDACTED-*`, `INSTANCE-REDACTED*`) and the computer name.
- The NVMe disk's instance-ID prefix is written in the standard form for its
  observed hardware IDs; its suffix was not recorded.
- `service` and `class_*` values of the USB sticks reflect that both were
  installed and working under "Disk drives"; the Driver tab was not opened.
- The keyboard/mouse entries carry only their observed instance-ID prefixes
  (class names were not recorded). No printer was attached to the VM.
- The secondary USB stick reports vendor `VendorC` and
  VID:PID `346D:5678` (generic controller firmware).
