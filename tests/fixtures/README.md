# Test fixtures

`synthetic-lab-snapshot.json` is **synthetic**. It was not captured from real
hardware. USBSTOR identifier strings follow Microsoft's documented format;
SCSI/UASP strings, serial numbers and product names are illustrative.

It deliberately contains no TÜBİTAK SIR II data: those descriptors are unknown
until physical inspection, and inventing them would hide the real gap.

Devices modelled: two SanDisk models, Kingston (present and previously installed),
Seagate UASP HDD, JMicron-bridged SSD, generic flash drive, a spoofed device
reporting "SanDisk" with an unrelated VID, a disk with unreadable hardware IDs,
USB DVD drive, MTP phone, composite keyboard+storage device, keyboard, mouse,
printer, internal SATA and NVMe disks, controllers, hub and a volume.

Real snapshots captured with `rustward-inventory capture` must be reviewed before
being committed: they contain serial numbers and the computer name.
