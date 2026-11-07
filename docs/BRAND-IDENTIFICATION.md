# Brand Identification

## Principle

An administrator thinks in brands ("SanDisk", "TÜBİTAK"). Windows enforces
identifiers. RustWard bridges them through a **local, versioned manufacturer
catalog** (`config/manufacturer-catalog.json`) and makes the gap visible
instead of hiding it.

## Identifier kinds

| Kind | Example | Enforceable? | Why |
|---|---|---|---|
| `inquiry_vendor` | `SanDisk` → `USBSTOR\DiskSanDisk_` | **Yes** | Windows generates a vendor-level hardware ID from it (documented for USBSTOR). Device Installation policy can match it exactly. |
| `usb_vid` | `0781` | No (corroborating only) | Windows exposes no VID-only hardware ID; matching all products of a VID would need every PID (model list). |
| aliases / names | "SanDisk Ultra USB Device" | No (hint only) | Text from INF or firmware; trivially inconsistent. Never authorizes. |

The decision engine's verdict is computed **only** from the enforceable
identifier, so the simulated decision equals what the OS rule would do. VID and
names are attached as evidence ("corroborating", "hint", "warning").

## Encoding

`encode_inquiry_field` pads the vendor to 8 characters with spaces and replaces
spaces with `_`, giving Microsoft's documented form (`SEAGATE` →
`USBSTOR\DiskSEAGATE_`). Matching is case-insensitive like PnP. Non-ASCII values
(e.g. "TÜBİTAK") are rejected: INQUIRY data is ASCII, so such a value can never
match real hardware. The comma rule and the `SCSI\` namespace padding are
assumptions to confirm on hardware.

## Catalog rules (enforced by `ValidatedCatalog`)

- Brand ids are slugs; display names may be Unicode.
- An INQUIRY vendor may belong to **one** brand only; duplicates are rejected as ambiguous.
- Reserved generic vendors (`Generic`, `USB`, `JMicron`, `ASMT`, `Phison`, …) can never be a
  brand identifier.
- Every identifier carries a `verification` level (`unverified`, `public_registry`,
  `vendor_documented`, `lab_verified`) and a `source`.
- A policy in `enforce` mode is rejected unless every enabled brand has at least one
  `lab_verified` enforceable identifier. The shipped catalog has none, so only `dry_run`
  validates today — on purpose.

## Current catalog (2026.11.05-phase1)

| Brand | INQUIRY vendor | USB VIDs (public registry) | Status |
|---|---|---|---|
| SanDisk | `SanDisk` (unverified) | 0781, 0871 | Needs lab confirmation on ≥3 models |
| TÜBİTAK BİLGEM | — | — (no entry in public usb.ids) | **Unknown until SIR II inspection** |
| Kingston | `Kingston` (unverified) | 0951, 0E56 | Used as a denied example |
| Seagate | `Seagate` (unverified) | 0BC2, 0477, 1A2A | Used as a denied example |

VIDs were checked against the public usb.ids registry on 2026-11-05.

## Observed hardware (VM, 2026-11-07, read-only)

Real sticks passed through to the authorized Windows 10 test VM (19045),
read from RustWard's inventory and Device Manager. Sanitized evidence:
`tests/fixtures/vm-observed-usb-2026-11-07.json`; regression tests:
`crates/rustward-enforcement/tests/vm_observed_hardware.rs`.

| Stick (label) | USB VID:PID | INQUIRY vendor / product / rev | Transport | Matches catalog |
|---|---|---|---|---|
| Kingston DataTraveler 3.0 | 0951:1666 | `Kingston` / `DataTraveler_3.0` / blank | USBSTOR (bulk-only) | Kingston (VID and vendor agree) |
| **SanDisk-labelled** | **346D:5678** | **`VendorC` / `ProductCode` / `3.20`** | USBSTOR (bulk-only) | **No**: neither SanDisk VID nor vendor |

The SanDisk-labelled stick does not report SanDisk identifiers, so it does
not confirm the catalog's `SanDisk` INQUIRY vendor. That still needs a stick
that reports SanDisk's VID (0781/0871). Under the dry-run VM test policy the
"SanDisk" stick is denied as an unknown manufacturer, which is the intended
default-deny behaviour for a mislabelled or rebranded device.

## TÜBİTAK BİLGEM SIR II: DEFERRED, physical workplace validation required

Not available; no identifiers exist in RustWard and none may be invented.
At the workplace, read-only, with the inventory tool and Device Manager:

1. Inspect the device before PIN entry: every device node, class, hardware and
   compatible IDs, VID:PID.
2. Enter the PIN in the vendor's own software only. **Never request, capture,
   store or log the PIN.**
3. Inspect again after unlock.
4. Determine whether it re-enumerates (e.g. a CD-ROM/unlock volume first, a
   disk afterwards) and which device node carries the data.
5. Record its real manufacturer and storage identifiers (INQUIRY vendor and
   product, VID).
6. Check whether the disk appears under USBSTOR or UASP (SCSI namespace).
7. Confirm the supported Windows versions and that a device-installation
   restriction would not interfere with the unlock prompt.

## Unknown or new devices

Default deny. A device whose INQUIRY vendor is not in the catalog — even if the
plastic says "SanDisk" — is denied until an authorized administrator performs a
controlled offline catalog update backed by lab evidence (rustward-inventory
output from that device). This is the honest cost of brand-level policy.

## Collecting evidence (Phase 1 tool, read-only)

```powershell
rustward-inventory capture --out evidence\sandisk-ultra-64gb.json
rustward-inventory evaluate --snapshot evidence\sandisk-ultra-64gb.json
```

Record only hardware metadata. Never record PINs, file names or contents.
