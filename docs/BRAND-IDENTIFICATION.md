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
