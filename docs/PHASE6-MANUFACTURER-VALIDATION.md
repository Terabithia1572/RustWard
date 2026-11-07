# Phase 6 — Manufacturer identity validation

**Principle:** a manufacturer name is a *claim made by the device*. RustWard
grades how well independent self-reported sources agree. It never calls an
identity *authenticated*: `DeviceAssessment.authenticated` is always `false`.

## 1. Evidence sources

| Source | Where from (read-only) | Strength | Notes |
|---|---|---|---|
| SCSI INQUIRY vendor (8 chars) | `USBSTOR\Disk&Ven_…` / `SCSI\Disk&Ven_…` instance and hardware IDs | **Enforceable**: Windows can match `USBSTOR\Disk<Vendor8>` | Firmware string; cloned or rebadged sticks can carry any value |
| INQUIRY product / revision | same | Hint | Model-level matching only |
| USB VID / PID | parent `USB\VID_xxxx&PID_yyyy` (parent chain) | **Corroborating**: never authorizes alone | No VID-only hardware ID exists for USBSTOR children. Shared controller VIDs exist. |
| Device instance / parent chain | SetupAPI `CM_Get_Parent` chain | Scope | Proves USB vs internal attachment. An unresolved chain stays in scope. |
| Interface / transport | service (`USBSTOR`, `UASPStor`), setup class | Scope | UASP disks appear as `SCSI\Disk…` (vendor match shared with internal disks) |
| Windows installation status | problem code, driver installed | Enforcement evidence | Code 1/28 under a matching rule = installation denied |
| Friendly name / INF manufacturer | SetupAPI | Hint | Never used for a decision |

## 2. Confidence grades

| Grade | Rule | Effect |
|---|---|---|
| `corroborated` | The INQUIRY vendor maps to a catalog brand, and the USB VID is listed for **that brand only** | May become `ALLOW_CANDIDATE` |
| `single_source` | Only one source identifies a manufacturer | Allow: becomes `UNVERIFIED_IDENTITY`. Deny: `DENY_CANDIDATE`. |
| `ambiguous` | The VID is listed for several brands | `UNVERIFIED_IDENTITY` |
| `conflicting` | INQUIRY vendor and VID point to different brands, or the vendor is unknown while the VID is known | `UNVERIFIED_IDENTITY` |
| `generic` | The INQUIRY vendor is a reserved controller/bridge value | `UNVERIFIED_IDENTITY` |
| `missing` | No INQUIRY data | `UNVERIFIED_IDENTITY` |

## 3. Observed hardware (VM, read-only)

| Device | Reported | Grade | Decision under the target policy |
|---|---|---|---|
| Kingston DataTraveler 3.0 | VID:PID `0951:1666`; INQUIRY `Kingston` / `DataTraveler 3.0` / rev `PMAP` | `corroborated` (Kingston VID 0951) | `DENY_CANDIDATE` (explicit deny). Identifiers marked `lab_verified`. |
| Stick first reported as SanDisk-labelled (label later corrected by the owner to ASELSAN) | VID:PID `346D:5678`; INQUIRY `VendorC` / `ProductCode` / rev `3.20` | `generic` (`VendorC`/`VendorCo` reserved as generic in catalog `2026.11.07-phase6`) | `UNVERIFIED_IDENTITY`. **Never treated as SanDisk.** |
| TÜBİTAK SIR II | not inspected | — | No identifier exists; devices are denied. **No identifiers are invented.** |
| Genuine SanDisk | none available | — | SanDisk identifiers (`SanDisk`, VIDs 0781/0871) remain `unverified` / `public_registry` |

Serial numbers are never stored in fixtures or documents. Instance IDs are
masked (`SERIAL-REDACTED-…`) before any audit or export.

## 4. Can a brand-wide allow be enforced reliably?

**Not reliably.**

- Windows can enforce a vendor-level rule (`USBSTOR\DiskSanDisk_`), but that
  rule trusts a firmware string.
- A counterfeit or rebadged stick reporting `SanDisk` would be allowed.
- A genuine SanDisk stick whose bridge reports another vendor would be denied.
- The USB VID can only corroborate. Windows has no VID-only rule for the disk
  node, and a VID can be spoofed just as easily.

RustWard therefore keeps the conservative behaviour:

- An allow candidate needs two agreeing sources.
- The Windows allow rule is presented as **"reports SanDisk"**, not as
  "is SanDisk".
- TÜBİTAK stays denied until real identifiers are inspected and recorded with
  their source.

## 5. Deferred: TÜBİTAK SIR II checklist

1. Connect the SIR II to the VM only.
2. Record the following with `rustward-inventory` (read-only), **before and
   after** unlock:
   - the parent `USB\VID_…&PID_…`,
   - the `USBSTOR`/`SCSI` vendor, product and revision,
   - the setup class and service,
   - whether it re-enumerates on unlock.
3. Never request, capture, store or log the device PIN.
4. Add the identifiers to the catalog as `lab_verified`, with the source,
   only after at least two units agree.
5. Check that the encrypted device's unlock prompt is still reachable under
   the default-deny profile. The locked state may enumerate as a different
   class.
