# ARGON Device Identity & Classification Matrix

**Workspace:** `C:\Users\Yunus\Desktop\RustWard2` (`experiment/argon4-vm-enforcement`)

---

## 1. Fundamental Identity Distinctions (Mandatory Security Framing)

RustWard never conflates electronic descriptor strings with cryptographic hardware authentication:

| Concept | Technical Meaning | Can Firmware Spoof It? | Does It Prove Data Blocking? |
|---|---|---|---|
| **1. Reported manufacturer string** | Text read from USB `iManufacturer` (`DEVPKEY_Device_BusReportedDeviceDesc` / `Manufacturer`) or 8-byte ASCII SCSI `INQUIRY` vendor field (`USBSTOR\Disk<Vendor8>...`). | **Yes** — programmable USB controllers (e.g. FX2LP, RP2040, BadUSB) can report any string. | **No.** |
| **2. Matching hardware-ID rule** | Prefix match by Windows PnP against `DEVPKEY_Device_HardwareIds` or `CompatibleIds` in `DeviceInstall\Restrictions`. | **Yes** — derived directly from USB/SCSI descriptors reported on the bus. | **No** — proves rule presence only; already-installed devices remain usable unless retroactive or reinstalled. |
| **3. Verified manufacturer identity** | Cryptographic challenge-response against a factory-provisioned key/certificate (e.g. CCID/PKCS#11 hardware token attestation). | **No** (if private key is non-exportable), **but unavailable for standard USB Mass Storage (`BOT`/`UASP`)** (`authenticated = false` always). | **No.** |
| **4. Successfully installed device** | Windows PnP bound `disk.inf` / `disk.sys` (`driver_installed = true`, `problem_code = None`). | N/A (local OS kernel state). | **Opposite** — block device and volumes can mount. |
| **5. Genuinely blocked data access** | Live PnP installation denial (`CM_PROB_NOT_CONFIGURED = 1` or `CM_PROB_FAILED_INSTALL = 28`) prevents `disk.sys` attachment and removes disk/volume objects (`E:\`, `F:\` absent in Disk Management), **or** filesystem I/O is denied by storage stack. | Composite non-disk interfaces (HID/CD-ROM/MTP) or custom raw `WinUSB` drivers require separate verification. | **Yes, for `DiskDrive` block/filesystem paths when independently confirmed.** |

---

## 2. Target & Observed Hardware Identity Matrix

| Device / Brand | Observed / Catalog USB `VID:PID` | SCSI `INQUIRY` / Hardware ID Prefix | PnP Class & Transport | Catalog Confidence & Verification | RustWard Policy Verdict | Windows Enforcement Status |
|---|---|---|---|---|---|---|
| **SanDisk** *(Target Allow #1)* | `0781:*` (primary), `0871:*` *(public registry)* | `SanDisk` → `USBSTOR\DiskSanDisk_`, `SCSI\DiskSanDisk_` | `DiskDrive` (`BOT` / `UASP`) | `VendorDocumented` / `PublicRegistry` (`Corroborated` when `0781` + `SanDisk` match; **no physical unit inspected in VM yet**) | `ALLOW` (`BrandAllowed: sandisk`) — **unless** USB `VID` conflicts with another catalog brand (`ConflictingIdentifiers` → `DENY`) | Planned Layer-2 `AllowDeviceIDs`; Stage B **BLOCKED** pending physical SanDisk unit |
| **TÜBİTAK / BİLGEM / SIR II** *(Target Allow #2)* | **UNKNOWN** *(never invented)* | **UNKNOWN** *(may re-enumerate or expose CCID + Mass Storage after PIN unlock)* | Composite / SmartCard / `DiskDrive` (TBD on hardware) | `Unresolved` (`enforceable: false` in catalog; emits `brand_not_enforceable` warning) | **Fail-Closed `DENY`** (`UnknownManufacturer` / `BrandNotEnforceable`) until genuine lab-verified IDs are added | **UNVERIFIED / BLOCKED** until physical SIR II hardware inspection; RustWard **never** captures or stores PINs |
| **Kingston DataTraveler 3.0** *(Observed Real Hardware)* | `0951:1666` (`REV_0001`) | `Kingston` / `DataTraveler_3.0` → `USBSTOR\DiskKingstonDataTraveler_3.0____`, vendor prefix `USBSTOR\DiskKingston` | `DiskDrive` over `USBSTOR` (`BOT`), 2 volumes (`E:`, `F:` in VM) | `LabVerified` in VM (`Corroborated`: `VID_0951` + `INQUIRY Kingston`) | **Explicit `DENY`** (`BrandDenied: kingston`, `matched_brand: "kingston"`) | Model-ID retroactive deny (`Code 1` / `Code 28`, `E:`/`F:` gone) + rollback **PHYSICAL HARDWARE VERIFIED** in VM (2026-11-07) |
| **Second USB Stick (ASELSAN-labelled casing, generic controller)** *(Observed Real Hardware)* | `346D:5678` (`REV_0320`), bus string `Disk 20` | `VendorC` / `ProductCode` / `3.20` → `USBSTOR\DiskVendorC_ProductCode____3.20`, `USBSTOR\DiskVendorC_` | `DiskDrive` over `USBSTOR` (`BOT`), volume `G:` (`VTOYEFI`) | `Generic` (`VendorC` is in `RESERVED_GENERIC_VENDORS`; **never** added to SanDisk or TÜBİTAK) | **Fail-Closed `DENY`** (`GenericVendorIdentity: "VendorC"`) | Unaffected during Kingston-only test (`G:` remained readable, proving rule selectivity) |
| **Seagate** *(Target Deny #2)* | `0BC2:*` *(public registry)* | `Seagate` → `USBSTOR\DiskSeagate_`, `SCSI\DiskSeagate_` | `DiskDrive` (`BOT` / `UASP` external HDD/SSD) | `PublicRegistry` / `VendorDocumented` | **Explicit `DENY`** (`BrandDenied: seagate`, `matched_brand: "seagate"`) | Covered by explicit deny / Layer-3 `DiskDrive` default-deny for new installs |
| **Spoofed / Conflicting USB Drive** *(e.g. `VID_0951` Kingston + `INQUIRY SanDisk`)* | Mismatched catalog `VID` vs `INQUIRY` | Conflicting `VID` brand vs `INQUIRY` brand | `DiskDrive` (`BOT` / `UASP`) | `Conflicting` | **Fail-Closed `DENY`** (`ConflictingIdentifiers`) — enforced in `rustward-core::evaluate` (Phase 3 fix) | Denied; never receives allowlist trust |
| **Generic USB-to-SATA / NVMe Enclosures** | `174C:*` (ASMedia), `152D:*` (JMicron), `0BDA:*` (Realtek), `090C:*` (SMI), `13FE:*` (Phison) | `ASMT`, `JMicron`, `Realtek`, `Generic`, `USB` | `DiskDrive` over `USBSTOR` or `uaspstor` (`SCSI\Disk...`) | `Generic` (rejected by catalog validator & evaluator) | **Fail-Closed `DENY`** (`GenericVendorIdentity`) | Blocked on new install under Layer-3 `DiskDrive` prevent |
| **VMware System / Boot Disk** *(Observed Real VM Hardware)* | Non-USB PCI parent `PCI\VEN_15AD&DEV_07F0` | `SCSI\DISK&VEN_NVME&PROD_VMWARE_VIRTUAL_N\5&25A13950&0&000000` | `DiskDrive` under `SCSIAdapter` (`stornvme`), boot `C:` | Internal non-USB storage (`usb_ancestor == None`) | `NOT_APPLICABLE` (`SystemOrNonUsbStorage`) | Protected by non-retroactive class rule + explicit Layer-1 `AllowInstanceIDs` entry |
| **USB Keyboards, Mice, Printers, Hubs** | Various (`HIDClass`, `Keyboard`, `Mouse`, `Printer`, `USB`) | `HID\...`, `USB\CLASS_03...`, `USBPRINT\...`, `USB\ROOT_HUB30...` | Non-storage classes | Out-of-scope peripheral (`Peripheral`) | `NOT_APPLICABLE` (`NotInScope`) | Unaffected (no `USB` or `HIDClass` restriction is ever generated) |

---

## 3. Multi-LUN, Composite & Post-Unlock Re-Enumeration Handling

1. **Multi-LUN & Multi-Partition Drives**: Kingston (`0951:1666`) mounts two logical volumes (`E:`, `F:`) on a single `USBSTOR\Disk...` devnode; multi-LUN card readers create `&0`, `&1` sibling `DiskDrive` devnodes under the same `USB\VID_...` parent. RustWard keys inventory rows by normalized PnP `instance_id` (`device_key`), evaluates each LUN independently by walking to its `USB\VID_...` ancestor, and blocks all LUNs under a vendor/model hardware-ID prefix.
2. **Composite USB Devices (`usbccgp`)**: A device exposing both HID (keyboard/unlock pad) and Mass Storage (`USB\Class_08`) creates separate child function devnodes. RustWard classifies the HID child as `Peripheral` (`NotApplicable`) and the `DiskDrive` child as `UsbStorageDisk`, preventing peripheral breakage while still evaluating the storage function.
3. **PIN-Unlocked / Hardware-Encrypted Drives (e.g., TÜBİTAK SIR II)**: Encrypted drives commonly enumerate first as a read-only CD-ROM (`GenCdRom` / `UsbStorageOtherType`) or smart-card/HID launcher, then detach and re-enumerate with a new `DiskDrive` child (or new PID) after hardware/PIN unlock. RustWard:
   - Never intercepts, prompts for, or logs any PIN or credential.
   - Detects the post-unlock arrival via `CM_Register_Notification` (`diff.rs` `correlate_reenumeration`), recording `device_reenumerated` when serial/parent correlates or `device_detected` on the newly exposed `DiskDrive` devnode, and evaluates the unlocked storage node immediately.
