# RustWard

**Offline USB storage access control and Windows Local Group Policy enforcement for Windows 10/11 Pro.**

[Türkçe](README_TR.md) · Developer: **Yunus İNAN**

> **Status (V1.0.0, November 2026): VM-validated release (not production-certified).**
>
> - RustWard manages manufacturer-based USB storage rules (`Allow` / `Deny`) and compiles validated hardware identifiers into persistent **Windows Local Group Policy (`IGroupPolicyObject`)** restrictions (`DeviceInstall\Restrictions`).
> - Verified in an isolated Windows 10 Pro 22H2 (Build 19045) VMware guest on simultaneous **Kingston DataTraveler 3.0 (USBSTOR)** and **SanDisk 3.2Gen1 (UASP/SCSI)** denial, independent **SanDisk Allow / Deny transitions** while Kingston remains blocked, and full clean policy rollback.
> - Manufacturer identity is **self-reported** by USB descriptors and SCSI `INQUIRY` fields and is **not** cryptographically authenticated.
> - Full privileged policy enforcement requires the installed Windows service (`RustWardService`) and Windows Administrator privileges.
> - Internal system disks (NVMe/SCSI), VMware virtual disks, and HID input peripherals (keyboards/mice) are protected from restriction and restart.

## Contents

- [Overview](#overview)
- [Features](#features)
- [Security model](#security-model)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Supported Windows versions](#supported-windows-versions)
- [Installation](#installation)
- [Build](#build)
- [Testing](#testing)
- [Known limitations](#known-limitations)
- [Documentation](#documentation)

## Overview

RustWard targets standalone, air-gapped Windows workstations where external USB mass storage must be controlled per hardware manufacturer without requiring cloud connectivity or third-party kernel filter drivers:

| Manufacturer / Category | Supported Enforcement (V1.0.0) | Verification Status |
|---|---|---|
| SanDisk (USBSTOR & UASP/SCSI) | `Allow` / `Deny` transitions | **Verified in Windows 10 VM** |
| Kingston (USBSTOR) | `Deny` / `Allow` transitions | **Verified in Windows 10 VM** |
| Generic / Controller Vendors (`VendorC`, `Generic`) | `Deny` / Fail-closed classification | **Verified in Windows 10 VM** |
| Other catalog brands (50+ entries) | Configured rule compilation & policy matrix | Generic / hardware-dependent |
| Keyboards, mice, internal NVMe/SCSI disks | Never targeted (fail-safe excluded) | **Verified in Windows 10 VM** |

## Features

- **Real Device Inventory:** Read-only SetupAPI enumeration of USB mass storage (`USBSTOR` and `UASPStor` / `SCSI`), peripherals, and internal disks. Captures VID/PID, hardware/compatible IDs, SCSI `INQUIRY` fields, parent USB instance chains, connection state, Windows PnP problem codes (`CM_PROB_*`), and timestamps without blocking concurrent IPC calls.
- **Unified Multi-Manufacturer Policy Manager:**
  - Compound Windows Local Group Policy (`IGroupPolicyObject`) compiler supporting simultaneous `DenyDeviceIDs` / `AllowDeviceIDs` rules with `DenyDeviceIDsRetroactive = 1`.
  - Targeted recovery of newly-allowed USB devices (restarts blocked USB storage devnodes safely while leaving excluded internal disks and HID devices untouched).
  - Transactional baseline backup and clean Group Policy rollback.
- **UASP / SCSI & USBSTOR Enforcement:**
  - Blocks both traditional USBSTOR drives (`USBSTOR\DiskKingstonDataTraveler_3.0____`) and modern USB Attached SCSI drives (`SCSI\Disk_____USB_SanDisk_3.2Gen1`).
  - Strict generic ID guard rejects unsafe generic identifiers (`USBSTOR\GenDisk`, `SCSI\Disk`, `SCSI\DISK_____USB`, wildcard patterns `*`) from deny rules.
- **Real Windows Observation & Audit Log:**
  - Live read-only inspection of `DeviceInstall\Restrictions` registry values and SetupAPI PnP states.
  - Hash-chained, append-only SQLite (WAL) audit database mirrored to the Windows Application Event Log (`RustWard` source).
- **Bilingual Desktop UI:** Full Turkish default interface with English support.

## Security model

- **Privilege separation:**
  - `rustward-service.exe` runs as `LocalSystem` and owns the SQLite audit/policy store under `%ProgramData%\RustWard` (SYSTEM + Administrators ACL).
  - The Tauri desktop UI connects over named pipes (`RustWard.Status.v1` read-only, `RustWard.Admin.v1` requiring an elevated Windows Administrator token).
  - Refused unauthorized admin IPC requests are rate-limited and recorded in the audit log.
- **No kernel driver required:** Uses built-in Microsoft Windows Device Installation Restrictions via COM `IGroupPolicyObject`.
- **Honest identity boundaries:** Standard USB storage descriptors can be cloned or spoofed; RustWard reports hardware identity confidence transparently (`corroborated`, `single_source`, `conflicting`, `generic`, `missing`) and never claims cryptographic hardware attestation for plain mass-storage sticks.

See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Architecture

```text
Tauri 2 Desktop App (React, TypeScript, Tailwind)
  ├──► \\.\pipe\RustWard.Status.v1 (Read-only status & observation)
  └──► \\.\pipe\RustWard.Admin.v1  (Elevated Administrator policy control)
         └──► rustward-service.exe (LocalSystem Windows Service)
                ├─ rustward-app         requests, GPO apply/rollback orchestration
                ├─ rustward-core        catalog, policy rules, classification
                ├─ rustward-enforcement compound policy compiler, SetupAPI observer
                ├─ rustward-windows     SetupAPI, IGroupPolicyObject COM, Event Log
                ├─ rustward-ipc         named-pipe transport & caller verification
                └─ rustward-storage     SQLite WAL store & SHA-256 audit hash chain
```

## Technology stack

Rust (2024 edition), `windows-sys`, `windows-service`, SQLite (`rusqlite` bundled), Tauri 2, React 19, TypeScript, Tailwind CSS 4, Vitest, and WiX v3 (MSI). All frontend assets and USB vendor lookup data (`usb.ids`) are bundled for offline operation.

## Supported Windows versions

| Component | Support Status |
|---|---|
| Operating System | Windows 10 Pro/Enterprise/Education x64 (verified on 22H2 build 19045 VMware guest); builds for Windows 11 x64 (unverified in full VM suite). |
| Device Installation Policy Engine | Built-in Windows Local Group Policy (`gpedit.dll` / `IGroupPolicyObject`) — Pro, Enterprise, and Education editions (Windows Home lacks Group Policy client processing). |
| Runtime Dependencies | Microsoft Edge WebView2 Runtime (offline installer bundled in MSI), VC++ runtime. |
| Network Access | Not required (100% offline). |

## Installation

### MSI Installer (Recommended for Full Service Enforcement)

1. Verify the SHA-256 checksum against `SHA256SUMS.txt`.
2. Run `RustWard-v1.0.0-x64-Setup.msi` as **Administrator**.
3. The MSI installs the desktop client, registers the `RustWard USB Depolama Denetimi` (`RustWardService`) LocalSystem service, creates the Event Log source, and provisions `%ProgramData%\RustWard`.
4. Launch **RustWard** as Administrator to apply or roll back Windows Group Policy rules.

### Portable Package (`RustWard-v1.0.0-Portable.zip`)

The standalone `RustWard.exe` desktop binary is only a UI client and **cannot apply or enforce USB restrictions by itself** without the companion `rustward-service.exe` installed and running as a privileged Windows service (`LocalSystem`). Refer to the included `README-PORTABLE.txt` inside the archive for offline deployment and service installation instructions.

## Build

On Windows x64 with Rust (MSVC toolchain 1.90+), Visual Studio C++ Build Tools, Windows 10/11 SDK, Node.js 22 LTS, and WebView2:

```cmd
BUILD-RUSTWARD.cmd
```

## Testing

```powershell
cargo test --workspace
npm --prefix apps/rustward-desktop test -- --run
```

Acceptance evidence is documented in [docs/ARGON4-PHASED-HOTFIX-ACCEPTANCE.md](docs/ARGON4-PHASED-HOTFIX-ACCEPTANCE.md) and [docs/TEST-RESULTS.md](docs/TEST-RESULTS.md).

## Known limitations

- **VM-validated V1.0.0 release:** Validated inside an isolated Windows 10 Pro VMware environment; physical fleet deployment and enterprise code-signing remain pending.
- **No cryptographic USB authentication:** Manufacturer identification relies on self-reported USB VID/PID and SCSI `INQUIRY` fields.
- **Install-time vs. class-wide enforcement:** Device Installation Restrictions with `DenyDeviceIDsRetroactive = 1` uninstall blocked devices at driver level; already-running sessions without device re-enumeration require a PnP restart (performed automatically on transitions where safe).
- **Administrator privilege boundary:** Local Windows administrators can directly modify Group Policy outside RustWard; RustWard detects and audits external policy drift.
- **Desktop notifications & persistent boot reconciliation:** Planned for V1.1.

## Documentation

Full technical architecture, security reviews, and acceptance records reside in [`docs/`](docs/).
