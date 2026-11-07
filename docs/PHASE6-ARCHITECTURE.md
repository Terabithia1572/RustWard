# Phase 6 — Architecture

RustWard is a Cargo workspace plus a Tauri 2 desktop application. The Windows
service is the only component that reads Windows state. It runs as
LocalSystem and has no network dependency. The desktop application talks to
it over two named pipes. **No component writes Windows policy, device or
driver configuration.**

```
 Tauri 2 desktop app (React 19, TypeScript, Tailwind; Turkish/English)
   │ ipc_call ─► rustward-ui-bridge
   │              │  \\.\pipe\RustWard.Status.v1  (read-only requests)
   │              │  \\.\pipe\RustWard.Admin.v1   (elevated administrators)
   ▼              ▼
 rustward-service (Windows service, LocalSystem)
   ├─ runtime loop: periodic inventory refresh + WM_DEVICECHANGE wake
   ├─ rustward-ipc  : envelopes, validation, authorization, golden contract
   └─ rustward-app (AppService)
        ├─ inventory  ─► rustward-windows::setupapi        (read-only SetupAPI)
        ├─ policy     ─► rustward-windows::policy_reader   (read-only registry:
        │                 DeviceInstall\Restrictions + RemovableStorageDevices)
        ├─ decisions  ─► rustward-core (catalog, policy, classify, evaluate)
        ├─ assessment ─► rustward-enforcement::assessment  (Phase 6 categories)
        ├─ observer   ─► rustward-enforcement::observer    (policy × problem code)
        ├─ guided     ─► baseline / expected / verify / rollback sessions
        └─ storage    ─► rustward-storage (SQLite WAL, hash-chained audit,
                          Windows Event Log mirror)
```

## Data flow for one device

1. **Inventory.** SetupAPI enumeration runs **outside** the application lock.
   The device rows are then written in one transaction. Timings appear in
   Diagnostics.
2. **Classification.** The setup class, service and parent chain give the
   scope: USB storage, internal disk, peripheral or unsupported type.
3. **Policy decision (simulation).** The catalog maps the INQUIRY vendor to a
   brand. Allow, explicit deny or default deny applies.
4. **Identity grading.** INQUIRY vendor and USB VID are compared to give
   corroborated, single source, ambiguous, conflicting, generic or missing.
5. **Windows observation.** The live Restrictions policy is re-read and the
   rule that matches the device's hardware IDs is evaluated. A problem code
   of 1 or 28 under a matching rule means *installation denied*.
6. **Assessment.** One policy category (`ALLOW_CANDIDATE`, `DENY_CANDIDATE`,
   `UNVERIFIED_IDENTITY`, `UNSUPPORTED_DEVICE`, `OUT_OF_SCOPE`) and one
   enforcement category (`WINDOWS_DENIAL_VERIFIED`, `ENFORCEMENT_NOT_ACTIVE`).
7. **Audit.** One deduplicated event per denial episode
   (`windows_install_denied_observed` / `_ended`). The audit log is
   hash-chained and append-only, and mirrored to the Windows Event Log.

## Protection state (dashboard "Koruma durumu")

| State | Condition |
|---|---|
| `unknown` | The policy cannot be read |
| `inactive` | No Device Installation Restriction value is configured |
| `configured_unverified` | A rule exists, but no connected device is observed denied |
| `denial_observed` | Windows denies a connected device, but outside a verified RustWard session |
| `verified_active` | In an administrator session, the policy was verified exactly **and** Windows denies the target device, or any device for the default-deny profile while the live policy still equals the profile |

The dashboard also lists every **blocker** that keeps the system out of a
verified state:

- automatic application BLOCKED
- no rule
- dry-run mode
- allowed brand without a verified identifier
- default deny not verified
- devices denied by policy only
- installed before the rule
- unverified identities
- Removable Storage Access is class-wide
- read/write not verified

## Guided Windows sessions (administrator, never automatic)

| Session | Expected policy |
|---|---|
| Device deny | `DenyDeviceIDs` with the exact hardware ID of one connected USB disk (optionally retroactive). Refuses generic IDs, non-USB devices and collateral matches. |
| Default-deny profile | `AllowDenyLayered`; `DenyDeviceClasses` = DiskDrive (never retroactive); `AllowDeviceIDs` for the allowed brands; `AllowInstanceIDs` for every internal disk |

Each session:

1. saves the baseline,
2. shows the gpedit checklist,
3. verifies the administrator's change exactly ("partial" = mismatch),
4. observes the devices, and
5. verifies that the rollback equals the baseline.

Every step is audited. RustWard writes nothing to Windows. Automatic
application stays **BLOCKED**.

## Real-time behaviour

- **Service.** A device change wakes the refresh. It settles for 750 ms, with
  at least 2 s between wakes. A 30 s periodic refresh is the fallback.
  VM-measured: audit events are recorded within about 1–2 s of attach or
  detach.
- **UI.** It re-reads the observation every 2 s and reloads pages only when
  the device or policy state actually changes. Notices are polled one at a
  time, so the same device is never announced twice.

## Trust boundaries

- **UI.** Unelevated. It never opens the database and never decides
  authorization.
- **Status pipe.** Any authenticated user may connect, but only read-only
  requests are accepted.
- **Admin pipe.** SYSTEM and Administrators only, with an elevated token.
  Refusals are audited and rate-limited.
- **Registry.** Read with `KEY_READ` only. A crate test forbids any write API
  in `policy_reader.rs`.
