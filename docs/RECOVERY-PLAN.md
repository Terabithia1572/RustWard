# Recovery Plan

Phase 1 changes nothing on Windows, so there is nothing to recover yet. This plan
defines what must exist **before** Phase 2 applies any policy on the isolated test PC.

## Before any change (Phase 2 entry criteria)

1. Test PC is dedicated and sacrificial: not the development machine, not one of the five
   production workstations.
2. Full disk image or VM snapshot taken; restore tested once.
3. System Restore point created.
4. Baseline captured (read-only):
   - `rustward-inventory capture --include-non-present --out baseline\devices.json`
   - `scripts\check-prereqs.ps1 > baseline\environment.txt` (includes current device-installation
     and removable-storage policy registry values)
   - `reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall" baseline\deviceinstall.reg`
     (an empty/absent key is a valid baseline).
5. A PS/2 or known-good keyboard path, and local admin credentials, are available.
6. Written approval for the specific change.

## Rollback (to be validated in Phase 2)

| Situation | Action |
|---|---|
| Policy applied, system usable | Re-apply baseline (remove RustWard-set device-installation values), `gpupdate /force`, rescan devices, compare with baseline inventory. |
| Approved device blocked | Device Manager → remove device → rescan after correcting policy; record evidence. |
| Keyboard/mouse lost (should be impossible with a DiskDrive-only rule) | Remote: none (air-gapped). Use on-screen keyboard at logon if mouse works; otherwise boot WinRE → Command Prompt → load the offline SOFTWARE hive and remove the policy values, or restore the image. |
| System disk issue after driver update | Boot WinRE, remove DiskDrive prevent values from offline hive; restore image if needed. |
| Corrupted RustWard DB/config | Service refuses to change policy (fail-closed for changes) and logs Event 1008 if it cannot start; OS policy remains as last applied. Manual recovery: stop the service, move the damaged `rustward.db` aside as evidence, copy the latest verified backup (hash from `SHA256SUMS`/registry export) to `rustward.db`, start, check chain status in Diagnostics, record the incident outside RustWard (AUDIT-INTEGRITY.md §3). |
| Wrong policy after a restore | Restore the automatic `rustward-pre-restore-<ms>.db` with the same two-step flow (it becomes a new version; nothing is lost). |

Every recovery step is logged and followed by a verification scan.

## Never

- Never enable the retroactive flag on the DiskDrive class rule.
- Never test on the developer's primary Windows installation or a production workstation.
- Never silently remove pre-existing security policies; capture and restore them exactly.
