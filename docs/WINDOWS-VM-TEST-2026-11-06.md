# Native Windows VM test: service-connected application (2026-11-06)

**First test of RustWard on real Windows with the service installed.** USB enforcement stays disabled (`ACTIVATION_ENABLED = false`). No Device Installation Restrictions, Group Policy or storage driver change. Stage F was not run.

## Environment

| Item | Value |
|---|---|
| Build machine | Developer PC: Windows 11 Pro 23H2 (22631; registry ProductName says "Windows 10 Pro"), MSVC 14.51, Windows SDK 10.0.26100, Rust 1.92, Node 24.17. Built only; nothing installed. |
| Test machine | VMware Workstation 17 VM "Windows 10 x64" (authorized by the owner). Snapshot `before-rustward-install` taken before the first install. |
| Input method | Mouse only. VMware does not accept injected keystrokes, so PowerShell scripts could not be typed in the guest; everything ran through the installer UI, Task Manager, Explorer and the app. |
| Commit tested | `de4c6b4` (second install); `beca7b9` + `5dcb4d4` (first install) |

## Artifacts (final build)

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `dist\installer\RustWard_0.1.0_x64_en-US.msi` (app + service + Event Log source + data ACL + offline WebView2) | 218,914,816 | `1c0bc04c0522c2be99de5094fca617fb706b4a9e20e61fa46404e41acb51a4aa` |
| `dist\service\rustward-service.exe` (MESSAGETABLE embedded) | 3,095,040 | `b78a2999c04464699040ce992dadb24e939694166709df40b5a36ad0a38cc0c1` |
| `dist\RustWard.exe` (release, service backend) | 3,845,632 | `09a7353754fb75a0debe50150bc0eb8e18366a56a1ba636611f40015e94be6e4` |
| `dist\service\rustward-inventory.exe` | 774,656 | `154bd6c983c65aff9792bf182cceaf0f18e93f93158faded7613970cdef3791f` |

The MSI tables were checked read-only (Windows Installer COM) by `Build-RustWard.ps1`:
- `ServiceInstall`: RustWardService / LocalSystem / `service`;
- `File`: rustward-service.exe and the app;
- `ServiceControl`;
- Event Log `Registry` rows;
- `MsiLockPermissionsEx` = `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`. This resolves R-11-3 at build level; the ACL was not inspected on disk.

## Results

| # | Test | Result | Evidence |
|---|---|---|---|
| 1 | Native MSVC build of app, preview, service, inventory; full MSI | PASS | build-logs; PE checks (x64, GUI/console subsystem, MESSAGETABLE type 11) |
| 2 | App before install: service missing is reported, no crash | PASS | "RustWard hizmeti bu bilgisayarda kurulu değil." (SCM query) |
| 3 | MSI install (wizard, UAC, unsigned publisher) | PASS | "Completed the RustWard Setup Wizard"; service RUNNING |
| 4 | RustWard.exe ↔ service named-pipe IPC, pipe owner + server-PID verification | PASS | "RustWard Windows hizmetine bağlı"; backend `windows_service` |
| 5 | Service runs as LocalSystem | PASS | Task Manager Details: rustward-service.exe, user SYSTEM |
| 6 | Standard (unelevated) caller refused on admin pipe; status pipe works | PASS | "Hizmet çalışıyor; … yönetici olarak (yükseltilmiş) başlatın." |
| 7 | Elevated caller: admin requests (inventory refresh, policy edit) | PASS | "inventory refreshed: 8 stored devices"; policy v2/v3 |
| 8 | Caller identity in audit | FAIL → fixed → PASS | First install: "(by unknown)". Fixed in `de4c6b4`; second install: "(by DESKTOP-…\\<user>)" |
| 9 | Real read-only SetupAPI inventory | PASS | VMware USB/HID/ACPI devices; virtual SATA CD and NVMe disk as system storage |
| 10 | Real USB storage in the VM: simulated decision only, not blocked | PASS | VendorC 346D:5678 `SIMULATED DENY`, Kingston DT 3.0 `SIMULATED ALLOW` once allowed; "enforcement NOT ACTIVE"; device stayed accessible |
| 11 | SQLite persistence (`%ProgramData%\RustWard`, schema v2, integrity, hash chain) | PASS | Diagnostics: integrity OK, chain intact |
| 12 | Data kept across uninstall + reinstall | PASS | Policy v2 (Kingston allowed) and chain (81 entries) present after reinstall |
| 13 | SCM stop | PASS | stopped within ~4 s; app: "kurulu ancak durdurulmuş" |
| 14 | SCM start / restart | PASS | new PIDs 1688, 5740 |
| 15 | Crash recovery (End task on the service) | PASS | SCM restarted it as SYSTEM (PID 5448) within ~10 s; app reconnected |
| 16 | Event Log mirroring | PASS | Diagnostics: 12 written, 0 failed |
| 17 | Event Viewer shows formatted RustWard messages (C20) | NOT VERIFIED | Event Viewer's list did not render in the VM console |
| 18 | MSI uninstall removes the service | PASS | App afterwards: "RustWardService is not installed" |
| 19 | Pipe ACL inspection (AccessChk), impostor-pipe test (C12, C16), F-13/F-14 pool tests | NOT RUN | need typed commands in the guest |
| 20 | MSI hash check inside the guest | NOT RUN | MSI size and timestamp matched the verified build; no typed commands |

## State left behind

- The final MSI (`de4c6b4`) is **installed** in the VM; RustWardService is running and RustWard.exe is connected.
- Roll back with the VMware snapshot `before-rustward-install`, or uninstall from the MSI.
- The host PC was not modified (no install, no service, no policy).
