# Release Readiness (Phase 9A, updated Phase 9B)

Classification concerns **readiness for Windows VM testing**, not production security
approval. Nothing below has been built, installed or run on Windows.

## 1. Target configuration

| Item | Value | Source of truth | Checked by |
|---|---|---|---|
| OS | Windows 10 Pro x64 22H2 (19045.x; layered device-install evaluation needs ≥ 19041.1151) | `device_install::MIN_LAYERING_UBR_19041` | unit tests |
| Rust target | `x86_64-pc-windows-msvc` (MSVC + Windows SDK for `rc.exe`) | `build-release.ps1`, `deny.toml` | NOT RUN |
| Bundle | MSI only (`bundle.targets = ["msi"]`) | `tauri.conf.json` | `product_versions_are_consistent` |
| WebView2 | `offlineInstaller`, silent (MSI embeds the runtime installer; build machine needs internet, or switch to `fixedVersion`) | `tauri.conf.json`; OFFLINE-DEPLOYMENT.md §3 | test + NOT RUN on Windows |
| Version | 0.1.0 in Cargo workspace, `tauri.conf.json`, `package.json` | — | `product_versions_are_consistent` |
| Release profile | `lto = true`, `codegen-units = 1`, `panic = "abort"` | `Cargo.toml` | — |
| Dev backend | Excluded from release builds (`debug_assertions` + feature) | `rustward-ui-bridge` | release-mode test PASS |

## 2. Service installation design (draft WiX fragment)

| Concern | Design | Status |
|---|---|---|
| Install | `ServiceInstall` `RustWardService`, own process, auto start, `LocalSystem`, argument `service`, `Vital="yes"` | Draft, NOT RUN |
| Recovery | `util:ServiceConfig` restart ×3, 5 s, reset 1 day | Draft, NOT RUN |
| Start/stop | `ServiceControl` start on install, stop on install+uninstall, remove on uninstall, wait | Draft, NOT RUN |
| Event source | `util:EventSource` Application/`RustWard`, message file = service exe (embedded MESSAGETABLE) | Draft, NOT RUN |
| Data dir | `%ProgramData%\RustWard`, protected DACL SYSTEM+Administrators (`D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), `Permanent="yes"` | Draft, NOT RUN |
| Uninstall | Service stopped and deleted, event source removed, data kept (audit evidence); manual removal after export | Draft, NOT RUN |
| Uninstall recovery | If uninstall fails with the service running: `sc.exe stop RustWardService`, retry; if the service entry is orphaned: `sc.exe delete RustWardService`; if the event source key is orphaned: remove `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\RustWard` (admin, documented manual step) | Documented |
| Policy changes | **None.** The fragment contains no registry values; a test fails if it references DeviceInstall/Restrictions/RegistryValue | `installer_fragment_matches_runtime_constants` |
| Service account | LocalSystem now; virtual account `NT SERVICE\RustWardService` to evaluate (L-28) | Open |

## 3. SQLite initialization

First start creates `rustward.db` (WAL, `synchronous=FULL`) and applies migrations v1–v2 in
order. A newer schema is refused (fail-closed); v1 databases upgrade in place (tested).
The initial policy is the embedded example (`PC-01`, dry-run); the administrator renames
the workstation after installation.

## 4. Artifact integrity

`scripts/build-release.ps1` (NOT RUN) writes into `release-out\`:

| File | Content |
|---|---|
| `RustWard_0.1.0_x64_*.msi` | desktop app (+ service with `-WithService`) |
| `rustward-service.exe`, `rustward-inventory.exe` | release binaries |
| `BUILD-INFO.txt` | version, git commit, dirty flag, rustc/cargo/node versions, target, flags, `ACTIVATION_ENABLED: false` |
| `DEPENDENCY-INVENTORY.md` | crate and npm inventory |
| `SHA256SUMS.txt` | SHA-256 of every file above |

Binaries are **unsigned** (L-19). Verify on the target with
`Get-FileHash -Algorithm SHA256 <file>` against `SHA256SUMS.txt` transferred separately
(e.g. printed, or on a second medium).

## 5. Dependency inventory and supply chain

| Check | Result (Linux, 2026-11-06, Phase 9B) |
|---|---|
| Frontend runtime network | none — `scripts/check-offline-assets.mjs` on `dist/` (no external URL, no fetch/XHR/WebSocket; module-preload polyfill disabled), CSP local-only (test) |
| `npm audit --omit=dev` | 0 vulnerabilities in shipped dependencies; the dev-only test runner has advisories (L-30) |
| `cargo deny check` — workspace, Windows target | advisories ok, bans ok, licenses ok, sources ok |
| `cargo deny check` — Tauri shell, Windows target | advisories ok, bans ok (10 duplicate-version warnings), licenses ok, sources ok |
| Inventory | 38 crates (service/libs, + embed-resource and deps on a Windows host), 233 crates (shell), 5 npm production packages — `docs/DEPENDENCY-INVENTORY.md` |
| Lockfiles | `Cargo.lock`, `src-tauri/Cargo.lock`, `package-lock.json`; all builds use `--locked` |
| Offline vendoring | `scripts/vendor-offline.sh` (Linux-verified earlier; re-run after the embed-resource addition) |

Air-gapped advisory checks: copy a RustSec `advisory-db` checkout and run
`cargo deny check --disable-fetch` (not yet rehearsed).

## 6. Offline installation instructions (acceptance VM)

1. Transfer `release-out\` and `SHA256SUMS.txt` on approved media; verify every hash.
2. Take a VM checkpoint.
3. As an administrator: `msiexec /i RustWard_0.1.0_x64_en-US.msi /l*v C:\rw-evidence\install.log`.
4. Verify: `sc.exe qc RustWardService`, `sc.exe query RustWardService`,
   `Get-Acl $env:ProgramData\RustWard`, event source key, Event Viewer entries
   (WINDOWS-VM-ACCEPTANCE.md Stages C–D).
5. Start RustWard as a standard user (read-only), and via "Run as administrator" for
   administrative actions; rename the workstation.
6. Uninstall test: `msiexec /x … /l*v C:\rw-evidence\uninstall.log`; data directory kept.

## 7. Readiness checklist

| Gate | State |
|---|---|
| All Linux-feasible checks pass (`verify-all.sh`) | PASS |
| Restore no longer destroys audit history | PASS (tests) |
| Privileged IPC refused for every non-elevated or wrong-channel caller | PASS (tests, mock transport) |
| Pipe owner + per-request identification implemented | Implemented, type-checked; **NOT RUN on Windows** |
| Pipe DACL without create-instance for users, server-PID check, pooled servers with joined shutdown (F-13/F-14/F-18) | Logic tested; pipe code type-checked; **NOT RUN on Windows** |
| Audit truncation detection, checkpoints, read-only verify tool, persisted mirror cursor (F-12/F-15) | PASS (tests); Event Log delivery **NOT RUN on Windows** |
| Concurrent first open of the database (F-19) | PASS (regression test) |
| Enforcement planning: conflicts, merge, exact rollback, suspend/resume, staleness | PASS (tests); registry capture/write **not implemented** |
| UI against the real backend (SQLite, authorization) | PASS (13 integration tests) |
| Event Log message table + installer registration | Implemented, tested generator; **NOT RUN on Windows** |
| Activation disabled and gated | PASS (tests) |
| Windows build (MSVC) | **NOT RUN** — first step of Stage A |
| MSI build/install/uninstall | **NOT RUN** — Stages A, C |
| Code signing | Not set up (L-19) |

**Classification (Phase 9B): CONDITIONAL READY for Windows VM validation.** The conditions
are the Windows-only items above: the first native MSVC build may surface compile errors in
code that has only been type-checked (`rc.exe`/embed-resource, SCM host, pooled pipes, SID
conversion, SCM PID query), which must be fixed before Stage B. The tickable list is
WINDOWS-ACCEPTANCE-CHECKLIST.md. This is not a production security approval.
