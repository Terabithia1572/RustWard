# Offline Deployment

Status: **preparation only.** Nothing in this document has been executed on Windows.
The installer has not been built, installed or uninstalled anywhere. Offline installation
will not be claimed until it is tested on the acceptance VM with networking disabled
(TEST-PLAN T-25).

Target: Windows 10 Pro x64 (22H2 recommended), five standalone workstations, no Active
Directory, no internet.

## 1. Artifacts

| Artifact | Built by | Status |
|---|---|---|
| `rustward-service.exe` | `cargo build --release -p rustward-service` | Builds on Linux; **Windows build NOT RUN** |
| `rustward-inventory.exe` (read-only CLI) | `cargo build --release -p rustward-inventory` | idem |
| `RustWard_0.1.0_x64_*.msi` (desktop app, optional service) | `npx tauri build --bundles msi` | **NOT RUN** |
| `SHA256SUMS.txt` | `scripts/build-release.ps1` | **NOT RUN** |

Code signing is not set up. Unsigned binaries must be accepted explicitly by the security
owner for the acceptance VM; production deployment requires signing.

## 2. Build inputs for an offline build machine

`scripts/vendor-offline.sh` (run on a connected machine) writes, inside the repository:

| Path | Content |
|---|---|
| `vendor/` | All Rust crates for the workspace **and** the Tauri shell (`cargo vendor --locked --versioned-dirs`; 413 crates, ~600 MB) |
| `.cargo-offline/config.toml` | Source replacement → `vendor/` (pass with `--config`) |
| `.npm-offline-cache/` | npm tarballs for `package-lock.json`, including the **win32-x64** native packages of esbuild, rollup, Tailwind oxide and lightningcss (~76 MB) |

Verified on Linux (2026-11-06): with an empty `CARGO_HOME`, `cargo build --offline` of the
service and CLI and `cargo check --offline` of the Tauri shell succeed from `vendor/`;
`npm ci --offline` succeeds for linux-x64 and `--os=win32 --cpu=x64`. Not verified on Windows.

These directories are git-ignored; transfer them with the repository on approved media.

## 3. Build-time network requirements of `tauri build` (important)

Read from the tauri-bundler 2.10.4 source (`bundle/windows/msi/mod.rs`, `bundle/windows/util.rs`):

| Item | Behaviour | Offline consequence |
|---|---|---|
| WiX Toolset 3.14 | Downloaded from GitHub into `%LOCALAPPDATA%\tauri\WixTools314` if missing (SHA-256 checked) | Pre-provision that directory on the build machine |
| WebView2 `offlineInstaller` | `tauri build` sends a **HEAD request** to `go.microsoft.com` to resolve the installer path, then downloads it (~127 MB) unless already in `target\release\wix\x64\<guid>\` | The HEAD request is made **every build** → the build machine needs internet in this mode |
| WebView2 `fixedVersion` | Uses a local, extracted Fixed Version runtime directory; no download | Works on an air-gapped build machine; RustWard then ships WebView2 security updates itself |
| WiX environment | The bundler clears the environment for candle/light except `SYSTEMROOT`, `TMP`, `TEMP` and `TAURI*` variables | The service fragment uses `$(env.TAURI_RUSTWARD_SERVICE_EXE)` |

**Recommended:** build the MSI on a dedicated, *connected* build machine (it never touches
the protected network); only the finished, hashed MSI is carried to the workstations. The
MSI itself embeds the WebView2 offline installer and installs without internet. If the
build machine must be air-gapped, switch to `fixedVersion` and pre-provision WiX.

## 4. Building (Windows build machine)

```powershell
# Connected build machine (recommended)
powershell -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -WithService

# Air-gapped build machine (after vendor-offline.sh, WixTools314 pre-provisioned,
# and bundle.windows.webviewInstallMode switched to fixedVersion)
powershell -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -Offline -WithService
```

`build-release.ps1` (NOT RUN) runs tests, builds release binaries, `npm ci`, typecheck,
Vitest, `tauri build --bundles msi`, writes `release-out\BUILD-INFO.txt` (version, commit,
toolchain), copies the dependency inventory, and writes `release-out\SHA256SUMS.txt` over all
files. It never
installs the MSI or registers the service.

Release builds of the desktop app cannot contain the development backend: it is compiled
only with `debug_assertions` **and** the `dev-backend` feature (tested: release mode with the
feature on still selects the service).

## 5. What the MSI installs (with `-WithService`)

Defined by Tauri's template plus the **draft** fragment `packaging/wix/rustward-service.wxs`
(merged by `packaging/tauri.acceptance.conf.json`). Per-machine install.

| Item | Detail | Status |
|---|---|---|
| `C:\Program Files\RustWard\RustWard.exe` | Desktop app (unelevated; admin actions require "Run as administrator") | Tauri default |
| WebView2 Evergreen runtime | Silent offline installer, only if missing | Tauri `offlineInstaller` |
| `C:\Program Files\RustWard\rustward-service.exe` | Service binary | Draft fragment |
| Service `RustWardService` | `LocalSystem`, auto start, argument `service`, restart on failure 5 s ×3, reset 1 day; started on install, stopped/removed on uninstall | Draft fragment |
| `%ProgramData%\RustWard` | Protected DACL `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (SYSTEM + Administrators only); permanent | Draft fragment |
| Event Log source `RustWard` | `util:EventSource`, message file = `rustward-service.exe` | Draft fragment |
| Database | Created by the service on first start (`rustward.db`, WAL, migrations v1–v2); initial policy from `config/policy.example.json`, dry-run (see §6) | Implemented, Linux-tested |

The MSI changes **no** device, driver, registry policy or Group Policy. Enforcement stays
compiled out (`ACTIVATION_ENABLED = false`).

Manual equivalent (for diagnosis only, on the acceptance VM): `rustward-service install-plan`
prints the `sc.exe`/`icacls` commands; it executes nothing.

## 6. Database initialization

- First service start creates `%ProgramData%\RustWard\rustward.db` and applies migrations v1
  (schema) and v2 (backup registry, append-only triggers). Existing v1 databases are upgraded
  in place, keeping all data (tested).
- Initial policy: the embedded `config/manufacturer-catalog.json` and
  `config/policy.example.json` — workstation ID **`PC-01`**, SanDisk and TÜBİTAK allowed,
  mode `dry_run`. TÜBİTAK has no verified identifier yet, so its devices are still denied
  in simulation. Administrators change the allowlist in the UI.
- **Workstation ID:** after installation an administrator renames each machine in
  Settings → Workstation ID (a versioned, audited policy edit). An installer property is
  still open. Decide whether the initial allowlist should be empty or the example brands.
- **Event Log source (prepared in Phase 9A, NOT VERIFIED):** `rustward-service.exe` embeds a
  `MESSAGETABLE` resource generated by its `build.rs` from
  `rustward-windows/src/eventlog_map.rs` (one entry `%1` per event ID; IDs listed in
  WINDOWS-VM-ACCEPTANCE.md Stage D). The draft WiX fragment registers the source with
  `<util:EventSource Log="Application" Name="RustWard" EventMessageFile="[#RustWardServiceExe]"/>`,
  which creates `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\RustWard` and
  removes it on uninstall. RustWard never writes this key itself. Building the service on
  Windows needs `rc.exe` from the Windows 10/11 SDK (installed with the MSVC build tools).
  Cross-compiling the service from Linux is refused by `build.rs`.
- A database with a newer schema is refused (fail closed); a tampered policy row is reported
  as corrupt and the service keeps running with diagnostics.

## 7. Uninstall and recovery

| Action | Result |
|---|---|
| MSI uninstall | Stops and deletes `RustWardService`, removes program files. `%ProgramData%\RustWard` (database, backups, audit chain) is **kept**. |
| Remove audit data | Administrator exports events (UI → Audit Logs → CSV/JSON) and creates a backup (Settings), then deletes `%ProgramData%\RustWard` manually. |
| Restore | Two-step and non-destructive (Settings → Yedekler → Geri yükle → preview → Uygula): only registered backups whose SHA-256 matches; integrity, schema and policy are verified; the backup's policy becomes a **new** version after a pre-restore backup; audit history is never replaced (AUDIT-INTEGRITY.md). Backups never overwrite an existing file. |
| OS policy | Nothing to roll back in this build (no enforcement). Enforcement-phase rollback is specified in `RECOVERY-PLAN.md`. |

## 8. Requirements that stay in force

- No CDN, telemetry, account, online licence check or auto-update (no updater plugin; CSP
  `default-src 'self'`; bundle checked for external URLs).
- All fonts (system stack) and icons (lucide, bundled) are local.
- Pinned toolchain and lockfiles: `Cargo.lock`, `apps/rustward-desktop/src-tauri/Cargo.lock`,
  `package-lock.json`.
- Dependency inventory: `docs/DEPENDENCY-INVENTORY.md` (`scripts/dependency-inventory.sh`),
  copied into `release-out` and covered by `SHA256SUMS.txt`. `cargo deny check` (licences,
  advisories, sources, bans; Windows target) passes for both lockfiles as of 2026-11-06.
- Still to do before production: SBOM (CycloneDX), an offline advisory snapshot for
  `cargo deny` on the air-gapped side, code signing.
