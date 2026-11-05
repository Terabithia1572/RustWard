# Offline Deployment (plan — Phase 8)

Nothing here is implemented or tested yet. Offline installation will not be
claimed until tested on a machine with networking disabled.

## Packaging

- Tauri 2 supports MSI (WiX v3, built only on Windows) and NSIS (`-setup.exe`). Source: Tauri
  *Windows Installer* guide.
- **Preferred: MSI** for per-machine installation with a Windows service, predictable
  repair/uninstall, and administrator-driven deployment. Service registration via a WiX
  custom component or a signed post-install step; decision in Phase 8.
- NSIS remains an option (supports `perMachine`); cross-compiling from Linux is described by
  Tauri as less tested.

## WebView2

| Mode (`bundle.windows.webviewInstallMode.type`) | Needs internet | Size impact |
|---|---|---|
| `downloadBootstrapper` (default) | Yes | 0 |
| `embedBootstrapper` | Yes | ~1.8 MB |
| `offlineInstaller` | **No** | ~127 MB |
| `fixedVersion` | **No** | ~180 MB; updates managed by us |
| `skip` | — | app fails if runtime missing |

Choose `offlineInstaller` (Evergreen runtime installed once) or `fixedVersion` (fully pinned,
reproducible). For air-gapped machines without Windows Update, `fixedVersion` gives the most
predictable result but makes RustWard responsible for shipping WebView2 security updates.

## Requirements

- No CDN, telemetry, account, online license check or auto-update.
- All fonts/assets bundled.
- Reproducible builds: pinned toolchain, `Cargo.lock`, `package-lock.json`, `cargo vendor` /
  npm offline cache for the build machine.
- SBOM (CycloneDX for Rust and npm), `cargo audit`/`cargo deny` with an offline advisory DB
  snapshot, SHA-256 hashes of all artifacts.
- Code signing of binaries and installer (certificate management outside the repository).
- Uninstall restores the baseline policy captured at install time and leaves audit data unless
  the administrator chooses to export/remove it.
