# Phase Status

Last updated: 2026-11-05.

| Phase | Status | Notes |
|---|---|---|
| 0 — Repository and feasibility | **Done** | Feasibility matrix, threat model, limitations, workspace design, docs |
| 1 — Read-only inventory | **Foundation done; Windows execution pending** | Core logic + SetupAPI backend implemented and type-checked; needs a native run on Windows (TEST-PLAN W-01..W-05) |
| 2 — Enforcement feasibility PoC | Not started — **CONDITIONAL GO** | Requires isolated test PC, hardware set, SIR II inspection, written approval |
| 3 — Policy engine | Partially pre-built in `rustward-core` (validation, default deny, versioning, catalog binding) | Change history and persistence pending |
| 4–9 | Not started | — |

## Separation of facts

| Category | Items |
|---|---|
| Verified facts | Microsoft docs: DeviceInstallation CSP editions/versions/layering order; USBSTOR vendor-level hardware ID format; MDE requires internet connectivity and MDE licensing; kernel driver signing rules; windows-drivers-rs not production-ready. Public usb.ids VIDs for SanDisk, Kingston, Seagate. |
| Engineering assumptions | Install prevention ⇒ no volume ⇒ no access; non-retroactive rules leave installed devices untouched; SCSI-namespace padding; comma→`_` rule; SanDisk/Kingston/Seagate INQUIRY vendor strings. |
| Implemented | ID parsing/encoding, snapshot model, catalog + policy validation, classification, evaluation with evidence, plan preview, layered-evaluation model, consistency check, read-only SetupAPI enumerator, enforcement/protection-state types, inventory CLI, prereq script. |
| Tested | 47 automated tests + clippy (Linux workspace). Windows backend type-checked, **not executed**. |
| Not tested | Anything on Windows; anything on hardware. |
| Remaining risks | `KNOWN-LIMITATIONS.md` L-01…L-12. |

## Environment observed (2026-11-05)

### Development PC (Windows x64, device name `yunuss`) — observed read-only by folder listing

| Item | Observation |
|---|---|
| OS edition/build | **Not determined** (run `scripts\check-prereqs.ps1`) |
| Rust | rustup toolchain `stable-x86_64-pc-windows-msvc` present; exact version not readable remotely |
| MSVC | Visual Studio 2022 Enterprise (MSVC 14.44.35207) and Visual Studio 18 Enterprise/Insiders (MSVC 14.51.36231) |
| Windows SDK | 10.0.22621.0 and 10.0.26100.0 |
| WDK | **Not installed** (no `km` headers) — only needed for the minifilter fallback |
| Node.js | Installed under `C:\Program Files\nodejs`; version not readable remotely |
| Git | Git for Windows installed; version not readable remotely |
| WebView2 | 156.0.4314.58 |
| Tauri CLI | Not checked (Phase 6) |

The development PC is **not** the deployment target. The deployment target is
Windows 10 Pro x64 on five standalone workstations; none were accessed.

### Build/verification workspace (Linux x86_64)

rustc 1.97.0, cargo 1.97.0, clippy, rustfmt, Node 22.23.4, git 2.43.0. The
`x86_64-pc-windows-msvc` Rust target could not be downloaded (network policy), so the
Windows backend was type-checked through the `host-typecheck` feature instead of a
cross-compile.

### Dependency versions (Cargo.lock)

serde 1.0.229, serde_json 1.0.154, thiserror 2.0.21, windows-sys 0.61.2.
