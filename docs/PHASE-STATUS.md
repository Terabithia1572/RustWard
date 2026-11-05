# Phase Status

Last updated: 2026-11-06.

> RustWard is **not production-ready** and **does not block any USB device**. All policy
> decisions are simulations. Native Windows and physical USB testing were postponed by the
> project owner to the final acceptance stage and are **DEFERRED / NOT RUN**.

## Classification used

| Class | Meaning |
|---|---|
| **IMPLEMENTED AND AUTOMATED-TESTED** | Platform-independent code with passing automated tests (Linux). |
| **IMPLEMENTED BUT NOT WINDOWS-VERIFIED** | Windows-specific code that is written and type-checked (or compiled on Linux) but never executed on Windows. |
| **PARTIALLY IMPLEMENTED** | Some required parts missing or only drafted. |
| **BLOCKED** | Cannot progress without hardware, the acceptance VM or an owner decision. |

## Milestones (development without physical Windows testing)

| Milestone | Content | Classification |
|---|---|---|
| A — Policy engine (`rustward-core`) | PnP ID parsing, catalog + policy validation, default deny, classification, evaluation with evidence, policy editing with versioned history, explanations (TR/EN), snapshot diff and re-enumeration correlation | IMPLEMENTED AND AUTOMATED-TESTED |
| B — Storage (`rustward-storage`) | SQLite (bundled), versioned migrations, settings, policy history with optimistic versioning, device inventory, hash-chained security events, retention with chain anchor, backup/restore | IMPLEMENTED AND AUTOMATED-TESTED (restore not exposed in UI) |
| C — Service (`rustward-app`, `rustward-service`) | Application service (all IPC requests), periodic inventory refresh, health/degradation, retention scheduling, console mode | App logic + console runtime: IMPLEMENTED AND AUTOMATED-TESTED. SCM integration (`scm.rs`): IMPLEMENTED BUT NOT WINDOWS-VERIFIED (not compiled anywhere) |
| D — Enforcement provider (`rustward-enforcement`) | `DeviceInstallRestrictionProvider` dry-run plan (layered Device Installation Restrictions model), preconditions, risks, gaps; states NotConfigured / Simulated / PendingValidation / ActiveUnverified / VerifiedProtected / Degraded / Error; activation compiled out | Dry-run model: IMPLEMENTED AND AUTOMATED-TESTED. Real effect on Windows: **BLOCKED** (needs acceptance VM + approval) |
| E — IPC (`rustward-ipc`) | Versioned envelopes, per-request access levels, server-side validation, length-prefixed frames (4 MiB), mock transport, golden contract; named pipes with DACLs, remote-client rejection, impersonation + elevation check | Protocol + mock: IMPLEMENTED AND AUTOMATED-TESTED. Named pipes: IMPLEMENTED BUT NOT WINDOWS-VERIFIED (type-checked) |
| F — Desktop app (`apps/rustward-desktop`) | Tauri 2 + React 19 + TS strict + Tailwind 4; Dashboard, Devices, Allowed Manufacturers, Blocked Devices, Audit Logs, Diagnostics, Settings; Turkish primary, English; mandatory not-validated banner | Frontend: IMPLEMENTED AND AUTOMATED-TESTED. Tauri shell: compiled + IPC-tested on Linux/webkit2gtk; on WebView2: IMPLEMENTED BUT NOT WINDOWS-VERIFIED |
| G — Integration | UI → `ipc_call` → `rustward-ui-bridge` → (dev backend \| service pipe) → `rustward-app` → policy engine → SQLite | Dev-backend path: IMPLEMENTED AND AUTOMATED-TESTED (Tauri mock runtime). Service path: IMPLEMENTED BUT NOT WINDOWS-VERIFIED |
| H — Offline packaging preparation | Vendoring script (tested on Linux), offline build verified on Linux, release build script, MSI service fragment (draft), deployment/uninstall documentation | PARTIALLY IMPLEMENTED (Windows build and MSI NOT RUN) |

## Feature gaps (known, not hidden)

| Gap | Status |
|---|---|
| Desktop notification when a device is denied | Setting stored; delivery **not implemented** |
| Windows Event Log entries | **Not implemented** (audit goes to SQLite only) |
| Real-time PnP arrival notification (`CM_Register_Notification`) | **Not implemented**; periodic refresh (default 30 s) |
| Per-workstation ID | Not configurable; initial policy uses `PC-01` |
| Restore from backup in UI | Storage function exists; no IPC/UI |
| Elevation UX | Admin actions need the app started "Run as administrator"; no in-app elevation |
| Real enforcement | Compiled out (`ACTIVATION_ENABLED = false`) |

## Separation of facts

| Category | Items |
|---|---|
| Verified facts (documentation) | Microsoft docs: DeviceInstallation CSP editions/versions/layering; USBSTOR vendor-level hardware ID format. Tauri bundler behaviour read from tauri-bundler 2.10.4 source (WiX download, WebView2 HEAD request, environment clearing). |
| Engineering assumptions | Install prevention ⇒ no volume ⇒ no access; non-retroactive rules; SCSI-namespace padding; INQUIRY vendor strings of SanDisk/Kingston/Seagate; WiX fragment works with Tauri's template. |
| Tested | See `TEST-RESULTS.md`: 151 Rust workspace tests, 2 release-mode bridge tests, 4 Tauri IPC tests, 30 Vitest tests, fmt/clippy/tsc/build — all on Linux. |
| Not tested | Anything on Windows; anything on hardware. |

## Commits (private local repository, never pushed)

| Commit | Content |
|---|---|
| `2894098` | Phase 0 + Phase 1 read-only foundation |
| `9df731f` | Phase 1 hardening |
| `9ce785d` | Milestone A — policy engine |
| `0aaec8c` | Milestone B — storage |
| `20a1263` | Milestones D + E — dry-run enforcement, IPC |
| `f173fea` | Milestones C + G — application backend, service foundation |
| `a77c9d8` | Milestone F — Tauri desktop app |
| (this commit) | Milestone H — offline packaging preparation, documentation |

## Environment

| Item | Value |
|---|---|
| Development PC | Windows x64 with MSVC 14.44/14.51, Windows SDK 10.0.22621/26100, WebView2 156; not the deployment target. RustWard was never installed or run on it. |
| Build/verification workspace | Ubuntu 24.04.5, rustc 1.97.0, Node 22.23.4 (`TEST-RESULTS.md`) |
| Deployment target | Five standalone Windows 10 Pro x64 workstations — not accessed |
| Acceptance VM | Not yet provided |
