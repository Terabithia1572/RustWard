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
| B — Storage (`rustward-storage`) | SQLite (bundled), versioned migrations, settings, policy history with optimistic versioning, device inventory, hash-chained security events, retention with chain anchor, backup/restore, post-commit event observer (Event Log mirror) | IMPLEMENTED AND AUTOMATED-TESTED |
| C — Service (`rustward-app`, `rustward-service`) | Application service (all IPC requests), periodic inventory refresh with device-change wake-up (debounced, coalesced), health/degradation, retention scheduling, console mode, SCM host on windows-sys, Event Log mirroring, audited authorization failures (rate-limited), audited backups, restore with automatic pre-restore copy | App logic + runtime: IMPLEMENTED AND AUTOMATED-TESTED. SCM host, `CM_Register_Notification`, `ReportEventW`: IMPLEMENTED BUT NOT WINDOWS-VERIFIED (type-checked with `host-typecheck`; never executed) |
| D — Enforcement provider (`rustward-enforcement`) | `DeviceInstallRestrictionProvider` dry-run plan (layered Device Installation Restrictions model), preconditions, risks, gaps; states NotConfigured / Simulated / PendingValidation / ActiveUnverified / VerifiedProtected / Degraded / Error; activation compiled out | Dry-run model: IMPLEMENTED AND AUTOMATED-TESTED. Real effect on Windows: **BLOCKED** (needs acceptance VM + approval) |
| E — IPC (`rustward-ipc`) | Versioned envelopes, per-request access levels, server-side validation, length-prefixed frames (4 MiB), mock transport, golden contract; named pipes with DACLs, remote-client rejection, impersonation + elevation check | Protocol + mock: IMPLEMENTED AND AUTOMATED-TESTED. Named pipes: IMPLEMENTED BUT NOT WINDOWS-VERIFIED (type-checked) |
| F — Desktop app (`apps/rustward-desktop`) | Tauri 2 + React 19 + TS strict + Tailwind 4; Dashboard, Devices, Allowed Manufacturers, Blocked Devices, Audit Logs, Diagnostics, Settings (workstation ID, backups + confirmed restore); in-app notices for new simulated denials; Turkish primary, English; mandatory not-validated banner | Frontend: IMPLEMENTED AND AUTOMATED-TESTED. Tauri shell: compiled + IPC-tested on Linux/webkit2gtk; on WebView2: IMPLEMENTED BUT NOT WINDOWS-VERIFIED |
| G — Integration | UI → `ipc_call` → `rustward-ui-bridge` → (dev backend \| service pipe) → `rustward-app` → policy engine → SQLite | Dev-backend path: IMPLEMENTED AND AUTOMATED-TESTED (Tauri mock runtime). Service path: IMPLEMENTED BUT NOT WINDOWS-VERIFIED |
| H — Offline packaging preparation | Vendoring script (tested on Linux), offline build verified on Linux, release build script, MSI service fragment (draft), deployment/uninstall documentation | PARTIALLY IMPLEMENTED (Windows build and MSI NOT RUN) |

## Phase 9A — security hardening and Windows acceptance readiness

| Item | Content | Classification |
|---|---|---|
| Audit integrity | Two-step, non-destructive restore (backup policy becomes a new version; audit never replaced); registered + hashed backups; append-only triggers; failed attempts audited (AUDIT-INTEGRITY.md) | IMPLEMENTED AND AUTOMATED-TESTED |
| Privileged IPC | Full refusal matrix, replay, interruption and malformed-request tests through the real pipeline (`ipc_security.rs`); per-request identification after read; unidentifiable callers refused | Logic: IMPLEMENTED AND AUTOMATED-TESTED. Pipe owner check (`O:SY`), per-request token query: IMPLEMENTED BUT NOT WINDOWS-VERIFIED |
| Activation workflow | `rustward-enforcement::activation`: 6 stages, 13 gates (15 after Phase 9B), plan fingerprint, computed system-disk gate; activation refused (`ACTIVATION_ENABLED = false`) | IMPLEMENTED AND AUTOMATED-TESTED (as a refusal) |
| Event Log | MESSAGETABLE generator (tested), `build.rs` embedding (Windows only), WiX `util:EventSource`, start-failure event 1008 | Generator tested; embedding/registration IMPLEMENTED BUT NOT WINDOWS-VERIFIED |
| Release readiness | `deny.toml` + `cargo deny` clean (Windows target), dependency inventory, BUILD-INFO + hashes in release script, installer/version consistency tests | PARTIALLY IMPLEMENTED (Windows build NOT RUN) |
| Acceptance workflow | Stages A–F (F separate, not runnable in this build), Hyper-V limits (WINDOWS-VM-ACCEPTANCE.md) | Documented |
| Findings | 17 findings: 1 High, 6 Medium, 7 Low, 3 Info; 12 fixed or implemented, 5 open and documented (F-12…F-16) — SECURITY-AUDIT-PHASE-9A.md | — |

## Phase 9B — final implementation hardening before Windows validation

| Item | Content | Classification |
|---|---|---|
| F-12 audit vs. administrators | Truncation/gap detection, daily `audit_checkpoint` (5008) mirrored to the Event Log, read-only `verify-checkpoint` command | Partially mitigated (by design); tested |
| F-13 one pipe client at a time | Platform-independent pooled server (8 status / 4 admin), busy refusal, idle timeout | Logic tested; pipes NOT WINDOWS-VERIFIED |
| F-14 threads not joined | Shutdown wakes, answers in-flight, joins within 3 s, audits incomplete shutdown (1010) | Logic tested; NOT WINDOWS-VERIFIED |
| F-15 mirror cursor in memory | Persisted cursor, ordered back-fill (≤ 1000, gap event 1009), retry | IMPLEMENTED AND AUTOMATED-TESTED (Event Log delivery unverified) |
| F-16 LocalSystem | Service SID derivation (verified vector), SDDL builders, owner check accepts service SID, server-PID check | Prepared; open; decide in VM C16 |
| New F-18 pipe DACL | AU no longer gets `FILE_CREATE_PIPE_INSTANCE`; client rights reduced | Fixed; NOT WINDOWS-VERIFIED |
| New F-19 concurrent open | IMMEDIATE transactions, single migration transaction | Fixed + regression test |
| New F-20/F-21 | Offline-asset check, polyfill removed; test-runner advisories (dev only) | Fixed / open |
| Enforcement planning | `policy_state`: existing-policy model, conflicts, merge, exact rollback, suspend/resume, staleness; 2 new gates (15 total) | IMPLEMENTED AND AUTOMATED-TESTED; OS enforcement NOT IMPLEMENTED |
| Desktop workflow | 13 Vitest integration tests drive the real backend (SQLite) through a dev-only stdio harness, incl. standard-user refusals | IMPLEMENTED AND AUTOMATED-TESTED |
| Documents | SECURITY-AUDIT-PHASE-9B, ENFORCEMENT-PLANNING, WINDOWS-ACCEPTANCE-CHECKLIST; updated others | — |

## Phase 10 — read-only policy inspection and installed-device assessment

The actual Windows policy **application** code is **not implemented** (blocked by design): there
is no registry write path anywhere in RustWard, `ACTIVATION_ENABLED = false`, and Stage F was not
executed.

| Step | Item | Content | Classification |
|---|---|---|---|
| 1 | Policy reader | `rustward-windows::policy_reader`: `RegOpenKeyExW(KEY_READ \| KEY_WOW64_64KEY)`, `RegEnumValueW`, `RegEnumKeyExW`, `RegGetValueW` (UBR), `RegCloseKey`; `RtlGetVersion`, `GetProductInfo`; bounded (4096 entries, 64 KiB per value); allowlist test | IMPLEMENTED BUT NOT WINDOWS-VERIFIED (type-checked; native test written, NOT RUN) |
| 1 | Interpretation | `policy_inspect` (documented / unresolved / unrecognised names, layering support by build/UBR, edition, conflicts, plan presence), `policy_eval` (layered install-time evaluation model) | IMPLEMENTED AND AUTOMATED-TESTED |
| 1 | CLI | `rustward-inventory policy-capture`, `policy-inspect` | Logic tested from fixtures; live capture NOT WINDOWS-VERIFIED |
| 2 | Installed devices | `installed_assessment` + `rustward-inventory assess-installed`: denied-but-installed storage, internal disks protected, manual Device Manager steps (TR/EN) only, sanitized report | IMPLEMENTED AND AUTOMATED-TESTED (on synthetic inventories) |
| 3 | UI | Read-only IPC request `GetEnforcementReadiness` (26th request type); **Uygulama Hazırlığı** page: actual state, inspection source, conflicts, planned changes, 15 gates, permissions, recovery model, installed assessment; "Politikayı etkinleştir" permanently disabled | IMPLEMENTED AND AUTOMATED-TESTED (WebView2 NOT WINDOWS-VERIFIED) |
| 4 | Mock backend | `tests/mock_policy_backend.rs`: in-memory registry with fault injection — interruption, resumable rollback, unrelated values preserved, stale plans, authorization, "values present ≠ protected", verification failures | IMPLEMENTED AND AUTOMATED-TESTED (simulation only) |
| 4 | Fixes | F-19 follow-up (`PRAGMA journal_mode=WAL` busy without busy handler: bounded retry); integration harness truncated-line race | Fixed + repeated runs |
| 4 | Acceptance | WINDOWS-ACCEPTANCE-CHECKLIST.md and WINDOWS-VM-ACCEPTANCE.md restructured to Stages A–F (A compile, B device inspection, C service/IPC, D MSI/recovery, E policy inspection, F not executed) | Documented; no stage executed |
| — | Unresolved | List-entry layout and `*Retroactive` names (not in the Policy CSP mapping table); UBR has no documented API | Reported as unresolved, never guessed |

## Feature gaps (known, not hidden)

| Gap | Status |
|---|---|
| Desktop notification when a device is denied | **In-app notice only** (while the window is open); Windows toast notifications not implemented |
| Windows Event Log entries | Implemented in the Windows service; message table + installer registration prepared in Phase 9A; **not verified on Windows** |
| Real-time PnP arrival notification (`CM_Register_Notification`) | Implemented as a wake-up for the inventory refresh (telemetry only); **not verified on Windows** |
| Per-workstation ID | Configurable by an administrator (Settings → versioned policy edit); installer property still open |
| Restore from backup in UI | Two-step (preview with hash and changes → apply as a new policy version), automatic pre-restore copy, audit never replaced |
| Elevation UX | Admin actions need the app started "Run as administrator"; no in-app elevation |
| Real enforcement | Compiled out (`ACTIVATION_ENABLED = false`) |

## Separation of facts

| Category | Items |
|---|---|
| Verified facts (documentation) | Microsoft docs: DeviceInstallation CSP editions/versions/layering and the Policy CSP registry mapping table (value names used by the Phase 10 reader); USBSTOR vendor-level hardware ID format. Tauri bundler behaviour read from tauri-bundler 2.10.4 source (WiX download, WebView2 HEAD request, environment clearing). |
| Engineering assumptions | Install prevention ⇒ no volume ⇒ no access; non-retroactive rules; SCSI-namespace padding; INQUIRY vendor strings of SanDisk/Kingston/Seagate; WiX fragment works with Tauri's template. |
| Tested | See `TEST-RESULTS.md`: 270 Rust workspace tests, 2 release-mode bridge tests, 4 Tauri IPC tests, 43 Vitest + 16 Vitest integration tests, fmt/clippy/tsc/build/deny — all on Linux (Phase 10). |
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
| `e3f9bde` | Milestone H — offline packaging preparation, documentation |
| `c43a4c1`, `4909958` | Service host on windows-sys, device-change wake-up, Event Log mirror, authorization/backup auditing, workstation ID, restore; UI for these; documentation |
| `73537a2`, `296efc7`, `3c60cad` | Phase 9B — final implementation hardening before Windows validation (SECURITY-AUDIT-PHASE-9B.md) |
| `c63d188` | Phase 10 step 1 — read-only inspection of Device Installation Restrictions |
| `e17bd54` | Phase 10 step 2 — read-only assessment of already-installed storage devices |
| `60a676e` | Phase 10 step 3 — read-only enforcement readiness in the Turkish UI |
| (this commit) | Phase 10 step 4 — mock policy backend tests, Stage A–F acceptance documents, F-19 follow-up fix |
| `3aac8a2`, `7fd1a4b` | Phase 9A — security hardening and Windows acceptance readiness — see SECURITY-AUDIT-PHASE-9A.md |

## Environment

| Item | Value |
|---|---|
| Development PC | Windows x64 with MSVC 14.44/14.51, Windows SDK 10.0.22621/26100, WebView2 156; not the deployment target. RustWard was never installed or run on it. |
| Build/verification workspace | Ubuntu 24.04.5, rustc 1.97.0, Node 22.23.4 (`TEST-RESULTS.md`) |
| Deployment target | Five standalone Windows 10 Pro x64 workstations — not accessed |
| Acceptance VM | Not yet provided |
