# RustWard

Offline, brand-based USB storage access control for standalone Windows 10 Pro x64
workstations.

> **Current state (2026-11-06): development build, simulation only.**
> RustWard does **not** block any USB device. Every decision is a simulation
> (`SİMÜLE İZİN` / `SİMÜLE RET`) and the dashboard shows
> **"Koruma henüz gerçek Windows ortamında doğrulanmadı."** Native Windows and physical USB
> testing are deferred to the final acceptance stage. Not production-ready.

## What exists

| Part | Path | Status |
|---|---|---|
| Policy engine | `crates/rustward-core` | Tested |
| SQLite storage, hash-chained audit | `crates/rustward-storage` | Tested |
| Application service (all requests) | `crates/rustward-app` | Tested |
| Windows service | `crates/rustward-service` | Console mode + runtime tested; SCM host, Event Log mirror and device-change wake-up type-checked only (never run) |
| Dry-run enforcement providers + activation gates | `crates/rustward-enforcement` | Tested as a model; activation always refused; **no enforcement** |
| Local IPC (mock + named pipes) | `crates/rustward-ipc` | Protocol tested; pipes type-checked only |
| Windows adapters (read-only SetupAPI inventory, device-change notifications, Event Log, SCM host) | `crates/rustward-windows`, `crates/rustward-inventory` | Logic tested; native NOT RUN |
| Desktop app (Tauri 2, React, TS, Tailwind) | `apps/rustward-desktop` | UI tested; Tauri shell tested on Linux only |
| Backend selection for the app | `crates/rustward-ui-bridge` | Tested |
| Offline packaging preparation | `scripts/`, `packaging/` | Vendoring tested on Linux; MSI NOT RUN |

Details and classification: [`docs/PHASE-STATUS.md`](docs/PHASE-STATUS.md).
Test evidence: [`docs/TEST-RESULTS.md`](docs/TEST-RESULTS.md).

## Development

```bash
./scripts/verify-all.sh                       # fmt, clippy, all tests, UI typecheck/tests/build,
                                              # offline-asset check, UI ↔ real-backend integration, cargo deny

cd apps/rustward-desktop && npm ci
npm test                                      # Vitest
npx tauri dev                                 # debug build: in-process dev backend, temp DB
```

The debug app uses a development backend (temporary database, synthetic administrator,
same validation and authorization code as the service). Release builds always talk to the
Windows service; the development backend cannot be compiled into them.

Windows (MSVC toolchain), read-only:

```powershell
cargo test --workspace
cargo run -p rustward-inventory -- scan
cargo run -p rustward-service -- console      # temp database, synthetic inventory, no install
```

Never install or register the service on a development machine. Packaging:
[`docs/OFFLINE-DEPLOYMENT.md`](docs/OFFLINE-DEPLOYMENT.md).

## Feasibility in one paragraph

The only brand-level identifier Windows can enforce is the SCSI INQUIRY vendor string,
exposed as a vendor-level hardware ID such as `USBSTOR\DiskSanDisk_`. The candidate
mechanism is Windows Device Installation Restrictions with layered evaluation. It is not
spoof-proof, does not re-evaluate already-installed devices, and cannot help products that
report a generic controller vendor. TÜBİTAK SIR II identifiers are still unknown. See
[`docs/ENFORCEMENT-FEASIBILITY.md`](docs/ENFORCEMENT-FEASIBILITY.md).

## Documentation

| Document | Content |
|---|---|
| [PHASE-STATUS](docs/PHASE-STATUS.md) | Milestones, classification, gaps, commits |
| [TEST-RESULTS](docs/TEST-RESULTS.md) | What was tested where, and what is DEFERRED |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Crates, trust boundaries, IPC contract |
| [SECURITY-MODEL](docs/SECURITY-MODEL.md) / [THREAT-MODEL](docs/THREAT-MODEL.md) | Privilege separation, pipes, Tauri hardening |
| [KNOWN-LIMITATIONS](docs/KNOWN-LIMITATIONS.md) | Residual risks L-01…L-31 |
| [OFFLINE-DEPLOYMENT](docs/OFFLINE-DEPLOYMENT.md) | Vendoring, MSI, WebView2, install/uninstall |
| [ENFORCEMENT-FEASIBILITY](docs/ENFORCEMENT-FEASIBILITY.md) | Mechanism comparison and decision |
| [BRAND-IDENTIFICATION](docs/BRAND-IDENTIFICATION.md) / [DEVICE-CLASSIFICATION](docs/DEVICE-CLASSIFICATION.md) | Identifiers, categories |
| [TEST-PLAN](docs/TEST-PLAN.md) / [RECOVERY-PLAN](docs/RECOVERY-PLAN.md) | Acceptance tests, rollback |
| [SECURITY-AUDIT-PHASE-9A](docs/SECURITY-AUDIT-PHASE-9A.md) | Phase 9A findings by severity, fixes, open items |
| [SECURITY-AUDIT-PHASE-9B](docs/SECURITY-AUDIT-PHASE-9B.md) | Disposition of F-12…F-16, new findings F-18…F-21, regression checklist |
| [ENFORCEMENT-PLANNING](docs/ENFORCEMENT-PLANNING.md) | Stages, existing-policy comparison, merge, rollback, staleness; DIR strategy review; what is unimplemented |
| [WINDOWS-ACCEPTANCE-CHECKLIST](docs/WINDOWS-ACCEPTANCE-CHECKLIST.md) | Tickable Stage A–E checklist with evidence slots |
| [AUDIT-INTEGRITY](docs/AUDIT-INTEGRITY.md) | Non-destructive restore, backup verification, tamper-resistance limits |
| [WINDOWS-VM-ACCEPTANCE](docs/WINDOWS-VM-ACCEPTANCE.md) | Stages A–F on a disposable Windows 10 Pro VM; Hyper-V USB limits |
| [RELEASE-READINESS](docs/RELEASE-READINESS.md) | Target config, installer design, hashes, dependencies, readiness classification |
| [DEPENDENCY-INVENTORY](docs/DEPENDENCY-INVENTORY.md) | Generated crate/npm inventory (Windows target) |

## Safety rules for contributors

Do not modify Windows security policy, install drivers, disable devices or register the
service on the development machine or any production workstation. Enforcement experiments
run only on an isolated, imaged acceptance VM with written approval.
