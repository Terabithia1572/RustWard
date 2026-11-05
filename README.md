# RustWard

Offline USB storage access control for standalone Windows 10 Pro workstations.

> **Current state: Phase 0 complete, Phase 1 foundation (read-only).**
> RustWard does **not** block anything yet. Every output is a simulation and says so.

## What exists today

- `rustward-core` — pure Rust domain logic: Windows PnP ID parsing, manufacturer catalog,
  per-workstation brand policy (default deny), device classification, evaluation with
  evidence, and a *preview* of the Windows Device Installation Restriction configuration
  that Phase 2 would test.
- `rustward-windows` — read-only device inventory through SetupAPI.
- `rustward-enforcement` — honest protection-state types; no enforcement provider yet.
- `rustward-inventory` — read-only CLI.

## Quick start (Windows, MSVC toolchain)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-prereqs.ps1   # read-only environment report
cargo test --workspace
cargo run -p rustward-inventory -- scan                                  # live, read-only
cargo run -p rustward-inventory -- capture --include-non-present --out baseline\devices.json
cargo run -p rustward-inventory -- evaluate --snapshot tests\fixtures\synthetic-lab-snapshot.json
cargo run -p rustward-inventory -- plan --live                           # preview, never applied
```

## Feasibility in one paragraph

The only brand-level identifier Windows can enforce is the SCSI INQUIRY vendor string,
exposed as a vendor-level hardware ID such as `USBSTOR\DiskSanDisk_`. The candidate
mechanism is Windows Device Installation Restrictions with layered evaluation. It is not
spoof-proof, does not re-evaluate already-installed devices, and cannot help products
that report a generic controller vendor. TÜBİTAK SIR II identifiers are still unknown.
Recommendation: **CONDITIONAL GO** for a test-only Phase 2 proof of concept. See
[`docs/ENFORCEMENT-FEASIBILITY.md`](docs/ENFORCEMENT-FEASIBILITY.md).

## Documentation

| Document | Content |
|---|---|
| [ENFORCEMENT-FEASIBILITY](docs/ENFORCEMENT-FEASIBILITY.md) | Mechanism comparison, matrix, blockers, decision |
| [KNOWN-LIMITATIONS](docs/KNOWN-LIMITATIONS.md) | Residual risks needing sign-off |
| [BRAND-IDENTIFICATION](docs/BRAND-IDENTIFICATION.md) | Catalog, identifiers, verification levels |
| [DEVICE-CLASSIFICATION](docs/DEVICE-CLASSIFICATION.md) | Categories, peripheral impact matrix, scope decisions |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Crates, boundaries, dependencies |
| [THREAT-MODEL](docs/THREAT-MODEL.md) / [SECURITY-MODEL](docs/SECURITY-MODEL.md) | Adversaries, privilege separation, IPC |
| [TEST-PLAN](docs/TEST-PLAN.md) | Automated results and 30 hardware acceptance tests |
| [RECOVERY-PLAN](docs/RECOVERY-PLAN.md) | Baseline capture and rollback |
| [OFFLINE-DEPLOYMENT](docs/OFFLINE-DEPLOYMENT.md) | MSI/NSIS, WebView2 offline |
| [PHASE-STATUS](docs/PHASE-STATUS.md) | Progress, environment, verified vs. assumed |

## Safety rules for contributors

Do not modify Windows security policy, install drivers, or disable devices on the
development machine or any production workstation. Phase 2 experiments run only on an
isolated, imaged test PC with written approval.
