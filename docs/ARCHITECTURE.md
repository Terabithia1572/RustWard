# Architecture

## Layers and trust boundaries

```
 ┌────────────────────────────┐   named pipe (ACL: SYSTEM + Administrators,
 │ apps/rustward-desktop      │   client identity checked)          [Phase 5]
 │ Tauri 2 + React + TS       │◄──────────────────────────────┐
 │ unelevated, no DB access   │                               │
 └────────────────────────────┘                               │
                                                ┌─────────────┴─────────────┐
                                                │ crates/rustward-service   │ [Phase 4]
                                                │ Windows service, SYSTEM   │
                                                │ telemetry + coordination  │
                                                └──┬───────────┬────────────┘
                     ┌─────────────────────────────┘           │
       ┌─────────────▼────────────┐   ┌───────────────────────▼──────────────┐
       │ crates/rustward-storage  │   │ crates/rustward-enforcement           │
       │ SQLite, migrations,      │   │ provider trait, capability report,    │
       │ audit hash chain [Ph. 4] │   │ ProtectionState (verified only with   │
       └──────────────────────────┘   │ evidence)            [Phase 1: types] │
                                      └──────────────┬────────────────────────┘
                                                     │ (Phase 2: Device Install
                                                     │  Restriction provider)
 ┌──────────────────────────────┐   ┌────────────────▼──────────────┐
 │ crates/rustward-core          │◄──┤ crates/rustward-windows       │
 │ pure logic, no I/O, no unsafe │   │ READ-ONLY SetupAPI inventory  │ [Phase 1]
 │ ids, catalog, policy,         │   │ (later: CM_Register_Notification
 │ classify, evaluate, plan      │   │  telemetry)                   │
 └──────────────────────────────┘   └───────────────────────────────┘
```

The OS policy (not RustWard's process) is the enforcement boundary in the
candidate design. The service never sits in the I/O path; if it stops, the
OS policy keeps enforcing (fail-closed for new devices).

## Implemented in Phase 1

| Crate | Responsibility | Unsafe | Platform |
|---|---|---|---|
| `rustward-core` | PnP ID parsing/encoding, snapshot model, catalog + policy validation, classification, default-deny evaluation with evidence, plan preview + layered-evaluation **model**, consistency check | `forbid` | any |
| `rustward-windows` | Read-only device inventory via `SetupDiGetClassDevsW` / `SetupDiEnumDeviceInfo` / `SetupDiGetDevicePropertyW`; RAII handle cleanup; property decoding; read-only API allowlist test | documented, only in `setupapi.rs` | Windows (type-checks elsewhere with `host-typecheck`) |
| `rustward-enforcement` | `EnforcementProvider` trait, `CapabilityReport`, `ProtectionState`, notification selection; only `SimulationOnlyProvider` exists | `forbid` | any |
| `rustward-inventory` | CLI: `scan`, `capture`, `evaluate`, `plan` — all read-only | `forbid` | any (live scan on Windows) |

## Planned (not created yet)

`rustward-service` (Phase 4), `rustward-ipc` (Phase 5), `rustward-storage` (Phase 4),
`apps/rustward-desktop` (Phase 6). They are intentionally not scaffolded as
empty crates; the boundaries above are the contract.

## Key design rules

1. **Detection ≠ enforcement.** Every decision carries `enforcement: not_enforced_simulation`
   until a provider produces `VerificationEvidence`.
2. **The decision engine models the OS rule exactly.** Only the vendor-level INQUIRY
   hardware ID decides; VID and names are evidence only. `check_consistency` reports any
   divergence between the engine and the modelled OS plan (`enforcement_gap`, `over_blocking`).
3. **Default deny is not configurable.** Policies can only add brands.
4. **Policies are bound to a catalog version**, so a catalog change cannot silently alter
   an active policy.
5. **Platform code is isolated.** `rustward-core` never imports Windows APIs.

## Dependencies (resolved, see Cargo.lock)

| Crate | Version | Why |
|---|---|---|
| serde / serde_derive | 1.0.229 | JSON models |
| serde_json | 1.0.154 | catalog, policy, snapshot files |
| thiserror | 2.0.21 | error types |
| windows-sys | 0.61.2 | Microsoft raw Win32 bindings (SetupAPI, device properties) |

No other runtime dependencies. Toolchain used for verification: rustc 1.97.0.
