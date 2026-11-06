# Architecture

Status 2026-11-06: all components below exist. Windows-specific parts are type-checked
or compiled on Linux but **not executed on Windows** (`PHASE-STATUS.md`).

## Layers and trust boundaries

```
 ┌──────────────────────────────────────────┐
 │ apps/rustward-desktop  (unelevated user)  │
 │ React 19 + TS strict + Tailwind 4         │  WebView2; CSP default-src 'self'
 │   │ invoke("ipc_call", {request})        │  capability: allow-ipc-call only
 │ src-tauri (Tauri 2.12)                    │
 │   └─ rustward-ui-bridge                   │
 │        ├─ release: service pipe client    │
 │        └─ debug+dev-backend: in-process ──┼──────────────┐
 └────────────────┬─────────────────────────┘              │
     named pipes  │  \\.\pipe\RustWard.Status.v1  (Authenticated Users: read/write, read-only requests)
                  │  \\.\pipe\RustWard.Admin.v1   (SYSTEM + Administrators; elevated token required)
 ┌────────────────▼─────────────────────────┐              │
 │ crates/rustward-service  (LocalSystem)    │              │
 │  SCM wrapper, runtime loop, pipe servers  │              │
 │   └─ rustward-ipc::rpc::process ──────────┼──────────────┘ same validation + authorization
 │        (envelope version, access level,   │
 │         field validation)                 │
 │   └─ crates/rustward-app (AppService)     │
 └──┬───────────────┬───────────────┬────────┘
    │               │               │
 ┌──▼─────────┐ ┌───▼───────────┐ ┌─▼────────────────────────────┐
 │ rustward-  │ │ rustward-core │ │ rustward-enforcement          │
 │ storage    │ │ pure logic    │ │ providers: SimulationOnly,    │
 │ SQLite,    │ │ ids, catalog, │ │ DeviceInstallRestriction      │
 │ migrations,│ │ policy edit,  │ │ (DRY-RUN plan only;           │
 │ hash chain │ │ evaluate,     │ │  ACTIVATION_ENABLED = false)  │
 └────────────┘ │ explain, diff │ └───────────────────────────────┘
                └───────▲───────┘
                ┌───────┴──────────────────────┐
                │ rustward-windows              │ read-only SetupAPI inventory
                │ (5 read-only Win32 calls)     │ behind a DeviceSource trait
                └───────────────────────────────┘
```

The UI never opens the database and never authorizes anything. Every request is validated
and authorized by `rustward_ipc::rpc::process` — in the service for release builds, and in
the in-process development backend for debug builds (same function).

In the candidate enforcement design the Windows OS policy, not a RustWard process, is the
enforcement boundary; no enforcement is active in this build.

## Crates

| Crate | Responsibility | Unsafe | Platform | Tested |
|---|---|---|---|---|
| `rustward-core` | ID parsing/encoding, snapshot model, catalog + policy validation, classification, default-deny evaluation, policy editing (`PolicyEdit`, version `+local.N`), explanations TR/EN, plan preview, snapshot diff | `forbid` | any | 69 tests |
| `rustward-windows` | Read-only SetupAPI enumeration via `DeviceSource`; `CM_Register_Notification` device-change subscription (telemetry); Event Log writer; SCM service host; platform-neutral logic in `engine`, `svc_control`, `devchange`, `eventlog_map`; crate-wide test forbids device/driver/registry/service-configuration APIs; Event Log MESSAGETABLE generator | only in `setupapi.rs`, `device_notify.rs`, `event_log.rs`, `service_host.rs`; every block has a SAFETY comment | Windows (type-checked elsewhere with `host-typecheck`) | 28 tests (logic); native NOT RUN |
| `rustward-enforcement` | Provider trait, capability report, state machine, dry-run plan for layered Device Installation Restrictions, notification selection, activation gates + protection stages + plan fingerprint (`activation`; activation always refused) | `forbid` | any | 16 tests |
| `rustward-storage` | SQLite store: migrations v1–v2, settings, policy states + change history (optimistic version), devices, hash-chained events, append-only triggers, retention, registered + hashed backups, backup inspection, non-destructive restore as a new policy version, post-commit `EventObserver` | `forbid` | any | 22 tests |
| `rustward-ipc` | Envelopes, `Request`/`ResponseBody` (25 request types), access levels, validation (incl. backup file names that cannot escape the backup directory), framing, RPC client/server with authorization/validation/identification-failure hooks and per-request identification, mock transport, named pipes (owner-checked) | documented, only in `pipe.rs` | pipes: Windows | 21 tests + golden contract |
| `rustward-app` | `AppService`: implements every request; inventory sources (live, fixture, empty); simulation; export (formula-safe CSV); retention; backups; two-step restore (prepare/apply); rate-limited refusal audit; Event Log observer attachment | `forbid` | any | 27 tests (incl. `ipc_security.rs`) |
| `rustward-service` | Console / service modes, runtime loop with device-change wake-up, pipe servers, SCM entry (via `rustward-windows::service_host`) with start-failure Event Log entry, Event Log mirror adapter, paths, install plan text; `build.rs` embeds the message table on Windows | `forbid` | SCM: Windows | 14 tests (incl. installer/version consistency); SCM NOT RUN |
| `rustward-ui-bridge` | Backend selection for the desktop app | `forbid` | any | 2 + 2 (release) tests |
| `rustward-inventory` | Read-only CLI: `scan`, `capture`, `evaluate`, `report`, `plan` | `forbid` | any | 4 tests |
| `apps/rustward-desktop/src-tauri` | Tauri shell, single command `ipc_call` (outside the workspace: needs webview system libs) | none | Windows target | 4 mock-runtime tests (Linux) |
| `apps/rustward-desktop` (TS) | UI pages, i18n, typed API client mirroring `rustward-ipc`, in-app denial notices | — | WebView2 | 38 Vitest tests |

## IPC contract

- `crates/rustward-ipc/contract/request-types.json` is generated by a Rust test with an
  exhaustive `match`; the TypeScript test compares `REQUEST_TYPES` and `PRIVILEGED` with it.
  Any protocol change fails one side until both are updated.
- Read-only requests: dashboard, devices, manufacturers, explanation, blocked (simulated),
  events, policy changes, diagnostics, settings, run simulation.
- Administrator requests: manufacturer add/update/remove/allow/enable, settings, export,
  retention, backup, inventory refresh, load synthetic inventory.
- Policy mutations carry `expected_policy_version`; a stale version returns `conflict`.
  `version_mismatch` is reserved for protocol-version mismatch.

## Key design rules

1. **Detection ≠ enforcement.** Decisions are `SİMÜLE İZİN` / `SİMÜLE RET`; no state reaches
   `VerifiedProtected` without `VerificationEvidence`, which has no public constructor.
2. **The decision engine models the OS rule.** Only the vendor-level INQUIRY hardware ID can
   authorize; VID and names are evidence only.
3. **Default deny is not configurable.** Policies can only add brands.
4. **Policies are bound to a catalog version**; edits create a local catalog version.
5. **Fail closed.** Corrupt policy → mutations refused; newer DB schema → refused; release
   builds cannot select the development backend.
6. **Offline only.** No network calls at runtime, no telemetry, no CDN assets.

## Dependencies (runtime, resolved in `Cargo.lock`)

serde 1.0.229, serde_json 1.0.154, thiserror 2.0.21, windows-sys 0.61.2,
rusqlite 0.41.1 (bundled SQLite), sha2 0.11.1,
tauri 2.12.5 / tauri-build 2.7.4 (shell). Frontend: react 19.1, @tauri-apps/api 2.12.4,
lucide-react 0.577.0; build/test: vite 7.3, vitest 3.2, typescript 5.9, tailwindcss 4.1.
