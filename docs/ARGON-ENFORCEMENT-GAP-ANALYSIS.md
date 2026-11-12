# ARGON Phase 1 — Root Cause Analysis of Simulation-Only Operation

**Workspace:** `<workspace>` (`experiment/argon4-vm-enforcement`)

---

## 1. Executive Answers to the Seven Phase 1 Questions

| Question | Exact Finding in Source Code |
|---|---|
| **1. Does the current service merely evaluate simulated rules?** | RustWard's *internal policy engine* (`rustward_core::evaluate::evaluate_snapshot`) evaluates rules purely in memory and persists verdicts as `"allow"` / `"deny"` with `simulated = true` (`crates/rustward-app/src/lib.rs:285-359`). RustWard itself never blocks any device. |
| **2. Does it read genuine Windows policy?** | **Yes.** `rustward_windows::policy_reader::capture_device_install_policy` (`crates/rustward-windows/src/policy_reader.rs:34-215`) opens `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` and `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices` using Win32 `RegOpenKeyExW` with `KEY_READ` only. |
| **3. Does it verify an externally applied policy?** | **Yes.** `rustward_enforcement::observer::observe` correlates live `CapturedPolicy` rules with live SetupAPI `DeviceRecord` problem codes (`CM_PROB_FAILED_INSTALL = 28`, `CM_PROB_NOT_CONFIGURED = 1`) and `guided.rs` verifies exact registry equality against prepared single-device or default-deny profile sessions (`VerifyEnforcementApplied` / `VerifyEnforcementRollback`). |
| **4. Does it have any supported policy-application mechanism?** | **No.** `rustward_enforcement::ACTIVATION_ENABLED` is hardcoded `false` (`crates/rustward-enforcement/src/lib.rs:40`), and compile-time/unit tests (`activation_is_compiled_out`, `no_system_modification_apis_in_this_crate`, `no_module_references_state_changing_apis`) forbid any registry, GPO, driver, or PnP mutation API in the codebase. |
| **5. Does it require elevated authorization?** | **Yes, for all mutating/guided RustWard actions.** `rustward_ipc::pipe` impersonates the named-pipe caller and checks `TokenElevation` + `WinBuiltinAdministratorsSid`; `AppService::authorize` rejects unelevated callers on all `AccessLevel::Administrator` RPCs (`PrepareEnforcementSession`, `PrepareDefaultDenySession`, `VerifyEnforcementApplied`, `VerifyEnforcementRollback`, policy edits, backups). Read-only observation (`AccessLevel::ReadOnly`) is accessible to standard users. |
| **6. Does it have explicitly disabled enforcement paths?** | **Yes.** An earlier automated policy-writing path was halted by a Phase 6 safety review (`docs/PHASE6-PREFLIGHT-SAFETY.md` §6 `B1`) because direct registry writes bypass `Registry.pol` (`IGroupPolicyObject`) and broad retroactive `DiskDrive` rules risk boot failure. `DeviceInstallRestrictionProvider::status()` (`crates/rustward-enforcement/src/device_install.rs:251`) permanently returns `EnforcementState::PendingValidation` (`verified: None`), and the Readiness "Politikayı etkinleştir" button (`Readiness.tsx:96`) is permanently `disabled`. |
| **7. Can it distinguish active restrictions from stale audit history?** | **Partially — backend observer yes, several UI surfaces had contradictions.** `observer.rs` sets `EvidenceLevel::InstallDenied` *only* when `present == Some(true)`, `problem_code` is `1` or `28`, and an active matching `Prevented` rule exists in `CapturedPolicy`; once rolled back, `evidence` becomes `None`, `windows_install_denial_ended` is logged, and prior blocks move to `HistoricalDenial`. However, UI surfaces contained hardcoded simulation/unverified overrides documented in §3 below. |

---

## 2. Full End-to-End Execution Trace

`React UI → Tauri IPC → Rust Service → Policy Engine → Windows Enforcement Provider / Observer → Windows Result → Audit → UI`

1. **React UI (`apps/rustward-desktop/src`)**:
   - Pages call `Api` methods (`src/api/client.ts`), which invoke Tauri's `rustward_call({ request })`.
   - Simultaneously, `DeviceWatchProvider` (`src/lib/watch.tsx`) and `DenialNotifier` (`src/components/Notifier.tsx`) poll `get_enforcement_observation` every 2,000 ms, while `ConnectionBar` (`src/components/ConnectionBar.tsx`) polls `get_dashboard` every 15,000 ms.
2. **Tauri 2 IPC Bridge (`src-tauri/src/main.rs` → `rustward-ui-bridge/src/lib.rs`)**:
   - `rustward_call` dispatches on `tauri::async_runtime::spawn_blocking` to `ServiceBackend::call`.
   - `ServiceBackend` selects `\\.\pipe\RustWard\v1\status` for `ReadOnly` requests or `\\.\pipe\RustWard\v1\admin` for `Administrator` requests, verifies pipe owner SID + SCM service PID, and exchanges a length-prefixed JSON `RpcRequest` / `RpcResponse`.
3. **Rust Windows Service (`crates/rustward-service` → `crates/rustward-app`)**:
   - `PipeListener` impersonates the client token, constructs `ClientIdentity`, and invokes `AppService::handle`.
   - `validate_request` enforces structural limits; `authorize` enforces `AccessLevel::Administrator` (`is_administrator && elevated`).
4. **Core Policy Engine (`crates/rustward-core`)**:
   - `evaluate_snapshot(&snapshot, &policy, &catalog)` classifies each PnP node by walking its parent chain (`classify.rs`) and matches `UsbStorageDisk` nodes against `ValidatedCatalog` + `ValidatedPolicy` (`evaluate.rs`).
   - Regardless of `PolicyMode::DryRun` vs `PolicyMode::Enforce`, `evaluate_snapshot` produces pure analytical decisions (`Verdict::Allow`, `Verdict::Deny`, `Verdict::NotApplicable`).
5. **Windows Enforcement Provider vs. Live Windows Observer (`crates/rustward-enforcement`)**:
   - **Static Provider (`DeviceInstallRestrictionProvider`)**: Because `ACTIVATION_ENABLED == false`, `provider.status()` *always* returns `EnforcementState::PendingValidation` (`"Doğrulama bekleniyor — koruma etkin değil"`, `verified: None`).
   - **Live Observer (`observer::observe` + `guided::windows_protection`)**: Reads real Windows registry state via `LivePolicySource` (`policy_reader.rs`) and compares active `Restrictions` rules (`policy_eval::evaluate_new_install`) + live SetupAPI `problem_code` (`1` / `28`) + active guided sessions (`guided.rs`) to compute `WindowsProtectionView`:
     - `"inactive"` — no active Windows restriction rule.
     - `"configured_unverified"` — Windows restriction rule exists in registry, but no live USB denial or verified session matches yet.
     - `"denial_observed"` — Windows actively denied driver installation (`Code 1` or `Code 28`) on a connected USB storage device under a matching registry rule.
     - `"verified_active"` — a guided session's expected registry values match live Windows policy *and* a connected target device is actively installation-denied by Windows.
     - `"unknown"` — Windows registry policy could not be read.
6. **Audit & SQLite Persistence (`crates/rustward-storage`)**:
   - Simulated evaluations write `decision_simulated` (`simulated = true`, `enforcement_state = "pending_validation"`).
   - Real Windows transitions write `windows_install_denied_observed` and `windows_install_denial_ended` (`simulated = false`), mirrored to the Windows Application Event Log.

---

## 3. Exact Missing Links & UI/Backend Contradictions Explaining Why Simulation Banners Persist

Even when an administrator manually configures a real Windows Device Installation Restriction in `gpedit.msc` and Windows genuinely blocks a USB drive (`Code 1` / `Code 28`), four specific code paths caused the UI to continue displaying contradictory "not enabled / not enforced / simulation only" messages:

1. **Unconditional Global Sticky Warning & Sidebar Footer (`App.tsx:99-113`)**:
   - `App.tsx` rendered `not-activated-warning` (`"USB koruması henüz etkinleştirilmemiştir. Koruma henüz gerçek Windows ortamında doğrulanmadı. Tüm kararlar simülasyondur..."`) and sidebar footer `"Simülasyon · Doğrulanmadı"` unconditionally on every page, never consulting `dashboard.windows_protection` or guided session state. While RustWard's *automatic writer* is indeed disabled, stating that *no* Windows restriction is active when Windows is actively blocking a device contradicts `ProtectionPanel` right below it.
2. **`DashboardView.protection_verified` Hardcoded via Static Provider (`crates/rustward-app/src/lib.rs:509`, `Dashboard.tsx:84`)**:
   - `DashboardView.protection_verified` was set from `provider.status().is_verified()` (always `false` because `DeviceInstallRestrictionProvider` returns `PendingValidation`). Consequently, `Dashboard.tsx:84` rendered `<NotValidatedBanner />` ("Tüm kararlar simülasyondur") immediately above `<ProtectionPanel />` even when `windows_protection.state` was `"denial_observed"` or `"verified_active"`.
3. **`DeviceView` Ignored Live Windows Observation (`crates/rustward-app/src/lib.rs:362-385`)**:
   - `DeviceRow` in SQLite stored `enforcement_state = "pending_validation"` from `provider.status().code()`, and `to_device_view` hardcoded `enforcement_verified: false`.
4. **`Blocked.tsx` Blanket `"Uygulanmadı — yalnızca simüle karar"` Badge (`Blocked.tsx:106`)**:
   - In `Blocked.tsx`, the lower table (`r.data`, all devices with `decision == "deny"`) hardcoded `<Badge tone="warning">{t("blocked.notEnforced")}</Badge>` on **every** row — even if that exact device (e.g., Kingston `0951:1666`) was simultaneously listed in the upper card (`current`) as actively blocked by Windows (`WINDOWS_INSTALL_DENIED`)! Furthermore, `Blocked.tsx` lacked the required separate section for **Unknown / Unverified Identity** devices and tucked historical denials inside the active-denial card.

---

## 4. Honest Resolution Principles (Implemented in ARGON Phases 3–5)

Per Section 6 ("Do not make the application display 'Protected' simply by changing a status flag. Do not fabricate a successful enforcement result. A real active protection status must be supported by actual Windows evidence"):

- RustWard **never** claims automatic RustWard policy enforcement is active (`ACTIVATION_ENABLED` stays `false`, and automatic policy writing is always reported as unavailable/blocked).
- Status badges and banners are driven strictly by live Windows evidence using distinct, non-overlapping Turkish states (Bug D):
  - `KORUMA ETKİN DEĞİL` — No Windows restriction configured in registry and no active Windows denial observed.
  - `SIMÜLASYON` — RustWard's internal policy engine verdict (`SİMÜLE İZİN` / `SİMÜLE RET`), never conflated with OS blocking.
  - `POLİTİKA HAZIR` — Administrator-guided session prepared and baseline saved, awaiting manual `gpedit.msc` application.
  - `WINDOWS POLİTİKASI ETKİN` — Matching Windows `DeviceInstall\Restrictions` rules exist in `HKLM`, awaiting live device denial evidence or session verification.
  - `WINDOWS ENGELİ DOĞRULANDI` — Live Windows registry restriction + live PnP installation denial (`CM_PROB_FAILED_INSTALL = 28` or `CM_PROB_NOT_CONFIGURED = 1`) observed on a connected device.
  - `ERİŞİM DOĞRULANAMADI` — Explicit qualifier that PnP installation denial does not independently test raw/filesystem read-write paths, or policy/device state could not be verified.
  - `GERİ ALMA TAMAMLANDI` — Live Windows registry verified equal to pre-session baseline and active block cleared (prior denial retained strictly as historical record).
