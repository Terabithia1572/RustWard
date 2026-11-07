# Phase 6 — VM test report

VM: VMware "Windows 10 x64", Windows 10 Pro 22H2, build 19045. All
observations below were made in this VM. Automated tests are listed
separately at the end.

## 1. Installation

| Step | Result |
|---|---|
| Snapshot `rustward-before-phase6-c9b6c0e` | Taken 2026-11-08 01:12:20 |
| MSI `RustWard_0.1.0_x64_tr-TR.msi` | Upgrade **PASS**. SHA-256 `fd9e203c99f9fe4b909319496ed38cc7842f15b128d37fafc1b172143f2774b7`, from ISO `rustward-test-7.iso`. The service runs and policy/audit were kept. |
| Native build (host, build only) | `RustWard.exe` `a40480d4…e775`; `rustward-service.exe` 3,426,304 B, `dcc6025a…cc48`; `rustward-inventory.exe` `f7e122d1…fcc8` |

## 2. Observations

| # | Acceptance item | Result |
|---|---|---|
| 1 | Kingston identification | **PASS.** 0951:1666, INQUIRY `Kingston`; graded corroborated |
| 2 | Kingston policy evaluation (policy v11, target) | **PASS.** `DENY_CANDIDATE` (explicit deny) + `ENFORCEMENT_NOT_ACTIVE`; shown as "SİMÜLE RET" / "Windows engeli yok". A simulated notice appeared, labelled "yalnızca bir simülasyondur — RustWard aygıta erişimi kısıtlamadı". |
| — | 346D:5678 stick | `DENY_CANDIDATE`, "Üretici katalogda yok", graded **single source**. The VM still has catalog `2026.11.05-phase1`, so `VendorC` is not yet reserved as generic; the decision is still deny. Identity: see the preflight. |
| 3 | Windows installation denial | **NOT RUN.** The profile experiment is not authorized yet. Earlier evidence: guided Kingston deny, 2026-11-07 (Code 1). |
| 4 | Already-installed Kingston remains accessible under a non-retroactive rule | **NOT RUN** |
| 5 | Read/write restriction (Removable Storage Access) | **NOT RUN** (not authorized). The RSA row shows "Yapılandırılmamış". |
| 6 | Unrelated USB devices unaffected | No policy is applied, so N/A. Device classes inventoried (preflight §1). |
| 7 | Internal storage accessible | No policy is applied, so N/A. Precedence analysis in preflight §2. |
| 8 | Rollback restores the policy exactly | NOT RUN in Phase 6. The single-device rollback was verified on 2026-11-07. |
| 9 | RustWard shows the correct real-time status | **PASS** for the current state: "Windows koruması etkin değil"; Blocked page shows no current Windows denial plus past evidence; simulated decisions are separate. |
| 10 | Audit records the real outcome | **PASS** for policy edits v7–v11 and session preparation. No denial episode occurred. |
| — | Default-deny profile session preparation | **PASS.** Prepared at 01:18:48. Preconditions met on 19045 (layering, edition, internal NVMe disk allowed by instance ID). Saved baseline: "Restrictions anahtarı yoktu". 11 expected registry values, none retroactive. **No Windows value changed.** |
| — | Preflight (disks, controllers, precedence, identity, snapshot, rollback) | See [PHASE6-PREFLIGHT-SAFETY.md](PHASE6-PREFLIGHT-SAFETY.md) |

## 3. Automated tests (Linux container, not VM)

| Suite | Result |
|---|---|
| Rust workspace | 337 passed, 0 failed |
| Vitest | 83 passed |
| UI ↔ real-backend integration | 16 passed |
| `verify-all.sh` | 18 PASS, 0 FAIL, 5 NOT RUN (native Windows, pipes, SetupAPI, physical USB, Windows-target cross check) |
| Windows-target clippy (`x86_64-pc-windows-gnu`; default, all-features and release) | PASS; link step not completed (container disk space) |
| `cargo deny` (workspace, src-tauri) | PASS |
| `npm audit --omit=dev` | 0 vulnerabilities |
