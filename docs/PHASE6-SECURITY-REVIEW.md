# Phase 6 — Security review

Scope: the changes from `be4fac6` to the Phase 6 branch, and the publication
of the repository. Earlier reviews: SECURITY-AUDIT-PHASE-9A/9B.

## 1. Boundaries kept

| Boundary | Status |
|---|---|
| No automated privileged policy writing | Kept. No registry, Group Policy, device, driver, PowerShell, scheduled-task or service write path was added. `policy_reader.rs` still opens keys with `KEY_READ` only; the crate test `policy_reader_is_read_only` still enforces the allowed API list. **Automatic application: BLOCKED.** |
| No raw device access | Kept. RustWard does not open disks or volumes. Read/write denial is an administrator observation, not a RustWard probe. |
| Development host untouched | Kept. Builds only (`BUILD-RUSTWARD.cmd`, no install). No policy, service or driver change. |
| Policy experiments only in the authorized VM, after a named snapshot and explicit approval | Kept. See `PHASE6-VM-TEST-REPORT.md`. |
| Simulation never shown as enforcement | Kept, with new tests for the profile and Removable Storage Access states |

## 2. New attack surface and mitigations

| Change | Risk | Mitigation |
|---|---|---|
| `PrepareDefaultDenySession` IPC request | An unprivileged caller prepares a session | Administrator-only (`AccessLevel::Administrator`), enforced by the RPC layer before `handle`. Covered by the privileged-sample test (every privileged request, every unprivileged caller, every refusal audited). |
| Profile checklist includes a class rule (DiskDrive) | An administrator applies it retroactively and hits the system disk | The plan always writes `DenyDeviceClassesRetroactive = 0`, and preparation is refused if any value is retroactive. The checklist states "UNCHECKED" in Turkish and English. Internal disks get instance-ID allow rules; preparation is refused when an internal disk is not covered. Applied only in the snapshot-protected VM. |
| Profile verification accepts "retroactive 0 or absent" | Weaker comparison | Only the `*Retroactive` DWORD 0 value is treated as absent. Both mean "not retroactive" in Windows. Any other difference is a mismatch. |
| `verified_active` for the profile | Overclaiming protection | Requires that the session's apply was verified, that the live policy *still* equals the expected profile, **and** that a connected device is observed denied. The label says "new installations only". |
| Removable Storage Access capture | Misreading a class-wide control as a manufacturer control | Reported as class-wide with an explicit limitation blocker; never counted as protection. Read errors are non-fatal and reported. |
| Audit/IPC | Volume of refusal audit | Unchanged rate limit (20 per 60 s). The test now advances the clock however many privileged requests exist. |

## 3. Dependencies

| Check | Result |
|---|---|
| `cargo deny check`, workspace and src-tauri (advisories, licenses, bans, sources) | PASS |
| `npm audit --omit=dev` (shipped frontend) | 0 vulnerabilities |
| `npm audit`, including dev tooling | 3 findings in **test tooling only**: `vitest` 3.2.7 via `@vitest/mocker` (moderate) and `tinypool` (critical, prototype pollution leading to RCE in worker options). They are not shipped in the MSI and run only on developer machines. The fix requires `vitest` 5.x (major). **Open item:** upgrade the test runner in a separate change. |

## 4. Publication review (GitHub)

| Check | Result |
|---|---|
| Secrets in all 43+ commits (private keys, GitHub/AWS tokens, passwords) | None found |
| Real device serials | None. Fixture serials such as `E0D55EA5…` predate any real device observation (2026-11-05) and do not match the observed Kingston; VM fixtures use `SERIAL-REDACTED-…`. |
| Machine identifiers | The VM computer name is not in the repository. **The development PC's device name appears in two historical commits** (`2894098`, `e3f9bde`, `docs/PHASE-STATUS.md`). It was removed from current files long ago. History was **not rewritten**; the owner approved publishing as-is to a **private** repository. |
| Screenshots | Synthetic fixture data only (workstation `PC-TEST`, `EXAMPLEX` devices). No VM or host screenshots are committed. |
| Build outputs, logs, databases, bundles, ISOs, MSIs | Excluded by `.gitignore` (`/target/`, `dist/`, `/build-logs/`, `*.log`, `*.db`, `*.bundle`, `*.iso`, `*.msi`) |
| Repository visibility | Private |

## 5. Residual risks

See `PHASE6-KNOWN-LIMITATIONS.md`. The most important:

- **Identity.** Self-reported identity can be spoofed.
- **Administrators.** Local administrators can change policy.
- **Installation vs access.** Install-time rules do not affect installed
  devices, and an installation denial is not a read/write denial.
