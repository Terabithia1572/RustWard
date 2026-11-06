# Threat Model

## Assets

- Sensitive data on five standalone Windows 10 Pro workstations.
- RustWard policy, catalog and audit records on each workstation.
- Integrity of the workstation's existing Windows security configuration.

## Actors

| Actor | Capability | In scope |
|---|---|---|
| Standard user (operator) | Physical USB access, unprivileged login | **Primary adversary** (exfiltration or malware import via unauthorized storage) |
| Malicious device | Custom/reprogrammed USB firmware reporting arbitrary VID/PID/INQUIRY strings | Partially: cannot be distinguished from genuine (L-01) |
| Visitor / insider with physical access | Can plug devices, cannot log in as admin | Yes |
| Local administrator | Full control of OS policy and RustWard | **Trusted.** RustWard cannot defend against a malicious admin; it can only make changes evident. |
| Remote attacker | No network exists | Out of scope (air-gapped) |
| Supply chain (build time) | Malicious dependency | Mitigated by lockfile, dependency review, SBOM (Phase 7/8) |

## Threats and responses

| ID | Threat | Response | Residual |
|---|---|---|---|
| T1 | Plug unauthorized flash/HDD/SSD and copy data | OS-level install prevention (Phase 2 candidate) | Spoofed vendor (L-01) |
| T2 | Device connected before activation keeps working | Baseline cleanup + verification scan | Until cleanup verified (L-05) |
| T3 | Device spoofs approved vendor string | None technical; physical media control, audit, VID mismatch warning | **Accepted risk needed** |
| T4 | Use another storage class (CD/DVD, MTP phone, Thunderbolt) | Explicit scope decisions | Open (L-08) |
| T5 | Kill RustWard UI/service to disable protection | OS policy persists independently; service is telemetry only | None for enforcement; audit gap while stopped |
| T6 | Tamper with policy DB/config | ACLs (SYSTEM/Admins), integrity checks, versioning; OS policy is the source of truth | Admin can still change |
| T7 | Use the UI to escalate privilege | Unelevated UI, no direct DB access, authenticated named pipe, server-side validation, Tauri capabilities | Phase 5/7 review |
| T8 | BadUSB keyboard injection | Out of scope of storage control; document | Open |
| T9 | Unlock SIR II to bypass policy (re-enumeration) | Policy evaluated per devnode; test T-05/T-06 | Unknown until tested |
| T10 | Raw disk access to a blocked device | Device never installs → no disk object | Verify in Phase 2 |
| T11 | Log tampering | Hash chain + Event Log; tamper-evident only | L-11 |
| T13 | Standard user squats a pipe name (scheduled task in session 0) to impersonate the service | Client requires pipe owner = LocalSystem (`O:SY`) and session 0 (F-03) | Verify on Windows (C12) |
| T14 | Restore an old backup to re-activate a permissive policy or erase audit records | Two-step restore, registered SHA-256, new version, audit never replaced (F-01/F-02) | Admin-only; admins trusted |
| T12 | Misclassification blocks keyboard/mouse/system disk | DiskDrive-only rule, non-retroactive, baseline instance-ID allow list, peripheral tests, rollback | Verified only by hardware tests |

## Assumptions

- Operators do not have administrator rights.
- BIOS/UEFI is password-protected and booting from USB is disabled (otherwise any OS-level control can be bypassed by booting another OS). **Must be confirmed per workstation.**
- Physical chassis access is controlled.
- Windows receives security updates (ESU) or the residual risk is accepted (L-10).
