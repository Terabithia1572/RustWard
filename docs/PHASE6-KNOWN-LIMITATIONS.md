# Phase 6 — Known limitations

These are the limitations that matter for the target policy (allow SanDisk and
TÜBİTAK; deny everything else). The full historical register is
[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) (L-01…L-35). Items marked
**new** were added in Phase 6.

## Enforcement

| # | Limitation | Consequence |
|---|---|---|
| 1 | **Automatic policy application is BLOCKED.** RustWard writes no Windows policy, registry value, device or driver setting. | Every Windows change is made manually by an administrator in `gpedit.msc`. RustWard verifies, observes, audits and verifies the rollback. |
| 2 | Install-time rules (device ID, setup class, layered profile) do not affect devices that are already installed, unless a device rule is applied retroactively (L-05). | Unauthorized sticks installed before the profile keep working. They are listed as "not covered". |
| 3 | **(new)** The default-deny profile blocks **every new disk installation** not on the allow list, including new internal or virtual (VHD/VHDX) disks and reinstalls after controller changes (L-09, L-34). | Maintenance needs a procedure. Applied only in the snapshot-protected VM. |
| 4 | An installation denial (problem code 1/28) is **not** proof of read/write denial. | RustWard never reports read/write protection from a problem code. |
| 5 | **(new)** Removable Storage Access (read/write/execute deny) is class-wide. | It cannot allow SanDisk while denying Kingston. It is reported as a limitation, never as protection. Enforcement reliability depends on the patch level: an April 2025 regression was acknowledged by Microsoft. Only HKLM (computer) policies are read; per-user (HKCU) policies are not. |
| 6 | Local administrators can change or remove policy (L-06). | RustWard detects, audits and flags mismatches. It cannot prevent them. |
| 7 | USB CD/DVD and MTP/PTP devices are outside the DiskDrive rule (L-08). | Reported as `UNSUPPORTED_DEVICE` (denied by policy, not by Windows) |

## Identity

| # | Limitation | Consequence |
|---|---|---|
| 8 | VID/PID and INQUIRY strings are self-reported and cloneable (L-01). | "SanDisk" means "reports SanDisk". `authenticated` is always false. |
| 9 | No VID-only hardware ID exists for USB disks. | The VID can only corroborate. Windows rules match the INQUIRY vendor. |
| 10 | Generic or controller vendors (`VendorC`/`VendorCo`, `Generic`, …) cannot be attributed (L-02). | The ASELSAN-labelled (first reported as SanDisk-labelled) 346D:5678 stick is `UNVERIFIED_IDENTITY` and denied. |
| 11 | TÜBİTAK SIR II identifiers are unknown (L-04). | All SIR II devices are denied until a physical inspection records real identifiers. None are invented. |
| 12 | No genuine SanDisk device has been tested. | SanDisk identifiers stay `unverified` / `public_registry`. |
| 13 | **(new)** The policy and catalog are stored in the database. Upgrading the MSI does not replace an existing installation's catalog. | The VM still runs catalog `2026.11.05-phase1`, so 346D:5678 is graded `single_source` (not `generic`) there. The decision is the same (deny). A catalog update path is needed. |

## Monitoring and UI

| # | Limitation | Consequence |
|---|---|---|
| 14 | **(new)** The UI watcher polls the service every 2 s; there is no push. | A Windows change is visible within one poll after the service records it (VM: 3–9 s including USB re-enumeration). |
| 15 | Notices are shown only while the window is open (L-16) | No toast notifications |
| 16 | Administrative actions require starting the app with "Run as administrator" (L-15). | Toggles are disabled otherwise. |

## Development and supply chain

| # | Limitation | Consequence |
|---|---|---|
| 17 | Binaries and MSI are unsigned (L-19). | Integrity relies on published SHA-256 sums |
| 18 | The test runner (Vitest 3.2.7 / tinypool) has advisories; dev-only (L-30). | Upgrade to Vitest 5.x separately |
| 19 | **(new)** Two historical commits contain the development PC's device name. Published privately with owner approval; history not rewritten. | Do not make the repository public without reviewing history. |
