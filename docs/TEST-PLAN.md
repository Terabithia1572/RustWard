# Test Plan

Results vocabulary: PASS · FAIL · BLOCKED · NOT RUN · NOT APPLICABLE.
A test passes only when the observed result matches the security requirement.
Use sacrificial media and synthetic files only.

## 1. Automated tests

Current results, environment and the full DEFERRED list: **`TEST-RESULTS.md`**
(run `./scripts/verify-all.sh`). Automated tests check RustWard's logic on Linux; they are
not evidence of Windows behaviour.

## 2. Phase 1 on-Windows checks (read-only, run on the dev PC)

| ID | Check | Result |
|---|---|---|
| W-01 | `cargo build --release` on Windows (MSVC toolchain) | NOT RUN |
| W-02 | `cargo test --workspace` on Windows | NOT RUN |
| W-03 | `rustward-inventory scan` lists keyboard/mouse as peripherals and internal disks as system storage | NOT RUN |
| W-04 | `capture --include-non-present` includes previously connected USB disks | NOT RUN |
| W-05 | Real hardware IDs of a USB flash drive match the documented USBSTOR format | NOT RUN |

## 3. Hardware acceptance tests (Phase 2 / Phase 9)

Environment for every row: isolated Windows 10 Pro 22H2 x64 test PC, build/UBR recorded,
RustWard commit hash recorded, evidence = inventory JSON + screenshots + command transcripts.

| # | Test | Expected | Result |
|---|---|---|---|
| T-01 | Previously installed approved SanDisk | Usable after baseline cleanup + policy | NOT RUN |
| T-02 | Previously unseen approved SanDisk | Installs and is usable without registration | NOT RUN |
| T-03 | Different-capacity SanDisk | Same INQUIRY vendor; usable | NOT RUN |
| T-04 | Approved Hardware-Encrypted USB | Usable once lab-verified identifier is in catalog | BLOCKED (identifiers unknown) |
| T-05 | Hardware-Encrypted USB before PIN entry | Record descriptors only; no PIN captured | NOT RUN |
| T-06 | Hardware-Encrypted USB after PIN entry | Re-enumeration recorded; policy still applies | NOT RUN |
| T-07 | Previously unseen Hardware-Encrypted USB unit | Same identity as T-06 | NOT RUN |
| T-08 | Unauthorized Kingston | No disk, no volume, no file access | NOT RUN |
| T-09 | Previously installed unauthorized USB | Blocked after baseline cleanup; documents behaviour before cleanup | NOT RUN |
| T-10 | Unauthorized external HDD | Blocked | NOT RUN |
| T-11 | Unauthorized external SSD | Blocked | NOT RUN |
| T-12 | UASP storage | Classified UASP; policy applies; SCSI ID format recorded | NOT RUN |
| T-13 | Composite device with storage | Non-storage function works; storage per policy | NOT RUN |
| T-14 | USB keyboard | Works throughout, incl. reboot | NOT RUN |
| T-15 | USB mouse | Works throughout | NOT RUN |
| T-16 | USB printer | Prints | NOT RUN |
| T-17 | Unauthorized USB connected at boot | Blocked | NOT RUN |
| T-18 | Approved USB connected at boot | Usable | NOT RUN |
| T-19 | Reboot with enforcement active | State unchanged | NOT RUN |
| T-20 | UI process terminated | Enforcement unchanged | NOT RUN |
| T-21 | Service failure | Enforcement unchanged; failure audited | NOT RUN |
| T-22 | Unauthorized policy modification attempt (standard user) | Denied and audited | NOT RUN |
| T-23 | Corrupted local policy file | Change refused; last OS policy intact | NOT RUN |
| T-24 | Policy rollback and recovery | Baseline restored exactly | NOT RUN |
| T-25 | Completely offline installation | Installs with network disabled | NOT RUN |
| T-26 | Different ports and hubs | Same decision; serial-less devices re-evaluated per port | NOT RUN |
| T-27 | Read/write from Explorer | Denied for blocked device | NOT RUN |
| T-28 | Read/write via `CreateFile`/`ReadFile`/`WriteFile` | Denied | NOT RUN |
| T-29 | Volume path / mount point access | No volume exists for blocked device | NOT RUN |
| T-30 | Non-destructive storage validation | Synthetic file round-trip on approved device only | NOT RUN |

Additional model-derived checks: USB CD/DVD and MTP phone behaviour (scope decisions),
spoofed-vendor device (expected to pass — documents L-01), generic-vendor flash drive
(expected blocked).
