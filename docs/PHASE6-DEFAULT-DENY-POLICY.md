# Phase 6 — Default-deny policy model

The policy model decides what *should* happen. It never claims what Windows
*does*. Evaluation (`rustward-core::evaluate`, `rustward-enforcement::assessment`)
is separate from Windows observation (`rustward-enforcement::observer`). The
two meet only in the assessment's enforcement category.

## 1. Target policy (`config/policy.example.json`, catalog `2026.11.07-phase6`)

| Manufacturer | Rule | Effective decision today |
|---|---|---|
| SanDisk | `allowed_brands` | Allow **candidate** only when the INQUIRY vendor (`SanDisk`) and the USB VID (`0781`/`0871`) agree. The identifiers are not verified on a genuine SanDisk device. |
| TÜBİTAK / BİLGEM / SIR II | `allowed_brands` | **Denied**: the catalog has no identifier, so no device can match. SIR II physical identification is deferred. |
| Kingston | `denied_brands` (explicit) | Deny candidate. The identifiers are lab-verified on 0951:1666. |
| Seagate | `denied_brands` (explicit) | Deny candidate (no hardware tested) |
| Any other manufacturer | — | Deny (default) |
| Unknown / generic / conflicting identity | — | Unverified identity, deny |
| Keyboards, mice, printers, hubs, internal and virtual disks | — | Out of scope (never touched) |

The policy file is in **dry-run** mode. Rules:

- An explicit deny list is validated against the catalog and can never be
  combined with an allow rule for the same brand.
- Edits are administrator-only, versioned and audited
  (`SetManufacturerAllowed`, `SetManufacturerDenied`).

## 2. Result categories

| Category | Side | Meaning |
|---|---|---|
| `ALLOW_CANDIDATE` | policy | Allowed manufacturer, **and** the INQUIRY vendor and USB VID agree (`corroborated`). Still self-reported. |
| `DENY_CANDIDATE` | policy | Explicitly denied, unlisted or unknown manufacturer with a usable identity |
| `UNVERIFIED_IDENTITY` | policy | Generic, missing, ambiguous or conflicting identity, or an allow that would rest on one source. Denied. |
| `UNSUPPORTED_DEVICE` | policy | Storage-capable but outside the brand policy (MTP/PTP, optical). Denied pending a scope decision. |
| `OUT_OF_SCOPE` | policy | Not subject to the storage policy |
| `WINDOWS_DENIAL_VERIFIED` | enforcement | The device is connected **and** Windows refuses its installation under a matching live rule (problem code 1 or 28). Read/write not tested. |
| `ENFORCEMENT_NOT_ACTIVE` | enforcement | No Windows denial observed (no rule, installed before the rule, or not connected) |

Every in-scope device gets one policy category and one enforcement category.
A policy category alone is never reported as enforcement. The notice
"USB engellenmiştir. İşlem kayıt altına alınmıştır." is driven only by
`WINDOWS_DENIAL_VERIFIED` evidence for a connected device.

## 3. Special cases

| Case | Handling |
|---|---|
| Conflicting identifiers (INQUIRY vendor ≠ VID brand) | `UNVERIFIED_IDENTITY`. Never allowed, even if one source names an allowed brand. |
| Shared controller VID (several brands) | `ambiguous`, so `UNVERIFIED_IDENTITY` |
| Generic vendor (`VendorCo`, `VendorC`, `Generic`, …) | `generic`, so `UNVERIFIED_IDENTITY`. This is the SanDisk-labelled 346D:5678 stick. |
| Previously installed device | `previously_installed = true`. Shown as "installed before rule": a non-retroactive Windows rule does not affect it. |
| Disconnected device | Evaluated from its last record; enforcement category `ENFORCEMENT_NOT_ACTIVE` with "not connected". Never counted as blocked. |
| Non-storage USB peripheral | `OUT_OF_SCOPE` (classification by setup class and parent chain) |
| Internal storage | `OUT_OF_SCOPE` only when the parent chain proves a non-USB attachment. An unresolved chain is treated as **in scope** (conservative). |
| Unsupported interface | `UNSUPPORTED_DEVICE` |

## 4. From policy to Windows (administrator-guided)

The same policy compiles into the layered Device Installation Restrictions
plan (`rustward-core::plan::compile_plan`, provider
`windows-device-install-restrictions`):

- `AllowDenyLayered = 1`
- `DenyDeviceClasses` = DiskDrive `{4d36e967-e325-11ce-bfc1-08002be10318}`, with
  `DenyDeviceClassesRetroactive = 0` (never 1)
- `AllowDeviceIDs` = enforceable IDs of the allowed brands
  (`USBSTOR\DiskSanDisk_`, `SCSI\DiskSanDisk_`)
- `AllowInstanceIDs` = every existing internal disk (from the live inventory)

The **default-deny profile session** (`PrepareDefaultDenySession`,
administrator only) does the following:

1. Saves this plan's exact expected registry state and the current baseline,
   and audits both.
2. Shows a gpedit checklist in Turkish and English.

The administrator applies it, then **Uygulamayı doğrula** compares the live
policy with the expected state. An unchecked "also apply to installed
devices" box is accepted whether Group Policy writes it as 0 or leaves it
out. After the administrator restores Not Configured, **Geri almayı doğrula**
compares the live policy with the baseline.

Preparation is refused when:

- layering is unsupported on the build,
- the edition is not Pro, Enterprise or Education,
- an internal disk lacks an instance-ID allow,
- any value would be retroactive, or
- the policy already equals the profile.

## 5. Tests

| Area | Tests |
|---|---|
| Assessment (identity grading, categories, conflicts, generic vendors, installed/disconnected, out of scope) | `rustward-enforcement` unit tests; `rustward-app/tests/observation_flows.rs` |
| Explicit deny list (validation, no allow+deny overlap, audited edits) | `rustward-core` policy and policy-edit tests |
| Default-deny profile session (admin only, never retroactive, partial = mismatch, both Group Policy encodings, verified only with a real denial, rollback) | `rustward-app/tests/default_deny_profile.rs` |
| Removable Storage Access interpretation | `rustward-enforcement::removable_storage` tests |
| UI: categories, blockers, profile card, no simulated "blocked" notice | `apps/rustward-desktop/src/test/phase6.test.tsx`, `realStatus.test.tsx` |
