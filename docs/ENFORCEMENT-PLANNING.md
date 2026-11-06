# Enforcement Planning (Phase 9B)

Status: the **planning, validation, conflict detection, comparison and recovery logic is
implemented and tested on Linux**. **Actual Windows enforcement is NOT implemented:**

- there is no code that reads the Restrictions key on Windows;
- there is no code that writes it;
- nothing triggers a policy refresh or rescans devices;
- nothing produces `VerificationEvidence`;
- `ACTIVATION_ENABLED = false`, and `activation::request_activation` always refuses.

No undocumented or kernel-level technique is used or planned.

## 1. Stages (never conflated)

| Stage | Implemented | Where | Claims protection |
|---|---|---|---|
| Device identification (inventory, IDs, parent chain) | Yes (SetupAPI read-only; native run NOT VERIFIED) | `rustward-windows`, `rustward-core::device` | no |
| Manufacturer policy decision (classification, default deny) | Yes | `rustward-core::classify`, `evaluate` | no (labelled SİMÜLE) |
| Planned Windows policy changes (exact values) | Yes, dry-run only | `device_install::plan`, `policy_state` | no |
| Comparison with existing policy, merge, rollback, staleness | **Yes (Phase 9B)** | `policy_state` | no |
| Activation gates | Yes (15 gates, always refused) | `activation` | no |
| Actual operating-system enforcement (write values, refresh) | **No** | — | — |
| Verified access denial (read/write probe) | **No** | — | only this stage would |

## 2. Planning logic added in Phase 9B (`rustward-enforcement::policy_state`)

| Function | Purpose | Tests |
|---|---|---|
| `PolicySnapshot` | In-memory model of `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` and its list subkeys, compared case-insensitively as the registry does | all |
| `desired_values` / `forward_ops` | Exact values of a plan; only values that differ are set | `plan_values_are_well_formed`, `clean_machine_…` |
| `compare` | Values to add/change/keep, *foreign* values left untouched, and conflicts | `hazardous_existing_policy_is_reported`, `existing_lists_collide_…` |
| `merge_plan` | Renumbers planned list entries after existing ones; never overwrites an administrator's entries; idempotent | `existing_lists_collide_until_merged_and_are_then_preserved` |
| `rollback_ops` | Exact inverse: every touched value restored or deleted. *Apply + rollback = captured state*, bit for bit | `clean_machine_…`, `existing_lists_…` |
| `suspend_ops` | Maintenance before feature updates / storage-driver changes: `DenyDeviceClasses = 0`, lists kept; resume = rollback of the suspend | `maintenance_suspend_and_resume_round_trip` |
| `staleness` | Plan invalid after a new internal disk, an unknown-attachment disk, a removed internal disk, an OS build/UBR change, or a policy version change | `plan_goes_stale_on_hardware_os_and_policy_changes` |

Two activation gates use this logic:

- `existing_policy_compatible` requires a captured `PolicySnapshot` with no conflict.
- `plan_current` requires an empty `staleness` result.

Both are **NotMet when the input is missing**. Capture is not implemented, so they are NotMet in this build.

### Conflicts detected

| Conflict | Why it blocks | Source |
|---|---|---|
| `DenyUnspecified = 1` | "Prevent installation of devices not described by other policy settings" blocks every new device, including keyboards and mice | value name confirmed in Microsoft's Policy CSP mapping |
| A retroactive flag ≠ 0 | Retroactive rules act on already-installed devices (system disk hazard) | value names from the ADMX (e.g. `DenyDeviceClassesRetroactive`); **not in the CSP mapping table — confirm in the VM** |
| Existing `DenyDeviceIDs` entry = planned brand allow | Microsoft: an allow applies "unless another policy setting at the same or higher layer … specifically prevents that installation", so the allow would be ineffective | CSP page |
| Existing `DenyInstanceIDs` entry = planned internal-disk allow | Instance IDs are the highest layer: the system disk could be blocked | CSP page |
| List index collision | A planned `AllowDeviceIDs\N` would overwrite an administrator's entry; resolved by `merge_plan` | — |
| Invalid planned value | Unsupported type or data; reported instead of panicking | — |

"Prevent installation of removable devices" is **not** a conflict. It is the lowest layer
(instance IDs > device IDs > setup class > removable devices), so planned device-ID allows take
precedence over it. It is reported as a foreign value.

## 3. Review of the Device Installation Restrictions strategy

| Topic | Design | Residual risk / open item |
|---|---|---|
| **Internal system disk safety** | Prevent by **DiskDrive setup class**, never retroactive. Every internal disk in the baseline gets an `AllowInstanceIDs` entry (highest layer). The `system_disks_protected` gate requires an allow for every internal disk, no disk of unknown attachment, at least one internal disk, and no retroactive flag. `staleness` invalidates the plan when disks change. | A disk reinstalled with a *new* instance ID (controller change, some feature updates) is blocked: use `suspend_ops` first. Community reports of boot problems after feature updates are listed in the plan's risks. |
| **Already-installed unauthorized USB storage** | Install-time rules do **not** affect installed devices. The dry run lists them (`already_installed_denied`). The `dry_run_reviewed` gate requires the administrator to review them. Cleanup is a manual, documented step (Device Manager or `pnputil /remove-device <instance>` by the administrator, after a backup). RustWard never removes devices. | Until cleanup is verified, such a device keeps working when plugged in again (L-05). |
| **New USB devices** | A new USB disk needs a DiskDrive driver: prevented unless its vendor-level hardware ID is on `AllowDeviceIDs` (`USBSTOR\Disk<vendor>` or `SCSI\Disk<vendor8>`). The parent `USB\VID_…` device installs normally. | Vendor strings are not authenticated (L-01). |
| **USBSTOR and UASP** | BOT drives enumerate under `USBSTOR\Disk…`, UASP drives under `SCSI\Disk…`. Both namespaces are planned per brand. | A `SCSI\Disk<vendor>` allow also matches **internal** SATA/SAS disks reporting the same vendor string. That is over-allowing, not over-blocking. The USB parent chain cannot be expressed in Device Installation Restrictions. |
| **Class-level hazards** | DiskDrive prevent also affects VHD/VHDX mounts, Storage Spaces, iSCSI and any new internal disk. CD-ROM, WPD/MTP phones and card readers with other classes are **enforcement gaps** reported by the dry run. | The scope decision for CD/DVD and MTP is open (L-08). |
| **Changes to installed hardware** | Replacing or adding an internal disk: suspend → install → recapture baseline → re-plan → re-approve (`plan_current` gate). | Procedure only; nothing automated. |
| **Windows feature updates** | Before the update: `suspend_ops`. After the update: verify the system disk, keyboard and mouse; `staleness` reports `OsBuildChanged`; re-plan; resume (rollback of the suspend). | Needs VM validation with a real feature update (Stage F). |
| **Recovery and rollback** | `rollback_ops` restores the captured state exactly, including the administrator's pre-existing values. Offline recovery: WinRE → load the offline SOFTWARE hive → remove `DenyDeviceClasses` (RECOVERY-PLAN.md). | Writing and refreshing policy is not implemented, so rollback has only been tested on the in-memory model. |
| **Coexistence with Group Policy** | `merge_plan` keeps the administrator's own entries. Foreign values are never touched. Conflicts block activation. | Standalone workstations have no domain GPO. Local Group Policy edits made after activation are not monitored. |

## 4. Still unimplemented (explicit)

1. ~~Read-only capture of the Restrictions key on Windows.~~ **Phase 10 step 1:** implemented in
   `rustward-windows::policy_reader` (`KEY_READ` only; NOT VERIFIED ON WINDOWS) and interpreted by
   `rustward-enforcement::policy_inspect`; CLI `rustward-inventory policy-capture` /
   `policy-inspect`. See §5.
2. Any registry write, policy refresh or device rescan.
3. Confirming every planned value name against Microsoft documentation in the VM. All but `AllowDenyLayered` are still marked `confirmed_against_documentation = false`.
4. Producing `AppliedPolicyReceipt` and `VerificationEvidence` (read/write denial probe).
5. A UI for the activation workflow: the gates exist in the library only.

Sources: [Policy CSP – DeviceInstallation (Microsoft Learn)](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-deviceinstallation) ·
[Named Pipe Security and Access Rights (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

## 5. Read-only policy inspection (Phase 10 step 1)

| Part | Implementation | Status |
|---|---|---|
| Capture | `rustward-windows::policy_reader::capture`: `RegOpenKeyExW(HKLM, …\DeviceInstall\Restrictions, KEY_READ \| KEY_WOW64_64KEY)`, `RegEnumValueW` / `RegEnumKeyExW` (values of the key and one level of subkeys, ≤ 4096 entries, ≤ 64 KiB per value), `RegCloseKey`. Read-only API allowlist enforced by test `policy_reader_is_read_only`. | Type-checked; NOT RUN on Windows |
| OS facts | `RtlGetVersion` (major/minor/build), `GetProductInfo` (edition code). UBR via `RegGetValueW(…\Windows NT\CurrentVersion, "UBR")` — **no documented API**, so layering support on 19041–19045 is reported *unresolved* even when the UBR is high enough. | Type-checked |
| Decoding | `rustward-windows::regdecode` (REG_DWORD, REG_SZ, REG_EXPAND_SZ verbatim, REG_MULTI_SZ; other types by type and size only) | Tested |
| Interpretation | `policy_inspect::inspect`: the 8 CSP-documented names are *documented*; list-entry layout (numbered values in a subkey named after the policy) and `*Retroactive` flags are *unresolved*; everything else is *unrecognised* and shown raw; edition support (product codes checked against windows-sys constants), layering support, conflicts with the RustWard plan, plan-value presence (`not_applied` / `partial` / `policy_values_present` — never "protected") | Tested |
| Evaluation model | `policy_eval::evaluate_install`: documented layered order and default prevent-precedence, hardware **or** compatible ID matching, `DenyUnspecified`; removable-devices layer not modelled | Tested; predictions NOT VERIFIED |
| CLI | `rustward-inventory policy-capture --out FILE`, `policy-inspect (--policy-capture FILE \| --live) [--snapshot FILE] [--json]` | Tested with capture files |

Sources: [Policy CSP – DeviceInstallation](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-deviceinstallation) ·
[Manage Device Installation with Group Policy](https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy)

## 6. Already-installed storage devices (Phase 10 step 2)

`rustward-enforcement::installed_assessment::assess` (CLI `rustward-inventory assess-installed`)
assesses every **disk-class** device in an inventory, including non-present devices. Keyboards,
mice, printers and hubs are never assessed. For each device it reports:

- the simulated RustWard verdict;
- the modelled outcome of a *new* installation under the planned policy (merged with the captured
  existing policy);
- whether it **would remain accessible after activation**. This is the case for any denied
  device whose installation already exists, because installation restrictions are not retroactive
  and RustWard never plans a retroactive class rule.

| Finding | Meaning | Action |
|---|---|---|
| `denied_but_installed` | Denied, but the existing installation keeps working | **Manual** remediation steps (backup → Device Manager "Uninstall device" by an administrator → re-assess). RustWard does none of this. |
| `denied_not_installed` | Denied, no installation (problem code 28); a new installation would be prevented (model) | none |
| `allowed` | Allowed brand (including UASP and previously unseen models through vendor-level IDs) | none |
| `internal_disk_protected` / `internal_disk_unprotected` | Internal disk with / without an effective allow rule (an existing `DenyInstanceIDs` entry outranks it) | never remediated; unprotected blocks activation |
| `attachment_unknown` | Parent chain broken | manual review only |
| `allowed_but_plan_prevents` / `denied_but_plan_allows` | Plan and policy disagree | fix the plan |

Installation state: problem code 28 means *not installed*. A recorded driver service means
*installed*. Anything else is *unknown* and is treated as installed, which is the fail-safe
assumption that the device stays accessible.

Requirements this mechanism **cannot** fulfil (also listed in every report):

- blocking devices that are already installed, without a retroactive rule;
- authenticating a vendor string: a device reporting the SanDisk vendor string is allowed (the
  fixture's spoof case shows this);
- covering CD/DVD, MTP and other non-DiskDrive classes.
