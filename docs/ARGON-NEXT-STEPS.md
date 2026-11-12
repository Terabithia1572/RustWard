# ARGON Exact Next Engineering & Acceptance Steps

**Workspace:** `<workspace>` (`experiment/argon4-vm-enforcement`)

---

## 1. Immediate Action: Controlled Windows 10 VMware Acceptance Run (Awaiting User Approval)

All safe repository-side engineering — Phase 0–2 audits, Phase 3 policy-engine hardening (`ConflictingIdentifiers` + explicit denylist `matched_brand`), Phase 4 bug fixes (Bug A `retroactive` round-trip guard, Bug B SetupAPI/IPC/lock optimizations, Bug C historical rollback separation, Bug D Turkish status badges), Phase 5 8-page UX upgrades, native Windows test suite fixes, and isolated x64 release/MSI builds — is complete inside `RustWard2`.

To proceed into live VM execution (**Stage A & Stage E**), explicit user authorization is requested for the following exact sequence on **`<test-vm>.vmx`** (leaving the Windows 11 host and original `<baseline-workspace>` completely untouched):

1. **Snapshot First**: Create VMware snapshot `rustward2-argon4-before-acceptance` via `vmrun.exe`.
2. **Read-Only Live Guest Inspection**: Boot the VM and record live Windows build, PnP storage/USB tree, current `Restrictions` & `RemovableStorageDevices` registry keys, installed `RustWardService` version, and SQLite session/audit state.
3. **Isolated `RustWard2` MSI Upgrade**: Copy `<workspace>\dist\installer\RustWard_0.1.0_x64_tr-TR.msi` into the guest (without touching `<baseline-workspace>`), upgrade `RustWardService` + `RustWard.exe`, and verify database/audit preservation and live IPC/SetupAPI latency inside the VM.
4. **Stage A — Guided Kingston Denial & Rollback**:
   - Prepare Kingston (`USBSTOR\DiskKingstonDataTraveler_3.0____`, `retroactive = true`) session and confirm round-trip persistence in UI.
   - Apply the single-device `DenyDeviceIDs` policy via `gpedit.msc` + `gpupdate /force`.
   - Independently verify `Code 1`/`Code 28` block, `E:`/`F:` removal, and zero impact on `C:` (NVMe), `G:` (`346D:5678`), keyboard, mouse, and hubs.
   - Reboot test (if included in approval — **Stage E**) to verify policy and `RustWardService` auto-start persistence across restart.
   - Roll back policy in `gpedit.msc` + `gpupdate /force`, verify `GERİ ALMA TAMAMLANDI` in RustWard, confirm `E:`/`F:` return healthy, and confirm Kingston appears only under historical blocks.

---

## 2. Subsequent Hardware & Security Milestones

1. **Stage B — Physical Hardware Inspection (SanDisk & Hardware-Encrypted USB)**:
   - Connect at least two genuine SanDisk USB drives (classic `USBSTOR` BOT flash drive and, if used in production, UASP external SSD) to confirm `VID_0781` and `USBSTOR\DiskSanDisk_` / `SCSI\DiskSanDisk_` prefixes across models.
   - When a genuine **Hardware-Encrypted USB (Unverified Profile)** device is physically available, capture its read-only `rustward-inventory capture` descriptors **both before and after hardware/PIN unlock** (never capturing or recording the PIN), verify whether its vendor identifier is unique vs. generic controller silicon, and add lab-verified identifiers to `manufacturer-catalog.json`.
2. **Stage C & D — Non-Retroactive Layered Default-Deny Profile Trial (Separate Approval)**:
   - After Stage B confirms genuine SanDisk identifiers, take a dedicated VM snapshot and test the 4-setting non-retroactive `DefaultDenyProfile` (`AllowDenyLayered = 1`, Layer-1 internal NVMe `AllowInstanceIDs`, Layer-2 `AllowDeviceIDs`, Layer-3 `DenyDeviceClasses = DiskDrive` with `DenyDeviceClassesRetroactive = 0`), verifying newly connected unapproved drives are blocked (`Code 28`) while `C:`, approved SanDisk drives, and HID peripherals work normally.
3. **Separate Security Review for Optional Future `IGroupPolicyObject` Writer (`B1`)**:
   - Only if the security owner explicitly authorizes lifting `B1`, implement the STA COM `IGroupPolicyObject` (`GPO_OPEN_LOAD_REGISTRY` + `Save` to `Machine\Registry.pol`) writer behind the 7 architectural gates defined in [ARGON-ARCHITECTURE-REVIEW.md](ARGON-ARCHITECTURE-REVIEW.md) §3, rehearsing WinRE offline recovery first.
4. **Release Hardening for Production Rollout**:
   - Authenticode-sign `rustward-service.exe`, `rustward-inventory.exe`, `RustWard.exe`, and `RustWard_0.1.0_x64_tr-TR.msi` with an enterprise code-signing certificate.
   - Add an elevated-launch shortcut/manifest helper for admin workflows while keeping daily workstation operators on Standard User accounts.
   - Upgrade dev-only test runner `vitest` (`3.2.7` → `>= 4.1.12`) in an isolated tooling commit.
