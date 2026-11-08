# Next Phase Architecture: Managing Authorized Windows USB Access Policies via Desktop UI

## 1. Overview
The goal of this phase is to transition from manual Group Policy Editor (`gpedit.msc`) administration to an administrator-authorized, desktop-managed workflow through the RustWard desktop client, without creating local privilege escalation (LPE) vulnerabilities or risking system disk lockouts.

---

## 2. Security Boundaries & Authorization Architecture
1. **Named Pipe Authorization (`\\.\pipe\RustWard.Admin.v1`)**:
   - Must verify caller's Windows access token using `ImpersonateNamedPipeClient` + `OpenThreadToken` + `GetTokenInformation`.
   - Caller must hold `TokenElevationTypeFull` and `BUILTIN\Administrators` (`S-1-5-32-544`).
   - Standard user processes cannot trigger policy writes.
2. **Strict Scope Limiting**:
   - Service policy writer can only write under `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`.
   - Writes to arbitrary registry paths or files are strictly prohibited.
3. **Internal Disk Whitelist Invariant**:
   - Before applying any `DenyDeviceIDs` or `DenyDeviceClasses`, the service must query all present system disks (NVMe, SATA, SCSI) and inject their instance paths into `AllowInstanceIDs` with `AllowDenyLayered = 1`.
4. **Watchdog Auto-Revert Loop**:
   - Applying a policy arms an automatic 60-second watchdog.
   - If the system disk fails health checks, or if the administrator fails to confirm responsiveness within 60s, the service automatically rolls back to the pre-change baseline stored in SQLite.

---

## 3. Implementation Plan
1. **Service Side (`crates/rustward-enforcement`)**:
   - Implement `PolicyWriter` struct with transactional registry write, verification, and automatic rollback.
   - Implement `Watchdog` thread for auto-rollback timer.
2. **IPC Protocol (`crates/rustward-ipc`)**:
   - Add typed requests: `ApplyPolicyPlan { session_id, confirmation_token }`, `ConfirmPolicyHealthy { session_id }`, `RollbackPolicy { session_id }`.
3. **Frontend Client (`apps/rustward-desktop`)**:
   - Enhance `Readiness.tsx` and `Dashboard.tsx` with one-click administrative apply, watchdog confirmation modal, and immediate visual status updates.
