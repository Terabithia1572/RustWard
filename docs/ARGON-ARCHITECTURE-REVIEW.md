# ARGON Architecture Review — Windows Service, IPC & Desktop Client

**Workspace:** `<workspace>` (`experiment/argon4-vm-enforcement`)

---

## 1. End-to-End Runtime Architecture

RustWard is structured as an offline-first, privilege-separated Windows endpoint application comprising eight Rust crates and a Tauri 2 + React 19/TypeScript desktop client:

1. **Presentation Layer (`apps/rustward-desktop/src`)**:
   - Stateless React 19 UI rendered inside WebView2.
   - Zero direct network, filesystem, registry, or shell capabilities (`connect-src 'self'`).
   - Communicates exclusively via `invoke("rustward_call", { request })` (`src/api/client.ts`).
2. **Desktop Shell (`apps/rustward-desktop/src-tauri` + `crates/rustward-ui-bridge`)**:
   - Exposes a single Tauri command (`rustward_call`) executed on Tokio's `spawn_blocking` pool so synchronous pipe I/O never stalls the UI event loop.
   - In release builds (`cfg(not(all(debug_assertions, feature = "dev-backend")))`), `ServiceBackend` is the **only** compiled backend; `DevBackend` does not exist in `RustWard.exe`.
3. **Authenticated Local IPC (`crates/rustward-ipc`)**:
   - Length-prefixed JSON frames (`u32` LE + UTF-8 payload, capped at `MAX_FRAME_BYTES = 1,048,576` bytes; strings validated for length, control characters, and structure in `validate.rs` before dispatch).
   - Split across two named pipes under `\\.\pipe\RustWard\v1\`:
     - `status` (`MAX_STATUS_CONNECTIONS = 8`, `AccessLevel::ReadOnly`): SDDL permits `SY`, `BA`, and `AU` (Authenticated Users), with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`.
     - `admin` (`MAX_ADMIN_CONNECTIONS = 4`, `AccessLevel::Administrator`): SDDL restricts pipe open to `SY` and `BA` (`BUILTIN\Administrators`), preventing unprivileged users from exhausting admin worker slots.
   - **Mutual Verification**:
     - **Client verifies server** (`pipe.rs`): Queries object owner SID (`GetSecurityInfo` must be `LocalSystem` or `RustWardService` virtual SID) and verifies `GetNamedPipeServerProcessId` matches SCM's `QueryServiceStatusEx` PID for `RustWardService` (defeating pipe squatting prior to service start).
     - **Server verifies client** (`pipe.rs`): Calls `ImpersonateNamedPipeClient`, extracts user SID + account name, checks `TokenElevation` + `CheckTokenMembership(WinBuiltinAdministratorsSid)`, immediately calls `RevertToSelf`, and caps `channel_max_access` by pipe role.
4. **Windows Service & Application Core (`crates/rustward-service`, `rustward-app`, `rustward-core`, `rustward-enforcement`)**:
   - Runs as `RustWardService` (`LocalSystem`, auto-start, SCM failure recovery restart after 5s).
   - `ServiceRuntime` combines event-driven PnP arrival/removal notifications (`CM_Register_Notification`, debounced 400ms) with a bounded periodic refresh loop (`inventory_refresh_seconds`, default 30s), retention check, and daily `audit_checkpoint`.
   - `AppService` coordinates pure policy evaluation (`rustward-core`), read-only Windows policy/device observation (`rustward-enforcement`), and transactional persistence (`rustward-storage`).
5. **Persistence & Audit Evidence (`crates/rustward-storage` + `rustward-windows::event_log`)**:
   - `%ProgramData%\RustWard\rustward.db` protected by `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`.
   - SQLite `WAL` + `synchronous = FULL`, `BEFORE UPDATE`/`BEFORE DELETE` triggers guarding `security_events` and `policy_changes`, SHA-256 hash chaining, `sqlite_sequence` truncation detection, and ordered mirroring to the Windows Application Event Log (`RustWard` source with embedded `RT_MESSAGETABLE`).

---

## 2. Concurrency, Locking, Cancellation & Crash Recovery Review

### 2.1 Existing Strengths Preserved
- **Graceful Shutdown**: SCM `SERVICE_CONTROL_STOP` / `SHUTDOWN` signals an `AtomicBool` stop flag and wakes worker condition variables (`runtime.rs`, `ipc_pool.rs`). Each pipe server stops its acceptor via self-connect wakeup and joins worker threads within `SHUTDOWN_DEADLINE` (3s per pipe, well inside SCM `WAIT_HINT_MS = 10,000ms`), auditing `ipc_shutdown_incomplete` if any worker misses the deadline.
- **Crash & Restart Recovery**: Active policy states carry SHA-256 checksums; guided enforcement sessions are persisted in SQLite (`settings` key `guided_enforcement_session_v1`) so service restarts or Windows reboots preserve baseline snapshots and expected policy lines. SQLite `WAL` recovers cleanly after power loss.
- **Zero Command Execution**: Neither the service nor the Tauri shell spawns external processes (`powershell.exe`, `cmd.exe`, `reg.exe`, `pnputil.exe`, `gpupdate.exe`).

### 2.2 Architectural Bottlenecks Identified & Addressed in ARGON Phase 4

1. **Registry Policy Reads Under Global `AppService::inner` Mutex**:
   - Previously, `GetDashboard`, `GetEnforcementObservation`, `GetEnforcementReadiness`, `GetEnforcementSession`, `PrepareEnforcementSession`, `PrepareDefaultDenySession`, `VerifyEnforcementApplied`, and `VerifyEnforcementRollback` called `self.policy_source.capture(now)` *inside* `self.inner.lock()`. Because the UI's `DeviceWatchProvider` polls `GetEnforcementObservation` every 2 seconds alongside page loads, registry enumeration serialized behind and blocked SQLite/IPC readers.
   - **Resolution**: Capture read-only Windows policy *outside* `self.inner.lock()` before acquiring the mutex, and deduplicate per-request `evaluate_snapshot()` passes.
2. **O(N²) Snapshot Re-Evaluation on Device Removal**:
   - Previously, `apply_inventory` cloned and re-evaluated the entire `old` snapshot inside `for id in &diff.removed`. Unplugging a composite USB device with multiple child nodes scaled quadratically while holding `self.inner.lock()`.
   - **Resolution**: Evaluate `old` once before iterating `diff.removed` (`O(N)`).
3. **SetupAPI Double-Syscall Pattern**:
   - `rustward-windows::engine::get_property` started with an empty `Vec::new()` (0 bytes), forcing every `SetupDiGetDevicePropertyW` call to fail with `ERROR_INSUFFICIENT_BUFFER`, heap-allocate, and call into SetupAPI a second time (~28,000+ syscalls per full scan).
   - **Resolution**: Probe first into a 512-byte stack buffer, falling back to exact-sized `Vec<u8>` only for oversized multi-string properties.
4. **Named-Pipe Poll Quantum & Refresh Coalescing**:
   - `PipeConnection::read_exact_until` slept `10ms` (~15.6ms Windows timer tick) on the first empty `PeekNamedPipe`, adding ~16ms latency to every fast RPC. Adaptive backoff (`yield -> 1ms -> 5ms`) removes this floor while keeping CPU idle on quiet connections.
   - Coalescing concurrent/just-completed (<250ms) `refresh_inventory` requests and giving explicit admin verification calls a bounded 25s RPC deadline eliminates compound queue stalls when `WM_DEVICECHANGE` fires concurrently with administrator verification.

---

## 3. Design Specification for Future Automated Policy Management (Not Activated)

Per Section 10, `ACTIVATION_ENABLED` remains `false` and automated policy writing remains **BLOCKED** pending explicit owner authorization and dedicated security review (`B1`). Should that review be approved in a future phase, a production-grade automatic writer **must** satisfy all seven architectural invariants below:

1. **Supported API Only (`IGroupPolicyObject` COM Interface)**:
   - Never write `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` directly via `RegSetValueExW` (which desynchronizes `%SystemRoot%\System32\GroupPolicy\Machine\Registry.pol` and is overwritten on the next `gpupdate`).
   - Use `CoCreateInstance(CLSID_GroupPolicyObject)` → `OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY)` → `GetRegistryKey(GPO_SECTION_MACHINE)` → write validated `Restrictions` values → `Save(TRUE, TRUE, &REGISTRY_EXTENSION_GUID, &RUSTWARD_ADMIN_GUID)` on a dedicated STA worker thread.
2. **Strict Authorization & Two-Step Confirmation**:
   - Require `AccessLevel::Administrator` (elevated UAC token verified via pipe impersonation) plus a short-lived plan fingerprint token (`plan_fingerprint` + `expected_policy_version`) matching the exact dry-run preview reviewed by the administrator.
3. **Mandatory Pre-Write Safety Gates**:
   - Refuse compilation or commit if `DenyUnspecified == 1`, `DenyDeviceClassesRetroactive == 1`, any generic hardware ID (`USBSTOR\GenDisk`, `GenDisk`) appears in an allow list, or any present boot/paging/crashdump/internal storage devnode lacks a verified Layer-1 `AllowInstanceIDs` entry.
4. **Transactional Baseline Snapshot & Atomic Rollback**:
   - Persist both the live registry capture and a SHA-256 backup copy of `Machine\Registry.pol` into `%ProgramData%\RustWard\policy-baselines\` *before* mutating the GPO, enabling deterministic 1-click rollback (`policy_ops.rs`).
5. **Post-Write Self-Verification & Dead-Man Watchdog**:
   - Re-read `Restrictions` via `policy_reader` immediately after `IGroupPolicyObject::Save`, verify exact value equality, and re-enumerate internal storage devnodes (`problem_code == None`). If internal storage reports a policy error or mismatch, automatically execute rollback within the same transaction.
6. **Maintenance Suspend Window**:
   - Provide a time-bounded maintenance suspend command (audited, admin-only) so administrators can attach replacement internal disks or mount VHD/VHDX images without permanently deleting allowlist rules.
7. **Tamper-Evident Audit Trail**:
   - Record preparation, pre-write baseline hash, exact GPO mutation diff, post-write verification outcome, and rollback in the SQLite hash chain and Windows Event Log (`Event ID 3xxx`).
