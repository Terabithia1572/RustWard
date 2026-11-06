# Audit Integrity (Phase 9A)

Status (updated Phase 9B): **implemented and tested on Linux** (SQLite logic, IPC, UI). Event Log
mirroring, the message table and the installer's event-source registration are
**NOT VERIFIED ON WINDOWS**.

## 1. What changed and why

Before Phase 9A, "restore" replaced the whole live database with the backup. In that
design:

- every audit event recorded after the backup left the live database (it survived only
  in a pre-restore copy and in the Event Log);
- the active policy silently went back to the backup's policy version, so a restore
  could re-activate an old, more permissive policy;
- any file in the backup directory with a valid name was accepted. Its contents
  were checked only by SQLite `integrity_check`, so a foreign or tampered
  database file passed as long as SQLite could open it.

Phase 9A replaces this with a **non-destructive, two-step policy restore**. Audit history
is never rolled back.

## 2. Restore design

```
            Administrator (elevated, admin pipe)
                     │ PrepareRestore{file_name}
                     ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ inspect_backup (read-only)                                   │
  │  1 file name is a plain RustWard backup name (no path)       │
  │  2 name is in the backup registry (created by this service)  │
  │  3 regular file (symlink_metadata), size and SHA-256 match   │
  │  4 copied to a private temp file, opened read-only           │
  │  5 PRAGMA integrity_check, schema version ≤ current,         │
  │    RustWard tables present, active policy validates          │
  │    against the catalog stored in the backup, settings valid  │
  └──────────────────────────────────────────────────────────────┘
                     │ preview: diff of workstation id, mode, brands
                     │ allowed/removed/changed, settings; restore_id;
                     │ expires in 10 min; audit "restore_prepared"
                     ▼
            Administrator reviews the preview in the UI
                     │ ApplyRestore{restore_id, expected_policy_version}
                     ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ apply (single use, same account, not expired, version check) │
  │  1 pre-restore backup of the current state (registered)      │
  │  2 ONE SQLite transaction:                                   │
  │     - backup's policy saved as NEW version (active + 1)      │
  │     - policy_changes row "policy_restored"                   │
  │     - settings from the backup                               │
  │     - audit event "policy_restored" (warning)                │
  │  3 decisions re-evaluated (simulation)                       │
  └──────────────────────────────────────────────────────────────┘
```

Properties (all covered by automated tests, see §6):

| Requirement | How |
|---|---|
| Audit history preserved independently of policy restores | Restore never touches `security_events`; it appends. Older and newer events, the hash chain and the chain anchor are unchanged. |
| Successful and failed attempts recorded | `restore_prepared`, `policy_restored`, `restore_failed` (stage `prepare` / `apply` / `request`, reason code, account). Invalid requests and refused authorizations are audited too (`authorization_failed`, rate-limited). |
| Timestamps, policy versions, restore id, admin identity | `policy_restored` details: `restore_id`, `backup_file`, `backup_sha256`, `backup_created_ms`, `backup_policy_version`, `from_policy_version`, `to_policy_version`, `workstation_id`, `catalog_version`; actor = Windows account from the pipe token. |
| No silent loss of newer records | Nothing is deleted or replaced. Audit/history tables are append-only for application code (triggers, §4). |
| Recoverable pre-restore state | A registered `rustward-pre-restore-<ms>.db` is created before the change; it can itself be restored with the same two-step flow. |
| Backup integrity verified | Registry entry (name, SHA-256, size, policy version, kind, actor) is written in the same transaction as the `backup_created` audit event; restore requires an exact hash match. |
| Corrupted / unauthorized files rejected | Unregistered, altered (hash mismatch), missing, non-regular (symlink), corrupt, non-RustWard, newer-schema and invalid-policy files are rejected with a stable code (`not_registered`, `hash_mismatch`, `missing`, `not_regular_file`, `corrupt`, `not_rust_ward`, `schema_too_new`, `invalid_policy`, `invalid_name`). |
| Path traversal prevented | IPC validation accepts only `rustward-backup-<digits>.db` / `rustward-pre-restore-<digits>.db`; storage re-checks that the name has no separators. The directory is fixed by the service. |
| Atomic | Policy version, history row, settings and audit event commit in one transaction. A version conflict (someone changed the policy after the preview) aborts everything. |
| Never auto-activates an older policy | The backup's *content* becomes a **new, higher** version; the version number never goes back. `expected_policy_version` and the per-preview diff make the change explicit. Restoring does not change enforcement (dry-run build). |

The old `database_restored` event ID (5000) is kept in the Event Log map so historic
entries keep their ID; the code no longer emits it.

## 3. Disaster recovery (lost or corrupted live database)

The two-step restore needs a working live database (the registry and the audit log live
in it). If the live database itself is corrupt or deleted, recovery is a **manual,
documented procedure** (RECOVERY-PLAN.md §"Corrupted RustWard DB"): stop the service,
move the damaged file aside (keep it as evidence), copy the most recent backup in place as
`rustward.db`, start the service, verify the chain status in Diagnostics, and record the
incident outside RustWard (paper/incident log). Events recorded after that backup exist only
in the damaged file and in the Event Log. This is deliberately not automated: an
automatic file-level replacement is exactly the audit-loss pattern removed above.

## 4. Append-only tables (migration v2)

| Table | Guard |
|---|---|
| `security_events` | `UPDATE` refused; `DELETE` refused except rows at or below the cutoff of an active retention guard row inserted by `apply_retention` in the same transaction. |
| `policy_changes` | no `UPDATE`, no `DELETE` |
| `policy_states` | content columns immutable; no `DELETE` (only `is_active` may change) |
| `backups` | no `UPDATE`, no `DELETE` (a deleted file stays registered and is shown as "Dosya yok") |

Triggers protect against **application bugs** and accidental SQL, not against an attacker:
anyone who can write the database file can drop the triggers.

## 5. Separate audit store? (evaluation)

| Option | Assessment |
|---|---|
| Separate append-only SQLite file for audit | Rejected for now. A policy change and its audit event would no longer commit atomically: SQLite multi-database transactions are not atomic across files in WAL mode, so a crash could leave a policy change without its audit record, or the reverse. The same ACL protects both files, so a separate file adds no protection against an administrator. The real problem, restore erasing audit history, is solved by never replacing the database. |
| Windows Event Log mirror | **Kept and strengthened** (message table + installer registration). It is a second, independent copy outside the RustWard database and survives deletion of RustWard data. Limits: administrators can clear the log; log size/retention is a Windows setting (`wevtutil sl Application /ms:`); mirroring runs after commit and only while the service runs. **Phase 9B:** the delivery cursor is persisted, so events written before the mirror attaches or during an Event Log outage are delivered later in order (newest 1000 at most; an older gap is recorded as `event_log_backfill_skipped`, 1009); delivery is at-least-once. |
| Event forwarding / WORM / remote syslog | The strongest option, but it needs a network or removable media workflow. Out of scope for an air-gapped, standalone design. A periodic **signed export to write-once media** (CD-R, or a separate locked USB drive kept by the security officer) is the recommended organisational control. |
| Keyed hash (HMAC) chain | Not adopted. A key stored on the same machine is readable by the same administrators who can rewrite the chain, so it adds complexity without changing the threat model. |

## 5a. Detection added in Phase 9B

| Mechanism | Detects | Does not detect |
|---|---|---|
| `verify_chain` → `Missing` | removed events inside the chain (id gap), including newest events removed and new ones appended | a rewrite that renumbers ids consistently |
| `verify_chain` → `Truncated` | newest events removed (SQLite `AUTOINCREMENT` counter above the newest id) | an attacker who also resets `sqlite_sequence` |
| `audit_checkpoint` (5008) at start and daily, mirrored to the Event Log | anything that changes or removes the checkpointed head, compared with `rustward-service verify-checkpoint` (read-only) | changes when every out-of-database copy (Event Log, exports, printouts) is also destroyed |

Procedure: an auditor copies `head #N <hash>` from a 5008 entry in Event Viewer (or from an
export kept on write-once media) and runs
`rustward-service verify-checkpoint --head-id N --hash <hash>`. Exit 0 = unchanged, 3 = rewritten
or removed, 4 = older than retention (not verifiable).

## 6. Tamper-resistance limits (honest statement)

The local audit log is **tamper-evident against non-administrators and against software
bugs. It is not tamper-proof.**

- A local administrator or SYSTEM can stop the service, edit the database, drop triggers,
  recompute the SHA-256 chain (it is unkeyed) and the anchor, delete backups, and clear the
  Event Log. Clearing the Application log is itself logged by Windows (System/Security
  logs), but those can be cleared too.
- The chain detects modification or removal of records **inside** the chain, and (Phase 9B)
  truncation of the newest records unless the attacker also resets SQLite's sequence
  counter. A fully consistent rewrite is detected only by comparison with an
  out-of-database checkpoint (§5a). Removal of the oldest records with an anchor rewrite is
  what retention legitimately does (`retention_applied`).
- Retention uses the system clock; an administrator who moves the clock forward can make
  retention delete more than intended. The deletion is recorded and mirrored.
- Backups are protected by the data-directory ACL (SYSTEM + Administrators) and by the
  registry hash; an administrator can delete them (a deleted file stays in the registry).
- Detection depends on someone comparing the Event Log, exports and the database
  (Diagnostics shows chain status and mirror status).

Organisational controls therefore matter: standard-user operators, separate admin
accounts, periodic exports to write-once media, and review of `restore_*`,
`policy_*`, `authorization_failed` and `retention_applied` events.

## 7. Tests

- `crates/rustward-storage/tests/store.rs`: `backups_are_registered_hashed_and_audited`,
  `restore_applies_backup_as_a_new_version_without_losing_history_or_audit`,
  `stale_restore_is_refused_atomically`,
  `foreign_altered_missing_and_traversal_backups_are_rejected`,
  `registered_but_invalid_backups_are_rejected`,
  `audit_and_history_tables_are_append_only_for_application_code`,
  `v1_database_upgrades_to_v2_keeping_data_and_gaining_guards`, plus the chain-tamper tests
  (which drop the triggers first, i.e. model an attacker with file access).
- `crates/rustward-app/tests/app_flows.rs`:
  `restore_is_two_step_and_never_rolls_back_versions_history_or_audit`,
  `prepared_restores_are_single_use_bound_to_the_admin_and_expire`,
  `foreign_altered_and_traversal_restores_are_refused_and_audited`.
- `crates/rustward-app/tests/ipc_security.rs`: restore requests from non-admin, unelevated
  and read-only-channel callers are refused and audited.
- `crates/rustward-windows/src/eventlog_map.rs`:
  `message_table_resolves_every_event_id_and_nothing_else`.
- Frontend: two-step restore dialog, cancel, missing-file badge (`pages.test.tsx`).
