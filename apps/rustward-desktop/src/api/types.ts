// TypeScript mirror of crates/rustward-ipc/src/messages.rs.
// Keep in sync; request type names are checked against
// crates/rustward-ipc/contract/request-types.json by a test.

export type Verification = "unverified" | "public_registry" | "vendor_documented" | "lab_verified";
export type IdentifierKind = "inquiry_vendor" | "usb_vid";

export interface BrandIdentifier {
  kind: IdentifierKind;
  value: string;
  verification: Verification;
  source: string;
}

export interface ManufacturerInput {
  id?: string | null;
  display_name: string;
  aliases: string[];
  identifiers: BrandIdentifier[];
  notes?: string | null;
}

export interface EventQuery {
  text?: string | null;
  min_severity?: "info" | "warning" | "critical" | null;
  kind?: string | null;
  since_ms?: number | null;
  until_ms?: number | null;
  simulated?: boolean | null;
  limit?: number | null;
  offset?: number | null;
}

export type ExportFormat = "csv" | "json";

export interface SettingsView {
  theme: "system" | "light" | "dark";
  language: "tr" | "en";
  notifications_enabled: boolean;
  audit_retention_days: number;
  inventory_refresh_seconds: number;
}

export type Request =
  | { type: "get_dashboard" }
  | { type: "list_devices"; include_absent: boolean }
  | { type: "list_manufacturers" }
  | { type: "explain_device"; device_key: string }
  | { type: "list_blocked"; limit: number }
  | { type: "list_events"; query: EventQuery }
  | { type: "list_policy_changes"; limit: number }
  | { type: "get_diagnostics" }
  | { type: "get_enforcement_readiness" }
  | { type: "get_enforcement_observation" }
  | { type: "get_policy_checklist"; device_key: string; retroactive: boolean }
  | { type: "get_enforcement_session" }
  | { type: "prepare_enforcement_session"; device_key: string; retroactive: boolean }
  | { type: "prepare_default_deny_session" }
  | { type: "verify_enforcement_applied"; session_id: string }
  | { type: "verify_enforcement_rollback"; session_id: string }
  | { type: "cancel_enforcement_session"; session_id: string }
  | { type: "get_settings" }
  | { type: "run_simulation" }
  | { type: "add_manufacturer"; input: ManufacturerInput; allowed: boolean; expected_policy_version: number }
  | { type: "update_manufacturer"; id: string; input: ManufacturerInput; expected_policy_version: number }
  | { type: "remove_manufacturer"; id: string; expected_policy_version: number }
  | { type: "set_manufacturer_allowed"; id: string; allowed: boolean; expected_policy_version: number }
  | { type: "set_manufacturer_denied"; id: string; denied: boolean; expected_policy_version: number }
  | { type: "set_rule_enabled"; id: string; enabled: boolean; expected_policy_version: number }
  | { type: "update_settings"; settings: SettingsView }
  | { type: "export_events"; query: EventQuery; format: ExportFormat }
  | { type: "apply_retention" }
  | { type: "create_backup" }
  | { type: "refresh_inventory" }
  | { type: "load_synthetic_inventory" }
  | { type: "set_workstation_id"; workstation_id: string; expected_policy_version: number }
  | { type: "list_backups" }
  | { type: "prepare_restore"; file_name: string }
  | { type: "apply_restore"; restore_id: string; expected_policy_version: number }
  | { type: "apply_device_block"; session_id?: string | undefined; device_key?: string | undefined; retroactive?: boolean | undefined }
  | { type: "restore_device_policy"; session_id?: string | undefined }
  | { type: "get_compound_policy_plan" }
  | { type: "apply_compound_policy"; retroactive?: boolean | undefined; expected_policy_version: number }
  | { type: "rollback_compound_policy" }
  | { type: "recover_device"; device_key: string };

export type RequestType = Request["type"];

/** Every request type, in contract order. */
export const REQUEST_TYPES: readonly RequestType[] = [
  "get_dashboard",
  "list_devices",
  "list_manufacturers",
  "explain_device",
  "list_blocked",
  "list_events",
  "list_policy_changes",
  "get_diagnostics",
  "get_enforcement_readiness",
  "get_enforcement_observation",
  "get_policy_checklist",
  "get_enforcement_session",
  "get_settings",
  "run_simulation",
  "prepare_enforcement_session",
  "prepare_default_deny_session",
  "verify_enforcement_applied",
  "verify_enforcement_rollback",
  "cancel_enforcement_session",
  "add_manufacturer",
  "update_manufacturer",
  "remove_manufacturer",
  "set_manufacturer_allowed",
  "set_manufacturer_denied",
  "set_rule_enabled",
  "update_settings",
  "export_events",
  "apply_retention",
  "create_backup",
  "refresh_inventory",
  "load_synthetic_inventory",
  "set_workstation_id",
  "list_backups",
  "prepare_restore",
  "apply_restore",
  "apply_device_block",
  "restore_device_policy",
  "get_compound_policy_plan",
  "apply_compound_policy",
  "rollback_compound_policy",
  "recover_device",
];

/** Requests that require an elevated administrator (server-enforced). */
export const PRIVILEGED: ReadonlySet<RequestType> = new Set<RequestType>([
  "prepare_enforcement_session",
  "prepare_default_deny_session",
  "verify_enforcement_applied",
  "verify_enforcement_rollback",
  "cancel_enforcement_session",
  "add_manufacturer",
  "update_manufacturer",
  "remove_manufacturer",
  "set_manufacturer_allowed",
  "set_manufacturer_denied",
  "set_rule_enabled",
  "update_settings",
  "export_events",
  "apply_retention",
  "create_backup",
  "refresh_inventory",
  "load_synthetic_inventory",
  "set_workstation_id",
  "list_backups",
  "prepare_restore",
  "apply_restore",
  "apply_device_block",
  "restore_device_policy",
  "apply_compound_policy",
  "rollback_compound_policy",
  "recover_device",
]);

export interface ServiceStatusView {
  backend: "dev_backend" | "windows_service" | string;
  state: "running" | "degraded" | "unreachable" | string;
  healthy: boolean;
  started_ms: number | null;
  last_refresh_ms: number | null;
  message: string;
  /** Turkish rendering (empty from older services). */
  message_tr?: string;
}

export type SimulatedDecision = "allow" | "deny" | "not_applicable";

export interface DeviceView {
  device_key: string;
  display_id: string;
  category: string;
  storage_type: string | null;
  vendor: string | null;
  product: string | null;
  usb_vid_pid: string | null;
  vendor_level_id: string | null;
  friendly_name: string | null;
  matched_brand: string | null;
  present: boolean;
  synthetic: boolean;
  first_seen_ms: number;
  last_seen_ms: number;
  simulated_decision: SimulatedDecision | string;
  reason: string;
  policy_version: number;
  enforcement_state: string;
  enforcement_verified: boolean;
}

export interface EventView {
  id: number;
  utc_ms: number;
  severity: "info" | "warning" | "critical" | string;
  kind: string;
  device_key: string | null;
  message: string;
  /** Turkish rendering; the stored record stays as written. */
  message_tr?: string;
  simulated: boolean;
  enforcement_state: string;
  policy_version: number | null;
}

export interface DashboardView {
  enforcement_state: string;
  enforcement_label_tr: string;
  enforcement_label_en: string;
  protection_verified: boolean;
  not_validated_banner: string | null;
  service: ServiceStatusView;
  workstation_id: string;
  policy_version: number;
  catalog_version: string;
  last_policy_update_ms: number | null;
  allowed_manufacturers: number;
  connected_storage: number;
  recent_denied: DeviceView[];
  recent_events: EventView[];
  warnings: string[];
  warnings_tr?: string[];
  synthetic_data_present: boolean;
  /** Real Windows protection state (absent from older services). */
  windows_protection?: WindowsProtectionView;
}

/** Protection state derived only from real Windows evidence. */
export type WindowsProtectionState =
  | "unknown"
  | "inactive"
  | "configured_unverified"
  | "denial_observed"
  | "verified_active";

export interface WindowsProtectionView {
  state: WindowsProtectionState | string;
  label_tr: string;
  label_en: string;
  detail_tr: string;
  detail_en: string;
  denied_now: number;
  automated_apply_available: boolean;
  summary?: StorageSummaryView;
  blockers?: ProtectionBlockerView[];
}

export interface StorageSummaryView {
  connected: number;
  allow_candidates: number;
  deny_candidates: number;
  unverified_identity: number;
  unsupported: number;
  windows_denied: number;
  denied_by_policy_only: number;
  disconnected: number;
}

export interface ProtectionBlockerView {
  code: string;
  /** blocked | action | limitation */
  kind: string;
  tr: string;
  en: string;
}

/** Service-side timings in milliseconds (absent from older services). */
export interface PerformanceView {
  last_inventory_collect_ms: number | null;
  last_inventory_apply_ms: number | null;
  max_inventory_collect_ms: number | null;
  inventory_refreshes: number;
  last_inventory_devices: number | null;
  first_inventory_after_start_ms: number | null;
  last_observation_ms: number | null;
  last_verification_ms: number | null;
}

export interface IdentifierView {
  kind: IdentifierKind | string;
  value: string;
  verification: Verification | string;
  source: string;
  enforceable: boolean;
  vendor_level_ids: string[];
}

export interface ManufacturerView {
  id: string;
  display_name: string;
  aliases: string[];
  identifiers: IdentifierView[];
  notes: string | null;
  allowed: boolean;
  enabled: boolean;
  /** Explicitly denied (Phase 6). */
  denied?: boolean;
  enforceable: boolean;
  issues: string[];
  issues_tr?: string[];
}

export interface ManufacturersView {
  workstation_id: string;
  policy_version: number;
  catalog_version: string;
  mode: "dry_run" | "enforce" | string;
  manufacturers: ManufacturerView[];
  warnings: string[];
  warnings_tr?: string[];
  reserved_generic_vendors: string[];
}

export interface PolicyChangeView {
  id: number;
  utc_ms: number;
  actor: string;
  action: string;
  brand_id: string;
  summary: string;
  summary_tr?: string;
  from_version: number;
  to_version: number;
}

export interface ExplanationStep {
  stage: string;
  tr: string;
  en: string;
}

export interface ExplanationView {
  device: DeviceView;
  explanation: { summary_tr: string; summary_en: string; steps: ExplanationStep[] };
}

export type CapabilityStatus = "not_implemented" | "unsupported" | "designed_not_verified" | "verified";

export interface CapabilityReport {
  provider_id: string;
  pre_access_blocking: CapabilityStatus;
  brand_allowlisting: CapabilityStatus;
  previously_installed_devices: CapabilityStatus;
  persistence: CapabilityStatus;
  self_verification: CapabilityStatus;
  activation_available: boolean;
}

export interface Precondition {
  id: string;
  en: string;
  tr: string;
  status: "met" | "not_met" | "unknown";
}

export interface DiagnosticsView {
  service: ServiceStatusView;
  database: {
    schema_version: number;
    integrity_ok: boolean;
    chain_status: string;
    chain_ok: boolean;
    location_kind: string;
  };
  windows_adapter: { platform: string; live_inventory_available: boolean; last_error: string | null };
  policy: { valid: boolean; errors: string[]; warnings: string[]; errors_tr?: string[]; warnings_tr?: string[] };
  enforcement: {
    state: string;
    label_tr: string;
    label_en: string;
    provider_id: string;
    capabilities: CapabilityReport;
    planned_changes: number;
    preconditions: Precondition[];
    risks: string[];
    risks_tr?: string[];
    enforcement_gaps: string[];
  };
  /** Windows Event Log mirroring (absent from older services). */
  event_log?: { attached: boolean; delivered: number; failures: number; pending?: number; skipped?: number };
  unsupported_features: string[];
  pending_native_tests: string[];
  unsupported_features_tr?: string[];
  pending_native_tests_tr?: string[];
  performance?: PerformanceView;
  app_version: string;
}

export interface BackupView {
  file_name: string;
  bytes: number;
  created_ms: number;
  kind: "manual" | "pre_restore" | string;
  policy_version: number;
  sha256: string;
  actor: string;
  file_present: boolean;
}

export interface RestorePreviewView {
  restore_id: string;
  file_name: string;
  sha256: string;
  backup_created_ms: number;
  backup_policy_version: number;
  current_policy_version: number;
  resulting_policy_version: number;
  backup_workstation_id: string;
  changes: string[];
  changes_tr?: string[];
  expires_ms: number;
  notice: string;
  notice_tr?: string;
}

export interface MutationView {
  policy_version: number;
  catalog_version: string;
  summary: string;
  summary_tr?: string;
  warnings: string[];
  warnings_tr?: string[];
}

export interface ExportView {
  file_name: string;
  mime: string;
  content: string;
  count: number;
}

export interface SimulationView {
  evaluated: number;
  simulated_allow: number;
  simulated_deny: number;
  not_applicable: number;
  enforcement_gaps: string[];
  notice: string;
  notice_tr?: string;
}

export type ResponseBody =
  | { type: "dashboard"; data: DashboardView }
  | { type: "devices"; data: DeviceView[] }
  | { type: "manufacturers"; data: ManufacturersView }
  | { type: "explanation"; data: ExplanationView }
  | { type: "events"; data: EventView[] }
  | { type: "policy_changes"; data: PolicyChangeView[] }
  | { type: "diagnostics"; data: DiagnosticsView }
  | { type: "enforcement_readiness"; data: EnforcementReadinessView }
  | { type: "enforcement_observation"; data: EnforcementObservationView }
  | { type: "policy_checklist"; data: PolicyChecklistView }
  | { type: "settings"; data: SettingsView }
  | { type: "simulation"; data: SimulationView }
  | { type: "mutation"; data: MutationView }
  | { type: "export"; data: ExportView }
  | { type: "done"; data: DoneView }
  | { type: "enforcement_session"; data: EnforcementSessionView }
  | { type: "backups"; data: BackupView[] }
  | { type: "restore_preview"; data: RestorePreviewView }
  | { type: "compound_policy_plan"; data: CompoundPolicyPlanView };

export interface DoneView {
  message: string;
  message_tr?: string;
}

export type ErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "not_found"
  | "conflict"
  | "validation_failed"
  | "version_mismatch"
  | "not_supported"
  | "unavailable"
  | "timeout"
  | "internal";

// ---- Enforcement readiness (read-only; Phase 10) ---------------------------
// Mirrors rustward-ipc EnforcementReadinessView and the embedded
// rustward-enforcement types (serde shapes).

export type RegData =
  | { type: "dword"; data: number }
  | { type: "sz"; data: string }
  | { type: "multi_sz"; data: string[] }
  | { type: "other"; data: { reg_type: number; bytes: number } };

export interface ValueRef {
  key: string;
  name: string;
}

export type NameStatus = "documented" | "unresolved";

export interface PolicyListView {
  name: string;
  allow: boolean;
  layer: "instance_id" | "device_id" | "setup_class";
  enabled: number | null;
  entries: string[];
  name_status: NameStatus;
  layout_status: NameStatus;
}

export interface PolicyFlagView {
  name: string;
  value: number | null;
  name_status: NameStatus;
}

export type LayeringSupport =
  | { status: "supported" }
  | { status: "not_supported"; reason: string; reason_tr?: string }
  | { status: "unresolved"; reason: string; reason_tr?: string };

export type PlanPresence =
  | { state: "not_applied" }
  | { state: "partial"; matching: number; missing: number; different: number }
  | { state: "policy_values_present" };

export interface PolicyInspection {
  captured_ms: number;
  key_present: boolean;
  layered: PolicyFlagView;
  deny_unspecified: PolicyFlagView;
  lists: PolicyListView[];
  retroactive: PolicyFlagView[];
  unrecognised: [ValueRef, RegData][];
  os: {
    is_windows: boolean;
    major: number | null;
    minor: number | null;
    build: number | null;
    ubr: number | null;
    product_type: number | null;
  };
  edition_supported: boolean | null;
  layering: LayeringSupport;
  conflicts: PolicyConflict[];
  plan_presence: PlanPresence | null;
  read_errors: string[];
}

export type PolicyConflict =
  | { kind: "existing_deny_unspecified" }
  | { kind: "retroactive_flag"; value: string }
  | { kind: "list_index_collision"; list: string; index: number; existing: string; planned: string }
  | { kind: "deny_overlaps_allow"; deny_list: string; id: string }
  | { kind: "invalid_planned_value"; detail: string };

export interface PlannedChange {
  hive: string;
  key: string;
  value_name: string;
  value_type: string;
  data: string;
  purpose: string;
  confirmed_against_documentation: boolean;
}

export interface TextTrEn {
  tr: string;
  en: string;
}

export interface GateView {
  code: string;
  status: "met" | "not_met" | "unknown";
  detail: string;
}

export type InstallOutcome =
  | { outcome: "allowed"; rule: { layer: string; list: string; entry: string } }
  | { outcome: "prevented"; rule: { layer: string; list: string; entry: string } }
  | { outcome: "not_restricted" };

export type InstalledFinding =
  | "denied_but_installed"
  | "denied_not_installed"
  | "allowed"
  | "internal_disk_protected"
  | "internal_disk_unprotected"
  | "attachment_unknown"
  | "allowed_but_plan_prevents"
  | "denied_but_plan_allows";

export interface AssessedDevice {
  instance_id: string;
  name: string;
  attachment: "usb_bot" | "usb_uasp" | "usb_other" | "internal" | "unknown_attachment";
  present: boolean | null;
  install_state: "installed" | "not_installed" | "unknown";
  simulated_verdict: string;
  planned_new_install: InstallOutcome;
  remains_accessible_after_activation: boolean;
  finding: InstalledFinding;
  remediation: TextTrEn[];
}

export interface InstalledAssessment {
  sanitized: boolean;
  devices: AssessedDevice[];
  summary: {
    assessed: number;
    denied_but_installed: number;
    denied_not_installed: number;
    allowed: number;
    internal_protected: number;
    internal_unprotected: number;
    needs_review: number;
    plan_disagreements: number;
  };
  limitations: TextTrEn[];
  manual_only: boolean;
}

export interface EnforcementReadinessView {
  actual_enforcement: {
    state: string;
    label_tr: string;
    label_en: string;
    verified_protection: boolean;
    activation_available: boolean;
  };
  inspection_source: "windows_registry_read_only" | "fixture" | "unavailable";
  inspection: PolicyInspection | null;
  inspection_error: string | null;
  plan_fingerprint: string;
  planned_changes: PlannedChange[];
  conflicts: PolicyConflict[];
  gates: GateView[];
  required_permissions: TextTrEn[];
  recovery: {
    steps: { order: number; en: string; tr: string }[];
    rollback_modelled_exact: boolean;
    forward_operations: number;
    rollback_operations: number;
    suspend_operations: number;
  };
  installed: InstalledAssessment;
}

// ---- Real Windows enforcement observation (read-only) ----------------------
// Mirrors rustward-enforcement observer/checklist and rustward-ipc views.

export type ObservedState =
  | "SIMULATED_DENY"
  | "NO_WINDOWS_RESTRICTION"
  | "WINDOWS_RULE_CONFIGURED"
  | "WINDOWS_INSTALL_DENIED"
  | "WINDOWS_ACCESS_NOT_VERIFIED"
  | "STATUS_UNKNOWN"
  | "POLICY_MISMATCH";

export type EvidenceLevel = "none" | "policy_only" | "install_denied";

export interface MatchedRuleView {
  layer: string;
  list: string;
  entry: string;
}

export type WindowsInstallOutcome =
  | { outcome: "allowed"; rule: MatchedRuleView }
  | { outcome: "prevented"; rule: MatchedRuleView }
  | { outcome: "not_restricted" };

export interface HistoricalDenial {
  observed_ms: number;
  problem_code: number;
  rule_entry: string;
}

export interface ObservedDevice {
  instance_id: string;
  name: string;
  vid_pid: string | null;
  reported_vendor: string | null;
  reported_product: string | null;
  hardware_id: string | null;
  rustward_verdict: string;
  rustward_reason: string;
  windows_rule: WindowsInstallOutcome;
  present: boolean | null;
  problem_code: number | null;
  driver_installed: boolean | null;
  states: ObservedState[];
  evidence: EvidenceLevel;
  label_rustward_tr: string;
  label_policy_tr: string;
  label_status_tr: string;
  explanation_tr: string;
  history: HistoricalDenial | null;
  /** Phase 6 assessment (absent from older services). */
  assessment?: DeviceAssessment | null;
}

/** Phase 6 result categories. */
export type AssessmentCategory =
  | "ALLOW_CANDIDATE"
  | "DENY_CANDIDATE"
  | "UNVERIFIED_IDENTITY"
  | "UNSUPPORTED_DEVICE"
  | "OUT_OF_SCOPE"
  | "WINDOWS_DENIAL_VERIFIED"
  | "ENFORCEMENT_NOT_ACTIVE";

export type IdentityConfidence =
  | "corroborated"
  | "single_source"
  | "ambiguous"
  | "conflicting"
  | "generic"
  | "missing"
  | "not_evaluated";

export interface IdentitySignal {
  source: string;
  value: string;
  brands: string[];
  strength: string;
}

export interface DeviceAssessment {
  policy_category: AssessmentCategory;
  enforcement_category: AssessmentCategory | null;
  identity: IdentityConfidence;
  reported_brand: string | null;
  /** Always false: nothing a USB device reports is authenticated. */
  authenticated: boolean;
  signals: IdentitySignal[];
  present: boolean | null;
  previously_installed: boolean;
  summary_tr: string;
  summary_en: string;
}

export interface ObservedDeviceView {
  device_key: string;
  /** Latest audit event recorded for this device. */
  last_event_kind?: string | null;
  last_event_ms?: number | null;
  observed: ObservedDevice;
}

export interface EnforcementObservationView {
  policy_source: string;
  policy_error: string | null;
  policy_captured_ms: number;
  policy_key_present: boolean;
  windows_restrictions_configured: boolean;
  inventory_collected_unix_seconds: number | null;
  devices: ObservedDeviceView[];
  newly_observed_denials: string[];
  rustward_applies_nothing: boolean;
  /** Removable Storage Access policy (class-wide; absent from older services). */
  removable_storage?: RemovableStorageState;
}

export interface RemovableStorageState {
  configured: boolean;
  deny_all: boolean;
  disks_deny_read: boolean;
  disks_deny_write: boolean;
  disks_deny_execute: boolean;
  other_classes: string[];
}

export interface PolicyChecklist {
  device_name: string;
  vid_pid: string | null;
  hardware_id: string;
  policy_name_en: string;
  policy_name_tr: string;
  policy_path_en: string;
  policy_path_tr: string;
  retroactive: boolean;
  device_installed: boolean;
  existing: string[];
  expected_registry: string[];
  affected_devices: string[];
  steps: string[];
  risks: string[];
  rollback: string[];
  verification: string[];
}

export interface PolicyChecklistView {
  checklist: PolicyChecklist;
  text: string;
}

// ---- Administrator-guided enforcement session ------------------------------

export interface LadderStepView {
  code:
    | "policy_simulation"
    | "windows_restriction_configured"
    | "windows_install_denied"
    | "read_write_verified"
    | "protection_inactive"
    | "enforcement_error"
    | "recovery_required";
  label_tr: string;
  label_en: string;
  status: "yes" | "no" | "not_verified";
}

export interface SessionView {
  session_id: string;
  prepared_ms: number;
  prepared_by: string;
  device_key: string;
  device_name: string;
  hardware_id: string;
  retroactive: boolean;
  baseline: string[];
  expected_lines: string[];
  /** `device_deny` (one device) or `default_deny_profile`. */
  kind?: string;
  /** Administrator checklist (default-deny profile only). */
  checklist_text?: string | null;
  last_verification: string | null;
  last_verification_ms: number | null;
}

export interface EnforcementSessionView {
  state: LadderStepView["code"];
  state_tr: string;
  state_en: string;
  ladder: LadderStepView[];
  session: SessionView | null;
  differences: string[];
  policy_error: string | null;
  target: ObservedDeviceView | null;
  automated_apply_available: boolean;
  automated_apply_blocker: { tr: string; en: string };
}

export type ConfiguredIntention = "allowed" | "explicit_deny" | "disabled";
export type IdentityCoverage = "verified" | "partial" | "unknown";
export type WindowsPolicyStatus = "applied" | "not_applied" | "conflict" | "unsupported";
export type DeviceOutcomeStatus = "accessible" | "installation_denied" | "driver_recovery_needed" | "not_connected" | "unknown";

export interface ManufacturerPolicyView {
  brand_id: string;
  display_name: string;
  configured_intention: ConfiguredIntention;
  identity_coverage: IdentityCoverage;
  hardware_ids: string[];
  windows_policy: WindowsPolicyStatus;
  device_outcome: DeviceOutcomeStatus;
  notes?: string | null;
}

export interface CompiledWindowsPolicy {
  revision_id: string;
  deny_hardware_ids: string[];
  allow_hardware_ids: string[];
  retroactive: boolean;
  fingerprint: string;
}

export interface ObservedWindowsPolicy {
  active_denies: string[];
  active_allows: string[];
  retroactive: boolean;
  raw_gpo_present: boolean;
  fingerprint: string;
}

export interface CompoundPolicyDiff {
  added_denies: string[];
  removed_denies: string[];
  retained_denies: string[];
  is_synchronized: boolean;
}

export interface CompoundPolicyPlanView {
  revision_id: string;
  policy_version: number;
  manufacturers: ManufacturerPolicyView[];
  compiled: CompiledWindowsPolicy;
  observed: ObservedWindowsPolicy;
  diff: CompoundPolicyDiff;
  safety_checklist: string[];
  can_apply: boolean;
  blocker_reason?: TextTrEn | null;
  is_applied: boolean;
}
