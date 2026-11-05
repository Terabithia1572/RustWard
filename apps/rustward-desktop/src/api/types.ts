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
  | { type: "get_settings" }
  | { type: "run_simulation" }
  | { type: "add_manufacturer"; input: ManufacturerInput; allowed: boolean; expected_policy_version: number }
  | { type: "update_manufacturer"; id: string; input: ManufacturerInput; expected_policy_version: number }
  | { type: "remove_manufacturer"; id: string; expected_policy_version: number }
  | { type: "set_manufacturer_allowed"; id: string; allowed: boolean; expected_policy_version: number }
  | { type: "set_rule_enabled"; id: string; enabled: boolean; expected_policy_version: number }
  | { type: "update_settings"; settings: SettingsView }
  | { type: "export_events"; query: EventQuery; format: ExportFormat }
  | { type: "apply_retention" }
  | { type: "create_backup" }
  | { type: "refresh_inventory" }
  | { type: "load_synthetic_inventory" };

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
  "get_settings",
  "run_simulation",
  "add_manufacturer",
  "update_manufacturer",
  "remove_manufacturer",
  "set_manufacturer_allowed",
  "set_rule_enabled",
  "update_settings",
  "export_events",
  "apply_retention",
  "create_backup",
  "refresh_inventory",
  "load_synthetic_inventory",
];

/** Requests that require an elevated administrator (server-enforced). */
export const PRIVILEGED: ReadonlySet<RequestType> = new Set<RequestType>([
  "add_manufacturer",
  "update_manufacturer",
  "remove_manufacturer",
  "set_manufacturer_allowed",
  "set_rule_enabled",
  "update_settings",
  "export_events",
  "apply_retention",
  "create_backup",
  "refresh_inventory",
  "load_synthetic_inventory",
]);

export interface ServiceStatusView {
  backend: "dev_backend" | "windows_service" | string;
  state: "running" | "degraded" | "unreachable" | string;
  healthy: boolean;
  started_ms: number | null;
  last_refresh_ms: number | null;
  message: string;
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
  synthetic_data_present: boolean;
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
  enforceable: boolean;
  issues: string[];
}

export interface ManufacturersView {
  workstation_id: string;
  policy_version: number;
  catalog_version: string;
  mode: "dry_run" | "enforce" | string;
  manufacturers: ManufacturerView[];
  warnings: string[];
  reserved_generic_vendors: string[];
}

export interface PolicyChangeView {
  id: number;
  utc_ms: number;
  actor: string;
  action: string;
  brand_id: string;
  summary: string;
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
  policy: { valid: boolean; errors: string[]; warnings: string[] };
  enforcement: {
    state: string;
    label_tr: string;
    label_en: string;
    provider_id: string;
    capabilities: CapabilityReport;
    planned_changes: number;
    preconditions: Precondition[];
    risks: string[];
    enforcement_gaps: string[];
  };
  unsupported_features: string[];
  pending_native_tests: string[];
  app_version: string;
}

export interface MutationView {
  policy_version: number;
  catalog_version: string;
  summary: string;
  warnings: string[];
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
}

export type ResponseBody =
  | { type: "dashboard"; data: DashboardView }
  | { type: "devices"; data: DeviceView[] }
  | { type: "manufacturers"; data: ManufacturersView }
  | { type: "explanation"; data: ExplanationView }
  | { type: "events"; data: EventView[] }
  | { type: "policy_changes"; data: PolicyChangeView[] }
  | { type: "diagnostics"; data: DiagnosticsView }
  | { type: "settings"; data: SettingsView }
  | { type: "simulation"; data: SimulationView }
  | { type: "mutation"; data: MutationView }
  | { type: "export"; data: ExportView }
  | { type: "done"; data: { message: string } };

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
