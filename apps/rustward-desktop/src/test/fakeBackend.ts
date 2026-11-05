// In-memory fake used ONLY by unit tests. It mimics the service contract
// closely enough to exercise the UI (version checks, error codes); it is never
// bundled into the application and never shown as real data.
import type { Backend } from "../api/client";
import type {
  DashboardView,
  DeviceView,
  DiagnosticsView,
  EventView,
  ManufacturerView,
  Request,
  ResponseBody,
  SettingsView,
} from "../api/types";

export const BANNER_TR = "Koruma henüz gerçek Windows ortamında doğrulanmadı.";

export function device(over: Partial<DeviceView> = {}): DeviceView {
  return {
    device_key: "k-deny",
    display_id: "USBSTOR\\DISK&VEN_EXAMPLEX&****",
    category: "usb_storage_disk",
    storage_type: "Disk",
    vendor: "EXAMPLEX",
    product: "SYNTH DRIVE",
    usb_vid_pid: "FFFF:0001",
    vendor_level_id: "USBSTOR\\DiskEXAMPLEX",
    friendly_name: null,
    matched_brand: null,
    present: true,
    synthetic: true,
    first_seen_ms: 1_700_000_000_000,
    last_seen_ms: 1_700_000_000_000,
    simulated_decision: "deny",
    reason: "unknown_manufacturer",
    policy_version: 1,
    enforcement_state: "simulated",
    enforcement_verified: false,
    ...over,
  };
}

export function event(over: Partial<EventView> = {}): EventView {
  return {
    id: 1,
    utc_ms: 1_700_000_000_000,
    severity: "warning",
    kind: "simulated_deny",
    device_key: "k-deny",
    message: "SYNTHETIC device would be denied (simulation)",
    simulated: true,
    enforcement_state: "simulated",
    policy_version: 1,
    ...over,
  };
}

function manufacturer(over: Partial<ManufacturerView> = {}): ManufacturerView {
  return {
    id: "examplex",
    display_name: "ExampleX (synthetic)",
    aliases: [],
    identifiers: [
      {
        kind: "inquiry_vendor",
        value: "EXAMPLEX",
        verification: "unverified",
        source: "synthetic test fixture",
        enforceable: true,
        vendor_level_ids: ["USBSTOR\\DiskEXAMPLEX", "SCSI\\DiskEXAMPLEX"],
      },
    ],
    notes: null,
    allowed: true,
    enabled: true,
    enforceable: true,
    issues: [],
    ...over,
  };
}

export interface FakeState {
  version: number;
  manufacturers: ManufacturerView[];
  settings: SettingsView;
  events: EventView[];
  devices: DeviceView[];
  calls: Request[];
  /** Force the next call to fail with this IPC error. */
  failNext: { code: string; message: string } | null;
}

export function fakeBackend(init: Partial<FakeState> = {}): { backend: Backend; state: FakeState } {
  const state: FakeState = {
    version: 3,
    manufacturers: [manufacturer()],
    settings: { theme: "dark", language: "tr", notifications_enabled: true, audit_retention_days: 365, inventory_refresh_seconds: 30 },
    events: [event()],
    devices: [device(), device({ device_key: "k-allow", simulated_decision: "allow", reason: "brand_allowed", matched_brand: "ExampleX (synthetic)" })],
    calls: [],
    failNext: null,
    ...init,
  };

  const mutation = (summary: string): ResponseBody => {
    state.version += 1;
    return { type: "mutation", data: { policy_version: state.version, catalog_version: `test+local.${state.version}`, summary, warnings: [] } };
  };
  const checkVersion = (v: number) => {
    if (v !== state.version) throw { code: "conflict", message: `policy changed (expected ${v}, current ${state.version})` };
  };
  const find = (id: string) => {
    const m = state.manufacturers.find((x) => x.id === id);
    if (!m) throw { code: "not_found", message: `manufacturer '${id}' not found` };
    return m;
  };

  const dashboard = (): DashboardView => ({
    enforcement_state: "simulated",
    enforcement_label_tr: "Simülasyon (uygulanmıyor)",
    enforcement_label_en: "Simulation (not enforced)",
    protection_verified: false,
    not_validated_banner: BANNER_TR,
    service: { backend: "dev_backend", state: "running", healthy: true, started_ms: 1, last_refresh_ms: 2, message: "ok" },
    workstation_id: "PC-TEST",
    policy_version: state.version,
    catalog_version: "test",
    last_policy_update_ms: 1_700_000_000_000,
    allowed_manufacturers: state.manufacturers.filter((m) => m.allowed && m.enabled).length,
    connected_storage: state.devices.length,
    recent_denied: state.devices.filter((d) => d.simulated_decision === "deny"),
    recent_events: state.events,
    warnings: [],
    synthetic_data_present: true,
  });

  const diagnostics = (): DiagnosticsView => ({
    service: dashboard().service,
    database: { schema_version: 1, integrity_ok: true, chain_status: "intact", chain_ok: true, location_kind: "development" },
    windows_adapter: { platform: "linux", live_inventory_available: false, last_error: null },
    policy: { valid: true, errors: [], warnings: [] },
    enforcement: {
      state: "simulated",
      label_tr: "Simülasyon (uygulanmıyor)",
      label_en: "Simulation (not enforced)",
      provider_id: "simulation_only",
      capabilities: {
        provider_id: "simulation_only",
        pre_access_blocking: "not_implemented",
        brand_allowlisting: "designed_not_verified",
        previously_installed_devices: "unsupported",
        persistence: "not_implemented",
        self_verification: "not_implemented",
        activation_available: false,
      },
      planned_changes: 0,
      preconditions: [{ id: "native", en: "Native validation", tr: "Yerel doğrulama", status: "not_met" }],
      risks: ["risk-a"],
      enforcement_gaps: ["gap-a"],
    },
    unsupported_features: ["desktop notifications"],
    pending_native_tests: ["native SetupAPI enumeration"],
    app_version: "0.0.0-test",
  });

  const handle = (r: Request): ResponseBody => {
    switch (r.type) {
      case "get_dashboard":
        return { type: "dashboard", data: dashboard() };
      case "list_devices":
        return { type: "devices", data: state.devices };
      case "list_blocked":
        return { type: "devices", data: state.devices.filter((d) => d.simulated_decision === "deny") };
      case "explain_device": {
        const d = state.devices.find((x) => x.device_key === r.device_key);
        if (!d) throw { code: "not_found", message: "device not found" };
        return {
          type: "explanation",
          data: {
            device: d,
            explanation: {
              summary_tr: "SİMÜLE RET: üretici katalogda yok.",
              summary_en: "SIMULATED DENY: manufacturer not in catalog.",
              steps: [{ stage: "identity", tr: "Kimlik okundu", en: "Identity read" }],
            },
          },
        };
      }
      case "list_manufacturers":
        return {
          type: "manufacturers",
          data: {
            workstation_id: "PC-TEST",
            policy_version: state.version,
            catalog_version: "test",
            mode: "dry_run",
            manufacturers: state.manufacturers,
            warnings: [],
            reserved_generic_vendors: ["GENERIC"],
          },
        };
      case "list_policy_changes":
        return { type: "policy_changes", data: [] };
      case "list_events": {
        const q = r.query;
        let ev = state.events;
        if (q.text) ev = ev.filter((e) => e.message.toLowerCase().includes(q.text!.toLowerCase()));
        if (q.simulated !== null && q.simulated !== undefined) ev = ev.filter((e) => e.simulated === q.simulated);
        return { type: "events", data: ev };
      }
      case "get_diagnostics":
        return { type: "diagnostics", data: diagnostics() };
      case "get_settings":
        return { type: "settings", data: state.settings };
      case "run_simulation":
        return {
          type: "simulation",
          data: { evaluated: 2, simulated_allow: 1, simulated_deny: 1, not_applicable: 0, enforcement_gaps: [], notice: "Simulation only." },
        };
      case "add_manufacturer": {
        checkVersion(r.expected_policy_version);
        const id = r.input.id ?? r.input.display_name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        if (state.manufacturers.some((m) => m.id === id)) throw { code: "conflict", message: `duplicate id '${id}'` };
        state.manufacturers = [
          ...state.manufacturers,
          manufacturer({ id, display_name: r.input.display_name, identifiers: [], enforceable: false, allowed: r.allowed }),
        ];
        return mutation(`added ${id}`);
      }
      case "update_manufacturer": {
        checkVersion(r.expected_policy_version);
        const m = find(r.id);
        m.display_name = r.input.display_name;
        return mutation(`updated ${r.id}`);
      }
      case "remove_manufacturer":
        checkVersion(r.expected_policy_version);
        find(r.id);
        state.manufacturers = state.manufacturers.filter((m) => m.id !== r.id);
        return mutation(`removed ${r.id}`);
      case "set_manufacturer_allowed":
        checkVersion(r.expected_policy_version);
        find(r.id).allowed = r.allowed;
        return mutation(`allowed=${r.allowed}`);
      case "set_rule_enabled":
        checkVersion(r.expected_policy_version);
        find(r.id).enabled = r.enabled;
        return mutation(`enabled=${r.enabled}`);
      case "update_settings":
        state.settings = r.settings;
        return { type: "settings", data: state.settings };
      case "export_events":
        return {
          type: "export",
          data: { file_name: `events.${r.format}`, mime: r.format === "csv" ? "text/csv" : "application/json", content: "x", count: state.events.length },
        };
      case "apply_retention":
      case "create_backup":
      case "refresh_inventory":
      case "load_synthetic_inventory":
        return { type: "done", data: { message: `${r.type} done` } };
    }
  };

  const backend: Backend = {
    call(request) {
      state.calls.push(request);
      if (state.failNext) {
        const f = state.failNext;
        state.failNext = null;
        return Promise.reject(f);
      }
      try {
        return Promise.resolve(handle(request));
      } catch (e) {
        return Promise.reject(e);
      }
    },
  };
  return { backend, state };
}
