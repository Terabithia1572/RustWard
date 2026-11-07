import type {
  BackupView,
  DashboardView,
  DeviceView,
  DiagnosticsView,
  EnforcementObservationView,
  EnforcementSessionView,
  EnforcementReadinessView,
  PolicyChecklistView,
  ErrorCode,
  EventQuery,
  EventView,
  ExplanationView,
  ExportFormat,
  ExportView,
  ManufacturerInput,
  ManufacturersView,
  MutationView,
  PolicyChangeView,
  Request,
  RestorePreviewView,
  ResponseBody,
  SettingsView,
  SimulationView,
} from "./types";

/** Error returned by the backend (validated server-side). */
export class ApiError extends Error {
  readonly code: ErrorCode | "client";
  /** Turkish message from the backend, when it has one. */
  readonly messageTr: string | undefined;
  constructor(code: ErrorCode | "client", message: string, messageTr?: string) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.messageTr = messageTr;
  }
}

/** Transport to the RustWard backend. The UI never touches the database. */
export interface Backend {
  call(request: Request): Promise<ResponseBody>;
}

function isIpcError(e: unknown): e is { code: ErrorCode; message: string; message_tr?: unknown } {
  return typeof e === "object" && e !== null && "code" in e && "message" in e &&
    typeof (e as { code: unknown }).code === "string" && typeof (e as { message: unknown }).message === "string";
}

/** Normalize anything thrown by a backend into an ApiError. */
export function toApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  if (isIpcError(e)) return new ApiError(e.code, e.message, typeof e.message_tr === "string" ? e.message_tr : undefined);
  if (e instanceof Error) return new ApiError("client", e.message);
  return new ApiError("client", String(e));
}

type Invoke = (cmd: string, args: Record<string, unknown>) => Promise<unknown>;

/** Backend using the Tauri command `ipc_call` (the only allowed command). */
export function tauriBackend(invoke: Invoke): Backend {
  return {
    async call(request) {
      try {
        return (await invoke("ipc_call", { request })) as ResponseBody;
      } catch (e) {
        throw toApiError(e);
      }
    },
  };
}

type DataOf = { [K in ResponseBody["type"]]: Extract<ResponseBody, { type: K }>["data"] };

function expect<T extends ResponseBody["type"]>(r: ResponseBody, type: T): DataOf[T] {
  if (r.type !== type) {
    throw new ApiError("client", `unexpected response '${r.type}', expected '${type}'`);
  }
  return r.data as DataOf[T];
}

/** Round-trip timing of one request, as seen by the UI. */
export interface IpcTiming {
  type: Request["type"];
  ms: number;
  ok: boolean;
}

const now = (): number => (typeof performance !== "undefined" ? performance.now() : Date.now());

/** Typed API on top of a backend. */
export class Api {
  /** Most recent round trips (newest last), for the Diagnostics page. */
  readonly timings: IpcTiming[] = [];

  constructor(private readonly backend: Backend) {}

  private record(type: Request["type"], start: number, ok: boolean) {
    this.timings.push({ type, ms: Math.round(now() - start), ok });
    if (this.timings.length > 50) this.timings.shift();
  }

  private async call(request: Request): Promise<ResponseBody> {
    const start = now();
    try {
      const r = await this.backend.call(request);
      this.record(request.type, start, true);
      return r;
    } catch (e) {
      this.record(request.type, start, false);
      throw toApiError(e);
    }
  }

  async dashboard(): Promise<DashboardView> {
    return expect(await this.call({ type: "get_dashboard" }), "dashboard");
  }
  async devices(includeAbsent: boolean): Promise<DeviceView[]> {
    return expect(await this.call({ type: "list_devices", include_absent: includeAbsent }), "devices");
  }
  async blocked(limit = 500): Promise<DeviceView[]> {
    return expect(await this.call({ type: "list_blocked", limit }), "devices");
  }
  async explain(deviceKey: string): Promise<ExplanationView> {
    return expect(await this.call({ type: "explain_device", device_key: deviceKey }), "explanation");
  }
  async manufacturers(): Promise<ManufacturersView> {
    return expect(await this.call({ type: "list_manufacturers" }), "manufacturers");
  }
  async policyChanges(limit = 50): Promise<PolicyChangeView[]> {
    return expect(await this.call({ type: "list_policy_changes", limit }), "policy_changes");
  }
  async events(query: EventQuery): Promise<EventView[]> {
    return expect(await this.call({ type: "list_events", query }), "events");
  }
  async diagnostics(): Promise<DiagnosticsView> {
    return expect(await this.call({ type: "get_diagnostics" }), "diagnostics");
  }
  async enforcementReadiness(): Promise<EnforcementReadinessView> {
    return expect(await this.call({ type: "get_enforcement_readiness" }), "enforcement_readiness");
  }
  async enforcementObservation(): Promise<EnforcementObservationView> {
    return expect(await this.call({ type: "get_enforcement_observation" }), "enforcement_observation");
  }
  async policyChecklist(deviceKey: string, retroactive: boolean): Promise<PolicyChecklistView> {
    return expect(
      await this.call({ type: "get_policy_checklist", device_key: deviceKey, retroactive }),
      "policy_checklist",
    );
  }
  async enforcementSession(): Promise<EnforcementSessionView> {
    return expect(await this.call({ type: "get_enforcement_session" }), "enforcement_session");
  }
  async prepareSession(deviceKey: string, retroactive: boolean): Promise<EnforcementSessionView> {
    return expect(
      await this.call({ type: "prepare_enforcement_session", device_key: deviceKey, retroactive }),
      "enforcement_session",
    );
  }
  async verifyApplied(sessionId: string): Promise<EnforcementSessionView> {
    return expect(await this.call({ type: "verify_enforcement_applied", session_id: sessionId }), "enforcement_session");
  }
  async verifyRollback(sessionId: string): Promise<EnforcementSessionView> {
    return expect(await this.call({ type: "verify_enforcement_rollback", session_id: sessionId }), "enforcement_session");
  }
  async cancelSession(sessionId: string): Promise<EnforcementSessionView> {
    return expect(await this.call({ type: "cancel_enforcement_session", session_id: sessionId }), "enforcement_session");
  }
  async settings(): Promise<SettingsView> {
    return expect(await this.call({ type: "get_settings" }), "settings");
  }
  async simulate(): Promise<SimulationView> {
    return expect(await this.call({ type: "run_simulation" }), "simulation");
  }
  async addManufacturer(input: ManufacturerInput, allowed: boolean, version: number): Promise<MutationView> {
    return expect(
      await this.call({ type: "add_manufacturer", input, allowed, expected_policy_version: version }),
      "mutation",
    );
  }
  async updateManufacturer(id: string, input: ManufacturerInput, version: number): Promise<MutationView> {
    return expect(
      await this.call({ type: "update_manufacturer", id, input, expected_policy_version: version }),
      "mutation",
    );
  }
  async removeManufacturer(id: string, version: number): Promise<MutationView> {
    return expect(await this.call({ type: "remove_manufacturer", id, expected_policy_version: version }), "mutation");
  }
  async setAllowed(id: string, allowed: boolean, version: number): Promise<MutationView> {
    return expect(
      await this.call({ type: "set_manufacturer_allowed", id, allowed, expected_policy_version: version }),
      "mutation",
    );
  }
  async setEnabled(id: string, enabled: boolean, version: number): Promise<MutationView> {
    return expect(
      await this.call({ type: "set_rule_enabled", id, enabled, expected_policy_version: version }),
      "mutation",
    );
  }
  async saveSettings(settings: SettingsView): Promise<SettingsView> {
    return expect(await this.call({ type: "update_settings", settings }), "settings");
  }
  async exportEvents(query: EventQuery, format: ExportFormat): Promise<ExportView> {
    return expect(await this.call({ type: "export_events", query, format }), "export");
  }
  async setWorkstationId(workstationId: string, version: number): Promise<MutationView> {
    return expect(
      await this.call({ type: "set_workstation_id", workstation_id: workstationId, expected_policy_version: version }),
      "mutation",
    );
  }
  async backups(): Promise<BackupView[]> {
    return expect(await this.call({ type: "list_backups" }), "backups");
  }
  async prepareRestore(fileName: string): Promise<RestorePreviewView> {
    return expect(await this.call({ type: "prepare_restore", file_name: fileName }), "restore_preview");
  }
  async applyRestore(restoreId: string, version: number): Promise<MutationView> {
    return expect(
      await this.call({ type: "apply_restore", restore_id: restoreId, expected_policy_version: version }),
      "mutation",
    );
  }
  async action(
    type: "apply_retention" | "create_backup" | "refresh_inventory" | "load_synthetic_inventory",
  ): Promise<{ message: string; message_tr?: string }> {
    return expect(await this.call({ type }), "done");
  }
}
