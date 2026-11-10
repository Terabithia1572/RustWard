// In-memory fake used ONLY by unit tests. It mimics the service contract
// closely enough to exercise the UI (version checks, error codes); it is never
// bundled into the application and never shown as real data.
import type { Backend } from "../api/client";
import type {
  BackupView,
  DashboardView,
  DeviceView,
  DiagnosticsView,
  EnforcementObservationView,
  EnforcementReadinessView,
  EnforcementSessionView,
  LadderStepView,
  SessionView,
  EventView,
  ObservedDevice,
  ManufacturerView,
  Request,
  ResponseBody,
  SettingsView,
  WindowsProtectionView,
  DeviceAssessment,
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
    message_tr: "SENTETİK cihaz reddedilirdi (simülasyon)",
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
    denied: false,
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
  workstationId: string;
  backups: BackupView[];
  preparedRestore: string | null;
  calls: Request[];
  /** Force the next call (optionally only of type `only`) to fail with this IPC error. */
  failNext: { code: string; message: string; only?: Request["type"] } | null;
  /** Readiness view includes a policy inspection (otherwise "unavailable"). */
  readinessInspection: boolean;
  /** Windows observation returned by get_enforcement_observation. */
  observation: EnforcementObservationView;
  /** Guided enforcement session state. */
  session: EnforcementSessionView;
}

const LADDER: [LadderStepView["code"], string, string][] = [
  ["policy_simulation", "Politika simülasyonu", "Policy simulation"],
  ["windows_restriction_configured", "Windows kısıtlaması yapılandırıldı", "Windows restriction configured"],
  ["windows_install_denied", "Windows cihaz kurulumu engellendi", "Windows device installation denied"],
  ["read_write_verified", "Okuma/yazma erişimi doğrulandı", "Read/write access verified"],
  ["protection_inactive", "Koruma etkin değil", "Protection inactive"],
  ["enforcement_error", "Uygulama hatası", "Enforcement error"],
  ["recovery_required", "Kurtarma gerekli", "Recovery required"],
];

/** Guided session view in a given state (mirrors the service's ladder). */
export function sessionView(state: LadderStepView["code"], session: SessionView | null = null): EnforcementSessionView {
  const on: Record<string, boolean> = {
    policy_simulation: true,
    windows_restriction_configured: state === "windows_restriction_configured" || state === "windows_install_denied",
    windows_install_denied: state === "windows_install_denied",
    protection_inactive: state === "policy_simulation" || state === "protection_inactive",
    enforcement_error: state === "enforcement_error",
    recovery_required: state === "recovery_required",
  };
  return {
    state,
    state_tr: `Durum: ${state}`,
    state_en: `State: ${state}`,
    ladder: LADDER.map(([code, tr, en]) => ({
      code,
      label_tr: tr,
      label_en: en,
      status: code === "read_write_verified" ? "not_verified" : on[code] ? "yes" : "no",
    })),
    session,
    differences: [],
    policy_error: null,
    target: null,
    automated_apply_available: false,
    automated_apply_blocker: {
      tr: "Otomatik uygulama bu sürümde kullanılamaz: RustWard Windows Grup İlkesine veya kayıt defterine yazmaz.",
      en: "Automated application is not available in this build.",
    },
  };
}

/** Observed device as the VM showed it after the rollback (accessible). */
export function observed(over: Partial<ObservedDevice> = {}): ObservedDevice {
  return {
    instance_id: "USBSTOR\\DISK&VEN_KINGSTON&****",
    name: "Kingston DataTraveler 3.0 USB Device",
    vid_pid: "0951:1666",
    reported_vendor: "Kingston",
    reported_product: "DataTraveler_3.0",
    hardware_id: "USBSTOR\\DiskKingstonDataTraveler_3.0____",
    rustward_verdict: "deny",
    rustward_reason: "brand_not_allowed",
    windows_rule: { outcome: "not_restricted" },
    present: true,
    problem_code: null,
    driver_installed: true,
    states: ["SIMULATED_DENY", "NO_WINDOWS_RESTRICTION"],
    evidence: "none",
    label_rustward_tr: "Simülasyonda ret",
    label_policy_tr: "Kural uygulanmamış",
    label_status_tr: "Erişilebilir (sürücü kurulu)",
    explanation_tr: "RustWard kararı yalnızca simülasyondur; Windows bu cihazı engellemiyor.",
    history: null,
    assessment: assessment(),
    ...over,
  };
}

/** Phase 6 assessment of the observed Kingston (deny candidate, not enforced). */
export function assessment(over: Partial<DeviceAssessment> = {}): DeviceAssessment {
  return {
    policy_category: "DENY_CANDIDATE",
    enforcement_category: "ENFORCEMENT_NOT_ACTIVE",
    identity: "corroborated",
    reported_brand: "kingston",
    authenticated: false,
    signals: [
      { source: "scsi_inquiry_vendor", value: "Kingston", brands: ["kingston"], strength: "enforceable" },
      { source: "usb_vid", value: "0951", brands: ["kingston"], strength: "corroborating" },
    ],
    present: true,
    previously_installed: true,
    summary_tr: "Ret adayı: politika bu cihazı reddediyor. Windows bu cihaz için engel uygulamıyor (koruma etkin değil).",
    summary_en: "Deny candidate: the policy denies this device. Windows enforces no denial for this device (protection not active).",
    ...over,
  };
}

/** The observed Kingston while Windows denied its installation. */
export function deniedKingston(): ObservedDevice {
  return observed({
    windows_rule: { outcome: "prevented", rule: { layer: "device_id", list: "DenyDeviceIDs", entry: "USBSTOR\\DiskKingstonDataTraveler_3.0____" } },
    problem_code: 28,
    driver_installed: false,
    states: ["SIMULATED_DENY", "WINDOWS_INSTALL_DENIED", "WINDOWS_ACCESS_NOT_VERIFIED"],
    evidence: "install_denied",
    label_policy_tr: "Engelleme kuralı eşleşiyor (DenyDeviceIDs: USBSTOR\\DiskKingstonDataTraveler_3.0____)",
    label_status_tr: "Windows kurulumu engelledi (Kod 28)",
    explanation_tr: "Windows bu cihazın sürücü kurulumunu reddetti; disk ve birim nesnesi oluşmaz. Okuma/yazma yolları ayrıca test edilmedi.",
    assessment: assessment({
      enforcement_category: "WINDOWS_DENIAL_VERIFIED",
      previously_installed: false,
      summary_tr: "Ret adayı. Gerçek Windows kanıtı: Windows kurulumu reddetti; okuma/yazma ayrıca test edilmedi.",
    }),
  });
}

export function observation(devices: ObservedDevice[], over: Partial<EnforcementObservationView> = {}): EnforcementObservationView {
  return {
    policy_source: "windows_registry_read_only",
    policy_error: null,
    policy_captured_ms: 1_794_048_315_000,
    policy_key_present: false,
    windows_restrictions_configured: false,
    inventory_collected_unix_seconds: 1_794_048_300,
    devices: devices.map((o, i) => ({ device_key: i === 0 ? "k-deny" : `k-obs-${i}`, observed: o })),
    newly_observed_denials: [],
    rustward_applies_nothing: true,
    ...over,
  };
}

export function fakeBackend(init: Partial<FakeState> = {}): { backend: Backend; state: FakeState } {
  const state: FakeState = {
    version: 3,
    manufacturers: [manufacturer()],
    settings: { theme: "dark", language: "tr", notifications_enabled: true, audit_retention_days: 365, inventory_refresh_seconds: 30 },
    events: [event()],
    devices: [device(), device({ device_key: "k-allow", simulated_decision: "allow", reason: "brand_allowed", matched_brand: "ExampleX (synthetic)" })],
    workstationId: "PC-TEST",
    readinessInspection: true,
    session: sessionView("policy_simulation"),
    observation: observation([
      observed(),
      observed({
        instance_id: "USBSTOR\\DISK&VEN_VENDORC&****",
        name: "VendorC ProductCode USB Device",
        vid_pid: "346D:5678",
        reported_vendor: "VendorC",
        reported_product: "ProductCode",
        hardware_id: "USBSTOR\\DiskVendorC_ProductCode_____3.20",
        rustward_reason: "unknown_manufacturer",
      }),
    ]),
    backups: [
      {
        file_name: "rustward-backup-1700000000000.db",
        bytes: 40960,
        created_ms: 1_700_000_000_000,
        kind: "manual",
        policy_version: 2,
        sha256: "cd".repeat(32),
        actor: "PC-TEST\\admin",
        file_present: true,
      },
    ],
    preparedRestore: null,
    calls: [],
    failNext: null,
    ...init,
  };

  const mutation = (summary: string): ResponseBody => {
    state.version += 1;
    return { type: "mutation", data: { policy_version: state.version, catalog_version: `test+local.${state.version}`, summary, summary_tr: `TR: ${summary}`, warnings: [], warnings_tr: [] } };
  };
  const checkVersion = (v: number) => {
    if (v !== state.version) throw { code: "conflict", message: `policy changed (expected ${v}, current ${state.version})` };
  };
  const find = (id: string) => {
    const m = state.manufacturers.find((x) => x.id === id);
    if (!m) throw { code: "not_found", message: `manufacturer '${id}' not found` };
    return m;
  };

  /** Mirrors the service: protection state follows real Windows evidence only. */
  const protection = (): WindowsProtectionView => {
    const o = state.observation;
    const denied = o.devices.filter((d) => d.observed.present === true && d.observed.evidence === "install_denied");
    const names = denied.map((d) => d.observed.name).join(", ");
    const present = o.devices.filter((d) => d.observed.present === true);
    const cat = (c: string) => present.filter((d) => d.observed.assessment?.policy_category === c).length;
    const summary = {
      connected: present.length,
      allow_candidates: cat("ALLOW_CANDIDATE"),
      deny_candidates: cat("DENY_CANDIDATE"),
      unverified_identity: cat("UNVERIFIED_IDENTITY"),
      unsupported: cat("UNSUPPORTED_DEVICE"),
      windows_denied: denied.length,
      denied_by_policy_only: present.length - denied.length - cat("ALLOW_CANDIDATE"),
      disconnected: o.devices.length - present.length,
    };
    const blockers = [
      { code: "automatic_apply_blocked", kind: "blocked", tr: "Otomatik politika uygulama ENGELLİ.", en: "Automatic policy application is BLOCKED." },
      ...(o.windows_restrictions_configured
        ? []
        : [{ code: "no_windows_rule", kind: "action", tr: "Windows'ta hiçbir Aygıt Yükleme Kısıtlaması kuralı yok.", en: "No Device Installation Restriction rule exists in Windows." }]),
      { code: "manufacturer_default_deny_unverified", kind: "limitation", tr: "Üretici genelinde varsayılan ret Windows'ta doğrulanmadı.", en: "Manufacturer-wide default deny is not verified in Windows." },
      { code: "read_write_unverified", kind: "limitation", tr: "Okuma/yazma engeli doğrulanmadı.", en: "Read/write denial is not verified." },
    ];
    const mk = (st: string, tr: string, en: string, dtr: string, den: string): WindowsProtectionView => ({
      state: st,
      label_tr: tr,
      label_en: en,
      detail_tr: dtr,
      detail_en: den,
      denied_now: denied.length,
      automated_apply_available: false,
      summary,
      blockers,
    });
    if (o.policy_error) return mk("unknown", "Durum bilinmiyor", "State unknown", "Windows politikası okunamadı.", "The Windows policy could not be read.");
    if (!o.windows_restrictions_configured)
      return mk("inactive", "Windows koruması etkin değil", "Windows protection inactive", "Windows'ta hiçbir Aygıt Yükleme Kısıtlaması kuralı yapılandırılmamış.", "No Device Installation Restriction rule is configured.");
    if (denied.length === 0)
      return mk("configured_unverified", "Politika yapılandırılmış, doğrulanmadı", "Policy configured, not verified", "Gerçek bir kurulum engeli gözlenmedi.", "No real installation denial is observed.");
    const s = state.session.session;
    if (s && s.last_verification === "enforcement_session_apply_verified" && denied.some((d) => d.device_key === s.device_key))
      return mk("verified_active", "Windows koruması doğrulandı (yalnızca hedef cihaz)", "Windows protection verified (target device only)", `Gerçek Windows kanıtı: ${names}. Okuma/yazma yolları ayrıca doğrulanmadı.`, `Real Windows evidence: ${names}.`);
    return mk("denial_observed", "Windows cihaz kurulumunu engelliyor (RustWard oturumu dışında)", "Windows denies device installation (outside a RustWard session)", `Gerçek Windows kanıtı: ${names}.`, `Real Windows evidence: ${names}.`);
  };

  const dashboard = (): DashboardView => ({
    enforcement_state: "simulated",
    enforcement_label_tr: "Simülasyon (uygulanmıyor)",
    enforcement_label_en: "Simulation (not enforced)",
    protection_verified: false,
    not_validated_banner: BANNER_TR,
    service: { backend: "dev_backend", state: "running", healthy: true, started_ms: 1, last_refresh_ms: 2, message: "RustWard service running", message_tr: "RustWard hizmeti çalışıyor." },
    workstation_id: state.workstationId,
    policy_version: state.version,
    catalog_version: "test",
    last_policy_update_ms: 1_700_000_000_000,
    allowed_manufacturers: state.manufacturers.filter((m) => m.allowed && m.enabled).length,
    connected_storage: state.devices.length,
    recent_denied: state.devices.filter((d) => d.simulated_decision === "deny"),
    recent_events: state.events,
    warnings: [],
    synthetic_data_present: true,
    windows_protection: protection(),
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
    performance: {
      last_inventory_collect_ms: 412,
      last_inventory_apply_ms: 9,
      max_inventory_collect_ms: 1830,
      inventory_refreshes: 7,
      last_inventory_devices: 12,
      first_inventory_after_start_ms: 640,
      last_observation_ms: 21,
      last_verification_ms: 455,
    },
    app_version: "0.0.0-test",
  });

  const readiness = (): EnforcementReadinessView => ({
    actual_enforcement: {
      state: "pending_validation",
      label_tr: "Doğrulama bekleniyor — koruma etkin değil",
      label_en: "Pending validation — protection not active",
      verified_protection: false,
      activation_available: false,
    },
    inspection_source: state.readinessInspection ? "fixture" : "unavailable",
    inspection: state.readinessInspection
      ? {
          captured_ms: 1_700_000_000_000,
          key_present: true,
          layered: { name: "AllowDenyLayered", value: null, name_status: "documented" },
          deny_unspecified: { name: "DenyUnspecified", value: 1, name_status: "documented" },
          lists: [
            { name: "AllowDeviceIDs", allow: true, layer: "device_id", enabled: 1, entries: ["X"], name_status: "documented", layout_status: "unresolved" },
          ],
          retroactive: [{ name: "DenyDeviceClassesRetroactive", value: null, name_status: "unresolved" }],
          unrecognised: [[{ key: "K", name: "VENDORTOOL" }, { type: "sz", data: "x" }]],
          os: { is_windows: true, major: 10, minor: 0, build: 19045, ubr: 5011, product_type: 48 },
          edition_supported: true,
          layering: { status: "unresolved", reason: "UBR undocumented" },
          conflicts: [{ kind: "existing_deny_unspecified" }],
          plan_presence: { state: "partial", matching: 1, missing: 5, different: 0 },
          read_errors: [],
        }
      : null,
    inspection_error: state.readinessInspection ? null : "policy inspection requires Windows",
    plan_fingerprint: "ab".repeat(32),
    planned_changes: [
      {
        hive: "HKLM",
        key: "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions",
        value_name: "AllowDenyLayered",
        value_type: "REG_DWORD",
        data: "1",
        purpose: "layered",
        confirmed_against_documentation: true,
      },
    ],
    conflicts: state.readinessInspection ? [{ kind: "existing_deny_unspecified" }] : [],
    gates: [
      { code: "build_permits_activation", status: "not_met", detail: "ACTIVATION_ENABLED is false" },
      { code: "administrator_authorized", status: "met", detail: "" },
    ],
    required_permissions: [{ tr: "Okuma: standart kullanıcı.", en: "Read: standard user." }],
    recovery: { steps: [{ order: 1, tr: "Dışa aktarın.", en: "Export." }], rollback_modelled_exact: true, forward_operations: 6, rollback_operations: 6, suspend_operations: 1 },
    installed: {
      sanitized: true,
      devices: [
        {
          instance_id: "USBSTOR\\DISK&VEN_KINGSTON\\ID-001",
          name: "Kingston DataTraveler",
          attachment: "usb_bot",
          present: true,
          install_state: "installed",
          simulated_verdict: "deny",
          planned_new_install: { outcome: "prevented", rule: { layer: "setup_class", list: "DenyDeviceClasses", entry: "{x}" } },
          remains_accessible_after_activation: true,
          finding: "denied_but_installed",
          remediation: [{ tr: "Aygıtı yönetici elle kaldırır. RustWard bu işlemi yapmaz.", en: "Removed manually. RustWard never does this." }],
        },
      ],
      summary: { assessed: 1, denied_but_installed: 1, denied_not_installed: 0, allowed: 0, internal_protected: 0, internal_unprotected: 0, needs_review: 0, plan_disagreements: 0 },
      limitations: [{ tr: "Yükleme kısıtlamaları mevcut kurulumları etkilemez.", en: "Installation restrictions do not affect existing installations." }],
      manual_only: true,
    },
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
            workstation_id: state.workstationId,
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
      case "get_enforcement_session":
        return { type: "enforcement_session", data: state.session };
      case "prepare_enforcement_session":
        state.session = sessionView("protection_inactive", {
          session_id: "0123456789abcdef",
          prepared_ms: 1_794_050_000_000,
          prepared_by: "PC-TEST\\admin",
          device_key: r.device_key,
          device_name: "Kingston DataTraveler 3.0 USB Device",
          hardware_id: "USBSTOR\\DiskKingstonDataTraveler_3.0____",
          retroactive: r.retroactive,
          baseline: [],
          expected_lines: ["DenyDeviceIDs = 1 (REG_DWORD)"],
          last_verification: null,
          last_verification_ms: null,
        });
        return { type: "enforcement_session", data: state.session };
      case "prepare_default_deny_session":
        state.session = sessionView("protection_inactive", {
          session_id: "fedcba9876543210",
          prepared_ms: 1_794_050_000_000,
          prepared_by: "PC-TEST\\admin",
          device_key: "default_deny_profile",
          device_name: "Varsayılan ret profili (Aygıt Yükleme Kısıtlamaları)",
          hardware_id: "DiskDrive {4d36e967-e325-11ce-bfc1-08002be10318} prevent + allow list (layered)",
          retroactive: false,
          baseline: [],
          expected_lines: [
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\AllowDenyLayered = REG_DWORD 1",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\DenyDeviceClassesRetroactive = REG_DWORD 0",
          ],
          kind: "default_deny_profile",
          checklist_text: "VARSAYILAN RET PROFİLİ — YÖNETİCİ KONTROL LİSTESİ\n\"Zaten yüklü olan eşleşen aygıtlara da uygula\" İŞARETLENMEZ",
          last_verification: null,
          last_verification_ms: null,
        });
        return { type: "enforcement_session", data: state.session };
      case "verify_enforcement_applied":
        if (!state.session.session) throw { code: "not_found", message: "no active enforcement session", message_tr: "Etkin bir uygulama oturumu yok." };
        state.session = sessionView("windows_install_denied", {
          ...state.session.session,
          last_verification: "enforcement_session_apply_verified",
          last_verification_ms: 1_794_050_100_000,
        });
        return { type: "enforcement_session", data: state.session };
      case "apply_device_block": {
        const dk = r.device_key ?? (state.session.session ? state.session.session.device_key : "k-deny");
        state.session = sessionView("windows_install_denied", {
          session_id: r.session_id ?? "0123456789abcdef",
          prepared_ms: 1_794_050_000_000,
          prepared_by: "PC-TEST\\admin",
          device_key: dk,
          device_name: "Kingston DataTraveler 3.0 USB Device",
          hardware_id: "USBSTOR\\DiskKingstonDataTraveler_3.0____",
          retroactive: r.retroactive ?? true,
          baseline: [],
          expected_lines: ["DenyDeviceIDs = 1 (REG_DWORD)"],
          last_verification: "enforcement_session_apply_verified",
          last_verification_ms: 1_794_050_100_000,
        });
        return { type: "enforcement_session", data: state.session };
      }
      case "restore_device_policy":
      case "verify_enforcement_rollback":
      case "cancel_enforcement_session":
        state.session = sessionView("policy_simulation");
        return { type: "enforcement_session", data: state.session };
      case "get_enforcement_observation":
        return { type: "enforcement_observation", data: state.observation };
      case "get_policy_checklist": {
        const d = state.observation.devices.find((x) => x.device_key === r.device_key);
        if (!d) throw { code: "not_found", message: "device not in the current inventory" };
        const text = `RustWard - Yönetici Grup İlkesi kontrol listesi (RustWard bu değişikliği UYGULAMAZ)\nDonanım kimliği: ${d.observed.hardware_id}\nGeriye dönük: ${r.retroactive ? "evet" : "hayır"}\n`;
        return {
          type: "policy_checklist",
          data: {
            text,
            checklist: {
              device_name: d.observed.name,
              vid_pid: d.observed.vid_pid,
              hardware_id: d.observed.hardware_id ?? "",
              policy_name_en: "Prevent installation of devices that match any of these device IDs",
              policy_name_tr: "Bu aygıt kimliklerinden herhangi biriyle eşleşen aygıtların yüklenmesini engelle",
              policy_path_en: "Computer Configuration > ...",
              policy_path_tr: "Bilgisayar Yapılandırması > ...",
              retroactive: r.retroactive,
              device_installed: true,
              existing: ["DenyDeviceIDs: yapılandırılmamış"],
              expected_registry: ["DenyDeviceIDs = 1 (REG_DWORD)"],
              affected_devices: [d.observed.name],
              steps: ["gpedit.msc açın"],
              risks: ["Bu kimlik bu modelin TÜM birimleriyle eşleşir"],
              rollback: ["İlkeyi açın ve \"Yapılandırılmadı\" seçin."],
              verification: ["Kod 1 / Kod 28"],
            },
          },
        };
      }
      case "get_enforcement_readiness":
        return { type: "enforcement_readiness", data: readiness() };
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
      case "set_manufacturer_denied": {
        checkVersion(r.expected_policy_version);
        const m = find(r.id);
        m.denied = r.denied;
        if (r.denied) m.allowed = false;
        return mutation(`denied=${r.denied}`);
      }
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
      case "set_workstation_id":
        checkVersion(r.expected_policy_version);
        state.workstationId = r.workstation_id;
        return mutation(`workstation ${r.workstation_id}`);
      case "list_backups":
        return { type: "backups", data: state.backups };
      case "prepare_restore": {
        const b = state.backups.find((x) => x.file_name === r.file_name);
        if (!b) throw { code: "validation_failed", message: "backup rejected (not_registered)" };
        state.preparedRestore = "0123456789abcdef0123456789abcdef";
        return {
          type: "restore_preview",
          data: {
            restore_id: state.preparedRestore,
            file_name: b.file_name,
            sha256: b.sha256,
            backup_created_ms: b.created_ms,
            backup_policy_version: b.policy_version,
            current_policy_version: state.version,
            resulting_policy_version: state.version + 1,
            backup_workstation_id: state.workstationId,
            changes: ["would no longer be allowed: examplex"],
            expires_ms: b.created_ms + 600_000,
            notice: "Nothing has been changed yet.",
          },
        };
      }
      case "apply_restore": {
        if (r.restore_id !== state.preparedRestore) throw { code: "not_found", message: "no prepared restore" };
        state.preparedRestore = null;
        checkVersion(r.expected_policy_version);
        const pre = `rustward-pre-restore-${1_700_000_000_000 + state.backups.length}.db`;
        state.backups = [
          { file_name: pre, bytes: 40960, created_ms: 1_700_000_000_000 + state.backups.length, kind: "pre_restore", policy_version: state.version, sha256: "ab".repeat(32), actor: "PC-TEST\\admin", file_present: true },
          ...state.backups,
        ];
        return mutation(`backup applied; previous state saved as ${pre}`);
      }
      case "apply_retention":
      case "create_backup":
      case "refresh_inventory":
      case "load_synthetic_inventory":
      case "recover_device":
        return { type: "done", data: { message: `${r.type} done` } };
      case "get_compound_policy_plan":
      case "apply_compound_policy":
      case "rollback_compound_policy":
        return {
          type: "compound_policy_plan",
          data: {
            revision_id: "a1b2c3d4e5f60718",
            policy_version: state.version,
            manufacturers: state.manufacturers.map((m) => ({
              brand_id: m.id,
              display_name: m.display_name,
              configured_intention: m.denied ? "explicit_deny" : m.allowed ? "allowed" : "disabled",
              identity_coverage: m.id === "tubitak" ? "unknown" : "verified",
              hardware_ids: m.id === "kingston" ? ["USBSTOR\\DiskKingstonDataTraveler_3.0____"] : m.id === "sandisk" ? ["USBSTOR\\DiskSanDisk_"] : [],
              windows_policy: m.denied ? "applied" : "not_applied",
              device_outcome: m.id === "kingston" ? "installation_denied" : "not_connected",
              notes: m.notes,
            })),
            compiled: {
              revision_id: "a1b2c3d4e5f60718",
              deny_hardware_ids: ["USBSTOR\\DiskKingstonDataTraveler_3.0____"],
              allow_hardware_ids: ["USBSTOR\\DiskSanDisk_"],
              retroactive: true,
              fingerprint: "a1b2c3d4e5f60718".repeat(4),
            },
            observed: {
              active_denies: ["USBSTOR\\DiskKingstonDataTraveler_3.0____"],
              active_allows: [],
              retroactive: true,
              raw_gpo_present: true,
              fingerprint: "a1b2c3d4e5f60718".repeat(4),
            },
            diff: {
              added_denies: [],
              removed_denies: [],
              retained_denies: ["USBSTOR\\DiskKingstonDataTraveler_3.0____"],
              is_synchronized: true,
            },
            safety_checklist: [
              "Disk 0 / VMware Virtual NVMe Disk (C:) sistem diski koruma altında — GPO kapsamı dışında",
              "USB Klavye, Fare ve Giriş Aygıtları (HID) koruma altında — GPO kapsamı dışında",
              "Yalnızca doğrulanmış USBSTOR depolama donanım kimlikleri hedeflenir",
              "Geniş kapsamlı DiskDrive sınıfı engelleme uygulanmaz",
            ],
            can_apply: true,
            is_applied: true,
          },
        };
    }
  };

  const backend: Backend = {
    call(request) {
      state.calls.push(request);
      if (state.failNext && (state.failNext.only === undefined || state.failNext.only === request.type)) {
        const { code, message } = state.failNext;
        state.failNext = null;
        return Promise.reject({ code, message });
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
