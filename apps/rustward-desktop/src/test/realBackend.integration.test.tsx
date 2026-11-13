// Integration tests: the real React application against the REAL RustWard
// backend (AppService + SQLite file, the service's validation and
// authorization path) through the development-only stdio harness. No fake
// data: everything shown comes from the backend, including the synthetic
// inventory fixture (which is itself labelled SENTETİK).
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Api } from "../api/client";
import { App, type PageId } from "../App";
import type { ResponseBody } from "../api/types";
import { resolve } from "node:path";
import { startRealBackend, type RealBackend } from "./stdioBackend";

const BANNER_TR = "Koruma henüz gerçek Windows ortamında doğrulanmadı.";
const FORBIDDEN_BLOCKED_CLAIM = /USB engellenmiştir|engellendi|blocked successfully/i;

let real: RealBackend | undefined;

type DataOf<T extends ResponseBody["type"]> = Extract<ResponseBody, { type: T }> extends { data: infer D } ? D : never;

function data<T extends ResponseBody["type"]>(r: ResponseBody, type: T): DataOf<T> {
  expect(r.type).toBe(type);
  return r.data as DataOf<T>;
}

const ADMIN_USER = "admin";
const ADMIN_PASS = "V11Admin!Pass#2026";

async function authenticateBackend(target: RealBackend, caller: "admin" | "user", synthetic: boolean) {
  if (caller === "admin") {
    await target.call({
      type: "setup_initial_admin",
      username: ADMIN_USER,
      display_name: "Administrator",
      password: ADMIN_PASS,
    });
    if (synthetic) await target.call({ type: "load_synthetic_inventory" });
  } else {
    const admin = startRealBackend("admin", target.dataDir);
    try {
      await admin.call({
        type: "setup_initial_admin",
        username: ADMIN_USER,
        display_name: "Administrator",
        password: ADMIN_PASS,
      });
      if (synthetic) await admin.call({ type: "load_synthetic_inventory" });
    } finally {
      await admin.close();
    }
    await target.call({ type: "login", username: ADMIN_USER, password: ADMIN_PASS });
  }
}

async function boot(page: PageId, caller: "admin" | "user" = "admin", synthetic = true) {
  real = startRealBackend(caller);
  await authenticateBackend(real, caller, synthetic);
  const user = userEvent.setup();
  render(<App api={new Api(real.backend)} initialPage={page} />);
  return { user, real };
}

beforeEach(() => {
  try {
    window.localStorage.clear();
  } catch {
    /* ignore */
  }
});

afterEach(async () => {
  await real?.close();
  real = undefined;
  vi.restoreAllMocks();
});

describe("real backend: dashboard and devices", () => {
  it("shows the banner, real counts and only simulated, labelled decisions", async () => {
    await boot("dashboard");
    expect(await screen.findByTestId("not-validated-banner")).toHaveTextContent(BANNER_TR);
    await waitFor(() => expect(screen.getAllByText("SENTETİK").length).toBeGreaterThan(0));
    expect(screen.getAllByText(/SİMÜLE (RET|İZİN)/).length).toBeGreaterThan(0);
    expect(screen.getByText("Doğrulama bekleniyor — koruma etkin değil", { exact: false })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(FORBIDDEN_BLOCKED_CLAIM);
  });

  it("lists the stored inventory and explains a real decision", async () => {
    const { user } = await boot("devices");
    await waitFor(() => expect(document.querySelectorAll("tbody tr").length).toBeGreaterThan(5));
    const rows = [...document.querySelectorAll<HTMLTableRowElement>("tbody tr")];
    const denied = rows.find((r) => r.textContent?.includes("SİMÜLE RET"));
    expect(denied).toBeDefined();
    await user.click(denied!);
    const panel = (await screen.findByText("Karar açıklaması")).closest("section") ?? document.body;
    await waitFor(() => expect(panel.textContent).toMatch(/SİMÜLE RET/));
    // Real Windows status column: off Windows the policy cannot be read, so
    // USB storage rows say exactly that (never "no rule", never "blocked");
    // rows the observer does not cover show "—".
    await waitFor(() => expect(document.querySelectorAll("[data-testid=windows-status]").length).toBeGreaterThan(0));
    for (const c of document.querySelectorAll("[data-testid=windows-status]")) {
      expect(c.textContent).toContain("Windows politikası okunamadı");
      expect(c.textContent).not.toContain("Kural uygulanmamış");
    }
    for (const r of rows) expect(r.textContent).not.toMatch(FORBIDDEN_BLOCKED_CLAIM);
  });
});

describe("real backend: manufacturers and policy history", () => {
  it("adds, allows and removes a brand as new policy versions, with history", async () => {
    const { user, real } = await boot("manufacturers");
    const before = data(await real.call({ type: "list_manufacturers" }), "manufacturers");

    await user.click(await screen.findByRole("button", { name: "Üretici ekle" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Görünen ad"), "Integration Brand");
    await user.click(within(dialog).getByRole("button", { name: "Kaydet" }));
    await waitFor(async () => {
      const m = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
      expect(m.manufacturers.some((b) => b.display_name === "Integration Brand")).toBe(true);
    });

    await user.type(screen.getByRole("searchbox", { name: "Ara" }), "Integration Brand");
    const sw = await screen.findByRole("switch", { name: "İzinli: Integration Brand" });
    const wasAllowed = sw.getAttribute("aria-checked") === "true";
    await user.click(sw);
    await waitFor(async () => {
      const m = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
      expect(m.manufacturers.find((b) => b.display_name === "Integration Brand")?.allowed).toBe(!wasAllowed);
    });

    const after = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
    expect(after.policy_version).toBe(before.policy_version + 2);
    const history = data(await real.call({ type: "list_policy_changes", limit: 10 }), "policy_changes");
    expect(history.length).toBeGreaterThanOrEqual(2);
    expect(await screen.findByText("Politika değişiklik geçmişi")).toBeInTheDocument();
  });

  it("surfaces a real version conflict from the backend", async () => {
    const { user, real } = await boot("manufacturers");
    const allSwitches = await screen.findAllByRole("switch");
    const sw = allSwitches.find((s) => s.getAttribute("aria-label")?.startsWith("İzinli:"));
    expect(sw).toBeDefined();
    // Someone else changes the policy after the page loaded.
    const m = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
    await real.call({
      type: "set_workstation_id",
      workstation_id: "PC-ELSEWHERE",
      expected_policy_version: m.policy_version,
    });
    await user.click(sw!);
    expect(await screen.findByText("Çakışma — politika bu arada değişmiş olabilir; yenileyip yeniden deneyin")).toBeInTheDocument();
  });
});

describe("real backend: blocked devices, audit, diagnostics", () => {
  it("states that every listed denial is simulated and not enforced", async () => {
    await boot("blocked");
    expect(await screen.findByText("Simüle edilen retler (uygulanmadı)")).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText("Uygulanmadı — yalnızca simüle karar").length).toBeGreaterThan(0));
    expect(document.body.textContent).not.toMatch(FORBIDDEN_BLOCKED_CLAIM);
  });

  it("shows real audit records and exports them", async () => {
    const create = vi.fn(() => "blob:test");
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const { user } = await boot("audit");
    await waitFor(() => expect(document.querySelectorAll("tbody tr").length).toBeGreaterThan(0));
    expect(screen.getAllByText("Simülasyon").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "JSON dışa aktar" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(await screen.findByText(/kayıt dışa aktarıldı\./)).toBeInTheDocument();
  });

  it("reports an intact audit chain, no Event Log mirror and a dry-run simulation", async () => {
    const { user } = await boot("diagnostics");
    expect(await screen.findByText(/intact \(\d+ entries\)/)).toBeInTheDocument();
    expect(screen.getByText("Bağlı değil (yalnızca Windows hizmetinde)")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Simülasyonu çalıştır" }));
    expect(await screen.findByTestId("simulation-result")).toHaveTextContent(/aygıt değerlendirildi/);
    expect(screen.getByText("Bu sürümde devre dışı (yalnızca kuru çalıştırma)")).toBeInTheDocument();
  });
});

describe("real backend: settings, backup, two-step restore, workstation ID", () => {
  it("backs up, previews and applies a restore as a new version without losing audit history", async () => {
    const { user, real } = await boot("settings");
    await user.click(await screen.findByRole("button", { name: "Yedek oluştur" }));
    await waitFor(async () => {
      const b = data(await real.call({ type: "list_backups" }), "backups");
      expect(b.length).toBe(1);
    });
    const backup = data(await real.call({ type: "list_backups" }), "backups")[0]!;
    expect(await screen.findByText(backup.file_name)).toBeInTheDocument();

    // Change the policy after the backup.
    const m = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
    await real.call({ type: "set_workstation_id", workstation_id: "PC-CHANGED", expected_policy_version: m.policy_version });
    const eventsBefore = data(await real.call({ type: "list_events", query: { limit: 5000 } }), "events").length;

    await user.click(screen.getByRole("button", { name: "Geri yükle" }));
    const dialog = await screen.findByRole("dialog", { name: "Yedeği geri yükle" });
    expect(dialog).toHaveTextContent("henüz hiçbir şey değiştirilmedi");
    expect(dialog).toHaveTextContent(backup.sha256);
    // Nothing applied yet.
    let now = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
    expect(now.workstation_id).toBe("PC-CHANGED");

    await user.click(within(dialog).getByRole("button", { name: "Uygula" }));
    expect(await screen.findByText(/Geri yükleme uygulandı\./)).toBeInTheDocument();
    now = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
    expect(now.workstation_id).toBe(m.workstation_id);
    expect(now.policy_version).toBe(m.policy_version + 2); // rename + restore, never backwards
    const events = data(await real.call({ type: "list_events", query: { limit: 5000 } }), "events");
    expect(events.length).toBeGreaterThan(eventsBefore); // appended, nothing lost
    expect(events.some((e) => e.kind === "policy_restored")).toBe(true);
    expect(await screen.findByText("Geri yükleme öncesi")).toBeInTheDocument();
  });

  it("renames the workstation through the backend and rejects invalid IDs client-side", async () => {
    const { user, real } = await boot("settings", "admin", false);
    const input = await screen.findByLabelText("İş istasyonu kimliği");
    await waitFor(() => expect(input).not.toHaveValue(""));
    await user.clear(input);
    await user.type(input, "PC 01");
    expect(screen.getByRole("button", { name: "Kimliği kaydet" })).toBeDisabled();
    await user.clear(input);
    await user.type(input, "PC-INT-01");
    await user.click(screen.getByRole("button", { name: "Kimliği kaydet" }));
    expect(await screen.findByText(/İş istasyonu kimliği güncellendi \(politika v\d+\)\./)).toBeInTheDocument();
    const m = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
    expect(m.workstation_id).toBe("PC-INT-01");
  });

  it("saves settings that persist in the database", async () => {
    const { user, real } = await boot("settings", "admin", false);
    await user.selectOptions(await screen.findByLabelText("Tema"), "light");
    await user.click(screen.getAllByRole("button", { name: "Kaydet" })[0]!);
    await waitFor(async () => {
      const s = data(await real.call({ type: "get_settings" }), "settings");
      expect(s.theme).toBe("light");
    });
  });
});

describe("real backend: standard user (no administrator rights)", () => {
  it("sees the real dashboard with the not-validated banner", async () => {
    await boot("dashboard", "user");
    expect(await screen.findByTestId("not-validated-banner")).toHaveTextContent(BANNER_TR);
    await waitFor(() => expect(screen.getAllByText("SENTETİK").length).toBeGreaterThan(0));
    expect(document.body.textContent).not.toMatch(FORBIDDEN_BLOCKED_CLAIM);
  });

  it("can read but every change is refused by the backend, in Turkish", async () => {
    const { user, real } = await boot("settings", "user");
    const REFUSED = "Bu işlem için yükseltilmiş yönetici yetkisi gerekir.";
    // Listing backups is itself an administrator request: refused on load.
    const before = (await screen.findAllByText(REFUSED)).length;
    await user.click(await screen.findByRole("button", { name: "Yedek oluştur" }));
    await waitFor(() => expect(screen.getAllByText(REFUSED).length).toBeGreaterThan(before));
    // Nothing was created; reading still works.
    await expect(real.call({ type: "list_backups" })).rejects.toMatchObject({ code: "unauthorized" });
    const d = data(await real.call({ type: "get_dashboard" }), "dashboard");
    expect(d.enforcement_state).not.toBe("verified_protected");
  });

  it("cannot change brands from the UI", async () => {
    const { user, real } = await boot("manufacturers", "user");
    const before = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
    const allSwitches = await screen.findAllByRole("switch");
    const sw = allSwitches.find((s) => s.getAttribute("aria-label")?.startsWith("İzinli:"));
    expect(sw).toBeDefined();
    await user.click(sw!);
    expect(await screen.findByText("Bu işlem için yükseltilmiş yönetici yetkisi gerekir.")).toBeInTheDocument();
    const after = data(await real.call({ type: "list_manufacturers" }), "manufacturers");
    expect(after.policy_version).toBe(before.policy_version);
    expect(after.manufacturers).toEqual(before.manufacturers);
  });
});

// Tests run from apps/rustward-desktop (vitest root).
const POLICY_FIXTURE = resolve(process.cwd(), "../../tests/fixtures/policy-capture-synthetic.json");

describe("real backend: enforcement readiness (read-only)", () => {
  it("inspects a synthetic policy capture, merges around existing entries and keeps activation disabled", async () => {
    real = startRealBackend("admin", undefined, { policyCapture: POLICY_FIXTURE });
    await authenticateBackend(real, "admin", true);
    const v = data(await real.call({ type: "get_enforcement_readiness" }), "enforcement_readiness");
    expect(v.actual_enforcement.verified_protection).toBe(false);
    expect(v.actual_enforcement.activation_available).toBe(false);
    expect(v.inspection_source).toBe("fixture");
    // The administrator's existing AllowDeviceIDs\1 is kept; planned entries follow it.
    const allow = v.planned_changes.filter((c) => c.key.endsWith("\\AllowDeviceIDs"));
    expect(allow.length).toBeGreaterThan(0);
    expect(allow.every((c) => c.value_name !== "1")).toBe(true);
    expect(v.conflicts).toEqual([]);
    expect(v.recovery.rollback_modelled_exact).toBe(true);
    expect(v.gates.find((g) => g.code === "build_permits_activation")?.status).toBe("not_met");
    expect(v.installed.summary.denied_but_installed).toBeGreaterThan(0);
    expect(v.installed.manual_only).toBe(true);

    render(<App api={new Api(real.backend)} initialPage="readiness" />);
    expect(await screen.findByText("SENTETİK kayıt dosyası (geliştirme)")).toBeInTheDocument();
    expect(screen.getByText(/SYNTHETICVENDORTOOL/)).toBeInTheDocument();
    expect(screen.getByText("Çakışma yok.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Politikayı etkinleştir" })).toBeDisabled();
    expect(within(screen.getByTestId("installed-table")).getAllByText("Reddedilen ama kurulu — elle düzeltme gerekli").length).toBe(
      v.installed.summary.denied_but_installed,
    );
    expect(screen.getByTestId("remediation-steps")).toHaveTextContent("RustWard bu işlemi yapmaz");
    expect(document.body.textContent).not.toMatch(FORBIDDEN_BLOCKED_CLAIM);
  });

  it("says plainly that the policy cannot be read off Windows", async () => {
    await boot("readiness");
    expect(await screen.findByTestId("inspection-error")).toHaveTextContent("policy inspection requires Windows");
  });

  it("is readable by a standard user, whose administrator gate is not met", async () => {
    real = startRealBackend("user", undefined, { policyCapture: POLICY_FIXTURE });
    await authenticateBackend(real, "user", false);
    const v = data(await real.call({ type: "get_enforcement_readiness" }), "enforcement_readiness");
    expect(v.gates.find((g) => g.code === "administrator_authorized")?.status).toBe("not_met");
    render(<App api={new Api(real.backend)} initialPage="readiness" />);
    expect(await screen.findByTestId("actual-enforcement")).toHaveTextContent("koruma etkin değil");
  });

  it.runIf(process.platform === "win32")(
    "reads live Windows DeviceInstall\\Restrictions read-only on Windows without mutating anything",
    async () => {
      real = startRealBackend("admin", undefined, { policyCapture: "live" });
      await authenticateBackend(real, "admin", false);
      const v = data(await real.call({ type: "get_enforcement_readiness" }), "enforcement_readiness");
      expect(v.inspection_source).toBe("windows_registry_read_only");
      expect(v.inspection).not.toBeNull();
      expect(v.inspection_error).toBeNull();
      expect(v.actual_enforcement.activation_available).toBe(false);
    },
  );
});
