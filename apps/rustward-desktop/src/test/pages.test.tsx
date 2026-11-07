import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Api } from "../api/client";
import { PRIVILEGED } from "../api/types";
import { App, type PageId } from "../App";
import { BANNER_TR, fakeBackend, type FakeState } from "./fakeBackend";

function setup(page: PageId, init: Partial<FakeState> = {}) {
  const { backend, state } = fakeBackend(init);
  const user = userEvent.setup();
  render(<App api={new Api(backend)} initialPage={page} />);
  return { state, user };
}

beforeEach(() => {
  try {
    window.localStorage.clear();
  } catch {
    /* ignore */
  }
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Dashboard", () => {
  it("shows the mandated not-validated banner verbatim", async () => {
    setup("dashboard");
    const banner = await screen.findByTestId("not-validated-banner");
    expect(banner).toHaveTextContent(BANNER_TR);
  });

  it("keeps the Turkish banner sentence in English mode", async () => {
    setup("dashboard", {
      settings: { theme: "light", language: "en", notifications_enabled: true, audit_retention_days: 365, inventory_refresh_seconds: 30 },
    });
    await screen.findByRole("heading", { name: "Dashboard" });
    expect(screen.getByTestId("not-validated-banner")).toHaveTextContent(BANNER_TR);
  });

  it("labels synthetic data and simulated decisions, never as enforced", async () => {
    setup("dashboard");
    await screen.findByText("PC-TEST", { exact: false });
    expect(screen.getAllByText("SENTETİK").length).toBeGreaterThan(0);
    expect(screen.getAllByText("SİMÜLE RET").length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toMatch(/engellendi|engellenmiştir/i);
  });
});

describe("Navigation and mandatory warning", () => {
  it("shows the eight pages in the required order and the not-activated warning", async () => {
    setup("dashboard");
    await screen.findByTestId("not-validated-banner");
    const nav = screen.getByRole("navigation");
    const labels = within(nav)
      .getAllByRole("button")
      .map((b) => b.textContent?.trim());
    expect(labels).toEqual([
      "Dashboard",
      "Cihazlar",
      "İzinli Markalar",
      "Engellenen Cihazlar",
      "Olay Kayıtları",
      "Tanılama",
      "Uygulama Hazırlığı",
      "Ayarlar",
    ]);
    expect(screen.getByTestId("not-activated-warning")).toHaveTextContent(
      "USB koruması henüz etkinleştirilmemiştir.",
    );
  });

  it("keeps the not-activated warning when the service is not installed", async () => {
    const down = {
      call: () => Promise.reject({ code: "unavailable", message: "the RustWard service is not reachable" }),
    };
    render(<App api={new Api(down)} initialPage="readiness" />);
    expect(await screen.findByTestId("not-activated-warning")).toHaveTextContent(
      "USB koruması henüz etkinleştirilmemiştir.",
    );
    expect(document.body.textContent).not.toMatch(/USB engellenmiştir/i);
  });
});

describe("Service connection bar", () => {
  const down = (message: string) => ({ call: () => Promise.reject({ code: "unavailable", message }) });

  it("explains a service that is not installed, in Turkish, and claims no protection", async () => {
    render(<App api={new Api(down("[service_not_installed] the RustWard service (RustWardService) is not installed"))} initialPage="devices" />);
    const bar = await screen.findByTestId("connection-bar");
    await waitFor(() => expect(bar).toHaveAttribute("data-state", "disconnected"));
    expect(bar).toHaveTextContent("Hizmet bağlantısı yok.");
    expect(bar).toHaveTextContent("RustWard hizmeti bu bilgisayarda kurulu değil.");
    expect(bar).toHaveTextContent("koruma da yok");
    expect(screen.getByTestId("not-activated-warning")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/koruma etkin(?! değil)|USB engellenmiştir/i);
  });

  it("distinguishes a stopped service and a missing administrator token", async () => {
    render(<App api={new Api(down("[service_stopped] the RustWard service (RustWardService) is installed but stopped"))} initialPage="dashboard" />);
    expect(await screen.findAllByText("RustWard hizmeti kurulu ancak durdurulmuş.")).not.toHaveLength(0);
  });

  it("shows an unelevated administrator refusal as an authorization problem, not a missing service", async () => {
    const api = new Api({
      call: (req: { type: string }) =>
        req.type === "refresh_inventory"
          ? Promise.reject({ code: "unavailable", message: "[admin_required] the RustWard service is running, but this account is not an elevated administrator" })
          : fakeBackend().backend.call(req as never),
    } as never);
    render(<App api={api} initialPage="devices" />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Envanteri yenile/ }));
    expect(await screen.findByText("Bu işlem için yükseltilmiş yönetici yetkisi gerekir.")).toBeInTheDocument();
    expect(screen.getByText("Hizmet çalışıyor; bu işlem için uygulamayı yönetici olarak (yükseltilmiş) başlatın.")).toBeInTheDocument();
  });

  it("reports a rejected service identity as a security refusal", async () => {
    render(<App api={new Api(down("service identity could not be verified: pipe served by process 42"))} initialPage="dashboard" />);
    expect(await screen.findAllByText("Hizmetin kimliği doğrulanamadı; bağlantı güvenlik nedeniyle reddedildi.")).not.toHaveLength(0);
  });

  it("labels the development backend and never equates a connection with protection", async () => {
    setup("dashboard");
    const bar = await screen.findByTestId("connection-bar");
    await waitFor(() => expect(bar).toHaveAttribute("data-state", "connected"));
    expect(bar).toHaveTextContent("Bağlantı, USB korumasının etkin olduğu anlamına gelmez.");
  });
});

describe("Service unavailable (stopped or not installed)", () => {
  it("never reads a missing service as protection: banner stays, error is explicit", async () => {
    const down = {
      call: () => Promise.reject({ code: "unavailable", message: "the RustWard service is not reachable" }),
    };
    render(<App api={new Api(down)} initialPage="dashboard" />);
    expect(await screen.findByTestId("not-validated-banner")).toHaveTextContent(BANNER_TR);
    expect((await screen.findAllByText("RustWard hizmetine ulaşılamıyor.")).length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toMatch(/engellenmiştir|koruma etkin(?! değil)|doğrulandı/i);
  });
});

describe("Devices", () => {
  it("explains a selected device", async () => {
    const { user } = setup("devices");
    const rows = await screen.findAllByText("EXAMPLEX SYNTH DRIVE");
    await user.click(rows[0]!);
    expect(await screen.findByText("SİMÜLE RET: üretici katalogda yok.")).toBeInTheDocument();
  });

  it("refreshes the inventory through the backend", async () => {
    const { user, state } = setup("devices");
    await user.click(await screen.findByRole("button", { name: "Envanteri yenile" }));
    expect(await screen.findByText("refresh_inventory done")).toBeInTheDocument();
    expect(state.calls.some((c) => c.type === "refresh_inventory")).toBe(true);
  });
});

describe("Allowed manufacturers", () => {
  it("toggles allowed with the expected policy version", async () => {
    const { user, state } = setup("manufacturers");
    const sw = await screen.findByRole("switch", { name: "İzinli: ExampleX (synthetic)" });
    await user.click(sw);
    await waitFor(() => expect(state.manufacturers[0]!.allowed).toBe(false));
    const call = state.calls.find((c) => c.type === "set_manufacturer_allowed");
    expect(call).toEqual({ type: "set_manufacturer_allowed", id: "examplex", allowed: false, expected_policy_version: 3 });
  });

  it("shows a version conflict from the service", async () => {
    const { user, state } = setup("manufacturers");
    const sw = await screen.findByRole("switch", { name: "Kural etkin: ExampleX (synthetic)" });
    state.version = 9; // changed elsewhere
    await user.click(sw);
    expect(await screen.findByText("Çakışma — politika bu arada değişmiş olabilir; yenileyip yeniden deneyin")).toBeInTheDocument();
    expect(screen.getByText("policy changed (expected 3, current 9)")).toBeInTheDocument();
    expect(state.manufacturers[0]!.enabled).toBe(true);
  });

  it("validates identifiers client-side before calling the service", async () => {
    const { user, state } = setup("manufacturers");
    await user.click(await screen.findByRole("button", { name: "Üretici ekle" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Görünen ad"), "Synthetic Brand");
    await user.click(within(dialog).getByRole("button", { name: "Kimlik ekle" }));
    await user.selectOptions(within(dialog).getByLabelText("Tür"), "usb_vid");
    await user.type(within(dialog).getByLabelText("Değer"), "XYZ");
    await user.click(within(dialog).getByRole("button", { name: "Kaydet" }));
    expect(within(dialog).getByText("USB VID 4 onaltılık basamak olmalıdır (ör. 0781).")).toBeInTheDocument();
    expect(within(dialog).getByText("Her kimlik için kaynak gerekli.")).toBeInTheDocument();
    expect(state.calls.some((c) => c.type === "add_manufacturer")).toBe(false);
  });

  it("adds a manufacturer through the backend", async () => {
    const { user, state } = setup("manufacturers");
    await user.click(await screen.findByRole("button", { name: "Üretici ekle" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Görünen ad"), "Synthetic Brand");
    await user.click(within(dialog).getByRole("button", { name: "Kaydet" }));
    await waitFor(() => expect(state.manufacturers).toHaveLength(2));
    expect(await screen.findByText("TR: added synthetic-brand")).toBeInTheDocument();
  });

  it("asks for confirmation before removing", async () => {
    const { user, state } = setup("manufacturers");
    await user.click(await screen.findByRole("button", { name: "Kaldır" }));
    const dialog = await screen.findByRole("dialog");
    expect(state.calls.some((c) => c.type === "remove_manufacturer")).toBe(false);
    await user.click(within(dialog).getByRole("button", { name: "Kaldır" }));
    await waitFor(() => expect(state.manufacturers).toHaveLength(0));
  });
});

describe("Blocked devices", () => {
  it("states that the decision was not enforced", async () => {
    setup("blocked");
    expect(await screen.findByText("Uygulanmadı — yalnızca simüle karar")).toBeInTheDocument();
    expect(screen.getByText("Engellenen Cihazlar (simülasyon)")).toBeInTheDocument();
  });
});

describe("Audit logs", () => {
  it("sends text filters to the backend", async () => {
    const { user, state } = setup("audit");
    await screen.findByText("SENTETİK cihaz reddedilirdi (simülasyon)");
    await user.type(screen.getByLabelText("Ara"), "nomatch");
    await waitFor(() => {
      const last = [...state.calls].reverse().find((c) => c.type === "list_events");
      expect(last).toMatchObject({ query: { text: "nomatch", offset: 0 } });
    });
    expect(await screen.findByText("Kayıt yok.")).toBeInTheDocument();
  });

  it("exports events as a local download", async () => {
    const create = vi.fn(() => "blob:test");
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const { user, state } = setup("audit");
    await user.click(await screen.findByRole("button", { name: "CSV dışa aktar" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(create).toHaveBeenCalled();
    expect(state.calls.find((c) => c.type === "export_events")).toMatchObject({ format: "csv" });
  });
});

describe("Diagnostics", () => {
  it("runs a simulation and reports counts", async () => {
    const { user } = setup("diagnostics");
    await user.click(await screen.findByRole("button", { name: "Simülasyonu çalıştır" }));
    expect(await screen.findByTestId("simulation-result")).toHaveTextContent("2 aygıt değerlendirildi: 1 simüle izin, 1 simüle ret");
    expect(screen.getByText("Bu sürümde devre dışı (yalnızca kuru çalıştırma)")).toBeInTheDocument();
  });
});

describe("Settings", () => {
  it("renames the workstation through a versioned policy edit", async () => {
    const { user, state } = setup("settings");
    const input = await screen.findByLabelText("İş istasyonu kimliği");
    await waitFor(() => expect(input).toHaveValue("PC-TEST"));
    await user.clear(input);
    await user.type(input, "PC 09");
    expect(screen.getByText("Yalnızca A–Z, a–z, 0–9, - ve _ kullanılabilir (1–64 karakter).")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Kimliği kaydet" })).toBeDisabled();
    await user.clear(input);
    await user.type(input, "PC-09");
    await user.click(screen.getByRole("button", { name: "Kimliği kaydet" }));
    expect(await screen.findByText("İş istasyonu kimliği güncellendi (politika v4).")).toBeInTheDocument();
    expect(state.workstationId).toBe("PC-09");
    const call = state.calls.find((c) => c.type === "set_workstation_id");
    expect(call).toEqual({ type: "set_workstation_id", workstation_id: "PC-09", expected_policy_version: 3 });
  });

  it("restores in two steps: verified preview first, apply only after confirmation", async () => {
    const { user, state } = setup("settings");
    await screen.findByText("rustward-backup-1700000000000.db");
    await user.click(screen.getByRole("button", { name: "Geri yükle" }));
    const dialog = await screen.findByRole("dialog", { name: "Yedeği geri yükle" });
    expect(dialog).toHaveTextContent("henüz hiçbir şey değiştirilmedi");
    expect(dialog).toHaveTextContent("YENİ politika v4 olarak kaydedilir (şu an v3, yedek v2)");
    expect(within(dialog).getByText("would no longer be allowed: examplex")).toBeInTheDocument();
    expect(dialog).toHaveTextContent("cd".repeat(32));
    expect(state.calls.some((c) => c.type === "prepare_restore")).toBe(true);
    expect(state.calls.some((c) => c.type === "apply_restore")).toBe(false);
    await user.click(within(dialog).getByRole("button", { name: "Uygula" }));
    expect(await screen.findByText(/Geri yükleme uygulandı\./)).toBeInTheDocument();
    expect(state.calls.find((c) => c.type === "apply_restore")).toEqual({
      type: "apply_restore",
      restore_id: "0123456789abcdef0123456789abcdef",
      expected_policy_version: 3,
    });
    expect(await screen.findByText("Geri yükleme öncesi")).toBeInTheDocument();
  });

  it("cancelling the restore preview applies nothing", async () => {
    const { user, state } = setup("settings");
    await screen.findByText("rustward-backup-1700000000000.db");
    await user.click(screen.getByRole("button", { name: "Geri yükle" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Vazgeç" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(state.calls.some((c) => c.type === "apply_restore")).toBe(false);
  });

  it("saves the theme and applies it", async () => {
    const { user, state } = setup("settings");
    await waitFor(() => expect(document.documentElement).toHaveClass("dark"));
    await user.selectOptions(await screen.findByLabelText("Tema"), "light");
    await user.click(screen.getByRole("button", { name: "Kaydet" }));
    await waitFor(() => expect(state.settings.theme).toBe("light"));
    expect(document.documentElement).not.toHaveClass("dark");
  });

  it("rejects an out-of-range retention value without calling the service", async () => {
    const { user, state } = setup("settings");
    const input = await screen.findByLabelText("Saklama süresi (gün)");
    await user.clear(input);
    await user.type(input, "5");
    expect(screen.getByRole("button", { name: "Kaydet" })).toBeDisabled();
    expect(state.calls.some((c) => c.type === "update_settings")).toBe(false);
  });

  it("shows the backend's authorization error", async () => {
    const { user, state } = setup("settings");
    await user.click(await screen.findByRole("button", { name: "Yedek oluştur" }));
    await screen.findByText("create_backup done");
    state.failNext = { code: "unauthorized", message: "elevation required", only: "create_backup" };
    await user.click(screen.getByRole("button", { name: "Yedek oluştur" }));
    expect(await screen.findByText("Bu işlem için yükseltilmiş yönetici yetkisi gerekir.")).toBeInTheDocument();
  });

  it("shows a missing backup file instead of a restore button", async () => {
    setup("settings", {
      backups: [
        {
          file_name: "rustward-backup-1.db",
          bytes: 1,
          created_ms: 1,
          kind: "manual",
          policy_version: 1,
          sha256: "ef".repeat(32),
          actor: "x",
          file_present: false,
        },
      ],
    });
    expect(await screen.findByText("Dosya yok")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Geri yükle" })).not.toBeInTheDocument();
  });
});

describe("Diagnostics Event Log", () => {
  it("states that Event Log mirroring is not attached outside the Windows service", async () => {
    setup("diagnostics");
    expect(await screen.findByText("Bağlı değil (yalnızca Windows hizmetinde)")).toBeInTheDocument();
  });
});

describe("Enforcement readiness (read-only)", () => {
  it("shows the real status, keeps activation disabled and never claims blocking", async () => {
    const { state } = setup("readiness");
    expect(await screen.findByText("Uygulama Hazırlığı (salt okunur)")).toBeInTheDocument();
    const actual = screen.getByTestId("actual-enforcement");
    expect(actual).toHaveTextContent("Doğrulama bekleniyor — koruma etkin değil");
    const button = screen.getByRole("button", { name: "Politikayı etkinleştir" });
    expect(button).toBeDisabled();
    expect(screen.getByText(/ACTIVATION_ENABLED = false/)).toBeInTheDocument();
    // Only read-only requests were made (no privileged request at all).
    expect(state.calls.some((c) => c.type === "get_enforcement_readiness")).toBe(true);
    expect(state.calls.filter((c) => PRIVILEGED.has(c.type))).toEqual([]);
    expect(document.body.textContent).not.toMatch(/engellendi|engellenmiştir/i);
  });

  it("explains conflicts, unresolved names, prerequisites and manual remediation in Turkish", async () => {
    setup("readiness");
    expect(await screen.findByTestId("conflicts")).toHaveTextContent("DenyUnspecified = 1: tanımlanmayan tüm yeni aygıtlar");
    expect(screen.getByText("Kayıt düzeni Microsoft CSP tablosunda yok; VM'de doğrulanmalı.")).toBeInTheDocument();
    expect(screen.getByText("Tanınmayan değerler (yorumlanmaz, değiştirilmez): 1")).toBeInTheDocument();
    expect(screen.getByText("Kısmi: 1 eşleşen, 5 eksik, 0 farklı")).toBeInTheDocument();
    expect(screen.getByText("Yalnızca politika durumudur; erişim engelinin kanıtı değildir.")).toBeInTheDocument();
    const gates = screen.getByTestId("gates");
    expect(within(gates).getByText("Sürüm etkinleştirmeye izin veriyor")).toBeInTheDocument();
    expect(within(gates).getAllByText("Karşılanmadı").length).toBe(1);
    expect(screen.getByText("Reddedilen ama kurulu — elle düzeltme gerekli")).toBeInTheDocument();
    expect(screen.getByTestId("remediation-steps")).toHaveTextContent("RustWard bu işlemi yapmaz");
    expect(screen.getByText("SİMÜLE RET")).toBeInTheDocument();
  });

  it("states plainly when the policy cannot be read (not on Windows)", async () => {
    setup("readiness", { readinessInspection: false });
    expect(await screen.findByTestId("inspection-error")).toHaveTextContent("Politika okunamadı: policy inspection requires Windows");
    expect(screen.getByText("Okunamadı")).toBeInTheDocument();
  });
});
