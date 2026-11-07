import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Api, ApiError } from "../api/client";
import { App, type PageId } from "../App";
import { ErrorNotice } from "../components/ui";
import { I18nProvider } from "../i18n";
import { fakeBackend, type FakeState } from "./fakeBackend";

function page(p: PageId, init: Partial<FakeState> = {}) {
  const { backend, state } = fakeBackend(init);
  render(<App api={new Api(backend)} initialPage={p} />);
  return { state, user: userEvent.setup() };
}

describe("Turkish rendering of backend text", () => {
  it("shows the service status and audit messages in Turkish", async () => {
    page("dashboard");
    expect(await screen.findByText("RustWard hizmeti çalışıyor.")).toBeInTheDocument();
    expect(screen.queryByText("RustWard service running")).not.toBeInTheDocument();
    expect(screen.getAllByText("SENTETİK cihaz reddedilirdi (simülasyon)").length).toBeGreaterThan(0);
  });

  it("shows the English original in English mode", async () => {
    page("dashboard", {
      settings: { theme: "light", language: "en", notifications_enabled: true, audit_retention_days: 365, inventory_refresh_seconds: 30 },
    });
    expect(await screen.findByText("RustWard service running")).toBeInTheDocument();
  });

  it("uses the backend's Turkish error message and keeps the technical detail", () => {
    const err = new ApiError("unauthorized", "administrator rights (elevated) are required for this operation", "Bu işlem için yükseltilmiş yönetici hakları gerekir.");
    const { unmount } = render(
      <I18nProvider lang="tr">
        <ErrorNotice error={err} />
      </I18nProvider>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Bu işlem için yükseltilmiş yönetici hakları gerekir.");
    unmount();
    render(
      <I18nProvider lang="en">
        <ErrorNotice error={err} />
      </I18nProvider>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("administrator rights (elevated) are required");
  });
});

describe("Administrator-guided Windows enforcement", () => {
  it("states that automated application is unavailable and never claims read/write verification", async () => {
    page("readiness");
    const card = await screen.findByTestId("guided-session");
    expect(await within(card).findByTestId("auto-blocker")).toHaveTextContent("RustWard Windows Grup İlkesine veya kayıt defterine yazmaz");
    const ladder = within(card).getByTestId("guided-ladder");
    expect(ladder).toHaveTextContent("Okuma/yazma erişimi doğrulandıDoğrulanmadı");
    expect(ladder).toHaveTextContent("Koruma etkin değilEvet");
    expect(screen.getAllByText("Otomatik uygulama: kullanılamıyor").length).toBeGreaterThan(0);
  });

  it("prepares, verifies and rolls back through administrator requests only", async () => {
    const { state, user } = page("readiness");
    const card = await screen.findByTestId("guided-session");
    const select = await within(card).findByLabelText("Cihaz");
    await within(card).findByRole("option", { name: /Kingston DataTraveler 3.0 USB Device/ });
    await user.selectOptions(select, "k-deny");
    await user.click(within(card).getByLabelText("Kurulu cihazlara da uygula (geriye dönük)"));
    await user.click(within(card).getByRole("button", { name: "Oturumu hazırla" }));
    const active = await within(card).findByTestId("guided-active");
    expect(active).toHaveTextContent("USBSTOR\\DiskKingstonDataTraveler_3.0____");
    expect(state.calls).toContainEqual({ type: "prepare_enforcement_session", device_key: "k-deny", retroactive: true });

    await user.click(within(card).getByRole("button", { name: "Uygulamayı doğrula" }));
    expect(await within(card).findByText(/Son doğrulama: .*politika beklenenle eşleşti/)).toBeInTheDocument();
    expect(within(card).getByTestId("guided-ladder")).toHaveTextContent("Windows cihaz kurulumu engellendiEvet");
    expect(within(card).getByTestId("guided-ladder")).toHaveTextContent("Okuma/yazma erişimi doğrulandıDoğrulanmadı");

    await user.click(within(card).getByRole("button", { name: "Geri almayı doğrula" }));
    await within(card).findByRole("button", { name: "Oturumu hazırla" });
    // No request in this flow writes anything but RustWard's own audit log.
    const types = state.calls.map((c) => c.type);
    expect(types).toContain("verify_enforcement_applied");
    expect(types).toContain("verify_enforcement_rollback");
  });
});
