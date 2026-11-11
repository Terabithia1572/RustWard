import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Api } from "../api/client";
import { DenialNotifier } from "../components/Notifier";
import { I18nProvider } from "../i18n";
import { ApiProvider } from "../lib/hooks";
import { device, fakeBackend } from "./fakeBackend";

function mount(enabled: boolean) {
  const fake = fakeBackend();
  render(
    <ApiProvider api={new Api(fake.backend)}>
      <I18nProvider lang="tr">
        <DenialNotifier enabled={enabled} pollMs={40} />
      </I18nProvider>
    </ApiProvider>,
  );
  return fake;
}

const dashboardCalls = (calls: { type: string }[]) => calls.filter((c) => c.type === "get_dashboard").length;

describe("DenialNotifier", () => {
  it("does not notify for devices that were already denied when the window opened", async () => {
    const { state } = mount(true);
    await waitFor(() => expect(dashboardCalls(state.calls)).toBeGreaterThanOrEqual(3));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("notifies once per new simulated denial with honest wording, and can be dismissed", async () => {
    const { state } = mount(true);
    await waitFor(() => expect(dashboardCalls(state.calls)).toBeGreaterThanOrEqual(1));
    state.devices.push(device({ device_key: "k-new", vendor: "Kingston", product: "DataTraveler" }));
    const notice = await screen.findByRole("status");
    expect(notice).toHaveTextContent("UYARI: Yasaklı USB depolama aygıtı erişilebilir: Kingston DataTraveler.");
    expect(notice).toHaveTextContent("Windows engellemesi doğrulanamadı");
    expect(notice.textContent).not.toMatch(/engellendi|engellenmiştir/i);
    const before = dashboardCalls(state.calls);
    await waitFor(() => expect(dashboardCalls(state.calls)).toBeGreaterThan(before + 2));
    expect(screen.getAllByRole("status")).toHaveLength(1);
    await userEvent.setup().click(screen.getByRole("button", { name: "Bildirimi kapat" }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("ignores simulated allows and does not poll when notifications are disabled", async () => {
    const enabled = mount(true);
    await waitFor(() => expect(dashboardCalls(enabled.state.calls)).toBeGreaterThanOrEqual(1));
    enabled.state.devices.push(device({ device_key: "k-ok", simulated_decision: "allow" }));
    await waitFor(() => expect(dashboardCalls(enabled.state.calls)).toBeGreaterThanOrEqual(4));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("makes no requests when disabled", async () => {
    const { state } = mount(false);
    await new Promise((r) => setTimeout(r, 150));
    expect(dashboardCalls(state.calls)).toBe(0);
  });
});
