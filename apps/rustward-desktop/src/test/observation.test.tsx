import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Api } from "../api/client";
import { App, type PageId } from "../App";
import { DenialNotifier } from "../components/Notifier";
import { I18nProvider } from "../i18n";
import { ApiProvider } from "../lib/hooks";
import { deniedKingston, fakeBackend, observation, observed, type FakeState } from "./fakeBackend";

const BLOCKED = "USB engellenmiştir. İşlem kayıt altına alınmıştır.";

function page(p: PageId, init: Partial<FakeState> = {}) {
  const { backend, state } = fakeBackend(init);
  render(<App api={new Api(backend)} initialPage={p} />);
  return { state, user: userEvent.setup() };
}

function notifier(init: Partial<FakeState> = {}) {
  const fake = fakeBackend(init);
  render(
    <ApiProvider api={new Api(fake.backend)}>
      <I18nProvider lang="tr">
        <DenialNotifier enabled pollMs={40} />
      </I18nProvider>
    </ApiProvider>,
  );
  return fake;
}

const obsCalls = (calls: { type: string }[]) => calls.filter((c) => c.type === "get_enforcement_observation").length;

describe("Real Windows observation (Readiness)", () => {
  it("shows the rolled-back state: no rule, accessible, simulated deny only", async () => {
    page("readiness");
    const card = await screen.findByTestId("observation");
    const row = within(card).getByTestId("obs-k-deny");
    expect(row).toHaveTextContent("Kingston DataTraveler 3.0 USB Device");
    expect(row).toHaveTextContent("0951:1666");
    expect(row).toHaveTextContent("USBSTOR\\DiskKingstonDataTraveler_3.0____");
    expect(row).toHaveTextContent("Simülasyonda ret");
    expect(row).toHaveTextContent("Kural uygulanmamış");
    expect(row).toHaveTextContent("Erişilebilir");
    expect(row).toHaveTextContent("Gerçek engel kanıtı yok");
    expect(within(card).getByTestId("obs-k-obs-1")).toHaveTextContent("VendorC");
    expect(card).toHaveTextContent("RustWard bu kısıtlamaları uygulamaz");
    expect(document.body.textContent).not.toContain(BLOCKED);
  });

  it("labels an earlier denial as history, never as a current block", async () => {
    page("readiness", {
      observation: observation([
        observed({ history: { observed_ms: 1_794_047_470_000, problem_code: 1, rule_entry: "USBSTOR\\DiskKingstonDataTraveler_3.0____" }, explanation_tr: "Geçmiş kanıt: ..." }),
      ]),
    });
    const row = await screen.findByTestId("obs-k-deny");
    expect(row).toHaveTextContent(/Geçmiş kanıt .*Kod 1.*şu an engel yok/);
    expect(row).not.toHaveTextContent("Güncel: Windows kurulumu engelledi");
  });

  it("shows a current installation denial precisely, without claiming read/write tests", async () => {
    page("readiness", {
      observation: observation([deniedKingston()], { policy_key_present: true, windows_restrictions_configured: true }),
    });
    const row = await screen.findByTestId("obs-k-deny");
    expect(row).toHaveTextContent("Windows kurulumu engelledi (Kod 28)");
    expect(row).toHaveTextContent("Güncel: Windows kurulumu engelledi");
    expect(row).toHaveTextContent("Okuma/yazma doğrulanmadı");
  });

  it("generates a checklist for the selected device and applies nothing", async () => {
    const { state, user } = page("readiness");
    await screen.findByTestId("checklist");
    await user.click(screen.getByLabelText("Kurulu cihazlara da uygula (geriye dönük)"));
    await user.click(screen.getByRole("button", { name: "Kontrol listesi oluştur" }));
    const text = await screen.findByTestId("checklist-text");
    expect(text).toHaveTextContent("UYGULAMAZ");
    expect(text).toHaveTextContent("USBSTOR\\DiskKingstonDataTraveler_3.0____");
    expect(text).toHaveTextContent("Geriye dönük: evet");
    const req = state.calls.find((c) => c.type === "get_policy_checklist");
    expect(req).toEqual({ type: "get_policy_checklist", device_key: "k-deny", retroactive: true });
    // Only read-only requests were sent by this page.
    expect(state.calls.every((c) => c.type.startsWith("get_") || c.type.startsWith("list_"))).toBe(true);
  });
});

describe("Devices: real Windows status column", () => {
  it("shows Windows policy and device status next to the simulated decision", async () => {
    page("devices");
    const cells = await screen.findAllByTestId("windows-status");
    expect(cells[0]).toHaveTextContent("Windows politikası: Kural uygulanmamış");
    expect(cells[0]).toHaveTextContent("Gerçek cihaz durumu: Erişilebilir");
    expect(screen.getByRole("columnheader", { name: "Gerçek Windows durumu" })).toBeInTheDocument();
  });
});

describe("Real blocked notice", () => {
  it("is shown only for a connected device whose installation Windows currently denies", async () => {
    const { state } = notifier();
    await waitFor(() => expect(obsCalls(state.calls)).toBeGreaterThanOrEqual(2));
    expect(screen.queryByText(BLOCKED)).not.toBeInTheDocument();
    state.observation = observation([deniedKingston()], { windows_restrictions_configured: true });
    expect(await screen.findByText(BLOCKED)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Kod 28");
    expect(screen.getByRole("status")).toHaveTextContent("okuma/yazma yolları ayrıca test edilmedi");
    const before = obsCalls(state.calls);
    await waitFor(() => expect(obsCalls(state.calls)).toBeGreaterThan(before + 2));
    expect(screen.getAllByText(BLOCKED)).toHaveLength(1);
  });

  it("is never shown for history, a disconnected device or a rule without denial", async () => {
    const { state } = notifier();
    await waitFor(() => expect(obsCalls(state.calls)).toBeGreaterThanOrEqual(1));
    state.observation = observation([
      observed({ history: { observed_ms: 1, problem_code: 28, rule_entry: "x" } }),
      { ...deniedKingston(), present: false, evidence: "policy_only" },
      observed({ windows_rule: { outcome: "prevented", rule: { layer: "device_id", list: "DenyDeviceIDs", entry: "x" } }, evidence: "policy_only" }),
    ]);
    const before = obsCalls(state.calls);
    await waitFor(() => expect(obsCalls(state.calls)).toBeGreaterThan(before + 3));
    expect(screen.queryByText(BLOCKED)).not.toBeInTheDocument();
  });

  it("shows a denial newly observed by the very first poll", async () => {
    notifier({
      observation: observation([deniedKingston()], { newly_observed_denials: ["k-deny"], windows_restrictions_configured: true }),
    });
    expect(await screen.findByText(BLOCKED)).toBeInTheDocument();
  });
});
