// Phase 5: the primary UI reflects real Windows state only.
import { render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Api } from "../api/client";
import { App, type PageId } from "../App";
import { deniedKingston, device, fakeBackend, observation, observed, sessionView, type FakeState } from "./fakeBackend";

const BLOCKED = "USB engellenmiştir. İşlem kayıt altına alınmıştır.";

function page(p: PageId, init: Partial<FakeState> = {}) {
  const { backend, state } = fakeBackend(init);
  render(<App api={new Api(backend)} initialPage={p} />);
  return state;
}

const KINGSTON_RULE = { outcome: "prevented", rule: { layer: "device_id", list: "DenyDeviceIDs", entry: "USBSTOR\\DiskKingstonDataTraveler_3.0____" } } as const;

describe("Dashboard protection status (Koruma durumu)", () => {
  it("is inactive without a Windows rule, even though RustWard simulates a deny", async () => {
    page("dashboard");
    const p = await screen.findByTestId("protection-panel");
    expect(p).toHaveAttribute("data-state", "inactive");
    expect(p).toHaveTextContent("Windows koruması etkin değil");
    expect(p).toHaveTextContent("Gerçek engel kanıtı yok");
    expect(p).toHaveTextContent("Otomatik uygulama: kullanılamıyor");
    expect(screen.getByText("RustWard politika simülasyonu")).toBeInTheDocument();
  });

  it("never shows a block for a configured rule alone", async () => {
    page("dashboard", {
      observation: observation([observed({ windows_rule: KINGSTON_RULE, states: ["SIMULATED_DENY", "WINDOWS_RULE_CONFIGURED"] })], {
        policy_key_present: true,
        windows_restrictions_configured: true,
      }),
    });
    const p = await screen.findByTestId("protection-panel");
    expect(p).toHaveAttribute("data-state", "configured_unverified");
    expect(p).toHaveTextContent("Politika yapılandırılmış, doğrulanmadı");
    expect(p).not.toHaveTextContent("Gerçek Windows kanıtı:");
  });

  it("shows real Windows evidence for an observed installation denial", async () => {
    page("dashboard", {
      observation: observation([deniedKingston()], { policy_key_present: true, windows_restrictions_configured: true }),
    });
    const p = await screen.findByTestId("protection-panel");
    expect(p).toHaveAttribute("data-state", "denial_observed");
    expect(p).toHaveTextContent("Gerçek Windows kanıtı");
    expect(p).toHaveTextContent("1");
  });

  it("is verified only for the target of an administrator-verified session", async () => {
    page("dashboard", {
      observation: observation([deniedKingston()], { policy_key_present: true, windows_restrictions_configured: true }),
      session: sessionView("windows_install_denied", {
        session_id: "s1",
        prepared_ms: 1,
        prepared_by: "VM\\admin",
        device_key: "k-deny",
        device_name: "Kingston DataTraveler 3.0 USB Device",
        hardware_id: "USBSTOR\\DiskKingstonDataTraveler_3.0____",
        retroactive: true,
        baseline: [],
        expected_lines: [],
        last_verification: "enforcement_session_apply_verified",
        last_verification_ms: 2,
      }),
    });
    const p = await screen.findByTestId("protection-panel");
    expect(p).toHaveAttribute("data-state", "verified_active");
    expect(p).toHaveTextContent("yalnızca hedef cihaz");
    expect(p).toHaveTextContent("Okuma/yazma yolları ayrıca doğrulanmadı");
  });

  it("is unknown when the Windows policy cannot be read", async () => {
    page("dashboard", { observation: observation([observed()], { policy_error: "access denied" }) });
    const p = await screen.findByTestId("protection-panel");
    expect(p).toHaveAttribute("data-state", "unknown");
  });
});

describe("Engellenen cihazlar", () => {
  it("lists a real Windows denial separately from simulated decisions", async () => {
    page("blocked", {
      observation: observation([deniedKingston()], { policy_key_present: true, windows_restrictions_configured: true }),
    });
    const real = await screen.findByTestId("real-denied-k-deny");
    expect(real).toHaveTextContent("Kingston DataTraveler 3.0 USB Device");
    expect(real).toHaveTextContent("Güncel: Windows kurulumu engelledi");
    expect(real).toHaveTextContent("Okuma/yazma yolları ayrıca test edilmedi");
    expect(screen.getByText("Simüle edilen retler (uygulanmadı)")).toBeInTheDocument();
    // The page never shows the user notice: that is the notifier's job.
    expect(document.body.textContent).not.toContain(BLOCKED);
  });

  it("does not list a disconnected device as currently denied", async () => {
    page("blocked", {
      observation: observation([{ ...deniedKingston(), present: false }], { policy_key_present: true, windows_restrictions_configured: true }),
    });
    expect(await screen.findByText("Şu an Windows'un kurulumunu reddettiği bağlı cihaz yok.")).toBeInTheDocument();
  });

  it("moves a rolled-back denial into historical denials and separates simulated and unknown-identity sections", async () => {
    page("blocked", {
      devices: [
        device({ device_key: "k-deny", vendor: "Kingston", reason: "brand_denied", matched_brand: "Kingston" }),
        device({ device_key: "k-conflict", vendor: "SanDisk", usb_vid_pid: "0951:1666", reason: "conflicting_identifiers" }),
      ],
      observation: observation([
        observed({
          evidence: "none",
          windows_rule: { outcome: "not_restricted" },
          history: {
            observed_ms: 1_794_047_470_000,
            problem_code: 28,
            rule_entry: "USBSTOR\\DiskKingstonDataTraveler_3.0____",
          },
        }),
      ]),
    });

    const realSec = await screen.findByTestId("blocked-real");
    expect(realSec).toHaveTextContent("Şu an Windows'un kurulumunu reddettiği bağlı cihaz yok.");

    const histSec = screen.getByTestId("blocked-history");
    expect(within(histSec).getByTestId("history-denied-k-deny")).toHaveTextContent("Kingston DataTraveler 3.0 USB Device");
    expect(within(histSec).getByTestId("history-denied-k-deny")).toHaveTextContent("GERİ ALMA TAMAMLANDI");

    const simSec = screen.getByTestId("blocked-sim");
    expect(within(simSec).getAllByText("SIMÜLASYON").length).toBeGreaterThanOrEqual(2);
    expect(within(simSec).getByText("Üretici açıkça reddedildi")).toBeInTheDocument();

    const unkSec = screen.getByTestId("blocked-unknown");
    expect(within(unkSec).getByTestId("unknown-device-k-conflict")).toHaveTextContent(
      "Kimlik çelişkisi (INQUIRY üreticisi ile USB VID farklı)",
    );
    expect(within(unkSec).queryByTestId("unknown-device-k-deny")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(BLOCKED);
  });
});

describe("Devices page identity and real status", () => {
  it("labels the manufacturer as reported, not verified, and shows the last real event", async () => {
    const obs = observation([observed()]);
    obs.devices[0] = { ...obs.devices[0]!, last_event_kind: "device_detected", last_event_ms: 1_794_048_300_000 };
    page("devices", { observation: obs });
    const cell = (await screen.findAllByTestId("manufacturer-cell"))[0]!;
    expect(cell).toHaveTextContent("Bildirilen (doğrulanmamış): EXAMPLEX");
    expect(cell).toHaveTextContent("Kriptografik kimlik doğrulaması yok");
    const last = await screen.findByTestId("last-event");
    expect(last).toHaveTextContent("Son olay: Takıldı");
    const status = within(last.parentElement!);
    expect(status.getByText("USBSTOR\\DiskKingstonDataTraveler_3.0____")).toBeInTheDocument();
  });

  it("renders BOT/UASP transport stack labels and live SetupAPI driver/problem badges", async () => {
    page("devices", {
      devices: [
        device({ device_key: "k-deny", storage_type: "bulk_only" }),
        device({ device_key: "k-obs-1", storage_type: "uasp", simulated_decision: "allow", reason: "brand_allowed" }),
      ],
      observation: observation([
        deniedKingston(),
        observed({ driver_installed: true, problem_code: null }),
      ]),
    });
    expect(await screen.findByText(/BOT \(USBSTOR\)/)).toBeInTheDocument();
    expect(screen.getByText(/UASP \(SCSI\)/)).toBeInTheDocument();
    expect(screen.getByText("Sorun kodu 28")).toBeInTheDocument();
    expect(screen.getByText("Sürücü kurulu")).toBeInTheDocument();
  });
});

describe("Diagnostics performance", () => {
  it("shows service timings and the UI-measured IPC round trip", async () => {
    page("diagnostics");
    const perf = await screen.findByTestId("performance");
    expect(perf).toHaveTextContent("Son envanter okuma (SetupAPI)");
    expect(perf).toHaveTextContent("412 ms");
    expect(perf).toHaveTextContent("1830 ms");
    expect(perf).toHaveTextContent("455 ms");
    expect(perf).toHaveTextContent(/IPC gidiş-dönüş \(arayüz\)\d+ ms \([a-z_]+\) · max \d+ ms/);
  });
});

describe("Real-time updates from Windows events", () => {
  it("re-renders the Devices page when the service reports a removal, without a manual refresh", async () => {
    const { backend, state } = fakeBackend();
    render(<App api={new Api(backend)} initialPage="devices" watchMs={30} />);
    expect((await screen.findAllByText("Bağlı")).length).toBeGreaterThan(0);
    const listCalls = () => state.calls.filter((c) => c.type === "list_devices").length;
    const before = listCalls();
    // Windows removed the Kingston: the service's observation and inventory change.
    state.devices = state.devices.map((d) => (d.device_key === "k-deny" ? { ...d, present: false } : d));
    state.observation = observation([observed({ present: false })]);
    await waitFor(() => expect(listCalls()).toBeGreaterThan(before));
    expect(await screen.findByText("Önceden algılandı")).toBeInTheDocument();
  });

  it("does not reload while nothing changes", async () => {
    const { backend, state } = fakeBackend();
    render(<App api={new Api(backend)} initialPage="devices" watchMs={20} />);
    await screen.findAllByText("Bağlı");
    const obs = () => state.calls.filter((c) => c.type === "get_enforcement_observation").length;
    const start = obs();
    await waitFor(() => expect(obs()).toBeGreaterThan(start + 4));
    expect(state.calls.filter((c) => c.type === "list_devices").length).toBeLessThanOrEqual(2);
  });
});
