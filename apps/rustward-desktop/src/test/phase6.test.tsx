// Phase 6: default-deny assessment, identity confidence and readiness blockers.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Api } from "../api/client";
import { App, type PageId } from "../App";
import { assessment, deniedKingston, fakeBackend, observation, observed, type FakeState } from "./fakeBackend";

const BLOCKED = "USB engellenmiştir. İşlem kayıt altına alınmıştır.";

function page(p: PageId, init: Partial<FakeState> = {}) {
  const { backend, state } = fakeBackend(init);
  render(<App api={new Api(backend)} initialPage={p} watchMs={0} />);
  return state;
}

describe("Dashboard summary and blockers", () => {
  it("counts connected storage and lists what prevents verified protection", async () => {
    page("dashboard", {
      observation: observation([
        observed(),
        observed({
          vid_pid: "346D:5678",
          name: "VendorC ProductCode USB Device",
          assessment: assessment({ policy_category: "UNVERIFIED_IDENTITY", identity: "generic", reported_brand: null }),
        }),
      ]),
    });
    const s = await screen.findByTestId("storage-summary");
    expect(s).toHaveTextContent("Bağlı USB depolama2");
    expect(s).toHaveTextContent("Windows'un reddettiği (doğrulanmış)0");
    expect(s).toHaveTextContent("Kimliği doğrulanamayan1");
    const b = screen.getByTestId("blockers");
    const codes = within(b)
      .getAllByRole("listitem")
      .map((li) => li.getAttribute("data-code"))
      .filter(Boolean);
    expect(codes[0]).toBe("automatic_apply_blocked");
    expect(codes).toContain("no_windows_rule");
    expect(b).toHaveTextContent("ENGELLİ");
    expect(document.body.textContent).not.toContain(BLOCKED);
  });

  it("counts a real Windows denial only for a connected device", async () => {
    page("dashboard", {
      observation: observation([deniedKingston()], { policy_key_present: true, windows_restrictions_configured: true }),
    });
    expect(await screen.findByTestId("storage-summary")).toHaveTextContent("Windows'un reddettiği (doğrulanmış)1");
  });
});

describe("Devices: policy evaluation vs verified outcome", () => {
  it("shows the Phase 6 categories and that identity is self-reported", async () => {
    page("devices", { observation: observation([observed()]) });
    const cell = await screen.findByTestId("assessment");
    expect(cell).toHaveTextContent("Politika değerlendirmesi:Ret adayı");
    expect(cell).toHaveTextContent("Doğrulanmış sonuç:Windows engeli yok");
    expect(cell).toHaveTextContent("SCSI üretici adı ve USB VID uyumlu");
    expect(cell).toHaveTextContent("cihazın kendi bildirimi, doğrulanmış kimlik değil");
    expect(within(cell).getByTitle("DENY_CANDIDATE")).toBeInTheDocument();
  });

  it("marks a verified Windows denial", async () => {
    page("devices", {
      observation: observation([deniedKingston()], { policy_key_present: true, windows_restrictions_configured: true }),
    });
    const cell = await screen.findByTestId("assessment");
    expect(within(cell).getByTitle("WINDOWS_DENIAL_VERIFIED")).toHaveTextContent("Windows reddi doğrulandı");
  });
});

describe("Allowed manufacturers: configured rules are not Windows access", () => {
  it("explains the target policy and supports an explicit deny", async () => {
    const state = page("manufacturers");
    expect(await screen.findByTestId("configured-note")).toHaveTextContent("Bunlar yapılandırılmış RustWard kurallarıdır; Windows erişimi değildir.");
    const toggle = await screen.findByRole("switch", { name: /Açıkça reddet: ExampleX/ });
    fireEvent.click(toggle);
    await waitFor(() => expect(state.calls.some((c) => c.type === "set_manufacturer_denied")).toBe(true));
    expect(await screen.findByText("Açıkça reddedildi")).toBeInTheDocument();
  });
});

describe("Readiness blockers", () => {
  it("lists every blocker with its kind", async () => {
    page("readiness");
    const b = await screen.findByTestId("blockers");
    expect(within(b).getAllByRole("listitem").length).toBeGreaterThanOrEqual(4);
    expect(b).toHaveTextContent("Sınırlama");
    expect(b).toHaveTextContent("Okuma/yazma engeli doğrulanmadı.");
  });
});

describe("Default-deny profile session (administrator-guided)", () => {
  it("prepares the profile without applying anything and shows the checklist", async () => {
    const { backend, state } = fakeBackend();
    render(<App api={new Api(backend)} initialPage="readiness" watchMs={0} />);
    const card = await screen.findByTestId("guided-profile");
    expect(card).toHaveTextContent("Kural geriye dönük değildir");
    fireEvent.click(within(card).getByRole("button", { name: /Varsayılan ret profilini hazırla/ }));
    const text = await screen.findByTestId("guided-profile-checklist");
    expect(text).toHaveTextContent("İŞARETLENMEZ");
    expect(screen.getByText("Varsayılan ret profili oturumu")).toBeInTheDocument();
    // The single-device checklist button is not offered for the profile.
    expect(screen.queryByRole("button", { name: /Kontrol listesini göster/ })).not.toBeInTheDocument();
    expect(state.calls.map((c) => c.type)).toContain("prepare_default_deny_session");
    // Nothing claims a block.
    expect(document.body.textContent).not.toContain("USB engellenmiştir");
  });
});

describe("Removable Storage Access (class-wide, read-only report)", () => {
  it("shows a configured removable-disk read deny as class-wide, not as protection", async () => {
    const obs = observation([observed()]);
    obs.removable_storage = {
      configured: true,
      deny_all: false,
      disks_deny_read: true,
      disks_deny_write: false,
      disks_deny_execute: false,
      other_classes: [],
    };
    page("readiness", { observation: obs });
    const row = await screen.findByTestId("removable-storage");
    expect(row).toHaveTextContent("Çıkarılabilir diskler: okuma reddi");
    expect(row).toHaveTextContent("üretici ayrımı yapamaz");
    expect(document.body.textContent).not.toContain(BLOCKED);
  });

  it("reports not configured by default", async () => {
    page("readiness");
    expect(await screen.findByTestId("removable-storage")).toHaveTextContent("Yapılandırılmamış");
  });
});
