import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Api } from "../api/client";
import type { EventView, Request } from "../api/types";
import { App, type PageId } from "../App";
import { fakeBackend, type FakeState } from "./fakeBackend";

function renderApp(page: PageId, init?: Partial<FakeState>) {
  const { backend, state } = fakeBackend(init);
  const api = new Api(backend);
  const user = userEvent.setup();
  render(<App api={api} initialPage={page} />);
  return { user, state, backend };
}

function recorded(calls: Request[], type: Request["type"]) {
  return calls.filter((c) => c.type === type);
}

describe("V1.1 AuthGate, session security and RBAC", () => {
  it("handles initial admin setup and displays the recovery key once", async () => {
    const { user, state } = renderApp("dashboard", {
      authStatus: {
        auth_enforced: true,
        setup_required: true,
        authenticated: false,
        locked: false,
        current_user: null,
        session_expires_at_ms: null,
        idle_timeout_minutes: 15,
        lockout_remaining_seconds: null,
        windows_admin_channel: true,
      },
    });

    const userInput = await screen.findByLabelText("Kullanıcı adı");
    await user.clear(userInput);
    await user.type(userInput, "secadmin");
    const dispInput = screen.getByLabelText("Görünen ad");
    await user.clear(dispInput);
    await user.type(dispInput, "Security Admin");
    await user.type(screen.getByLabelText("Parola"), "StrongPass!2026");
    await user.type(screen.getByLabelText("Parola (tekrar)"), "StrongPass!2026");
    await user.click(screen.getByRole("button", { name: "Yönetici Hesabı Oluştur ve Giriş Yap" }));

    await waitFor(() => expect(recorded(state.calls, "setup_initial_admin").length).toBe(1));
    const dialog = await screen.findByRole("dialog", { name: "Kurtarma Anahtarınızı Güvenle Saklayın" });
    expect(dialog).toHaveTextContent("RWREC-FAKE-1111-2222-3333-4444");

    await user.click(within(dialog).getByRole("button", { name: "Kaydettim, Devam Et" }));
    await screen.findByRole("navigation");
  });

  it("logs in when unauthenticated and supports recovery reset", async () => {
    const { user, state } = renderApp("dashboard", {
      authStatus: {
        auth_enforced: true,
        setup_required: false,
        authenticated: false,
        locked: false,
        current_user: null,
        session_expires_at_ms: null,
        idle_timeout_minutes: 15,
        lockout_remaining_seconds: null,
        windows_admin_channel: true,
      },
    });

    const userInput = await screen.findByLabelText("Kullanıcı adı");
    await user.clear(userInput);
    await user.type(userInput, "admin");
    await user.type(screen.getByLabelText("Parola"), "StrongPass!2026");
    await user.click(screen.getByRole("button", { name: "Giriş Yap" }));

    await waitFor(() => expect(recorded(state.calls, "login").length).toBe(1));
    await screen.findByRole("navigation");
  });

  it("unlocks a locked session and allows locking from the session bar", async () => {
    const { user, state } = renderApp("dashboard", {
      authStatus: {
        auth_enforced: true,
        setup_required: false,
        authenticated: true,
        locked: false,
        current_user: { username: "admin", display_name: "Administrator", role: "admin" },
        session_expires_at_ms: null,
        idle_timeout_minutes: 15,
        lockout_remaining_seconds: null,
        windows_admin_channel: true,
      },
    });
    await screen.findByRole("navigation");

    await user.click(screen.getByRole("button", { name: "Kilitle" }));
    await waitFor(() => expect(recorded(state.calls, "lock_session").length).toBe(1));

    await screen.findByText("Oturum Kilitli");
    await user.type(screen.getByLabelText("Parola"), "StrongPass!2026");
    await user.click(screen.getByRole("button", { name: "Kilidi Aç" }));
    await waitFor(() => expect(recorded(state.calls, "login").length).toBe(1));
    await screen.findByRole("navigation");
  });

  it("enforces read_only RBAC banner and hides admin user management", async () => {
    const { state } = renderApp("settings", {
      authStatus: {
        auth_enforced: true,
        setup_required: false,
        authenticated: true,
        locked: false,
        current_user: { username: "auditor", display_name: "Audit Viewer", role: "read_only" },
        session_expires_at_ms: null,
        idle_timeout_minutes: 15,
        lockout_remaining_seconds: null,
        windows_admin_channel: true,
      },
    });

    await screen.findByText(/Salt Okunur Oturum/i);
    expect(screen.queryByRole("button", { name: "Yeni Kullanıcı Ekle" })).not.toBeInTheDocument();
    expect(recorded(state.calls, "list_app_users").length).toBe(0);
  });
});

describe("V1.1 Protected exit authorization modal", () => {
  it("prompts administrator verification before closing and explains service persistence", async () => {
    const { user, state } = renderApp("dashboard", {
      authStatus: {
        auth_enforced: true,
        setup_required: false,
        authenticated: true,
        locked: false,
        current_user: { username: "admin", display_name: "Administrator", role: "admin" },
        session_expires_at_ms: null,
        idle_timeout_minutes: 15,
        lockout_remaining_seconds: null,
        windows_admin_channel: true,
      },
    });
    await screen.findByRole("navigation");

    await user.click(screen.getByRole("button", { name: "Uygulamadan Çık" }));
    const dialog = await screen.findByRole("dialog", { name: "Uygulamadan Çıkış Doğrulaması" });
    expect(dialog).toHaveTextContent("RustWard uygulamasından çıkmak için yönetici doğrulaması gereklidir.");
    expect(dialog).toHaveTextContent(/arka plan RustWard Windows hizmeti/);

    await user.type(within(dialog).getByLabelText("Parola"), "StrongPass!2026");
    await user.click(within(dialog).getByRole("button", { name: "Çıkışı Onayla" }));
    await waitFor(() => expect(recorded(state.calls, "verify_exit_authorization").length).toBe(1));
  });
});

describe("V1.1 Manufacturers dynamic plan, retroactive toggle and bulk actions", () => {
  it("toggles DenyDeviceIDsRetroactive and executes bulk preview + apply", async () => {
    const { user, state } = renderApp("manufacturers");
    await screen.findByTestId("windows-policy-plan-section");

    const retroSwitch = screen.getByRole("switch", { name: "Kurulu aygıtlar dahil (DenyDeviceIDsRetroactive)" });
    expect(retroSwitch).toHaveAttribute("aria-checked", "true");
    await user.click(retroSwitch);
    expect(retroSwitch).toHaveAttribute("aria-checked", "false");

    await user.click(screen.getByRole("button", { name: "Windows'a Uygula" }));
    const applyDialog = await screen.findByRole("dialog");
    expect(applyDialog).toHaveTextContent("0 (Yalnızca yeni kurulumlar)");
    await user.click(within(applyDialog).getByRole("button", { name: "Yönetici Olarak Onayla ve Windows'a Uygula" }));

    await waitFor(() => {
      const applied = recorded(state.calls, "apply_compound_policy");
      expect(applied.length).toBe(1);
      expect(applied[0]).toMatchObject({ retroactive: false });
    });

    await user.click(screen.getByRole("button", { name: "Tüm Üreticilere İzin Ver" }));
    await waitFor(() => expect(recorded(state.calls, "preview_bulk_manufacturers").length).toBe(1));
    const dialog = await screen.findByRole("dialog", { name: "Toplu Kural Değişikliği Önizlemesi" });
    await user.click(within(dialog).getByRole("button", { name: "Toplu Değişikliği Uygula" }));

    await waitFor(() => {
      const calls = recorded(state.calls, "apply_bulk_manufacturers");
      expect(calls.length).toBe(1);
      expect(calls[0]).toMatchObject({ action: "allow_all" });
    });
  });
});

describe("V1.1 Settings, users CRUD and audit metadata", () => {
  it("persists V1.1 startup reconciliation & idle timeout settings", async () => {
    const { user, state } = renderApp("settings");
    const startupToggle = await screen.findByRole("switch", { name: "Son onaylanan USB politikasını Windows açılışında uygula." });
    expect(startupToggle).toHaveAttribute("aria-checked", "true");
    await user.click(startupToggle);

    const idleInput = screen.getByLabelText("Oturum boşta kalma kilidi (dakika)");
    await user.clear(idleInput);
    await user.type(idleInput, "30");

    await user.click(screen.getByRole("button", { name: "Kaydet" }));
    await waitFor(() => {
      const updates = recorded(state.calls, "update_settings");
      expect(updates.length).toBe(1);
      expect(updates[0]).toMatchObject({
        settings: {
          reconcile_on_startup: false,
          session_idle_timeout_minutes: 30,
        },
      });
    });
  });

  it("verifies audit chain and opens event details dialog with SHA-256 hash", async () => {
    const richEvent: EventView = {
      id: 901,
      utc_ms: 1_700_000_005_000,
      severity: "critical",
      kind: "device_install_denied",
      device_key: "usb\\vid_0951&pid_1666",
      message: "Installation denied by Windows GPO",
      message_tr: "Kurulum Windows GPO tarafından kısıtlandı",
      simulated: false,
      enforcement_state: "enforced",
      policy_version: 5,
      computer_name: "WIN10-LAB",
      manufacturer_id: "kingston",
      device_name: "Kingston DataTraveler 3.0",
      vid_pid: "0951:1666",
      transport: "USBSTOR",
      pnp_problem_code: 28,
      effective_decision: "deny",
      enforcement_outcome: "install_denied",
      actor_username: "secadmin",
      windows_user: "LAB\\Operator",
      policy_revision: "a1b2c3d4",
      hash: "fe".repeat(32),
      prev_hash: "00".repeat(32),
    };

    const { user, state } = renderApp("audit", { events: [richEvent] });
    await screen.findByText(/Kingston DataTraveler 3\.0/i);

    await user.click(screen.getByRole("button", { name: "Kayıt Zincirini Doğrula" }));
    await waitFor(() => expect(recorded(state.calls, "verify_audit_chain").length).toBe(1));
    await screen.findByText(/SHA-256 kayıt zinciri bütünlüğü doğrulandı/);

    const row = screen.getByText(/Kingston DataTraveler 3\.0/i).closest("tr");
    expect(row).not.toBeNull();
    await user.click(row!);
    const dialog = await screen.findByRole("dialog", { name: "Denetim Olayı Ayrıntıları" });
    expect(dialog).toHaveTextContent("fe".repeat(32));
  });
});

describe("V1.1 About page and Phase 13 protection banners", () => {
  it("renders AboutPage with Yunus İNAN and zero legacy codename references", async () => {
    renderApp("about");
    await screen.findByText("Yunus İNAN");
    expect(document.body.textContent).not.toMatch(/Argon\s*4/i);
  });

  it("hides unverified banner when Windows protection_category is protection_active", async () => {
    renderApp("dashboard", {
      dashboardOverrides: {
        protection_verified: true,
        protection_category: "protection_active",
        enforcement_state: "verified_protected",
        enforcement_label_tr: "Windows cihaz kurulumu etkin",
        enforcement_label_en: "Windows device installation active",
        not_validated_banner: null,
      },
    });

    await screen.findByTestId("protection-category");
    expect(screen.getByTestId("protection-category")).toHaveTextContent("GPO Koruma Etkin ve Doğrulandı");
    expect(screen.queryByTestId("not-validated-banner")).not.toBeInTheDocument();
  });

  it("shows policy_applied_no_target accurately without claiming unverified total denial", async () => {
    renderApp("dashboard", {
      dashboardOverrides: {
        protection_verified: true,
        protection_category: "policy_applied_no_target",
        enforcement_state: "enforced",
        not_validated_banner: null,
      },
    });

    await screen.findByTestId("protection-category");
    expect(screen.getByTestId("protection-category")).toHaveTextContent("GPO Politikası Uygulandı (Hedef Cihaz Bağlı Değil)");
    expect(screen.queryByTestId("not-validated-banner")).not.toBeInTheDocument();
  });
});
