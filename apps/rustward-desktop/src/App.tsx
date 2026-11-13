import { useCallback, useEffect, useRef, useState, type ComponentType } from "react";
import {
  Activity,
  Ban,
  Cpu,
  Factory,
  ClipboardCheck,
  Info,
  LayoutDashboard,
  Lock,
  LogOut,
  Power,
  ScrollText,
  Settings as SettingsIcon,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  Usb,
} from "lucide-react";
import type { Api } from "./api/client";
import type { AuthStatusView, LoginResultView, SettingsView } from "./api/types";
import { AuthScreen, ExitAuthorizationDialog, RecoveryKeyOnceDialog } from "./components/AuthGate";
import { ConnectionBar } from "./components/ConnectionBar";
import { DenialNotifier } from "./components/Notifier";
import { Badge, Button } from "./components/ui";
import { I18nProvider, translate, useI18n, type Lang } from "./i18n";
import type { TKey } from "./i18n/tr";
import { ApiProvider, AuthProvider, useAuth, useResource } from "./lib/hooks";
import { DeviceWatchProvider, WATCH_POLL_MS, useDeviceEpoch } from "./lib/watch";
import { applyTheme, readCachedPrefs, writeCachedPrefs } from "./lib/prefs";
import { AboutPage } from "./pages/About";
import { AuditPage } from "./pages/Audit";
import { BlockedPage } from "./pages/Blocked";
import { DashboardPage } from "./pages/Dashboard";
import { DevicesPage } from "./pages/Devices";
import { DiagnosticsPage } from "./pages/Diagnostics";
import { ManufacturersPage } from "./pages/Manufacturers";
import { ReadinessPage } from "./pages/Readiness";
import { SettingsPage } from "./pages/Settings";

export type PageId =
  | "dashboard"
  | "devices"
  | "manufacturers"
  | "blocked"
  | "audit"
  | "readiness"
  | "diagnostics"
  | "settings"
  | "about";

const NAV: { id: PageId; label: TKey; icon: ComponentType<{ className?: string }> }[] = [
  { id: "dashboard", label: "nav.dashboard", icon: LayoutDashboard },
  { id: "devices", label: "nav.devices", icon: Usb },
  { id: "manufacturers", label: "nav.manufacturers", icon: Factory },
  { id: "blocked", label: "nav.blocked", icon: Ban },
  { id: "audit", label: "nav.audit", icon: ScrollText },
  { id: "diagnostics", label: "nav.diagnostics", icon: Activity },
  { id: "readiness", label: "nav.readiness", icon: ClipboardCheck },
  { id: "settings", label: "nav.settings", icon: SettingsIcon },
  { id: "about", label: "nav.about", icon: Info },
];

function Shell({
  page,
  setPage,
  settings,
  onSettings,
  onLock,
  onLogout,
  onOpenExit,
}: {
  page: PageId;
  setPage: (p: PageId) => void;
  settings: SettingsView | null;
  onSettings: (s: SettingsView) => void;
  onLock: () => Promise<void>;
  onLogout: () => Promise<void>;
  onOpenExit: () => void;
}) {
  const { lang, t } = useI18n();
  const auth = useAuth();
  const epoch = useDeviceEpoch();
  const dashRes = useResource((api) => api.dashboard(), `shell-dash-${epoch}`);
  const d = dashRes.data;
  const cat = d?.protection_category;
  const gpoVerified = d?.protection_verified === true || cat === "protection_active" || cat === "policy_applied_no_target";
  const gpoPartial = !gpoVerified && cat === "protection_partial";
  const isReadOnly = Boolean(auth?.auth_enforced && auth.authenticated && auth.current_user?.role === "read_only");

  return (
    <div className="flex h-full min-h-0">
      <nav
        aria-label="RustWard"
        className="flex w-56 shrink-0 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex items-center gap-2 px-4 py-4">
          <ShieldHalf className="size-6 text-cyan-600 dark:text-cyan-400" aria-hidden />
          <div>
            <div className="text-base font-semibold tracking-tight">{t("app.name")}</div>
            <div className="text-[11px] leading-tight text-slate-500 dark:text-slate-400">{t("app.tagline")}</div>
          </div>
        </div>
        <ul className="flex-1 space-y-0.5 px-2">
          {NAV.map(({ id, label, icon: Icon }) => (
            <li key={id}>
              <button
                type="button"
                aria-current={page === id ? "page" : undefined}
                onClick={() => setPage(id)}
                className={`flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-cyan-500 ${
                  page === id
                    ? "bg-cyan-50 font-medium text-cyan-800 dark:bg-cyan-950 dark:text-cyan-200"
                    : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                }`}
              >
                <Icon className="size-4" aria-hidden />
                {t(label)}
              </button>
            </li>
          ))}
        </ul>
        <div className="flex items-center gap-2 border-t border-slate-200 px-4 py-3 text-[11px] text-slate-500 dark:border-slate-800 dark:text-slate-400">
          {gpoVerified ? (
            <ShieldCheck className="size-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden />
          ) : (
            <Cpu className="size-3.5" aria-hidden />
          )}
          {gpoVerified
            ? cat === "policy_applied_no_target"
              ? t("dash.cat.policy_applied_no_target")
              : "GPO Koruma Etkin"
            : gpoPartial
              ? t("dash.cat.protection_partial")
              : `${t("badge.simulated")} · ${t("badge.notVerified")}`}
        </div>
      </nav>
      <main className="min-w-0 flex-1 overflow-y-auto">
        {!gpoVerified && !gpoPartial && (
          <div
            role="status"
            data-testid="not-activated-warning"
            className="sticky top-0 z-10 flex items-center gap-2 border-b border-amber-300 bg-amber-100 px-6 py-2 text-sm font-semibold text-amber-950 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100"
          >
            <ShieldAlert className="size-4 shrink-0" aria-hidden />
            {translate("tr", "banner.notActivated")}
            {lang !== "tr" && <span className="font-normal opacity-90">({t("banner.notActivated")})</span>}
          </div>
        )}
        {gpoPartial && (
          <div
            role="status"
            data-testid="partial-protection-banner"
            className="sticky top-0 z-10 flex items-center gap-2 border-b border-cyan-300 bg-cyan-50 px-6 py-2 text-sm font-semibold text-cyan-950 dark:border-cyan-800 dark:bg-cyan-950 dark:text-cyan-100"
          >
            <ShieldAlert className="size-4 shrink-0" aria-hidden />
            {t("dash.cat.protection_partial")}
          </div>
        )}
        <ConnectionBar />
        {auth?.auth_enforced && auth.authenticated && auth.current_user && (
          <div
            role="region"
            aria-label="Session bar"
            data-testid="session-bar"
            className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 bg-slate-50 px-6 py-1.5 text-xs dark:border-slate-800 dark:bg-slate-900/70"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-slate-800 dark:text-slate-200">
                {auth.current_user.display_name} ({auth.current_user.username})
              </span>
              <Badge tone={auth.current_user.role === "admin" ? "info" : "warning"}>
                {t(auth.current_user.role === "admin" ? "role.admin" : "role.read_only")}
              </Badge>
              {isReadOnly && (
                <span className="text-amber-800 dark:text-amber-300">
                  {t("auth.readOnlyBanner", { user: auth.current_user.username })}
                </span>
              )}
            </div>
            <div className="flex items-center gap-1.5">
              <Button variant="ghost" icon={<Lock className="size-3.5" aria-hidden />} onClick={() => void onLock()}>
                {t("auth.lockButton")}
              </Button>
              <Button variant="ghost" icon={<LogOut className="size-3.5" aria-hidden />} onClick={() => void onLogout()}>
                {t("auth.logoutButton")}
              </Button>
              <Button variant="ghost" icon={<Power className="size-3.5" aria-hidden />} onClick={onOpenExit}>
                {t("exit.button")}
              </Button>
            </div>
          </div>
        )}
        <div className="mx-auto max-w-[1400px] px-6 py-5">
          {page === "dashboard" && <DashboardPage onNavigate={setPage} />}
          {page === "devices" && <DevicesPage />}
          {page === "manufacturers" && <ManufacturersPage />}
          {page === "blocked" && <BlockedPage />}
          {page === "audit" && <AuditPage />}
          {page === "readiness" && <ReadinessPage />}
          {page === "diagnostics" && <DiagnosticsPage />}
          {page === "settings" && <SettingsPage settings={settings} onSaved={onSettings} />}
          {page === "about" && <AboutPage />}
        </div>
      </main>
      <DenialNotifier enabled={settings?.notifications_enabled ?? false} />
    </div>
  );
}

export function App({ api, initialPage = "dashboard", watchMs = WATCH_POLL_MS }: { api: Api; initialPage?: PageId; watchMs?: number }) {
  const cached = readCachedPrefs();
  const [lang, setLang] = useState<Lang>(cached.language);
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatusView | null>(null);
  const [authLoaded, setAuthLoaded] = useState(false);
  const [pendingRecoveryKey, setPendingRecoveryKey] = useState<string | null>(null);
  const [exitOpen, setExitOpen] = useState(false);
  const [page, setPage] = useState<PageId>(initialPage);

  const lastActivityRef = useRef<number>(Date.now());
  const lastHeartbeatRef = useRef<number>(0);

  const onSettings = useCallback((s: SettingsView) => {
    setSettings(s);
    setLang(s.language);
    applyTheme(s.theme);
    writeCachedPrefs({ theme: s.theme, language: s.language });
  }, []);

  const refreshAuthAndSettings = useCallback(async () => {
    try {
      const status = await api.authStatus();
      setAuthStatus(status);
      if (!status.auth_enforced || (status.authenticated && !status.locked)) {
        try {
          onSettings(await api.settings());
        } catch {
          /* Settings errors are surfaced on the Settings page. */
        }
      }
    } catch {
      /* Service down, not supported in minimal test mocks, or older backend. */
      setAuthStatus(null);
      try {
        onSettings(await api.settings());
      } catch {
        /* Handled by ConnectionBar. */
      }
    } finally {
      setAuthLoaded(true);
    }
  }, [api, onSettings]);

  useEffect(() => {
    applyTheme(cached.theme);
    void refreshAuthAndSettings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api]);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  // Listen for native Tauri window close interception (`WindowEvent::CloseRequested`).
  useEffect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return;
    let unlisten: (() => void) | undefined;
    let mounted = true;
    void import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen("rustward://exit-requested", () => {
          if (mounted) setExitOpen(true);
        }),
      )
      .then((fn) => {
        if (mounted) unlisten = fn;
        else fn();
      })
      .catch(() => {
        /* Ignore outside Tauri event capability. */
      });
    return () => {
      mounted = false;
      unlisten?.();
    };
  }, []);

  // Track interactive activity + enforce idle auto-lock cleanly.
  useEffect(() => {
    if (!authStatus?.auth_enforced || !authStatus.authenticated || authStatus.locked) return;
    lastActivityRef.current = Date.now();
    const bump = () => {
      const now = Date.now();
      lastActivityRef.current = now;
      if (now - lastHeartbeatRef.current >= 30_000) {
        lastHeartbeatRef.current = now;
        void api
          .heartbeatSession()
          .then((next) => {
            if (next.locked || !next.authenticated) setAuthStatus(next);
          })
          .catch(() => {});
      }
    };
    const events: (keyof WindowEventMap)[] = ["mousemove", "keydown", "pointerdown", "focus"];
    for (const ev of events) window.addEventListener(ev, bump, { passive: true });
    const idleMs = Math.max(1, authStatus.idle_timeout_minutes || 15) * 60_000;
    const timer = window.setInterval(() => {
      if (Date.now() - lastActivityRef.current >= idleMs) {
        void api
          .lockSession()
          .then(setAuthStatus)
          .catch(() => {});
      }
    }, Math.min(30_000, idleMs));
    return () => {
      for (const ev of events) window.removeEventListener(ev, bump);
      window.clearInterval(timer);
    };
  }, [api, authStatus?.auth_enforced, authStatus?.authenticated, authStatus?.locked, authStatus?.idle_timeout_minutes]);

  const needsAuthScreen =
    authLoaded &&
    Boolean(authStatus?.auth_enforced) &&
    Boolean(authStatus?.setup_required || !authStatus?.authenticated || authStatus?.locked);

  const handleAuthenticated = async (loginRes?: LoginResultView) => {
    if (loginRes?.recovery_key_once) {
      setPendingRecoveryKey(loginRes.recovery_key_once);
    }
    await refreshAuthAndSettings();
  };

  return (
    <ApiProvider api={api}>
      <AuthProvider auth={authStatus}>
        <DeviceWatchProvider pollMs={watchMs}>
          <I18nProvider lang={lang}>
            {pendingRecoveryKey && (
              <RecoveryKeyOnceDialog
                recoveryKey={pendingRecoveryKey}
                onAcknowledge={() => setPendingRecoveryKey(null)}
              />
            )}
            <ExitAuthorizationDialog
              open={exitOpen}
              defaultUsername={authStatus?.current_user?.role === "admin" ? authStatus.current_user.username : "admin"}
              onClose={() => setExitOpen(false)}
              onAuthorized={() => setExitOpen(false)}
            />
            {needsAuthScreen && authStatus ? (
              <AuthScreen status={authStatus} onAuthenticated={handleAuthenticated} />
            ) : (
              <Shell
                page={page}
                setPage={setPage}
                settings={settings}
                onSettings={onSettings}
                onLock={async () => {
                  setAuthStatus(await api.lockSession());
                }}
                onLogout={async () => {
                  setAuthStatus(await api.logout());
                }}
                onOpenExit={() => setExitOpen(true)}
              />
            )}
          </I18nProvider>
        </DeviceWatchProvider>
      </AuthProvider>
    </ApiProvider>
  );
}
