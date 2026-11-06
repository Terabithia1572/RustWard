import { useCallback, useEffect, useState, type ComponentType } from "react";
import {
  Activity,
  Ban,
  Cpu,
  Factory,
  ClipboardCheck,
  LayoutDashboard,
  ScrollText,
  Settings as SettingsIcon,
  ShieldHalf,
  Usb,
} from "lucide-react";
import type { Api } from "./api/client";
import type { SettingsView } from "./api/types";
import { DenialNotifier } from "./components/Notifier";
import { I18nProvider, useI18n, type Lang } from "./i18n";
import type { TKey } from "./i18n/tr";
import { ApiProvider } from "./lib/hooks";
import { applyTheme, readCachedPrefs, writeCachedPrefs } from "./lib/prefs";
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
  | "settings";

const NAV: { id: PageId; label: TKey; icon: ComponentType<{ className?: string }> }[] = [
  { id: "dashboard", label: "nav.dashboard", icon: LayoutDashboard },
  { id: "devices", label: "nav.devices", icon: Usb },
  { id: "manufacturers", label: "nav.manufacturers", icon: Factory },
  { id: "blocked", label: "nav.blocked", icon: Ban },
  { id: "audit", label: "nav.audit", icon: ScrollText },
  { id: "readiness", label: "nav.readiness", icon: ClipboardCheck },
  { id: "diagnostics", label: "nav.diagnostics", icon: Activity },
  { id: "settings", label: "nav.settings", icon: SettingsIcon },
];

function Shell({
  page,
  setPage,
  settings,
  onSettings,
}: {
  page: PageId;
  setPage: (p: PageId) => void;
  settings: SettingsView | null;
  onSettings: (s: SettingsView) => void;
}) {
  const { t } = useI18n();
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
          <Cpu className="size-3.5" aria-hidden />
          {t("badge.simulated")} · {t("badge.notVerified")}
        </div>
      </nav>
      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1400px] px-6 py-5">
          {page === "dashboard" && <DashboardPage onNavigate={setPage} />}
          {page === "devices" && <DevicesPage />}
          {page === "manufacturers" && <ManufacturersPage />}
          {page === "blocked" && <BlockedPage />}
          {page === "audit" && <AuditPage />}
          {page === "readiness" && <ReadinessPage />}
          {page === "diagnostics" && <DiagnosticsPage />}
          {page === "settings" && <SettingsPage settings={settings} onSaved={onSettings} />}
        </div>
      </main>
      <DenialNotifier enabled={settings?.notifications_enabled ?? false} />
    </div>
  );
}

export function App({ api, initialPage = "dashboard" }: { api: Api; initialPage?: PageId }) {
  const cached = readCachedPrefs();
  const [lang, setLang] = useState<Lang>(cached.language);
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [page, setPage] = useState<PageId>(initialPage);

  const onSettings = useCallback((s: SettingsView) => {
    setSettings(s);
    setLang(s.language);
    applyTheme(s.theme);
    writeCachedPrefs({ theme: s.theme, language: s.language });
  }, []);

  useEffect(() => {
    applyTheme(cached.theme);
    api
      .settings()
      .then(onSettings)
      .catch(() => {
        /* Settings errors are shown on the Settings page; keep cached prefs. */
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api]);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  return (
    <ApiProvider api={api}>
      <I18nProvider lang={lang}>
        <Shell page={page} setPage={setPage} settings={settings} onSettings={onSettings} />
      </I18nProvider>
    </ApiProvider>
  );
}
