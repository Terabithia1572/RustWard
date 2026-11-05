import type { SettingsView } from "../api/types";

const KEY = "rustward.ui.prefs";

export interface CachedPrefs {
  theme: SettingsView["theme"];
  language: SettingsView["language"];
}

/** Per-viewer cache of theme/language for the first paint only. The
 * authoritative settings live in the backend database. */
export function readCachedPrefs(): CachedPrefs {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (raw) {
      const p = JSON.parse(raw) as Partial<CachedPrefs>;
      return {
        theme: p.theme === "light" || p.theme === "dark" ? p.theme : "system",
        language: p.language === "en" ? "en" : "tr",
      };
    }
  } catch {
    /* storage unavailable */
  }
  return { theme: "system", language: "tr" };
}

export function writeCachedPrefs(p: CachedPrefs): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    /* storage unavailable */
  }
}

export function applyTheme(theme: SettingsView["theme"]): void {
  const dark =
    theme === "dark" ||
    (theme === "system" && typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
}
