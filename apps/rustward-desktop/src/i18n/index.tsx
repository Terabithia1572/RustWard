import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";
import { en } from "./en";
import { tr, type TKey } from "./tr";

export type Lang = "tr" | "en";

const dictionaries: Record<Lang, Record<TKey, string>> = { tr, en };

export type Translate = (key: TKey, params?: Record<string, string | number>) => string;

interface I18n {
  lang: Lang;
  t: Translate;
  /** Translate a dynamic key (category/reason codes) with a fallback. */
  tx: (prefix: string, code: string) => string;
  formatTime: (ms: number | null | undefined) => string;
  /** Backend text: the Turkish rendering in Turkish mode (English otherwise or when absent). */
  pick: (en: string, tr?: string | null) => string;
  /** Backend list: the Turkish rendering in Turkish mode when it has the same length. */
  pickList: (en: string[], tr?: string[] | null) => string[];
}

export function translate(lang: Lang, key: TKey, params?: Record<string, string | number>): string {
  let s = dictionaries[lang][key];
  if (params) {
    for (const [k, v] of Object.entries(params)) s = s.replaceAll(`{${k}}`, String(v));
  }
  return s;
}

function isKey(k: string): k is TKey {
  return Object.prototype.hasOwnProperty.call(tr, k);
}

const I18nContext = createContext<I18n | null>(null);

export function I18nProvider({ lang, children }: { lang: Lang; children: ReactNode }) {
  const t = useCallback<Translate>((key, params) => translate(lang, key, params), [lang]);
  const value = useMemo<I18n>(() => {
    const fmt = new Intl.DateTimeFormat(lang === "tr" ? "tr-TR" : "en-GB", {
      dateStyle: "short",
      timeStyle: "medium",
    });
    return {
      lang,
      t,
      tx: (prefix, code) => {
        const k = `${prefix}.${code}`;
        return isKey(k) ? t(k) : code;
      },
      formatTime: (ms) => (ms === null || ms === undefined ? "—" : fmt.format(new Date(ms))),
      pick: (enText, trText) => (lang === "tr" && trText ? trText : enText),
      pickList: (enList, trList) => (lang === "tr" && trList && trList.length === enList.length ? trList : enList),
    };
  }, [lang, t]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18n {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n outside I18nProvider");
  return ctx;
}
