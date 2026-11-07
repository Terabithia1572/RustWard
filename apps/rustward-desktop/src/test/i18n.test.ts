import { describe, expect, it } from "vitest";
import { en } from "../i18n/en";
import { tr } from "../i18n/tr";
import { translate } from "../i18n";

const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe("i18n", () => {
  it("English has exactly the Turkish keys", () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(tr).sort());
  });

  it("no translation is empty and placeholders match", () => {
    for (const [k, v] of Object.entries(tr)) {
      const e = (en as Record<string, string>)[k] ?? "";
      expect(v.trim(), k).not.toBe("");
      expect(e.trim(), k).not.toBe("");
      expect(placeholders(e), k).toEqual(placeholders(v));
    }
  });

  it("carries the mandated not-validated sentence verbatim", () => {
    expect(tr["banner.notValidated"]).toBe("Koruma henüz gerçek Windows ortamında doğrulanmadı.");
    expect(tr["banner.notActivated"]).toBe("USB koruması henüz etkinleştirilmemiştir.");
  });

  it("never claims that a device was actually blocked (except the evidence-gated notice)", () => {
    // notify.realBlocked is shown only by the notifier, for a connected device
    // whose installation Windows currently denies (see observation.test.tsx).
    const EVIDENCE_GATED = new Set(["notify.realBlocked"]);
    const forbidden = [/engellendi/i, /engellenmiştir/i, /\bblocked by rustward\b/i, /\bwas blocked\b/i, /\bprotected\b(?! by)/i];
    for (const [k, v] of [...Object.entries(tr), ...Object.entries(en)]) {
      if (EVIDENCE_GATED.has(k)) continue;
      for (const f of forbidden) expect(f.test(v), `${k}: ${v}`).toBe(false);
    }
    expect(tr["notify.realBlocked"]).toBe("USB engellenmiştir. İşlem kayıt altına alınmıştır.");
  });

  it("interpolates parameters", () => {
    expect(translate("tr", "common.policyVersion", { version: 7 })).toBe("Politika v7");
  });
});
