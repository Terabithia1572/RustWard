import { useEffect, useRef, useState } from "react";
import { TriangleAlert, X } from "lucide-react";
import type { DeviceView } from "../api/types";
import { useI18n } from "../i18n";
import { useApi } from "../lib/hooks";

/** Poll interval while the window is open. */
export const NOTIFY_POLL_MS = 15_000;
/** At most this many notices are shown at once. */
export const MAX_NOTICES = 3;

interface Notice {
  key: string;
  label: string;
  /** Real Windows installation denial (current evidence), not a simulation. */
  real?: { code: number };
}

function label(d: DeviceView): string {
  const name = [d.vendor, d.product].filter(Boolean).join(" ");
  return name || d.friendly_name || d.display_id;
}

/**
 * In-app notices for NEW simulated denials. The first poll only records a
 * baseline, so devices seen before the window opened do not pop up.
 *
 * Simulated notices never claim that access was blocked. The
 * "USB engellenmiştir" notice is shown only for a connected device whose
 * installation Windows currently denies (observer evidence), and its detail
 * says that read/write paths were not tested separately.
 */
export function DenialNotifier({ enabled, pollMs = NOTIFY_POLL_MS }: { enabled: boolean; pollMs?: number }) {
  const { t } = useI18n();
  const api = useApi();
  const seen = useRef<Set<string> | null>(null);
  const seenReal = useRef<Set<string> | null>(null);
  const [notices, setNotices] = useState<Notice[]>([]);

  useEffect(() => {
    if (!enabled) {
      seen.current = null;
      seenReal.current = null;
      setNotices([]);
      return;
    }
    let alive = true;
    const pollSimulated = async () => {
      try {
        const denied = (await api.dashboard()).recent_denied.filter((d) => d.simulated_decision === "deny");
        if (!alive) return;
        if (seen.current === null) {
          seen.current = new Set(denied.map((d) => d.device_key));
          return;
        }
        const fresh = denied.filter((d) => !seen.current!.has(d.device_key));
        for (const d of fresh) seen.current.add(d.device_key);
        if (fresh.length > 0) {
          setNotices((n) => [...fresh.map((d) => ({ key: d.device_key, label: label(d) })), ...n].slice(0, MAX_NOTICES));
        }
      } catch {
        /* Service errors are shown on the pages; notices simply pause. */
      }
    };
    const pollReal = async () => {
      // Real Windows evidence: only a CONNECTED device whose installation
      // Windows currently denies. History, disconnected devices and
      // simulations never produce this notice.
      try {
        const o = await api.enforcementObservation();
        if (!alive) return;
        const current = o.devices.filter((d) => d.observed.evidence === "install_denied" && d.observed.present === true);
        const before = seenReal.current;
        const fresh = current.filter((d) =>
          before === null ? o.newly_observed_denials.includes(d.device_key) : !before.has(d.device_key),
        );
        seenReal.current = new Set(current.map((d) => d.device_key));
        if (fresh.length > 0) {
          setNotices((n) =>
            [
              ...fresh.map((d) => ({
                key: `real-${d.device_key}`,
                label: d.observed.name,
                real: { code: d.observed.problem_code ?? 0 },
              })),
              ...n.filter((x) => !fresh.some((d) => x.key === `real-${d.device_key}`)),
            ].slice(0, MAX_NOTICES),
          );
        }
      } catch {
        /* Observation unavailable: no real notice is ever guessed. */
      }
    };
    const poll = async () => {
      await pollSimulated();
      await pollReal();
    };
    void poll();
    const id = window.setInterval(() => void poll(), pollMs);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, [api, enabled, pollMs]);

  return (
    <div
      role="region"
      aria-label={t("notify.region")}
      aria-live="polite"
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-2"
    >
      {notices.map((n) => (
        <div
          key={n.key}
          role="status"
          className="pointer-events-auto flex gap-3 rounded-lg border border-amber-300 bg-white p-3 text-sm shadow-lg dark:border-amber-700 dark:bg-slate-900"
        >
          <TriangleAlert className="mt-0.5 size-5 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden />
          <div className="min-w-0 flex-1">
            {n.real ? (
              <>
                <p className="font-medium text-slate-900 dark:text-slate-50">{t("notify.realBlocked")}</p>
                <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-300">
                  {t("notify.realBlockedDetail", { device: n.label, code: n.real.code })}
                </p>
              </>
            ) : (
              <>
                <p className="font-medium text-slate-900 dark:text-slate-50">{t("notify.simulatedDenial", { device: n.label })}</p>
                <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-300">{t("notify.simulatedDenialDetail")}</p>
              </>
            )}
          </div>
          <button
            type="button"
            aria-label={t("notify.dismiss")}
            className="self-start rounded p-0.5 text-slate-500 hover:bg-slate-100 focus-visible:outline-2 focus-visible:outline-cyan-500 dark:hover:bg-slate-800"
            onClick={() => setNotices((all) => all.filter((x) => x.key !== n.key))}
          >
            <X className="size-4" aria-hidden />
          </button>
        </div>
      ))}
    </div>
  );
}
