import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import type { EnforcementObservationView } from "../api/types";
import { useApi } from "./hooks";

/** How often the window re-reads the service's Windows observation. */
export const WATCH_POLL_MS = 2_000;

const EpochContext = createContext(0);

/**
 * What a page shows about real Windows state: connection, problem code,
 * evidence and the policy. Timestamps are left out so the periodic
 * refresh alone never counts as a change.
 */
export function observationSignature(o: EnforcementObservationView): string {
  const devices = o.devices
    .map((d) => `${d.device_key}:${String(d.observed.present)}:${d.observed.problem_code ?? "-"}:${d.observed.evidence}:${d.observed.states.join("+")}`)
    .sort();
  return [o.policy_error ?? "", String(o.policy_key_present), String(o.windows_restrictions_configured), ...devices].join("|");
}

/**
 * Bumps an epoch whenever the service reports a different real Windows
 * state (device arrival/removal, problem-code change, policy change). The
 * service itself re-enumerates on WM_DEVICECHANGE, so pages that key their
 * data on the epoch update from genuine Windows events without a manual
 * refresh. Read-only: it only calls get_enforcement_observation.
 */
export function DeviceWatchProvider({ pollMs = WATCH_POLL_MS, children }: { pollMs?: number; children: ReactNode }) {
  const api = useApi();
  const [epoch, setEpoch] = useState(0);
  const last = useRef<string | null>(null);
  useEffect(() => {
    if (pollMs <= 0) return;
    let alive = true;
    const tick = async () => {
      try {
        const sig = observationSignature(await api.enforcementObservation());
        if (!alive) return;
        if (last.current !== null && last.current !== sig) setEpoch((e) => e + 1);
        last.current = sig;
      } catch {
        /* Service unavailable: the connection bar reports it. */
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), pollMs);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, [api, pollMs]);
  return <EpochContext.Provider value={epoch}>{children}</EpochContext.Provider>;
}

/** Changes whenever the real Windows device or policy state changes. */
export function useDeviceEpoch(): number {
  return useContext(EpochContext);
}
