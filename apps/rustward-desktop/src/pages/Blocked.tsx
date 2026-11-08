import { Badge, Card, DecisionBadge, Empty, ErrorNotice, Loading, PageHeader } from "../components/ui";
import { EvidenceBadge, useObservation } from "../components/WindowsObservation";
import { useI18n } from "../i18n";
import { useResource } from "../lib/hooks";
import { useDeviceEpoch } from "../lib/watch";
import { deviceName } from "./Devices";

const UNKNOWN_REASONS = new Set([
  "unknown_manufacturer",
  "generic_vendor_identity",
  "missing_enforceable_identity",
  "conflicting_identifiers",
]);

/**
 * Denied devices page with four distinct, evidence-graded sections:
 * 1. Currently Windows-denied devices (live SetupAPI + registry evidence)
 * 2. Historical Windows-denied devices (rolled back or disconnected — inactive)
 * 3. Simulated deny candidates (RustWard policy decisions, not OS-enforced)
 * 4. Unknown / unverified identity devices (fail-closed policy candidates)
 */
export function BlockedPage() {
  const { t, tx, formatTime } = useI18n();
  const epoch = useDeviceEpoch();
  const r = useResource((a) => a.blocked(500), `blocked-${epoch}`);
  const obs = useObservation(`observation-blocked-${epoch}`);
  const all = obs.data?.devices ?? [];
  const obsByKey = new Map(all.map((d) => [d.device_key, d.observed]));
  const current = all.filter((d) => d.observed.present === true && d.observed.evidence === "install_denied");
  const history = all.filter((d) => d.observed.evidence !== "install_denied" && d.observed.history);
  const simRows = r.data ?? [];
  const unknownRows = simRows.filter((d) => {
    const o = obsByKey.get(d.device_key);
    return UNKNOWN_REASONS.has(d.reason) || o?.assessment?.policy_category === "UNVERIFIED_IDENTITY";
  });

  return (
    <div className="space-y-4">
      <PageHeader title={t("blocked.title")} subtitle={t("blocked.subtitle")} />

      {/* 1. Currently Windows-denied devices */}
      <Card title={t("blocked.real.title")}>
        <div className="space-y-3 text-sm" data-testid="blocked-real">
          <p className="text-xs text-slate-600 dark:text-slate-300">{t("blocked.real.note")}</p>
          {obs.error && <ErrorNotice error={obs.error} onRetry={obs.reload} />}
          {!obs.data ? (
            !obs.error && <Loading />
          ) : obs.data.policy_error ? (
            <p className="text-amber-800 dark:text-amber-300">{t("blocked.real.unreadable")}</p>
          ) : current.length === 0 ? (
            <Empty>{t("blocked.real.empty")}</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {current.map(({ device_key, observed: o }) => (
                <li key={device_key} className="space-y-1 py-2" data-testid={`real-denied-${device_key}`}>
                  <div className="flex flex-wrap items-center gap-2 font-medium">
                    {o.name}
                    <Badge tone="danger">{t("status.windowsBlockVerified")}</Badge>
                    <Badge tone="warning">{t("status.accessNotVerified")}</Badge>
                    <EvidenceBadge o={o} />
                  </div>
                  <div className="text-xs text-slate-500">
                    {o.vid_pid && <>VID:PID {o.vid_pid} · </>}
                    {t("devices.reported", { v: o.reported_vendor ?? "—" })}
                  </div>
                  <div className="break-all font-mono text-[11px] text-slate-500">{o.hardware_id ?? "—"}</div>
                  <div>{o.label_status_tr} · <span className="[overflow-wrap:anywhere]">{o.label_policy_tr}</span></div>
                  <div className="text-xs text-slate-600 dark:text-slate-300">{o.explanation_tr}</div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Card>

      {/* 2. Historical Windows-denied devices (rolled back or disconnected) */}
      <Card title={t("blocked.history.title")}>
        <div className="space-y-3 text-sm" data-testid="blocked-history">
          <p className="text-xs text-slate-600 dark:text-slate-300">{t("blocked.history.note")}</p>
          {!obs.data ? (
            !obs.error && <Loading />
          ) : history.length === 0 ? (
            <Empty>{t("blocked.history.empty")}</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {history.map(({ device_key, observed: o }) => (
                <li key={device_key} className="space-y-1 py-2" data-testid={`history-denied-${device_key}`}>
                  <div className="flex flex-wrap items-center gap-2 font-medium">
                    {o.name}
                    <Badge tone="neutral">
                      {o.windows_rule.outcome === "prevented"
                        ? t("status.protectionInactive")
                        : t("status.rollbackCompleted")}
                    </Badge>
                    <EvidenceBadge o={o} />
                  </div>
                  <div className="text-xs text-slate-500">
                    {o.vid_pid && <>VID:PID {o.vid_pid} · </>}
                    {o.label_status_tr} · {o.label_policy_tr}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Card>

      {/* 3. Simulated deny candidates */}
      <Card title={t("blocked.sim.title")}>
        <div data-testid="blocked-sim">
          <p className="mb-3 text-xs text-slate-600 dark:text-slate-300">{t("blocked.sim.note")}</p>
          {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
          {r.loading && !r.data ? (
            <Loading />
          ) : !r.data || r.data.length === 0 ? (
            <Empty>{t("blocked.empty")}</Empty>
          ) : (
            <div className="-mx-4 -mb-4 overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-y border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                  <tr>
                    <th className="px-3 py-2">{t("devices.col.device")}</th>
                    <th className="px-3 py-2">{t("devices.col.manufacturer")}</th>
                    <th className="px-3 py-2">{t("blocked.col.time")}</th>
                    <th className="px-3 py-2">{t("blocked.col.reason")}</th>
                    <th className="px-3 py-2">{t("devices.col.decision")}</th>
                    <th className="px-3 py-2">{t("blocked.col.enforcement")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {r.data.map((d) => {
                    const o = obsByKey.get(d.device_key);
                    const liveDenied = o?.present === true && o.evidence === "install_denied";
                    return (
                      <tr key={d.device_key} className="align-top">
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-1.5 font-medium">
                            {deviceName(d)}
                            {d.synthetic && <Badge tone="synthetic">{t("badge.synthetic")}</Badge>}
                          </div>
                          <div className="break-all font-mono text-[11px] text-slate-500">{d.display_id}</div>
                        </td>
                        <td className="px-3 py-2">
                          {d.vendor ? t("devices.reported", { v: d.vendor }) : t("devices.reportedNone")}
                          {d.usb_vid_pid && <div className="font-mono text-[11px] text-slate-500">VID:PID {d.usb_vid_pid}</div>}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap">{formatTime(d.last_seen_ms)}</td>
                        <td className="px-3 py-2">{tx("reason", d.reason)}</td>
                        <td className="px-3 py-2">
                          <DecisionBadge decision={d.simulated_decision} />
                        </td>
                        <td className="space-y-1 px-3 py-2">
                          {liveDenied ? (
                            <div className="flex flex-wrap gap-1">
                              <Badge tone="danger">{t("status.windowsBlockVerified")}</Badge>
                              <Badge tone="warning">{t("status.accessNotVerified")}</Badge>
                            </div>
                          ) : (
                            <div className="flex flex-wrap gap-1">
                              <Badge tone="info">{t("status.simulation")}</Badge>
                              <Badge tone="warning">{t("blocked.notEnforced")}</Badge>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      {/* 4. Unknown / unverified identity devices */}
      <Card title={t("blocked.unknown.title")}>
        <div className="space-y-3 text-sm" data-testid="blocked-unknown">
          <p className="text-xs text-slate-600 dark:text-slate-300">{t("blocked.unknown.note")}</p>
          {r.loading && !r.data ? (
            <Loading />
          ) : unknownRows.length === 0 ? (
            <Empty>{t("blocked.unknown.empty")}</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {unknownRows.map((d) => (
                <li key={d.device_key} className="flex flex-wrap items-center justify-between gap-2 py-2" data-testid={`unknown-device-${d.device_key}`}>
                  <div>
                    <div className="flex flex-wrap items-center gap-1.5 font-medium">
                      {deviceName(d)}
                      {d.synthetic && <Badge tone="synthetic">{t("badge.synthetic")}</Badge>}
                    </div>
                    <div className="text-xs text-slate-500">
                      {d.vendor ? t("devices.reported", { v: d.vendor }) : t("devices.reportedNone")}
                      {d.usb_vid_pid && ` · VID:PID ${d.usb_vid_pid}`}
                      {" · "}
                      {tx("reason", d.reason)}
                    </div>
                  </div>
                  <Badge tone="warning">{t("assess.cat.UNVERIFIED_IDENTITY")}</Badge>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Card>
    </div>
  );
}
