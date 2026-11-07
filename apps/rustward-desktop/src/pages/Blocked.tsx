import { Badge, Card, DecisionBadge, Empty, ErrorNotice, Loading, PageHeader } from "../components/ui";
import { EvidenceBadge, useObservation } from "../components/WindowsObservation";
import { useI18n } from "../i18n";
import { useResource } from "../lib/hooks";
import { deviceName } from "./Devices";

/** Devices Windows actually denies (real evidence), then simulated
 * RustWard decisions in a separate, labelled section. A simulated decision
 * is never presented as an enforced block. */
export function BlockedPage() {
  const { t, tx, formatTime } = useI18n();
  const r = useResource((a) => a.blocked(500), "blocked");
  const obs = useObservation("observation-blocked");
  const all = obs.data?.devices ?? [];
  const current = all.filter((d) => d.observed.present === true && d.observed.evidence === "install_denied");
  const history = all.filter((d) => d.observed.evidence !== "install_denied" && d.observed.history);
  return (
    <div className="space-y-4">
      <PageHeader title={t("blocked.title")} subtitle={t("blocked.subtitle")} />
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
          {history.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{t("blocked.real.history")}</h3>
              <ul className="mt-1 space-y-1">
                {history.map(({ device_key, observed: o }) => (
                  <li key={device_key} className="flex flex-wrap items-center gap-2">
                    {o.name}
                    <EvidenceBadge o={o} />
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </Card>
      <Card title={t("blocked.sim.title")}>
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
                {r.data.map((d) => (
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
                    <td className="px-3 py-2">
                      <Badge tone="warning">{t("blocked.notEnforced")}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
