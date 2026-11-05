import { Badge, Card, DecisionBadge, Empty, ErrorNotice, Loading, PageHeader } from "../components/ui";
import { useI18n } from "../i18n";
import { useResource } from "../lib/hooks";
import { deviceName } from "./Devices";

/** Devices the policy would deny. This page never presents a simulated
 * decision as an enforced block. */
export function BlockedPage() {
  const { t, tx, formatTime } = useI18n();
  const r = useResource((a) => a.blocked(500), "blocked");
  return (
    <div className="space-y-4">
      <PageHeader title={t("blocked.title")} subtitle={t("blocked.subtitle")} />
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      <Card>
        {r.loading && !r.data ? (
          <Loading />
        ) : !r.data || r.data.length === 0 ? (
          <Empty>{t("blocked.empty")}</Empty>
        ) : (
          <div className="-m-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
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
                      <div className="font-mono text-[11px] text-slate-500">{d.display_id}</div>
                    </td>
                    <td className="px-3 py-2">
                      {d.matched_brand ?? d.vendor ?? "—"}
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
