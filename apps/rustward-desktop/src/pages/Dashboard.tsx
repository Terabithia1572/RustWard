import { Clock, Factory, HardDrive, Server, ShieldQuestion } from "lucide-react";
import type { PageId } from "../App";
import { Badge, Card, DecisionBadge, Empty, ErrorNotice, Loading, NotValidatedBanner, PageHeader, Stat, Button } from "../components/ui";
import { useI18n } from "../i18n";
import { useResource } from "../lib/hooks";
import { EventRow } from "./Audit";

export function DashboardPage({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const { t, lang, formatTime, tx } = useI18n();
  const r = useResource((api) => api.dashboard(), "dashboard");
  const d = r.data;

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("dashboard.title")}
        subtitle={d ? `${t("dashboard.workstation")}: ${d.workstation_id} · ${t("common.policyVersion", { version: d.policy_version })}` : undefined}
        actions={
          <>
            {d?.synthetic_data_present && <Badge tone="synthetic">{t("badge.synthetic")}</Badge>}
            {d?.service.backend === "dev_backend" && <Badge tone="warning">{t("badge.devBackend")}</Badge>}
            <Button onClick={r.reload}>{t("common.refresh")}</Button>
          </>
        }
      />
      {/* Shown until real enforcement validation succeeds. */}
      {(!d || !d.protection_verified) && <NotValidatedBanner />}
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      {r.loading && !d && <Loading />}
      {d && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
            <Stat
              icon={<ShieldQuestion className="size-4" aria-hidden />}
              label={t("dashboard.protection")}
              value={<span className="text-base">{lang === "tr" ? d.enforcement_label_tr : d.enforcement_label_en}</span>}
              hint={<Badge tone="warning">{t("badge.notVerified")}</Badge>}
            />
            <Stat
              icon={<Server className="size-4" aria-hidden />}
              label={t("dashboard.service")}
              value={d.service.healthy ? t("dashboard.healthy") : t("dashboard.degraded")}
              hint={d.service.message}
            />
            <Stat icon={<Factory className="size-4" aria-hidden />} label={t("dashboard.allowed")} value={d.allowed_manufacturers} />
            <Stat icon={<HardDrive className="size-4" aria-hidden />} label={t("dashboard.connected")} value={d.connected_storage} />
            <Stat
              icon={<Clock className="size-4" aria-hidden />}
              label={t("dashboard.lastPolicy")}
              value={<span className="text-base">{formatTime(d.last_policy_update_ms)}</span>}
              hint={d.catalog_version}
            />
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Card
              title={t("dashboard.recentDenied")}
              actions={<Button variant="ghost" onClick={() => onNavigate("blocked")}>{t("nav.blocked")}</Button>}
            >
              {d.recent_denied.length === 0 ? (
                <Empty>{t("dashboard.noDenied")}</Empty>
              ) : (
                <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                  {d.recent_denied.map((dev) => (
                    <li key={dev.device_key} className="flex items-center justify-between gap-3 py-2">
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium">
                          {dev.friendly_name ?? [dev.vendor, dev.product].filter(Boolean).join(" ")}
                        </div>
                        <div className="truncate text-xs text-slate-500 dark:text-slate-400">{tx("reason", dev.reason)}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1.5">
                        {dev.synthetic && <Badge tone="synthetic">{t("badge.synthetic")}</Badge>}
                        <DecisionBadge decision={dev.simulated_decision} />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card
              title={t("dashboard.recentEvents")}
              actions={<Button variant="ghost" onClick={() => onNavigate("audit")}>{t("nav.audit")}</Button>}
            >
              {d.recent_events.length === 0 ? (
                <Empty />
              ) : (
                <table className="w-full text-sm">
                  <tbody>
                    {d.recent_events.map((e) => (
                      <EventRow key={e.id} e={e} compact />
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          </div>
          {d.warnings.length > 0 && (
            <Card title={t("dashboard.warnings")}>
              <ul className="list-disc space-y-1 pl-5 text-sm text-amber-800 dark:text-amber-300">
                {d.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
