import { Clock, Factory, FlaskConical, HardDrive, Server, ShieldAlert, ShieldCheck, ShieldOff, ShieldQuestion } from "lucide-react";
import type { WindowsProtectionView } from "../api/types";
import { BlockerList, SummaryTiles } from "../components/Assessment";
import type { PageId } from "../App";
import { Badge, Card, DecisionBadge, Empty, ErrorNotice, Loading, NotValidatedBanner, PageHeader, Stat, Button, type Tone } from "../components/ui";
import { useI18n } from "../i18n";
import { useResource } from "../lib/hooks";
import { useDeviceEpoch } from "../lib/watch";
import { EventRow } from "./Audit";

const protectionTone: Record<string, Tone> = {
  unknown: "neutral",
  inactive: "warning",
  configured_unverified: "warning",
  denial_observed: "danger",
  verified_active: "success",
};

/**
 * Primary status: derived by the service only from real Windows evidence
 * (policy re-read + device problem codes). A configured rule alone never
 * shows as an active block.
 */
export function ProtectionPanel({ p }: { p: WindowsProtectionView | undefined }) {
  const { t, tx, lang } = useI18n();
  const state = p?.state ?? "unknown";
  const tone = protectionTone[state] ?? "neutral";
  const Icon = state === "verified_active" ? ShieldCheck : state === "denial_observed" ? ShieldAlert : state === "inactive" ? ShieldOff : ShieldQuestion;
  const ring: Record<Tone, string> = {
    success: "border-emerald-300 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-950/40",
    danger: "border-rose-300 bg-rose-50 dark:border-rose-800 dark:bg-rose-950/40",
    warning: "border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/40",
    neutral: "border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900",
    info: "border-cyan-200 bg-cyan-50 dark:border-cyan-900 dark:bg-cyan-950/40",
    synthetic: "border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900",
  };
  return (
    <section className={`rounded-lg border p-4 ${ring[tone]}`} data-testid="protection-panel" data-state={state}>
      <div className="flex flex-wrap items-start gap-3">
        <Icon className="mt-0.5 size-6 shrink-0" aria-hidden />
        <div className="min-w-0 flex-1 space-y-1">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">{t("prot.title")}</div>
          <div className="text-lg font-semibold" data-testid="protection-label">
            {p ? (lang === "tr" ? p.label_tr : p.label_en) : t("prot.state.unknown")}
          </div>
          <p className="text-sm text-slate-700 dark:text-slate-300">{p ? (lang === "tr" ? p.detail_tr : p.detail_en) : t("prot.legacy")}</p>
          <div className="flex flex-wrap gap-1.5 pt-1">
            <Badge tone={tone}>{tx("prot.state", state)}</Badge>
            {p && p.denied_now > 0 ? (
              <Badge tone="danger">
                {t("prot.evidence")}: {t("prot.deniedNow", { n: p.denied_now })}
              </Badge>
            ) : (
              <Badge>{t("prot.noEvidence")}</Badge>
            )}
            {!p?.automated_apply_available && <Badge tone="warning">{t("prot.autoApply")}</Badge>}
          </div>
        </div>
      </div>
    </section>
  );
}

export function DashboardPage({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const { t, lang, formatTime, tx, pick, pickList } = useI18n();
  const epoch = useDeviceEpoch();
  const r = useResource((api) => api.dashboard(), `dashboard-${epoch}`);
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
          <ProtectionPanel p={d.windows_protection} />
          {d.windows_protection?.summary && <SummaryTiles s={d.windows_protection.summary} />}
          {d.windows_protection?.blockers && d.windows_protection.blockers.length > 0 && (
            <Card
              title={t("blocker.title")}
              actions={<Button variant="ghost" onClick={() => onNavigate("readiness")}>{t("nav.readiness")}</Button>}
            >
              <BlockerList blockers={d.windows_protection.blockers} limit={4} />
            </Card>
          )}
          {/* The content area is the window minus the sidebar, so five columns only
              from 2xl; at the default 1280 px window three columns keep the
              cards readable. */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5">
            <Stat
              icon={<FlaskConical className="size-4" aria-hidden />}
              label={t("prot.simulation")}
              value={<span className="text-base">{lang === "tr" ? d.enforcement_label_tr : d.enforcement_label_en}</span>}
              hint={<span className="text-xs">{t("prot.simulationNote")}</span>}
            />
            <Stat
              icon={<Server className="size-4" aria-hidden />}
              label={t("dashboard.service")}
              value={d.service.healthy ? t("dashboard.healthy") : t("dashboard.degraded")}
              hint={pick(d.service.message, d.service.message_tr)}
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
          <div className="grid grid-cols-1 gap-4 2xl:grid-cols-2">
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
                <table className="w-full table-fixed text-sm">
                  <colgroup>
                    <col className="w-32" />
                    <col className="w-16" />
                    <col />
                    <col className="w-28" />
                  </colgroup>
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
                {pickList(d.warnings, d.warnings_tr).map((w) => (
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
