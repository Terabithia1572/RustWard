// Enforcement readiness (Phase 10): READ-ONLY. Shows what RustWard found and
// what an activation would need. Nothing here can change Windows: the only
// request is `get_enforcement_readiness`, and the activation button is
// permanently disabled in this build.
import type { ReactNode } from "react";
import { GuidedSessionCard } from "../components/GuidedSession";
import { BlockerList, SummaryTiles } from "../components/Assessment";
import { useDeviceEpoch } from "../lib/watch";
import { ObservationCard } from "../components/WindowsObservation";
import { Lock } from "lucide-react";
import type {
  EnforcementReadinessView,
  PolicyConflict,
  PolicyInspection,
  RegData,
} from "../api/types";
import { Badge, Button, Card, DecisionBadge, Empty, ErrorNotice, Loading, PageHeader, Stat, type Tone } from "../components/ui";
import { useI18n } from "../i18n";
import type { TKey } from "../i18n/tr";
import { useResource } from "../lib/hooks";

const statusTone = { met: "success", not_met: "danger", unknown: "warning" } as const satisfies Record<string, Tone>;

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-2 py-1.5 text-sm">
      <dt className="text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="text-right font-medium">{children}</dd>
    </div>
  );
}

function regText(d: RegData): string {
  switch (d.type) {
    case "dword":
      return `REG_DWORD ${d.data}`;
    case "sz":
      return `REG_SZ "${d.data}"`;
    case "multi_sz":
      return `REG_MULTI_SZ [${d.data.join(", ")}]`;
    case "other":
      return `type ${d.data.reg_type}, ${d.data.bytes} B`;
  }
}

function ConflictText({ c }: { c: PolicyConflict }) {
  const { t } = useI18n();
  const key = `conflict.${c.kind}` as TKey;
  switch (c.kind) {
    case "existing_deny_unspecified":
      return <>{t(key)}</>;
    case "retroactive_flag":
      return <>{t(key, { value: c.value })}</>;
    case "list_index_collision":
      return <>{t(key, { list: c.list, index: c.index })}</>;
    case "deny_overlaps_allow":
      return <>{t(key, { list: c.deny_list, id: c.id })}</>;
    case "invalid_planned_value":
      return <>{t(key, { detail: c.detail })}</>;
  }
}

function InspectionCard({ v }: { v: EnforcementReadinessView }) {
  const { t, tx, formatTime, pick } = useI18n();
  const i: PolicyInspection | null = v.inspection;
  const flag = (n: number | null) => (n === null ? t("readiness.notSet") : String(n));
  return (
    <Card
      title={t("readiness.inspection")}
      actions={
        <Badge tone={v.inspection_source === "fixture" ? "synthetic" : v.inspection_source === "unavailable" ? "warning" : "info"}>
          {tx("readiness.source", v.inspection_source)}
        </Badge>
      }
    >
      {!i ? (
        <p className="text-sm text-amber-800 dark:text-amber-300" data-testid="inspection-error">
          {t("readiness.inspectionError", { error: v.inspection_error ?? "—" })}
        </p>
      ) : (
        <div className="space-y-3">
          <dl className="divide-y divide-slate-100 dark:divide-slate-800">
            <Row label={t("readiness.keyPresent")}>{i.key_present ? t("common.yes") : t("common.no")}</Row>
            <Row label={t("readiness.layered")}>{flag(i.layered.value)}</Row>
            <Row label={t("readiness.denyUnspecified")}>{flag(i.deny_unspecified.value)}</Row>
            <Row label={t("readiness.os")}>
              {i.os.build ?? "—"}
              {i.os.ubr !== null && (
                <span title={t("readiness.ubrNote")}>
                  .{i.os.ubr} <Badge tone="warning">UBR?</Badge>
                </span>
              )}
            </Row>
            <Row label={t("readiness.edition")}>
              {i.edition_supported === null ? t("common.unknown") : i.edition_supported ? t("common.yes") : t("common.no")}
            </Row>
            <Row label={t("readiness.layering")}>
              <Badge tone={i.layering.status === "supported" ? "success" : i.layering.status === "not_supported" ? "danger" : "warning"}>
                {tx("readiness.layering", i.layering.status)}
              </Badge>
              {"reason" in i.layering && <div className="mt-1 text-xs font-normal text-slate-500">{pick(i.layering.reason, i.layering.reason_tr)}</div>}
            </Row>
            <Row label={t("readiness.planPresence")}>
              {i.plan_presence === null
                ? "—"
                : i.plan_presence.state === "partial"
                  ? t("readiness.presence.partial", {
                      matching: i.plan_presence.matching,
                      missing: i.plan_presence.missing,
                      different: i.plan_presence.different,
                    })
                  : tx("readiness.presence", i.plan_presence.state)}
              <div className="mt-1 text-xs font-normal text-slate-500">{t("readiness.presenceNote")}</div>
            </Row>
          </dl>
          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{t("readiness.lists")}</h3>
            <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead className="text-xs text-slate-500">
                <tr>
                  <th className="py-1 pr-2">{t("readiness.col.list")}</th>
                  <th className="py-1 pr-2">{t("readiness.col.kind")}</th>
                  <th className="py-1 pr-2">{t("readiness.col.layer")}</th>
                  <th className="py-1 pr-2">{t("readiness.col.enabled")}</th>
                  <th className="py-1">{t("readiness.col.entries")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {i.lists.map((l) => (
                  <tr key={l.name}>
                    <td className="py-1 pr-2 font-mono text-xs">{l.name}</td>
                    <td className="py-1 pr-2">{l.allow ? t("readiness.list.allow") : t("readiness.list.prevent")}</td>
                    <td className="py-1 pr-2">{tx("readiness.layer", l.layer)}</td>
                    <td className="py-1 pr-2">{flag(l.enabled)}</td>
                    <td className="py-1">{l.entries.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            <p className="mt-1 text-xs text-slate-500">{t("readiness.layoutUnresolved")}</p>
          </div>
          <div className="text-sm">
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{t("readiness.retroactive")}</h3>
            <ul className="space-y-0.5">
              {i.retroactive.map((f) => (
                <li key={f.name} className="font-mono text-xs">
                  {f.name}: {flag(f.value)}
                </li>
              ))}
            </ul>
          </div>
          <div className="text-sm">
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
              {t("readiness.unrecognised", { count: i.unrecognised.length })}
            </h3>
            <ul className="space-y-0.5">
              {i.unrecognised.map(([r, d]) => (
                <li key={`${r.key}\\${r.name}`} className="break-all font-mono text-xs">
                  {r.name} = {regText(d)}
                </li>
              ))}
            </ul>
          </div>
          {i.read_errors.length > 0 && <ErrorNotice error={new Error(i.read_errors.join("; "))} />}
          <p className="text-xs text-slate-500">{formatTime(i.captured_ms)}</p>
        </div>
      )}
    </Card>
  );
}

function InstalledCard({ v }: { v: EnforcementReadinessView }) {
  const { t, tx, lang } = useI18n();
  const a = v.installed;
  const withSteps = a.devices.find((d) => d.remediation.length > 0);
  return (
    <Card title={t("readiness.installed")}>
      <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">{t("readiness.installedNote")}</p>
      <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label={t("readiness.sum.assessed")} value={a.summary.assessed} />
        <Stat label={t("readiness.sum.deniedInstalled")} value={a.summary.denied_but_installed} />
        <Stat label={t("readiness.sum.allowed")} value={a.summary.allowed} />
        <Stat label={t("readiness.sum.internal")} value={a.summary.internal_protected} />
        <Stat label={t("readiness.sum.review")} value={a.summary.needs_review + a.summary.internal_unprotected + a.summary.plan_disagreements} />
      </div>
      {a.devices.length === 0 ? (
        <Empty>{t("readiness.installedEmpty")}</Empty>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm" data-testid="installed-table">
            <thead className="text-xs text-slate-500">
              <tr>
                <th className="py-1 pr-2">{t("readiness.col.device")}</th>
                <th className="py-1 pr-2">{t("readiness.col.attachment")}</th>
                <th className="py-1 pr-2">{t("readiness.col.install")}</th>
                <th className="py-1 pr-2">{t("readiness.col.decision")}</th>
                <th className="py-1 pr-2">{t("readiness.col.newInstall")}</th>
                <th className="py-1 pr-2">{t("readiness.col.remains")}</th>
                <th className="py-1">{t("readiness.col.finding")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {a.devices.map((d) => (
                <tr key={d.instance_id} className="align-top">
                  <td className="py-1.5 pr-2">
                    <div className="font-medium">{d.name}</div>
                    <div className="break-all font-mono text-[11px] text-slate-500">{d.instance_id}</div>
                  </td>
                  <td className="py-1.5 pr-2">{tx("readiness.attach", d.attachment)}</td>
                  <td className="py-1.5 pr-2">{tx("readiness.install", d.install_state)}</td>
                  <td className="py-1.5 pr-2">
                    {d.simulated_verdict === "not_applicable" ? "—" : <DecisionBadge decision={d.simulated_verdict} />}
                  </td>
                  <td className="py-1.5 pr-2">{tx("readiness.outcome", d.planned_new_install.outcome)}</td>
                  <td className="py-1.5 pr-2">
                    {d.remains_accessible_after_activation ? <Badge tone="warning">{t("common.yes")}</Badge> : t("common.no")}
                  </td>
                  <td className="py-1.5">{tx("finding", d.finding)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {withSteps && (
        <div className="mt-4">
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{t("readiness.remediation")}</h3>
          <ol className="list-decimal space-y-1 pl-5 text-sm" data-testid="remediation-steps">
            {withSteps.remediation.map((s) => (
              <li key={s.en}>{lang === "tr" ? s.tr : s.en}</li>
            ))}
          </ol>
        </div>
      )}
      <div className="mt-4">
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{t("readiness.limitations")}</h3>
        <ul className="list-disc space-y-1 pl-5 text-sm text-amber-800 dark:text-amber-300">
          {a.limitations.map((l) => (
            <li key={l.en}>{lang === "tr" ? l.tr : l.en}</li>
          ))}
        </ul>
      </div>
    </Card>
  );
}

export function ReadinessPage() {
  const { t, tx, lang } = useI18n();
  const r = useResource((a) => a.enforcementReadiness(), "readiness");
  const epoch = useDeviceEpoch();
  const dash = useResource((a) => a.dashboard(), `readiness-protection-${epoch}`);
  const prot = dash.data?.windows_protection;
  const v = r.data;
  return (
    <div className="space-y-4">
      <PageHeader title={t("readiness.title")} subtitle={t("readiness.subtitle")} />
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      {!v ? (
        !r.error && <Loading />
      ) : (
        <>
          <Card title={t("blocker.title")}>
            {prot?.summary && (
              <div className="mb-3">
                <SummaryTiles s={prot.summary} />
              </div>
            )}
            {prot?.blockers ? <BlockerList blockers={prot.blockers} /> : <Loading />}
          </Card>

          <Card title={t("readiness.actual")}>
            <dl className="divide-y divide-slate-100 dark:divide-slate-800" data-testid="actual-enforcement">
              <Row label={t("readiness.actual")}>
                <Badge tone="warning">{lang === "tr" ? v.actual_enforcement.label_tr : v.actual_enforcement.label_en}</Badge>
              </Row>
              <Row label={t("readiness.verified")}>
                <Badge tone={v.actual_enforcement.verified_protection ? "success" : "danger"}>
                  {v.actual_enforcement.verified_protection ? t("common.yes") : t("common.no")}
                </Badge>
              </Row>
              <Row label={t("readiness.activation")}>
                <Button disabled icon={<Lock className="size-4" aria-hidden />} aria-describedby="activation-disabled">
                  {t("readiness.activateButton")}
                </Button>
              </Row>
            </dl>
            <p id="activation-disabled" className="mt-2 text-sm text-slate-600 dark:text-slate-300">
              {t("readiness.activationDisabled")}
            </p>
          </Card>

          <GuidedSessionCard />

          <ObservationCard />

          <InspectionCard v={v} />

          <Card title={t("readiness.conflicts")}>
            {v.conflicts.length === 0 ? (
              <p className="text-sm text-slate-500">{t("readiness.noConflicts")}</p>
            ) : (
              <ul className="list-disc space-y-1 pl-5 text-sm text-rose-800 dark:text-rose-300" data-testid="conflicts">
                {v.conflicts.map((c, n) => (
                  <li key={n}>
                    <ConflictText c={c} />
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title={t("readiness.planned")}>
            <p className="mb-2 text-sm text-slate-600 dark:text-slate-300">{t("readiness.plannedNote")}</p>
            <ul className="space-y-1 text-xs" data-testid="planned-changes">
              {v.planned_changes.map((c) => (
                <li key={`${c.key}\\${c.value_name}`} className="break-all font-mono">
                  {c.key.replace("SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\", "…\\")}\{c.value_name} = {c.value_type} {c.data}{" "}
                  <Badge tone={c.confirmed_against_documentation ? "success" : "warning"}>
                    {t("readiness.documented")}: {c.confirmed_against_documentation ? t("common.yes") : t("common.no")}
                  </Badge>
                </li>
              ))}
            </ul>
            <p className="mt-2 break-all font-mono text-[11px] text-slate-500">
              {t("readiness.fingerprint")}: {v.plan_fingerprint}
            </p>
          </Card>

          <Card
            title={t("readiness.gates")}
            actions={
              <Badge tone="danger">
                {t("readiness.gatesSummary", {
                  met: v.gates.filter((g) => g.status === "met").length,
                  total: v.gates.length,
                })}
              </Badge>
            }
          >
            <ul className="space-y-1 text-sm" data-testid="gates">
              {v.gates.map((g) => (
                <li key={g.code} className="flex items-start justify-between gap-3">
                  <span title={g.detail}>{tx("gate", g.code)}</span>
                  <Badge tone={statusTone[g.status]}>{tx("readiness.status", g.status)}</Badge>
                </li>
              ))}
            </ul>
          </Card>

          <div className="grid gap-4 md:grid-cols-2">
            <Card title={t("readiness.permissions")}>
              <ul className="list-disc space-y-1 pl-5 text-sm">
                {v.required_permissions.map((p) => (
                  <li key={p.en}>{lang === "tr" ? p.tr : p.en}</li>
                ))}
              </ul>
            </Card>
            <Card title={t("readiness.recovery")}>
              <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                <Row label={t("readiness.rollbackExact")}>
                  <Badge tone={v.recovery.rollback_modelled_exact ? "success" : "danger"}>
                    {v.recovery.rollback_modelled_exact ? t("common.yes") : t("common.no")}
                  </Badge>
                </Row>
              </dl>
              <p className="mt-1 text-xs text-slate-500">
                {t("readiness.operations", {
                  forward: v.recovery.forward_operations,
                  rollback: v.recovery.rollback_operations,
                  suspend: v.recovery.suspend_operations,
                })}
              </p>
              <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm">
                {v.recovery.steps.map((s) => (
                  <li key={s.order}>{lang === "tr" ? s.tr : s.en}</li>
                ))}
              </ol>
            </Card>
          </div>

          <InstalledCard v={v} />
        </>
      )}
    </div>
  );
}
