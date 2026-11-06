import { useState, type ReactNode } from "react";
import { FlaskConical } from "lucide-react";
import type { CapabilityReport, CapabilityStatus, SimulationView } from "../api/types";
import { Badge, Button, Card, ErrorNotice, Loading, PageHeader, type Tone } from "../components/ui";
import { useI18n } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";

const CAPS: (keyof Omit<CapabilityReport, "provider_id" | "activation_available">)[] = [
  "pre_access_blocking",
  "brand_allowlisting",
  "previously_installed_devices",
  "persistence",
  "self_verification",
];

const capTone: Record<CapabilityStatus, Tone> = {
  not_implemented: "neutral",
  unsupported: "danger",
  designed_not_verified: "warning",
  verified: "success",
};

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-2 py-1.5 text-sm">
      <dt className="text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="text-right font-medium">{children}</dd>
    </div>
  );
}

function OkBadge({ ok, yes, no }: { ok: boolean; yes: string; no: string }) {
  return <Badge tone={ok ? "success" : "danger"}>{ok ? yes : no}</Badge>;
}

function List({ items, tone = "neutral" }: { items: string[]; tone?: "neutral" | "warning" }) {
  const { t } = useI18n();
  if (items.length === 0) return <p className="text-sm text-slate-500">{t("common.none")}</p>;
  return (
    <ul className={`list-disc space-y-1 pl-5 text-sm ${tone === "warning" ? "text-amber-800 dark:text-amber-300" : ""}`}>
      {items.map((x) => (
        <li key={x}>{x}</li>
      ))}
    </ul>
  );
}

export function DiagnosticsPage() {
  const { t, tx, lang, formatTime } = useI18n();
  const api = useApi();
  const r = useResource((a) => a.diagnostics(), "diagnostics");
  const sim = useAction();
  const [result, setResult] = useState<SimulationView | null>(null);
  const d = r.data;

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("diag.title")}
        subtitle={d ? `${t("common.version")} ${d.app_version}` : undefined}
        actions={
          <>
            <Button onClick={r.reload}>{t("common.refresh")}</Button>
            <Button
              variant="primary"
              icon={<FlaskConical className="size-4" aria-hidden />}
              busy={sim.busy}
              onClick={() =>
                void sim.run(() => api.simulate()).then((res) => {
                  if (res) setResult(res);
                })
              }
            >
              {t("diag.runSimulation")}
            </Button>
          </>
        }
      />
      {sim.error && <ErrorNotice error={sim.error} />}
      {result && (
        <Card title={t("diag.runSimulation")}>
          <div className="space-y-2 text-sm">
            <p data-testid="simulation-result">
              {t("diag.simulationResult", {
                evaluated: result.evaluated,
                allow: result.simulated_allow,
                deny: result.simulated_deny,
                na: result.not_applicable,
              })}
            </p>
            <p className="text-amber-800 dark:text-amber-300">{result.notice}</p>
            {result.enforcement_gaps.length > 0 && <List items={result.enforcement_gaps} tone="warning" />}
          </div>
        </Card>
      )}
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      {r.loading && !d && <Loading />}
      {d && (
        <>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title={t("diag.service")}>
              <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                <Row label={t("settings.backend")}>
                  <Badge tone={d.service.backend === "dev_backend" ? "warning" : "info"}>{d.service.backend}</Badge>
                </Row>
                <Row label={t("diag.health")}>
                  <OkBadge ok={d.service.healthy} yes={t("dashboard.healthy")} no={t("dashboard.degraded")} />
                </Row>
                <Row label={t("diag.state")}>{d.service.state}</Row>
                <Row label={t("diag.lastRefresh")}>{formatTime(d.service.last_refresh_ms)}</Row>
                <Row label={t("diag.detail")}>{d.service.message}</Row>
              </dl>
            </Card>
            <Card title={t("diag.database")}>
              <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                <Row label={t("diag.schema")}>v{d.database.schema_version}</Row>
                <Row label={t("diag.integrity")}>
                  <OkBadge ok={d.database.integrity_ok} yes={t("diag.valid")} no={t("diag.invalid")} />
                </Row>
                <Row label={t("diag.chain")}>
                  <OkBadge ok={d.database.chain_ok} yes={d.database.chain_status} no={d.database.chain_status} />
                </Row>
                <Row label={t("diag.location")}>{d.database.location_kind}</Row>
              </dl>
            </Card>
            <Card title={t("diag.adapter")}>
              <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                <Row label={t("diag.platform")}>{d.windows_adapter.platform}</Row>
                <Row label={t("diag.liveInventory")}>
                  <Badge tone={d.windows_adapter.live_inventory_available ? "info" : "neutral"}>
                    {d.windows_adapter.live_inventory_available ? t("common.yes") : t("common.no")}
                  </Badge>
                </Row>
                <Row label={t("diag.lastError")}>{d.windows_adapter.last_error ?? t("common.none")}</Row>
              </dl>
            </Card>
            <Card title={t("diag.eventLog")}>
              <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                <Row label={t("diag.eventLogAttached")}>
                  <Badge tone={d.event_log?.attached ? "info" : "neutral"}>
                    {d.event_log?.attached ? t("diag.eventLogOn") : t("diag.eventLogOff")}
                  </Badge>
                </Row>
                <Row label={t("diag.eventLogDelivered")}>{d.event_log?.delivered ?? 0}</Row>
                <Row label={t("diag.eventLogFailures")}>
                  <Badge tone={(d.event_log?.failures ?? 0) > 0 ? "warning" : "neutral"}>{d.event_log?.failures ?? 0}</Badge>
                </Row>
              </dl>
            </Card>
            <Card title={t("diag.policy")}>
              <div className="space-y-2">
                <OkBadge ok={d.policy.valid} yes={t("diag.valid")} no={t("diag.invalid")} />
                {d.policy.errors.length > 0 && <List items={d.policy.errors} />}
                {d.policy.warnings.length > 0 && <List items={d.policy.warnings} tone="warning" />}
              </div>
            </Card>
          </div>

          <Card
            title={t("diag.enforcement")}
            actions={<Badge tone="warning">{lang === "tr" ? d.enforcement.label_tr : d.enforcement.label_en}</Badge>}
          >
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <div className="space-y-3">
                <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                  <Row label={t("diag.provider")}>
                    <code className="font-mono text-xs">{d.enforcement.provider_id}</code>
                  </Row>
                  <Row label={t("diag.plannedChanges")}>{d.enforcement.planned_changes}</Row>
                  <Row label={t("diag.activation")}>
                    {d.enforcement.capabilities.activation_available ? t("common.yes") : t("diag.activationDisabled")}
                  </Row>
                </dl>
                <div>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{t("diag.capabilities")}</h3>
                  <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                    {CAPS.map((c) => (
                      <Row key={c} label={t(`diag.cap.${c}`)}>
                        <Badge tone={capTone[d.enforcement.capabilities[c]] ?? "neutral"}>
                          {tx("diag.cap", d.enforcement.capabilities[c])}
                        </Badge>
                      </Row>
                    ))}
                  </dl>
                </div>
              </div>
              <div className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{t("diag.preconditions")}</h3>
                <ul className="space-y-1.5 text-sm">
                  {d.enforcement.preconditions.map((p) => (
                    <li key={p.id} className="flex items-start justify-between gap-3">
                      <span>{lang === "tr" ? p.tr : p.en}</span>
                      <Badge tone={p.status === "met" ? "success" : p.status === "not_met" ? "danger" : "neutral"}>
                        {tx("diag.precondition", p.status)}
                      </Badge>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title={t("diag.risks")}>
              <List items={d.enforcement.risks} tone="warning" />
            </Card>
            <Card title={t("diag.gaps")}>
              <List items={d.enforcement.enforcement_gaps} tone="warning" />
            </Card>
            <Card title={t("diag.unsupported")}>
              <List items={d.unsupported_features} />
            </Card>
            <Card title={t("diag.pending")}>
              <List items={d.pending_native_tests} />
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
