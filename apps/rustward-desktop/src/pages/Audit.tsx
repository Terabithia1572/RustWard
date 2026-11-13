import { useState } from "react";
import { Download, ShieldCheck } from "lucide-react";
import type { AuditChainVerificationView, EventQuery, EventView, ExportFormat } from "../api/types";
import { Badge, Button, Card, Dialog, Empty, ErrorNotice, Field, Loading, PageHeader, inputClass, type Tone } from "../components/ui";
import { useI18n } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";

const PAGE = 50;

const severityTone: Record<string, Tone> = { info: "info", warning: "warning", critical: "danger" };

export function EventRow({
  e,
  compact = false,
  onInspect,
}: {
  e: EventView;
  compact?: boolean;
  onInspect?: (e: EventView) => void;
}) {
  const { t, tx, formatTime, pick } = useI18n();
  return (
    <tr
      className={`border-b border-slate-100 align-top last:border-0 dark:border-slate-800 ${
        !compact && onInspect ? "cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" : ""
      }`}
      onClick={!compact && onInspect ? () => onInspect(e) : undefined}
    >
      <td className="py-1.5 pr-3 whitespace-nowrap text-xs text-slate-500">{formatTime(e.utc_ms)}</td>
      <td className="py-1.5 pr-3">
        <Badge tone={severityTone[e.severity] ?? "neutral"}>{tx("audit.severity", e.severity)}</Badge>
      </td>
      {!compact && <td className="py-1.5 pr-3 font-mono text-xs [overflow-wrap:anywhere]">{e.kind}</td>}
      {!compact && (
        <td className="py-1.5 pr-3 text-xs">
          <div className="font-medium text-slate-800 dark:text-slate-200">{e.device_name ?? "—"}</div>
          {(e.manufacturer_id || e.vid_pid) && (
            <div className="font-mono text-[11px] text-slate-500">
              {[e.manufacturer_id, e.vid_pid].filter(Boolean).join(" · ")}
            </div>
          )}
        </td>
      )}
      {!compact && (
        <td className="py-1.5 pr-3 text-xs">
          {e.effective_decision && <span className="font-medium">{e.effective_decision}</span>}
          {e.enforcement_outcome && (
            <div className="text-[11px] text-slate-500">
              {e.enforcement_outcome}
              {e.pnp_problem_code !== null && e.pnp_problem_code !== undefined ? ` (PnP ${e.pnp_problem_code})` : ""}
            </div>
          )}
          {!e.effective_decision && !e.enforcement_outcome && "—"}
        </td>
      )}
      {!compact && (
        <td className="py-1.5 pr-3 text-xs">
          <div>{e.actor_username ?? "—"}</div>
          {e.windows_user && <div className="font-mono text-[11px] text-slate-500">{e.windows_user}</div>}
        </td>
      )}
      <td className="min-w-0 py-1.5 pr-3 [overflow-wrap:anywhere]">{pick(e.message, e.message_tr)}</td>
      <td className="py-1.5">
        {e.simulated ? <Badge tone="synthetic">{t("audit.origin.simulated")}</Badge> : <Badge>{t("audit.origin.real")}</Badge>}
      </td>
    </tr>
  );
}

function toMs(date: string, endOfDay: boolean): number | null {
  if (!date) return null;
  const d = new Date(`${date}T${endOfDay ? "23:59:59.999" : "00:00:00"}`);
  return Number.isNaN(d.getTime()) ? null : d.getTime() + (endOfDay ? 1 : 0);
}

/** Trigger a local file download of exported content. */
export function downloadText(fileName: string, mime: string, content: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function AuditPage() {
  const { t, formatTime, pick } = useI18n();
  const api = useApi();
  const [text, setText] = useState("");
  const [minSeverity, setMinSeverity] = useState<"" | "info" | "warning" | "critical">("");
  const [origin, setOrigin] = useState<"" | "simulated" | "real">("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [manufacturerId, setManufacturerId] = useState("");
  const [deviceQuery, setDeviceQuery] = useState("");
  const [actorUsername, setActorUsername] = useState("");
  const [windowsUser, setWindowsUser] = useState("");
  const [effectiveDecision, setEffectiveDecision] = useState("");
  const [offset, setOffset] = useState(0);
  const [inspecting, setInspecting] = useState<EventView | null>(null);
  const [chainResult, setChainResult] = useState<AuditChainVerificationView | null>(null);

  const query: EventQuery = {
    text: text.trim() || null,
    min_severity: minSeverity || null,
    simulated: origin === "" ? null : origin === "simulated",
    since_ms: toMs(from, false),
    until_ms: toMs(to, true),
    manufacturer_id: manufacturerId.trim() || null,
    device_query: deviceQuery.trim() || null,
    actor_username: actorUsername.trim() || null,
    windows_user: windowsUser.trim() || null,
    effective_decision: effectiveDecision.trim() || null,
    limit: PAGE,
    offset,
  };
  const key = JSON.stringify(query);
  const r = useResource((a) => a.queryAuditEvents(query), key);
  const exporter = useAction();
  const chainAction = useAction();
  const [notice, setNotice] = useState<string | null>(null);

  const doExport = async (format: ExportFormat) => {
    const res = await exporter.run(() => api.exportEvents({ ...query, limit: 5000, offset: 0 }, format));
    if (res) {
      downloadText(res.file_name, res.mime, res.content);
      setNotice(t("audit.exported", { count: res.count }));
    }
  };

  const verifyChain = async () => {
    const res = await chainAction.run(() => api.verifyAuditChain());
    if (res) setChainResult(res);
  };

  const reset = (fn: () => void) => {
    fn();
    setOffset(0);
  };

  const pageData = r.data;
  const events = pageData?.events ?? [];
  const totalCount = pageData?.total_count ?? 0;
  const fromIdx = totalCount === 0 ? 0 : offset + 1;
  const toIdx = Math.min(totalCount, offset + events.length);

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("audit.title")}
        subtitle={t("audit.chainNote")}
        actions={
          <>
            <Button
              icon={<ShieldCheck className="size-4" aria-hidden />}
              busy={chainAction.busy}
              onClick={() => void verifyChain()}
            >
              {t("audit.verifyChain")}
            </Button>
            <Button icon={<Download className="size-4" aria-hidden />} busy={exporter.busy} onClick={() => void doExport("csv")}>
              {t("audit.exportCsv")}
            </Button>
            <Button icon={<Download className="size-4" aria-hidden />} busy={exporter.busy} onClick={() => void doExport("json")}>
              {t("audit.exportJson")}
            </Button>
          </>
        }
      />
      {(exporter.error ?? chainAction.error) && <ErrorNotice error={(exporter.error ?? chainAction.error)!} />}
      {notice && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{notice}</p>}
      {chainResult && (
        <div
          role="status"
          data-testid="audit-chain-banner"
          className={`rounded-md border p-3 text-sm ${
            chainResult.intact
              ? "border-emerald-300 bg-emerald-50 text-emerald-950 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-100"
              : "border-rose-300 bg-rose-50 text-rose-950 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-100"
          }`}
        >
          {chainResult.intact
            ? t("audit.chainVerifiedOk", { entries: chainResult.entries })
            : t("audit.chainVerifiedBad", { summary: pick(chainResult.summary_en, chainResult.summary_tr) })}
        </div>
      )}
      <Card>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <Field label={t("common.search")}>
            {(id) => <input id={id} type="search" className={inputClass} value={text} onChange={(e) => reset(() => setText(e.target.value))} />}
          </Field>
          <Field label={t("audit.minSeverity")}>
            {(id) => (
              <select id={id} className={inputClass} value={minSeverity} onChange={(e) => reset(() => setMinSeverity(e.target.value as typeof minSeverity))}>
                <option value="">{t("common.all")}</option>
                <option value="info">{t("audit.severity.info")}</option>
                <option value="warning">{t("audit.severity.warning")}</option>
                <option value="critical">{t("audit.severity.critical")}</option>
              </select>
            )}
          </Field>
          <Field label={t("audit.origin")}>
            {(id) => (
              <select id={id} className={inputClass} value={origin} onChange={(e) => reset(() => setOrigin(e.target.value as typeof origin))}>
                <option value="">{t("common.all")}</option>
                <option value="simulated">{t("audit.origin.simulated")}</option>
                <option value="real">{t("audit.origin.real")}</option>
              </select>
            )}
          </Field>
          <Field label={t("audit.from")}>
            {(id) => <input id={id} type="date" className={inputClass} value={from} onChange={(e) => reset(() => setFrom(e.target.value))} />}
          </Field>
          <Field label={t("audit.to")}>
            {(id) => <input id={id} type="date" className={inputClass} value={to} onChange={(e) => reset(() => setTo(e.target.value))} />}
          </Field>
          <Field label={t("audit.filter.manufacturer")}>
            {(id) => <input id={id} className={inputClass} placeholder="kingston / sandisk" value={manufacturerId} onChange={(e) => reset(() => setManufacturerId(e.target.value))} />}
          </Field>
          <Field label={t("audit.filter.device")}>
            {(id) => <input id={id} className={inputClass} placeholder="0951:1666" value={deviceQuery} onChange={(e) => reset(() => setDeviceQuery(e.target.value))} />}
          </Field>
          <Field label={t("audit.filter.actor")}>
            {(id) => <input id={id} className={inputClass} value={actorUsername} onChange={(e) => reset(() => setActorUsername(e.target.value))} />}
          </Field>
          <Field label={t("audit.filter.windowsUser")}>
            {(id) => <input id={id} className={inputClass} value={windowsUser} onChange={(e) => reset(() => setWindowsUser(e.target.value))} />}
          </Field>
          <Field label={t("audit.filter.decision")}>
            {(id) => <input id={id} className={inputClass} placeholder="allow / deny" value={effectiveDecision} onChange={(e) => reset(() => setEffectiveDecision(e.target.value))} />}
          </Field>
        </div>
      </Card>
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      <Card>
        {r.loading && !pageData ? (
          <Loading />
        ) : events.length === 0 ? (
          <Empty />
        ) : (
          <div className="-m-4 overflow-x-auto p-4">
            <table className="w-full min-w-[960px] text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="pb-2 pr-3">{t("audit.time")}</th>
                  <th className="pb-2 pr-3">{t("audit.severity")}</th>
                  <th className="pb-2 pr-3">{t("audit.kind")}</th>
                  <th className="pb-2 pr-3">{t("audit.col.device")}</th>
                  <th className="pb-2 pr-3">{t("audit.col.decision")}</th>
                  <th className="pb-2 pr-3">{t("audit.col.actor")}</th>
                  <th className="pb-2 pr-3">{t("audit.message")}</th>
                  <th className="pb-2">{t("audit.origin")}</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <EventRow key={e.id} e={e} onInspect={setInspecting} />
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span>{t("audit.totalRecords", { total: totalCount, from: fromIdx, to: toIdx })}</span>
            {pageData && (
              <Badge tone={pageData.chain_ok ? "success" : "danger"}>{pageData.chain_status}</Badge>
            )}
          </div>
          <div className="flex gap-2">
            <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
              {t("common.previous")}
            </Button>
            <Button disabled={offset + PAGE >= totalCount} onClick={() => setOffset(offset + PAGE)}>
              {t("common.next")}
            </Button>
          </div>
        </div>
      </Card>
      {inspecting && (
        <Dialog
          open
          wide
          title={t("audit.detailsTitle")}
          onClose={() => setInspecting(null)}
          footer={<Button onClick={() => setInspecting(null)}>{t("common.close")}</Button>}
        >
          <div className="space-y-3 text-xs" data-testid="audit-details-modal">
            <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2">
              <div><dt className="text-slate-500">ID</dt><dd className="font-mono">#{inspecting.id}</dd></div>
              <div><dt className="text-slate-500">{t("audit.time")}</dt><dd>{formatTime(inspecting.utc_ms)}</dd></div>
              <div><dt className="text-slate-500">{t("audit.kind")}</dt><dd className="font-mono">{inspecting.kind}</dd></div>
              <div><dt className="text-slate-500">{t("dashboard.workstation")}</dt><dd className="font-mono">{inspecting.computer_name ?? "—"}</dd></div>
              <div><dt className="text-slate-500">{t("audit.filter.manufacturer")}</dt><dd className="font-mono">{inspecting.manufacturer_id ?? "—"}</dd></div>
              <div><dt className="text-slate-500">{t("audit.filter.device")}</dt><dd className="font-mono">{inspecting.device_name ?? "—"} {inspecting.vid_pid ? `(${inspecting.vid_pid})` : ""}</dd></div>
              <div><dt className="text-slate-500">{t("audit.col.decision")}</dt><dd className="font-mono">{inspecting.effective_decision ?? "—"} · {inspecting.enforcement_outcome ?? "—"}</dd></div>
              <div><dt className="text-slate-500">{t("audit.col.actor")}</dt><dd className="font-mono">{inspecting.actor_username ?? "—"} / {inspecting.windows_user ?? "—"}</dd></div>
            </dl>
            <p className="rounded bg-slate-50 p-2 text-sm dark:bg-slate-900">{pick(inspecting.message, inspecting.message_tr)}</p>
            {inspecting.hash && (
              <div className="break-all font-mono text-[11px] text-slate-500">
                {t("audit.detailsChainHash")}: {inspecting.hash}
              </div>
            )}
            {inspecting.details !== undefined && (
              <pre className="max-h-56 overflow-auto rounded bg-slate-950 p-3 font-mono text-[11px] text-slate-100">
                {JSON.stringify(inspecting.details, null, 2)}
              </pre>
            )}
          </div>
        </Dialog>
      )}
    </div>
  );
}
