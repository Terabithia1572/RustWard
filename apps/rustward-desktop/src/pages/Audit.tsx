import { useState } from "react";
import { Download } from "lucide-react";
import type { EventQuery, EventView, ExportFormat } from "../api/types";
import { Badge, Button, Card, Empty, ErrorNotice, Field, Loading, PageHeader, inputClass, type Tone } from "../components/ui";
import { useI18n } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";

const PAGE = 100;

const severityTone: Record<string, Tone> = { info: "info", warning: "warning", critical: "danger" };

export function EventRow({ e, compact = false }: { e: EventView; compact?: boolean }) {
  const { t, tx, formatTime, pick } = useI18n();
  return (
    <tr className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800">
      <td className="py-1.5 pr-3 text-xs text-slate-500">{formatTime(e.utc_ms)}</td>
      <td className="py-1.5 pr-3">
        <Badge tone={severityTone[e.severity] ?? "neutral"}>{tx("audit.severity", e.severity)}</Badge>
      </td>
      {!compact && <td className="py-1.5 pr-3 font-mono text-xs [overflow-wrap:anywhere]">{e.kind}</td>}
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
  const { t } = useI18n();
  const api = useApi();
  const [text, setText] = useState("");
  const [minSeverity, setMinSeverity] = useState<"" | "info" | "warning" | "critical">("");
  const [origin, setOrigin] = useState<"" | "simulated" | "real">("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [offset, setOffset] = useState(0);

  const query: EventQuery = {
    text: text.trim() || null,
    min_severity: minSeverity || null,
    simulated: origin === "" ? null : origin === "simulated",
    since_ms: toMs(from, false),
    until_ms: toMs(to, true),
    limit: PAGE,
    offset,
  };
  const key = JSON.stringify(query);
  const r = useResource((a) => a.events(query), key);
  const exporter = useAction();
  const [notice, setNotice] = useState<string | null>(null);

  const doExport = async (format: ExportFormat) => {
    const res = await exporter.run(() => api.exportEvents({ ...query, limit: 5000, offset: 0 }, format));
    if (res) {
      downloadText(res.file_name, res.mime, res.content);
      setNotice(t("audit.exported", { count: res.count }));
    }
  };

  const reset = (fn: () => void) => {
    fn();
    setOffset(0);
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("audit.title")}
        subtitle={t("audit.chainNote")}
        actions={
          <>
            <Button icon={<Download className="size-4" aria-hidden />} busy={exporter.busy} onClick={() => void doExport("csv")}>
              {t("audit.exportCsv")}
            </Button>
            <Button icon={<Download className="size-4" aria-hidden />} busy={exporter.busy} onClick={() => void doExport("json")}>
              {t("audit.exportJson")}
            </Button>
          </>
        }
      />
      {exporter.error && <ErrorNotice error={exporter.error} />}
      {notice && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{notice}</p>}
      <Card>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
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
        </div>
      </Card>
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      <Card>
        {r.loading && !r.data ? (
          <Loading />
        ) : !r.data || r.data.length === 0 ? (
          <Empty />
        ) : (
          <div className="-m-4 overflow-x-auto p-4">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="pb-2 pr-3">{t("audit.time")}</th>
                <th className="pb-2 pr-3">{t("audit.severity")}</th>
                <th className="pb-2 pr-3">{t("audit.kind")}</th>
                <th className="pb-2 pr-3">{t("audit.message")}</th>
                <th className="pb-2">{t("audit.origin")}</th>
              </tr>
            </thead>
            <tbody>
              {r.data.map((e) => (
                <EventRow key={e.id} e={e} />
              ))}
            </tbody>
          </table>
          </div>
        )}
        <div className="mt-3 flex justify-end gap-2">
          <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            {t("common.previous")}
          </Button>
          <Button disabled={(r.data?.length ?? 0) < PAGE} onClick={() => setOffset(offset + PAGE)}>
            {t("common.next")}
          </Button>
        </div>
      </Card>
    </div>
  );
}
