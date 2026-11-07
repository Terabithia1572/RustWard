import { useMemo, useState } from "react";
import { FlaskConical, RefreshCw } from "lucide-react";
import type { DeviceView, ExplanationView } from "../api/types";
import { Badge, Button, Card, DecisionBadge, Empty, ErrorNotice, Loading, PageHeader, Toggle, inputClass } from "../components/ui";
import { useI18n } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";
import { WindowsStatusCell, useObservation } from "../components/WindowsObservation";
import { AssessmentCell } from "../components/Assessment";
import { useDeviceEpoch } from "../lib/watch";

const STORAGE = new Set(["usb_storage_disk", "usb_storage_other_type", "usb_portable_device", "storage_attachment_unknown"]);

type Filter = "all" | "storage" | "peripherals";

export function deviceName(d: DeviceView): string {
  return d.friendly_name ?? ([d.vendor, d.product].filter(Boolean).join(" ") || d.display_id);
}

function ExplanationPanel({ data }: { data: ExplanationView }) {
  const { lang, t } = useI18n();
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <DecisionBadge decision={data.device.simulated_decision} />
        <Badge tone="warning">{t("badge.notVerified")}</Badge>
      </div>
      <p className="text-sm font-medium">{lang === "tr" ? data.explanation.summary_tr : data.explanation.summary_en}</p>
      <ol className="space-y-2 text-sm">
        {data.explanation.steps.map((s, i) => (
          <li key={`${s.stage}-${i}`} className="flex gap-2">
            <span className="mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full bg-slate-100 text-[11px] font-semibold text-slate-600 dark:bg-slate-800 dark:text-slate-300">
              {i + 1}
            </span>
            <span>{lang === "tr" ? s.tr : s.en}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function DevicesPage() {
  const { t, tx, formatTime, pick } = useI18n();
  const api = useApi();
  const [includeAbsent, setIncludeAbsent] = useState(true);
  const [filter, setFilter] = useState<Filter>("storage");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  // Re-read when Windows reports a device or policy change.
  const epoch = useDeviceEpoch();
  const r = useResource((a) => a.devices(includeAbsent), `devices-${includeAbsent}-${epoch}`);
  const explain = useResource(
    (a) => (selected ? a.explain(selected) : Promise.resolve(null)),
    `explain-${selected ?? ""}-${r.data?.length ?? 0}`,
  );
  const action = useAction();
  const [notice, setNotice] = useState<string | null>(null);
  // Real Windows state per device (read-only observer), re-read with the list.
  const obs = useObservation(`observation-${r.data?.length ?? 0}-${r.loading}`);
  const observed = useMemo(
    () => new Map((obs.data?.devices ?? []).map((d) => [d.device_key, d])),
    [obs.data],
  );

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (r.data ?? []).filter((d) => {
      if (filter === "storage" && !STORAGE.has(d.category)) return false;
      if (filter === "peripherals" && d.category !== "peripheral") return false;
      if (!q) return true;
      return [deviceName(d), d.vendor, d.product, d.vendor_level_id, d.usb_vid_pid, d.matched_brand, d.display_id]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q));
    });
  }, [r.data, filter, query]);

  const runAction = async (type: "refresh_inventory" | "load_synthetic_inventory") => {
    const msg = await action.run(() => api.action(type));
    if (msg !== undefined) {
      setNotice(pick(msg.message, msg.message_tr));
      r.reload();
    }
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("devices.title")}
        actions={
          <>
            <Button icon={<RefreshCw className="size-4" aria-hidden />} busy={action.busy} onClick={() => runAction("refresh_inventory")}>
              {t("devices.refresh")}
            </Button>
            <Button icon={<FlaskConical className="size-4" aria-hidden />} busy={action.busy} onClick={() => runAction("load_synthetic_inventory")}>
              {t("devices.loadSynthetic")}
            </Button>
          </>
        }
      />
      {action.error && <ErrorNotice error={action.error} />}
      {notice && <p className="text-sm text-slate-600 dark:text-slate-300">{notice}</p>}
      <div className="flex flex-wrap items-center gap-3">
        <div className="inline-flex rounded-md border border-slate-300 p-0.5 dark:border-slate-700" role="group">
          {(["all", "storage", "peripherals"] as const).map((f) => (
            <button
              key={f}
              type="button"
              aria-pressed={filter === f}
              onClick={() => setFilter(f)}
              className={`rounded px-2.5 py-1 text-xs font-medium ${
                filter === f ? "bg-slate-800 text-white dark:bg-slate-200 dark:text-slate-900" : "text-slate-600 dark:text-slate-300"
              }`}
            >
              {t(`devices.filter.${f}`)}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <Toggle checked={includeAbsent} onChange={setIncludeAbsent} label={t("devices.includeAbsent")} />
          {t("devices.includeAbsent")}
        </label>
        <input
          type="search"
          aria-label={t("common.search")}
          placeholder={t("devices.searchPlaceholder")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className={`${inputClass} max-w-xs`}
        />
      </div>
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      <div className="grid grid-cols-1 gap-4 2xl:grid-cols-[1fr_380px]">
        <Card>
          {r.loading && !r.data ? (
            <Loading />
          ) : rows.length === 0 ? (
            <Empty />
          ) : (
            <div className="-m-4 overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                  <tr>
                    <th className="px-3 py-2">{t("devices.col.device")}</th>
                    <th className="px-3 py-2">{t("devices.col.type")}</th>
                    <th className="px-3 py-2">{t("devices.col.manufacturer")}</th>
                    <th className="px-3 py-2">{t("devices.col.identity")}</th>
                    <th className="px-3 py-2">{t("devices.col.connection")}</th>
                    <th className="px-3 py-2">{t("devices.col.decision")}</th>
                    <th className="px-3 py-2">{t("devices.col.windows")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {rows.map((d) => (
                    <tr
                      key={d.device_key}
                      onClick={() => setSelected(d.device_key)}
                      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelected(d.device_key)}
                      tabIndex={0}
                      aria-selected={selected === d.device_key}
                      className={`cursor-pointer align-top hover:bg-slate-50 focus:outline-none focus-visible:bg-cyan-50 dark:hover:bg-slate-800/60 ${
                        selected === d.device_key ? "bg-cyan-50/60 dark:bg-cyan-950/40" : ""
                      }`}
                    >
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5 font-medium">
                          {deviceName(d)}
                          {d.synthetic && <Badge tone="synthetic">{t("badge.synthetic")}</Badge>}
                        </div>
                        <div className="break-all font-mono text-[11px] text-slate-500 dark:text-slate-400">{d.display_id}</div>
                      </td>
                      <td className="px-3 py-2">
                        {tx("category", d.category)}
                        {d.storage_type && (
                          <div className="text-xs text-slate-500">
                            {t("devices.interface")}: {d.storage_type}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2" data-testid="manufacturer-cell">
                        {/* A reported string is never a verified identity. */}
                        <div>{d.vendor ? t("devices.reported", { v: d.vendor }) : t("devices.reportedNone")}</div>
                        {d.matched_brand && (
                          <div className="text-xs text-slate-500">{t("devices.policyMatch", { b: d.matched_brand })}</div>
                        )}
                        {STORAGE.has(d.category) && (
                          <div className="text-[11px] text-amber-700 dark:text-amber-400">{t("devices.noCryptoIdentity")}</div>
                        )}
                      </td>
                      <td className="break-all px-3 py-2 font-mono text-[11px]">
                        {d.vendor_level_id && <div>{d.vendor_level_id}</div>}
                        {d.usb_vid_pid && <div className="text-slate-500">VID:PID {d.usb_vid_pid}</div>}
                      </td>
                      <td className="px-3 py-2">
                        <Badge tone={d.present ? "info" : "neutral"}>{d.present ? t("devices.present") : t("devices.absent")}</Badge>
                        <div className="mt-1 text-[11px] text-slate-500">{formatTime(d.last_seen_ms)}</div>
                      </td>
                      <td className="px-3 py-2">
                        <DecisionBadge decision={d.simulated_decision} />
                        {d.simulated_decision !== "not_applicable" && (
                          <div className="mt-1 text-[11px] text-slate-500">{tx("reason", d.reason)}</div>
                        )}
                        {STORAGE.has(d.category) && (
                          <div className="mt-2 min-w-48">
                            <AssessmentCell a={observed.get(d.device_key)?.observed.assessment} />
                          </div>
                        )}
                      </td>
                      <td className="max-w-xs px-3 py-2">
                        {STORAGE.has(d.category) ? (
                          <WindowsStatusCell v={observed.get(d.device_key)} />
                        ) : (
                          <span className="text-xs text-slate-500">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title={t("devices.explainTitle")}>
          {!selected ? (
            <Empty>{t("devices.explainHint")}</Empty>
          ) : explain.error ? (
            <ErrorNotice error={explain.error} />
          ) : explain.data ? (
            <ExplanationPanel data={explain.data} />
          ) : (
            <Loading />
          )}
        </Card>
      </div>
    </div>
  );
}
