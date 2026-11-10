import { useMemo, useState } from "react";
import { FlaskConical, RefreshCw, RotateCcw, ShieldAlert } from "lucide-react";
import type { DeviceView, ExplanationView, ObservedDeviceView } from "../api/types";
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

function ExplanationPanel({
  data,
  observed,
  onBlock,
  onUnblock,
  actionBusy,
}: {
  data: ExplanationView;
  observed?: ObservedDeviceView | undefined;
  onBlock?: (() => void) | undefined;
  onUnblock?: (() => void) | undefined;
  actionBusy?: boolean | undefined;
}) {
  const { lang, t } = useI18n();
  const isStorage = STORAGE.has(data.device.category);
  const isDenied = observed?.observed.evidence === "install_denied";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <DecisionBadge decision={data.device.simulated_decision} />
        {isDenied ? (
          <Badge tone="danger">{t("status.windowsBlockVerified")}</Badge>
        ) : (
          <Badge tone="warning">{t("badge.notVerified")}</Badge>
        )}
      </div>

      {isStorage && (
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-900/60 space-y-2">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            {t("devices.col.enforcement")}
          </div>
          {isDenied ? (
            <div className="space-y-2">
              <p className="text-xs text-rose-700 dark:text-rose-400 font-medium">
                {t("status.windowsBlockVerified")}
              </p>
              <Button
                variant="primary"
                icon={<RotateCcw className="size-4" aria-hidden />}
                busy={Boolean(actionBusy)}
                onClick={onUnblock}
              >
                {t("devices.action.unblock")}
              </Button>
            </div>
          ) : (
            <div className="space-y-2">
              <Button
                variant="danger"
                icon={<ShieldAlert className="size-4" aria-hidden />}
                busy={Boolean(actionBusy)}
                onClick={onBlock}
              >
                {t("devices.action.block")}
              </Button>
            </div>
          )}
        </div>
      )}

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
  const [blockModalOpen, setBlockModalOpen] = useState(false);
  const [unblockModalOpen, setUnblockModalOpen] = useState(false);
  const [retroactive, setRetroactive] = useState(true);
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
                            {t("devices.interface")}: {tx("devices.transport", d.storage_type)}
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
                        {STORAGE.has(d.category) && observed.has(d.device_key) && (() => {
                          const o = observed.get(d.device_key)!.observed;
                          if (o.problem_code != null) {
                            return (
                              <div className="mt-1">
                                <Badge tone="danger">{t("devices.driver.problem", { code: o.problem_code })}</Badge>
                              </div>
                            );
                          }
                          if (o.driver_installed === true) {
                            return (
                              <div className="mt-1">
                                <Badge tone="neutral">{t("devices.driver.installed")}</Badge>
                              </div>
                            );
                          }
                          if (o.driver_installed === false) {
                            return (
                              <div className="mt-1">
                                <Badge tone="warning">{t("devices.driver.notInstalled")}</Badge>
                              </div>
                            );
                          }
                          return null;
                        })()}
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
            <ExplanationPanel
              data={explain.data}
              observed={selected ? observed.get(selected) : undefined}
              onBlock={() => setBlockModalOpen(true)}
              onUnblock={() => setUnblockModalOpen(true)}
              actionBusy={action.busy}
            />
          ) : (
            <Loading />
          )}
        </Card>
      </div>

      {blockModalOpen && (() => {
        const selectedDevice = (r.data ?? []).find((d) => d.device_key === selected);
        const selectedObs = selected ? observed.get(selected) : undefined;
        if (!selectedDevice) return null;
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
            <div className="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-4">
              <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 font-semibold text-lg">
                <ShieldAlert className="size-5" />
                <h3>{t("devices.action.blockModalTitle")}</h3>
              </div>
              <p className="text-sm text-slate-600 dark:text-slate-300">
                {t("devices.action.blockWarning")}
              </p>
              <div className="rounded-lg bg-slate-50 p-3 dark:bg-slate-800/60 space-y-2 text-xs font-mono">
                <div><span className="text-slate-500 font-sans">{t("devices.action.targetDevice")}:</span> {deviceName(selectedDevice)}</div>
                <div className="break-all"><span className="text-slate-500 font-sans">{t("devices.action.targetHwid")}:</span> {selectedObs?.observed.hardware_id ?? selectedDevice.vendor_level_id ?? selectedDevice.display_id}</div>
                {selectedDevice.usb_vid_pid && <div><span className="text-slate-500 font-sans">VID:PID:</span> {selectedDevice.usb_vid_pid}</div>}
              </div>
              <label className="flex items-start gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={retroactive}
                  onChange={(e) => setRetroactive(e.target.checked)}
                  className="mt-1 rounded border-slate-300"
                />
                <div>
                  <div className="font-medium">{t("devices.action.retroactive")}</div>
                  <div className="text-xs text-slate-500">{t("devices.action.retroactiveHint")}</div>
                </div>
              </label>
              {action.error && <ErrorNotice error={action.error} />}
              <div className="flex justify-end gap-2 pt-2">
                <Button variant="ghost" disabled={action.busy} onClick={() => setBlockModalOpen(false)}>
                  {t("common.cancel")}
                </Button>
                <Button
                  variant="danger"
                  busy={action.busy}
                  onClick={async () => {
                    const res = await action.run(() =>
                      api.applyDeviceBlock({
                        deviceKey: selectedDevice.device_key,
                        retroactive,
                      })
                    );
                    if (res) {
                      setBlockModalOpen(false);
                      setNotice(t("devices.action.blockSuccess"));
                      r.reload();
                      obs.reload();
                    }
                  }}
                >
                  {t("devices.action.confirmBlock")}
                </Button>
              </div>
            </div>
          </div>
        );
      })()}

      {unblockModalOpen && (() => {
        const selectedDevice = (r.data ?? []).find((d) => d.device_key === selected);
        const selectedObs = selected ? observed.get(selected) : undefined;
        if (!selectedDevice) return null;
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
            <div className="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-4">
              <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-semibold text-lg">
                <RotateCcw className="size-5" />
                <h3>{t("devices.action.unblockModalTitle")}</h3>
              </div>
              <p className="text-sm text-slate-600 dark:text-slate-300">
                {t("devices.action.unblockNote")}
              </p>
              <div className="rounded-lg bg-slate-50 p-3 dark:bg-slate-800/60 space-y-2 text-xs font-mono">
                <div><span className="text-slate-500 font-sans">{t("devices.action.targetDevice")}:</span> {deviceName(selectedDevice)}</div>
                <div className="break-all"><span className="text-slate-500 font-sans">{t("devices.action.targetHwid")}:</span> {selectedObs?.observed.hardware_id ?? selectedDevice.vendor_level_id ?? selectedDevice.display_id}</div>
              </div>
              {action.error && <ErrorNotice error={action.error} />}
              <div className="flex justify-end gap-2 pt-2">
                <Button variant="ghost" disabled={action.busy} onClick={() => setUnblockModalOpen(false)}>
                  {t("common.cancel")}
                </Button>
                <Button
                  variant="primary"
                  busy={action.busy}
                  onClick={async () => {
                    const res = await action.run(() => api.restoreDevicePolicy());
                    if (res) {
                      setUnblockModalOpen(false);
                      setNotice(t("devices.action.unblockSuccess"));
                      r.reload();
                      obs.reload();
                    }
                  }}
                >
                  {t("devices.action.confirmUnblock")}
                </Button>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
