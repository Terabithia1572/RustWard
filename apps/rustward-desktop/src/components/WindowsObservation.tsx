import { useState } from "react";
import { ClipboardCopy, Eye, FileText } from "lucide-react";
import type { EnforcementObservationView, ObservedDevice, ObservedDeviceView, ObservedState, PolicyChecklistView } from "../api/types";
import { useI18n } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";
import { Badge, Button, Card, Empty, ErrorNotice, Loading, type Tone } from "./ui";

const stateTone: Record<ObservedState, Tone> = {
  SIMULATED_DENY: "synthetic",
  NO_WINDOWS_RESTRICTION: "neutral",
  WINDOWS_RULE_CONFIGURED: "info",
  WINDOWS_INSTALL_DENIED: "danger",
  WINDOWS_ACCESS_NOT_VERIFIED: "warning",
  STATUS_UNKNOWN: "neutral",
  POLICY_MISMATCH: "warning",
};

/** Real Windows observation, shared by the Devices and Readiness pages. */
export function useObservation(key = "observation") {
  return useResource((a) => a.enforcementObservation(), key);
}

/** "Current" vs "historical" evidence badge. Never claims a block without current evidence. */
export function EvidenceBadge({ o }: { o: ObservedDevice }) {
  const { t, formatTime } = useI18n();
  if (o.evidence === "install_denied") {
    return <Badge tone="danger">{t("obs.evidence.current")}</Badge>;
  }
  if (o.history) {
    return (
      <Badge tone="neutral" title={formatTime(o.history.observed_ms)}>
        {t("obs.evidence.history", { time: formatTime(o.history.observed_ms), code: o.history.problem_code })}
      </Badge>
    );
  }
  return <Badge tone="neutral">{t("obs.evidence.none")}</Badge>;
}

/** Compact Windows status for a device table cell. */
export function WindowsStatusCell({ v }: { v: ObservedDeviceView | undefined }) {
  const { t, tx, formatTime } = useI18n();
  if (!v) return <span className="text-xs text-slate-500">—</span>;
  const o = v.observed;
  return (
    <div className="min-w-0 space-y-0.5 text-xs" data-testid="windows-status">
      <div>
        <span className="text-slate-500">{t("obs.policy")}: </span>
        <span className="[overflow-wrap:anywhere]">{o.label_policy_tr}</span>
      </div>
      <div>
        <span className="text-slate-500">{t("obs.status")}: </span>
        {o.label_status_tr}
      </div>
      <EvidenceBadge o={o} />
      {o.hardware_id && (
        <div className="break-all font-mono text-[10px] text-slate-500" title={t("devices.hardwareId")}>
          {o.hardware_id}
        </div>
      )}
      {v.last_event_kind && (
        <div data-testid="last-event">
          <span className="text-slate-500">{t("devices.lastEvent")}: </span>
          {tx("event", v.last_event_kind)} · {formatTime(v.last_event_ms)}
        </div>
      )}
    </div>
  );
}

function StateBadges({ states }: { states: ObservedState[] }) {
  const { tx } = useI18n();
  return (
    <div className="flex flex-wrap gap-1">
      {states.map((s) => (
        <Badge key={s} tone={stateTone[s]} title={s}>
          {tx("obs.state", s)}
        </Badge>
      ))}
    </div>
  );
}

function Header({ v }: { v: EnforcementObservationView }) {
  const { t, formatTime } = useI18n();
  const yesNo = (b: boolean) => (b ? t("common.yes") : t("common.no"));
  return (
    <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2" data-testid="observation-header">
      <div className="flex justify-between gap-2">
        <dt className="text-slate-500">{t("obs.keyPresent")}</dt>
        <dd>{v.policy_error ? t("obs.unreadable") : yesNo(v.policy_key_present)}</dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-slate-500">{t("obs.restrictions")}</dt>
        <dd>{v.policy_error ? t("obs.unreadable") : yesNo(v.windows_restrictions_configured)}</dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-slate-500">{t("obs.policyTime")}</dt>
        <dd>{formatTime(v.policy_captured_ms)}</dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-slate-500">{t("obs.inventoryTime")}</dt>
        <dd>{formatTime(v.inventory_collected_unix_seconds === null ? null : v.inventory_collected_unix_seconds * 1000)}</dd>
      </div>
    </dl>
  );
}

/** Readiness page: the real Windows observation. */
export function ObservationCard() {
  const { t, tx } = useI18n();
  const r = useObservation();
  const v = r.data;
  return (
    <Card
      title={t("obs.title")}
      actions={
        <Button icon={<Eye className="size-4" aria-hidden />} onClick={r.reload} busy={r.loading}>
          {t("obs.reread")}
        </Button>
      }
    >
      <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">{t("obs.note")}</p>
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      {!v ? (
        !r.error && <Loading />
      ) : (
        <div className="space-y-3" data-testid="observation">
          <Header v={v} />
          {v.policy_error && <p className="text-sm text-amber-800 dark:text-amber-300">{t("obs.unreadableNote")}</p>}
          {v.devices.length === 0 ? (
            <Empty>{t("obs.noDevices")}</Empty>
          ) : (
            <div className="-mx-4 overflow-x-auto">
              <table className="w-full table-fixed text-sm">
                <thead className="border-y border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                  <tr>
                    <th className="w-[26%] px-3 py-2">{t("obs.col.device")}</th>
                    <th className="w-[14%] px-3 py-2">{t("obs.col.rustward")}</th>
                    <th className="w-[24%] px-3 py-2">{t("obs.col.policy")}</th>
                    <th className="w-[18%] px-3 py-2">{t("obs.col.status")}</th>
                    <th className="w-[18%] px-3 py-2">{t("obs.col.evidence")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {v.devices.map(({ device_key, observed: o }) => (
                    <tr key={device_key} className="align-top" data-testid={`obs-${device_key}`}>
                      <td className="px-3 py-2">
                        <div className="font-medium [overflow-wrap:anywhere]">{o.name}</div>
                        <div className="text-xs text-slate-500">
                          {o.vid_pid && <>VID:PID {o.vid_pid} · </>}
                          {t("obs.reported")}: {o.reported_vendor ?? "—"}
                          {o.reported_product && ` / ${o.reported_product}`}
                        </div>
                        <div className="break-all font-mono text-[11px] text-slate-500">{o.hardware_id ?? "—"}</div>
                      </td>
                      <td className="px-3 py-2">
                        {o.label_rustward_tr}
                        <div className="text-[11px] text-slate-500">{tx("reason", o.rustward_reason)}</div>
                      </td>
                      <td className="px-3 py-2 [overflow-wrap:anywhere]">{o.label_policy_tr}</td>
                      <td className="px-3 py-2">{o.label_status_tr}</td>
                      <td className="space-y-1 px-3 py-2">
                        <EvidenceBadge o={o} />
                        <StateBadges states={o.states} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {v.devices
            .filter((d) => d.observed.explanation_tr)
            .map(({ device_key, observed: o }) => (
              <p key={device_key} className="text-xs text-slate-600 dark:text-slate-300">
                <span className="font-medium">{o.name}:</span> {o.explanation_tr}
              </p>
            ))}
          <p className="text-xs text-slate-500">{t("obs.appliesNothing")}</p>
          <ChecklistSection v={v} />
        </div>
      )}
    </Card>
  );
}

/** Administrator checklist: generated and copied, never applied. */
function ChecklistSection({ v }: { v: EnforcementObservationView }) {
  const { t } = useI18n();
  const api = useApi();
  const action = useAction();
  const [key, setKey] = useState(v.devices[0]?.device_key ?? "");
  const [retro, setRetro] = useState(false);
  const [result, setResult] = useState<PolicyChecklistView | null>(null);
  const [copied, setCopied] = useState(false);
  if (v.devices.length === 0) return null;
  const generate = async () => {
    setCopied(false);
    const c = await action.run(() => api.policyChecklist(key, retro));
    if (c) setResult(c);
  };
  const copy = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800" data-testid="checklist">
      <h3 className="text-sm font-semibold">{t("obs.checklist.title")}</h3>
      <p className="text-xs text-slate-600 dark:text-slate-300">{t("obs.checklist.note")}</p>
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-2">
          {t("obs.checklist.device")}
          <select
            className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
            value={key}
            onChange={(e) => {
              setKey(e.target.value);
              setResult(null);
            }}
          >
            {v.devices.map((d) => (
              <option key={d.device_key} value={d.device_key}>
                {d.observed.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={retro} onChange={(e) => setRetro(e.target.checked)} />
          {t("obs.checklist.retro")}
        </label>
        <Button icon={<FileText className="size-4" aria-hidden />} busy={action.busy} onClick={generate}>
          {t("obs.checklist.generate")}
        </Button>
        {result && (
          <Button icon={<ClipboardCopy className="size-4" aria-hidden />} onClick={copy}>
            {copied ? t("obs.checklist.copied") : t("obs.checklist.copy")}
          </Button>
        )}
      </div>
      {action.error && <ErrorNotice error={action.error} />}
      {result && (
        <pre
          className="max-h-96 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] [overflow-wrap:anywhere] dark:border-slate-800 dark:bg-slate-950"
          data-testid="checklist-text"
        >
          {result.text}
        </pre>
      )}
    </div>
  );
}
