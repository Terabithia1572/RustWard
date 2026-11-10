import { useState } from "react";
import {
  CheckCircle2,
  ClipboardCheck,
  Loader2,
  RotateCcw,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import type {
  EnforcementSessionView,
  LadderStepView,
  PolicyChecklistView,
} from "../api/types";
import { useI18n } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";
import { Badge, Button, Card, ErrorNotice, Loading, type Tone } from "./ui";
import { useObservation } from "./WindowsObservation";
import { useDeviceEpoch } from "../lib/watch";

function stepTone(s: LadderStepView): Tone {
  if (s.status === "not_verified") return "warning";
  if (s.status === "no") return "neutral";
  switch (s.code) {
    case "windows_install_denied":
    case "windows_restriction_configured":
      return "success";
    case "enforcement_error":
    case "recovery_required":
      return "danger";
    case "protection_inactive":
      return "warning";
    default:
      return "info";
  }
}

/**
 * Administrator-guided Windows enforcement. RustWard never writes Group
 * Policy: it saves the previous state, the administrator applies the
 * checklist in gpedit.msc, RustWard re-reads, observes and audits.
 */
export function GuidedSessionCard() {
  const { t, lang, formatTime, pick } = useI18n();
  const api = useApi();
  const r = useResource((a) => a.enforcementSession(), "enforcement-session");
  const epoch = useDeviceEpoch();
  const obs = useObservation(`observation-guided-${epoch}`);
  const action = useAction();
  const [view, setView] = useState<EnforcementSessionView | null>(null);
  const [device, setDevice] = useState("");
  const [retro, setRetro] = useState(false);
  const [checklist, setChecklist] = useState<PolicyChecklistView | null>(null);
  const [mismatchError, setMismatchError] = useState<{
    requested: string;
    actual: string;
  } | null>(null);
  const [rollbackDone, setRollbackDone] = useState(false);
  const v = view ?? r.data;

  // What is running, for progress feedback: verifications re-read the whole
  // Windows device inventory and policy, which can take a few seconds.
  const [phase, setPhase] = useState<"prepare" | "verify" | null>(null);
  const run = async (
    fn: () => Promise<EnforcementSessionView>,
    p: "prepare" | "verify" = "verify",
    opts?: {
      expectedDeviceKey?: string;
      expectedRetroactive?: boolean;
      isRollback?: boolean;
    },
  ) => {
    setPhase(p);
    try {
      const res = await action.run(fn);
      if (res) {
        setView(res);
        setChecklist(null);
        if (p === "prepare") {
          setRollbackDone(false);
          if (
            opts?.expectedRetroactive !== undefined &&
            (!res.session ||
              res.session.retroactive !== opts.expectedRetroactive ||
              (opts.expectedDeviceKey !== undefined &&
                res.session.device_key !== opts.expectedDeviceKey))
          ) {
            setMismatchError({
              requested: String(opts.expectedRetroactive),
              actual: res.session ? String(res.session.retroactive) : "none",
            });
          } else {
            setMismatchError(null);
          }
        } else if (opts?.isRollback) {
          setMismatchError(null);
          setRollbackDone(!res.session);
        } else {
          setRollbackDone(false);
          if (!res.session) setMismatchError(null);
        }
        obs.reload();
      }
    } finally {
      setPhase(null);
    }
  };

  return (
    <Card
      title={t("guided.title")}
      actions={<Badge tone="warning">{t("guided.autoUnavailable")}</Badge>}
    >
      <div className="space-y-3 text-sm" data-testid="guided-session">
        {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
        {action.error && <ErrorNotice error={action.error} />}
        {action.busy && phase && (
          <p
            className="flex items-center gap-2 text-cyan-800 dark:text-cyan-300"
            role="status"
            data-testid="guided-progress"
          >
            <Loader2 className="size-4 animate-spin" aria-hidden />
            {phase === "prepare" ? t("guided.busyPrepare") : t("guided.busy")}
          </p>
        )}
        {!v ? (
          !r.error && <Loading />
        ) : (
          <>
            <p
              className="rounded-md border border-amber-200 bg-amber-50 p-2 text-amber-900 dark:border-amber-900 dark:bg-amber-950/50 dark:text-amber-200"
              data-testid="auto-blocker"
            >
              <ShieldAlert
                className="mr-1 inline size-4 align-text-bottom"
                aria-hidden
              />
              {lang === "tr"
                ? v.automated_apply_blocker.tr
                : v.automated_apply_blocker.en}
            </p>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-medium" data-testid="guided-state">
                {lang === "tr" ? v.state_tr : v.state_en}
              </p>
              <div
                className="flex flex-wrap items-center gap-1.5"
                data-testid="guided-status-badges"
              >
                {v.state === "windows_install_denied" ? (
                  <>
                    <Badge tone="success">{t("status.windowsBlockVerified")}</Badge>
                    <Badge tone="warning">{t("status.accessNotVerified")}</Badge>
                  </>
                ) : v.state === "windows_restriction_configured" ? (
                  <Badge tone="info">{t("status.windowsPolicyActive")}</Badge>
                ) : v.session ? (
                  <>
                    <Badge tone="info">{t("status.policyReady")}</Badge>
                    <Badge tone="warning">{t("status.protectionInactive")}</Badge>
                  </>
                ) : (
                  <>
                    <Badge tone="info">{t("status.simulation")}</Badge>
                    <Badge tone="warning">{t("status.protectionInactive")}</Badge>
                  </>
                )}
              </div>
            </div>
            {rollbackDone && !v.session && (
              <div
                className="flex flex-wrap items-center gap-2 rounded-md border border-cyan-200 bg-cyan-50 p-2 text-cyan-950 dark:border-cyan-900 dark:bg-cyan-950/40 dark:text-cyan-200"
                role="status"
                data-testid="guided-rollback-completed"
              >
                <Badge tone="info">{t("status.rollbackCompleted")}</Badge>
                <span>{t("guided.rollbackDoneNote")}</span>
              </div>
            )}
            {mismatchError && (
              <div
                className="rounded-md border border-rose-300 bg-rose-50 p-2 text-rose-900 dark:border-rose-900 dark:bg-rose-950/50 dark:text-rose-200"
                role="alert"
                data-testid="retroactive-mismatch-error"
              >
                {t("guided.retroactiveMismatch", mismatchError)}
              </div>
            )}
            <ul
              className="grid gap-1 sm:grid-cols-2"
              data-testid="guided-ladder"
            >
              {v.ladder.map((s) => (
                <li
                  key={s.code}
                  className="flex items-center justify-between gap-2 rounded border border-slate-200 px-2 py-1 dark:border-slate-800"
                >
                  <span>{lang === "tr" ? s.label_tr : s.label_en}</span>
                  <Badge tone={stepTone(s)}>
                    {t(`guided.status.${s.status}`)}
                  </Badge>
                </li>
              ))}
            </ul>
            {v.policy_error && (
              <p className="text-amber-800 dark:text-amber-300">
                {t("guided.policyError")}
              </p>
            )}
            {v.differences.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wide text-rose-700">
                  {t("guided.differences")}
                </h3>
                <ul className="font-mono text-[11px]">
                  {v.differences.map((d) => (
                    <li key={d} className="break-all">
                      {d}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {!v.session ? (
              <>
                <div
                  className="space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800"
                  data-testid="guided-profile"
                >
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    {t("guided.profile.title")}
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300">
                    {t("guided.profile.note")}
                  </p>
                  <Button
                    icon={<ClipboardCheck className="size-4" aria-hidden />}
                    busy={action.busy}
                    onClick={() =>
                      void run(
                        () => api.prepareDefaultDenySession(),
                        "prepare",
                        {
                          expectedDeviceKey: "default_deny_profile",
                          expectedRetroactive: false,
                        },
                      )
                    }
                  >
                    {t("guided.profile.prepare")}
                  </Button>
                </div>
                <div className="space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800">
                  <p className="text-xs text-slate-600 dark:text-slate-300">
                    {t("guided.prepareNote")}
                  </p>
                  <div className="flex flex-wrap items-center gap-3">
                    <label className="flex items-center gap-2">
                      {t("obs.checklist.device")}
                      <select
                        aria-label={t("obs.checklist.device")}
                        className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
                        value={device}
                        onChange={(e) => setDevice(e.target.value)}
                      >
                        <option value="">{t("guided.chooseDevice")}</option>
                        {(obs.data?.devices ?? []).map((d) => (
                          <option key={d.device_key} value={d.device_key}>
                            {d.observed.name}{" "}
                            {d.observed.vid_pid
                              ? `(${d.observed.vid_pid})`
                              : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={retro}
                        onChange={(e) => setRetro(e.target.checked)}
                      />
                      {t("obs.checklist.retro")}
                    </label>
                    <Button
                      icon={<ClipboardCheck className="size-4" aria-hidden />}
                      disabled={!device}
                      busy={action.busy}
                      onClick={() =>
                        void run(
                          () => api.prepareSession(device, retro),
                          "prepare",
                          {
                            expectedDeviceKey: device,
                            expectedRetroactive: retro,
                          },
                        )
                      }
                    >
                      {t("guided.prepare")}
                    </Button>
                  </div>
                </div>
              </>
            ) : (
              <div
                className="space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800"
                data-testid="guided-active"
              >
                <dl className="grid gap-x-4 gap-y-0.5 sm:grid-cols-2">
                  <dt className="text-slate-500">{t("guided.device")}</dt>
                  <dd>
                    {v.session.kind === "default_deny_profile"
                      ? t("guided.profile.active")
                      : v.session.device_name}
                  </dd>
                  <dt className="text-slate-500">{t("guided.hardwareId")}</dt>
                  <dd className="break-all font-mono text-[11px]">
                    {v.session.hardware_id}
                  </dd>
                  <dt className="text-slate-500">
                    {t("guided.retroactiveLabel")}
                  </dt>
                  <dd data-testid="session-retroactive">
                    {v.session.retroactive
                      ? t("guided.retroactiveYes")
                      : t("guided.retroactiveNo")}
                  </dd>
                  <dt className="text-slate-500">{t("guided.prepared")}</dt>
                  <dd>
                    {formatTime(v.session.prepared_ms)} ·{" "}
                    {v.session.prepared_by}
                  </dd>
                  <dt className="text-slate-500">{t("guided.session")}</dt>
                  <dd className="font-mono text-[11px]">
                    {v.session.session_id}
                  </dd>
                </dl>
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    {t("guided.expected")}
                  </h3>
                  <ul className="font-mono text-[11px]">
                    {v.session.expected_lines.map((l) => (
                      <li key={l} className="break-all">
                        {l}
                      </li>
                    ))}
                  </ul>
                  <h3 className="mt-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                    {t("guided.baseline")}
                  </h3>
                  <ul className="font-mono text-[11px]">
                    {v.session.baseline.length === 0 ? (
                      <li>{t("guided.baselineEmpty")}</li>
                    ) : (
                      v.session.baseline.map((l) => (
                        <li key={l} className="break-all">
                          {l}
                        </li>
                      ))
                    )}
                  </ul>
                </div>
                {v.target && (
                  <p>
                    <span className="text-slate-500">{t("obs.status")}: </span>
                    {v.target.observed.label_status_tr} ·{" "}
                    {v.target.observed.label_policy_tr}
                  </p>
                )}
                <ol className="list-decimal space-y-1 pl-5 text-xs text-slate-700 dark:text-slate-300">
                  <li>{t("guided.step1")}</li>
                  <li>{t("guided.step2")}</li>
                  <li>{t("guided.step3")}</li>
                  <li>{t("guided.step4")}</li>
                </ol>
                <div className="flex flex-wrap gap-2">
                  <Button
                    icon={<CheckCircle2 className="size-4" aria-hidden />}
                    busy={action.busy}
                    onClick={() =>
                      void run(() => api.applyDeviceBlock({ sessionId: v.session!.session_id }))
                    }
                  >
                    {t("guided.directApply")}
                  </Button>
                  <Button
                    icon={<RotateCcw className="size-4" aria-hidden />}
                    busy={action.busy}
                    onClick={() =>
                      void run(
                        () => api.restoreDevicePolicy({ sessionId: v.session!.session_id }),
                        "verify",
                        { isRollback: true },
                      )
                    }
                  >
                    {t("guided.directRollback")}
                  </Button>
                  {v.session.kind !== "default_deny_profile" && (
                    <Button
                      icon={<ClipboardCheck className="size-4" aria-hidden />}
                      busy={action.busy}
                      onClick={() =>
                        void action
                          .run(() =>
                            api.policyChecklist(
                              v.session!.device_key,
                              v.session!.retroactive,
                            ),
                          )
                          .then((c) => c && setChecklist(c))
                      }
                    >
                      {t("guided.showChecklist")}
                    </Button>
                  )}
                  <Button
                    icon={<CheckCircle2 className="size-4" aria-hidden />}
                    disabled={Boolean(mismatchError)}
                    busy={action.busy}
                    onClick={() =>
                      void run(() => api.verifyApplied(v.session!.session_id))
                    }
                  >
                    {t("guided.verifyApplied")}
                  </Button>
                  <Button
                    icon={<RotateCcw className="size-4" aria-hidden />}
                    busy={action.busy}
                    onClick={() =>
                      void run(
                        () => api.verifyRollback(v.session!.session_id),
                        "verify",
                        { isRollback: true },
                      )
                    }
                  >
                    {t("guided.verifyRollback")}
                  </Button>
                  <Button
                    variant="ghost"
                    icon={<XCircle className="size-4" aria-hidden />}
                    busy={action.busy}
                    onClick={() =>
                      void run(() => api.cancelSession(v.session!.session_id))
                    }
                  >
                    {t("guided.cancel")}
                  </Button>
                </div>
                {v.session.checklist_text && (
                  <pre
                    className="max-h-96 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] [overflow-wrap:anywhere] dark:border-slate-800 dark:bg-slate-950"
                    data-testid="guided-profile-checklist"
                  >
                    {v.session.checklist_text}
                  </pre>
                )}
                {checklist && (
                  <pre
                    className="max-h-80 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] [overflow-wrap:anywhere] dark:border-slate-800 dark:bg-slate-950"
                    data-testid="guided-checklist"
                  >
                    {checklist.text}
                  </pre>
                )}
                {v.session.last_verification && (
                  <p className="text-xs text-slate-500">
                    {t("guided.lastVerification", {
                      time: formatTime(v.session.last_verification_ms),
                      result: pick(
                        v.session.last_verification,
                        v.session.last_verification ===
                          "enforcement_session_apply_verified"
                          ? t("guided.verifiedOk")
                          : t("guided.verifiedBad"),
                      ),
                    })}
                  </p>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  );
}
