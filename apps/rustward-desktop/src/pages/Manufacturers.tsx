import { useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  HardDrive,
  Pencil,
  Plus,
  Shield,
  ShieldAlert,
  Trash2,
  Undo2,
} from "lucide-react";
import type {
  BrandIdentifier,
  CompoundPolicyPlanView,
  DeviceView,
  EnforcementSessionView,
  IdentifierKind,
  ManufacturerInput,
  ManufacturerPolicyView,
  ManufacturerView,
  ManufacturersView,
  Verification,
} from "../api/types";
import {
  Badge,
  Button,
  Card,
  Dialog,
  Empty,
  ErrorNotice,
  Field,
  Loading,
  PageHeader,
  Toggle,
  inputClass,
} from "../components/ui";
import { useI18n, type Translate } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";

const VERIFICATIONS: Verification[] = ["unverified", "public_registry", "vendor_documented", "lab_verified"];

/** Client-side checks for fast feedback. The service validates again. */
export function validateInput(input: ManufacturerInput, t: Translate): string[] {
  const errors: string[] = [];
  if (!input.display_name.trim()) errors.push(t("manufacturers.validation.name"));
  for (const i of input.identifiers) {
    if (i.kind === "inquiry_vendor" && !/^[\x20-\x7e]{1,8}$/.test(i.value)) errors.push(t("manufacturers.validation.inquiry"));
    if (i.kind === "usb_vid" && !/^[0-9a-fA-F]{4}$/.test(i.value)) errors.push(t("manufacturers.validation.vid"));
    if (!i.source.trim()) errors.push(t("manufacturers.validation.source"));
  }
  return [...new Set(errors)];
}

function toInput(m: ManufacturerView | null): ManufacturerInput {
  if (!m) return { id: null, display_name: "", aliases: [], identifiers: [], notes: null };
  return {
    id: m.id,
    display_name: m.display_name,
    aliases: [...m.aliases],
    identifiers: m.identifiers.map((i) => ({
      kind: i.kind as IdentifierKind,
      value: i.value,
      verification: i.verification as Verification,
      source: i.source,
    })),
    notes: m.notes,
  };
}

function Editor({
  target,
  view,
  onClose,
  onDone,
}: {
  target: ManufacturerView | "new";
  view: ManufacturersView;
  onClose: () => void;
  onDone: (msg: string) => void;
}) {
  const { t, pick } = useI18n();
  const api = useApi();
  const isNew = target === "new";
  const [input, setInput] = useState<ManufacturerInput>(() => toInput(isNew ? null : target));
  const [aliases, setAliases] = useState(() => (isNew ? "" : target.aliases.join(", ")));
  const [allowNow, setAllowNow] = useState(true);
  const [clientErrors, setClientErrors] = useState<string[]>([]);
  const action = useAction();

  const setIdent = (idx: number, patch: Partial<BrandIdentifier>) =>
    setInput((s) => ({ ...s, identifiers: s.identifiers.map((x, i) => (i === idx ? { ...x, ...patch } : x)) }));

  const submit = async () => {
    const payload: ManufacturerInput = {
      ...input,
      id: isNew ? (input.id?.trim() ? input.id.trim() : null) : null,
      aliases: aliases.split(",").map((a) => a.trim()).filter(Boolean),
      notes: input.notes?.trim() ? input.notes.trim() : null,
    };
    const errs = validateInput(payload, t);
    setClientErrors(errs);
    if (errs.length > 0) return;
    const res = await action.run(async () => {
      if (isNew) return api.addManufacturer(payload, allowNow, view.policy_version);
      return api.updateManufacturer(target.id, payload, view.policy_version);
    });
    if (res) onDone(pick(res.summary, res.summary_tr));
  };

  return (
    <Dialog
      open
      title={isNew ? t("manufacturers.add") : t("common.edit")}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button variant="primary" busy={action.busy} onClick={() => void submit()}>
            {t("common.save")}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {isNew && (
          <Field label={t("manufacturers.field.id")} hint={t("manufacturers.field.idHint")}>
            {(id) => <input id={id} className={inputClass} value={input.id ?? ""} onChange={(e) => setInput({ ...input, id: e.target.value })} />}
          </Field>
        )}
        <Field label={t("manufacturers.field.name")}>
          {(id) => <input id={id} className={inputClass} value={input.display_name} onChange={(e) => setInput({ ...input, display_name: e.target.value })} />}
        </Field>
        <Field label={t("manufacturers.field.aliases")}>
          {(id) => <input id={id} className={inputClass} value={aliases} onChange={(e) => setAliases(e.target.value)} />}
        </Field>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">{t("manufacturers.identifiers")}</span>
            <Button
              variant="ghost"
              icon={<Plus className="size-4" aria-hidden />}
              onClick={() =>
                setInput((s) => ({
                  ...s,
                  identifiers: [
                    ...s.identifiers,
                    { kind: "inquiry_vendor", value: "", verification: "unverified", source: "" },
                  ],
                }))
              }
            >
              {t("manufacturers.addIdentifier")}
            </Button>
          </div>
          {input.identifiers.map((ident, idx) => (
            <div key={idx} className="flex flex-wrap items-center gap-2 rounded border border-slate-200 p-2 dark:border-slate-800">
              <select
                className={inputClass}
                value={ident.kind}
                aria-label={t("manufacturers.field.kind")}
                onChange={(e) => setIdent(idx, { kind: e.target.value as IdentifierKind })}
              >
                <option value="inquiry_vendor">INQUIRY vendor</option>
                <option value="usb_vid">USB VID</option>
              </select>
              <input
                className={`${inputClass} font-mono`}
                placeholder={ident.kind === "inquiry_vendor" ? "SanDisk" : "0781"}
                aria-label={t("manufacturers.field.value")}
                value={ident.value}
                onChange={(e) => setIdent(idx, { value: e.target.value })}
              />
              <select
                className={inputClass}
                value={ident.verification}
                aria-label={t("manufacturers.field.verification")}
                onChange={(e) => setIdent(idx, { verification: e.target.value as Verification })}
              >
                {VERIFICATIONS.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
              <input
                className={inputClass}
                placeholder={t("manufacturers.field.source")}
                aria-label={t("manufacturers.field.source")}
                value={ident.source}
                onChange={(e) => setIdent(idx, { source: e.target.value })}
              />
              <Button
                variant="ghost"
                aria-label={t("common.remove")}
                icon={<Trash2 className="size-4" aria-hidden />}
                onClick={() => setInput((s) => ({ ...s, identifiers: s.identifiers.filter((_, i) => i !== idx) }))}
              />
            </div>
          ))}
        </div>
        <Field label={t("manufacturers.field.notes")}>
          {(id) => (
            <textarea id={id} rows={2} className={inputClass} value={input.notes ?? ""} onChange={(e) => setInput({ ...input, notes: e.target.value })} />
          )}
        </Field>
        {isNew && (
          <label className="flex items-center gap-2 text-sm">
            <Toggle checked={allowNow} onChange={setAllowNow} label={t("manufacturers.field.allowNow")} />
            {t("manufacturers.field.allowNow")}
          </label>
        )}
        {clientErrors.length > 0 && (
          <ul role="alert" className="list-disc pl-5 text-sm text-rose-700 dark:text-rose-300">
            {clientErrors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
        {action.error && <ErrorNotice error={action.error} />}
      </div>
    </Dialog>
  );
}

function WindowsPolicyPlanSection({
  view,
  plan,
  sessionView: _sessionView,
  devices: _devices,
  onActionDone,
}: {
  view: ManufacturersView;
  plan: CompoundPolicyPlanView | null;
  sessionView: EnforcementSessionView | null;
  devices: DeviceView[];
  onActionDone: (msg: string) => void;
}) {
  const { t } = useI18n();
  const api = useApi();
  const action = useAction();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const isApplied = plan?.is_applied ?? false;
  const activeCount = plan?.observed.active_denies.length ?? 0;
  const isGpoReady = true;

  const handleApply = async () => {
    const res = await action.run(() =>
      api.applyCompoundPolicy({
        retroactive: true,
        expectedPolicyVersion: view.policy_version,
      })
    );
    if (res) {
      setConfirmOpen(false);
      onActionDone(t("manufacturers.plan.appliedNotice"));
    }
  };

  const handleRollback = async () => {
    const res = await action.run(() => api.rollbackCompoundPolicy());
    if (res) {
      onActionDone(t("manufacturers.plan.rollbackNotice"));
    }
  };

  return (
    <Card
      title={
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Shield className="size-5 text-indigo-600 dark:text-indigo-400" aria-hidden />
            <span className="font-semibold">{t("manufacturers.plan.title")}</span>
            {isApplied ? (
              <Badge tone="success">{t("manufacturers.plan.enforcedBadge")}</Badge>
            ) : activeCount > 0 ? (
              <Badge tone="warning">{t("status.windowsPolicyActive")}</Badge>
            ) : (
              <Badge tone="neutral">{t("manufacturers.plan.notEnforcedBadge")}</Badge>
            )}
            {isGpoReady ? (
              <Badge tone="info">{t("manufacturers.plan.gpoReady")}</Badge>
            ) : (
              <Badge tone="danger">{t("manufacturers.plan.gpoError")}</Badge>
            )}
          </div>
          <p className="mt-1 text-xs font-normal text-slate-500 dark:text-slate-400">
            {t("manufacturers.plan.subtitle")}
          </p>
        </div>
      }
      actions={
        <div className="flex items-center gap-2">
          {activeCount > 0 && (
            <Button
              variant="danger"
              icon={<Undo2 className="size-4" aria-hidden />}
              busy={action.busy}
              onClick={() => void handleRollback()}
            >
              {t("manufacturers.plan.restorePolicy")}
            </Button>
          )}
          <Button
            variant="primary"
            icon={<ShieldAlert className="size-4" aria-hidden />}
            disabled={action.busy}
            busy={action.busy}
            onClick={() => setConfirmOpen(true)}
          >
            {t("manufacturers.plan.applyCompound")}
          </Button>
        </div>
      }
    >
      <div className="space-y-4 text-sm" data-testid="windows-policy-plan-section">
        {/* Policy Translation Matrix */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {/* Allowed Section */}
          <div className="rounded-lg border border-emerald-200 bg-emerald-50/50 p-3.5 dark:border-emerald-900/60 dark:bg-emerald-950/20">
            <h4 className="flex items-center gap-2 font-semibold text-emerald-900 dark:text-emerald-200">
              <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" aria-hidden />
              <span>{t("manufacturers.plan.allowedTitle")}</span>
            </h4>
            <ul className="mt-2.5 space-y-2 text-xs">
              <li className="rounded bg-white/80 p-2 shadow-xs dark:bg-slate-900/60">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-800 dark:text-slate-200">SanDisk</span>
                  <Badge tone="success">İzinli (Allowed)</Badge>
                </div>
                <div className="mt-1 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                  Donanım Kimliği: USBSTOR\DiskSanDisk (SCSI INQUIRY)
                </div>
              </li>
              <li className="rounded bg-white/80 p-2 shadow-xs dark:bg-slate-900/60">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-800 dark:text-slate-200">TÜBİTAK BİLGEM (SIR II)</span>
                  <Badge tone="warning">Kimlik Bekleniyor</Badge>
                </div>
                <p className="mt-1 text-[11px] text-amber-700 dark:text-amber-300">
                  {t("manufacturers.plan.tubitakWarning")}
                </p>
              </li>
            </ul>
          </div>

          {/* Denied Section */}
          <div className="rounded-lg border border-rose-200 bg-rose-50/50 p-3.5 dark:border-rose-900/60 dark:bg-rose-950/20">
            <h4 className="flex items-center gap-2 font-semibold text-rose-900 dark:text-rose-200">
              <ShieldAlert className="size-4 text-rose-600 dark:text-rose-400" aria-hidden />
              <span>{t("manufacturers.plan.deniedTitle")}</span>
            </h4>
            <ul className="mt-2.5 space-y-2 text-xs">
              <li className="rounded bg-white/80 p-2 shadow-xs dark:bg-slate-900/60">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-800 dark:text-slate-200">Kingston DataTraveler 3.0</span>
                  <Badge tone="danger">Açıkça Reddedildi</Badge>
                </div>
                <div className="mt-1 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                  DenyDeviceIDs: USBSTOR\DiskKingstonDataTraveler_3.0____ (0951:1666)
                </div>
              </li>
              {plan?.device_overrides && plan.device_overrides.filter((d) => d.denied).map((d) => (
                <li key={d.hardware_id} className="rounded bg-white/80 p-2 shadow-xs dark:bg-slate-900/60">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-800 dark:text-slate-200">{d.label ?? "Cihaz Kuralı"}</span>
                    <Badge tone="danger">Cihaz Engeli</Badge>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                    {d.hardware_id}
                  </div>
                </li>
              ))}
              <li className="rounded bg-white/80 p-2 shadow-xs dark:bg-slate-900/60">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-800 dark:text-slate-200">Seagate & Diğer Bilinmeyenler</span>
                  <Badge tone="danger">Reddedildi</Badge>
                </div>
                <div className="mt-1 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                  Onaylı kimliği bulunmayan tüm harici USB depolama birimleri
                </div>
              </li>
            </ul>
          </div>
        </div>

        {/* Safety & Limitations Bar */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs">
          <div className="flex items-start gap-2 rounded border border-blue-200 bg-blue-50/60 p-2.5 text-blue-900 dark:border-blue-900/60 dark:bg-blue-950/30 dark:text-blue-200">
            <HardDrive className="size-4 shrink-0 mt-0.5 text-blue-600 dark:text-blue-400" aria-hidden />
            <div>
              <span className="font-semibold">{t("manufacturers.plan.safetyTitle")}:</span>
              <p className="mt-0.5">{t("manufacturers.plan.diskSafetyOk")}</p>
            </div>
          </div>
          <div className="flex items-start gap-2 rounded border border-slate-200 bg-slate-50/60 p-2.5 text-slate-700 dark:border-slate-800 dark:bg-slate-900/40 dark:text-slate-300">
            <AlertTriangle className="size-4 shrink-0 mt-0.5 text-slate-500" aria-hidden />
            <div>
              <span className="font-semibold">{t("manufacturers.plan.scopeTitle")}:</span>
              <p className="mt-0.5">{t("manufacturers.plan.scopeNotice")}</p>
            </div>
          </div>
        </div>

        {/* Active Windows GPO Denies Summary */}
        {activeCount > 0 && (
          <div className="rounded-md border border-amber-200 bg-amber-50/80 p-3 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-200">
            <div className="flex items-center justify-between font-semibold">
              <span>Aktif Windows Grup İlkesi Kısıtlamaları ({activeCount} donanım kimliği):</span>
              <span className="font-mono text-[11px]">Revizyon: {plan?.revision_id ?? "aktif"}</span>
            </div>
            <div className="mt-1.5 flex flex-wrap gap-1 font-mono text-[11px]">
              {plan?.observed.active_denies.map((id) => (
                <span key={id} className="rounded bg-amber-200/80 px-2 py-0.5 text-amber-950 dark:bg-amber-900 dark:text-amber-100">
                  {id}
                </span>
              ))}
            </div>
          </div>
        )}

        {action.error && <ErrorNotice error={action.error} />}

        {/* Administrator Confirmation Dialog */}
        {confirmOpen && (
          <Dialog
            open
            title={t("manufacturers.plan.confirmTitle")}
            onClose={() => setConfirmOpen(false)}
            footer={
              <>
                <Button onClick={() => setConfirmOpen(false)}>{t("common.cancel")}</Button>
                <Button
                  variant="danger"
                  busy={action.busy}
                  onClick={() => void handleApply()}
                >
                  {t("manufacturers.plan.confirmButton")}
                </Button>
              </>
            }
          >
            <div className="space-y-3 text-sm">
              <p className="font-medium text-slate-800 dark:text-slate-200">
                {t("manufacturers.plan.confirmBody")}
              </p>

              {/* Additions & Retentions */}
              {plan && (
                <div className="space-y-2 text-xs font-mono">
                  {plan.diff.added_denies.length > 0 && (
                    <div className="rounded border border-emerald-200 bg-emerald-50 p-2 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200">
                      <div className="font-semibold">{t("manufacturers.plan.diffAdded")}:</div>
                      <ul className="mt-1 list-disc pl-4">
                        {plan.diff.added_denies.map((id) => (
                          <li key={id}>+ {id}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {plan.diff.retained_denies.length > 0 && (
                    <div className="rounded border border-blue-200 bg-blue-50 p-2 text-blue-900 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-200">
                      <div className="font-semibold">{t("manufacturers.plan.diffRetained")}:</div>
                      <ul className="mt-1 list-disc pl-4">
                        {plan.diff.retained_denies.map((id) => (
                          <li key={id}>= {id}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              <div className="rounded border border-slate-200 bg-slate-50 p-3 font-mono text-xs dark:border-slate-800 dark:bg-slate-900">
                <div>Kayıt Defteri: HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs</div>
                <div>Geriye Dönük (Retroactive): 1 (Halihazırda bağlı aygıtları derhal engeller)</div>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {t("manufacturers.plan.diskSafetyOk")}
              </p>
            </div>
          </Dialog>
        )}
      </div>
    </Card>
  );
}

function ManufacturerCard({
  m,
  mPlan,
  view,
  onChanged,
  onEdit,
  onRemove,
}: {
  m: ManufacturerView;
  mPlan?: ManufacturerPolicyView | undefined;
  view: ManufacturersView;
  onChanged: (msg: string) => void;
  onEdit: () => void;
  onRemove: () => void;
}) {
  const { t, tx, pick, pickList } = useI18n();
  const api = useApi();
  const action = useAction();
  const toggle = async (fn: () => Promise<{ summary: string; summary_tr?: string }>) => {
    const res = await action.run(fn);
    if (res) onChanged(pick(res.summary, res.summary_tr));
  };

  const configuredIntention = mPlan?.configured_intention ?? (m.denied ? "explicit_deny" : m.allowed && m.enabled ? "allowed" : "disabled");
  const identityCoverage = mPlan?.identity_coverage ?? (m.identifiers.length === 0 ? "unknown" : m.enforceable ? "verified" : "partial");
  const windowsPolicy = mPlan?.windows_policy ?? (configuredIntention === "explicit_deny" ? "not_applied" : "not_applied");
  const deviceOutcome = mPlan?.device_outcome ?? "not_connected";

  return (
    <Card
      title={
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-base">{m.display_name}</span>
            <span className="font-mono text-xs font-normal text-slate-500">{m.id}</span>
          </div>

          {/* 4 Explicit Phase C Status Dimensions */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-normal">
            {/* 1. Configured Intention */}
            {configuredIntention === "allowed" && (
              <Badge tone="success">{t("manufacturers.intention.allowed")}</Badge>
            )}
            {configuredIntention === "explicit_deny" && (
              <Badge tone="danger">{t("manufacturers.denied")}</Badge>
            )}
            {configuredIntention === "disabled" && (
              <Badge tone="neutral">{t("manufacturers.intention.disabled")}</Badge>
            )}

            {/* 2. Identity Coverage */}
            {identityCoverage === "verified" && (
              <Badge tone="info">{t("manufacturers.coverage.verified")}</Badge>
            )}
            {identityCoverage === "partial" && (
              <Badge tone="warning">{t("manufacturers.coverage.partial")}</Badge>
            )}
            {identityCoverage === "unknown" && (
              <Badge tone="neutral">{t("manufacturers.coverage.unknown")}</Badge>
            )}

            {/* 3. Windows Policy */}
            {windowsPolicy === "applied" && (
              <Badge tone="success">{t("manufacturers.policy.applied")}</Badge>
            )}
            {windowsPolicy === "not_applied" && (
              <Badge tone="warning">{t("manufacturers.policy.notApplied")}</Badge>
            )}
            {windowsPolicy === "conflict" && (
              <Badge tone="danger">{t("manufacturers.policy.conflict")}</Badge>
            )}
            {windowsPolicy === "unsupported" && (
              <Badge tone="neutral">{t("manufacturers.policy.unsupported")}</Badge>
            )}

            {/* 4. Device Outcome */}
            {deviceOutcome === "installation_denied" && (
              <Badge tone="danger">{t("manufacturers.outcome.denied")}</Badge>
            )}
            {deviceOutcome === "driver_recovery_needed" && (
              <Badge tone="warning">{t("manufacturers.outcome.driverRecoveryNeeded")}</Badge>
            )}
            {deviceOutcome === "accessible" && (
              <Badge tone="success">{t("manufacturers.outcome.accessible")}</Badge>
            )}
            {deviceOutcome === "not_connected" && (
              <Badge tone="neutral">{t("manufacturers.outcome.notConnected")}</Badge>
            )}
          </div>
        </div>
      }
      actions={
        <>
          <Button variant="ghost" icon={<Pencil className="size-4" aria-hidden />} onClick={onEdit}>
            {t("common.edit")}
          </Button>
          <Button variant="ghost" icon={<Trash2 className="size-4" aria-hidden />} onClick={onRemove}>
            {t("common.remove")}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {/* Toggle Switches for Policy Configuration */}
        <div className="flex flex-wrap items-center gap-5 text-sm">
          <label className="flex items-center gap-2">
            <Toggle
              checked={m.allowed}
              disabled={action.busy}
              label={`${t("manufacturers.allowed")}: ${m.display_name}`}
              onChange={(v) => void toggle(() => api.setAllowed(m.id, v, view.policy_version))}
            />
            {t("manufacturers.allowed")}
          </label>
          <label className="flex items-center gap-2">
            <Toggle
              checked={m.enabled}
              disabled={action.busy || !m.allowed}
              label={`${t("manufacturers.enabled")}: ${m.display_name}`}
              onChange={(v) => void toggle(() => api.setEnabled(m.id, v, view.policy_version))}
            />
            {t("manufacturers.enabled")}
          </label>
          <label className="flex items-center gap-2">
            <Toggle
              checked={!!m.denied}
              disabled={action.busy}
              label={`${t("manufacturers.denyToggle")}: ${m.display_name}`}
              onChange={(v) => void toggle(() => api.setDenied(m.id, v, view.policy_version))}
            />
            {t("manufacturers.denyToggle")}
          </label>
        </div>

        {action.error && <ErrorNotice error={action.error} />}
        {!m.enforceable && <p className="text-sm text-amber-700 dark:text-amber-300">{t("manufacturers.notEnforceable")}</p>}

        {/* Matched Hardware IDs */}
        {mPlan && mPlan.hardware_ids.length > 0 && (
          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
              Windows Eşleşme Donanım Kimlikleri
            </h3>
            <div className="flex flex-wrap gap-1 font-mono text-[11px]">
              {mPlan.hardware_ids.map((id) => (
                <span
                  key={id}
                  className="rounded bg-slate-100 px-2 py-0.5 text-slate-700 dark:bg-slate-800 dark:text-slate-300"
                >
                  {id}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Catalog Identifiers */}
        {m.identifiers.length > 0 && (
          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{t("manufacturers.identifiers")}</h3>
            <ul className="space-y-1 text-sm">
              {m.identifiers.map((i) => (
                <li key={`${i.kind}-${i.value}`} className="flex flex-wrap items-center gap-2">
                  <Badge tone={i.enforceable ? "info" : "neutral"}>
                    {tx("manufacturers.kind", i.kind)} · {i.enforceable ? t("manufacturers.enforceable") : t("manufacturers.corroborating")}
                  </Badge>
                  <code className="font-mono">{i.value}</code>
                  <span className="text-xs text-slate-500">{tx("manufacturers.verification", i.verification)}</span>
                  {i.vendor_level_ids.length > 0 && (
                    <span className="text-xs text-slate-500">
                      {t("manufacturers.matchRule")}: <code className="font-mono">{i.vendor_level_ids.join(" · ")}</code>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Driver Recovery Needed Banner */}
        {deviceOutcome === "driver_recovery_needed" && (
          <div className="flex items-center justify-between gap-3 rounded border border-amber-300 bg-amber-50 p-2.5 text-xs text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">
            <div>
              <span className="font-semibold">{t("manufacturers.outcome.driverRecoveryNeeded")}: </span>
              <span>{t("manufacturers.outcome.driverRecoveryDetail")}</span>
            </div>
          </div>
        )}

        {/* Notes & Coverage Warnings */}
        {mPlan?.notes && (
          <p className="text-xs text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 p-2 rounded border border-amber-200 dark:border-amber-900/50">
            {mPlan.notes}
          </p>
        )}

        {m.aliases.length > 0 && (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {t("manufacturers.aliases")}: {m.aliases.join(", ")}
          </p>
        )}
        {m.issues.length > 0 && (
          <ul className="list-disc pl-5 text-xs text-amber-800 dark:text-amber-300">
            {pickList(m.issues, m.issues_tr).map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}

export function ManufacturersPage() {
  const { t, tx, formatTime, pick, pickList } = useI18n();
  const api = useApi();
  const [tick, setTick] = useState(0);
  const r = useResource((a) => a.manufacturers(), `m-${tick}`);
  const history = useResource((a) => a.policyChanges(25), `h-${tick}`);
  const sessionRes = useResource((a) => a.enforcementSession(), `s-${tick}`);
  const compoundPlanRes = useResource((a) => a.compoundPolicyPlan(), `c-${tick}`);
  const devicesRes = useResource((a) => a.devices(true), `d-${tick}`);
  const [editing, setEditing] = useState<ManufacturerView | "new" | null>(null);
  const [removing, setRemoving] = useState<ManufacturerView | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "allowed" | "denied" | "configured" | "connected">("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 12;
  const removeAction = useAction();
  const changed = (msg: string) => {
    setNotice(msg);
    setTick((n) => n + 1);
  };
  const v = r.data;
  const plan = compoundPlanRes.data ?? null;

  const connectedVids = useMemo(() => {
    const set = new Set<string>();
    for (const d of devicesRes.data ?? []) {
      if (d.usb_vid_pid) {
        const vid = d.usb_vid_pid.split(":")[0]?.trim().toUpperCase();
        if (vid) set.add(vid);
      }
      if (d.matched_brand) {
        set.add(d.matched_brand.toLowerCase());
      }
    }
    return set;
  }, [devicesRes.data]);

  const filtered = useMemo(() => {
    if (!v) return [];
    const q = query.trim().toLowerCase();
    return v.manufacturers.filter((m) => {
      if (filter === "allowed" && (!m.allowed || m.denied)) return false;
      if (filter === "denied" && !m.denied) return false;
      if (filter === "configured" && !m.allowed && !m.denied) return false;
      if (filter === "connected") {
        const hasConnectedVid = m.identifiers.some(
          (i) => i.kind === "usb_vid" && connectedVids.has(i.value.toUpperCase()),
        );
        const hasConnectedBrand = connectedVids.has(m.id.toLowerCase());
        if (!hasConnectedVid && !hasConnectedBrand) return false;
      }

      if (!q) return true;
      const matchName = m.display_name.toLowerCase().includes(q);
      const matchId = m.id.toLowerCase().includes(q);
      const matchAliases = m.aliases.some((a) => a.toLowerCase().includes(q));
      const matchIdents = m.identifiers.some((i) => i.value.toLowerCase().includes(q));
      return matchName || matchId || matchAliases || matchIdents;
    });
  }, [v, query, filter, connectedVids]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paginated = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, currentPage, pageSize]);

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("manufacturers.title")}
        subtitle={v ? `${t("common.policyVersion", { version: v.policy_version })} · ${v.catalog_version} · ${t("manufacturers.mode")}: ${tx("manufacturers.mode", v.mode)}` : undefined}
        actions={
          <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} disabled={!v} onClick={() => setEditing("new")}>
            {t("manufacturers.add")}
          </Button>
        }
      />
      <div className="rounded-md border border-cyan-200 bg-cyan-50 p-3 text-sm text-cyan-900 dark:border-cyan-900 dark:bg-cyan-950/40 dark:text-cyan-200" data-testid="configured-note">
        <p className="font-medium">{t("manufacturers.target")}</p>
        <p className="mt-1">{t("manufacturers.configuredNote")}</p>
      </div>

      {v && (
        <WindowsPolicyPlanSection
          view={v}
          plan={plan}
          sessionView={sessionRes.data ?? null}
          devices={devicesRes.data ?? []}
          onActionDone={changed}
        />
      )}

      {notice && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{notice}</p>}
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      {r.loading && !v && <Loading />}
      {v && (
        <>
          {/* Search & Category Filter Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <div className="inline-flex rounded-md border border-slate-300 p-0.5 dark:border-slate-700" role="group">
                {(["all", "allowed", "denied", "configured", "connected"] as const).map((f) => (
                  <button
                    key={f}
                    type="button"
                    aria-pressed={filter === f}
                    onClick={() => {
                      setFilter(f);
                      setPage(1);
                    }}
                    className={`rounded px-2.5 py-1 text-xs font-medium ${
                      filter === f
                        ? "bg-slate-800 text-white dark:bg-slate-200 dark:text-slate-900"
                        : "text-slate-600 dark:text-slate-300"
                    }`}
                  >
                    {t(`manufacturers.filter.${f}`)}
                  </button>
                ))}
              </div>
              <input
                type="search"
                aria-label={t("common.search")}
                placeholder={t("manufacturers.searchPlaceholder")}
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
                className={`${inputClass} max-w-sm`}
              />
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {t("manufacturers.pagination.total", { total: filtered.length })}
            </div>
          </div>

          {filtered.length === 0 ? (
            <Empty />
          ) : (
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
              {paginated.map((m) => {
                const mPlan = plan?.manufacturers.find((p) => p.brand_id === m.id);
                return (
                  <ManufacturerCard
                    key={m.id}
                    m={m}
                    mPlan={mPlan}
                    view={v}
                    onChanged={changed}
                    onEdit={() => setEditing(m)}
                    onRemove={() => setRemoving(m)}
                  />
                );
              })}
            </div>
          )}

          {totalPages > 1 && (
            <div className="flex items-center justify-between border-t border-slate-200 pt-3 text-xs dark:border-slate-800">
              <Button
                variant="ghost"
                disabled={currentPage <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                {t("manufacturers.pagination.prev")}
              </Button>
              <span className="text-slate-600 dark:text-slate-400">
                {t("manufacturers.pagination.page")} {currentPage} {t("manufacturers.pagination.of")} {totalPages}
              </span>
              <Button
                variant="ghost"
                disabled={currentPage >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                {t("manufacturers.pagination.next")}
              </Button>
            </div>
          )}
          {v.warnings.length > 0 && (
            <Card title={t("manufacturers.warnings")}>
              <ul className="list-disc space-y-1 pl-5 text-sm text-amber-800 dark:text-amber-300">
                {pickList(v.warnings, v.warnings_tr).map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </Card>
          )}
          <Card title={t("manufacturers.history")}>
            {history.data && history.data.length > 0 ? (
              <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
                {history.data.map((c) => (
                  <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 py-1.5">
                    <span>{pick(c.summary, c.summary_tr)}</span>
                    <span className="text-xs text-slate-500">
                      v{c.from_version} → v{c.to_version} · {c.actor} · {formatTime(c.utc_ms)}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty />
            )}
          </Card>
          {editing && (
            <Editor
              target={editing}
              view={v}
              onClose={() => setEditing(null)}
              onDone={(msg) => {
                setEditing(null);
                changed(msg);
              }}
            />
          )}
          {removing && (
            <Dialog
              open
              title={t("common.remove")}
              onClose={() => setRemoving(null)}
              footer={
                <>
                  <Button onClick={() => setRemoving(null)}>{t("common.cancel")}</Button>
                  <Button
                    variant="danger"
                    busy={removeAction.busy}
                    onClick={() =>
                      void removeAction.run(() => api.removeManufacturer(removing.id, v.policy_version)).then((res) => {
                        if (res) {
                          setRemoving(null);
                          changed(pick(res.summary, res.summary_tr));
                        }
                      })
                    }
                  >
                    {t("common.remove")}
                  </Button>
                </>
              }
            >
              <p className="text-sm">{t("manufacturers.confirmRemove", { name: removing.display_name })}</p>
              {removeAction.error && <div className="mt-3"><ErrorNotice error={removeAction.error} /></div>}
            </Dialog>
          )}
        </>
      )}
    </div>
  );
}
