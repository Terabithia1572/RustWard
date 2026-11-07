import { useState } from "react";
import { AlertTriangle, Pencil, Plus, Trash2 } from "lucide-react";
import type { BrandIdentifier, IdentifierKind, ManufacturerInput, ManufacturerView, ManufacturersView, Verification } from "../api/types";
import { Badge, Button, Card, Dialog, Empty, ErrorNotice, Field, Loading, PageHeader, Toggle, inputClass } from "../components/ui";
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
    const res = await action.run(() =>
      isNew
        ? api.addManufacturer(payload, allowNow, view.policy_version)
        : api.updateManufacturer(target.id, payload, view.policy_version),
    );
    if (res) onDone(pick(res.summary, res.summary_tr));
  };

  return (
    <Dialog
      open
      wide
      title={isNew ? t("manufacturers.addTitle") : t("manufacturers.editTitle")}
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
      <div className="space-y-4">
        <p className="text-xs text-slate-500 dark:text-slate-400">{t("manufacturers.nameHint")}</p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label={t("manufacturers.field.name")}>
            {(id) => (
              <input id={id} className={inputClass} value={input.display_name} onChange={(e) => setInput({ ...input, display_name: e.target.value })} />
            )}
          </Field>
          <Field label={t("manufacturers.field.id")} hint={t("manufacturers.field.idHint")}>
            {(id) => (
              <input
                id={id}
                className={inputClass}
                value={isNew ? input.id ?? "" : target.id}
                disabled={!isNew}
                onChange={(e) => setInput({ ...input, id: e.target.value })}
              />
            )}
          </Field>
        </div>
        <Field label={t("manufacturers.field.aliases")}>
          {(id) => <input id={id} className={inputClass} value={aliases} onChange={(e) => setAliases(e.target.value)} />}
        </Field>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{t("manufacturers.identifiers")}</h3>
            <Button
              variant="ghost"
              icon={<Plus className="size-4" aria-hidden />}
              onClick={() =>
                setInput((s) => ({
                  ...s,
                  identifiers: [...s.identifiers, { kind: "inquiry_vendor", value: "", verification: "unverified", source: "" }],
                }))
              }
            >
              {t("manufacturers.addIdentifier")}
            </Button>
          </div>
          {input.identifiers.length === 0 && <p className="text-xs text-amber-700 dark:text-amber-300">{t("manufacturers.notEnforceable")}</p>}
          {input.identifiers.map((ident, idx) => (
            <div key={idx} className="grid grid-cols-1 gap-2 rounded-md border border-slate-200 p-2 sm:grid-cols-[150px_110px_150px_1fr_auto] dark:border-slate-800">
              <select
                aria-label={t("manufacturers.field.kind")}
                className={inputClass}
                value={ident.kind}
                onChange={(e) => setIdent(idx, { kind: e.target.value as IdentifierKind })}
              >
                <option value="inquiry_vendor">{t("manufacturers.kind.inquiry_vendor")}</option>
                <option value="usb_vid">{t("manufacturers.kind.usb_vid")}</option>
              </select>
              <input
                aria-label={t("manufacturers.field.value")}
                className={`${inputClass} font-mono`}
                value={ident.value}
                maxLength={8}
                onChange={(e) => setIdent(idx, { value: e.target.value })}
              />
              <select
                aria-label={t("manufacturers.field.verification")}
                className={inputClass}
                value={ident.verification}
                onChange={(e) => setIdent(idx, { verification: e.target.value as Verification })}
              >
                {VERIFICATIONS.map((v) => (
                  <option key={v} value={v}>
                    {t(`manufacturers.verification.${v}`)}
                  </option>
                ))}
              </select>
              <input
                aria-label={t("manufacturers.field.source")}
                placeholder={t("manufacturers.field.source")}
                className={inputClass}
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

function ManufacturerCard({
  m,
  view,
  onChanged,
  onEdit,
  onRemove,
}: {
  m: ManufacturerView;
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
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          {m.display_name}
          <span className="font-mono text-xs font-normal text-slate-500">{m.id}</span>
          {m.allowed && m.enabled && <Badge tone="success">{t("manufacturers.allowed")}</Badge>}
          {!m.enforceable && (
            <Badge tone="warning" title={t("manufacturers.notEnforceable")}>
              <AlertTriangle className="size-3" aria-hidden />
              {t("manufacturers.issues")}
            </Badge>
          )}
        </span>
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
        </div>
        {action.error && <ErrorNotice error={action.error} />}
        {!m.enforceable && <p className="text-sm text-amber-700 dark:text-amber-300">{t("manufacturers.notEnforceable")}</p>}
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
  const [editing, setEditing] = useState<ManufacturerView | "new" | null>(null);
  const [removing, setRemoving] = useState<ManufacturerView | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const removeAction = useAction();
  const changed = (msg: string) => {
    setNotice(msg);
    setTick((n) => n + 1);
  };
  const v = r.data;

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
      {notice && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{notice}</p>}
      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      {r.loading && !v && <Loading />}
      {v && (
        <>
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
            {v.manufacturers.map((m) => (
              <ManufacturerCard key={m.id} m={m} view={v} onChanged={changed} onEdit={() => setEditing(m)} onRemove={() => setRemoving(m)} />
            ))}
          </div>
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
