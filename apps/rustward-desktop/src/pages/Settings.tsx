import { useEffect, useState } from "react";
import { Archive, Eraser, History, Monitor, ShieldCheck } from "lucide-react";
import type { BackupView, RestorePreviewView, SettingsView } from "../api/types";
import { Badge, Button, Card, Dialog, Empty, ErrorNotice, Field, Loading, PageHeader, Toggle, inputClass } from "../components/ui";
import { useI18n } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";

/** Same rule as the service (`[A-Za-z0-9_-]{1,64}`); the service re-validates. */
export const WORKSTATION_ID = /^[A-Za-z0-9_-]{1,64}$/;

function WorkstationCard() {
  const { t } = useI18n();
  const api = useApi();
  const [tick, setTick] = useState(0);
  const r = useResource((a) => a.manufacturers(), `ws-${tick}`);
  const [draft, setDraft] = useState<string | null>(null);
  const save = useAction();
  const [notice, setNotice] = useState<string | null>(null);
  const current = r.data?.workstation_id ?? "";
  const value = draft ?? current;
  const valid = WORKSTATION_ID.test(value);
  const dirty = value !== current;

  const submit = async () => {
    if (!r.data || !valid || !dirty) return;
    const res = await save.run(() => api.setWorkstationId(value, r.data!.policy_version));
    if (res) {
      setNotice(t("settings.workstationSaved", { version: res.policy_version }));
      setDraft(null);
      setTick((n) => n + 1);
    }
  };

  return (
    <Card title={t("settings.workstation")}>
      {r.error ? (
        <ErrorNotice error={r.error} onRetry={r.reload} />
      ) : !r.data ? (
        <Loading />
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-slate-500 dark:text-slate-400">{t("settings.workstationHint")}</p>
          <Field label={t("settings.workstation")} error={valid ? null : t("settings.workstationInvalid")}>
            {(id) => (
              <input
                id={id}
                className={`${inputClass} font-mono`}
                value={value}
                maxLength={64}
                spellCheck={false}
                autoComplete="off"
                onChange={(e) => setDraft(e.target.value)}
              />
            )}
          </Field>
          <Button
            icon={<Monitor className="size-4" aria-hidden />}
            disabled={!dirty || !valid}
            busy={save.busy}
            onClick={() => void submit()}
          >
            {t("settings.workstationSave")}
          </Button>
          {notice && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{notice}</p>}
          {save.error && <ErrorNotice error={save.error} />}
        </div>
      )}
    </Card>
  );
}

function BackupsCard() {
  const { t, formatTime } = useI18n();
  const api = useApi();
  const [tick, setTick] = useState(0);
  const list = useResource((a) => a.backups(), `backups-${tick}`);
  const create = useAction();
  const restore = useAction();
  const [preview, setPreview] = useState<RestorePreviewView | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const doCreate = async () => {
    const msg = await create.run(() => api.action("create_backup"));
    if (msg !== undefined) {
      setNotice(msg);
      setTick((n) => n + 1);
    }
  };
  // Step 1: the service verifies the backup and returns a preview; nothing changes.
  const doPrepare = async (b: BackupView) => {
    setNotice(null);
    const p = await restore.run(() => api.prepareRestore(b.file_name));
    if (p) setPreview(p);
  };
  // Step 2: apply the previewed backup as a new policy version.
  const doApply = async (p: RestorePreviewView) => {
    const res = await restore.run(() => api.applyRestore(p.restore_id, p.current_policy_version));
    setPreview(null);
    if (res) {
      setNotice(`${t("settings.restoreDone")} ${res.summary}`);
      setTick((n) => n + 1);
    }
  };

  return (
    <Card title={t("settings.database")}>
      <div className="space-y-3">
        <Button icon={<Archive className="size-4" aria-hidden />} busy={create.busy} onClick={() => void doCreate()}>
          {t("settings.backup")}
        </Button>
        {notice && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{notice}</p>}
        {(create.error ?? restore.error) && <ErrorNotice error={create.error ?? restore.error} />}
        <h3 className="pt-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{t("settings.backups")}</h3>
        {list.error ? (
          <ErrorNotice error={list.error} onRetry={list.reload} />
        ) : !list.data ? (
          <Loading />
        ) : list.data.length === 0 ? (
          <Empty>{t("settings.backupsEmpty")}</Empty>
        ) : (
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800" aria-label={t("settings.backups")}>
            {list.data.map((b) => (
              <li key={b.file_name} className="flex items-center justify-between gap-2 py-1.5">
                <div className="min-w-0 flex-1" title={b.file_name}>
                  <div className="truncate font-mono text-xs">{b.file_name}</div>
                  <div className="text-xs text-slate-500">
                    {formatTime(b.created_ms)} · {t("settings.backupPolicy", { version: b.policy_version })} ·{" "}
                    {t("settings.size", { kb: Math.max(1, Math.round(b.bytes / 1024)) })}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Badge tone={b.kind === "pre_restore" ? "warning" : "neutral"}>
                    {b.kind === "pre_restore" ? t("settings.backupKind.pre_restore") : t("settings.backupKind.manual")}
                  </Badge>
                  {b.file_present ? (
                    <Button
                      variant="ghost"
                      icon={<History className="size-4" aria-hidden />}
                      busy={restore.busy}
                      onClick={() => void doPrepare(b)}
                    >
                      {t("settings.restore")}
                    </Button>
                  ) : (
                    <Badge tone="danger">{t("settings.backupMissing")}</Badge>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
      {preview && (
        <Dialog
          open
          title={t("settings.restoreTitle")}
          onClose={() => setPreview(null)}
          footer={
            <>
              <Button onClick={() => setPreview(null)}>{t("common.cancel")}</Button>
              <Button variant="danger" busy={restore.busy} onClick={() => void doApply(preview)}>
                {t("settings.restoreApply")}
              </Button>
            </>
          }
        >
          <div className="space-y-3 text-sm">
            <p>
              {t("settings.restoreConfirm", {
                to: preview.resulting_policy_version,
                from: preview.current_policy_version,
                backup: preview.backup_policy_version,
              })}
            </p>
            <div>
              <div className="font-mono text-xs">{preview.file_name}</div>
              <div className="break-all font-mono text-[11px] text-slate-500">
                {t("settings.restoreHash")}: {preview.sha256}
              </div>
            </div>
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{t("settings.restoreChanges")}</h3>
              {preview.changes.length === 0 ? (
                <p className="text-slate-500">{t("settings.restoreNoChanges")}</p>
              ) : (
                <ul className="list-disc space-y-0.5 pl-5" aria-label={t("settings.restoreChanges")}>
                  {preview.changes.map((c) => (
                    <li key={c} className="font-mono text-xs">{c}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </Dialog>
      )}
    </Card>
  );
}

export const RETENTION_RANGE = [30, 3650] as const;
export const REFRESH_RANGE = [5, 3600] as const;

function inRange(n: number, [lo, hi]: readonly [number, number]): boolean {
  return Number.isInteger(n) && n >= lo && n <= hi;
}

export function SettingsPage({ settings, onSaved }: { settings: SettingsView | null; onSaved: (s: SettingsView) => void }) {
  const { t } = useI18n();
  const api = useApi();
  const fallback = useResource((a) => (settings ? Promise.resolve(settings) : a.settings()), `settings-${settings ? "given" : "load"}`);
  const current = settings ?? fallback.data;
  const [draft, setDraft] = useState<SettingsView | null>(current ?? null);
  const save = useAction();
  const maint = useAction();
  const diag = useResource((a) => a.diagnostics(), "settings-diag");
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (current) setDraft(current);
  }, [current]);

  if (!draft) {
    return (
      <div className="space-y-4">
        <PageHeader title={t("settings.title")} />
        {fallback.error ? <ErrorNotice error={fallback.error} onRetry={fallback.reload} /> : <Loading />}
      </div>
    );
  }

  const retentionOk = inRange(draft.audit_retention_days, RETENTION_RANGE);
  const refreshOk = inRange(draft.inventory_refresh_seconds, REFRESH_RANGE);
  const dirty = JSON.stringify(draft) !== JSON.stringify(current);

  const submit = async () => {
    if (!retentionOk || !refreshOk) return;
    const res = await save.run(() => api.saveSettings(draft));
    if (res) {
      onSaved(res);
      setNotice(t("settings.saved"));
    }
  };

  const maintenance = async (type: "apply_retention") => {
    const msg = await maint.run(() => api.action(type));
    if (msg !== undefined) setNotice(msg);
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("settings.title")}
        actions={
          <Button variant="primary" disabled={!dirty || !retentionOk || !refreshOk} busy={save.busy} onClick={() => void submit()}>
            {t("common.save")}
          </Button>
        }
      />
      {notice && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{notice}</p>}
      {save.error && <ErrorNotice error={save.error} />}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title={t("settings.appearance")}>
          <div className="space-y-3">
            <Field label={t("settings.theme")}>
              {(id) => (
                <select
                  id={id}
                  className={inputClass}
                  value={draft.theme}
                  onChange={(e) => setDraft({ ...draft, theme: e.target.value as SettingsView["theme"] })}
                >
                  <option value="system">{t("settings.theme.system")}</option>
                  <option value="light">{t("settings.theme.light")}</option>
                  <option value="dark">{t("settings.theme.dark")}</option>
                </select>
              )}
            </Field>
            <Field label={t("settings.language")}>
              {(id) => (
                <select
                  id={id}
                  className={inputClass}
                  value={draft.language}
                  onChange={(e) => setDraft({ ...draft, language: e.target.value as SettingsView["language"] })}
                >
                  <option value="tr">Türkçe</option>
                  <option value="en">English</option>
                </select>
              )}
            </Field>
            <div className="flex items-start gap-3">
              <Toggle
                checked={draft.notifications_enabled}
                onChange={(v) => setDraft({ ...draft, notifications_enabled: v })}
                label={t("settings.notifications")}
              />
              <div>
                <div className="text-sm font-medium">{t("settings.notifications")}</div>
                <p className="text-xs text-slate-500 dark:text-slate-400">{t("settings.notificationsHint")}</p>
              </div>
            </div>
          </div>
        </Card>
        <Card title={t("settings.audit")}>
          <div className="space-y-3">
            <Field
              label={t("settings.retentionDays")}
              hint={`${RETENTION_RANGE[0]}–${RETENTION_RANGE[1]}`}
              error={retentionOk ? null : `${RETENTION_RANGE[0]}–${RETENTION_RANGE[1]}`}
            >
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={RETENTION_RANGE[0]}
                  max={RETENTION_RANGE[1]}
                  className={inputClass}
                  value={draft.audit_retention_days}
                  onChange={(e) => setDraft({ ...draft, audit_retention_days: Number(e.target.value) })}
                />
              )}
            </Field>
            <Field
              label={t("settings.refreshSeconds")}
              hint={`${REFRESH_RANGE[0]}–${REFRESH_RANGE[1]}`}
              error={refreshOk ? null : `${REFRESH_RANGE[0]}–${REFRESH_RANGE[1]}`}
            >
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={REFRESH_RANGE[0]}
                  max={REFRESH_RANGE[1]}
                  className={inputClass}
                  value={draft.inventory_refresh_seconds}
                  onChange={(e) => setDraft({ ...draft, inventory_refresh_seconds: Number(e.target.value) })}
                />
              )}
            </Field>
            <Button icon={<Eraser className="size-4" aria-hidden />} busy={maint.busy} onClick={() => void maintenance("apply_retention")}>
              {t("settings.applyRetention")}
            </Button>
            {maint.error && <ErrorNotice error={maint.error} />}
          </div>
        </Card>
        <WorkstationCard />
        <BackupsCard />
        <Card title={t("settings.admin")}>
          <div className="flex gap-3 text-sm">
            <ShieldCheck className="mt-0.5 size-5 shrink-0 text-cyan-600" aria-hidden />
            <p>{t("settings.adminHint")}</p>
          </div>
        </Card>
        <Card title={t("settings.about")}>
          {diag.data ? (
            <dl className="space-y-1 text-sm">
              <div className="flex justify-between gap-2">
                <dt className="text-slate-500">{t("common.version")}</dt>
                <dd className="font-mono">{diag.data.app_version}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-slate-500">{t("settings.backend")}</dt>
                <dd className="font-mono">{diag.data.service.backend}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-slate-500">{t("diag.platform")}</dt>
                <dd className="font-mono">{diag.data.windows_adapter.platform}</dd>
              </div>
            </dl>
          ) : diag.error ? (
            <ErrorNotice error={diag.error} />
          ) : (
            <Loading />
          )}
        </Card>
      </div>
    </div>
  );
}
