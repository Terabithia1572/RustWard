import { useEffect, useState } from "react";
import { Archive, Eraser, ShieldCheck } from "lucide-react";
import type { SettingsView } from "../api/types";
import { Button, Card, ErrorNotice, Field, Loading, PageHeader, Toggle, inputClass } from "../components/ui";
import { useI18n } from "../i18n";
import { useAction, useApi, useResource } from "../lib/hooks";

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

  const maintenance = async (type: "apply_retention" | "create_backup") => {
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
          </div>
        </Card>
        <Card title={t("settings.database")}>
          <div className="space-y-3">
            <Button icon={<Archive className="size-4" aria-hidden />} busy={maint.busy} onClick={() => void maintenance("create_backup")}>
              {t("settings.backup")}
            </Button>
            {maint.error && <ErrorNotice error={maint.error} />}
          </div>
        </Card>
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
