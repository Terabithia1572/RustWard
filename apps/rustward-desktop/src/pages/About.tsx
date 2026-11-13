import { Cpu, GitBranch, Info, Scale, ShieldCheck, User } from "lucide-react";
import { Badge, Card, ErrorNotice, Loading, PageHeader } from "../components/ui";
import { useI18n } from "../i18n";
import { useResource } from "../lib/hooks";

export function AboutPage() {
  const { t, pick } = useI18n();
  const r = useResource((api) => api.aboutInfo(), "about-info");
  const info = r.data;

  return (
    <div className="space-y-4" data-testid="about-page">
      <PageHeader
        title={t("about.title")}
        subtitle={info ? pick(info.tagline_en, info.tagline_tr) : undefined}
        actions={info ? <Badge tone="info">v{info.version}</Badge> : undefined}
      />

      {r.error && <ErrorNotice error={r.error} onRetry={r.reload} />}
      {r.loading && !info && <Loading />}

      {info && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card
            title={
              <div className="flex items-center gap-2">
                <User className="size-4 text-cyan-600" aria-hidden />
                <span>{info.app_name}</span>
              </div>
            }
          >
            <dl className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
              <div className="flex justify-between gap-3 py-2">
                <dt className="text-slate-500 dark:text-slate-400">{t("about.developer")}</dt>
                <dd className="font-semibold text-slate-900 dark:text-slate-100">{info.author}</dd>
              </div>
              <div className="flex justify-between gap-3 py-2">
                <dt className="text-slate-500 dark:text-slate-400">{t("about.version")}</dt>
                <dd className="font-mono">{info.version}</dd>
              </div>
              <div className="flex justify-between gap-3 py-2">
                <dt className="text-slate-500 dark:text-slate-400">{t("about.commitSha")}</dt>
                <dd className="flex items-center gap-1.5 font-mono text-xs">
                  <GitBranch className="size-3.5 text-slate-400" aria-hidden />
                  {info.commit_sha}
                </dd>
              </div>
              <div className="flex justify-between gap-3 py-2">
                <dt className="text-slate-500 dark:text-slate-400">{t("about.buildTime")}</dt>
                <dd className="font-mono text-xs">{info.build_timestamp}</dd>
              </div>
              <div className="flex justify-between gap-3 py-2">
                <dt className="text-slate-500 dark:text-slate-400">{t("about.license")}</dt>
                <dd className="text-right text-xs">{info.license}</dd>
              </div>
              <div className="flex justify-between gap-3 py-2">
                <dt className="text-slate-500 dark:text-slate-400">{t("about.repository")}</dt>
                <dd className="break-all text-right font-mono text-xs">{info.repository_url}</dd>
              </div>
            </dl>
            <p className="mt-3 border-t border-slate-100 pt-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
              {pick(info.copyright_en, info.copyright_tr)}
            </p>
          </Card>

          <Card
            title={
              <div className="flex items-center gap-2">
                <Cpu className="size-4 text-indigo-600" aria-hidden />
                <span>{t("about.architecture")}</span>
              </div>
            }
          >
            <div className="space-y-3 text-sm">
              <p className="leading-relaxed text-slate-700 dark:text-slate-300">
                {pick(info.architecture_summary_en, info.architecture_summary_tr)}
              </p>
              <div>
                <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  {t("about.techStack")}
                </h3>
                <ul className="list-disc space-y-1 pl-5 text-xs text-slate-700 dark:text-slate-300">
                  {info.tech_stack.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  {t("about.verifiedEnvs")}
                </h3>
                <ul className="list-disc space-y-1 pl-5 text-xs text-emerald-800 dark:text-emerald-300">
                  {info.verified_environments.map((env) => (
                    <li key={env}>{env}</li>
                  ))}
                </ul>
              </div>
            </div>
          </Card>

          <Card
            title={
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-4 text-amber-600" aria-hidden />
                <span>{t("about.securityLimits")}</span>
              </div>
            }
          >
            <ul className="list-disc space-y-1.5 pl-5 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
              {(pick("en", "tr") === "tr" ? info.security_limits_tr : info.security_limits_en).map((lim) => (
                <li key={lim}>{lim}</li>
              ))}
            </ul>
          </Card>

          <Card
            title={
              <div className="flex items-center gap-2">
                <Scale className="size-4 text-slate-600" aria-hidden />
                <span>{t("about.acknowledgments")}</span>
              </div>
            }
          >
            <div className="space-y-3 text-xs">
              <ul className="space-y-1 text-slate-700 dark:text-slate-300">
                {info.acknowledgments_tr.map((a) => (
                  <li key={a} className="flex items-center gap-1.5">
                    <Info className="size-3.5 shrink-0 text-cyan-600" aria-hidden />
                    <span>{a}</span>
                  </li>
                ))}
              </ul>
              <div className="border-t border-slate-100 pt-2 dark:border-slate-800">
                <ul className="list-disc space-y-1 pl-5 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                  {info.third_party_notices.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
