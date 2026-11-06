import { serviceReason } from "../lib/serviceReason";
import { useEffect, useId, useRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { AlertTriangle, Loader2, ShieldAlert, X } from "lucide-react";
import { ApiError } from "../api/client";
import { translate, useI18n } from "../i18n";
import type { TKey } from "../i18n/tr";

type Variant = "primary" | "secondary" | "danger" | "ghost";

const variants: Record<Variant, string> = {
  primary:
    "bg-cyan-700 text-white hover:bg-cyan-600 disabled:bg-cyan-700/50 dark:bg-cyan-600 dark:hover:bg-cyan-500",
  secondary:
    "border border-slate-300 bg-white text-slate-800 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800",
  danger: "bg-rose-700 text-white hover:bg-rose-600 disabled:bg-rose-700/50",
  ghost: "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800",
};

export function Button({
  variant = "secondary",
  icon,
  busy = false,
  className = "",
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; icon?: ReactNode; busy?: boolean }) {
  return (
    <button
      type="button"
      {...rest}
      disabled={disabled === true || busy}
      className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 disabled:cursor-not-allowed disabled:opacity-60 ${variants[variant]} ${className}`}
    >
      {busy ? <Loader2 className="size-4 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  );
}

export type Tone = "neutral" | "info" | "success" | "warning" | "danger" | "synthetic";

const tones: Record<Tone, string> = {
  neutral: "bg-slate-100 text-slate-700 ring-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-700",
  info: "bg-sky-50 text-sky-800 ring-sky-200 dark:bg-sky-950 dark:text-sky-300 dark:ring-sky-900",
  success: "bg-emerald-50 text-emerald-800 ring-emerald-200 dark:bg-emerald-950 dark:text-emerald-300 dark:ring-emerald-900",
  warning: "bg-amber-50 text-amber-900 ring-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:ring-amber-900",
  danger: "bg-rose-50 text-rose-800 ring-rose-200 dark:bg-rose-950 dark:text-rose-300 dark:ring-rose-900",
  synthetic: "bg-violet-50 text-violet-800 ring-violet-200 dark:bg-violet-950 dark:text-violet-300 dark:ring-violet-900",
};

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function Card({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`min-w-0 rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900 ${className}`}
    >
      {(title !== undefined || actions !== undefined) && (
        <header className="flex items-center justify-between gap-3 border-b border-slate-200 px-4 py-2.5 dark:border-slate-800">
          <h2 className="min-w-0 text-sm font-semibold text-slate-800 dark:text-slate-100">{title}</h2>
          <div className="flex shrink-0 items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint, icon }: { label: string; value: ReactNode; hint?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {icon}
        {label}
      </div>
      <div className="mt-2 text-lg font-semibold leading-snug text-slate-900 [overflow-wrap:anywhere] dark:text-slate-50">{value}</div>
      {hint !== undefined && <div className="mt-1 text-xs text-slate-500 [overflow-wrap:anywhere] dark:text-slate-400">{hint}</div>}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string | undefined; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-50">{title}</h1>
        {subtitle !== undefined && <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">{actions}</div>
    </div>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 disabled:cursor-not-allowed disabled:opacity-50 ${
        checked ? "bg-cyan-600" : "bg-slate-300 dark:bg-slate-700"
      }`}
    >
      <span
        className={`inline-block size-4 rounded-full bg-white shadow transition-transform ${checked ? "translate-x-4" : "translate-x-0.5"}`}
      />
    </button>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string | null;
  children: (id: string) => ReactNode;
}) {
  const id = useId();
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-xs font-medium text-slate-700 dark:text-slate-300">
        {label}
      </label>
      {children(id)}
      {hint !== undefined && <p className="text-xs text-slate-500 dark:text-slate-400">{hint}</p>}
      {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
    </div>
  );
}

export const inputClass =
  "w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100";

export function Dialog({
  open,
  title,
  onClose,
  children,
  footer,
  wide = false,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const { t } = useI18n();
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    const first = ref.current?.querySelector<HTMLElement>("input, select, textarea, button");
    first?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-950/60 p-4">
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`flex max-h-[90vh] w-full flex-col rounded-lg border border-slate-200 bg-white shadow-xl dark:border-slate-700 dark:bg-slate-900 ${
          wide ? "max-w-3xl" : "max-w-lg"
        }`}
      >
        <header className="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">{title}</h2>
          <Button variant="ghost" aria-label={t("common.close")} onClick={onClose} icon={<X className="size-4" />} />
        </header>
        <div className="overflow-y-auto px-4 py-4">{children}</div>
        {footer !== undefined && (
          <footer className="flex justify-end gap-2 border-t border-slate-200 px-4 py-3 dark:border-slate-800">{footer}</footer>
        )}
      </div>
    </div>
  );
}

const errorKeys: Record<string, TKey> = {
  unauthorized: "error.unauthorized",
  unavailable: "error.unavailable",
  conflict: "error.conflict",
  validation_failed: "error.validation_failed",
  invalid_request: "error.invalid_request",
  not_found: "error.not_found",
  version_mismatch: "error.version_mismatch",
  not_supported: "error.not_supported",
  timeout: "error.timeout",
};

export function ErrorNotice({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useI18n();
  const e = error instanceof ApiError ? error : new ApiError("client", String(error));
  const key = errorKeys[e.code];
  const reason = e.code === "unavailable" ? serviceReason(e.message) : null;
  return (
    <div role="alert" className="flex items-start gap-3 rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-200">
      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="font-medium">{key ? t(key) : t("error.title")}</div>
        {reason && <div className="font-medium">{t(reason.key)}</div>}
        <div className="opacity-90 [overflow-wrap:anywhere]">{reason ? reason.detail : e.message}</div>
      </div>
      {onRetry && (
        <Button variant="ghost" onClick={onRetry}>
          {t("common.retry")}
        </Button>
      )}
    </div>
  );
}

export function Loading() {
  const { t } = useI18n();
  return (
    <div className="flex items-center gap-2 p-4 text-sm text-slate-500 dark:text-slate-400" role="status">
      <Loader2 className="size-4 animate-spin" aria-hidden />
      {t("common.loading")}
    </div>
  );
}

export function Empty({ children }: { children?: ReactNode }) {
  const { t } = useI18n();
  return <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">{children ?? t("common.empty")}</p>;
}

/** The mandatory "not validated" banner. The exact Turkish sentence is always
 * shown, whatever the UI language, until real Windows validation succeeds. */
export function NotValidatedBanner() {
  const { lang, t } = useI18n();
  return (
    <div
      role="status"
      data-testid="not-validated-banner"
      className="flex items-start gap-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-amber-950 dark:border-amber-800 dark:bg-amber-950/60 dark:text-amber-100"
    >
      <ShieldAlert className="mt-0.5 size-5 shrink-0" aria-hidden />
      <div>
        <p className="font-semibold">{translate("tr", "banner.notActivated")}</p>
        <p className="font-semibold">{translate("tr", "banner.notValidated")}</p>
        {lang !== "tr" && (
          <p className="text-sm font-medium">
            {t("banner.notActivated")} {t("banner.notValidated")}
          </p>
        )}
        <p className="text-sm opacity-90">{t("banner.simulationDetail")}</p>
      </div>
    </div>
  );
}

export function DecisionBadge({ decision }: { decision: string }) {
  const { tx } = useI18n();
  const tone: Tone = decision === "deny" ? "danger" : decision === "allow" ? "success" : "neutral";
  return <Badge tone={tone}>{tx("decision", decision)}</Badge>;
}
