import { CheckCircle2, Loader2, PlugZap, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";
import type { ServiceStatusView } from "../api/types";
import { useI18n } from "../i18n";
import { useApi } from "../lib/hooks";
import { serviceReason } from "../lib/serviceReason";

type Conn =
  | { state: "checking" }
  | { state: "connected"; service: ServiceStatusView }
  | { state: "disconnected"; error: ApiError };

const POLL_MS = 15_000;

/**
 * Backend connection status, shown on every page. "Connected" only means the
 * application reaches its backend; it never claims USB protection.
 */
export function ConnectionBar() {
  const api = useApi();
  const { t } = useI18n();
  const [conn, setConn] = useState<Conn>({ state: "checking" });
  const alive = useRef(true);

  const check = useCallback(() => {
    api
      .dashboard()
      .then((d) => alive.current && setConn({ state: "connected", service: d.service }))
      .catch((e: unknown) => {
        if (!alive.current) return;
        const err = e instanceof ApiError ? e : new ApiError("unavailable", String((e as { message?: string })?.message ?? e));
        setConn({ state: "disconnected", error: err });
      });
  }, [api]);

  useEffect(() => {
    alive.current = true;
    check();
    const id = setInterval(check, POLL_MS);
    return () => {
      alive.current = false;
      clearInterval(id);
    };
  }, [check]);

  if (conn.state === "checking") {
    return (
      <div data-testid="connection-bar" data-state="checking" role="status" className="flex items-center gap-2 border-b border-slate-200 bg-slate-50 px-6 py-1.5 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300">
        <Loader2 className="size-3.5 animate-spin" aria-hidden />
        {t("conn.checking")}
      </div>
    );
  }
  if (conn.state === "connected") {
    const dev = conn.service.backend === "dev_backend";
    return (
      <div
        data-testid="connection-bar"
        data-state="connected"
        role="status"
        className={`flex flex-wrap items-center gap-x-2 gap-y-0.5 border-b px-6 py-1.5 text-xs ${
          dev
            ? "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/50 dark:text-amber-200"
            : "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200"
        }`}
      >
        <CheckCircle2 className="size-3.5 shrink-0" aria-hidden />
        <span className="font-medium">{dev ? t("conn.connectedDev") : t("conn.connectedService")}</span>
        <span className="opacity-80">· {t("conn.noProtection")}</span>
      </div>
    );
  }
  const { key, detail } = serviceReason(conn.error.message);
  return (
    <div
      data-testid="connection-bar"
      data-state="disconnected"
      role="alert"
      className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-rose-200 bg-rose-50 px-6 py-2 text-sm text-rose-900 dark:border-rose-900 dark:bg-rose-950/60 dark:text-rose-100"
    >
      <PlugZap className="size-4 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1">
        <span className="font-semibold">{t("conn.disconnected")}</span> <span>{t(key)}</span>
        <div className="text-xs opacity-80 [overflow-wrap:anywhere]">
          {t("conn.disconnectedNote")} {detail && <span className="font-mono">({detail})</span>}
        </div>
      </div>
      <button
        type="button"
        onClick={() => {
          setConn({ state: "checking" });
          check();
        }}
        className="inline-flex shrink-0 items-center gap-1 rounded-md border border-rose-300 bg-white px-2.5 py-1 text-xs font-medium text-rose-900 hover:bg-rose-100 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-100"
      >
        <RefreshCw className="size-3.5" aria-hidden />
        {t("common.retry")}
      </button>
    </div>
  );
}
