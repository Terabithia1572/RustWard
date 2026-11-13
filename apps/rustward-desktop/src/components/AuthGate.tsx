import { useState } from "react";
import { CheckCircle2, Copy, KeyRound, Lock, LogOut, ShieldAlert, ShieldHalf, UserPlus } from "lucide-react";
import type { AuthStatusView, LoginResultView, RecoveryResetView } from "../api/types";
import { Badge, Button, Card, Dialog, ErrorNotice, Field, inputClass } from "./ui";
import { useI18n } from "../i18n";
import { useAction, useApi } from "../lib/hooks";

export function RecoveryKeyOnceDialog({
  recoveryKey,
  onAcknowledge,
}: {
  recoveryKey: string;
  onAcknowledge: () => void;
}) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard?.writeText(recoveryKey);
      setCopied(true);
    } catch {
      /* Clipboard unavailable in non-secure / headless test contexts. */
    }
  };

  return (
    <Dialog
      open
      title={t("auth.recoveryOnceTitle")}
      onClose={onAcknowledge}
      footer={
        <>
          <Button
            icon={copied ? <CheckCircle2 className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
            onClick={() => void copy()}
          >
            {copied ? "OK" : "Copy"}
          </Button>
          <Button variant="primary" onClick={onAcknowledge}>
            {t("auth.recoveryOnceAck")}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm" data-testid="recovery-key-once-modal">
        <p className="text-slate-700 dark:text-slate-300">{t("auth.recoveryOnceNote")}</p>
        <div className="select-all break-all rounded-md border border-amber-300 bg-amber-50 p-3 text-center font-mono text-base font-semibold tracking-wider text-amber-950 dark:border-amber-700 dark:bg-amber-950/60 dark:text-amber-100">
          {recoveryKey}
        </div>
      </div>
    </Dialog>
  );
}

export function ExitAuthorizationDialog({
  open,
  defaultUsername,
  onClose,
  onAuthorized,
}: {
  open: boolean;
  defaultUsername: string;
  onClose: () => void;
  onAuthorized: () => void;
}) {
  const { t } = useI18n();
  const api = useApi();
  const action = useAction();
  const [username, setUsername] = useState(defaultUsername);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  if (!open) return null;

  const submit = async () => {
    const res = await action.run(() => api.verifyExitAuthorization(username.trim(), password));
    setPassword("");
    if (res?.authorized) {
      setMessage(res.message_tr || t("exit.prompt"));
      onAuthorized();
    }
  };

  return (
    <Dialog
      open
      title={t("exit.title")}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button
            variant="danger"
            busy={action.busy}
            disabled={!username.trim() || !password}
            onClick={() => void submit()}
          >
            {t("exit.confirm")}
          </Button>
        </>
      }
    >
      <form
        className="space-y-3 text-sm"
        data-testid="exit-authorization-modal"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div className="flex items-start gap-2.5 rounded-md border border-amber-300 bg-amber-50 p-3 text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">
          <ShieldAlert className="mt-0.5 size-5 shrink-0" aria-hidden />
          <div className="space-y-1">
            <p className="font-semibold">{t("exit.prompt")}</p>
            <p className="text-xs opacity-90">{t("exit.serviceNote")}</p>
          </div>
        </div>
        <Field label={t("auth.username")}>
          {(id) => (
            <input
              id={id}
              className={inputClass}
              value={username}
              autoComplete="username"
              onChange={(e) => setUsername(e.target.value)}
            />
          )}
        </Field>
        <Field label={t("auth.password")}>
          {(id) => (
            <input
              id={id}
              type="password"
              className={inputClass}
              value={password}
              autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
            />
          )}
        </Field>
        {message && <p className="text-xs text-emerald-700 dark:text-emerald-300">{message}</p>}
        {action.error && <ErrorNotice error={action.error} />}
      </form>
    </Dialog>
  );
}

export function AuthScreen({
  status,
  onAuthenticated,
}: {
  status: AuthStatusView;
  onAuthenticated: (loginResult?: LoginResultView) => Promise<void> | void;
}) {
  const { t, pick } = useI18n();
  const api = useApi();
  const action = useAction();

  const [mode, setMode] = useState<"default" | "recovery">("default");
  const [username, setUsername] = useState(status.current_user?.username ?? "admin");
  const [displayName, setDisplayName] = useState("Administrator");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const [recoveryResult, setRecoveryResult] = useState<RecoveryResetView | null>(null);

  const isSetup = status.setup_required;
  const isLocked = !isSetup && status.authenticated && status.locked;

  const submitSetup = async () => {
    setLocalError(null);
    if (password !== confirmPassword) {
      setLocalError(t("auth.passwordMismatch"));
      return;
    }
    const res = await action.run(() => api.setupInitialAdmin(username.trim(), displayName.trim(), password));
    setPassword("");
    setConfirmPassword("");
    if (res) {
      await onAuthenticated(res);
    }
  };

  const submitLogin = async () => {
    setLocalError(null);
    const u = isLocked ? status.current_user?.username ?? username.trim() : username.trim();
    const res = await action.run(() => api.login(u, password));
    setPassword("");
    if (res) {
      await onAuthenticated(res);
    }
  };

  const submitRecovery = async () => {
    setLocalError(null);
    if (password !== confirmPassword) {
      setLocalError(t("auth.passwordMismatch"));
      return;
    }
    const res = await action.run(() => api.resetPasswordWithRecovery(username.trim(), recoveryKey.trim(), password));
    setPassword("");
    setConfirmPassword("");
    setRecoveryKey("");
    if (res) {
      setRecoveryResult(res);
      setMode("default");
    }
  };

  const signOutLocked = async () => {
    await action.run(() => api.logout());
    setPassword("");
    await onAuthenticated();
  };

  return (
    <div className="flex min-h-full items-center justify-center bg-slate-50 p-6 dark:bg-slate-950" data-testid="auth-screen">
      <div className="w-full max-w-md space-y-4">
        <div className="flex items-center justify-center gap-2.5 text-slate-900 dark:text-slate-100">
          <ShieldHalf className="size-8 text-cyan-600 dark:text-cyan-400" aria-hidden />
          <div>
            <div className="text-xl font-bold tracking-tight">{t("app.name")}</div>
            <div className="text-xs text-slate-500 dark:text-slate-400">{t("app.tagline")}</div>
          </div>
        </div>

        {recoveryResult?.new_recovery_key_once && (
          <RecoveryKeyOnceDialog
            recoveryKey={recoveryResult.new_recovery_key_once}
            onAcknowledge={() => setRecoveryResult(null)}
          />
        )}

        {recoveryResult && !recoveryResult.new_recovery_key_once && (
          <div className="rounded-md border border-emerald-300 bg-emerald-50 p-3 text-xs text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200">
            {pick(recoveryResult.message, recoveryResult.message_tr)}
          </div>
        )}

        <Card
          title={
            <div className="flex items-center gap-2">
              {isSetup ? (
                <UserPlus className="size-4 text-cyan-600" aria-hidden />
              ) : mode === "recovery" ? (
                <KeyRound className="size-4 text-amber-600" aria-hidden />
              ) : (
                <Lock className="size-4 text-cyan-600" aria-hidden />
              )}
              <span>
                {isSetup
                  ? t("auth.setupTitle")
                  : mode === "recovery"
                    ? t("auth.recoveryTitle")
                    : isLocked
                      ? t("auth.lockedTitle")
                      : t("auth.loginTitle")}
              </span>
            </div>
          }
          actions={
            status.windows_admin_channel ? (
              <Badge tone="info">Windows Admin</Badge>
            ) : (
              <Badge tone="neutral">Standard Channel</Badge>
            )
          }
        >
          {mode === "recovery" ? (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                void submitRecovery();
              }}
            >
              <Field label={t("auth.username")}>
                {(id) => (
                  <input
                    id={id}
                    className={inputClass}
                    value={username}
                    autoComplete="username"
                    onChange={(e) => setUsername(e.target.value)}
                  />
                )}
              </Field>
              <Field label={t("auth.recoveryKey")}>
                {(id) => (
                  <input
                    id={id}
                    className={`${inputClass} font-mono`}
                    value={recoveryKey}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => setRecoveryKey(e.target.value)}
                  />
                )}
              </Field>
              <Field label={t("auth.newPassword")}>
                {(id) => (
                  <input
                    id={id}
                    type="password"
                    className={inputClass}
                    value={password}
                    autoComplete="new-password"
                    onChange={(e) => setPassword(e.target.value)}
                  />
                )}
              </Field>
              <Field label={t("auth.passwordConfirm")}>
                {(id) => (
                  <input
                    id={id}
                    type="password"
                    className={inputClass}
                    value={confirmPassword}
                    autoComplete="new-password"
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                )}
              </Field>
              {localError && <p role="alert" className="text-xs text-rose-600 dark:text-rose-400">{localError}</p>}
              {action.error && <ErrorNotice error={action.error} />}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <Button variant="ghost" onClick={() => setMode("default")}>
                  {t("auth.backToLogin")}
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  busy={action.busy}
                  disabled={!username.trim() || !recoveryKey.trim() || !password}
                >
                  {t("auth.recoverySubmit")}
                </Button>
              </div>
            </form>
          ) : isSetup ? (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                void submitSetup();
              }}
            >
              <p className="text-xs text-slate-600 dark:text-slate-300">{t("auth.setupSubtitle")}</p>
              <Field label={t("auth.username")}>
                {(id) => (
                  <input
                    id={id}
                    className={inputClass}
                    value={username}
                    autoComplete="username"
                    onChange={(e) => setUsername(e.target.value)}
                  />
                )}
              </Field>
              <Field label={t("auth.displayName")}>
                {(id) => (
                  <input
                    id={id}
                    className={inputClass}
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                  />
                )}
              </Field>
              <Field label={t("auth.password")}>
                {(id) => (
                  <input
                    id={id}
                    type="password"
                    className={inputClass}
                    value={password}
                    autoComplete="new-password"
                    onChange={(e) => setPassword(e.target.value)}
                  />
                )}
              </Field>
              <Field label={t("auth.passwordConfirm")}>
                {(id) => (
                  <input
                    id={id}
                    type="password"
                    className={inputClass}
                    value={confirmPassword}
                    autoComplete="new-password"
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                )}
              </Field>
              {localError && <p role="alert" className="text-xs text-rose-600 dark:text-rose-400">{localError}</p>}
              {action.error && <ErrorNotice error={action.error} />}
              <Button
                type="submit"
                variant="primary"
                className="w-full justify-center"
                busy={action.busy}
                disabled={!username.trim() || !displayName.trim() || !password}
              >
                {t("auth.setupSubmit")}
              </Button>
            </form>
          ) : (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                void submitLogin();
              }}
            >
              <p className="text-xs text-slate-600 dark:text-slate-300">
                {isLocked ? t("auth.lockedSubtitle") : t("auth.loginSubtitle")}
              </p>
              {status.lockout_remaining_seconds !== null && status.lockout_remaining_seconds > 0 && (
                <p role="alert" className="rounded bg-rose-50 p-2 text-xs text-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                  {t("auth.lockoutNotice", { seconds: status.lockout_remaining_seconds })}
                </p>
              )}
              <Field label={t("auth.username")}>
                {(id) => (
                  <input
                    id={id}
                    className={inputClass}
                    value={isLocked ? status.current_user?.username ?? username : username}
                    disabled={isLocked}
                    autoComplete="username"
                    onChange={(e) => setUsername(e.target.value)}
                  />
                )}
              </Field>
              <Field label={t("auth.password")}>
                {(id) => (
                  <input
                    id={id}
                    type="password"
                    className={inputClass}
                    value={password}
                    autoComplete="current-password"
                    onChange={(e) => setPassword(e.target.value)}
                  />
                )}
              </Field>
              {action.error && <ErrorNotice error={action.error} />}
              <Button
                type="submit"
                variant="primary"
                className="w-full justify-center"
                busy={action.busy}
                disabled={(!isLocked && !username.trim()) || !password}
              >
                {isLocked ? t("auth.unlockSubmit") : t("auth.loginSubmit")}
              </Button>
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <Button variant="ghost" onClick={() => setMode("recovery")}>
                  {t("auth.forgotRecovery")}
                </Button>
                {isLocked && (
                  <Button
                    variant="ghost"
                    icon={<LogOut className="size-4" aria-hidden />}
                    onClick={() => void signOutLocked()}
                  >
                    {t("auth.logoutButton")}
                  </Button>
                )}
              </div>
            </form>
          )}
        </Card>
      </div>
    </div>
  );
}
