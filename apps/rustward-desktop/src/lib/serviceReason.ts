import type { TKey } from "../i18n/tr";

/**
 * The Windows bridge tags `unavailable` errors with the reason it read from
 * the Service Control Manager, e.g. "[service_not_installed] ...". Map the tag
 * to a translated sentence. Unknown messages fall back to a generic reason.
 */
const REASONS: Record<string, TKey> = {
  service_not_installed: "reason.service_not_installed",
  service_stopped: "reason.service_stopped",
  service_starting: "reason.service_starting",
  service_stopping: "reason.service_stopping",
  admin_required: "reason.admin_required",
  service_unreachable: "reason.service_unreachable",
};

export function serviceReason(message: string): { key: TKey; detail: string } {
  const m = /^\[([a-z_]+)\]\s*(.*)$/s.exec(message);
  if (m) {
    const key = REASONS[m[1] ?? ""];
    if (key) return { key, detail: m[2] ?? "" };
  }
  if (/service identity could not be verified/i.test(message)) {
    return { key: "reason.identity_rejected", detail: message };
  }
  return { key: "reason.service_unreachable", detail: message };
}
