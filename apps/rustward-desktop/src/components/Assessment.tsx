import { Ban, CircleAlert, Info } from "lucide-react";
import type { AssessmentCategory, DeviceAssessment, ProtectionBlockerView, StorageSummaryView } from "../api/types";
import { useI18n } from "../i18n";
import { Badge, type Tone } from "./ui";

const CATEGORY_TONE: Record<AssessmentCategory, Tone> = {
  ALLOW_CANDIDATE: "success",
  DENY_CANDIDATE: "warning",
  UNVERIFIED_IDENTITY: "warning",
  UNSUPPORTED_DEVICE: "neutral",
  OUT_OF_SCOPE: "neutral",
  WINDOWS_DENIAL_VERIFIED: "danger",
  ENFORCEMENT_NOT_ACTIVE: "neutral",
};

/** One Phase 6 category. The code stays visible next to the Turkish label. */
export function CategoryBadge({ category }: { category: AssessmentCategory }) {
  const { tx } = useI18n();
  return (
    <Badge tone={CATEGORY_TONE[category] ?? "neutral"} title={category}>
      {tx("assess.cat", category)}
    </Badge>
  );
}

/**
 * Policy evaluation (left) and the verified Windows outcome (right). The
 * policy side is a prediction; only WINDOWS_DENIAL_VERIFIED is evidence.
 */
export function AssessmentCell({ a }: { a: DeviceAssessment | null | undefined }) {
  const { t, tx, lang } = useI18n();
  if (!a) return <span className="text-xs text-slate-500">—</span>;
  return (
    <div className="space-y-1 text-xs" data-testid="assessment">
      <div className="flex flex-wrap items-center gap-1">
        <span className="text-slate-500">{t("assess.policy")}:</span>
        <CategoryBadge category={a.policy_category} />
      </div>
      {a.enforcement_category && (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-slate-500">{t("assess.enforcement")}:</span>
          <CategoryBadge category={a.enforcement_category} />
        </div>
      )}
      {a.identity !== "not_evaluated" && (
        <div>
          <span className="text-slate-500">{t("assess.identity")}: </span>
          {tx("assess.identity", a.identity)}
          {!a.authenticated && <span className="text-amber-700 dark:text-amber-400"> · {t("assess.notAuthenticated")}</span>}
        </div>
      )}
      <p className="text-slate-600 dark:text-slate-300">{lang === "tr" ? a.summary_tr : a.summary_en}</p>
    </div>
  );
}

/** Counts over USB storage, from the service. */
export function SummaryTiles({ s }: { s: StorageSummaryView }) {
  const { tx } = useI18n();
  const tiles: [string, number, Tone][] = [
    ["connected", s.connected, "info"],
    ["windowsDenied", s.windows_denied, s.windows_denied > 0 ? "danger" : "neutral"],
    ["policyOnly", s.denied_by_policy_only, s.denied_by_policy_only > 0 ? "warning" : "neutral"],
    ["unverified", s.unverified_identity, s.unverified_identity > 0 ? "warning" : "neutral"],
    ["allowCandidates", s.allow_candidates, "success"],
  ];
  return (
    <ul className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5" data-testid="storage-summary">
      {tiles.map(([k, n, tone]) => (
        <li key={k} className="rounded-md border border-slate-200 bg-white px-3 py-2 dark:border-slate-800 dark:bg-slate-900">
          <div className="text-xs text-slate-500">{tx("summary", k)}</div>
          <div className="flex items-center gap-2 text-lg font-semibold">
            {n}
            {n > 0 && tone !== "neutral" && tone !== "info" && <Badge tone={tone}>{tx("summary.tone", tone)}</Badge>}
          </div>
        </li>
      ))}
    </ul>
  );
}

const BLOCKER_ICON = { blocked: Ban, action: CircleAlert, limitation: Info } as const;

/** Every condition that keeps the system out of a verified protection state. */
export function BlockerList({ blockers, limit }: { blockers: ProtectionBlockerView[]; limit?: number }) {
  const { t, tx, lang } = useI18n();
  const shown = limit ? blockers.slice(0, limit) : blockers;
  return (
    <ul className="space-y-1.5 text-sm" data-testid="blockers">
      {shown.map((b) => {
        const Icon = BLOCKER_ICON[b.kind as keyof typeof BLOCKER_ICON] ?? Info;
        return (
          <li key={b.code + b.en} className="flex gap-2" data-code={b.code}>
            <Icon
              className={`mt-0.5 size-4 shrink-0 ${b.kind === "blocked" ? "text-rose-600" : b.kind === "action" ? "text-amber-600" : "text-slate-500"}`}
              aria-hidden
            />
            <div className="min-w-0">
              <Badge tone={b.kind === "blocked" ? "danger" : b.kind === "action" ? "warning" : "neutral"}>{tx("blocker.kind", b.kind)}</Badge>{" "}
              <span>{lang === "tr" ? b.tr : b.en}</span>
            </div>
          </li>
        );
      })}
      {limit && blockers.length > limit && <li className="text-xs text-slate-500">{t("blocker.more", { n: blockers.length - limit })}</li>}
    </ul>
  );
}
