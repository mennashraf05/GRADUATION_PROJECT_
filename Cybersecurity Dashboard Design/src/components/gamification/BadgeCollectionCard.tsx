import React from "react";
import { Award, Lock } from "lucide-react";

import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import type { GamificationBadge } from "../../utils/gamification";
import { useLanguage } from "../../contexts/LanguageContext";

function rarityClass(rarity: string) {
  if (rarity === "legendary") return "tone-amber-chip";
  if (rarity === "epic") return "tone-rose-chip";
  if (rarity === "rare") return "tone-sky-chip";
  return "tone-emerald-chip";
}

function badgeModuleLabel(item: GamificationBadge): string | null {
  const text = `${item.badge_code || ""} ${item.badge_title || ""} ${
    item.badge_description || ""
  }`.toLowerCase();

  if (
    text.includes("vault") ||
    text.includes("offline") ||
    text.includes("encrypted file") ||
    text.includes("integrity") ||
    text.includes("secure upload")
  ) {
    return "Vault";
  }

  if (text.includes("password")) return "Password";
  if (text.includes("identity")) return "Identity";

  if (
    text.includes("pcap") ||
    text.includes("alert") ||
    text.includes("evidence") ||
    text.includes("report") ||
    text.includes("analysis")
  ) {
    return "PCAP";
  }

  return null;
}

function BadgeTile({ item }: { item: GamificationBadge }) {
  const progressTarget =
    typeof item.progress_target === "number"
      ? Math.max(item.progress_target, 0)
      : null;

  const progressCurrent =
    typeof item.progress_current === "number"
      ? Math.max(item.progress_current, 0)
      : null;

  const progressLabel =
    progressCurrent !== null && progressTarget !== null
      ? `${
          progressTarget > 0
            ? Math.min(progressCurrent, progressTarget)
            : progressCurrent
        }/${progressTarget}`
      : null;

  const moduleLabel = badgeModuleLabel(item);

  return (
    <div
      className={`rounded-2xl border p-3 transition-all ${
        item.unlocked
          ? "border-white/10 bg-black/15"
          : "border-white/6 bg-black/10 opacity-65"
      }`}
      title={item.badge_description}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="text-sm font-semibold text-white">
              {item.badge_title}
            </div>

            {moduleLabel ? (
              <span className="rounded-full border border-white/10 bg-white/[0.04] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-300">
                {moduleLabel}
              </span>
            ) : null}
          </div>

          <div className="mt-1 text-xs leading-5 text-slate-400">
            {item.badge_description}
          </div>
        </div>

        {item.unlocked ? (
          <Award className="h-5 w-5 text-cyan-200" />
        ) : (
          <Lock className="h-5 w-5 text-slate-500" />
        )}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge className={`${rarityClass(item.rarity)} border px-3 py-1 text-xs`}>
          {item.rarity}
        </Badge>

        {progressLabel ? (
          <span className="text-xs text-slate-400">{progressLabel}</span>
        ) : null}
      </div>
    </div>
  );
}

export function BadgeCollectionCard({
  unlocked,
  locked,
}: {
  unlocked: GamificationBadge[];
  locked: GamificationBadge[];
}) {
  const { language } = useLanguage();
  const isArabic = language === "arabic";

  const items = [...unlocked, ...locked].slice(0, 12);

  return (
    <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10">
      <div className="pointer-events-none absolute inset-0 tone-amber-spotlight opacity-75" />

      <CardHeader className="relative px-4 pt-4 pb-2 sm:px-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base text-white">
              {isArabic ? "مجموعة الأوسمة" : "Badge Collection"}
            </CardTitle>

            <p className="mt-1.5 text-xs leading-5 text-slate-400">
              {isArabic
                ? "تظهر الإنجازات المفتوحة دائمًا، بينما تعرض الأوسمة المغلقة تقدمك الحالي."
                : "Unlocked achievements stay visible, while locked badges show live progress."}
            </p>
          </div>

          <div className="flex h-10 w-10 items-center justify-center rounded-2xl border tone-amber-icon">
            <Award className="h-4 w-4 text-white" />
          </div>
        </div>
      </CardHeader>

      <CardContent className="relative px-4 pb-4 sm:px-5">
        {items.length === 0 ? (
          <div className="rounded-2xl border border-white/8 bg-black/15 p-3 text-sm text-slate-400">
            {isArabic
              ? "أكمل نشاطًا مؤهلًا لبدء جمع الأوسمة."
              : "Complete an eligible activity to start earning badges."}
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {items.map((item) => (
              <BadgeTile key={item.badge_code} item={item} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
