import React from "react";
import { CalendarRange, CheckCircle2, Flame } from "lucide-react";

import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Progress } from "../ui/progress";
import type { GamificationChallenge } from "../../utils/gamification";
import { useLanguage } from "../../contexts/LanguageContext";

function challengeModuleLabel(challenge: GamificationChallenge): string | null {
  const text = `${challenge.challenge_code || ""} ${challenge.title || ""} ${
    challenge.description || ""
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

function ChallengeGroup({
  title,
  icon,
  challenges,
}: {
  title: string;
  icon: React.ReactNode;
  challenges: GamificationChallenge[];
}) {
  const { language } = useLanguage();
  const isArabic = language === "arabic";

  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-2 text-sm font-semibold text-white">
        {icon}
        {title}
      </div>

      {challenges.length === 0 ? (
        <div className="rounded-2xl border border-white/8 bg-black/15 p-3 text-sm text-slate-400">
          {isArabic
            ? `لا توجد تحديات ${title} نشطة حاليًا.`
            : `No active ${title.toLowerCase()} challenges.`}
        </div>
      ) : (
        challenges.map((challenge) => {
          const progressPercent =
            challenge.target_value > 0
              ? Math.min(
                  (challenge.current_value / challenge.target_value) * 100,
                  100
                )
              : 0;

          const moduleLabel = challengeModuleLabel(challenge);

          return (
            <div
              key={`${challenge.challenge_type}-${challenge.challenge_code}`}
              className="rounded-2xl border border-white/8 bg-black/15 p-3"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="text-sm font-semibold text-white">
                      {challenge.title}
                    </div>

                    {moduleLabel ? (
                      <span className="rounded-full border border-white/10 bg-white/[0.04] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-300">
                        {moduleLabel}
                      </span>
                    ) : null}
                  </div>

                  <div className="mt-1 text-xs leading-5 text-slate-400">
                    {challenge.description}
                  </div>
                </div>

                <Badge
                  className={
                    challenge.status === "completed"
                      ? "tone-emerald-chip border px-3 py-1 text-xs"
                      : "tone-sky-chip border px-3 py-1 text-xs"
                  }
                >
                  +{challenge.reward_points}
                </Badge>
              </div>

              <div className="mt-3 flex items-center justify-between gap-3 text-xs text-slate-400">
                <span>
                  {challenge.current_value}/{challenge.target_value}
                </span>
                <span className="capitalize">{challenge.status}</span>
              </div>

              <Progress value={progressPercent} className="mt-2 h-2" />
            </div>
          );
        })
      )}
    </div>
  );
}

export function ActiveChallengesCard({
  daily,
  weekly,
}: {
  daily: GamificationChallenge[];
  weekly: GamificationChallenge[];
}) {
  const { language } = useLanguage();
  const isArabic = language === "arabic";

  return (
    <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10">
      <div className="pointer-events-none absolute inset-0 tone-emerald-spotlight opacity-80" />

      <CardHeader className="relative px-4 pt-4 pb-2 sm:px-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base text-white">
              {isArabic ? "التحديات النشطة" : "Active Challenges"}
            </CardTitle>

            <p className="mt-1.5 text-xs leading-5 text-slate-400">
              {isArabic
                ? "الأهداف اليومية والأسبوعية تتحدث تلقائيًا بناءً على نشاط التحليل، المراجعة، كلمات المرور، والـ Vault."
                : "Daily and weekly goals update automatically from real analyzer, review, password, and vault activity."}
            </p>
          </div>

          <div className="flex h-10 w-10 items-center justify-center rounded-2xl border tone-emerald-icon">
            <CheckCircle2 className="h-4 w-4 text-white" />
          </div>
        </div>
      </CardHeader>

      <CardContent className="relative grid gap-3 px-4 pb-4 sm:px-5 xl:grid-cols-2">
        <ChallengeGroup
          title={isArabic ? "يومية" : "Daily"}
          icon={<Flame className="h-4 w-4 text-amber-300" />}
          challenges={daily}
        />

        <ChallengeGroup
          title={isArabic ? "أسبوعية" : "Weekly"}
          icon={<CalendarRange className="h-4 w-4 text-cyan-300" />}
          challenges={weekly}
        />
      </CardContent>
    </Card>
  );
}
