import React from "react";
import { Award, Shield, Sparkles, Target, TrendingUp } from "lucide-react";

import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Progress } from "../ui/progress";
import type { GamificationProfile } from "../../utils/gamification";
import { useLanguage } from "../../contexts/LanguageContext";

export function SecurityProgressCard({
  profile,
  loading,
}: {
  profile: GamificationProfile | null;
  loading?: boolean;
}) {
  const { language } = useLanguage();
  const isArabic = language === "arabic";
  return (
    <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10">
      <div className="pointer-events-none absolute inset-0 tone-sky-spotlight opacity-85" />
      <CardHeader className="relative px-4 pt-4 pb-2 sm:px-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base text-white">{isArabic ? "Ø§Ù„ØªÙ‚Ø¯Ù… Ø§Ù„Ø£Ù…Ù†ÙŠ" : "Security Progress"}</CardTitle>
            <p className="mt-1.5 text-xs leading-5 text-slate-400">
              {isArabic ? "Ù†Ø´Ø§Ø· Ù…Ø­Ù„Ù„ ÙØ¹Ù‘Ø§Ù„ ÙˆØ³Ù„Ø§Ø³Ù„ Ø¥Ù†Ø¬Ø§Ø² ÙˆØªØ·ÙˆØ± ÙÙŠ Ø§Ù„Ù…Ø³ØªÙˆÙ‰." : "Meaningful analyst activity, streaks, and level growth."}
            </p>
          </div>
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl border tone-sky-icon">
            <Shield className="h-4 w-4 text-white" />
          </div>
        </div>
      </CardHeader>

      <CardContent className="relative space-y-3 px-4 pb-4 sm:px-5">
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_200px]">
          <div className="space-y-3">
            <div className="flex flex-wrap items-end gap-3">
              <div className={`text-3xl font-bold text-white ${loading ? "animate-pulse" : ""}`}>
                {profile ? profile.total_points : "--"}
              </div>
              <div className="pb-1 text-sm text-slate-400">{isArabic ? "Ø¥Ø¬Ù…Ø§Ù„ÙŠ Ø§Ù„Ù†Ù‚Ø§Ø·" : "total points"}</div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Badge className="tone-sky-chip border px-3 py-1 text-xs uppercase tracking-[0.18em]">
                {isArabic ? `Ø§Ù„Ù…Ø³ØªÙˆÙ‰ ${profile?.current_level ?? "--"}` : `Level ${profile?.current_level ?? "--"}`}
              </Badge>
              <span className="text-sm font-medium text-slate-200">
                {profile?.current_level_name ?? (isArabic ? "Ø¨Ø§Ù†ØªØ¸Ø§Ø± Ø§Ù„Ù†Ø´Ø§Ø·" : "Awaiting activity")}
              </span>
            </div>

            <div className="rounded-2xl border border-white/8 bg-black/20 p-3">
              <div className="flex items-center justify-between gap-3 text-sm text-slate-300">
                <span className="flex items-center gap-2">
                  <Target className="h-4 w-4 text-cyan-300" />
                  {isArabic ? "Ø§Ù„Ù…Ø³ØªÙˆÙ‰ Ø§Ù„ØªØ§Ù„ÙŠ" : "Next level"}
                </span>
                <span>
                  {profile?.next_level_name
                    ? (isArabic ? `${profile.points_to_next_level} Ù†Ù‚Ø·Ø© Ù…ØªØ¨Ù‚ÙŠØ©` : `${profile.points_to_next_level} pts remaining`)
                    : (isArabic ? "ØªÙ… Ø§Ù„ÙˆØµÙˆÙ„ Ø¥Ù„Ù‰ Ø£Ø¹Ù„Ù‰ Ù…Ø³ØªÙˆÙ‰" : "Max level reached")}
                </span>
              </div>
              <Progress
                value={profile?.level_progress_percent ?? 0}
                className="mt-2 h-2"
              />
            </div>
          </div>

          <div className="grid gap-2.5 sm:grid-cols-3 lg:grid-cols-1">
            <div className="rounded-2xl border border-amber-300/12 bg-amber-400/8 p-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-amber-100/90">
                <Sparkles className="h-4 w-4" />
                {isArabic ? "Ø§Ù„Ø³Ù„Ø³Ù„Ø© Ø§Ù„Ø­Ø§Ù„ÙŠØ©" : "Current streak"}
              </div>
              <div className="mt-1.5 text-lg font-semibold text-white">
                {profile?.current_streak ?? 0}
              </div>
            </div>

            <div className="rounded-2xl border border-emerald-300/12 bg-emerald-400/8 p-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-emerald-100/90">
                <TrendingUp className="h-4 w-4" />
                {isArabic ? "Ø£Ø·ÙˆÙ„ Ø³Ù„Ø³Ù„Ø©" : "Longest streak"}
              </div>
              <div className="mt-1.5 text-lg font-semibold text-white">
                {profile?.longest_streak ?? 0}
              </div>
            </div>

            <div className="rounded-2xl border border-white/8 bg-white/[0.04] p-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-300">
                <Award className="h-4 w-4" />
                {isArabic ? "Ø¢Ø®Ø± ÙˆØ³Ø§Ù…" : "Last badge"}
              </div>
              <div className="mt-2 text-sm font-semibold text-white">
                {profile?.last_badge?.badge_title ?? (isArabic ? "Ù„Ø§ ÙŠÙˆØ¬Ø¯ ÙˆØ³Ø§Ù… Ø¨Ø¹Ø¯" : "No badge yet")}
              </div>
            </div>
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-2xl border border-white/8 bg-black/15 p-3">
            <div className="text-xs uppercase tracking-[0.18em] text-slate-400">{isArabic ? "Ø§Ù„ÙØ­ÙˆØµØ§Øª" : "Scans"}</div>
            <div className="mt-1.5 text-lg font-semibold text-white">
              {profile?.total_scans ?? 0}
            </div>
          </div>
          <div className="rounded-2xl border border-white/8 bg-black/15 p-3">
            <div className="text-xs uppercase tracking-[0.18em] text-slate-400">
              {isArabic ? "Ø§Ù„ØªÙ†Ø¨ÙŠÙ‡Ø§Øª Ø§Ù„Ù…ÙØ±Ø§Ø¬Ø¹Ø©" : "Reviewed alerts"}
            </div>
            <div className="mt-1.5 text-lg font-semibold text-white">
              {profile?.total_reviewed_alerts ?? 0}
            </div>
          </div>
          <div className="rounded-2xl border border-white/8 bg-black/15 p-3">
            <div className="text-xs uppercase tracking-[0.18em] text-slate-400">{isArabic ? "Ø§Ù„Ø£ÙˆØ³Ù…Ø©" : "Badges"}</div>
            <div className="mt-1.5 text-lg font-semibold text-white">
              {profile?.total_badges ?? 0}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

