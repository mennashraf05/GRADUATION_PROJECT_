import React from "react";
import { Clock3, History } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import {
  formatGamificationTimestamp,
  type GamificationHistoryItem,
} from "../../utils/gamification";
import { useLanguage } from "../../contexts/LanguageContext";

function historyModuleLabel(item: GamificationHistoryItem): string | null {
  const text = `${item.event_type || ""} ${item.human_readable_reason || ""}`.toLowerCase();
  if (text.includes("phishing")) return "Phishing";
  if (text.includes("password")) return "Password";
  if (text.includes("identity")) return "Identity";
  if (text.includes("pcap") || text.includes("alert") || text.includes("evidence") || text.includes("report")) return "PCAP";
  return null;
}

export function RewardHistoryCard({
  history,
}: {
  history: GamificationHistoryItem[];
}) {
  const { language } = useLanguage();
  const isArabic = language === "arabic";
  return (
    <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10">
      <div className="pointer-events-none absolute inset-0 tone-rose-spotlight opacity-70" />
      <CardHeader className="relative px-4 pt-4 pb-2 sm:px-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base text-white">{isArabic ? "Ø³Ø¬Ù„ Ø§Ù„Ù…ÙƒØ§ÙØ¢Øª" : "Rewards History"}</CardTitle>
            <p className="mt-1.5 text-xs leading-5 text-slate-400">
              {isArabic ? "Ø£Ø­Ø¯Ø« Ø§Ù„Ø£Ø­Ø¯Ø§Ø« Ø§Ù„ØªÙŠ Ù…Ù†Ø­Øª Ù…ÙƒØ§ÙØ¢Øª Ù…Ù† Ø³ÙŠØ± Ø¹Ù…Ù„ Ø§Ù„ØªØ­Ù„ÙŠÙ„ ÙˆØ§Ù„Ù…Ø±Ø§Ø¬Ø¹Ø©." : "Recent reward-bearing events from the analyzer and review workflow."}
            </p>
          </div>
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl border tone-rose-icon">
            <History className="h-4 w-4 text-white" />
          </div>
        </div>
      </CardHeader>
      <CardContent className="relative px-4 pb-4 sm:px-5">
        {history.length === 0 ? (
          <div className="rounded-2xl border border-white/8 bg-black/15 p-3 text-sm text-slate-400">
            {isArabic ? "Ø³ÙŠØ¸Ù‡Ø± Ø³Ø¬Ù„ Ø§Ù„Ù…ÙƒØ§ÙØ¢Øª Ø¨Ø¹Ø¯ Ø£ÙˆÙ„ Ø¥Ø¬Ø±Ø§Ø¡ Ù…Ø¤Ù‡Ù„ ØªÙ‚ÙˆÙ… Ø¨Ù‡." : "Reward history will appear after your first eligible action."}
          </div>
        ) : (
          <div className="space-y-2.5">
            {history.map((item, index) => (
              <div
                key={`${item.event_type}-${item.created_at}-${index}`}
                className="rounded-2xl border border-white/8 bg-black/15 p-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2 text-sm font-semibold text-white"><span>+{item.points_awarded} {isArabic ? "نقطة" : "points"}</span>{historyModuleLabel(item) ? (<span className="rounded-full border border-white/10 bg-white/[0.04] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-300">{historyModuleLabel(item)}</span>) : null}</div>
                    <div className="mt-1 text-xs leading-5 text-slate-300">
                      {item.human_readable_reason}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <Clock3 className="h-3.5 w-3.5" />
                    {formatGamificationTimestamp(item.created_at)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

