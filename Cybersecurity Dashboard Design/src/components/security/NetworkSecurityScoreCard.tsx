import React, { useEffect, useState } from "react";
import { motion } from "motion/react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  Info,
  Minus,
  Network,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";

import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "../ui/sheet";
import { cn } from "../ui/utils";
import {
  type NetworkSecurityScoreSummary,
  loadNetworkSecurityScoreSummary,
} from "../../utils/networkSecurityScore";
import {
  formatRelativeTime,
  RECENT_PCAP_ALERT_EVENT,
  RECENT_PCAP_ALERT_UPDATED_AT_KEY,
} from "../../utils/recentPcapAlerts";
import { useLanguage } from "../../contexts/LanguageContext";

function createEmptySummary(): NetworkSecurityScoreSummary {
  return {
    finalScore: null,
    rating: null,
    filesUsed: 0,
    latestCompletedAt: null,
    trendDelta: null,
    tone: "slate",
    analyses: [],
  };
}

function scoreToneClasses(tone: NetworkSecurityScoreSummary["tone"]) {
  return {
    border: `tone-${tone}-border`,
    chip: `tone-${tone}-chip`,
    icon: `tone-${tone}-icon`,
    glow: `tone-${tone}-glow`,
    spotlight: `tone-${tone}-spotlight`,
    value: `tone-${tone}-value`,
  };
}

function formatTrend(delta: number | null, language: "english" | "arabic"): {
  icon: React.ComponentType<{ className?: string }>;
  text: string;
} | null {
  if (delta == null) {
    return null;
  }

  const rounded = Math.round(delta);
  if (rounded > 0) {
    return {
      icon: TrendingUp,
      text:
        language === "arabic"
          ? `+${rounded}% مقارنةً بعمليات الفحص المكتملة السابقة`
          : `+${rounded}% vs previous completed scans`,
    };
  }

  if (rounded < 0) {
    return {
      icon: ShieldAlert,
      text:
        language === "arabic"
          ? `${rounded}% مقارنةً بعمليات الفحص المكتملة السابقة`
          : `${rounded}% vs previous completed scans`,
    };
  }

  return {
    icon: Minus,
    text:
      language === "arabic"
        ? "مستقرة مقارنةً بعمليات الفحص المكتملة السابقة"
        : "Stable against previous completed scans",
  };
}

function helperLine(summary: NetworkSecurityScoreSummary, error: string | null): string {
  if (summary.filesUsed > 0) {
    return `Based on latest ${summary.filesUsed} PCAP ${
      summary.filesUsed === 1 ? "analysis" : "analyses"
    }`;
  }

  if (error) {
    return "Unable to load recent PCAP analyses";
  }

  return "Run a PCAP analysis to populate this card";
}

function basename(value: string): string {
  const normalized = String(value || "").trim().replace(/\\/g, "/");
  if (!normalized) {
    return "";
  }

  return normalized.split("/").filter(Boolean).pop() || normalized;
}

function looksMachineGeneratedLabel(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return true;
  }

  const hasFileExtension = /\.[a-z0-9]{2,8}$/i.test(normalized);
  const uuidLike = /^[a-f0-9]{8}-[a-f0-9-]{20,}$/i.test(normalized);
  return !hasFileExtension && uuidLike;
}

function formatAnalysisLabel(
  analysis: NetworkSecurityScoreSummary["analyses"][number],
  index: number
): string {
  // Use a compact basename so long capture paths do not stretch the card layout.
  const label = basename(analysis.uploadName);
  if (label && !looksMachineGeneratedLabel(label)) {
    return label;
  }

  return `Capture ${index + 1}`;
}

function formatAnalysisMeta(
  analysis: NetworkSecurityScoreSummary["analyses"][number]
): string {
  const label = basename(analysis.uploadName);
  if (label && !looksMachineGeneratedLabel(label)) {
    return analysis.completedAt
      ? `Completed ${formatRelativeTime(analysis.completedAt)}`
      : "Completed analysis";
  }

  const shortJobId = analysis.jobId.slice(0, 8);
  const completedLabel = analysis.completedAt
    ? formatRelativeTime(analysis.completedAt)
    : "recently";
  return shortJobId
    ? `Job ${shortJobId} • completed ${completedLabel}`
    : `Completed ${completedLabel}`;
}

function buildTrendBasisLine(summary: NetworkSecurityScoreSummary): string {
  if (summary.trendDelta != null) {
    return "Trend compares the latest completed analyses against the previous completed window.";
  }

  if (summary.filesUsed > 0) {
    return "Trend appears after enough earlier completed analyses exist for a comparison window.";
  }

  return "Trend basis becomes available once completed analyses are included in the score.";
}

export function NetworkSecurityScoreCard({
  className,
}: {
  className?: string;
}) {
  const { language, isRtl, formatNumber } = useLanguage();
  const navigate = useNavigate();
  const [summary, setSummary] = useState<NetworkSecurityScoreSummary>(
    createEmptySummary
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);

  useEffect(() => {
    let mounted = true;

    const loadScore = async (showLoader = false) => {
      if (showLoader && mounted) {
        setLoading(true);
      }

      try {
        const nextSummary = await loadNetworkSecurityScoreSummary();
        if (!mounted) {
          return;
        }

        setSummary(nextSummary);
        setError(null);
      } catch (loadError) {
        if (!mounted) {
          return;
        }

        setError(
          loadError instanceof Error
            ? loadError.message
            : "Unable to update the network score right now."
        );
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    void loadScore(true);

    // Re-sync the card whenever recent PCAP activity updates elsewhere in the dashboard.
    const handleRecentAlertsUpdated = () => {
      void loadScore(false);
    };

    const handleStorageEvent = (event: StorageEvent) => {
      if (event.key === RECENT_PCAP_ALERT_UPDATED_AT_KEY) {
        void loadScore(false);
      }
    };

    window.addEventListener(RECENT_PCAP_ALERT_EVENT, handleRecentAlertsUpdated);
    window.addEventListener("storage", handleStorageEvent);

    return () => {
      mounted = false;
      window.removeEventListener(
        RECENT_PCAP_ALERT_EVENT,
        handleRecentAlertsUpdated
      );
      window.removeEventListener("storage", handleStorageEvent);
    };
  }, []);

  useEffect(() => {
    if (summary.analyses.length === 0) {
      setDetailsOpen(false);
    }
  }, [summary.analyses.length]);

  useEffect(() => {
    if (!detailsOpen) {
      return;
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDetailsOpen(false);
      }
    };

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [detailsOpen]);

  const toneClasses = scoreToneClasses(summary.tone);
  const trend = formatTrend(summary.trendDelta, language);
  const scoreDisplay =
    summary.finalScore == null ? "--" : `${Math.round(summary.finalScore)}%`;
  const statusLabel = loading
    ? language === "arabic" ? "جارٍ المزامنة" : "Syncing"
    : error
    ? language === "arabic" ? "مشكلة مزامنة" : "Sync issue"
    : summary.rating ?? (language === "arabic" ? "بانتظار البيانات" : "Awaiting data");
  const supportingLine =
    summary.filesUsed > 0
      ? language === "arabic"
        ? `استنادًا إلى آخر ${formatNumber(summary.filesUsed)} ${summary.filesUsed === 1 ? "تحليل" : "تحليلات"} PCAP`
        : helperLine(summary, error)
      : error
      ? language === "arabic"
        ? "تعذر تحميل آخر تحليلات PCAP"
        : helperLine(summary, error)
      : language === "arabic"
      ? "شغّل تحليل PCAP لعرض هذه البطاقة"
      : helperLine(summary, error);
  const detailLine = trend
    ? trend.text
    : summary.latestCompletedAt
    ? language === "arabic"
      ? `تم التحديث ${formatRelativeTime(summary.latestCompletedAt)}`
      : `Updated ${formatRelativeTime(summary.latestCompletedAt)}`
    : error
    ? language === "arabic"
      ? "تعذر مزامنة آخر درجة PCAP"
      : "Unable to sync the latest PCAP score"
    : language === "arabic"
    ? "افتح محلل PCAP لبدء الفحص"
    : "Open PCAP Analyzer to start a scan";
  const TrendIcon = trend?.icon ?? Activity;
  const recentAnalyses = summary.analyses.slice(0, 5);
  const trendBasisLine = buildTrendBasisLine(summary);
  const showLaunchAction = !loading && summary.finalScore == null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28 }}
      className={cn("h-full", className)}
      dir={isRtl ? "rtl" : "ltr"}
    >
      <Card
        className={cn(
          "cyber-card cyber-glow-border group relative h-full overflow-hidden rounded-3xl border border-white/10 bg-[linear-gradient(180deg,rgba(8,17,31,0.98),rgba(6,14,28,0.96))] shadow-lg",
          toneClasses.border
        )}
      >
        <div
          className={cn("pointer-events-none absolute inset-0 opacity-90", toneClasses.spotlight)}
          aria-hidden="true"
        />
        <div
          className={cn(
            "pointer-events-none absolute inset-x-0 top-0 h-px opacity-85",
            toneClasses.glow
          )}
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute -right-12 top-5 h-24 w-24 rounded-full bg-cyan-400/10 blur-3xl transition-opacity duration-300 group-hover:opacity-100"
          aria-hidden="true"
        />

        <CardHeader className="relative flex flex-row items-start justify-between space-y-0 pb-2">
          <div className="min-w-0 pr-3">
            <CardTitle className="text-sm font-semibold tracking-[0.01em] text-white">
              {language === "arabic" ? "درجة أمان الشبكة" : "Network Security Score"}
            </CardTitle>
            <p className="mt-1 text-[11px] leading-5 text-slate-400">
              {language === "arabic" ? "آخر وضع أمني لتحليلات PCAP" : "Recent PCAP posture"}
            </p>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            {recentAnalyses.length > 0 ? (
              <button
                type="button"
                onClick={() => setDetailsOpen(true)}
                className="flex h-9 w-9 items-center justify-center rounded-2xl border border-white/8 bg-white/[0.03] text-slate-300 transition-all hover:border-white/14 hover:bg-white/[0.06] hover:text-white"
                aria-label={language === "arabic" ? "عرض تفاصيل الدرجة" : "View score details"}
                title={language === "arabic" ? "عرض تفاصيل الدرجة" : "View score details"}
              >
                <Info className="h-4 w-4" />
              </button>
            ) : null}

            <div
              className={cn(
                "flex h-10 w-10 items-center justify-center rounded-2xl border transition-transform duration-300 group-hover:-translate-y-0.5",
                toneClasses.icon
              )}
            >
              <Network className="h-4.5 w-4.5 text-white" />
            </div>
          </div>
        </CardHeader>

        <CardContent className="relative space-y-3 pt-0">
          <div className="flex items-end gap-2">
            <motion.div
              key={scoreDisplay}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.22 }}
              className={cn(
                "text-[2rem] font-semibold leading-none tracking-[-0.03em]",
                toneClasses.value,
                loading && "animate-pulse"
              )}
            >
              {scoreDisplay}
            </motion.div>

            {summary.finalScore != null ? (
              <span className="pb-1 text-sm font-medium text-slate-300/80">
                {language === "arabic" ? "مرجحة" : "weighted"}
              </span>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Badge
              className={cn(
                "rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.18em]",
                toneClasses.chip
              )}
            >
              {statusLabel}
            </Badge>

            <span className="text-[11px] leading-5 text-slate-400">
              {supportingLine}
            </span>
          </div>

          <div
            className="flex items-center gap-2 rounded-2xl border border-white/8 bg-white/[0.03] px-3 py-2"
            title={error || undefined}
          >
            <TrendIcon className="h-3.5 w-3.5 text-slate-300/75" />
            <span className="text-[11px] leading-5 text-slate-300/78">
              {detailLine}
            </span>
          </div>

          {showLaunchAction ? (
            <Button
              type="button"
              variant="ghost"
              className="h-10 w-full justify-between rounded-2xl border border-cyan-400/24 bg-cyan-500/10 px-3 text-sm font-medium text-cyan-50 hover:bg-cyan-500/16"
              onClick={() => navigate("/pcap-analyzer")}
            >
              {language === "arabic" ? "افتح محلل PCAP" : "Open PCAP Analyzer"}
              <ArrowRight className="h-4 w-4" />
            </Button>
          ) : null}
        </CardContent>

      </Card>
      <Sheet open={detailsOpen && recentAnalyses.length > 0} onOpenChange={setDetailsOpen}>
        <SheetContent
          side="right"
          className="flex h-full w-full flex-col gap-0 border-l border-white/10 bg-[linear-gradient(180deg,rgba(2,6,23,0.995),rgba(3,10,24,0.99))] p-0 text-white shadow-[0_30px_90px_rgba(0,0,0,0.78)] sm:max-w-[40rem]"
        >
          <SheetHeader className="shrink-0 border-b border-white/10 px-5 py-5 text-left sm:px-6">
            <div className="pr-10">
              <div className="flex flex-wrap items-center gap-2">
                <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-300/75">
                  {language === "arabic" ? "تفاصيل الدرجة" : "Score details"}
                </div>
                <Badge className="rounded-full border border-white/12 bg-white/[0.06] px-3 py-1 text-[11px] font-medium text-slate-100">
                  {language === "arabic" ? `${formatNumber(summary.filesUsed)} مستخدم` : `${summary.filesUsed} used`}
                </Badge>
              </div>
              <SheetTitle className="mt-2 text-xl font-semibold text-white">
                {language === "arabic" ? "أحدث مدخلات الدرجة" : "Recent score inputs"}
              </SheetTitle>
              <SheetDescription className="mt-2 text-sm leading-6 text-slate-300">
                {language === "arabic"
                  ? "آخر الملفات المكتملة المساهمة في النتيجة المرجحة الحالية"
                  : "Latest completed files contributing to the current weighted result"}
              </SheetDescription>
            </div>
          </SheetHeader>

          <div className="score-details-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain px-5 py-5 sm:px-6">
            <div className="space-y-3">
              {recentAnalyses.map((analysis, index) => {
                const label = formatAnalysisLabel(analysis, index);
                const metaLabel = formatAnalysisMeta(analysis);
                return (
                  <div
                    key={analysis.jobId || `${label}-${index}`}
                    className="grid gap-3 rounded-[22px] border border-white/10 bg-slate-900/88 px-4 py-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"
                  >
                    <div className="min-w-0">
                      <div
                        className="text-[15px] font-semibold leading-6 text-white [overflow-wrap:anywhere]"
                        title={analysis.uploadName || label}
                      >
                        {label}
                      </div>
                      <div className="mt-1 text-[12px] leading-5 text-slate-300">
                        {metaLabel}
                      </div>
                    </div>

                    <div className="w-fit rounded-xl border border-cyan-400/18 bg-cyan-500/8 px-3 py-2 text-left sm:justify-self-end sm:text-right">
                      <div className="text-base font-semibold text-white">
                        {Math.round(analysis.score)}%
                      </div>
                      <div className="text-[11px] text-slate-300">
                        {language === "arabic" ? "درجة الملف" : "file score"}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="mt-4 rounded-[22px] border border-white/10 bg-slate-900/88 px-4 py-4">
              <div className="text-sm leading-6 text-slate-200">
                {language === "arabic"
                  ? `يتم استخدام ${formatNumber(summary.filesUsed)} ${summary.filesUsed === 1 ? "ملف مكتمل" : "ملفات مكتملة"} في الدرجة المرجحة الحالية.`
                  : `Using ${summary.filesUsed} recent completed ${summary.filesUsed === 1 ? "file" : "files"} in the current weighted score.`}
              </div>
              <div className="mt-1.5 text-xs leading-5 text-slate-400">
                {trendBasisLine}
              </div>
            </div>
          </div>

          <SheetFooter className="shrink-0 border-t border-white/10 px-5 py-4 sm:px-6">
            <SheetClose asChild>
              <Button
                type="button"
                className="h-11 w-full rounded-xl bg-cyan-500 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
              >
                {language === "arabic" ? "إغلاق التفاصيل" : "Close details"}
              </Button>
            </SheetClose>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </motion.div>
  );
}
