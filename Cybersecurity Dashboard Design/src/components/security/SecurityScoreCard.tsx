import React from "react";
import {
  AlertTriangle,
  Shield,
  ShieldCheck,
  TrendingUp,
  XCircle,
} from "lucide-react";

import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { cn } from "../ui/utils";
import type {
  SecurityScoreLevel,
  SecurityScoreResult,
  SecurityScoreRiskLevel,
  SecurityScoreSeverity,
} from "../../utils/securityScore";

type ToneDefinition = {
  key: "emerald" | "amber" | "orange" | "rose" | "slate";
  icon: React.ComponentType<{ className?: string }>;
};

function toneFromLevel(level: SecurityScoreLevel | null | undefined): ToneDefinition {
  if (level === "Secure") return { key: "emerald", icon: ShieldCheck };
  if (level === "Warning") return { key: "amber", icon: AlertTriangle };
  if (level === "Risky") return { key: "orange", icon: Shield };
  if (level === "Critical") return { key: "rose", icon: XCircle };
  return { key: "slate", icon: Shield };
}

function ringStrokeForTone(tone: ToneDefinition["key"]): string {
  if (tone === "emerald") return "#34d399";
  if (tone === "amber") return "#fbbf24";
  if (tone === "orange") return "#f97316";
  if (tone === "rose") return "#fb7185";
  return "#4F8CFF";
}

function ringTrackStrokeForTone(tone: ToneDefinition["key"]): string {
  if (tone === "emerald") return "rgba(52, 211, 153, 0.16)";
  if (tone === "amber") return "rgba(251, 191, 36, 0.16)";
  if (tone === "orange") return "rgba(249, 115, 22, 0.16)";
  if (tone === "rose") return "rgba(244, 63, 94, 0.18)";
  return "rgba(148, 163, 184, 0.16)";
}

function formatScore(score: number | null): string {
  if (score == null) return "--";
  return Number.isInteger(score) ? String(score) : score.toFixed(1);
}

function formatSeverity(severity: SecurityScoreSeverity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

function formatConfidence(confidence: number): string {
  if (!Number.isFinite(confidence) || confidence <= 0) {
    return "Confidence unavailable";
  }

  return `${Math.round(confidence * 100)}% confidence`;
}

function formatRiskLevel(level: SecurityScoreRiskLevel | null, display?: string | null): string {
  if (display) return display;
  if (!level) return "Risk summary unavailable";
  return `${level} analyzer risk`;
}

function formatMetricCount(count: number, singular: string, plural?: string): string {
  return `${count} ${count === 1 ? singular : plural ?? `${singular}s`}`;
}

function formatImpact(impact: number): string {
  if (!Number.isFinite(impact)) return "0";
  if (impact > 0) return `+${impact.toFixed(1).replace(/\.0$/, "")}`;
  return impact.toFixed(1).replace(/\.0$/, "");
}

function severityBadgeTone(severity: SecurityScoreSeverity): string {
  if (severity === "critical") {
    return "tone-rose-chip";
  }

  if (severity === "high") {
    return "tone-orange-chip";
  }

  if (severity === "medium") {
    return "tone-amber-chip";
  }

  return "tone-emerald-chip";
}

export function SecurityScoreCard({
  result,
  className,
}: {
  result: SecurityScoreResult;
  className?: string;
}) {
  const tone = toneFromLevel(result.level);
  const Icon = tone.icon;
  const toneKey = tone.key;
  const toneBorder = `tone-${toneKey}-border`;
  const toneChip = `tone-${toneKey}-chip`;
  const toneIcon = `tone-${toneKey}-icon`;
  const toneGlow = `tone-${toneKey}-glow`;
  const toneSpotlight = `tone-${toneKey}-spotlight`;
  const toneValue = `tone-${toneKey}-value`;
  const ringStroke = ringStrokeForTone(toneKey);
  const ringTrackStroke = ringTrackStrokeForTone(toneKey);
  const scoreValue = result.score ?? 0;
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (scoreValue / 100) * circumference;
  const levelLabel = result.level ?? "No analysis data";
  const contextPills = [
    ...(result.metrics.riskLevel || result.metrics.riskDisplay
      ? [formatRiskLevel(result.metrics.riskLevel, result.metrics.riskDisplay)]
      : []),
    ...(result.metrics.alerts > 0
      ? [formatMetricCount(result.metrics.alerts, "alert")]
      : []),
    ...(result.metrics.suspicious > 0
      ? [formatMetricCount(result.metrics.suspicious, "suspicious event")]
      : []),
  ];

  return (
    <Card
      className={cn(
        "cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 shadow-lg",
        toneBorder,
        className
      )}
    >
      <div className={cn("absolute inset-0 opacity-90", toneSpotlight)} aria-hidden="true" />
      <div className={cn("pointer-events-none absolute inset-x-0 top-0 h-px opacity-80", toneGlow)} aria-hidden="true" />
      <div
        className="pointer-events-none absolute -right-16 top-6 h-36 w-36 rounded-full bg-white/5 blur-3xl"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute left-8 top-20 h-24 w-24 rounded-full bg-purple-500/10 blur-3xl"
        aria-hidden="true"
      />

      <CardHeader className="relative pb-1">
        <CardTitle className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                "flex h-12 w-12 items-center justify-center rounded-3xl border",
                toneIcon
              )}
            >
              <Icon className="h-5 w-5 text-white" />
            </div>

            <div>
              <div className="text-lg font-semibold text-white">Security Score</div>
              <div className="text-xs uppercase tracking-widest text-gray-400">
                PCAP Risk Posture
              </div>
            </div>
          </div>

          <Badge className={cn("border px-3 py-1 text-xs font-semibold uppercase tracking-widest", toneChip)}>
            {levelLabel}
          </Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="relative pt-4">
        <div className="grid gap-6 lg:grid-cols-2 lg:items-center">
          <div className="flex items-center justify-center">
            <div
              className="relative flex items-center justify-center"
              style={{ width: 168, height: 168 }}
            >
              <div
                className={cn("absolute rounded-full opacity-70 blur-2xl", toneSpotlight)}
                style={{ inset: 10 }}
              />
              <div
                className="absolute rounded-full border border-white/10 bg-gray-900"
                style={{ inset: 18, opacity: 0.7 }}
              />
              <svg
                className="h-full w-full"
                viewBox="0 0 140 140"
                role="img"
                aria-label={
                  result.score == null
                    ? "Security score unavailable"
                    : `Security score ${formatScore(result.score)} out of 100`
                }
              >
                <circle
                  cx="70"
                  cy="70"
                  r={radius}
                  fill="none"
                  stroke={ringTrackStroke}
                  strokeWidth="12"
                />
                <circle
                  cx="70"
                  cy="70"
                  r={radius}
                  fill="none"
                  stroke={ringStroke}
                  strokeWidth="10"
                  strokeLinecap="round"
                  className="transition-all duration-500"
                  style={{
                    transform: "rotate(-90deg)",
                    transformOrigin: "50% 50%",
                    strokeDasharray: circumference,
                    strokeDashoffset: dashOffset,
                  }}
                />
              </svg>

              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <div className={cn("text-5xl font-bold leading-none tracking-tight", toneValue)}>
                  {formatScore(result.score)}
                </div>
                <div className="mt-1 text-xs uppercase tracking-widest text-gray-400">
                  Out of 100
                </div>
              </div>
            </div>
          </div>

          <div className="min-w-0 space-y-4">
            <p className="text-sm leading-relaxed text-gray-200">{result.summary}</p>

            {result.hasData ? (
              <div className="flex flex-wrap gap-2">
                {contextPills.map((pill) => (
                  <div
                    key={pill}
                    className={cn(
                      "rounded-full border px-3 py-1 text-xs font-semibold",
                      toneChip
                    )}
                  >
                    {pill}
                  </div>
                ))}
              </div>
            ) : null}

            <div className="grid gap-3 sm:grid-cols-2">
              <div className={cn("cyber-panel-soft rounded-3xl border p-4", toneBorder)}>
                <div className="text-xs uppercase tracking-widest text-gray-400">
                  Top Risk
                </div>

                {result.topThreat ? (
                  <div className="mt-2 space-y-3">
                    <div className="text-base font-semibold text-white">
                      {result.topThreat.label}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge
                        className={cn(
                          "border uppercase tracking-widest",
                          severityBadgeTone(result.topThreat.severity)
                        )}
                      >
                        {formatSeverity(result.topThreat.severity)}
                      </Badge>
                      <span className="text-xs text-gray-200">
                        {formatConfidence(result.topThreat.confidence)}
                      </span>
                      <span className="text-xs text-gray-400">
                        {formatMetricCount(result.topThreat.count, "related event")}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="mt-2 text-sm text-gray-400">
                    {result.hasData
                      ? "No dominant threat detected."
                      : "Threat ranking will appear after analysis."}
                  </div>
                )}
              </div>

              <div className={cn("cyber-panel-soft rounded-3xl border p-4", toneBorder)}>
                <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-gray-400">
                  <TrendingUp className="h-4 w-4" />
                  Trend
                </div>
                <div className="mt-2 text-base font-semibold text-white">{result.trend}</div>
                <div className="mt-2 text-sm text-gray-300">
                  {result.hasData
                    ? "Scoped to the current analysis session only."
                    : "Requires a completed analyzer report."}
                </div>
              </div>
            </div>

            <div className={cn("cyber-panel-soft rounded-3xl border p-4", toneBorder)}>
              <div className="text-xs uppercase tracking-widest text-gray-400">
                Why this score?
              </div>

              {result.scoreExplanation && result.scoreExplanation.riskContributors.length > 0 ? (
                <div className="mt-3 space-y-3">
                  {result.scoreExplanation.riskContributors.slice(0, 5).map((contributor) => (
                    <div
                      key={`${contributor.label}-${contributor.impact}-${contributor.details}`}
                      className="cyber-panel-soft rounded-3xl border border-white/10 p-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-white">
                            {contributor.label}
                          </div>
                          <div className="mt-1 text-xs leading-relaxed text-gray-400">
                            {contributor.details}
                          </div>
                        </div>

                        <Badge
                          className={cn(
                            "shrink-0 border",
                            contributor.impact < 0
                              ? "tone-rose-chip"
                              : "tone-sky-chip"
                          )}
                        >
                          {formatImpact(contributor.impact)}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mt-3 text-sm text-gray-400">
                  Score explanation is unavailable for this analysis.
                </div>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
