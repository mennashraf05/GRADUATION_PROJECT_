import React from "react";
import { Network } from "lucide-react";

import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { cn } from "../ui/utils";
import { ChartEmptyState } from "./ChartEmptyState";
import type { SecurityScoreSeverity } from "../../utils/securityScore";
import { useLanguage } from "../../contexts/LanguageContext";

export interface RiskPerIpRow {
  ip: string;
  role: "source" | "destination" | "both";
  threat_count: number;
  suspicious_count: number;
  top_severity: SecurityScoreSeverity;
  max_confidence: number;
  ip_risk_score: number;
  top_attack?: string | null;
}

function severityTone(severity: SecurityScoreSeverity): string {
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

function riskTone(score: number): string {
  if (score >= 75) {
    return "tone-rose-chip";
  }
  if (score >= 45) {
    return "tone-orange-chip";
  }
  if (score >= 20) {
    return "tone-amber-chip";
  }
  return "tone-emerald-chip";
}

function formatConfidence(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
    return "0%";
  }
  return `${Math.round(value * 100)}%`;
}

function formatRiskScore(value: number): string {
  if (!Number.isFinite(value)) {
    return "0";
  }
  return value.toFixed(1).replace(/\.0$/, "");
}

function roleTone(role: RiskPerIpRow["role"]): string {
  if (role === "both") {
    return "tone-slate-chip";
  }
  if (role === "destination") {
    return "tone-sky-chip";
  }
  return "tone-emerald-chip";
}

function rowTone(score: number): string {
  if (score >= 75) {
    return "bg-red-500/10";
  }
  if (score >= 45) {
    return "bg-orange-500/10";
  }
  if (score >= 20) {
    return "bg-yellow-500/10";
  }
  return "bg-white/5";
}

function ConfidenceBar({ value }: { value: number }) {
  const bounded = Math.max(0, Math.min(100, Math.round((Number(value) || 0) * 100)));
  const barBackground =
    bounded >= 75
      ? "linear-gradient(90deg,#fb7185,#f97316)"
      : bounded >= 45
      ? "linear-gradient(90deg,#f97316,#fbbf24)"
      : bounded >= 20
      ? "linear-gradient(90deg,#fbbf24,#fde68a)"
      : "linear-gradient(90deg,#34d399,#14b8a6)";

  return (
    <div className="space-y-2" style={{ minWidth: 130 }}>
      <div className="text-xs font-semibold text-white">{formatConfidence(value)}</div>
      <div className="h-1.5 overflow-hidden rounded-full bg-white/10 shadow-sm">
        <div
          className="h-full rounded-full shadow-sm"
          style={{ width: `${bounded}%`, background: barBackground }}
        />
      </div>
    </div>
  );
}

export function RiskPerIpCard({
  rows,
  className,
}: {
  rows: RiskPerIpRow[];
  className?: string;
}) {
  const { t } = useLanguage();
  const hasRows = rows.length > 0;
  const topRiskRow = hasRows ? rows[0] : null;
  const highestConfidenceRow = hasRows
    ? [...rows].sort((left, right) => right.max_confidence - left.max_confidence)[0]
    : null;
  const elevatedCount = rows.filter(
    (row) => row.top_severity === "critical" || row.top_severity === "high"
  ).length;

  return (
    <Card
      className={cn(
        "relative cyber-card cyber-glow-border overflow-hidden rounded-3xl border border-white/10 shadow-lg",
        className
      )}
    >
      <div
        className="pointer-events-none absolute inset-0 tone-sky-spotlight opacity-90"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px tone-sky-glow opacity-80"
        aria-hidden="true"
      />
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-col gap-3 text-white md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-3xl border tone-sky-icon">
              <Network className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="text-lg font-semibold text-white">{t("riskPerIp.title")}</div>
              <div className="text-xs uppercase tracking-widest text-gray-400">
                {t("riskPerIp.subtitle")}
              </div>
            </div>
          </div>

          <Badge className="border px-3 py-1 text-xs tone-sky-chip">
            {hasRows ? t("riskPerIp.badgeCount", { count: rows.length }) : t("riskPerIp.noIpData")}
          </Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="relative">
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <div className="cyber-card relative overflow-hidden rounded-3xl border px-4 py-3 shadow-lg tone-sky-border">
            <div className="pointer-events-none absolute inset-0 tone-sky-spotlight opacity-90" aria-hidden="true" />
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-sky-glow opacity-70" aria-hidden="true" />
            <div className="text-xs font-semibold uppercase tracking-widest text-gray-400">
              {t("riskPerIp.mostExposedIp")}
            </div>
            <div className="mt-2 text-lg font-semibold text-white">
              {topRiskRow?.ip ?? t("riskPerIp.noRankedIps")}
            </div>
            <div className="mt-2 text-sm leading-relaxed text-gray-300">
              {topRiskRow
                ? t("riskPerIp.mostExposedDescription", {
                    score: formatRiskScore(topRiskRow.ip_risk_score),
                    label: topRiskRow.top_attack || t("riskPerIp.noDominantLabel"),
                  })
                : t("riskPerIp.mostExposedEmpty")}
            </div>
          </div>

          <div className="cyber-card relative overflow-hidden rounded-3xl border px-4 py-3 shadow-lg tone-slate-border">
            <div className="pointer-events-none absolute inset-0 tone-slate-spotlight opacity-90" aria-hidden="true" />
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-slate-glow opacity-70" aria-hidden="true" />
            <div className="text-xs font-semibold uppercase tracking-widest text-gray-400">
              {t("riskPerIp.highestConfidence")}
            </div>
            <div className="mt-2 text-lg font-semibold text-white">
              {highestConfidenceRow ? formatConfidence(highestConfidenceRow.max_confidence) : "0%"}
            </div>
            <div className="mt-2 text-sm leading-relaxed text-gray-300">
              {highestConfidenceRow
                ? t("riskPerIp.highestConfidenceDescription", { ip: highestConfidenceRow.ip })
                : t("riskPerIp.highestConfidenceEmpty")}
            </div>
          </div>

          <div className="cyber-card relative overflow-hidden rounded-3xl border px-4 py-3 shadow-lg tone-rose-border">
            <div className="pointer-events-none absolute inset-0 tone-rose-spotlight opacity-90" aria-hidden="true" />
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-rose-glow opacity-70" aria-hidden="true" />
            <div className="text-xs font-semibold uppercase tracking-widest text-gray-400">
              {t("riskPerIp.elevatedRiskEntities")}
            </div>
            <div className="mt-2 text-lg font-semibold text-white">{elevatedCount}</div>
            <div className="mt-2 text-sm leading-relaxed text-gray-300">
              {t("riskPerIp.elevatedRiskDescription")}
            </div>
          </div>
        </div>

        <div className="cyber-panel-soft overflow-hidden rounded-3xl border border-white/10">
          <div className="overflow-x-auto" style={{ minHeight: 220 }}>
            <Table>
              <TableHeader className="sticky top-0 z-10 bg-gray-900 backdrop-blur-sm">
                <TableRow className="border-gray-800">
                  <TableHead className="text-gray-300">{t("riskPerIp.table.ip")}</TableHead>
                  <TableHead className="text-gray-300">{t("riskPerIp.table.role")}</TableHead>
                  <TableHead className="text-gray-300">{t("riskPerIp.table.threats")}</TableHead>
                  <TableHead className="text-gray-300">{t("riskPerIp.table.topSeverity")}</TableHead>
                  <TableHead className="text-gray-300">{t("riskPerIp.table.confidence")}</TableHead>
                  <TableHead className="text-gray-300">{t("riskPerIp.table.riskScore")}</TableHead>
                  <TableHead className="text-gray-300">{t("riskPerIp.table.topAttack")}</TableHead>
                </TableRow>
              </TableHeader>

              <TableBody>
                {!hasRows && (
                  <TableRow className="border-gray-800">
                    <TableCell colSpan={7} className="py-10 text-center">
                      <ChartEmptyState
                        title={t("riskPerIp.emptyTitle")}
                        description={t("riskPerIp.emptyDescription")}
                        className="border-0 bg-transparent px-0 py-0"
                      />
                    </TableCell>
                  </TableRow>
                )}

                {hasRows &&
                  rows.map((row) => (
                    <TableRow
                      key={`${row.ip}-${row.role}-${row.top_attack ?? "unknown"}`}
                      className={cn(
                        "border-gray-800 transition-colors hover:bg-white/5",
                        rowTone(row.ip_risk_score)
                      )}
                    >
                      <TableCell className="font-mono text-gray-200">
                        <div className="font-mono text-white">{row.ip}</div>
                        <div className="mt-1 text-xs text-gray-400">
                          {row.top_attack || t("riskPerIp.awaitingDominantLabel")}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={cn("border", roleTone(row.role))}>
                          {t(`riskPerIp.role.${row.role}`)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-gray-200">
                        <div className="font-semibold text-white">{row.threat_count}</div>
                        <div className="mt-1 text-xs text-gray-400">
                          {t("riskPerIp.suspiciousCount", { count: row.suspicious_count })}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={cn(
                            "border",
                            severityTone(row.top_severity)
                          )}
                        >
                          {t(`riskPerIp.severity.${row.top_severity}`)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-gray-200">
                        <ConfidenceBar value={row.max_confidence} />
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={cn(
                            "border",
                            riskTone(row.ip_risk_score)
                          )}
                        >
                          {formatRiskScore(row.ip_risk_score)}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs text-white">
                        <div className="truncate font-medium" title={row.top_attack || undefined}>
                          {row.top_attack || t("riskPerIp.unknownThreat")}
                        </div>
                        <div className="mt-1 text-xs text-gray-400">
                          {t("riskPerIp.topAttackHelp")}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
