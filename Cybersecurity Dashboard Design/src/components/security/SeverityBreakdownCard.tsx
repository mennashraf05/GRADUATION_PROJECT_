import React from "react";
import { ShieldAlert } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { cn } from "../ui/utils";
import { ChartEmptyState } from "./ChartEmptyState";
import type { SeverityBreakdownDatum } from "../../utils/pcapChartSelectors";

type SeverityTooltipProps = {
  active?: boolean;
  payload?: Array<{
    value?: number;
    payload?: SeverityBreakdownDatum;
  }>;
};

function hexToRgba(hex: string, alpha: number) {
  const normalized = hex.replace("#", "");
  const value = normalized.length === 3
    ? normalized
        .split("")
        .map((char) => `${char}${char}`)
        .join("")
    : normalized;

  const numeric = Number.parseInt(value, 16);
  if (Number.isNaN(numeric)) {
    return `rgba(148,163,184,${alpha})`;
  }

  const r = (numeric >> 16) & 255;
  const g = (numeric >> 8) & 255;
  const b = numeric & 255;

  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function formatCount(value: number, noun: string) {
  return `${value} ${value === 1 ? noun : `${noun}s`}`;
}

function SeverityTooltip({ active, payload }: SeverityTooltipProps) {
  const item = payload?.[0]?.payload;
  const value = Number(payload?.[0]?.value ?? item?.value ?? 0);

  if (!active || !item || value <= 0) {
    return null;
  }

  return (
    <div className="cyber-glass min-w-[170px] rounded-3xl border border-white/10 px-3 py-2 text-xs shadow-lg">
      <div className="font-semibold text-white">{item.label}</div>
      <div className="mt-1 text-gray-300">{formatCount(value, "finding")}</div>
    </div>
  );
}

export function SeverityBreakdownCard({
  data,
  total,
  loading = false,
  error = null,
  hasAnalysis = false,
  className,
}: {
  data: SeverityBreakdownDatum[];
  total: number;
  loading?: boolean;
  error?: string | null;
  hasAnalysis?: boolean;
  className?: string;
}) {
  const hasData = total > 0 && data.length > 0;

  return (
    <Card
      className={cn(
        "relative cyber-card cyber-glow-border overflow-hidden rounded-3xl border border-white/10 shadow-lg",
        className
      )}
    >
      <div
        className="pointer-events-none absolute inset-0 tone-rose-spotlight opacity-90"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px tone-rose-glow opacity-80"
        aria-hidden="true"
      />
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-col gap-3 text-white md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-3xl border tone-rose-icon">
              <ShieldAlert className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="text-lg font-semibold text-white">Severity Breakdown</div>
              <div className="text-xs uppercase tracking-widest text-gray-400">
                Threat Severity Distribution
              </div>
            </div>
          </div>

          <Badge className="border px-3 py-1 text-xs tone-rose-chip">
            {hasData ? formatCount(total, "finding") : "No severity data"}
          </Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="relative pt-3">
        {loading && !hasData ? (
          <ChartEmptyState
            title="Preparing severity distribution"
            description="Severity distribution will appear when analyzer results are ready."
            tone="loading"
          />
        ) : error && !hasData ? (
          <ChartEmptyState
            title="Severity distribution unavailable"
            description={error}
            tone="error"
          />
        ) : hasData ? (
          <div className="grid gap-6 lg:grid-cols-2 lg:items-center">
            <div className="flex items-center justify-center">
              <div className="relative h-64 w-64 max-w-xs">
                <div className="absolute inset-5 rounded-full bg-purple-500/10 blur-2xl" />
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={data}
                      dataKey="value"
                      nameKey="label"
                      cx="50%"
                      cy="50%"
                      innerRadius={54}
                      outerRadius={78}
                      paddingAngle={3}
                      stroke="rgba(15, 23, 42, 0.85)"
                      strokeWidth={2}
                      isAnimationActive={true}
                      animationDuration={650}
                    >
                      {data.map((item) => (
                        <Cell key={item.key} fill={item.color} />
                      ))}
                    </Pie>
                    <Tooltip content={<SeverityTooltip />} />
                  </PieChart>
                </ResponsiveContainer>

                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                  <div className="text-4xl font-bold leading-none tracking-tight text-white">
                    {total}
                  </div>
                  <div className="mt-1 text-xs uppercase tracking-widest text-gray-400">
                    Findings
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              {data.map((item) => {
                const percentage = total > 0 ? Math.round((item.value / total) * 100) : 0;
                const chipStyle = {
                  borderColor: hexToRgba(item.color, 0.22),
                  background: `linear-gradient(180deg, ${hexToRgba(item.color, 0.18)}, ${hexToRgba(item.color, 0.08)})`,
                } as React.CSSProperties;
                const valueStyle = {
                  borderColor: hexToRgba(item.color, 0.22),
                  backgroundColor: hexToRgba(item.color, 0.14),
                  color: item.color,
                } as React.CSSProperties;

                return (
                  <div
                    key={item.key}
                    className="cyber-panel-soft flex items-center justify-between gap-3 rounded-3xl border px-4 py-3"
                    style={chipStyle}
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <span
                        className="h-3 w-3 shrink-0 rounded-full"
                        style={{ backgroundColor: item.color }}
                      />
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-white">{item.label}</div>
                        <div className="text-xs text-gray-300">
                          {percentage}% of current analysis findings
                        </div>
                      </div>
                    </div>

                    <Badge className="border px-2.5 py-0.5 text-xs font-semibold" style={valueStyle}>
                      {item.value}
                    </Badge>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <ChartEmptyState
            title={
              hasAnalysis
                ? "No promoted severity findings"
                : "No severity distribution yet"
            }
            description={
              hasAnalysis
                ? "This analysis completed without any promoted severity findings to chart."
                : "Run a PCAP analysis to populate the threat severity distribution."
            }
          />
        )}
      </CardContent>
    </Card>
  );
}
