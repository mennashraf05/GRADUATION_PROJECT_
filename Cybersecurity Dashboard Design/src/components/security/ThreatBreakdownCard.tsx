import React from "react";
import { ShieldAlert } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { cn } from "../ui/utils";
import { ChartEmptyState } from "./ChartEmptyState";
import type { TopAttackTypeDatum } from "../../utils/pcapChartSelectors";
import { formatAttackAxisLabel } from "../../utils/pcapChartSelectors";

export interface ThreatBreakdownDatum extends TopAttackTypeDatum {}

type ThreatBreakdownTooltipProps = {
  active?: boolean;
  payload?: Array<{
    value?: number;
    payload?: ThreatBreakdownDatum;
  }>;
};

function formatCount(value: number, noun: string): string {
  return `${value} ${value === 1 ? noun : `${noun}s`}`;
}

function ThreatBreakdownTooltip({
  active,
  payload,
}: ThreatBreakdownTooltipProps) {
  const item = payload?.[0]?.payload;
  const value = Number(payload?.[0]?.value ?? item?.count ?? 0);

  if (!active || !item || value <= 0) {
    return null;
  }

  return (
    <div className="cyber-glass min-w-[210px] rounded-3xl border border-white/10 px-3 py-2 text-xs shadow-lg">
      <div className="font-semibold text-white">{item.attack}</div>
      <div className="mt-1 text-gray-300">{formatCount(value, "finding")}</div>
    </div>
  );
}

export function ThreatBreakdownCard({
  data,
  totalThreats,
  summaryText,
  loading = false,
  error = null,
  hasAnalysis = false,
  className,
}: {
  data: ThreatBreakdownDatum[];
  totalThreats: number;
  summaryText?: string;
  loading?: boolean;
  error?: string | null;
  hasAnalysis?: boolean;
  className?: string;
}) {
  const hasData = totalThreats > 0 && data.length > 0;
  const chartHeight = Math.max(260, data.length * 52);

  return (
    <Card
      className={cn(
        "relative cyber-card cyber-glow-border overflow-hidden rounded-3xl border border-white/10 shadow-lg",
        className
      )}
    >
      <div
        className="pointer-events-none absolute inset-0 tone-orange-spotlight opacity-90"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px tone-orange-glow opacity-80"
        aria-hidden="true"
      />
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-col gap-3 text-white md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-3xl border tone-orange-icon">
              <ShieldAlert className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="text-lg font-semibold text-white">Threat Breakdown</div>
              <div className="text-xs uppercase tracking-widest text-gray-400">
                Top detected attack categories in this analysis
              </div>
            </div>
          </div>

          <Badge className="border px-3 py-1 text-xs tone-orange-chip">
            {hasData ? formatCount(totalThreats, "finding") : "No threat data"}
          </Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="relative pt-3">
        {loading && !hasData ? (
          <ChartEmptyState
            title="Preparing attack category breakdown"
            description="Detected attack categories will appear when the analyzer returns report data."
            tone="loading"
          />
        ) : error && !hasData ? (
          <ChartEmptyState
            title="Attack category breakdown unavailable"
            description={error}
            tone="error"
          />
        ) : hasData ? (
          <div className="space-y-4">
            <div
              className="cyber-panel-soft rounded-3xl border border-white/10 p-3"
              style={{ height: chartHeight }}
            >
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={data}
                  layout="vertical"
                  margin={{ top: 8, right: 44, left: 12, bottom: 0 }}
                  barCategoryGap={18}
                >
                  <CartesianGrid
                    stroke="rgba(148,163,184,0.14)"
                    strokeDasharray="3 6"
                    horizontal={true}
                    vertical={false}
                  />
                  <XAxis
                    type="number"
                    allowDecimals={false}
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: "#cbd5e1", fontSize: 11 }}
                  />
                  <YAxis
                    type="category"
                    dataKey="attack"
                    width={150}
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: "#f8fafc", fontSize: 12 }}
                    tickFormatter={formatAttackAxisLabel}
                  />
                  <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={<ThreatBreakdownTooltip />} />
                  <Bar
                    dataKey="count"
                    radius={[0, 12, 12, 0]}
                    maxBarSize={20}
                    isAnimationActive={true}
                    animationDuration={650}
                  >
                    {data.map((item) => (
                      <Cell key={`${item.attack}-${item.severity}`} fill={item.color} />
                    ))}
                    <LabelList
                      dataKey="count"
                      position="right"
                      fill="#e2e8f0"
                      fontSize={11}
                      fontWeight={600}
                    />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="cyber-panel-soft rounded-3xl border px-4 py-3 text-sm text-gray-200 tone-orange-border">
              {summaryText}
            </div>
          </div>
        ) : (
          <ChartEmptyState
            title={
              hasAnalysis
                ? "No promoted attack categories"
                : "No attack category breakdown yet"
            }
            description={
              hasAnalysis
                ? "This analysis did not promote any attack categories into the current threat breakdown."
                : "Run a PCAP analysis to populate the top detected attack categories."
            }
          />
        )}
      </CardContent>
    </Card>
  );
}
