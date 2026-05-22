import React from "react";
import { Activity } from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { cn } from "../ui/utils";
import { ChartEmptyState } from "./ChartEmptyState";
import type { ThreatTimelineDatum } from "../../utils/pcapChartSelectors";

type NormalizedThreatTimelinePoint = {
  bucketStart: number;
  time: string;
  threats: number;
  suspicious: number;
  confirmed: number;
};

type ThreatTimelineTooltipProps = {
  active?: boolean;
  payload?: Array<{
    value?: number;
    name?: string;
    color?: string;
    payload?: ThreatTimelineDatum;
  }>;
  label?: string;
};

function formatSeriesLabel(key: string) {
  if (key === "confirmed") return "Confirmed";
  if (key === "suspicious") return "Suspicious";
  return "Threats";
}

function seriesTone(key: "threats" | "suspicious" | "confirmed") {
  if (key === "confirmed") {
    return {
      color: "#fb7185",
      badge: "tone-rose-chip",
    };
  }

  if (key === "suspicious") {
    return {
      color: "#fbbf24",
      badge: "tone-amber-chip",
    };
  }

  return {
    color: "#38bdf8",
    badge: "tone-sky-chip",
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function toNonNegativeNumber(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0;
  }
  return Math.max(0, numeric);
}

function formatFallbackBucketLabel(bucketStart: number): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(bucketStart));
}

function normalizeTimelineChartData(
  data: ThreatTimelineDatum[]
): NormalizedThreatTimelinePoint[] {
  if (!Array.isArray(data)) {
    return [];
  }

  return data
    .map((item) => {
      if (!isPlainObject(item)) {
        return null;
      }

      const bucketStart = toNonNegativeNumber(item.bucketStart);
      const suspicious = toNonNegativeNumber(item.suspicious);
      const confirmed = toNonNegativeNumber(item.confirmed);
      const threats = Math.max(
        toNonNegativeNumber(item.threats),
        suspicious + confirmed,
        suspicious,
        confirmed
      );
      const time = String(item.time ?? item.timeLabel ?? "").trim();
      const nextTime =
        time || (bucketStart > 0 ? formatFallbackBucketLabel(bucketStart) : "");

      if (!nextTime || threats <= 0) {
        return null;
      }

      return {
        bucketStart,
        time: nextTime,
        threats,
        suspicious,
        confirmed,
      };
    })
    .filter(
      (item): item is NormalizedThreatTimelinePoint =>
        item !== null && item.time.length > 0
    )
    .sort((left, right) => left.bucketStart - right.bucketStart);
}

function ThreatTimelineTooltip({
  active,
  payload,
  label,
}: ThreatTimelineTooltipProps) {
  if (!active || !payload?.length) {
    return null;
  }

  return (
    <div className="cyber-glass min-w-[190px] rounded-3xl border border-white/10 px-3 py-2 text-xs shadow-lg">
      <div className="font-semibold text-white">{label}</div>
      <div className="mt-2 space-y-1.5">
        {payload.map((entry) => (
          <div
            key={`${entry.name}-${entry.color}`}
            className="flex items-center justify-between gap-4"
          >
            <div className="flex items-center gap-2 text-gray-300">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: entry.color }}
              />
              <span>{formatSeriesLabel(String(entry.name ?? ""))}</span>
            </div>
            <span className="font-medium text-white">{Number(entry.value ?? 0)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ThreatActivityAreaChart({
  data,
  loading = false,
  error = null,
  hasAnalysis = false,
  hasSourceData = false,
  className,
}: {
  data: ThreatTimelineDatum[];
  loading?: boolean;
  error?: string | null;
  hasAnalysis?: boolean;
  hasSourceData?: boolean;
  className?: string;
}) {
  const chartData = React.useMemo(() => normalizeTimelineChartData(data), [data]);
  const hasIncomingData = Array.isArray(data) && data.length > 0;
  const hasData = chartData.length > 0;
  const hasConfirmed = chartData.some((item) => item.confirmed > 0);
  const hasSuspicious = chartData.some((item) => item.suspicious > 0);
  const showPointDots = chartData.length <= 12;
  const hasInvalidChartData = hasIncomingData && !hasData;

  React.useEffect(() => {
    if (!import.meta.env.DEV) {
      return;
    }

    console.debug("[ThreatActivityAreaChart] final timeline data", {
      inputCount: Array.isArray(data) ? data.length : 0,
      normalizedCount: chartData.length,
      sample: chartData.slice(0, 5),
    });
  }, [chartData, data]);

  return (
    <div
      className={cn(
        "cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 p-4 shadow-lg",
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
      <div
        className="pointer-events-none absolute -right-8 top-2 h-28 w-28 rounded-full bg-blue-500/10 blur-3xl"
        aria-hidden="true"
      />
      <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <span className="flex h-9 w-9 items-center justify-center rounded-2xl border tone-sky-icon">
              <Activity className="h-4 w-4 text-white" />
            </span>
            Threat Activity Over Time
          </div>
          <div className="mt-1 text-xs uppercase tracking-widest text-gray-400">
            Timeline view of scored analyzer events
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-gray-300">
          <span className="rounded-full border px-3 py-1 text-xs tone-sky-chip">
            {hasData
              ? `${chartData.length} time bucket${chartData.length === 1 ? "" : "s"}`
              : "No timeline data"}
          </span>
          <span className={cn("rounded-full border px-3 py-1", seriesTone("threats").badge)}>
            Threats
          </span>
          {hasSuspicious ? (
            <span className={cn("rounded-full border px-3 py-1", seriesTone("suspicious").badge)}>
              Suspicious
            </span>
          ) : null}
          {hasConfirmed ? (
            <span className={cn("rounded-full border px-3 py-1", seriesTone("confirmed").badge)}>
              Confirmed
            </span>
          ) : null}
        </div>
      </div>

      {loading && !hasData ? (
        <ChartEmptyState
          title="Preparing activity timeline"
          description="Threat activity will render here as soon as timestamped analysis events are available."
          tone="loading"
          className="min-h-[240px]"
        />
      ) : error && !hasData ? (
        <ChartEmptyState
          title="Timeline unavailable"
          description={error}
          tone="error"
          className="min-h-[240px]"
        />
      ) : hasData ? (
        <div className="cyber-panel-soft rounded-3xl border border-white/10 p-3">
          <div className="w-full" style={{ height: 280, minHeight: 280 }}>
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart
                data={chartData}
                margin={{ top: 8, right: 12, left: -18, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="pcap-timeline-threats" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.42} />
                    <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.04} />
                  </linearGradient>
                  <linearGradient id="pcap-timeline-confirmed" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#fb7185" stopOpacity={0.26} />
                    <stop offset="100%" stopColor="#fb7185" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="pcap-timeline-suspicious" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#fbbf24" stopOpacity={0.24} />
                    <stop offset="100%" stopColor="#fbbf24" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  stroke="rgba(148,163,184,0.14)"
                  strokeDasharray="3 6"
                  vertical={false}
                />
                <XAxis
                  dataKey="time"
                  tick={{ fill: "#cbd5e1", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  minTickGap={18}
                />
                <YAxis
                  allowDecimals={false}
                  axisLine={false}
                  tick={{ fill: "#cbd5e1", fontSize: 11 }}
                  tickLine={false}
                  width={34}
                  domain={[0, "dataMax + 1"]}
                />
                <Tooltip content={<ThreatTimelineTooltip />} />
                <Area
                  type="monotone"
                  dataKey="threats"
                  name="threats"
                  stroke="#38bdf8"
                  strokeWidth={2.8}
                  fill="url(#pcap-timeline-threats)"
                  isAnimationActive={false}
                  dot={
                    showPointDots
                      ? { r: 3, fill: "#7dd3fc", stroke: "#38bdf8", strokeWidth: 1 }
                      : false
                  }
                  activeDot={{ r: 4, fill: "#e0f2fe", stroke: "#38bdf8", strokeWidth: 1 }}
                />
                {hasConfirmed ? (
                  <Area
                    type="monotone"
                    dataKey="confirmed"
                    name="confirmed"
                    stroke="#fb7185"
                    strokeWidth={2}
                    fill="url(#pcap-timeline-confirmed)"
                    fillOpacity={0.85}
                    isAnimationActive={false}
                    dot={
                      showPointDots
                        ? { r: 2.5, fill: "#fecdd3", stroke: "#fb7185", strokeWidth: 1 }
                        : false
                    }
                    activeDot={{ r: 3, fill: "#ffe4e6", stroke: "#fb7185", strokeWidth: 1 }}
                  />
                ) : null}
                {hasSuspicious ? (
                  <Area
                    type="monotone"
                    dataKey="suspicious"
                    name="suspicious"
                    stroke="#fbbf24"
                    strokeWidth={1.8}
                    fill="url(#pcap-timeline-suspicious)"
                    fillOpacity={0.8}
                    isAnimationActive={false}
                    dot={
                      showPointDots
                        ? { r: 2.5, fill: "#fde68a", stroke: "#fbbf24", strokeWidth: 1 }
                        : false
                    }
                    activeDot={{ r: 3, fill: "#fef3c7", stroke: "#fbbf24", strokeWidth: 1 }}
                  />
                ) : null}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      ) : (
        <ChartEmptyState
          title="No timeline data available for this analysis."
          description={
            hasInvalidChartData
              ? "Timeline rows were present, but none normalized into valid chart buckets for Recharts."
              : hasAnalysis
              ? hasSourceData
                ? "Analyzer events were present, but none crossed the active threat threshold for the timeline chart."
                : "No timestamped threat events were available for this report."
              : "No timestamped analyzer events are available for this report."
          }
          className="min-h-[240px]"
        />
      )}
    </div>
  );
}
