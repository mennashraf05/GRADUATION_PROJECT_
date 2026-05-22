import type { SecurityScoreSeverity } from "./securityScore";

export type ChartSeverityKey =
  | SecurityScoreSeverity
  | "informational"
  | "suppressed";

export interface SeverityBreakdownDatum {
  key: ChartSeverityKey;
  label: string;
  value: number;
  color: string;
}

export interface TopAttackTypeDatum {
  attack: string;
  count: number;
  severity: ChartSeverityKey;
  color: string;
}

export interface ThreatTimelineDatum {
  bucketStart: number;
  time: string;
  timeLabel: string;
  threats: number;
  suspicious: number;
  confirmed: number;
}

type SeverityCounts = Partial<Record<SecurityScoreSeverity, number>> | null | undefined;

type ClusterLike = {
  attack_type?: string | null;
  label?: string | null;
  severity?: string | null;
  count_flows?: number | null;
  count?: number | null;
};

type AlertLike = {
  label?: string | null;
  attack_type?: string | null;
  ml_label?: string | null;
  severity?: string | null;
  verdict?: string | null;
  decision?: string | null;
  time?: string | number | null;
  timestamp?: string | number | null;
};

type TimelineLike = {
  label?: string | null;
  attack_type?: string | null;
  ml_label?: string | null;
  ts?: string | number | null;
  time?: string | number | null;
  timestamp?: string | number | null;
  severity?: string | null;
  verdict?: string | null;
  decision?: string | null;
};

const SEVERITY_META: Record<
  ChartSeverityKey,
  { label: string; color: string; rank: number }
> = {
  critical: { label: "Critical", color: "#fb7185", rank: 4 },
  high: { label: "High", color: "#f97316", rank: 3 },
  medium: { label: "Medium", color: "#fbbf24", rank: 2 },
  low: { label: "Low", color: "#38bdf8", rank: 1 },
  informational: { label: "Informational", color: "#34d399", rank: 0 },
  suppressed: { label: "Suppressed", color: "#a78bfa", rank: -1 },
};

function toFiniteNumber(value: unknown): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function toPositiveCount(value: unknown, fallback = 0): number {
  const numeric = Math.round(toFiniteNumber(value));
  if (numeric > 0) {
    return numeric;
  }
  return fallback;
}

function toChartSeverity(value: unknown): ChartSeverityKey {
  const normalized = String(value ?? "").trim().toLowerCase();

  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "medium") return "medium";
  if (normalized === "low") return "low";
  if (
    normalized === "suppressed" ||
    normalized === "ignored" ||
    normalized === "dropped"
  ) {
    return "suppressed";
  }
  if (
    normalized === "info" ||
    normalized === "informational" ||
    normalized === "benign" ||
    normalized === "normal"
  ) {
    return "informational";
  }
  return "informational";
}

function severityRank(value: unknown): number {
  return SEVERITY_META[toChartSeverity(value)].rank;
}

function normalizeAttackLabel(value: unknown): string {
  const text = String(value ?? "").trim();
  return text || "Unknown Threat";
}

function getEventLabel(
  item: Pick<AlertLike & TimelineLike & ClusterLike, "attack_type" | "label" | "ml_label">
) {
  return normalizeAttackLabel(item.attack_type ?? item.label ?? item.ml_label);
}

function normalizeDecisionState(
  value: unknown,
  severity: unknown
):
  | "confirmed"
  | "suspicious"
  | "ignored"
  | "dropped"
  | "normal" {
  const normalized = String(value ?? "").trim().toLowerCase();

  if (normalized === "confirmed") return "confirmed";
  if (normalized === "suspicious") return "suspicious";
  if (normalized === "ignored") return "ignored";
  if (normalized === "dropped") return "dropped";
  if (normalized === "normal") return "normal";
  if (normalized === "critical" || normalized === "high") return "confirmed";
  if (normalized === "medium" || normalized === "low") return "suspicious";
  if (
    normalized === "info" ||
    normalized === "informational" ||
    normalized === "benign"
  ) {
    return "normal";
  }

  const chartSeverity = toChartSeverity(severity);
  if (chartSeverity === "critical" || chartSeverity === "high") return "confirmed";
  if (chartSeverity === "medium" || chartSeverity === "low") return "suspicious";
  if (chartSeverity === "suppressed") return "ignored";
  return "normal";
}

function isMeaningfulThreatEvent(
  item: Pick<
    AlertLike & TimelineLike,
    "attack_type" | "label" | "ml_label" | "decision" | "verdict" | "severity"
  >
) {
  const decision = normalizeDecisionState(item.decision ?? item.verdict, item.severity);
  if (decision === "confirmed" || decision === "suspicious") {
    return true;
  }

  const label = getEventLabel(item).toLowerCase();
  const severity = toChartSeverity(item.severity);

  if (label === "benign" || label === "unknown threat" || label === "—") {
    return false;
  }

  return (
    severity === "low" ||
    severity === "medium" ||
    severity === "high" ||
    severity === "critical"
  );
}

function getThreatSeverityBucket(
  item: Pick<AlertLike & TimelineLike, "decision" | "verdict" | "severity">
): SecurityScoreSeverity {
  const severity = toChartSeverity(item.severity);
  if (
    severity === "low" ||
    severity === "medium" ||
    severity === "high" ||
    severity === "critical"
  ) {
    return severity;
  }

  const decision = normalizeDecisionState(item.decision ?? item.verdict, item.severity);
  if (decision === "confirmed") {
    return "high";
  }
  return "medium";
}

function truncateLabel(value: string, maxLength = 22): string {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maxLength - 1)).trimEnd()}...`;
}

function toTimestamp(value: unknown): number | null {
  if (value == null || value === "") {
    return null;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) return null;
    return value > 1e11 ? value : value * 1000;
  }

  const raw = String(value).trim();
  if (!raw) {
    return null;
  }

  if (/^-?\d+(\.\d+)?$/.test(raw)) {
    const numeric = Number(raw);
    if (!Number.isFinite(numeric)) return null;
    return numeric > 1e11 ? numeric : numeric * 1000;
  }

  const parsed = new Date(raw).getTime();
  return Number.isFinite(parsed) ? parsed : null;
}

function chooseBucketSizeMs(spanMs: number): number {
  if (spanMs <= 2 * 60 * 1000) {
    return 10 * 1000;
  }
  if (spanMs <= 30 * 60 * 1000) {
    return 60 * 1000;
  }
  if (spanMs <= 3 * 60 * 60 * 1000) {
    return 5 * 60 * 1000;
  }
  if (spanMs <= 12 * 60 * 60 * 1000) {
    return 15 * 60 * 1000;
  }
  if (spanMs <= 48 * 60 * 60 * 1000) {
    return 60 * 60 * 1000;
  }
  return 6 * 60 * 60 * 1000;
}

function formatTimelineLabel(bucketStart: number, spanMs: number): string {
  const options: Intl.DateTimeFormatOptions =
    spanMs <= 24 * 60 * 60 * 1000
      ? { hour: "2-digit", minute: "2-digit" }
      : { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" };
  return new Intl.DateTimeFormat(undefined, options).format(new Date(bucketStart));
}

function isSuspiciousEvent(value: unknown, severity: unknown): boolean {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (normalized === "suspicious" || normalized === "medium") {
    return true;
  }
  return toChartSeverity(severity) === "medium";
}

function isConfirmedEvent(value: unknown, severity: unknown): boolean {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (
    normalized === "confirmed" ||
    normalized === "high" ||
    normalized === "critical"
  ) {
    return true;
  }
  const chartSeverity = toChartSeverity(severity);
  return chartSeverity === "high" || chartSeverity === "critical";
}

export function getChartSeverityMeta(key: ChartSeverityKey) {
  return SEVERITY_META[key];
}

export function buildSeverityBreakdownData(
  counts: SeverityCounts,
  suppressedCount?: number | null,
  timeline?: TimelineLike[] | null | undefined
): SeverityBreakdownDatum[] {
  const normalizedCounts: Record<ChartSeverityKey, number> = {
    critical: toPositiveCount(counts?.critical, 0),
    high: toPositiveCount(counts?.high, 0),
    medium: toPositiveCount(counts?.medium, 0),
    low: toPositiveCount(counts?.low, 0),
    informational: 0,
    suppressed: toPositiveCount(suppressedCount, 0),
  };

  const hasThreatCounts =
    normalizedCounts.critical > 0 ||
    normalizedCounts.high > 0 ||
    normalizedCounts.medium > 0 ||
    normalizedCounts.low > 0 ||
    normalizedCounts.suppressed > 0;

  if (!hasThreatCounts && Array.isArray(timeline) && timeline.length > 0) {
    timeline.forEach((item) => {
      if (isMeaningfulThreatEvent(item)) {
        normalizedCounts[getThreatSeverityBucket(item)] += 1;
        return;
      }

      normalizedCounts.informational += 1;
    });
  }

  return (Object.keys(SEVERITY_META) as ChartSeverityKey[])
    .map((key) => ({
      key,
      label: SEVERITY_META[key].label,
      value: normalizedCounts[key],
      color: SEVERITY_META[key].color,
    }))
    .filter((item) => item.value > 0);
}

export function buildTopAttackTypeData(
  clusters: ClusterLike[] | null | undefined,
  alerts: AlertLike[] | null | undefined,
  timeline?: TimelineLike[] | null | undefined,
  limit = 6
) {
  const sourceFromClusters = Array.isArray(clusters) && clusters.length > 0;
  const sourceFromAlerts = !sourceFromClusters && Array.isArray(alerts) && alerts.length > 0;
  const source = sourceFromClusters
    ? clusters.map((cluster) => ({
        label: normalizeAttackLabel(cluster.attack_type ?? cluster.label),
        count: toPositiveCount(cluster.count_flows ?? cluster.count, 1),
        severity: cluster.severity,
      }))
    : sourceFromAlerts
    ? (alerts ?? [])
        .filter((alert) => isMeaningfulThreatEvent(alert))
        .map((alert) => ({
        label: normalizeAttackLabel(alert.label ?? alert.attack_type),
        count: 1,
        severity: alert.severity ?? alert.verdict ?? alert.decision,
      }))
    : (timeline ?? [])
        .filter((item) => isMeaningfulThreatEvent(item))
        .map((item) => ({
          label: getEventLabel(item),
          count: 1,
          severity: item.severity ?? item.verdict ?? item.decision,
        }));

  const grouped = new Map<
    string,
    { attack: string; count: number; severity: ChartSeverityKey }
  >();

  source.forEach((item) => {
    const attack = normalizeAttackLabel(item.label);
    const existing = grouped.get(attack);
    const nextSeverity = toChartSeverity(item.severity);

    if (!existing) {
      grouped.set(attack, {
        attack,
        count: toPositiveCount(item.count, 1),
        severity: nextSeverity,
      });
      return;
    }

    existing.count += toPositiveCount(item.count, 1);
    if (severityRank(nextSeverity) > severityRank(existing.severity)) {
      existing.severity = nextSeverity;
    }
  });

  const data = Array.from(grouped.values())
    .sort((left, right) => {
      if (right.count !== left.count) {
        return right.count - left.count;
      }
      return severityRank(right.severity) - severityRank(left.severity);
    })
    .slice(0, Math.max(1, limit))
    .map((item) => ({
      attack: item.attack,
      count: item.count,
      severity: item.severity,
      color: SEVERITY_META[item.severity].color,
    }));

  const totalThreats = data.reduce((sum, item) => sum + item.count, 0);
  const summaryText =
    data.length === 0
      ? "No detected threat categories are available for this analysis."
      : `${data[0].attack} is the most frequent detected category with ${data[0].count} finding${
          data[0].count === 1 ? "" : "s"
        }.`;

  return {
    data,
    totalThreats,
    summaryText,
    hasSourceData: source.length > 0,
  };
}

export function buildThreatTimelineData(
  timeline: TimelineLike[] | null | undefined,
  alerts: AlertLike[] | null | undefined
) {
  const source = Array.isArray(timeline) && timeline.length > 0 ? timeline : alerts ?? [];

  const events = source
    .filter((item) => isMeaningfulThreatEvent(item))
    .map((item) => ({
      timestamp:
        toTimestamp(item.time) ??
        toTimestamp(item.timestamp) ??
        toTimestamp(item.ts),
      severity: item.severity,
      decision: item.decision ?? item.verdict,
    }))
    .filter(
      (item): item is { timestamp: number; severity: unknown; decision: unknown } =>
        typeof item.timestamp === "number" && Number.isFinite(item.timestamp)
    );

  if (events.length === 0) {
    return {
      data: [] as ThreatTimelineDatum[],
      hasSourceData: source.length > 0,
    };
  }

  const timestamps = events.map((item) => item.timestamp);
  const minTs = Math.min(...timestamps);
  const maxTs = Math.max(...timestamps);
  const spanMs = Math.max(maxTs - minTs, 0);
  const bucketSizeMs = chooseBucketSizeMs(spanMs);
  const buckets = new Map<number, ThreatTimelineDatum>();

  events.forEach((event) => {
    const bucketStart = Math.floor(event.timestamp / bucketSizeMs) * bucketSizeMs;
    const bucketLabel = formatTimelineLabel(bucketStart, spanMs);
    const existing = buckets.get(bucketStart);
    if (existing) {
      existing.threats += 1;
      if (isSuspiciousEvent(event.decision, event.severity)) {
        existing.suspicious += 1;
      }
      if (isConfirmedEvent(event.decision, event.severity)) {
        existing.confirmed += 1;
      }
      return;
    }

    buckets.set(bucketStart, {
      bucketStart,
      time: bucketLabel,
      timeLabel: bucketLabel,
      threats: 1,
      suspicious: isSuspiciousEvent(event.decision, event.severity) ? 1 : 0,
      confirmed: isConfirmedEvent(event.decision, event.severity) ? 1 : 0,
    });
  });

  return {
    data: Array.from(buckets.values()).sort(
      (left, right) => left.bucketStart - right.bucketStart
    ),
    hasSourceData: source.length > 0,
  };
}

export function formatAttackAxisLabel(value: string) {
  return truncateLabel(value, 22);
}
