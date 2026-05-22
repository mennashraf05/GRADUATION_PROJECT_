export type SecurityScoreSeverity = "low" | "medium" | "high" | "critical";

export type SecurityScoreLevel = "Secure" | "Warning" | "Risky" | "Critical";

export type SecurityScoreRiskLevel =
  | "Normal"
  | "Low"
  | "Medium"
  | "High"
  | "Critical";

export interface SecurityScoreThreatInput {
  label?: string | null;
  severity?: string | null;
  confidence?: number | null;
  count?: number | null;
}

export interface SecurityScorePrecomputedTopRiskInput {
  name?: string | null;
  label?: string | null;
  severity?: string | null;
  confidence?: number | null;
  count?: number | null;
  impact?: number | null;
}

export interface SecurityScorePrecomputedExplanationContributorInput {
  label?: string | null;
  impact?: number | null;
  details?: string | null;
}

export interface SecurityScorePrecomputedExplanationInput {
  base_score?: number | null;
  risk_contributors?:
    | SecurityScorePrecomputedExplanationContributorInput[]
    | null;
  final_score?: number | null;
}

export interface SecurityScoreTopThreat {
  label: string;
  severity: SecurityScoreSeverity;
  confidence: number;
  count: number;
  impact: number;
  signalRisk: number;
}

export interface SecurityScoreExplanationContributor {
  label: string;
  impact: number;
  details: string;
}

export interface SecurityScoreExplanation {
  baseScore: number;
  riskContributors: SecurityScoreExplanationContributor[];
  finalScore: number;
}

export interface SecurityScoreResult {
  score: number | null;
  level: SecurityScoreLevel | null;
  trend: string;
  topThreat: SecurityScoreTopThreat | null;
  summary: string;
  hasData: boolean;
  totalRisk: number;
  normalizedRisk: number;
  metrics: SecurityScoreMetrics;
  scoreExplanation: SecurityScoreExplanation | null;
}

export interface SecurityScoreMetrics {
  alerts: number;
  suspicious: number;
  overallRisk: number | null;
  riskLevel: SecurityScoreRiskLevel | null;
  riskContextLabel: string | null;
  riskDisplay: string | null;
  totalFlows: number;
  clusterCount: number;
  severityCounts: Record<SecurityScoreSeverity, number>;
}

export interface SecurityScoreAnalysisContext {
  alerts?: number | null;
  suspicious?: number | null;
  overallRisk?: number | null;
  riskLevel?: string | null;
  riskContextLabel?: string | null;
  riskDisplay?: string | null;
  totalFlows?: number | null;
  clusterCount?: number | null;
  severityCounts?: Partial<Record<SecurityScoreSeverity, number>> | null;
  precomputedScore?: number | null;
  precomputedLevel?: string | null;
  precomputedSummary?: string | null;
  precomputedTrend?: string | null;
  precomputedTopRisk?: SecurityScorePrecomputedTopRiskInput | null;
  precomputedExplanation?: SecurityScorePrecomputedExplanationInput | null;
}

export interface CalculateSecurityScoreOptions {
  hasAnalysis?: boolean;
  treatMissingThreatsAsNoData?: boolean;
  trend?: string;
  noDataSummary?: string;
  emptySummary?: string;
  context?: SecurityScoreAnalysisContext;
}

const SEVERITY_WEIGHTS: Record<SecurityScoreSeverity, number> = {
  low: 5,
  medium: 12,
  high: 25,
  critical: 45,
};

const RISK_LEVEL_ORDER: Record<SecurityScoreRiskLevel, number> = {
  Normal: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const SCORE_BANDS: Record<
  SecurityScoreRiskLevel,
  { scoreMin: number; scoreMax: number }
> = {
  Normal: { scoreMin: 100, scoreMax: 100 },
  Low: { scoreMin: 80, scoreMax: 95 },
  Medium: { scoreMin: 55, scoreMax: 79 },
  High: { scoreMin: 30, scoreMax: 54 },
  Critical: { scoreMin: 0, scoreMax: 29 },
};

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function roundScore(value: number): number {
  return Number(value.toFixed(1));
}

function normalizeSeverity(value: string | null | undefined): SecurityScoreSeverity | null {
  const normalized = String(value ?? "").trim().toLowerCase();

  if (normalized === "low") return "low";
  if (normalized === "medium") return "medium";
  if (normalized === "high") return "high";
  if (normalized === "critical") return "critical";

  return null;
}

function normalizeRiskLevel(value: string | null | undefined): SecurityScoreRiskLevel | null {
  const normalized = String(value ?? "").trim().toLowerCase();

  if (normalized === "normal") return "Normal";
  if (normalized === "low") return "Low";
  if (normalized === "medium") return "Medium";
  if (normalized === "high") return "High";
  if (normalized === "critical") return "Critical";

  return null;
}

function normalizeConfidence(value: number | null | undefined): number {
  const numeric = Number(value);

  if (!Number.isFinite(numeric) || numeric <= 0) {
    return 0;
  }

  if (numeric <= 1) {
    return numeric;
  }

  if (numeric <= 100) {
    return numeric / 100;
  }

  return 1;
}

function normalizeCount(value: number | null | undefined): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? Math.round(numeric) : 1;
}

function normalizeMetricCount(value: number | null | undefined): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? Math.round(numeric) : 0;
}

function normalizeOverallRisk(value: number | null | undefined): number | null {
  const numeric = Number(value);

  if (!Number.isFinite(numeric) || numeric < 0) {
    return null;
  }

  if (numeric <= 1) {
    return numeric;
  }

  if (numeric <= 100) {
    return numeric / 100;
  }

  return 1;
}

function normalizeScore(value: number | null | undefined): number | null {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return null;
  }

  return clamp(numeric, 0, 100);
}

function normalizeText(value: string | null | undefined): string | null {
  const normalized = String(value ?? "").trim();
  return normalized ? normalized : null;
}

function resolveLevel(score: number): SecurityScoreLevel {
  if (score >= 90) return "Secure";
  if (score >= 70) return "Warning";
  if (score >= 40) return "Risky";
  return "Critical";
}

function createEmptySeverityCounts(): Record<SecurityScoreSeverity, number> {
  return {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
}

function boundedCountFactor(count: number): number {
  const softened = 1 + Math.log(Math.max(1, count));
  return Math.min(softened, 2.6);
}

function deriveSignalRisk(severity: SecurityScoreSeverity, confidence: number, count: number) {
  const weight = SEVERITY_WEIGHTS[severity];
  const countFactor = boundedCountFactor(count);
  const impact = weight * confidence * countFactor;
  const evidenceRisk = Math.min(0.98, (weight / 45) * confidence * countFactor);
  const activityRisk = Math.min(0.9, (weight / 45) * 0.45 * countFactor);
  const signalRisk = Math.max(evidenceRisk, activityRisk);

  return {
    impact,
    signalRisk,
  };
}

function getRiskLevelFromValue(value: number): SecurityScoreRiskLevel {
  if (value <= 0) return "Normal";
  if (value < 0.2) return "Low";
  if (value < 0.45) return "Medium";
  if (value < 0.75) return "High";
  return "Critical";
}

function getMoreSevereRiskLevel(
  left: SecurityScoreRiskLevel | null,
  right: SecurityScoreRiskLevel | null
): SecurityScoreRiskLevel | null {
  if (!left) return right;
  if (!right) return left;
  return RISK_LEVEL_ORDER[left] >= RISK_LEVEL_ORDER[right] ? left : right;
}

function deriveOverallRiskFromThreats(threats: SecurityScoreTopThreat[]): number | null {
  if (threats.length === 0) {
    return null;
  }

  let combinedRisk = 0;

  threats.forEach((threat) => {
    combinedRisk = 1 - (1 - combinedRisk) * (1 - threat.signalRisk);
  });

  return clamp(combinedRisk, 0, 1);
}

function scoreFromOverallRisk(value: number): number {
  const risk = clamp(value, 0, 1);

  if (risk <= 0) {
    return 100;
  }

  if (risk < 0.2) {
    const progress = risk / 0.2;
    return 95 - progress * 15;
  }

  if (risk < 0.45) {
    const progress = (risk - 0.2) / 0.25;
    return 79 - progress * 24;
  }

  if (risk < 0.75) {
    const progress = (risk - 0.45) / 0.3;
    return 54 - progress * 24;
  }

  const progress = (risk - 0.75) / 0.25;
  return Math.max(0, 29 - progress * 29);
}

function pluralize(count: number, singular: string, plural?: string): string {
  return `${count} ${count === 1 ? singular : plural ?? `${singular}s`}`;
}

function selectTopThreat(threats: SecurityScoreTopThreat[]): SecurityScoreTopThreat | null {
  if (threats.length === 0) {
    return null;
  }

  const ranked = [...threats].sort((left, right) => {
    const severityDelta =
      SEVERITY_WEIGHTS[right.severity] - SEVERITY_WEIGHTS[left.severity];
    if (severityDelta !== 0) return severityDelta;
    if (right.confidence !== left.confidence) {
      return right.confidence - left.confidence;
    }
    if (right.count !== left.count) {
      return right.count - left.count;
    }
    return right.impact - left.impact;
  });

  return ranked[0] ?? null;
}

function normalizePrecomputedTopRisk(
  value: SecurityScorePrecomputedTopRiskInput | null | undefined
): SecurityScoreTopThreat | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const severity = normalizeSeverity(value.severity);
  if (!severity) {
    return null;
  }

  const confidence = normalizeConfidence(value.confidence);
  const count = normalizeCount(value.count);
  const computed = deriveSignalRisk(severity, confidence, count);
  const providedImpact = Number(value.impact);
  const impact = Number.isFinite(providedImpact) ? providedImpact : computed.impact;

  return {
    label: String(value.label ?? value.name ?? "").trim() || "Unknown threat",
    severity,
    confidence,
    count,
    impact,
    signalRisk: computed.signalRisk,
  };
}

function normalizePrecomputedExplanation(
  value: SecurityScorePrecomputedExplanationInput | null | undefined
): SecurityScoreExplanation | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const baseScore = normalizeScore(value.base_score) ?? 100;
  const finalScore = normalizeScore(value.final_score) ?? baseScore;
  const riskContributors = Array.isArray(value.risk_contributors)
    ? value.risk_contributors
        .map((contributor) => {
          const label = normalizeText(contributor.label);
          const details = normalizeText(contributor.details);
          const impact = Number(contributor.impact);

          if (!label || !details || !Number.isFinite(impact)) {
            return null;
          }

          return {
            label,
            impact: Number(impact.toFixed(1)),
            details,
          };
        })
        .filter(
          (
            contributor
          ): contributor is SecurityScoreExplanationContributor => contributor !== null
        )
    : [];

  return {
    baseScore,
    riskContributors,
    finalScore,
  };
}

function buildMetrics(
  context: SecurityScoreAnalysisContext | undefined,
  normalizedThreats: SecurityScoreTopThreat[]
): SecurityScoreMetrics {
  const severityCounts = createEmptySeverityCounts();
  const providedCounts = context?.severityCounts ?? null;

  if (providedCounts) {
    (Object.keys(severityCounts) as SecurityScoreSeverity[]).forEach((severity) => {
      severityCounts[severity] = normalizeMetricCount(providedCounts[severity]);
    });
  }

  if (Object.values(severityCounts).every((count) => count === 0)) {
    normalizedThreats.forEach((threat) => {
      severityCounts[threat.severity] += 1;
    });
  }

  return {
    alerts: normalizeMetricCount(context?.alerts),
    suspicious: normalizeMetricCount(context?.suspicious),
    overallRisk: normalizeOverallRisk(context?.overallRisk),
    riskLevel: normalizeRiskLevel(context?.riskLevel),
    riskContextLabel: normalizeText(context?.riskContextLabel),
    riskDisplay: normalizeText(context?.riskDisplay),
    totalFlows: normalizeMetricCount(context?.totalFlows),
    clusterCount: normalizeMetricCount(context?.clusterCount),
    severityCounts,
  };
}

function buildRiskContextLabel(
  metrics: SecurityScoreMetrics,
  threats: SecurityScoreTopThreat[]
): string {
  const threatCount = threats.length;
  const maxConfidence = threats.reduce(
    (highest, threat) => Math.max(highest, threat.confidence),
    0
  );
  const hasClustering =
    metrics.clusterCount > 0 ||
    threatCount > 1 ||
    threats.some((threat) => threat.count > 1) ||
    metrics.alerts > 2 ||
    metrics.suspicious > 2;
  const repeatedHighOrCritical =
    metrics.severityCounts.critical > 0 ||
    threats.some(
      (threat) =>
        (threat.severity === "high" || threat.severity === "critical") &&
        threat.count > 1
    ) ||
    metrics.severityCounts.high + metrics.severityCounts.critical > 1;

  if (
    metrics.alerts <= 0 &&
    metrics.suspicious <= 0 &&
    metrics.clusterCount <= 0 &&
    threatCount === 0 &&
    !Object.values(metrics.severityCounts).some((count) => count > 0)
  ) {
    return "No Significant Threats";
  }

  if (repeatedHighOrCritical && hasClustering) {
    return "Active Attack Pattern";
  }

  if (metrics.severityCounts.critical > 0 && threatCount > 0) {
    return "Active Attack Pattern";
  }

  if (hasClustering) {
    return "Concentrated Threat Activity";
  }

  if (
    threatCount <= 1 &&
    metrics.alerts <= 1 &&
    metrics.suspicious <= 1 &&
    metrics.severityCounts.high === 0 &&
    metrics.severityCounts.critical === 0 &&
    maxConfidence < 0.45
  ) {
    return "Isolated Event";
  }

  if (metrics.alerts > 0 || metrics.suspicious > 0 || maxConfidence >= 0.35) {
    return "Limited Suspicious Activity";
  }

  return "Unknown Context";
}

function buildRiskDisplay(
  riskLevel: SecurityScoreRiskLevel | null,
  riskContextLabel: string | null
): string {
  if (!riskLevel) {
    return "Risk summary unavailable";
  }

  const prefix =
    riskLevel === "Critical"
      ? "Critical Risk"
      : riskLevel === "High"
      ? "High Risk"
      : riskLevel === "Medium"
      ? "Moderate Risk"
      : "Low Risk";

  if (!riskContextLabel || riskContextLabel === "Unknown Context") {
    return prefix;
  }

  return `${prefix} (${riskContextLabel})`;
}

function roundImpact(value: number): number {
  return Number(value.toFixed(1));
}

function formatSeverityLabel(severity: SecurityScoreSeverity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

function formatConfidencePercent(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

function buildScoreExplanation(
  metrics: SecurityScoreMetrics,
  threats: SecurityScoreTopThreat[],
  topThreat: SecurityScoreTopThreat | null,
  score: number
): SecurityScoreExplanation {
  const baseScore = 100;
  const finalScore = score;
  const totalPenalty = roundImpact(Math.max(0, baseScore - finalScore));

  if (
    totalPenalty <= 0 &&
    metrics.alerts <= 0 &&
    metrics.suspicious <= 0 &&
    metrics.clusterCount <= 0 &&
    threats.length === 0
  ) {
    return {
      baseScore,
      finalScore,
      riskContributors: [
        {
          label: "No critical threats detected",
          impact: 0,
          details: "No promoted alerts or clustered threats materially reduced the score.",
        },
        {
          label: "No suspicious activity observed",
          impact: 0,
          details: "No suspicious events were counted in this analysis session.",
        },
      ],
    };
  }

  const contributors: Array<
    SecurityScoreExplanationContributor & { weight: number }
  > = [];
  const repeatedSignals = threats.filter((threat) => threat.count > 1).length;

  if (topThreat) {
    contributors.push({
      label: `${formatSeverityLabel(topThreat.severity)}-severity threat detected`,
      impact: 0,
      details: `Top threat ${topThreat.label} was classified as ${topThreat.severity} severity at ${formatConfidencePercent(
        topThreat.confidence
      )} confidence.`,
      weight:
        Math.max(1, SEVERITY_WEIGHTS[topThreat.severity] / 12) *
        Math.max(topThreat.confidence, 0.35),
    });
  }

  if (metrics.alerts > 0 || metrics.suspicious > 0) {
    const eventCount = Math.max(metrics.alerts, metrics.suspicious);
    contributors.push({
      label: "Suspicious activity observed",
      impact: 0,
      details: `${pluralize(
        eventCount,
        "suspicious event"
      )} contributed to the score reduction.`,
      weight: 0.9 + Math.min(eventCount, 5) * 0.6,
    });
  }

  if (metrics.clusterCount > 0 || repeatedSignals > 0) {
    const clusterValue = Math.max(metrics.clusterCount, repeatedSignals);
    contributors.push({
      label: "Clustered activity increased risk",
      impact: 0,
      details: `${pluralize(
        clusterValue,
        "clustered threat group"
      )} increased the score reduction.`,
      weight: 1.1 + Math.min(clusterValue, 5) * 0.8,
    });
  }

  if (metrics.riskContextLabel === "Active Attack Pattern") {
    contributors.push({
      label: "Repeated attack patterns increased risk",
      impact: 0,
      details:
        "Repeated high-severity or critical findings materially reduced the score.",
      weight:
        1.8 +
        metrics.severityCounts.critical * 1.1 +
        metrics.severityCounts.high * 0.6,
    });
  }

  if (metrics.overallRisk != null && metrics.overallRisk > 0) {
    const label =
      metrics.overallRisk < 0.2
        ? "Low overall risk limited impact"
        : metrics.overallRisk < 0.45
        ? "Moderate overall risk reduced score"
        : "Elevated overall risk reduced score";

    contributors.push({
      label,
      impact: 0,
      details: `Overall normalized risk settled at ${metrics.overallRisk.toFixed(
        2
      )}.`,
      weight: Math.max(0.7, metrics.overallRisk * 3.5),
    });
  }

  if (metrics.riskContextLabel === "Isolated Event") {
    contributors.push({
      label: "Limited event spread reduced impact",
      impact: 0,
      details: "Threat activity stayed isolated, which limited score reduction.",
      weight: 0.6,
    });
  }

  if (
    metrics.riskContextLabel === "No Significant Threats" ||
    (metrics.severityCounts.high === 0 &&
      metrics.severityCounts.critical === 0 &&
      metrics.clusterCount === 0)
  ) {
    contributors.push({
      label: "No critical threats detected",
      impact: 0,
      details: "No critical findings were present in the promoted results.",
      weight: 0.5,
    });
  }

  const ranked = contributors
    .sort((left, right) => right.weight - left.weight)
    .slice(0, totalPenalty > 8 ? 4 : 3);

  if (ranked.length === 0) {
    return {
      baseScore,
      finalScore,
      riskContributors: [
        {
          label: "Score explanation is unavailable",
          impact: 0,
          details: "No explainable score contributors were available for this analysis.",
        },
      ],
    };
  }

  if (totalPenalty <= 0) {
    return {
      baseScore,
      finalScore,
      riskContributors: ranked.map(({ weight: _weight, ...contributor }) => contributor),
    };
  }

  const totalWeight = ranked.reduce((sum, contributor) => sum + contributor.weight, 0);
  let remainingPenalty = totalPenalty;

  const riskContributors = ranked.map((contributor, index) => {
    const isLast = index === ranked.length - 1;
    const allocatedPenalty = isLast
      ? remainingPenalty
      : roundImpact((totalPenalty * contributor.weight) / totalWeight);
    remainingPenalty = roundImpact(Math.max(0, remainingPenalty - allocatedPenalty));

    return {
      label: contributor.label,
      impact: -allocatedPenalty,
      details: contributor.details,
    };
  });

  return {
    baseScore,
    finalScore,
    riskContributors,
  };
}

function buildSummary(
  metrics: SecurityScoreMetrics,
  topThreat: SecurityScoreTopThreat | null,
  hasThreats: boolean,
  riskContextLabel: string,
  emptySummary?: string
): string {
  if (metrics.alerts <= 0 && metrics.suspicious <= 0 && metrics.clusterCount <= 0 && !hasThreats) {
    return emptySummary ?? "No significant threats detected. Network activity appears normal.";
  }

  if (metrics.severityCounts.critical > 0 || metrics.riskLevel === "Critical") {
    return "High-impact attack patterns detected. Immediate review is recommended.";
  }

  if (metrics.riskLevel === "High") {
    return "High-impact attack patterns detected. Immediate review is recommended.";
  }

  if (riskContextLabel === "Active Attack Pattern") {
    return "High-impact attack patterns detected. Immediate review is recommended.";
  }

  if (riskContextLabel === "Concentrated Threat Activity" || metrics.clusterCount > 0) {
    return "Suspicious clustered activity was observed. Investigate related flows.";
  }

  if (metrics.severityCounts.high > 0) {
    return "A high-severity event was detected. Review the top risk for verification.";
  }

  if (metrics.alerts <= 1 && metrics.suspicious <= 1) {
    return "A limited suspicious event was detected. Review the top risk for verification.";
  }

  if (metrics.suspicious > 0 || metrics.severityCounts.medium > 0) {
    return "Limited suspicious activity was detected. Review the top risk for verification.";
  }

  if (topThreat) {
    return `${topThreat.label} remains the primary low-volume finding in this capture.`;
  }

  return emptySummary ?? "Threat indicators were limited, but review the promoted findings for context.";
}

function buildTrend(
  metrics: SecurityScoreMetrics,
  hasThreats: boolean
): string {
  if (metrics.alerts <= 0 && metrics.clusterCount <= 0 && !hasThreats) {
    return "Stable - low clustered threat activity observed.";
  }

  if (metrics.severityCounts.critical > 0 || metrics.riskLevel === "Critical") {
    return "Concerning - critical traffic patterns detected in clustered analysis.";
  }

  if (metrics.riskLevel === "High") {
    return "Concerning - high-risk traffic patterns detected in clustered analysis.";
  }

  if (metrics.severityCounts.high > 0 || metrics.clusterCount > 0) {
    return "Elevated - suspicious activity is concentrated in a small set of flows.";
  }

  return "Elevated - suspicious activity was promoted for review in this session.";
}

export function calculateSecurityScore(
  threats: SecurityScoreThreatInput[] | null | undefined,
  options: CalculateSecurityScoreOptions = {}
): SecurityScoreResult {
  const rawThreats = Array.isArray(threats) ? threats : [];
  const normalizedThreats = rawThreats
    .map((threat) => {
      const severity = normalizeSeverity(threat.severity);
      if (!severity) {
        return null;
      }

      const confidence = normalizeConfidence(threat.confidence);
      const count = normalizeCount(threat.count);
      const { impact, signalRisk } = deriveSignalRisk(severity, confidence, count);

      return {
        label: String(threat.label ?? "").trim() || "Unlabeled threat",
        severity,
        confidence,
        count,
        impact,
        signalRisk,
      };
    })
    .filter((threat): threat is SecurityScoreTopThreat => threat !== null);

  const metrics = buildMetrics(options.context, normalizedThreats);
  const hasThreatInputs = rawThreats.length > 0;
  const precomputedTopRisk = normalizePrecomputedTopRisk(options.context?.precomputedTopRisk);
  const precomputedExplanation = normalizePrecomputedExplanation(
    options.context?.precomputedExplanation
  );
  const hasMeaningfulSignals =
    normalizedThreats.length > 0 ||
    precomputedTopRisk !== null ||
    Object.values(metrics.severityCounts).some((count) => count > 0) ||
    (metrics.overallRisk != null && metrics.overallRisk > 0) ||
    (metrics.riskLevel != null && metrics.riskLevel !== "Normal");
  const hasContextSignals =
    metrics.totalFlows > 0 ||
    metrics.alerts > 0 ||
    metrics.suspicious > 0 ||
    metrics.clusterCount > 0 ||
    metrics.overallRisk !== null ||
    metrics.riskLevel !== null ||
    Object.values(metrics.severityCounts).some((count) => count > 0);

  const shouldShowNoData =
    (!options.hasAnalysis && !hasThreatInputs && !hasContextSignals) ||
    (options.treatMissingThreatsAsNoData === true &&
      !hasThreatInputs &&
      !hasContextSignals);
  const hasIncompleteSignals =
    !hasMeaningfulSignals &&
    (hasThreatInputs ||
      metrics.alerts > 0 ||
      metrics.suspicious > 0 ||
      metrics.clusterCount > 0);

  if (shouldShowNoData || hasIncompleteSignals) {
    return {
      score: null,
      level: null,
      trend:
        options.trend ??
        (hasIncompleteSignals
          ? "Current session has incomplete threat detail"
          : "Awaiting first completed analysis"),
      topThreat: null,
      summary:
        options.noDataSummary ??
        (hasIncompleteSignals
          ? "Analysis completed, but threat details were incomplete. The Security Score will populate when threat data is available."
          : "No analysis data is available yet. Run a PCAP analysis to generate a security score."),
      hasData: false,
      totalRisk: 0,
      normalizedRisk: 0,
      metrics,
      scoreExplanation: null,
    };
  }

  const derivedOverallRisk = deriveOverallRiskFromThreats(normalizedThreats);
  const effectiveOverallRisk =
    metrics.overallRisk ?? derivedOverallRisk ?? (hasContextSignals ? 0 : null);
  const derivedRiskLevel =
    effectiveOverallRisk != null ? getRiskLevelFromValue(effectiveOverallRisk) : null;
  const effectiveRiskLevel = getMoreSevereRiskLevel(metrics.riskLevel, derivedRiskLevel);
  const precomputedScore = normalizeScore(options.context?.precomputedScore);
  const totalRisk = normalizedThreats.reduce((sum, threat) => sum + threat.impact, 0);
  const normalizedRisk =
    effectiveOverallRisk != null ? roundScore(effectiveOverallRisk * 100) : 0;

  let score =
    precomputedScore ??
    (effectiveOverallRisk != null ? scoreFromOverallRisk(effectiveOverallRisk) : 100);

  if (effectiveRiskLevel) {
    const band = SCORE_BANDS[effectiveRiskLevel];
    score = clamp(score, band.scoreMin, band.scoreMax);
  }

  score = roundScore(score);

  const resolvedMetrics: SecurityScoreMetrics = {
    ...metrics,
    overallRisk: effectiveOverallRisk,
    riskLevel: effectiveRiskLevel,
    riskContextLabel:
      metrics.riskContextLabel ?? buildRiskContextLabel(metrics, normalizedThreats),
    riskDisplay:
      metrics.riskDisplay ??
      buildRiskDisplay(
        effectiveRiskLevel,
        metrics.riskContextLabel ?? buildRiskContextLabel(metrics, normalizedThreats)
      ),
  };
  const topThreat = precomputedTopRisk ?? selectTopThreat(normalizedThreats);
  const hasThreats = normalizedThreats.length > 0 || topThreat !== null;
  const level = resolveLevel(score);
  const scoreExplanation =
    precomputedExplanation ??
    buildScoreExplanation(resolvedMetrics, normalizedThreats, topThreat, score);

  return {
    score,
    level,
    trend:
      options.context?.precomputedTrend ??
      options.trend ??
      buildTrend(resolvedMetrics, hasThreats),
    topThreat,
    summary:
      options.context?.precomputedSummary ??
      buildSummary(
        resolvedMetrics,
        topThreat,
        hasThreats,
        resolvedMetrics.riskContextLabel ?? "Unknown Context",
        options.emptySummary
      ),
    hasData: true,
    totalRisk,
    normalizedRisk,
    metrics: resolvedMetrics,
    scoreExplanation,
  };
}
