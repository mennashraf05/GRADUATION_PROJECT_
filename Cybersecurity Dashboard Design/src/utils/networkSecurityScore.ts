import {
  parseTimestampEpoch,
  readPcapReportSnapshotEntry,
} from "./recentPcapAlerts";

const DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:5000";
const JOB_HISTORY_PATH_CANDIDATES = ["/jobs", "/pcap/jobs"];
const JOB_HISTORY_FETCH_LIMIT = 36;
const RECENCY_WEIGHTS = [0.35, 0.25, 0.2, 0.12, 0.08] as const;

type ScoreTone = "slate" | "sky" | "emerald" | "amber" | "orange" | "rose";

export type NetworkSecurityScoreRating =
  | "Excellent"
  | "Good"
  | "Moderate"
  | "Risky"
  | "Critical";

type SeverityBucket = "normal" | "low" | "medium" | "high" | "critical";

type RawPcapJobHistoryItem = {
  job_id?: string | null;
  status?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  original_filename?: string | null;
  upload_name?: string | null;
  has_report?: boolean | null;
  report_available?: boolean | null;
  error?: string | null;
};

type ThreatCandidate = {
  confidence: number;
  label: string;
  severity: SeverityBucket;
  suppressed: boolean;
  rejected: boolean;
  validated?: boolean;
  validationStatus?: string | null;
};

export type PcapScoreBreakdown = {
  trafficCleanliness: number;
  threatSafety: number;
  detectionStability: number;
  repeatedAttackPenalty: number;
  totalFlows: number;
  benignFlows: number;
  validatedThreatCount: number;
  confirmedThreatCount: number;
  highConfidenceThreatCount: number;
};

export type PcapAnalysisScore = {
  jobId: string;
  score: number;
  completedAt: string | null;
  uploadName: string;
  breakdown: PcapScoreBreakdown;
};

export type NetworkSecurityScoreSummary = {
  finalScore: number | null;
  rating: NetworkSecurityScoreRating | null;
  filesUsed: number;
  latestCompletedAt: string | null;
  trendDelta: number | null;
  tone: ScoreTone;
  analyses: PcapAnalysisScore[];
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asRecordArray(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((item) => asRecord(item))
    .filter((item): item is Record<string, unknown> => item !== null);
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function numberValue(value: unknown): number | null {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function roundToTenths(value: number): number {
  return Math.round(value * 10) / 10;
}

function normalizeApiBase(raw: string): string {
  const trimmed = String(raw || "").trim().replace(/\/$/, "");
  if (!trimmed) {
    return "";
  }

  try {
    const url = new URL(trimmed);
    if (typeof window !== "undefined") {
      const currentHost = window.location.hostname;
      const isCurrentLocal =
        currentHost === "localhost" || currentHost === "127.0.0.1";
      const isTargetLocal =
        url.hostname === "localhost" || url.hostname === "127.0.0.1";

      if (isCurrentLocal && isTargetLocal) {
        url.hostname = currentHost;
      }
    }

    return url.origin;
  } catch {
    return trimmed;
  }
}

function pushApiBase(candidates: string[], value: string): void {
  if (value === "") {
    if (!candidates.includes("")) {
      candidates.push("");
    }
    return;
  }

  const normalized = normalizeApiBase(value);
  if (normalized && !candidates.includes(normalized)) {
    candidates.push(normalized);
  }
}

const API_BASE_URL = (() => {
  const envBase = normalizeApiBase(
    String(import.meta.env.VITE_API_BASE_URL || "")
  );
  if (envBase) {
    return envBase;
  }

  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      return `${window.location.protocol}//${host}:5000`;
    }
  }

  return DEFAULT_LOCAL_API_BASE;
})();

const API_BASE_CANDIDATES = (() => {
  const candidates: string[] = [];

  if (import.meta.env.DEV) {
    pushApiBase(candidates, "");
  }

  pushApiBase(candidates, API_BASE_URL);

  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    const protocol = window.location.protocol;

    if (host) {
      pushApiBase(candidates, `${protocol}//${host}:5000`);
      pushApiBase(candidates, `http://${host}:5000`);
    }

    if (host === "localhost" || host === "127.0.0.1") {
      pushApiBase(candidates, "http://127.0.0.1:5000");
      pushApiBase(candidates, "http://localhost:5000");
    }
  }

  pushApiBase(candidates, DEFAULT_LOCAL_API_BASE);
  return candidates;
})();

function buildCookieOnlyFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.delete("Authorization");
  return {
    ...init,
    credentials: "include",
    headers,
  };
}

const DEFAULT_REQUEST_TIMEOUT_MS = 15000;

function buildAuthedFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  if (typeof window !== "undefined") {
    const token = window.localStorage.getItem("sentinel_auth_token");
    if (token && token !== "cookie_based") {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }

  return {
    ...init,
    credentials: "include",
    headers,
  };
}

async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit = {},
  timeoutMs: number = DEFAULT_REQUEST_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    window.clearTimeout(timer);
  }
}

async function fetchWithPcapAuth(
  input: RequestInfo | URL,
  init: RequestInit = {}
): Promise<Response> {
  const cookieResponse = await fetchWithTimeout(
    input,
    buildCookieOnlyFetchInit(init)
  );
  if (cookieResponse.status !== 401 && cookieResponse.status !== 403) {
    return cookieResponse;
  }

  if (typeof window !== "undefined") {
    const storedToken = window.localStorage.getItem("sentinel_auth_token");
    if (storedToken && storedToken !== "cookie_based") {
      return fetchWithTimeout(input, buildAuthedFetchInit(init));
    }
  }

  return cookieResponse;
}

function buildApiUrl(path: string, base: string): string {
  return base ? `${base}${path}` : path;
}

function basename(value: unknown): string {
  const normalized = text(value).replace(/\\/g, "/");
  if (!normalized) {
    return "";
  }

  const name = normalized.split("/").filter(Boolean).pop() || "";
  return name.toLowerCase();
}

async function readJsonResponse(
  response: Response,
  fallbackMessage: string
): Promise<Record<string, unknown>> {
  const body = await response.text();
  if (!body.trim()) {
    return {};
  }

  try {
    const parsed = JSON.parse(body);
    return asRecord(parsed) ?? {};
  } catch {
    throw new Error(fallbackMessage);
  }
}

function buildJobStatusPath(jobId: string): string {
  return `/job/${encodeURIComponent(jobId)}`;
}

function jobTimestamp(job: RawPcapJobHistoryItem): number {
  return (
    parseTimestampEpoch(job.finished_at) ||
    parseTimestampEpoch(job.created_at) ||
    parseTimestampEpoch(job.started_at) ||
    0
  );
}

function isSuccessfulJob(job: RawPcapJobHistoryItem): boolean {
  if (text(job.job_id) === "") {
    return false;
  }

  if (text(job.status).toLowerCase() !== "done") {
    return false;
  }

  if (text(job.error) !== "") {
    return false;
  }

  const hasExplicitReportSignal =
    job.report_available === true || job.has_report === true;

  // Treat job history as discovery data only. Some archived/completed jobs may
  // omit the report flag, so the job details endpoint remains the final source
  // of truth before we compute a score.
  return hasExplicitReportSignal || jobTimestamp(job) > 0;
}

export function selectLatestSuccessfulPcapAnalyses(
  jobs: RawPcapJobHistoryItem[],
  limit = 5
): RawPcapJobHistoryItem[] {
  return [...jobs]
    .filter((job) => isSuccessfulJob(job))
    .sort((left, right) => jobTimestamp(right) - jobTimestamp(left))
    .slice(0, Math.max(0, limit));
}

function normalizeSeverity(value: unknown): SeverityBucket {
  const normalized = text(value).toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "medium") return "medium";
  if (normalized === "low" || normalized === "warning" || normalized === "info") {
    return "low";
  }
  return "normal";
}

function normalizeDecision(value: unknown): string {
  return text(value).toLowerCase();
}

function isThreatRejected(candidate: ThreatCandidate): boolean {
  if (candidate.suppressed || candidate.rejected) {
    return true;
  }

  if (
    candidate.validationStatus &&
    candidate.validationStatus !== "passed"
  ) {
    return true;
  }

  if (candidate.validated === false) {
    return true;
  }

  return false;
}

function getCandidateConfidence(raw: Record<string, unknown>): number {
  return clamp(
    numberValue(
      raw.threat_confidence ??
        raw.confidence ??
        raw.ml_confidence ??
        raw.max_threat_confidence ??
        raw.max_confidence ??
        0
    ) ?? 0,
    0,
    1
  );
}

function getCandidateLabel(raw: Record<string, unknown>): string {
  return (
    text(raw.label) ||
    text(raw.ml_label) ||
    text(raw.attack_type) ||
    text(raw.name) ||
    "unknown"
  );
}

function buildThreatCandidate(raw: Record<string, unknown>): ThreatCandidate {
  const decision = normalizeDecision(
    raw.decision ?? raw.status ?? raw.validation_decision ?? raw.verdict
  );
  const validationStatus = text(raw.validation_status).toLowerCase() || null;

  return {
    confidence: getCandidateConfidence(raw),
    label: getCandidateLabel(raw),
    severity: normalizeSeverity(raw.severity ?? raw.verdict),
    suppressed: raw.suppressed === true || decision === "ignored" || decision === "suppressed",
    rejected:
      raw.rejected === true ||
      decision === "rejected" ||
      decision === "dropped",
    validated:
      typeof raw.validated === "boolean"
        ? raw.validated
        : typeof raw.validation_passed === "boolean"
        ? (raw.validation_passed as boolean)
        : undefined,
    validationStatus,
  };
}

function extractThreatCandidates(report: Record<string, unknown>): ThreatCandidate[] {
  const alerts = asRecordArray(report.alerts);
  const clusters = asRecordArray(report.clusters);
  const timeline = asRecordArray(report.timeline);

  if (alerts.length > 0) {
    return alerts.map(buildThreatCandidate).filter((candidate) => candidate.severity !== "normal");
  }

  if (clusters.length > 0) {
    return clusters
      .map(buildThreatCandidate)
      .filter((candidate) => candidate.severity !== "normal");
  }

  return timeline
    .map(buildThreatCandidate)
    .filter((candidate) => candidate.severity !== "normal");
}

function getTotalFlows(report: Record<string, unknown>): number {
  const summary = asRecord(report.summary);
  const timeline = asRecordArray(report.timeline);

  return (
    numberValue(summary?.total_flows) ??
    numberValue(report.total_flows) ??
    timeline.length
  );
}

function getBenignFlows(report: Record<string, unknown>, totalFlows: number): number {
  const summary = asRecord(report.summary);
  const directValue =
    numberValue(summary?.benign_flows) ?? numberValue(report.benign_flows);

  if (directValue != null) {
    return clamp(directValue, 0, Math.max(totalFlows, 0));
  }

  const timeline = asRecordArray(report.timeline);
  if (timeline.length > 0) {
    const benignCount = timeline.filter((row) => {
      const label = getCandidateLabel(row).toLowerCase();
      const verdict = normalizeDecision(
        row.verdict ?? row.decision ?? row.status ?? row.severity
      );

      return (
        label === "benign" ||
        label === "normal" ||
        verdict === "normal" ||
        verdict === "benign" ||
        verdict === "safe"
      );
    }).length;

    return clamp(benignCount, 0, Math.max(totalFlows, 0));
  }

  const suspiciousCount = Math.max(
    numberValue(summary?.alerts_count) ?? 0,
    numberValue(summary?.alerts) ?? 0,
    numberValue(summary?.suspicious) ?? 0,
    numberValue(summary?.malicious) ?? 0
  );

  return clamp(totalFlows - suspiciousCount, 0, Math.max(totalFlows, 0));
}

function severityPenaltyWeight(severity: SeverityBucket): number {
  if (severity === "critical") return 18;
  if (severity === "high") return 10;
  if (severity === "medium") return 5;
  if (severity === "low") return 2;
  return 0;
}

function severityPenaltyMultiplier(index: number): number {
  if (index <= 0) return 1;
  if (index <= 2) return 0.7;
  return 0.45;
}

function calculateSeverityPenalty(validatedThreats: ThreatCandidate[]): number {
  const counts = new Map<string, number>();

  const totalPenalty = validatedThreats.reduce((sum, candidate) => {
    const key = candidate.label.toLowerCase();
    const seenCount = counts.get(key) || 0;
    counts.set(key, seenCount + 1);

    // Repeated findings are already penalized again by stability/repetition, so
    // apply mild diminishing returns here to avoid over-weighting the same threat.
    return (
      sum +
      severityPenaltyWeight(candidate.severity) *
        severityPenaltyMultiplier(seenCount)
    );
  }, 0);

  return clamp(totalPenalty, 0, 70);
}

function getReportGeneratedAt(report: Record<string, unknown>): number {
  const meta = asRecord(report.meta);
  return parseTimestampEpoch(meta?.generated_at);
}

function hasMinimalScoreReportShape(report: Record<string, unknown>): boolean {
  const summary = asRecord(report.summary);
  const alerts = Array.isArray(report.alerts) ? report.alerts : [];
  const clusters = Array.isArray(report.clusters) ? report.clusters : [];
  const timeline = Array.isArray(report.timeline) ? report.timeline : [];

  return (
    summary !== null ||
    alerts.length > 0 ||
    clusters.length > 0 ||
    timeline.length > 0
  );
}

function readCompatiblePcapReportSnapshot(
  jobId: string,
  job: RawPcapJobHistoryItem,
  payload?: Record<string, unknown>
): Record<string, unknown> | null {
  const snapshot = readPcapReportSnapshotEntry(jobId);
  if (!snapshot || snapshot.jobId !== jobId) {
    return null;
  }

  if (!hasMinimalScoreReportShape(snapshot.report)) {
    return null;
  }

  const generatedAt = getReportGeneratedAt(snapshot.report);
  const snapshotUpdatedAt = parseTimestampEpoch(snapshot.updatedAt);
  const createdAt = parseTimestampEpoch(payload?.created_at ?? job.created_at);
  const startedAt = parseTimestampEpoch(payload?.started_at ?? job.started_at);
  const finishedAt = parseTimestampEpoch(payload?.finished_at ?? job.finished_at);
  const earliestExpectedAt = startedAt || createdAt;

  // Require at least one trustworthy timestamp inside the snapshot report so we
  // can reject stale cached data instead of silently scoring old content.
  if (!generatedAt) {
    return null;
  }

  if (earliestExpectedAt > 0) {
    const allowedSkewMs = 5 * 60 * 1000;
    if (generatedAt + allowedSkewMs < earliestExpectedAt) {
      return null;
    }

    if (snapshotUpdatedAt > 0 && snapshotUpdatedAt + allowedSkewMs < earliestExpectedAt) {
      return null;
    }
  }

  if (finishedAt > 0) {
    const maxPostFinishWindowMs = 30 * 60 * 1000;
    if (generatedAt > finishedAt + maxPostFinishWindowMs) {
      return null;
    }
  }

  const expectedUploadName = basename(
    payload?.original_filename ??
      payload?.upload_name ??
      job.original_filename ??
      job.upload_name
  );
  const reportUploadName = basename(asRecord(snapshot.report.meta)?.pcap_path);
  if (
    expectedUploadName &&
    reportUploadName &&
    expectedUploadName !== reportUploadName
  ) {
    return null;
  }

  return snapshot.report;
}

export function calculatePcapFileScore(
  report: Record<string, unknown>
): {
  score: number;
  breakdown: PcapScoreBreakdown;
} {
  const totalFlows = Math.max(0, getTotalFlows(report));
  const benignFlows = getBenignFlows(report, totalFlows);
  const validatedThreats = extractThreatCandidates(report).filter(
    (candidate) => !isThreatRejected(candidate)
  );

  const trafficCleanliness = clamp(
    (benignFlows / Math.max(totalFlows, 1)) * 100,
    0,
    100
  );

  const severityPenalty = calculateSeverityPenalty(validatedThreats);
  const threatSafety = clamp(100 - severityPenalty, 0, 100);

  const confirmedThreatCount = validatedThreats.filter(
    (candidate) => candidate.confidence >= 0.8
  ).length;
  const highConfidenceThreatCount = validatedThreats.filter(
    (candidate) => candidate.confidence >= 0.9
  ).length;
  const stabilityPenalty = Math.min(
    40,
    confirmedThreatCount * 4 + highConfidenceThreatCount * 2
  );
  const detectionStability = clamp(100 - stabilityPenalty, 0, 100);

  const repeatedPenalty = clamp(
    Array.from(
      validatedThreats.reduce((counts, candidate) => {
        const key = candidate.label.toLowerCase();
        counts.set(key, (counts.get(key) || 0) + 1);
        return counts;
      }, new Map<string, number>())
    ).reduce((sum, [, count]) => {
      if (count >= 10) {
        return sum + 10;
      }
      if (count >= 5) {
        return sum + 5;
      }
      return sum;
    }, 0),
    0,
    20
  );

  const rawScore =
    0.5 * trafficCleanliness +
    0.3 * threatSafety +
    0.2 * detectionStability -
    repeatedPenalty;
  const score = roundToTenths(clamp(rawScore, 0, 100));

  return {
    score,
    breakdown: {
      trafficCleanliness: roundToTenths(trafficCleanliness),
      threatSafety: roundToTenths(threatSafety),
      detectionStability: roundToTenths(detectionStability),
      repeatedAttackPenalty: roundToTenths(repeatedPenalty),
      totalFlows,
      benignFlows,
      validatedThreatCount: validatedThreats.length,
      confirmedThreatCount,
      highConfidenceThreatCount,
    },
  };
}

function normalizedWeights(count: number): number[] {
  const base = RECENCY_WEIGHTS.slice(0, Math.max(0, count));
  const total = base.reduce((sum, weight) => sum + weight, 0);
  if (total <= 0) {
    return [];
  }

  return base.map((weight) => weight / total);
}

export function calculateWeightedNetworkSecurityScore(
  analyses: Array<{ score: number }>
): number | null {
  if (analyses.length === 0) {
    return null;
  }

  const weights = normalizedWeights(analyses.length);
  const value = analyses.reduce((sum, analysis, index) => {
    return sum + analysis.score * (weights[index] ?? 0);
  }, 0);

  return roundToTenths(clamp(value, 0, 100));
}

export function networkSecurityScoreRating(
  score: number | null
): NetworkSecurityScoreRating | null {
  if (score == null) {
    return null;
  }
  if (score >= 90) return "Excellent";
  if (score >= 75) return "Good";
  if (score >= 60) return "Moderate";
  if (score >= 40) return "Risky";
  return "Critical";
}

export function networkSecurityScoreTone(score: number | null): ScoreTone {
  const rating = networkSecurityScoreRating(score);
  if (rating === "Excellent") return "emerald";
  if (rating === "Good") return "sky";
  if (rating === "Moderate") return "amber";
  if (rating === "Risky") return "orange";
  if (rating === "Critical") return "rose";
  return "slate";
}

function buildEmptySummary(): NetworkSecurityScoreSummary {
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

async function fetchRecentSuccessfulJobHistory(): Promise<{
  base: string;
  jobs: RawPcapJobHistoryItem[];
}> {
  let lastError: unknown = null;
  let sawInvalidHtmlResponse = false;

  // Use the recent job history as the source of truth for recency ordering.
  for (const base of API_BASE_CANDIDATES) {
    for (const path of JOB_HISTORY_PATH_CANDIDATES) {
      try {
        const response = await fetchWithPcapAuth(
          buildApiUrl(`${path}?limit=${JOB_HISTORY_FETCH_LIMIT}`, base),
          {
            cache: "no-store",
          }
        );
        const contentType = String(
          response.headers.get("content-type") || ""
        ).toLowerCase();

        if (contentType.includes("text/html")) {
          sawInvalidHtmlResponse = true;
          continue;
        }

        if (response.status === 404) {
          continue;
        }

        const payload = await readJsonResponse(
          response,
          "PCAP job history endpoint returned an invalid response."
        );

        if (!response.ok) {
          throw new Error(
            text(payload.error) ||
              text(payload.message) ||
              "Failed to load recent PCAP job history."
          );
        }

        const jobs = asRecordArray(payload.jobs) as RawPcapJobHistoryItem[];
        return {
          base,
          jobs: selectLatestSuccessfulPcapAnalyses(jobs, 10),
        };
      } catch (error) {
        lastError = error;
      }
    }
  }

  if (sawInvalidHtmlResponse) {
    throw new Error(
      "PCAP job history endpoint returned an invalid response. Verify the backend or dev proxy."
    );
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("Failed to load recent PCAP job history.");
}

async function fetchJobReport(
  job: RawPcapJobHistoryItem,
  base: string
): Promise<PcapAnalysisScore | null> {
  const jobId = text(job.job_id);
  if (!jobId) {
    return null;
  }

  try {
    const response = await fetchWithPcapAuth(
      buildApiUrl(buildJobStatusPath(jobId), base),
      {
        cache: "no-store",
      }
    );
    const contentType = String(
      response.headers.get("content-type") || ""
    ).toLowerCase();

    if (!contentType.includes("text/html")) {
      const payload = await readJsonResponse(
        response,
        "PCAP job details endpoint returned an invalid response."
      );

      if (response.ok) {
        const inlineReport = asRecord(payload.report);
        const cachedReport =
          inlineReport == null
            ? readCompatiblePcapReportSnapshot(jobId, job, payload)
            : null;
        const report = inlineReport ?? cachedReport;

        if (report) {
          const scoreResult = calculatePcapFileScore(report);
          return {
            jobId,
            score: scoreResult.score,
            completedAt:
              text(payload.finished_at) ||
              text(job.finished_at) ||
              text(payload.created_at) ||
              text(job.created_at) ||
              null,
            uploadName:
              text(payload.original_filename) ||
              text(payload.upload_name) ||
              text(job.original_filename) ||
              text(job.upload_name) ||
              "",
            breakdown: scoreResult.breakdown,
          };
        }
      }
    }
  } catch {
    // Fall back to cached snapshots below.
  }

  // Archived runs may not inline their report payload, but only use a snapshot
  // when it can be corroborated against the current job metadata.
  const cachedReport = readCompatiblePcapReportSnapshot(jobId, job);
  if (!cachedReport) {
    return null;
  }

  const scoreResult = calculatePcapFileScore(cachedReport);
  return {
    jobId,
    score: scoreResult.score,
    completedAt: text(job.finished_at) || text(job.created_at) || null,
    uploadName: text(job.original_filename) || text(job.upload_name),
    breakdown: scoreResult.breakdown,
  };
}

export async function loadNetworkSecurityScoreSummary(): Promise<NetworkSecurityScoreSummary> {
  const { base, jobs } = await fetchRecentSuccessfulJobHistory();
  if (jobs.length === 0) {
    return buildEmptySummary();
  }

  const analyses = (
    await Promise.all(jobs.map((job) => fetchJobReport(job, base)))
  ).filter((item): item is PcapAnalysisScore => item !== null);

  if (analyses.length === 0) {
    return buildEmptySummary();
  }

  const currentWindow = analyses.slice(0, 5);
  const previousWindow = analyses.slice(5, 10);
  const finalScore = calculateWeightedNetworkSecurityScore(currentWindow);
  const previousScore = calculateWeightedNetworkSecurityScore(previousWindow);

  return {
    finalScore,
    rating: networkSecurityScoreRating(finalScore),
    filesUsed: currentWindow.length,
    latestCompletedAt: currentWindow[0]?.completedAt ?? null,
    trendDelta:
      finalScore != null && previousScore != null
        ? roundToTenths(finalScore - previousScore)
        : null,
    tone: networkSecurityScoreTone(finalScore),
    analyses: currentWindow,
  };
}
