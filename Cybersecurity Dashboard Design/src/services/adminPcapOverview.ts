export type PcapRiskLevel = "low" | "medium" | "high" | "critical" | "unknown";
export type PcapQueueHealthState = "healthy" | "warning" | "critical" | "unknown";
export type PcapAnalysisMode = "ML Only" | "Hybrid Logic" | "Heuristics Only" | "Unknown";
export type PcapZeekUsed = "yes" | "no" | "unknown";

export interface AdminPcapSummary {
  total_uploaded_files: number;
  total_jobs: number;
  queued_jobs: number;
  running_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  average_processing_time_seconds: number | null;
  last_analysis_time: string | null;
}

export interface AdminPcapQueueHealth {
  status: PcapQueueHealthState;
  message: string;
  latest_job_status: string;
}

export interface AdminPcapAttackFamily {
  family: string;
  count: number;
  severity: string | null;
  source: "ML" | "Heuristic" | "Hybrid" | "Unknown";
}

export interface AdminPcapJob {
  job_id: string;
  filename: string;
  status: string;
  score: number | null;
  risk_level: PcapRiskLevel;
  detected_family: string;
  analysis_mode: PcapAnalysisMode;
  zeek_used: PcapZeekUsed;
  processing_time_seconds: number | null;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  report_available: boolean;
  evidence_available: boolean;
  timeline_available: boolean;
  threat_detected: boolean;
}

export interface AdminPcapPerformance {
  average_processing_time_seconds: number | null;
  fastest_processing_time_seconds: number | null;
  slowest_processing_time_seconds: number | null;
  processed_files: number;
  failed_processing_rate: number | null;
}

export interface AdminPcapEngineStatus {
  zeek_used: PcapZeekUsed;
  analysis_mode: PcapAnalysisMode;
  model_version: string | null;
  feature_contract_status: string | null;
  report_evidence_availability: string | null;
  last_successful_analysis: string | null;
}

export interface AdminPcapTimelineEvent {
  job_id: string;
  filename: string;
  label: string;
  timestamp: string | null;
  status: string;
  detail: string;
}

export interface AdminPcapOverview {
  summary: AdminPcapSummary;
  queue_health: AdminPcapQueueHealth;
  latest_attack_families: AdminPcapAttackFamily[];
  top_suspicious_files: AdminPcapJob[];
  latest_files: AdminPcapJob[];
  performance: AdminPcapPerformance;
  engine_status: AdminPcapEngineStatus;
  timeline: AdminPcapTimelineEvent[];
  generated_at: string | null;
}

const DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:5000";

function normalizeApiBase(value: string): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) return "";

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

export const ADMIN_PCAP_API_BASE = (() => {
  const envBase = normalizeApiBase(String(import.meta.env.VITE_API_BASE_URL || ""));
  if (import.meta.env.DEV) return "";
  if (envBase) return envBase;
  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      return `${window.location.protocol}//${host}:5000`;
    }
  }
  return DEFAULT_LOCAL_API_BASE;
})();

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown, fallback = ""): string {
  const normalized = String(value ?? "").trim();
  return normalized || fallback;
}

function numberOrNull(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function stringOrNull(value: unknown): string | null {
  const normalized = text(value);
  return normalized || null;
}

function boolValue(value: unknown): boolean {
  return value === true || value === "true" || value === 1 || value === "1";
}

function clampScore(value: number | null): number | null {
  if (value === null) return null;
  return Math.max(0, Math.min(100, Number(value.toFixed(1))));
}

function normalizeQueueHealth(value: unknown): PcapQueueHealthState {
  const normalized = text(value).toLowerCase();
  if (normalized === "healthy") return "healthy";
  if (normalized === "warning") return "warning";
  if (normalized === "critical") return "critical";
  return "unknown";
}

function normalizeRiskLevel(value: unknown): PcapRiskLevel {
  const normalized = text(value).toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "medium") return "medium";
  if (normalized === "low" || normalized === "normal" || normalized === "safe") {
    return "low";
  }
  return "unknown";
}

function normalizeAnalysisMode(value: unknown): PcapAnalysisMode {
  const normalized = text(value).toLowerCase();
  if (normalized === "hybrid logic" || normalized === "hybrid") return "Hybrid Logic";
  if (normalized === "ml only" || normalized === "ml") return "ML Only";
  if (normalized === "heuristics only" || normalized === "heuristic") {
    return "Heuristics Only";
  }
  return "Unknown";
}

function normalizeZeekUsed(value: unknown): PcapZeekUsed {
  if (value === true) return "yes";
  if (value === false) return "no";
  const normalized = text(value).toLowerCase();
  if (["yes", "true", "used", "enabled"].includes(normalized)) return "yes";
  if (["no", "false", "not used", "disabled"].includes(normalized)) return "no";
  return "unknown";
}

function normalizeDetectionSource(value: unknown): "ML" | "Heuristic" | "Hybrid" | "Unknown" {
  const normalized = text(value).toLowerCase();
  if (normalized === "ml") return "ML";
  if (normalized === "heuristic" || normalized === "heuristics") return "Heuristic";
  if (normalized === "hybrid") return "Hybrid";
  return "Unknown";
}

export function getRiskLevelFromScore(
  score: number | null | undefined,
  providedLevel?: unknown
): PcapRiskLevel {
  const normalized = normalizeRiskLevel(providedLevel);
  if (normalized !== "unknown") return normalized;
  if (score === null || score === undefined || !Number.isFinite(Number(score))) {
    return "unknown";
  }
  const numeric = Number(score);
  if (numeric >= 85) return "critical";
  if (numeric >= 70) return "high";
  if (numeric >= 40) return "medium";
  return "low";
}

export function getRiskBadgeClass(level: PcapRiskLevel): string {
  switch (level) {
    case "critical":
      return "border-red-200 bg-red-50 text-red-700";
    case "high":
      return "border-orange-200 bg-orange-50 text-orange-700";
    case "medium":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "low":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    default:
      return "border-slate-200 bg-slate-50 text-slate-500";
  }
}

export function getQueueHealthState(
  overviewOrHealth: Partial<AdminPcapOverview> | Partial<AdminPcapQueueHealth>
): AdminPcapQueueHealth {
  const maybeOverview = overviewOrHealth as Partial<AdminPcapOverview>;
  const health = (maybeOverview.queue_health ||
    overviewOrHealth) as Partial<AdminPcapQueueHealth>;

  const status = normalizeQueueHealth(health.status);
  return {
    status,
    message:
      text(health.message) ||
      (status === "healthy"
        ? "Queue looks healthy."
        : status === "unknown"
          ? "Queue status is not available."
          : "Queue needs attention."),
    latest_job_status: text(health.latest_job_status, "unknown"),
  };
}

export function formatProcessingTime(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    return "Not available";
  }

  const totalSeconds = Math.max(0, Math.round(Number(value)));
  if (totalSeconds < 60) return `${totalSeconds}s`;

  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes < 60) return seconds ? `${minutes}m ${seconds}s` : `${minutes}m`;

  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes ? `${hours}h ${remainingMinutes}m` : `${hours}h`;
}

export function formatAdminPcapTime(value: string | null | undefined): string {
  if (!value) return "Not available";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "Not available";
  return parsed.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function normalizePcapJob(value: unknown): AdminPcapJob {
  const raw = asRecord(value);
  const score = clampScore(numberOrNull(raw.score ?? raw.risk_score));
  const riskLevel = getRiskLevelFromScore(score, raw.risk_level);

  return {
    job_id: text(raw.job_id),
    filename: text(raw.filename ?? raw.original_filename ?? raw.upload_name, "Not available"),
    status: text(raw.status, "unknown"),
    score,
    risk_level: riskLevel,
    detected_family: text(raw.detected_family, "Unknown / Not classified"),
    analysis_mode: normalizeAnalysisMode(raw.analysis_mode),
    zeek_used: normalizeZeekUsed(raw.zeek_used),
    processing_time_seconds: numberOrNull(raw.processing_time_seconds),
    created_at: stringOrNull(raw.created_at),
    started_at: stringOrNull(raw.started_at),
    finished_at: stringOrNull(raw.finished_at),
    report_available: boolValue(raw.report_available),
    evidence_available: boolValue(raw.evidence_available),
    timeline_available: boolValue(raw.timeline_available),
    threat_detected: boolValue(raw.threat_detected),
  };
}

function normalizeSummary(value: unknown): AdminPcapSummary {
  const raw = asRecord(value);
  return {
    total_uploaded_files: numberOrNull(raw.total_uploaded_files) ?? 0,
    total_jobs: numberOrNull(raw.total_jobs) ?? 0,
    queued_jobs: numberOrNull(raw.queued_jobs) ?? 0,
    running_jobs: numberOrNull(raw.running_jobs) ?? 0,
    completed_jobs: numberOrNull(raw.completed_jobs) ?? 0,
    failed_jobs: numberOrNull(raw.failed_jobs) ?? 0,
    average_processing_time_seconds: numberOrNull(raw.average_processing_time_seconds),
    last_analysis_time: stringOrNull(raw.last_analysis_time),
  };
}

function normalizeAttackFamily(value: unknown): AdminPcapAttackFamily {
  const raw = asRecord(value);
  return {
    family: text(raw.family, "Unknown / Not classified"),
    count: numberOrNull(raw.count) ?? 0,
    severity: stringOrNull(raw.severity),
    source: normalizeDetectionSource(raw.source),
  };
}

function normalizePerformance(value: unknown): AdminPcapPerformance {
  const raw = asRecord(value);
  return {
    average_processing_time_seconds: numberOrNull(raw.average_processing_time_seconds),
    fastest_processing_time_seconds: numberOrNull(raw.fastest_processing_time_seconds),
    slowest_processing_time_seconds: numberOrNull(raw.slowest_processing_time_seconds),
    processed_files: numberOrNull(raw.processed_files) ?? 0,
    failed_processing_rate: numberOrNull(raw.failed_processing_rate),
  };
}

function normalizeEngineStatus(value: unknown): AdminPcapEngineStatus {
  const raw = asRecord(value);
  return {
    zeek_used: normalizeZeekUsed(raw.zeek_used),
    analysis_mode: normalizeAnalysisMode(raw.analysis_mode),
    model_version: stringOrNull(raw.model_version),
    feature_contract_status: stringOrNull(raw.feature_contract_status),
    report_evidence_availability: stringOrNull(raw.report_evidence_availability),
    last_successful_analysis: stringOrNull(raw.last_successful_analysis),
  };
}

function normalizeTimelineEvent(value: unknown): AdminPcapTimelineEvent {
  const raw = asRecord(value);
  return {
    job_id: text(raw.job_id),
    filename: text(raw.filename, "Not available"),
    label: text(raw.label, "PCAP workflow event"),
    timestamp: stringOrNull(raw.timestamp),
    status: text(raw.status, "info"),
    detail: text(raw.detail, "No additional details available."),
  };
}

export function emptyAdminPcapOverview(): AdminPcapOverview {
  return {
    summary: {
      total_uploaded_files: 0,
      total_jobs: 0,
      queued_jobs: 0,
      running_jobs: 0,
      completed_jobs: 0,
      failed_jobs: 0,
      average_processing_time_seconds: null,
      last_analysis_time: null,
    },
    queue_health: {
      status: "unknown",
      message: "No PCAP job activity is available yet.",
      latest_job_status: "unknown",
    },
    latest_attack_families: [],
    top_suspicious_files: [],
    latest_files: [],
    performance: {
      average_processing_time_seconds: null,
      fastest_processing_time_seconds: null,
      slowest_processing_time_seconds: null,
      processed_files: 0,
      failed_processing_rate: 0,
    },
    engine_status: {
      zeek_used: "unknown",
      analysis_mode: "Unknown",
      model_version: null,
      feature_contract_status: null,
      report_evidence_availability: null,
      last_successful_analysis: null,
    },
    timeline: [],
    generated_at: null,
  };
}

export function normalizeAdminPcapOverview(value: unknown): AdminPcapOverview {
  const raw = asRecord(value);
  return {
    summary: normalizeSummary(raw.summary),
    queue_health: getQueueHealthState(asRecord(raw.queue_health)),
    latest_attack_families: asArray(raw.latest_attack_families).map(normalizeAttackFamily),
    top_suspicious_files: asArray(raw.top_suspicious_files).map(normalizePcapJob),
    latest_files: asArray(raw.latest_files).map(normalizePcapJob),
    performance: normalizePerformance(raw.performance),
    engine_status: normalizeEngineStatus(raw.engine_status),
    timeline: asArray(raw.timeline).map(normalizeTimelineEvent),
    generated_at: stringOrNull(raw.generated_at),
  };
}

function buildAdminFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.set("Accept", "application/json");

  if (typeof window !== "undefined") {
    const token = window.localStorage.getItem("sentinel_admin_token");
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }

  return {
    ...init,
    credentials: "include",
    headers,
  };
}

function getApiErrorMessage(payload: unknown, fallback: string): string {
  const raw = asRecord(payload);
  return text(raw.message ?? raw.error ?? raw.detail, fallback);
}

export async function loadAdminPcapOverview(): Promise<AdminPcapOverview> {
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/pcap/overview`,
    buildAdminFetchInit({ cache: "no-store" })
  );

  const bodyText = await response.text();
  let payload: unknown = {};
  if (bodyText) {
    try {
      payload = JSON.parse(bodyText);
    } catch {
      throw new Error("PCAP admin overview returned invalid JSON.");
    }
  }

  if (!response.ok) {
    const fallback =
      response.status === 404 || response.status === 405
        ? "PCAP admin overview endpoint is not available."
        : "Failed to load PCAP admin overview.";
    throw new Error(getApiErrorMessage(payload, fallback));
  }

  return normalizeAdminPcapOverview(payload);
}

export function getDownloadFilename(
  contentDisposition: string | null,
  fallback: string
): string {
  if (!contentDisposition) return fallback;

  const utfMatch = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utfMatch?.[1]) {
    try {
      return decodeURIComponent(utfMatch[1].replace(/"/g, ""));
    } catch {
      return utfMatch[1].replace(/"/g, "") || fallback;
    }
  }

  const plainMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
  return plainMatch?.[1] || fallback;
}

export function buildPcapArtifactFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);

  if (typeof window !== "undefined") {
    const token = window.localStorage.getItem("sentinel_admin_token");
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }

  return {
    ...init,
    credentials: "include",
    headers,
  };
}

export function getPcapJobExportUrl(jobId: string, type: "report" | "evidence"): string {
  return `${ADMIN_PCAP_API_BASE}/api/admin/pcap/jobs/${encodeURIComponent(jobId)}/export?type=${type}`;
}
