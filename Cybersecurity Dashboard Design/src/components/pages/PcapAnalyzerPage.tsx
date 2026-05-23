import React, { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { motion } from "motion/react";
import { useSearchParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { Badge } from "../ui/badge";
import { Progress } from "../ui/progress";
import { Input } from "../ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { ScrollArea } from "../ui/scroll-area";
import { Separator } from "../ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import {
  FileSearch,
  Activity,
  AlertTriangle,
  Shield,
  Search,
  History,
  Play,
  Settings2,
  Fingerprint,
  Layers,
  Network,
  XCircle,
  TimerReset,
  FileJson,
  Archive,
  FileCode2,
  Route,
  Eye,
  RefreshCw,
  Filter,
  ChevronRight,
  ShieldCheck,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { playSuccessSound, playCriticalSound, playErrorSound } from "../../utils/soundNotifications";
import { SecurityScoreCard } from "../security/SecurityScoreCard";
import { SeverityBreakdownCard } from "../security/SeverityBreakdownCard";
import { ThreatBreakdownCard } from "../security/ThreatBreakdownCard";
import { ThreatActivityAreaChart } from "../security/ThreatActivityAreaChart";
import { ChartEmptyState } from "../security/ChartEmptyState";
import { RiskPerIpCard, type RiskPerIpRow } from "../security/RiskPerIpCard";
import {
  calculateSecurityScore,
  type SecurityScoreSeverity,
  type SecurityScoreThreatInput,
} from "../../utils/securityScore";
import {
  buildSeverityBreakdownData,
  buildThreatTimelineData,
  buildTopAttackTypeData,
} from "../../utils/pcapChartSelectors";
import {
  broadcastRecentPcapAlertsUpdated,
  buildDashboardAlertsFromReport,
  type DashboardPcapAlert,
  persistRecentPcapAlertCache,
  persistPcapReportSnapshot,
  readRecentPcapAlertCache,
  readPcapReportSnapshot,
} from "../../utils/recentPcapAlerts";
import {
  broadcastGamificationUpdated,
  recordGamificationEvent,
  showGamificationToasts,
  type GamificationEventResponse,
} from "../../utils/gamification";
import { trackActivityEvent } from "../../utils/activityLogs";
import { useLanguage } from "../../contexts/LanguageContext";
/** ================== API (MATCHES YOUR FLASK ROUTES) ================== **/
const DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:5000";

function normalizeApiBase(raw: string) {
  const trimmed = String(raw || "").trim().replace(/\/$/, "");
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

const API_BASE = (() => {
  const envBase = normalizeApiBase(
    String(import.meta.env.VITE_API_BASE_URL || "")
  );
  if (import.meta.env.DEV) {
    return "";
  }
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

const API = {
  PCAP_UPLOAD: `${API_BASE}/analyze-pcap`,
  JOB_HISTORY: (limit = 50) => `${API_BASE}/jobs?limit=${limit}`,
  JOB_POLL: (id: string) => `${API_BASE}/job/${id}`,
  JOB_CANCEL: (id: string) => `${API_BASE}/api/pcap/cancel/${id}`,
  JOB_EXPORT: (id: string, type: "report" | "evidence") =>
    `${API_BASE}/job/${id}/export?type=${type}`,
};

function buildAuthedFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("sentinel_auth_token");
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

/** ================== Types ================== **/
type JobStep =
  | "Queued"
  | "Parsing"
  | "Flow Extraction"
  | "Heuristics"
  | "ML Inference"
  | "Validation"
  | "Zeek Evidence"
  | "Clustering"
  | "Report Ready"
  | "Failed"
  | "Cancelled";

type Decision = "CONFIRMED" | "SUSPICIOUS" | "IGNORED" | "DROPPED";
type Severity = "INFO" | "MEDIUM" | "HIGH" | "CRITICAL";
type ConfidenceMode = "Strict" | "Balanced" | "Relaxed";
type ExportType = "report" | "evidence";
type RawRecord = Record<string, unknown>;

interface ClusterPortCount {
  port: number;
  count: number;
}

interface ClusterDestinationCount {
  ip: string;
  count: number;
}

interface PcapJob {
  job_id: string;
  status: "queued" | "running" | "done" | "failed" | "cancelled";
  progress: number;
  current_step: JobStep;
  message?: string;
  started_at?: string;
  duration_s?: number;
  error?: string;
  report_available?: boolean;
  evidence_available?: boolean;
  artifact_protection?: ArtifactProtectionMetadata | null;
}

interface AttackCluster {
  id: string;
  severity: Severity;
  attack_type: string;
  source_ip: string;
  dest_ip: string;
  count_flows: number;
  max_threat_confidence: number;
  max_ml_confidence: number;
  top_dst_ports: ClusterPortCount[];
  top_dst_ips: ClusterDestinationCount[];
  raw: RawRecord;
}

interface AlertHeuristic {
  type: string;
  score: number;
  reason: string;
}

interface AlertZeekBytes {
  orig: number;
  resp: number;
}

interface AlertRow {
  id: string;
  time: string;
  source_ip: string;
  dest_ip: string;
  dst_port: number;
  label: string;
  threat_confidence: number;
  severity: Severity;
  decision: Decision;
  reason: string;
  validated?: boolean;
  evidence_refs?: string[];
  ml_label: string;
  ml_confidence: number;
  zeek_service: string;
  zeek_conn_state: string;
  zeek_proto: string;
  zeek_duration: number;
  zeek_bytes: AlertZeekBytes;
  dns_top_query: string;
  dns_query_count: number;
  http_top_host: string;
  http_top_uri: string;
  http_request_count: number;
  ssl_top_sni: string;
  ssl_event_count: number;
  heuristic: AlertHeuristic;
  raw: RawRecord;
}

interface TimelineRow {
  id: string;
  time: string;
  source_ip: string;
  dest_ip: string;
  dst_port: number;
  label: string;
  threat_confidence: number;
  severity: Severity;
  verdict: Decision;
}

interface EvidenceItem {
  id: string;
  kind: "DNS" | "HTTP" | "TLS" | "ZEEK";
  title: string;
  details: string;
  related_flows?: string[];
}

interface AssetRow {
  ip: string;
  mac?: string;
  vendor?: string;
  first_seen?: string;
  last_seen?: string;
}

interface PcapReport {
  meta?: {
    pipeline?: {
      confidence_mode?: string;
      analysis_mode?: string;
    };
    artifact_protection?: ArtifactProtectionMetadata | null;
  };
  summary: {
    total_flows: number;
    alerts: number;
    suspicious: number;
    suppressed: number;
    overall_risk: number;
    risk_level: "Normal" | "Low" | "Medium" | "High" | "Critical";
    risk_context_label?: string;
    risk_display?: string;
    security_score?: number;
    score_explanation?: {
      base_score?: number;
      risk_contributors?: Array<{
        label?: string;
        impact?: number;
        details?: string;
      }>;
      final_score?: number;
    } | null;
    security_score_level?: "Secure" | "Warning" | "Risky" | "Critical";
    summary?: string;
    security_summary?: string;
    security_trend?: string;
    cluster_count?: number;
    severity_counts?: Partial<Record<SecurityScoreSeverity, number>>;
    top_risk?: {
      name?: string;
      severity?: string;
      confidence?: number;
      count?: number;
      impact?: number;
    } | null;
  };
  clusters: AttackCluster[];
  alerts: AlertRow[];
  timeline: TimelineRow[];
  risk_per_ip?: RiskPerIpRow[];
  evidence?: EvidenceItem[];
  assets?: AssetRow[];
}

type DetailsTarget =
  | { kind: "alert"; alert: AlertRow }
  | { kind: "cluster"; cluster: AttackCluster; relatedAlert?: AlertRow | null };

type JobHistoryItem = {
  job_id: string;
  status?: string;
  created_at?: string;
  started_at?: string;
  finished_at?: string;
  progress?: number;
  message?: string;
  upload_name?: string;
  original_filename?: string;
  has_upload?: boolean;
  has_report?: boolean;
  report_available?: boolean;
  evidence_available?: boolean;
  artifact_protection?: ArtifactProtectionMetadata | null;
};

type ArtifactProtectionMetadata = {
  enabled?: boolean;
  mode?: string;
  protected_at?: string;
};

type ExportableJobRef = {
  job_id: string;
  status: PcapJob["status"];
  report_available: boolean;
  evidence_available: boolean;
};

/** ================== Helpers ================== **/
function normalizeArtifactProtection(
  raw: unknown
): ArtifactProtectionMetadata | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const value = raw as Record<string, unknown>;
  return {
    enabled: value.enabled === true,
    mode: value.mode != null ? String(value.mode) : undefined,
    protected_at:
      value.protected_at != null ? String(value.protected_at) : undefined,
  };
}

function cx(...xs: Array<string | false | undefined | null>) {
  return xs.filter(Boolean).join(" ");
}

function fmtPct(x: number | undefined | null) {
  if (x == null || Number.isNaN(x)) return "—";
  const v = x > 1 ? x : x * 100;
  return `${Math.round(v)}%`;
}

function fmtScore(x: number | undefined | null, digits = 2) {
  if (x == null || Number.isNaN(x)) return "—";
  return Number(x).toFixed(digits);
}

function fmtBytes(x: number | undefined | null) {
  if (x == null || Number.isNaN(x) || x <= 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Number(x);
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const digits = value >= 100 || unitIndex === 0 ? 0 : 1;
  return `${value.toFixed(digits)} ${units[unitIndex]}`;
}

const PCAP_MAX_UPLOAD_BYTES = 15 * 1024 * 1024 * 1024;
const PCAP_MAX_UPLOAD_LABEL = fmtBytes(PCAP_MAX_UPLOAD_BYTES);

function fmtTime(s: string | number | undefined | null) {
  if (s == null || s === "") return "—";
  try {
    const raw = String(s).trim();
    let d: Date;
    if (typeof s === "number" || /^-?\d+(\.\d+)?$/.test(raw)) {
      const num = typeof s === "number" ? s : Number(raw);
      d = new Date(num > 1e10 ? num : num * 1000);
    } else {
      d = new Date(raw);
    }
    if (!isNaN(d.getTime())) return d.toLocaleString();
  } catch {}
  return String(s);
}

function formatCompactNumber(value: number | undefined | null) {
  const numeric = Number(value ?? 0);
  if (!Number.isFinite(numeric)) {
    return "0";
  }
  return new Intl.NumberFormat().format(Math.round(numeric));
}

function formatCountLabel(value: number, singular: string, plural?: string) {
  const noun = value === 1 ? singular : plural ?? `${singular}s`;
  return `${formatCompactNumber(value)} ${noun}`;
}

type DashboardTone = "sky" | "emerald" | "amber" | "orange" | "rose" | "slate";

function dashboardToneClasses(tone: DashboardTone) {
  const key =
    tone === "sky"
      ? "sky"
      : tone === "emerald"
      ? "emerald"
      : tone === "amber"
      ? "amber"
      : tone === "orange"
      ? "orange"
      : tone === "rose"
      ? "rose"
      : "slate";

  return {
    border: `tone-${key}-border`,
    bg: "",
    value: `tone-${key}-value`,
    iconWrap: `tone-${key}-icon`,
    chip: `tone-${key}-chip`,
    shadow: "",
    glow: `tone-${key}-glow`,
    spotlight: `tone-${key}-spotlight`,
  };
}

function toneFromRiskLevel(
  level: PcapReport["summary"]["risk_level"] | null | undefined
): DashboardTone {
  if (level === "Critical") return "rose";
  if (level === "High") return "orange";
  if (level === "Medium") return "amber";
  if (level === "Low") return "sky";
  return "emerald";
}

function toneFromSeverityValue(value: string | null | undefined): DashboardTone {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (normalized === "critical") return "rose";
  if (normalized === "high") return "orange";
  if (normalized === "medium") return "amber";
  if (normalized === "low") return "sky";
  if (
    normalized === "info" ||
    normalized === "informational" ||
    normalized === "benign" ||
    normalized === "normal" ||
    normalized === "safe"
  ) {
    return "emerald";
  }
  return "slate";
}

function InsightStatCard({
  label,
  value,
  detail,
  tone = "slate",
  className,
}: {
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
  tone?: DashboardTone;
  className?: string;
}) {
  const toneClasses = dashboardToneClasses(tone);

  return (
    <div
      className={cx(
        "cyber-card cyber-glow-border group relative overflow-hidden rounded-3xl border px-4 py-4 shadow-lg",
        toneClasses.border,
        className
      )}
    >
      <div
        className={cx("pointer-events-none absolute inset-0 opacity-90", toneClasses.spotlight)}
        aria-hidden="true"
      />
      <div className={cx("pointer-events-none absolute inset-x-0 top-0 h-px opacity-80", toneClasses.glow)} />
      <div className="text-xs font-semibold uppercase tracking-widest text-gray-400">
        {label}
      </div>
      <div className={cx("mt-3 text-lg font-semibold leading-snug", toneClasses.value)}>
        {value}
      </div>
      {detail ? (
        <div className="mt-2 text-sm leading-relaxed text-gray-300">{detail}</div>
      ) : null}
    </div>
  );
}

function getDownloadFilename(
  contentDisposition: string | null,
  fallback: string
): string {
  if (!contentDisposition) return fallback;

  const utf8Match = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {}
  }

  const plainMatch = contentDisposition.match(/filename="?([^"]+)"?/i);
  return plainMatch?.[1] ?? fallback;
}

function getApiErrorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== "object") return fallback;
  const record = payload as Record<string, unknown>;
  const message = record.error ?? record.message;
  return typeof message === "string" && message.trim() ? message : fallback;
}

function normalizeJobStatusValue(raw: unknown): PcapJob["status"] {
  const value = String(raw ?? "").trim().toLowerCase();
  if (value === "done") return "done";
  if (value === "running") return "running";
  if (value === "cancelled" || value === "canceled") return "cancelled";
  if (value === "failed" || value === "error") return "failed";
  return "queued";
}

function hasText(value: unknown) {
  return typeof value === "string" ? value.trim().length > 0 : false;
}

function hasPositive(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

function getPcapUploadValidationError(file: File | null): string | null {
  if (!file) {
    return "No file selected. Please upload a PCAP file before analysis.";
  }

  if (file.size > PCAP_MAX_UPLOAD_BYTES) {
    return `PCAP files must be ${PCAP_MAX_UPLOAD_LABEL} or smaller. Choose a smaller capture before starting analysis.`;
  }

  const fileName = String(file.name || "").trim().toLowerCase();
  if (!fileName.endsWith(".pcap") && !fileName.endsWith(".pcapng")) {
    return "Invalid file type. Please upload a .pcap or .pcapng file.";
  }

  return null;
}

function tryParseJsonObject(text: string): Record<string, unknown> | null {
  const trimmed = String(text || "").trim();
  if (!trimmed) return null;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

const TABLE_ROW_OPTIONS = [10, 20, 50, 100, 250, 500, 1000];

function matchesTableSearch(
  query: string,
  fields: Array<string | number | undefined | null>
) {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return true;
  return fields.some((field) =>
    String(field ?? "")
      .toLowerCase()
      .includes(normalizedQuery)
  );
}

function jobStatusTone(status?: string) {
  const normalized = String(status ?? "").toLowerCase();
  if (normalized === "done") return "tone-emerald-chip";
  if (normalized === "running") return "tone-sky-chip";
  if (normalized === "queued") return "tone-amber-chip";
  if (normalized === "cancelled" || normalized === "canceled") return "tone-slate-chip";
  if (normalized === "failed" || normalized === "error") return "tone-rose-chip";
  return "tone-slate-chip";
}

function normalizeTimelineRow(
  raw: Record<string, unknown>,
  index: number
): TimelineRow {
  const ts = raw.ts as number | undefined;
  const src = String(raw.src_ip ?? raw.source_ip ?? "");
  const dst = String(raw.dst_ip ?? raw.dest_ip ?? "");
  const normalizedSeverity = normalizeSeverity(raw.severity ?? raw.verdict);
  const normalizedDecision = normalizeDecision({
    decision: raw.verdict,
    severity: raw.severity ?? raw.verdict,
    suppressed: raw.suppressed,
    validated: raw.validated,
  });
  return {
    id: String(raw.id ?? `t-${index}-${ts}-${src}-${dst}`),
    time: raw.time != null ? String(raw.time) : ts != null ? String(ts) : "",
    source_ip: src,
    dest_ip: dst,
    dst_port: Number(raw.dst_port ?? raw.destination_port ?? 0) || 0,
    label: String(raw.label ?? raw.ml_label ?? "—"),
    threat_confidence:
      Number(raw.threat_confidence ?? raw.confidence ?? raw.ml_confidence ?? 0) || 0,
    severity: normalizedSeverity,
    verdict: normalizedDecision,
  };
}

function normalizeSeverity(raw: unknown): Severity {
  const v = String(raw ?? "").trim().toLowerCase();
  if (v === "critical") return "CRITICAL";
  if (v === "high") return "HIGH";
  if (v === "medium") return "MEDIUM";
  return "INFO";
}

function normalizeDecision(raw: Record<string, unknown>): Decision {
  const explicit = String(raw.decision ?? "").trim().toUpperCase();
  if (
    explicit === "CONFIRMED" ||
    explicit === "SUSPICIOUS" ||
    explicit === "IGNORED" ||
    explicit === "DROPPED"
  ) {
    return explicit as Decision;
  }
  if (raw.suppressed === true) return "IGNORED";
  if (raw.validated === false) return "DROPPED";
  const sev = normalizeSeverity(raw.severity ?? raw.verdict);
  if (sev === "MEDIUM") return "SUSPICIOUS";
  if (sev === "HIGH" || sev === "CRITICAL") return "CONFIRMED";
  return "IGNORED";
}

function normalizeClusterRow(
  raw: Record<string, unknown>,
  index: number
): AttackCluster {
  const attackType = String(
    raw.attack_type ?? raw.label ?? raw.ml_label ?? "Unknown"
  );
  const sourceIp = String(raw.source_ip ?? raw.src_ip ?? "");
  const destIp = String(raw.dest_ip ?? raw.dst_ip ?? "");
  const rawTopPorts = Array.isArray(raw.top_dst_ports) ? raw.top_dst_ports : [];
  const rawTopDestinations = Array.isArray(raw.top_dst_ips)
    ? raw.top_dst_ips
    : [];
  return {
    id: String(raw.id ?? `c-${index}-${attackType}-${sourceIp}-${destIp}`),
    severity: normalizeSeverity(raw.severity),
    attack_type: attackType,
    source_ip: sourceIp,
    dest_ip: destIp,
    count_flows: Number(raw.count_flows ?? raw.count ?? 0) || 0,
    max_threat_confidence:
      Number(raw.max_threat_confidence ?? raw.max_confidence ?? raw.confidence ?? 0) ||
      0,
    max_ml_confidence:
      Number(
        raw.max_ml_confidence ??
          raw.ml_confidence ??
          raw.classification_confidence ??
          0
      ) || 0,
    top_dst_ports: rawTopPorts.map((item) => {
      const row = (item as Record<string, unknown>) ?? {};
      return {
        port: Number(row.port ?? 0) || 0,
        count: Number(row.count ?? 0) || 0,
      };
    }),
    top_dst_ips: rawTopDestinations.map((item) => {
      const row = (item as Record<string, unknown>) ?? {};
      return {
        ip: String(row.ip ?? ""),
        count: Number(row.count ?? 0) || 0,
      };
    }),
    raw,
  };
}

function normalizeAlertRow(raw: Record<string, unknown>, index: number): AlertRow {
  const sourceIp = String(raw.source_ip ?? raw.src_ip ?? "");
  const destIp = String(raw.dest_ip ?? raw.dst_ip ?? "");
  const ts = raw.ts ?? raw.time ?? raw.timestamp ?? "";
  const label = String(raw.label ?? raw.ml_label ?? raw.attack_type ?? "—");
  const heuristicRaw =
    raw.heuristic && typeof raw.heuristic === "object"
      ? (raw.heuristic as Record<string, unknown>)
      : {};
  const zeekBytesRaw =
    raw.zeek_bytes && typeof raw.zeek_bytes === "object"
      ? (raw.zeek_bytes as Record<string, unknown>)
      : {};
  const evidenceRefs = Array.isArray(raw.evidence_refs)
    ? raw.evidence_refs.map((v) => String(v))
    : [];
  const validated =
    typeof raw.validated === "boolean"
      ? raw.validated
      : typeof raw.validation_passed === "boolean"
      ? (raw.validation_passed as boolean)
      : undefined;

  return {
    id: String(raw.id ?? `a-${index}-${ts}-${sourceIp}-${destIp}-${label}`),
    time: String(ts ?? ""),
    source_ip: sourceIp,
    dest_ip: destIp,
    dst_port: Number(raw.dst_port ?? raw.destination_port ?? 0) || 0,
    label,
    threat_confidence:
      Number(raw.threat_confidence ?? raw.confidence ?? raw.ml_confidence ?? 0) || 0,
    severity: normalizeSeverity(raw.severity ?? raw.verdict),
    decision: normalizeDecision(raw),
    reason: String(raw.reason ?? raw.message ?? ""),
    validated,
    evidence_refs: evidenceRefs,
    ml_label: String(raw.ml_label ?? label),
    ml_confidence:
      Number(raw.ml_confidence ?? raw.classification_confidence ?? raw.confidence ?? 0) ||
      0,
    zeek_service: String(raw.zeek_service ?? raw.service ?? ""),
    zeek_conn_state: String(raw.zeek_conn_state ?? raw.conn_state ?? ""),
    zeek_proto: String(raw.zeek_proto ?? raw.proto ?? ""),
    zeek_duration: Number(raw.zeek_duration ?? raw.duration ?? 0) || 0,
    zeek_bytes: {
      orig: Number(zeekBytesRaw.orig ?? raw.orig_bytes ?? 0) || 0,
      resp: Number(zeekBytesRaw.resp ?? raw.resp_bytes ?? 0) || 0,
    },
    dns_top_query: String(raw.dns_top_query ?? ""),
    dns_query_count: Number(raw.dns_query_count ?? 0) || 0,
    http_top_host: String(raw.http_top_host ?? ""),
    http_top_uri: String(raw.http_top_uri ?? ""),
    http_request_count: Number(raw.http_request_count ?? 0) || 0,
    ssl_top_sni: String(raw.ssl_top_sni ?? ""),
    ssl_event_count: Number(raw.ssl_event_count ?? 0) || 0,
    heuristic: {
      type: String(heuristicRaw.type ?? raw.heuristic_type ?? ""),
      score: Number(heuristicRaw.score ?? raw.heuristic_score ?? 0) || 0,
      reason: String(heuristicRaw.reason ?? raw.heuristic_reason ?? ""),
    },
    raw,
  };
}

function normalizeRiskLevel(raw: unknown): PcapReport["summary"]["risk_level"] {
  const v = String(raw ?? "").trim().toLowerCase();
  if (v === "critical") return "Critical";
  if (v === "high") return "High";
  if (v === "medium") return "Medium";
  if (v === "low") return "Low";
  return "Normal";
}

function normalizeRiskPerIpRole(raw: unknown): RiskPerIpRow["role"] {
  const value = String(raw ?? "").trim().toLowerCase();
  if (value === "both") return "both";
  if (value === "destination") return "destination";
  return "source";
}

function normalizeRiskPerIpSeverity(raw: unknown): SecurityScoreSeverity {
  const value = String(raw ?? "").trim().toLowerCase();
  if (value === "critical") return "critical";
  if (value === "high") return "high";
  if (value === "medium") return "medium";
  return "low";
}

function normalizeRiskPerIpRow(raw: Record<string, unknown>): RiskPerIpRow {
  return {
    ip: String(raw.ip ?? ""),
    role: normalizeRiskPerIpRole(raw.role),
    threat_count: Number(raw.threat_count ?? 0) || 0,
    suspicious_count: Number(raw.suspicious_count ?? 0) || 0,
    top_severity: normalizeRiskPerIpSeverity(raw.top_severity),
    max_confidence: Number(raw.max_confidence ?? 0) || 0,
    ip_risk_score: Number(raw.ip_risk_score ?? 0) || 0,
    top_attack: String(raw.top_attack ?? ""),
  };
}

function normalizeReport(raw: Record<string, unknown>): PcapReport {
  const rawClusters = Array.isArray(raw.clusters) ? raw.clusters : [];
  const rawAlerts = Array.isArray(raw.alerts) ? raw.alerts : [];
  const rawTimeline = Array.isArray(raw.timeline) ? raw.timeline : [];
  const rawRiskPerIp = Array.isArray(raw.risk_per_ip) ? raw.risk_per_ip : [];
  const metaRaw =
    raw.meta && typeof raw.meta === "object"
      ? (raw.meta as Record<string, unknown>)
      : {};
  const pipelineRaw =
    metaRaw.pipeline && typeof metaRaw.pipeline === "object"
      ? (metaRaw.pipeline as Record<string, unknown>)
      : {};
  const confidenceModeApplied =
    pipelineRaw.confidence_mode != null
      ? String(pipelineRaw.confidence_mode)
      : undefined;
  const analysisModeApplied =
    pipelineRaw.analysis_mode != null
      ? String(pipelineRaw.analysis_mode)
      : metaRaw.analysis_mode != null
      ? String(metaRaw.analysis_mode)
      : undefined;
  const summaryRaw =
    raw.summary && typeof raw.summary === "object"
      ? (raw.summary as Record<string, unknown>)
      : {};

  const clusters = rawClusters.map((c, i) =>
    normalizeClusterRow((c as Record<string, unknown>) ?? {}, i)
  );
  const alerts = rawAlerts.map((a, i) =>
    normalizeAlertRow((a as Record<string, unknown>) ?? {}, i)
  );
  const timeline = rawTimeline.map((t, i) =>
    normalizeTimelineRow((t as Record<string, unknown>) ?? {}, i)
  );
  const riskPerIp = rawRiskPerIp.map((row) =>
    normalizeRiskPerIpRow((row as Record<string, unknown>) ?? {})
  );

  const suppressedDerived = alerts.filter(
    (a) => a.decision === "IGNORED" || a.decision === "DROPPED"
  ).length;

  return {
    meta: {
      pipeline: {
        confidence_mode: confidenceModeApplied,
        analysis_mode: analysisModeApplied,
      },
      artifact_protection: normalizeArtifactProtection(
        metaRaw.artifact_protection
      ),
    },
    summary: {
      total_flows: Number(summaryRaw.total_flows ?? 0) || 0,
      alerts:
        Number(summaryRaw.alerts ?? summaryRaw.alerts_count ?? alerts.length) ||
        alerts.length,
      suspicious: Number(summaryRaw.suspicious ?? 0) || 0,
      suppressed:
        Number(summaryRaw.suppressed ?? suppressedDerived) || suppressedDerived,
      overall_risk: Number(summaryRaw.overall_risk ?? 0) || 0,
      risk_level: normalizeRiskLevel(summaryRaw.risk_level),
      risk_context_label:
        summaryRaw.risk_context_label != null
          ? String(summaryRaw.risk_context_label)
          : undefined,
      risk_display:
        summaryRaw.risk_display != null
          ? String(summaryRaw.risk_display)
          : undefined,
      security_score:
        summaryRaw.security_score != null
          ? Number(summaryRaw.security_score)
          : undefined,
      score_explanation:
        summaryRaw.score_explanation &&
        typeof summaryRaw.score_explanation === "object"
          ? {
              base_score:
                Number(
                  (summaryRaw.score_explanation as Record<string, unknown>)
                    .base_score ?? 100
                ) || 100,
              risk_contributors: Array.isArray(
                (summaryRaw.score_explanation as Record<string, unknown>)
                  .risk_contributors
              )
                ? ((
                    summaryRaw.score_explanation as Record<string, unknown>
                  ).risk_contributors as Array<Record<string, unknown>>).map(
                    (item) => ({
                      label: String(item.label ?? ""),
                      impact: Number(item.impact ?? 0),
                      details: String(item.details ?? ""),
                    })
                  )
                : [],
              final_score:
                Number(
                  (summaryRaw.score_explanation as Record<string, unknown>)
                    .final_score ?? 0
                ) || 0,
            }
          : undefined,
      summary:
        summaryRaw.summary != null
          ? String(summaryRaw.summary)
          : summaryRaw.security_summary != null
          ? String(summaryRaw.security_summary)
          : undefined,
      security_score_level:
        summaryRaw.security_score_level != null
          ? (String(summaryRaw.security_score_level) as
              | "Secure"
              | "Warning"
              | "Risky"
              | "Critical")
          : undefined,
      security_summary:
        summaryRaw.security_summary != null
          ? String(summaryRaw.security_summary)
          : undefined,
      security_trend:
        summaryRaw.security_trend != null
          ? String(summaryRaw.security_trend)
          : undefined,
      cluster_count:
        summaryRaw.cluster_count != null
          ? Number(summaryRaw.cluster_count) || 0
          : undefined,
      severity_counts:
        summaryRaw.severity_counts &&
        typeof summaryRaw.severity_counts === "object"
          ? (summaryRaw.severity_counts as Partial<
              Record<SecurityScoreSeverity, number>
            >)
          : undefined,
      top_risk:
        summaryRaw.top_risk && typeof summaryRaw.top_risk === "object"
          ? {
              name: String(
                (summaryRaw.top_risk as Record<string, unknown>).name ?? ""
              ),
              severity: String(
                (summaryRaw.top_risk as Record<string, unknown>).severity ?? ""
              ),
              confidence:
                Number(
                  (summaryRaw.top_risk as Record<string, unknown>).confidence ?? 0
                ),
              count:
                Number((summaryRaw.top_risk as Record<string, unknown>).count ?? 0),
              impact:
                Number((summaryRaw.top_risk as Record<string, unknown>).impact ?? 0),
            }
          : undefined,
    },
    clusters,
    alerts,
    timeline,
    risk_per_ip: riskPerIp,
    evidence: Array.isArray(raw.evidence)
      ? (raw.evidence as EvidenceItem[])
      : undefined,
    assets: Array.isArray(raw.assets) ? (raw.assets as AssetRow[]) : undefined,
  };
}

function syncRecentSecurityAlertCache(
  rawReport: Record<string, unknown>,
  options: {
    jobId?: string | null;
    uploadName?: string | null;
    fallbackCreatedAt?: string | null;
    notifyDashboard?: boolean;
  } = {}
) {
  const alerts = buildDashboardAlertsFromReport(rawReport, {
    jobId: options.jobId,
    uploadName: options.uploadName,
    fallbackCreatedAt: options.fallbackCreatedAt,
    maxItems: 20,
  });

  if (alerts.length === 0) {
    return;
  }

  persistPcapReportSnapshot(options.jobId, rawReport);

  const buildAlertSignature = (alert: DashboardPcapAlert) =>
    [
      alert.id,
      alert.job_id ?? "",
      alert.type,
      alert.status,
      alert.title,
      alert.message,
      alert.severity,
      alert.risk_label,
      alert.threats_count,
      alert.flows_analyzed,
      alert.top_pattern ?? "",
      alert.filename ?? "",
      alert.created_at,
      alert.attack_type ?? "",
      alert.protocol ?? "",
      alert.src_ip ?? "",
      alert.dst_ip ?? "",
      alert.source_type ?? "",
    ].join("|");

  const cachedAlerts = readRecentPcapAlertCache(Math.max(alerts.length, 20));
  const nextSignature = alerts.map(buildAlertSignature).join("||");
  const cachedSignature = cachedAlerts.map(buildAlertSignature).join("||");
  if (nextSignature === cachedSignature) {
    return;
  }

  const updatedAt = new Date().toISOString();
  persistRecentPcapAlertCache(alerts, {
    jobId: options.jobId,
    updatedAt,
  });

  // Refresh dashboard score/alerts only for newly completed analyses,
  // not when reopening historical jobs.
  if (options.notifyDashboard === true) {
    broadcastRecentPcapAlertsUpdated(updatedAt);
  }
}

function normalizeStepFromMessage(msg?: string): JobStep {
  const v = (msg || "").toLowerCase();
  if (!v) return "Queued";
  if (v.includes("cancel")) return "Cancelled";
  if (v.includes("export")) return "Parsing";
  if (v.includes("cic") || v.includes("features")) return "Flow Extraction";
  if (v.includes("heur")) return "Heuristics";
  if (v.includes("ml")) return "ML Inference";
  if (v.includes("valid")) return "Validation";
  if (v.includes("zeek")) return "Zeek Evidence";
  if (v.includes("cluster")) return "Clustering";
  if (v.includes("report")) return "Report Ready";
  return "Queued";
}

function SevBadge({ s }: { s: Severity }) {
  const map: Record<Severity, string> = {
    INFO: "tone-emerald-chip",
    MEDIUM: "tone-amber-chip",
    HIGH: "tone-orange-chip",
    CRITICAL: "tone-rose-chip",
  };
  return (
    <Badge
      className={cx(
        "border px-3 py-1 text-xs font-semibold uppercase tracking-widest",
        map[s]
      )}
    >
      {s}
    </Badge>
  );
}

function DecisionBadge({ d }: { d: Decision }) {
  const map: Record<Decision, string> = {
    CONFIRMED: "tone-emerald-chip",
    SUSPICIOUS: "tone-amber-chip",
    IGNORED: "tone-slate-chip",
    DROPPED: "tone-rose-chip",
  };
  return (
    <Badge
      className={cx(
        "border px-3 py-1 text-xs font-semibold uppercase tracking-widest",
        map[d]
      )}
    >
      {d}
    </Badge>
  );
}

function ValidationBadge({ validated }: { validated?: boolean }) {
  if (validated == null) {
    return null;
  }

  const tone = validated
    ? "tone-emerald-chip"
    : "tone-rose-chip";

  return (
    <Badge
      className={cx(
        "border px-3 py-1 text-xs font-semibold uppercase tracking-widest",
        tone
      )}
    >
      {validated ? "Validated" : "Dropped"}
    </Badge>
  );
}

function RiskPill({
  level,
  displayLabel,
}: {
  level: PcapReport["summary"]["risk_level"];
  displayLabel?: string | null;
}) {
  const map: Record<string, string> = {
    Normal: "tone-emerald-chip",
    Low: "tone-sky-chip",
    Medium: "tone-amber-chip",
    High: "tone-orange-chip",
    Critical: "tone-rose-chip",
  };
  return (
    <Badge
      className={cx(
        "border px-3 py-1 text-xs font-semibold uppercase tracking-widest",
        map[level] ?? "tone-slate-chip"
      )}
    >
      <span className="inline-block w-2 h-2 rounded-full bg-current opacity-60 mr-2" />
      {displayLabel || level}
    </Badge>
  );
}

function toSecurityScoreSeverity(
  severity: Severity | null | undefined
): SecurityScoreSeverity {
  if (severity === "CRITICAL") return "critical";
  if (severity === "HIGH") return "high";
  if (severity === "MEDIUM") return "medium";
  return "low";
}

function createSeverityCounts(): Record<SecurityScoreSeverity, number> {
  return {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
}

function deriveSeverityCounts(
  report: Pick<PcapReport, "alerts" | "clusters"> | null,
  summaryCounts?: Partial<Record<SecurityScoreSeverity, number>>
): Record<SecurityScoreSeverity, number> {
  const counts = createSeverityCounts();

  if (summaryCounts) {
    (Object.keys(counts) as SecurityScoreSeverity[]).forEach((severity) => {
      const value = Number(summaryCounts[severity] ?? 0);
      counts[severity] = Number.isFinite(value) && value > 0 ? Math.round(value) : 0;
    });
  }

  const hasSummaryCounts = Object.values(counts).some((count) => count > 0);
  if (hasSummaryCounts || !report) {
    return counts;
  }

  if (report.alerts.length > 0) {
    report.alerts.forEach((alert) => {
      counts[toSecurityScoreSeverity(alert.severity)] += 1;
    });
    return counts;
  }

  report.clusters.forEach((cluster) => {
    counts[toSecurityScoreSeverity(cluster.severity)] += Math.max(
      cluster.count_flows || 0,
      1
    );
  });

  return counts;
}

function buildThreatBreakdownSummary(
  counts: Record<SecurityScoreSeverity, number>
): string {
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
  if (total <= 0) {
    return "No threat breakdown available for this analysis.";
  }

  if (counts.critical > 0) {
    return `${counts.critical} critical-severity threat${
      counts.critical === 1 ? "" : "s"
    } detected. Immediate review is recommended.`;
  }

  if (counts.high > 0) {
    return `${counts.high} high-severity threat${
      counts.high === 1 ? "" : "s"
    } detected. No critical threats were observed.`;
  }

  if (counts.medium > 0) {
    return `${counts.medium} medium-severity threat${
      counts.medium === 1 ? "" : "s"
    } detected. No critical threats were observed.`;
  }

  return `${counts.low} low-severity threat${
    counts.low === 1 ? "" : "s"
  } detected. No critical threats were observed.`;
}

function deriveRiskPerIpRows(report: PcapReport | null): RiskPerIpRow[] {
  if (!report) {
    return [];
  }

  if (Array.isArray(report.risk_per_ip) && report.risk_per_ip.length > 0) {
    return [...report.risk_per_ip]
      .filter((row) => row.ip)
      .sort((left, right) => right.ip_risk_score - left.ip_risk_score);
  }

  type IpAccumulator = {
    ip: string;
    roles: Set<RiskPerIpRow["role"]>;
    threats: SecurityScoreThreatInput[];
    severityCounts: Record<SecurityScoreSeverity, number>;
    threatCount: number;
    suspiciousCount: number;
    maxConfidence: number;
    topAttack: string;
    clusterCount: number;
  };

  const rows = new Map<string, IpAccumulator>();
  const usingClusters = report.clusters.length > 0;

  function getOrCreate(ip: string): IpAccumulator {
    const existing = rows.get(ip);
    if (existing) {
      return existing;
    }

    const created: IpAccumulator = {
      ip,
      roles: new Set<RiskPerIpRow["role"]>(),
      threats: [],
      severityCounts: createSeverityCounts(),
      threatCount: 0,
      suspiciousCount: 0,
      maxConfidence: 0,
      topAttack: "",
      clusterCount: 0,
    };
    rows.set(ip, created);
    return created;
  }

  function attachThreat(
    ip: string,
    role: RiskPerIpRow["role"],
    threat: SecurityScoreThreatInput,
    confidence: number,
    topAttack: string
  ) {
    if (!ip) {
      return;
    }

    const entry = getOrCreate(ip);
    if (role === "both") {
      entry.roles.add("source");
      entry.roles.add("destination");
    } else {
      entry.roles.add(role);
    }
    entry.threats.push(threat);
    entry.threatCount += 1;
    entry.suspiciousCount += 1;
    entry.maxConfidence = Math.max(entry.maxConfidence, confidence);
    entry.topAttack = entry.topAttack || topAttack;

    const severity = normalizeRiskPerIpSeverity(threat.severity);
    entry.severityCounts[severity] += 1;
    if (usingClusters) {
      entry.clusterCount += 1;
    }
  }

  if (usingClusters) {
    report.clusters.forEach((cluster) => {
      const threat: SecurityScoreThreatInput = {
        label: cluster.attack_type,
        severity: toSecurityScoreSeverity(cluster.severity),
        confidence: cluster.max_threat_confidence,
        count: cluster.count_flows || 1,
      };

      if (cluster.source_ip === cluster.dest_ip && cluster.source_ip) {
        attachThreat(
          cluster.source_ip,
          "both",
          threat,
          cluster.max_threat_confidence,
          cluster.attack_type
        );
        return;
      }

      attachThreat(
        cluster.source_ip,
        "source",
        threat,
        cluster.max_threat_confidence,
        cluster.attack_type
      );
      attachThreat(
        cluster.dest_ip,
        "destination",
        threat,
        cluster.max_threat_confidence,
        cluster.attack_type
      );
    });
  } else {
    report.alerts.forEach((alert) => {
      const threat: SecurityScoreThreatInput = {
        label: alert.label,
        severity: toSecurityScoreSeverity(alert.severity),
        confidence: alert.threat_confidence || alert.ml_confidence,
        count: 1,
      };
      const confidence = alert.threat_confidence || alert.ml_confidence;

      if (alert.source_ip === alert.dest_ip && alert.source_ip) {
        attachThreat(alert.source_ip, "both", threat, confidence, alert.label);
        return;
      }

      attachThreat(alert.source_ip, "source", threat, confidence, alert.label);
      attachThreat(alert.dest_ip, "destination", threat, confidence, alert.label);
    });
  }

  return Array.from(rows.values())
    .map((entry) => {
      const score = calculateSecurityScore(entry.threats, {
        hasAnalysis: true,
        context: {
          alerts: entry.threatCount,
          suspicious: entry.suspiciousCount,
          clusterCount: entry.clusterCount,
          severityCounts: entry.severityCounts,
        },
      });

      const role: RiskPerIpRow["role"] =
        entry.roles.has("source") && entry.roles.has("destination")
          ? "both"
          : entry.roles.has("destination")
          ? "destination"
          : "source";

      return {
        ip: entry.ip,
        role,
        threat_count: entry.threatCount,
        suspicious_count: entry.suspiciousCount,
        top_severity: score.topThreat?.severity ?? "low",
        max_confidence: entry.maxConfidence,
        ip_risk_score: Number(
          (((score.metrics.overallRisk ?? 0) * 100) as number).toFixed(1)
        ),
        top_attack: score.topThreat?.label ?? (entry.topAttack || "Unknown threat"),
      };
    })
    .filter((row) => row.ip)
    .sort((left, right) => right.ip_risk_score - left.ip_risk_score);
}

function DetailStat({
  label,
  value,
  accent = "slate",
}: {
  label: string;
  value: React.ReactNode;
  accent?: "slate" | "indigo" | "emerald" | "amber" | "rose";
}) {
  const displayValue = value === "—" ? "N/A" : value;
  const tone = dashboardToneClasses(
    accent === "indigo"
      ? "sky"
      : accent === "emerald"
      ? "emerald"
      : accent === "amber"
      ? "amber"
      : accent === "rose"
      ? "rose"
      : "slate"
  );

  return (
    <div
      className={cx(
        "cyber-panel-soft relative overflow-hidden rounded-2xl border p-4 shadow-lg",
        tone.border
      )}
    >
      <div
        className={cx("pointer-events-none absolute inset-0 opacity-70", tone.spotlight)}
        aria-hidden="true"
      />
      <div
        className={cx(
          "pointer-events-none absolute inset-x-0 top-0 h-px opacity-70",
          tone.glow
        )}
        aria-hidden="true"
      />
      <div className="relative">
        <div className="text-[11px] uppercase tracking-[0.18em] text-slate-400">
          {label}
        </div>
        <div className={cx("mt-2 text-sm font-semibold break-words", tone.value)}>
          {displayValue}
        </div>
      </div>
    </div>
  );
}

function EvidenceEmpty({ title }: { title: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-white/10 bg-white/[0.02] px-5 py-8 text-center">
      <div className="text-sm font-semibold text-white">{title}</div>
      <div className="mt-2 text-sm text-slate-400">
        No additional evidence was attached to this section for the selected item.
      </div>
    </div>
  );
}

function DetailField({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  const isEmpty =
    value == null ||
    value === "" ||
    value === "—" ||
    (typeof value === "number" && Number.isNaN(value));

  if (isEmpty) return null;

  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 min-h-[92px]">
      <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
        {label}
      </div>
      <div
        className={cx(
          "mt-2 text-sm text-slate-100",
          mono && "font-mono break-all"
        )}
      >
        {value}
      </div>
    </div>
  );
}

function AlertDetailsSheet({
  detail,
  jobId,
  open,
  onOpenChange,
  onEvidenceOpened,
}: {
  detail: DetailsTarget | null;
  jobId: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onEvidenceOpened: (evidenceKey: string) => void;
}) {
  const alert =
    detail?.kind === "alert"
      ? detail.alert
      : detail && detail.kind === "cluster"
      ? detail.relatedAlert ?? null
      : null;

  const cluster = detail && detail.kind === "cluster" ? detail.cluster : null;

  const hasConnectionEvidence =
    !!alert &&
    (hasText(alert.zeek_service) ||
      hasText(alert.zeek_conn_state) ||
      hasText(alert.zeek_proto) ||
      hasPositive(alert.zeek_duration) ||
      hasPositive(alert.zeek_bytes.orig) ||
      hasPositive(alert.zeek_bytes.resp) ||
      hasText(alert.heuristic.type) ||
      hasText(alert.heuristic.reason) ||
      hasPositive(alert.heuristic.score));

  const hasDnsEvidence =
    !!alert && (hasPositive(alert.dns_query_count) || hasText(alert.dns_top_query));

  const hasHttpEvidence =
    !!alert &&
    (hasPositive(alert.http_request_count) ||
      hasText(alert.http_top_host) ||
      hasText(alert.http_top_uri));

  const hasTlsEvidence =
    !!alert && (hasPositive(alert.ssl_event_count) || hasText(alert.ssl_top_sni));

  const whyFlagged = [
    alert?.reason,
    hasText(alert?.heuristic.reason)
      ? `Heuristic evidence: ${alert?.heuristic.reason}`
      : hasText(alert?.heuristic.type)
      ? `Heuristic type: ${alert?.heuristic.type}`
      : "",
    hasPositive(alert?.dns_query_count)
      ? `DNS activity observed with ${alert?.dns_query_count} queries${
          hasText(alert?.dns_top_query) ? `, led by ${alert?.dns_top_query}` : ""
        }.`
      : "",
    hasPositive(alert?.http_request_count)
      ? `HTTP activity observed with ${alert?.http_request_count} requests${
          hasText(alert?.http_top_host) ? ` against ${alert?.http_top_host}` : ""
        }.`
      : "",
    hasPositive(alert?.ssl_event_count)
      ? `TLS activity observed with ${alert?.ssl_event_count} events${
          hasText(alert?.ssl_top_sni) ? `, top SNI ${alert?.ssl_top_sni}` : ""
        }.`
      : "",
    cluster
      ? `Cluster context: ${cluster.count_flows} related flows${
          cluster.top_dst_ports.length
            ? ` across ports ${cluster.top_dst_ports
                .slice(0, 3)
                .map((item) => item.port)
                .join(", ")}`
            : ""
        }.`
      : "",
  ].filter(Boolean) as string[];

  const decisionContext = [
    alert
      ? `Final decision is ${alert.decision} with ${fmtPct(
          alert.threat_confidence
        )} threat confidence.`
      : cluster
      ? `Cluster severity is ${cluster.severity} with peak threat confidence ${fmtPct(
          cluster.max_threat_confidence
        )}.`
      : "",
    alert?.validated === true ? "Validation checks passed before alert promotion." : "",
    alert?.validated === false
      ? "Validation checks failed; review the supporting context carefully."
      : "",
    alert?.evidence_refs?.length
      ? `${alert.evidence_refs.length} evidence reference(s) are attached to this flow.`
      : "",
    hasText(alert?.zeek_service)
      ? `Zeek service classification: ${alert?.zeek_service}.`
      : hasText(alert?.zeek_proto)
      ? `Protocol observed: ${alert?.zeek_proto}.`
      : "",
  ].filter(Boolean) as string[];

  const rawPayload =
    detail?.kind === "cluster"
      ? {
          cluster: cluster?.raw ?? {},
          related_alert: alert?.raw ?? null,
        }
      : alert?.raw ?? {};

  const tabKeys = [
    "overview",
    ...(hasConnectionEvidence ? ["connection"] : []),
    ...(hasDnsEvidence ? ["dns"] : []),
    ...(hasHttpEvidence ? ["http"] : []),
    ...(hasTlsEvidence ? ["tls"] : []),
    "raw",
  ];

  const title = cluster?.attack_type ?? alert?.label ?? "Alert details";
  const subtitle = cluster
    ? "Attack cluster context with representative flow evidence"
    : "Flow-level decision context and supporting evidence";
  const [activeTab, setActiveTab] = useState(tabKeys[0] ?? "overview");

  useEffect(() => {
    setActiveTab(tabKeys[0] ?? "overview");
  }, [detail?.kind, alert?.id, cluster?.id]);

  useEffect(() => {
    const evidenceTabs = new Set(["connection", "dns", "http", "tls"]);
    if (!open || !jobId || !alert?.id || !evidenceTabs.has(activeTab)) {
      return;
    }
    onEvidenceOpened(activeTab);
  }, [activeTab, alert?.id, jobId, onEvidenceOpened, open]);

  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onOpenChange(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onOpenChange]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-50">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="absolute inset-0 cyber-backdrop"
        onClick={() => onOpenChange(false)}
      />

      <motion.div
        initial={{ x: 56, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ x: 56, opacity: 0 }}
        transition={{ duration: 0.22 }}
        className="absolute inset-y-0 right-0 w-full max-w-6xl border-l border-white/10 cyber-card shadow-2xl"
      >
        <div className="flex h-full min-h-0 flex-col">
          <div className="shrink-0 border-b border-white/10 cyber-panel px-6 py-5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 pr-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline" className="tone-sky-chip">
                    {detail?.kind === "cluster" ? "Cluster Details" : "Alert Details"}
                  </Badge>
                  {alert ? <SevBadge s={alert.severity} /> : null}
                  {!alert && cluster ? <SevBadge s={cluster.severity} /> : null}
                  {alert ? <DecisionBadge d={alert.decision} /> : null}
                </div>

                <div className="mt-3 text-3xl font-bold text-white">{title}</div>
                <div className="mt-2 text-sm text-slate-400">{subtitle}</div>
              </div>

              <button
                type="button"
                onClick={() => onOpenChange(false)}
                className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-slate-200 transition hover:bg-white/10"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto">
            <div className="px-6 py-6">
              <div className="grid gap-6 lg:grid-cols-[280px_minmax(0,1fr)]">
                <div className="space-y-4">
                  <div className="cyber-panel rounded-3xl p-5">
                    <div className="space-y-4">
                      <DetailField
                        label="Severity"
                        value={
                          alert ? (
                            <SevBadge s={alert.severity} />
                          ) : cluster ? (
                            <SevBadge s={cluster.severity} />
                          ) : (
                            "—"
                          )
                        }
                      />

                      <DetailField
                        label="Verdict"
                        value={
                          alert ? <DecisionBadge d={alert.decision} /> : "Representative cluster"
                        }
                      />

                      <DetailField
                        label="Threat Confidence"
                        value={
                          alert
                            ? fmtPct(alert.threat_confidence)
                            : cluster
                            ? fmtPct(cluster.max_threat_confidence)
                            : "—"
                        }
                      />

                      <DetailField
                        label="Source IP"
                        value={alert?.source_ip ?? cluster?.source_ip ?? "—"}
                        mono
                      />

                      <DetailField
                        label="Destination IP"
                        value={alert?.dest_ip ?? cluster?.dest_ip ?? "—"}
                        mono
                      />

                      <DetailField
                        label="Destination Port"
                        value={alert?.dst_port || "—"}
                      />

                      <DetailField
                        label="ML Confidence"
                        value={
                          alert
                            ? fmtPct(alert.ml_confidence)
                            : cluster
                            ? fmtPct(cluster.max_ml_confidence)
                            : "—"
                        }
                      />
                    </div>
                  </div>

                  <div className="cyber-panel rounded-3xl p-5">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <ShieldCheck className="h-4 w-4 text-indigo-300" />
                      Why Flagged
                    </div>

                    {whyFlagged.length > 0 ? (
                      <div className="mt-4 space-y-2 text-sm text-slate-300">
                        {whyFlagged.slice(0, 4).map((item, index) => (
                          <div key={`${item}-${index}`} className="flex gap-2">
                            <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-indigo-300" />
                            <span>{item}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="mt-4 text-sm text-slate-400">
                        No expanded reasoning is available.
                      </div>
                    )}
                  </div>
                </div>

                <div className="min-w-0 space-y-6">
                  <div className="grid gap-4 lg:grid-cols-3">
                    <DetailStat label="Attack Type" value={title} accent="indigo" />
                    <DetailStat
                      label="Observed Time"
                      value={
                        alert ? fmtTime(alert.time) : `${cluster?.count_flows ?? 0} flows`
                      }
                      accent="amber"
                    />
                    <DetailStat
                      label="Decision Context"
                      value={alert ? alert.decision : "Cluster summary"}
                      accent="emerald"
                    />
                  </div>

                  <Tabs
                    key={`${detail?.kind ?? "none"}-${alert?.id ?? cluster?.id ?? "empty"}`}
                    value={activeTab}
                    onValueChange={setActiveTab}
                    className="gap-4"
                  >
                    <TabsList className="h-auto w-full flex-wrap justify-start">
                      <TabsTrigger
                        value="overview"
                        className="rounded-xl"
                      >
                        Overview
                      </TabsTrigger>

                      {hasConnectionEvidence && (
                        <TabsTrigger
                          value="connection"
                          className="rounded-xl"
                        >
                          Connection
                        </TabsTrigger>
                      )}

                      {hasDnsEvidence && (
                        <TabsTrigger
                          value="dns"
                          className="rounded-xl"
                        >
                          DNS
                        </TabsTrigger>
                      )}

                      {hasHttpEvidence && (
                        <TabsTrigger
                          value="http"
                          className="rounded-xl"
                        >
                          HTTP
                        </TabsTrigger>
                      )}

                      {hasTlsEvidence && (
                        <TabsTrigger
                          value="tls"
                          className="rounded-xl"
                        >
                          TLS / SSL
                        </TabsTrigger>
                      )}

                      <TabsTrigger
                        value="raw"
                        className="rounded-xl"
                      >
                        Raw / JSON
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="overview" className="space-y-6">
                      <div className="cyber-panel rounded-3xl p-5">
                        <div className="text-sm font-semibold text-white">Core Context</div>
                        <div className="mt-4 grid gap-3 md:grid-cols-2">
                          <DetailField label="Attack Type" value={title} />
                          <DetailField
                            label="ML Label"
                            value={alert?.ml_label ?? cluster?.attack_type ?? "—"}
                          />
                          <DetailField
                            label="Observed Time"
                            value={alert ? fmtTime(alert.time) : "Representative cluster"}
                          />
                          <DetailField
                            label="Reason"
                            value={alert?.reason ?? "Cluster-level summary only"}
                          />
                        </div>
                      </div>

                      <div className="cyber-panel rounded-3xl p-5">
                        <div className="flex items-center gap-2 text-sm font-semibold text-white">
                          <ShieldCheck className="h-4 w-4 text-indigo-300" />
                          Why Flagged
                        </div>
                        {whyFlagged.length > 0 ? (
                          <div className="mt-4 space-y-2 text-sm text-slate-300">
                            {whyFlagged.slice(0, 4).map((item, index) => (
                              <div key={`${item}-${index}`} className="flex gap-2">
                                <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-indigo-300" />
                                <span>{item}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="mt-4 text-sm text-slate-400">
                            No expanded reasoning is available for this item.
                          </div>
                        )}
                      </div>

                      <div className="cyber-panel rounded-3xl p-5">
                        <div className="flex items-center gap-2 text-sm font-semibold text-white">
                          <Route className="h-4 w-4 text-indigo-300" />
                          Decision Context
                        </div>
                        {decisionContext.length > 0 ? (
                          <div className="mt-4 space-y-2 text-sm text-slate-300">
                            {decisionContext.slice(0, 4).map((item, index) => (
                              <div key={`${item}-${index}`} className="flex gap-2">
                                <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                                <span>{item}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="mt-4 text-sm text-slate-400">
                            No additional decision context is available.
                          </div>
                        )}
                      </div>

                      {cluster && (
                        <div className="cyber-panel rounded-3xl p-5">
                          <div className="text-sm font-semibold text-white">
                            Cluster Context
                          </div>
                          <div className="mt-4 grid gap-3 md:grid-cols-2">
                            <DetailField
                              label="Top Destination Ports"
                              value={
                                cluster.top_dst_ports.length
                                  ? cluster.top_dst_ports
                                      .slice(0, 5)
                                      .map((item) => `${item.port} (${item.count})`)
                                      .join(", ")
                                  : "—"
                              }
                            />
                            <DetailField
                              label="Top Destinations"
                              value={
                                cluster.top_dst_ips.length
                                  ? cluster.top_dst_ips
                                      .slice(0, 5)
                                      .map((item) => `${item.ip} (${item.count})`)
                                      .join(", ")
                                  : "—"
                              }
                            />
                          </div>
                        </div>
                      )}
                    </TabsContent>

                    <TabsContent value="connection" className="space-y-4">
                      {hasConnectionEvidence && alert ? (
                        <div className="cyber-panel rounded-3xl p-5 space-y-5">
                          <div className="grid gap-3 md:grid-cols-2">
                            <DetailField label="Service" value={alert.zeek_service || "—"} />
                            <DetailField label="Protocol" value={alert.zeek_proto || "—"} />
                            <DetailField
                              label="Connection State"
                              value={alert.zeek_conn_state || "—"}
                            />
                            <DetailField
                              label="Duration"
                              value={
                                hasPositive(alert.zeek_duration)
                                  ? `${fmtScore(alert.zeek_duration)} s`
                                  : "—"
                              }
                            />
                            <DetailField
                              label="Origin Bytes"
                              value={fmtBytes(alert.zeek_bytes.orig)}
                            />
                            <DetailField
                              label="Response Bytes"
                              value={fmtBytes(alert.zeek_bytes.resp)}
                            />
                          </div>

                          <Separator className="bg-white/10" />

                          <div className="grid gap-3 md:grid-cols-3">
                            <DetailField
                              label="Heuristic Type"
                              value={alert.heuristic.type || "—"}
                            />
                            <DetailField
                              label="Heuristic Score"
                              value={fmtScore(alert.heuristic.score)}
                            />
                            <DetailField
                              label="Heuristic Reason"
                              value={alert.heuristic.reason || "—"}
                            />
                          </div>
                        </div>
                      ) : (
                        <EvidenceEmpty title="No connection evidence" />
                      )}
                    </TabsContent>

                    <TabsContent value="dns">
                      {hasDnsEvidence && alert ? (
                        <div className="cyber-panel rounded-3xl p-5">
                          <div className="grid gap-3 md:grid-cols-2">
                            <DetailField
                              label="Top Query"
                              value={alert.dns_top_query || "—"}
                            />
                            <DetailField
                              label="Query Count"
                              value={alert.dns_query_count}
                            />
                          </div>
                        </div>
                      ) : (
                        <EvidenceEmpty title="No DNS evidence" />
                      )}
                    </TabsContent>

                    <TabsContent value="http">
                      {hasHttpEvidence && alert ? (
                        <div className="cyber-panel rounded-3xl p-5">
                          <div className="grid gap-3 md:grid-cols-2">
                            <DetailField
                              label="Top Host"
                              value={alert.http_top_host || "—"}
                            />
                            <DetailField
                              label="Top URI"
                              value={alert.http_top_uri || "—"}
                              mono
                            />
                            <DetailField
                              label="Request Count"
                              value={alert.http_request_count}
                            />
                          </div>
                        </div>
                      ) : (
                        <EvidenceEmpty title="No HTTP evidence" />
                      )}
                    </TabsContent>

                    <TabsContent value="tls">
                      {hasTlsEvidence && alert ? (
                        <div className="cyber-panel rounded-3xl p-5">
                          <div className="grid gap-3 md:grid-cols-2">
                            <DetailField
                              label="Top SNI"
                              value={alert.ssl_top_sni || "—"}
                            />
                            <DetailField
                              label="TLS Event Count"
                              value={alert.ssl_event_count}
                            />
                          </div>
                        </div>
                      ) : (
                        <EvidenceEmpty title="No TLS / SSL evidence" />
                      )}
                    </TabsContent>

                    <TabsContent value="raw">
                      <div className="cyber-panel rounded-3xl p-4">
                        <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
                          <FileCode2 className="h-4 w-4 text-indigo-300" />
                          Raw JSON payload
                        </div>
                        <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words rounded-2xl cyber-panel-soft p-4 text-xs leading-6 text-slate-300">
                          {JSON.stringify(rawPayload, null, 2)}
                        </pre>
                      </div>
                    </TabsContent>
                  </Tabs>
                </div>
              </div>
            </div>
          </div>

          <div className="shrink-0 border-t border-white/10 cyber-panel px-6 py-4">
            <div className="flex w-full items-center justify-between gap-3">
              <div className="text-xs text-slate-400">
                {alert
                  ? "Evidence tabs are populated only when supporting Zeek enrichment exists."
                  : "Cluster details use a representative alert when one is available."}
              </div>

              <Button
                variant="outline"
                className="border-white/10"
                onClick={() => onOpenChange(false)}
              >
                Close Details
              </Button>
            </div>
          </div>
        </div>
      </motion.div>
    </div>,
    document.body
  );
}

/** ================== KPI Tiles ================== **/
function KpiTile({
  label,
  value,
  icon,
  tone,
  helper,
  badge,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  tone: DashboardTone;
  helper?: string;
  badge?: string;
}) {
  const toneClasses = dashboardToneClasses(tone);

  return (
    <Card
      className={cx(
        "cyber-card cyber-glow-border group relative overflow-hidden rounded-3xl border",
        toneClasses.border,
      )}
    >
      <div className="relative p-6">
        <div
          className={cx(
            "pointer-events-none absolute inset-0 opacity-90",
            toneClasses.spotlight
          )}
        />
        <div className={cx("pointer-events-none absolute inset-x-0 top-0 h-px opacity-90", toneClasses.glow)} />
        <div className="relative flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <div className="text-xs font-semibold uppercase tracking-widest text-gray-400">
                {label}
              </div>
              {badge ? (
                <Badge className={cx("border px-2 py-1 text-xs", toneClasses.chip)}>
                  {badge}
                </Badge>
              ) : null}
            </div>
            <div className={cx("mt-4 text-4xl font-bold leading-none tracking-tight", toneClasses.value)}>
              {formatCompactNumber(value)}
            </div>
            {helper ? (
              <div className="mt-3 max-w-[14rem] text-sm leading-relaxed text-gray-300">
                {helper}
              </div>
            ) : null}
          </div>

          <div
            className={cx(
              "shrink-0 flex h-12 w-12 items-center justify-center rounded-2xl border",
              toneClasses.iconWrap
            )}
          >
            {icon}
          </div>
        </div>
      </div>
    </Card>
  );
}

/** ================== Page ================== **/
export function PcapAnalyzerPage() {
  const { language, isRtl } = useLanguage();
  const isArabic = language === "arabic";
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedJobId = (searchParams.get("job") || "").trim();
  const [autoOpenedJobId, setAutoOpenedJobId] = useState<string>("");
  const [lastAnalysis, setLastAnalysis] = useState<string>("—");
  const analysisWorkspaceRef = React.useRef<HTMLDivElement | null>(null);

  const [uploadFile, setUploadFile] = useState<File | null>(null);

  const [confidenceMode, setConfidenceMode] =
    useState<ConfidenceMode>("Balanced");
  const [maxAlerts, setMaxAlerts] = useState<number>(200);
  const [maxClusters, setMaxClusters] = useState<number>(100);
  const [includeZeek, setIncludeZeek] = useState<boolean>(true);

  const [job, setJob] = useState<PcapJob | null>(null);
  const [report, setReport] = useState<PcapReport | null>(null);
  const [running, setRunning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const [clusterSearch, setClusterSearch] = useState("");
  const [alertSearch, setAlertSearch] = useState("");
  const [timelineSearch, setTimelineSearch] = useState("");
  const [clusterSeverityFilter, setClusterSeverityFilter] = useState<
    "all" | Severity
  >("all");
  const [alertDecisionFilter, setAlertDecisionFilter] = useState<
    "all" | Decision
  >("all");

  const [rowsClusters, setRowsClusters] = useState<number>(10);
  const [rowsAlerts, setRowsAlerts] = useState<number>(20);
  const [rowsTimeline, setRowsTimeline] = useState<number>(10);

  const [historyOpen, setHistoryOpen] = useState(false);
  const [jobsHistory, setJobsHistory] = useState<JobHistoryItem[]>([]);
  const [exporting, setExporting] = useState<ExportType | null>(null);
  const [details, setDetails] = useState<DetailsTarget | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const [pollIntervalMs, setPollIntervalMs] = useState<number>(6000);
  const [pollingEnabled, setPollingEnabled] = useState(false);
  const trackedReportJobsRef = React.useRef<Set<string>>(new Set());
  const trackedAlertViewsRef = React.useRef<Set<string>>(new Set());
  const trackedEvidenceOpenRef = React.useRef<Set<string>>(new Set());

  const summary = report?.summary ?? {
    total_flows: 0,
    alerts: 0,
    suspicious: 0,
    suppressed: 0,
    overall_risk: 0,
    risk_level: "Normal" as const,
    risk_context_label: undefined,
    risk_display: undefined,
    security_score: undefined,
    score_explanation: undefined,
    security_score_level: undefined,
    summary: undefined,
    security_summary: undefined,
    security_trend: undefined,
    cluster_count: undefined,
    severity_counts: undefined,
    top_risk: undefined,
  };

  const riskTone = dashboardToneClasses(toneFromRiskLevel(summary.risk_level));

  const appliedConfidenceLabel = useMemo(() => {
    const raw = report?.meta?.pipeline?.confidence_mode;
    const normalized = String(raw ?? "").trim();
    if (!normalized) return undefined;

    const lower = normalized.toLowerCase();
    if (lower === "strict") return "Strict";
    if (lower === "relaxed") return "Relaxed";
    if (lower === "balanced") return "Balanced";

    return normalized.charAt(0).toUpperCase() + normalized.slice(1);
  }, [report]);

  const resetAll = () => {
    setJob(null);
    setReport(null);
    setErr(null);
    setRunning(false);
    setCancelling(false);
    setPollingEnabled(false);
    setClusterSearch("");
    setAlertSearch("");
    setTimelineSearch("");
    setClusterSeverityFilter("all");
    setAlertDecisionFilter("all");
    setDetails(null);
    setHistoryError(null);
    setPollIntervalMs(6000);
  };

  const latestCompletedHistoryJob = useMemo<ExportableJobRef | null>(() => {
    const candidate = jobsHistory.find((item) => {
      const status = normalizeJobStatusValue(item.status);
      return (
        status === "done" &&
        (item.report_available === true || item.evidence_available === true)
      );
    });

    if (!candidate?.job_id) {
      return null;
    }

    return {
      job_id: candidate.job_id,
      status: "done",
      report_available: candidate.report_available === true,
      evidence_available: candidate.evidence_available === true,
    };
  }, [jobsHistory]);

  const selectedExportJob = useMemo<ExportableJobRef | null>(() => {
    if (job?.job_id && job.status === "done") {
      return {
        job_id: job.job_id,
        status: job.status,
        report_available: job.report_available !== false,
        evidence_available: job.evidence_available === true,
      };
    }
    return latestCompletedHistoryJob;
  }, [job, latestCompletedHistoryJob]);

  const canExportReport =
    !!selectedExportJob?.job_id && selectedExportJob.report_available === true;
  const canExportEvidence =
    !!selectedExportJob?.job_id && selectedExportJob.evidence_available === true;

  const currentAlertTarget = () => {
    const selectedAlert =
      details?.kind === "alert"
        ? details.alert
        : details?.kind === "cluster"
        ? details.relatedAlert ?? null
        : null;

    if (!job?.job_id || !selectedAlert?.id) {
      return null;
    }

    return {
      jobId: job.job_id,
      alertId: selectedAlert.id,
    };
  };

  const applyGamificationResult = (result: GamificationEventResponse) => {
    showGamificationToasts(result);
  };

  const trackReportAccess = async (jobId: string) => {
    if (!jobId || trackedReportJobsRef.current.has(jobId)) {
      return;
    }

    trackedReportJobsRef.current.add(jobId);
    try {
      const result = await recordGamificationEvent({
        event_type: "report_accessed",
        job_id: jobId,
        access_method: "in_app_view",
      });
      applyGamificationResult(result);
      await trackActivityEvent({
        module: "pcap",
        action_type: "pcap_report_viewed",
        description: "The analysis report was opened inside the PCAP analyzer workspace.",
        target_type: "pcap_job",
        target_id: jobId,
        target_label: jobId,
        metadata: {
          job_id: jobId,
          access_method: "in_app_view",
        },
      });
    } catch (error) {
      trackedReportJobsRef.current.delete(jobId);
      console.error("Gamification report_accessed failed:", error);
    }
  };

  const handleEvidenceAccess = async (evidenceKey: string) => {
    const target = currentAlertTarget();
    if (!target) {
      return;
    }

    const dedupeKey = `${target.jobId}:${target.alertId}:${evidenceKey}`;
    if (trackedEvidenceOpenRef.current.has(dedupeKey)) {
      return;
    }

    trackedEvidenceOpenRef.current.add(dedupeKey);
    try {
      const result = await recordGamificationEvent({
        event_type: "evidence_accessed",
        job_id: target.jobId,
        alert_id: target.alertId,
        evidence_key: evidenceKey,
        evidence_context: evidenceKey,
        access_method: "in_app_view",
      });
      applyGamificationResult(result);
      await trackActivityEvent({
        module: "pcap",
        action_type: "pcap_evidence_viewed",
        description: "Evidence context was opened from the PCAP analysis details drawer.",
        target_type: "pcap_job",
        target_id: target.jobId,
        target_label: target.jobId,
        metadata: {
          job_id: target.jobId,
          alert_id: target.alertId,
          evidence_key: evidenceKey,
          access_method: "in_app_view",
        },
      });
    } catch (error) {
      trackedEvidenceOpenRef.current.delete(dedupeKey);
      console.error("Gamification evidence_accessed failed:", error);
    }
  };

  const syncDownloadGamificationAccess = (jobId: string, type: ExportType) => {
    const payload =
      type === "evidence"
        ? {
            event_type: "evidence_accessed" as const,
            job_id: jobId,
            evidence_key: "bundle",
            evidence_context: "bundle",
            access_method: "download_success",
          }
        : {
            event_type: "report_accessed" as const,
            job_id: jobId,
            access_method: "download_success",
          };

    void recordGamificationEvent(payload)
      .then((result) => {
        applyGamificationResult(result);
        if (!result.accepted && result.reason === "duplicate_event") {
          broadcastGamificationUpdated();
        }
      })
      .catch((error) => {
        console.error("Gamification download access sync failed:", error);
        broadcastGamificationUpdated();
      });
  };

  const startAnalysis = async () => {
    const validationMessage = getPcapUploadValidationError(uploadFile);
    if (validationMessage) {
      setErr(validationMessage);
      toast.error(validationMessage);
      return;
    }

    setErr(null);
    setReport(null);
    setDetails(null);
    setRunning(true);
    setPollingEnabled(false);
    setPollIntervalMs(6000);

    try {
      const selectedFile = uploadFile as File;

      const fd = new FormData();
      fd.append("file", selectedFile);
      fd.append("confidence_mode", confidenceMode);
      fd.append("max_alerts", String(maxAlerts));
      fd.append("max_clusters", String(maxClusters));
      fd.append("include_zeek", String(includeZeek));

      const res = await fetch(
        API.PCAP_UPLOAD,
        buildAuthedFetchInit({ method: "POST", body: fd })
      );

      const text = await res.text();
      const parsedPayload = tryParseJsonObject(text);
      if (!res.ok) {
        throw new Error(
          getApiErrorMessage(parsedPayload, "Upload failed. Please try again.")
        );
      }
      if (!parsedPayload) {
        throw new Error("Unexpected server response. Please try again.");
      }

      const data = parsedPayload;

      const job_id = String(data.job_id ?? "");
      const nextStatus = normalizeJobStatusValue(data.status);

      setJob({
        job_id,
        status: nextStatus,
        progress: Number(data.progress) || 0,
        current_step: "Queued",
        started_at: new Date().toISOString(),
        duration_s: 0,
        report_available: false,
        evidence_available: false,
      });
      setPollingEnabled(
        nextStatus === "queued" || nextStatus === "running"
      );

      setLastAnalysis(new Date().toLocaleString());
      if (Boolean(data.reused)) {
        toast("Existing PCAP analysis is already running. Reopened the active job.");
      } else {
        toast("PCAP analysis started.");
      }
    } catch (e: unknown) {
      const message =
        e instanceof Error ? e.message : "Failed to start analysis.";
      setErr(message);
      setRunning(false);
      setCancelling(false);
      setPollingEnabled(false);
      toast.error(message);
    }
  };

  const clearCurrentAnalysis = () => {
    setJob(null);
    setReport(null);
    setDetails(null);
    setErr(null);
    setRunning(false);
    setCancelling(false);
    setPollingEnabled(false);
  };

  const cancelPcapAnalysis = async () => {
    if (!job?.job_id || !(job.status === "queued" || job.status === "running")) {
      return;
    }

    setCancelling(true);
    setErr(null);

    try {
      const res = await fetch(
        API.JOB_CANCEL(job.job_id),
        buildAuthedFetchInit({ method: "POST" })
      );
      const text = await res.text();
      const payload = tryParseJsonObject(text);
      const nextStatus = normalizeJobStatusValue(payload?.status);
      const message = getApiErrorMessage(
        payload,
        res.ok ? "Analysis cancelled." : "Unable to cancel analysis right now."
      );

      if (!res.ok) {
        throw new Error(message);
      }

      if (nextStatus === "done") {
        try {
          const statusRes = await fetch(
            API.JOB_POLL(job.job_id),
            buildAuthedFetchInit({ cache: "no-store" })
          );
          const statusPayload = tryParseJsonObject(await statusRes.text());
          if (
            statusRes.ok &&
            statusPayload?.report &&
            typeof statusPayload.report === "object" &&
            !Array.isArray(statusPayload.report)
          ) {
            const rawReport = statusPayload.report as Record<string, unknown>;
            setReport(normalizeReport(rawReport));
            void trackReportAccess(job.job_id);
            syncRecentSecurityAlertCache(rawReport, {
              jobId: job.job_id,
              uploadName: String(statusPayload.original_filename ?? statusPayload.upload_name ?? ""),
              fallbackCreatedAt: String(
                statusPayload.finished_at ??
                  statusPayload.started_at ??
                  statusPayload.created_at ??
                  ""
              ),
              notifyDashboard: true,
            });
          }
        } catch {
          // Keep the completed state visible even if the follow-up report fetch fails.
        }
        setJob((prev) =>
          prev
            ? {
                ...prev,
                status: "done",
                progress: 100,
                message: "Analysis already completed.",
                report_available: true,
              }
            : prev
        );
        setRunning(false);
        setPollingEnabled(false);
        toast("Analysis already completed.");
        return;
      }

      if (nextStatus === "cancelled" && payload?.ok !== false) {
        setJob((prev) =>
          prev
            ? {
                ...prev,
                status: "cancelled",
                message: "Analysis cancelled by user.",
                current_step: "Cancelled",
                error: undefined,
              }
            : prev
        );
        setRunning(false);
        setPollingEnabled(false);
        setReport(null);
        toast.success("Analysis was cancelled.");
        return;
      }

      setErr(message);
      toast(message);
      setPollingEnabled(true);
    } catch (e: unknown) {
      const message =
        e instanceof Error ? e.message : "Unable to cancel analysis right now.";
      setErr(message);
      setPollingEnabled(true);
      toast.error(message);
    } finally {
      setCancelling(false);
    }
  };

  const handleUploadFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const nextFile = event.target.files?.[0] ?? null;
    setUploadFile(nextFile);
    setErr(getPcapUploadValidationError(nextFile));
  };

  useEffect(() => {
    const shouldPoll =
      pollingEnabled &&
      Boolean(job?.job_id) &&
      (job?.status === "queued" || job?.status === "running");
    if (!shouldPoll || !job?.job_id) return;

    const t0 = Date.now();
    const timer = setInterval(async () => {
      try {
        const res = await fetch(API.JOB_POLL(job.job_id), buildAuthedFetchInit());
        const txt = await res.text();

        if (res.status === 429) {
          setPollIntervalMs(8000);
          setJob((prev) =>
            prev
              ? {
                  ...prev,
                  message: "Rate limited — polling set to 8000ms…",
                }
              : prev
          );
          return;
        }

        if (!res.ok) throw new Error(txt || res.statusText);

        let j: Record<string, unknown>;
        try {
          j = JSON.parse(txt);
        } catch {
          throw new Error(
            "Invalid response from server (JSON parse error). The report may contain invalid data."
          );
        }

        const dur = Math.max(0, Math.round((Date.now() - t0) / 1000));
        const nextStatus = normalizeJobStatusValue(j.status);
        const nextMsg = String(j.message ?? "");
        const artifactProtection = normalizeArtifactProtection(
          j.artifact_protection ??
            ((j.report as Record<string, unknown> | undefined)?.meta as
              | Record<string, unknown>
              | undefined)?.artifact_protection
        );

        setJob((prev) =>
          prev
            ? {
                ...prev,
                status: nextStatus,
                progress: typeof j.progress === "number" ? j.progress : prev.progress,
                message: nextMsg,
                current_step: normalizeStepFromMessage(nextMsg),
                started_at: (j.started_at as string | undefined) ?? prev.started_at,
                duration_s: dur,
                error: (j.error as string | undefined) ?? prev.error,
                report_available: Boolean(j.report_available),
                evidence_available: Boolean(j.evidence_available),
                artifact_protection: artifactProtection,
              }
            : prev
        );

        if (nextStatus === "done") {
          clearInterval(timer);
          if (j.report && typeof j.report === "object") {
            const rawReport = j.report as Record<string, unknown>;
            setReport(normalizeReport(rawReport));
        void trackReportAccess(String(j.job_id ?? job?.job_id ?? ""));
            syncRecentSecurityAlertCache(rawReport, {
              jobId: String(j.job_id ?? job?.job_id ?? ""),
              uploadName: String(j.original_filename ?? j.upload_name ?? ""),
              fallbackCreatedAt: String(
                j.finished_at ?? j.started_at ?? j.created_at ?? ""
              ),
              notifyDashboard: true,
            });
          } else if (Boolean(j.report_available)) {
            setErr("PCAP analysis finished, but the report payload could not be loaded.");
            toast.error("PCAP analysis finished, but the report payload is unavailable.");
            setRunning(false);
            playErrorSound();
            return;
          } else {
            setErr(null);
            setReport(null);
            toast("PCAP analysis completed. Saved status is available, but the full report is unavailable for this run.");
          }
          setRunning(false);
          setPollingEnabled(false);
          toast.success("PCAP analysis completed.");
          playSuccessSound();
        }

        if (nextStatus === "cancelled") {
          clearInterval(timer);
          setErr(null);
          setReport(null);
          setRunning(false);
          setCancelling(false);
          setPollingEnabled(false);
          toast("Analysis was cancelled.");
        }

        if (nextStatus === "failed") {
          clearInterval(timer);
          const message = String(j.error ?? "Job failed");
          setErr(message);
          setRunning(false);
          setPollingEnabled(false);
          playErrorSound();

          toast.error(message);
        }
      } catch (e: any) {
        const message = e?.message || "Polling error";
        setErr(message);
        setRunning(false);
        setPollingEnabled(false);
        clearInterval(timer);
        toast.error(message);
      }
    }, pollIntervalMs);

    return () => clearInterval(timer);
  }, [job?.job_id, job?.status, pollIntervalMs, pollingEnabled]);

  const loadHistoryFromBackend = async () => {
    setHistoryLoading(true);
    setHistoryError(null);

    try {
      const res = await fetch(
        API.JOB_HISTORY(50),
        buildAuthedFetchInit({
          cache: "no-store",
        })
      );

      const text = await res.text();

      if (!res.ok) {
        let message = "Failed to load job history.";
        try {
          const payload = JSON.parse(text);
          message = getApiErrorMessage(payload, message);
        } catch {}
        throw new Error(message);
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error("Job history response is not valid JSON.");
      }

      const rawJobs = Array.isArray(parsed)
        ? parsed
        : parsed && typeof parsed === "object" && Array.isArray((parsed as any).jobs)
        ? (parsed as any).jobs
        : parsed && typeof parsed === "object" && Array.isArray((parsed as any).items)
        ? (parsed as any).items
        : [];

      const items: JobHistoryItem[] = (rawJobs as Record<string, unknown>[]).map(
        (item) => ({
          job_id: String(item.job_id ?? ""),
          status: item.status ? String(item.status) : undefined,
          created_at: item.created_at ? String(item.created_at) : undefined,
          started_at: item.started_at ? String(item.started_at) : undefined,
          finished_at: item.finished_at ? String(item.finished_at) : undefined,
          progress: Number(item.progress ?? 0) || 0,
          message: item.message ? String(item.message) : undefined,
          upload_name: item.original_filename
            ? String(item.original_filename)
            : item.upload_name
            ? String(item.upload_name)
            : undefined,
          original_filename: item.original_filename ? String(item.original_filename) : undefined,
          has_upload: Boolean(item.has_upload),
          has_report: Boolean(item.has_report),
          report_available: Boolean(item.report_available),
          evidence_available: Boolean(item.evidence_available),
          artifact_protection: normalizeArtifactProtection(item.artifact_protection),
        })
      );

      setJobsHistory(items);
    } catch (e: any) {
      setJobsHistory([]);
      setHistoryError(e?.message || "Failed to load job history.");
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    if (!historyOpen) return;
    void loadHistoryFromBackend();
  }, [historyOpen]);

  const closeHistoryModal = () => {
    setHistoryOpen(false);
    setHistoryLoading(false);
    setHistoryError(null);
  };

  useEffect(() => {
    if (!historyOpen) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [historyOpen]);

  useEffect(() => {
    if (!historyOpen) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeHistoryModal();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [historyOpen]);

  const downloadJobArtifact = async (
    jobId: string | undefined,
    type: ExportType
  ) => {
    const reportActionError = (message: string | null) => {
      if (historyOpen) {
        setHistoryError(message);
      } else {
        setErr(message);
      }
    };

    if (!jobId) {
      const message = "No completed job selected for export.";
      reportActionError(message);
      toast.error(message);
      return;
    }

    setExporting(type);
    reportActionError(null);

    try {
      const res = await fetch(
        API.JOB_EXPORT(jobId, type),
        buildAuthedFetchInit({
          cache: "no-store",
        })
      );

      if (!res.ok) {
        let message =
          type === "evidence" ? "Evidence export unavailable." : "Report export failed.";
        try {
          const payload = await res.json();
          message = getApiErrorMessage(payload, message);
        } catch {}
        throw new Error(message);
      }

      const fallbackName =
        type === "evidence"
          ? `pcap_evidence_${jobId}.zip`
          : `pcap_report_${jobId}.json`;

      const blob = await res.blob();
      if (!blob || blob.size === 0) {
        throw new Error(
          type === "evidence"
            ? "Evidence export returned an empty file."
            : "Report export returned an empty file."
        );
      }

      const filename = getDownloadFilename(
        res.headers.get("content-disposition"),
        fallbackName
      );

      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      anchor.style.display = "none";
      document.body.appendChild(anchor);
      anchor.click();

      window.setTimeout(() => {
        URL.revokeObjectURL(url);
        anchor.remove();
      }, 1000);

      toast.success(
        type === "evidence" ? "Evidence ZIP downloaded." : "Report JSON downloaded."
      );
      syncDownloadGamificationAccess(jobId, type);
    } catch (e: any) {
      const message =
        e?.message ||
        (type === "evidence"
          ? "Evidence export unavailable."
          : "Report export failed.");
      reportActionError(message);
      toast.error(message);
    } finally {
      setExporting(null);
    }
  };

  const openAlertDetails = (alert: AlertRow) => {
    setDetails({ kind: "alert", alert });
  };

  const findRepresentativeAlert = (cluster: AttackCluster) => {
    const alerts = report?.alerts ?? [];
    return (
      alerts.find(
        (alert) =>
          alert.source_ip === cluster.source_ip &&
          alert.dest_ip === cluster.dest_ip &&
          alert.label.toLowerCase() === cluster.attack_type.toLowerCase()
      ) ??
      alerts.find(
        (alert) =>
          alert.source_ip === cluster.source_ip && alert.dest_ip === cluster.dest_ip
      ) ??
      alerts.find(
        (alert) => alert.label.toLowerCase() === cluster.attack_type.toLowerCase()
      ) ??
      null
    );
  };

  const openClusterDetails = (cluster: AttackCluster) => {
    setDetails({
      kind: "cluster",
      cluster,
      relatedAlert: findRepresentativeAlert(cluster),
    });
  };

  useEffect(() => {
    const selectedAlert =
      details?.kind === "alert"
        ? details.alert
        : details?.kind === "cluster"
        ? details.relatedAlert ?? null
        : null;

    if (!job?.job_id || !selectedAlert?.id) {
      return;
    }

    const dedupeKey = `${job.job_id}:${selectedAlert.id}`;
    if (trackedAlertViewsRef.current.has(dedupeKey)) {
      return;
    }

    trackedAlertViewsRef.current.add(dedupeKey);
    void recordGamificationEvent({
      event_type: "alert_viewed",
      job_id: job.job_id,
      alert_id: selectedAlert.id,
    })
      .then((result) => {
        applyGamificationResult(result);
      })
      .catch((error) => {
        trackedAlertViewsRef.current.delete(dedupeKey);
        console.error("Gamification alert_viewed failed:", error);
      });
  }, [details, job?.job_id]);

  const openHistoricalJob = async (
    jobId: string,
    options: { closeHistory?: boolean; clearQuery?: boolean } = {}
  ) => {
    setErr(null);
    setHistoryError(null);
    setReport(null);
    setDetails(null);

    try {
      const res = await fetch(
        API.JOB_POLL(jobId),
        buildAuthedFetchInit({
          cache: "no-store",
        })
      );
      const text = await res.text();

      if (!res.ok) {
        let message =
          res.status === 404
            ? "This historical job is no longer available on the backend."
            : "Failed to load historical job.";
        try {
          const payload = JSON.parse(text);
          message = getApiErrorMessage(payload, message);
        } catch {}
        throw new Error(message);
      }

      let payload: Record<string, unknown>;
      try {
        payload = JSON.parse(text);
      } catch {
        throw new Error("Historical job response is not valid JSON.");
      }

      const status = normalizeJobStatusValue(payload.status);
      const message = String(payload.message ?? "");

      setJob({
        job_id: jobId,
        status,
        progress: Number(payload.progress) || 0,
        current_step: normalizeStepFromMessage(message),
        message,
        started_at:
          (payload.started_at as string | undefined) ?? new Date().toISOString(),
        duration_s: 0,
        error: payload.error ? String(payload.error) : undefined,
        report_available: Boolean(payload.report_available),
        evidence_available: Boolean(payload.evidence_available),
        artifact_protection: normalizeArtifactProtection(
          payload.artifact_protection ??
            ((payload.report as Record<string, unknown> | undefined)?.meta as
              | Record<string, unknown>
              | undefined)?.artifact_protection
        ),
      });

      const hasInlineReport =
        payload.report && typeof payload.report === "object" && !Array.isArray(payload.report);
      const cachedReport = readPcapReportSnapshot(jobId);

      if (hasInlineReport) {
        const rawReport = payload.report as Record<string, unknown>;
        setReport(normalizeReport(rawReport));
        void trackReportAccess(jobId);
        syncRecentSecurityAlertCache(rawReport, {
          jobId,
          uploadName: String(payload.original_filename ?? payload.upload_name ?? ""),
          fallbackCreatedAt: String(
            payload.finished_at ?? payload.started_at ?? payload.created_at ?? ""
          ),
        });
      } else if (status === "done" && cachedReport) {
        setReport(normalizeReport(cachedReport));
        void trackReportAccess(jobId);
        syncRecentSecurityAlertCache(cachedReport, {
          jobId,
          uploadName: String(payload.original_filename ?? payload.upload_name ?? ""),
          fallbackCreatedAt: String(
            payload.finished_at ?? payload.started_at ?? payload.created_at ?? ""
          ),
        });
      } else if (status === "done" && Boolean(payload.report_available)) {
        throw new Error("Completed job does not have a report artifact.");
      } else if (status === "done") {
        setReport(null);
      }

      setRunning(status === "queued" || status === "running");
      setPollingEnabled(false);
      setLastAnalysis(new Date().toLocaleString());
      if (options.closeHistory !== false) {
        setHistoryOpen(false);
      }
      if (options.clearQuery !== false && requestedJobId === jobId) {
        const nextParams = new URLSearchParams(searchParams);
        nextParams.delete("job");
        setSearchParams(nextParams, { replace: true });
      }

      toast.success(
        status === "done"
          ? hasInlineReport || Boolean(cachedReport)
            ? "Completed report loaded."
            : "Historical job reopened."
          : status === "cancelled"
          ? "Cancelled analysis reopened."
          : "Historical job reopened. Polling resumed."
      );
    } catch (e: any) {
      const message = e?.message || "Failed to load historical job.";
      setHistoryError(message);
      if (options.clearQuery !== false && requestedJobId === jobId) {
        const nextParams = new URLSearchParams(searchParams);
        nextParams.delete("job");
        setSearchParams(nextParams, { replace: true });
      }
      toast.error(message);
      void loadHistoryFromBackend();
    }
  };

  useEffect(() => {
    if (!requestedJobId) {
      if (autoOpenedJobId) {
        setAutoOpenedJobId("");
      }
      return;
    }
    if (requestedJobId === autoOpenedJobId) {
      return;
    }

    setAutoOpenedJobId(requestedJobId);
    void openHistoricalJob(requestedJobId, {
      closeHistory: false,
      clearQuery: true,
    });
  }, [autoOpenedJobId, requestedJobId]);

  useEffect(() => {
    if (!requestedJobId) {
      return;
    }

    const frame = window.requestAnimationFrame(() => {
      analysisWorkspaceRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    });

    return () => window.cancelAnimationFrame(frame);
  }, [requestedJobId, job?.status, report]);

  const executiveSummary = useMemo(() => {
    if (!report) {
      return "Run a PCAP analysis to generate a prioritized security summary, evidence-backed alerts, and exportable artifacts.";
    }

    if (summary.alerts === 0) {
      return `Analyzed ${summary.total_flows} flows. No alert crossed the active promotion threshold, so the capture currently reads as ${summary.risk_level.toLowerCase()} risk.`;
    }

    const topCluster = report.clusters[0];
    if (topCluster) {
      return `Analysis surfaced ${summary.alerts} alert${
        summary.alerts === 1 ? "" : "s"
      } across ${summary.total_flows} flows. Highest observed risk is ${
        summary.risk_level
      }, led by ${topCluster.attack_type} activity from ${topCluster.source_ip} to ${
        topCluster.dest_ip
      } with peak threat confidence ${fmtPct(topCluster.max_threat_confidence)}.`;
    }

    const topAlert = report.alerts[0];
    if (topAlert) {
      return `Analysis surfaced ${summary.alerts} alert${
        summary.alerts === 1 ? "" : "s"
      } across ${summary.total_flows} flows. The leading finding is ${
        topAlert.label
      } from ${topAlert.source_ip} to ${topAlert.dest_ip} at ${fmtPct(
        topAlert.threat_confidence
      )} threat confidence.`;
    }

    return `Analysis completed with ${summary.total_flows} flows processed and an overall risk score of ${fmtScore(
      summary.overall_risk
    )}.`;
  }, [report, summary]);

  const derivedSeverityCounts = useMemo(
    () => deriveSeverityCounts(report, summary.severity_counts),
    [report, summary.severity_counts]
  );

  const securityScore = useMemo(() => {
    if (!report) {
      return calculateSecurityScore([], {
        hasAnalysis: false,
        noDataSummary:
          "No analysis data is available yet. Run a PCAP analysis to calculate a Security Score.",
      });
    }

    const clusterThreats: SecurityScoreThreatInput[] = report.clusters.map((cluster) => ({
      label: cluster.attack_type,
      severity: toSecurityScoreSeverity(cluster.severity),
      confidence: cluster.max_threat_confidence,
      count: cluster.count_flows || 1,
    }));

    const alertThreats: SecurityScoreThreatInput[] = report.alerts.map((alert) => ({
      label: alert.label,
      severity: toSecurityScoreSeverity(alert.severity),
      confidence: alert.threat_confidence || alert.ml_confidence,
      count: 1,
    }));

    const threats = clusterThreats.length > 0 ? clusterThreats : alertThreats;

    return calculateSecurityScore(threats, {
      hasAnalysis: true,
      context: {
        alerts: summary.alerts,
        suspicious: summary.suspicious,
        overallRisk: summary.overall_risk,
        riskLevel: summary.risk_level,
        riskContextLabel: summary.risk_context_label,
        riskDisplay: summary.risk_display,
        totalFlows: summary.total_flows,
        clusterCount: summary.cluster_count ?? report.clusters.length,
        severityCounts: derivedSeverityCounts,
        precomputedScore: summary.security_score,
        precomputedExplanation: summary.score_explanation,
        precomputedLevel: summary.security_score_level,
        precomputedSummary: summary.security_summary ?? summary.summary,
        precomputedTrend: summary.security_trend,
        precomputedTopRisk: summary.top_risk ?? undefined,
      },
      noDataSummary:
        "Analysis completed, but threat details were incomplete. The Security Score will populate when threat data is returned.",
    });
  }, [derivedSeverityCounts, report, summary]);

  const severityBreakdown = useMemo(() => {
    const data = buildSeverityBreakdownData(
      derivedSeverityCounts,
      summary.suppressed,
      report?.timeline
    );

    return {
      data,
      totalThreats: data.reduce((sum, item) => sum + item.value, 0),
    };
  }, [derivedSeverityCounts, report?.timeline, summary.suppressed]);

  const threatBreakdown = useMemo(
    () => buildTopAttackTypeData(report?.clusters, report?.alerts, report?.timeline, 7),
    [report]
  );

  const timelineChart = useMemo(
    () => buildThreatTimelineData(report?.timeline, report?.alerts),
    [report]
  );

  const riskPerIpRows = useMemo(() => deriveRiskPerIpRows(report), [report]);

  const validatedAlertsCount = useMemo(
    () => (report?.alerts ?? []).filter((alert) => alert.validated === true).length,
    [report]
  );

  const confirmedAlertsCount = useMemo(
    () => (report?.alerts ?? []).filter((alert) => alert.decision === "CONFIRMED").length,
    [report]
  );

  const executiveOverview = useMemo(() => {
    const dominantThreat = threatBreakdown.data[0];
    const topRiskIp = riskPerIpRows[0];

    if (!report) {
      return {
        headline: isArabic ? "بانتظار ذكاء المحلل" : "Awaiting analyzer intelligence",
        body: isArabic
          ? "لم يتم تشغيل أي تحليل بعد. ارفع ملف PCAP لإنشاء تنبيهات مسجلة وأدلة زمنية وملخصات جاهزة للمحلل."
          : "No analysis has been run yet. Upload a PCAP file to generate scored alerts, timeline evidence, and analyst-ready summaries.",
        pills: isArabic
          ? ["ارفع ملف PCAP", "شغّل المحلل", "راجع الأدلة المسجلة"]
          : ["Upload a PCAP", "Run the analyzer", "Review scored evidence"],
        insights: [
          {
            label: isArabic ? "الوضع الأمني" : "Security Posture",
            value: isArabic ? "بانتظار التحليل" : "Pending analysis",
            detail: isArabic
              ? "تظهر درجة الوضع الأمني بعد تقييم التهديدات التي يكتشفها المحلل."
              : "A posture score appears after the analyzer evaluates promoted threats.",
            tone: "slate" as DashboardTone,
          },
          {
            label: isArabic ? "تركيز التهديد" : "Threat Focus",
            value: isArabic ? "لا توجد نتائج نشطة" : "No active findings",
            detail: isArabic
              ? "تظهر فئات الهجمات عند عودة النتائج المرفوعة من التحليل."
              : "Attack categories populate when promoted findings are returned.",
            tone: "slate" as DashboardTone,
          },
          {
            label: isArabic ? "تعرض الكيانات" : "Entity Exposure",
            value: isArabic ? "لا توجد عناوين IP ساخنة" : "No IP hotspots",
            detail: isArabic
              ? "يظهر ترتيب المخاطر لكل IP عند تقييم كيانات الشبكة."
              : "Risk-per-IP ranking appears when network entities are scored.",
            tone: "slate" as DashboardTone,
          },
          {
            label: isArabic ? "حالة التحقق" : "Validation State",
            value: isArabic ? "بانتظار الأدلة" : "Awaiting evidence",
            detail: isArabic
              ? "ستظهر حالة التحقق بعد أول تقرير مكتمل."
              : "Validation posture will appear after the first completed report.",
            tone: "slate" as DashboardTone,
          },
        ],
      };
    }

    const validationNarrative =
      validatedAlertsCount > 0
        ? `${formatCountLabel(validatedAlertsCount, "validated alert")} are ready for analyst review.`
        : summary.suppressed > 0
        ? `${formatCountLabel(summary.suppressed, "suppressed result")} were kept out of promoted findings.`
        : `${formatCountLabel(summary.suspicious, "suspicious event")} remain under review.`;

    return {
      headline:
        summary.alerts > 0
          ? `${formatCountLabel(summary.alerts, "promoted finding")} surfaced from ${formatCompactNumber(summary.total_flows)} analyzed flows.`
          : `${formatCompactNumber(summary.total_flows)} flows analyzed with no promoted alerts.`,
      body: executiveSummary,
      pills: [
        `${summary.risk_display ?? summary.risk_level} risk`,
        securityScore.level ? `${securityScore.level} posture` : "Posture pending",
        report.clusters.length > 0
          ? formatCountLabel(report.clusters.length, "attack cluster")
          : "No attack clusters",
      ],
      insights: [
        {
          label: "Highest Observed Risk",
          value: summary.risk_display ?? summary.risk_level,
          detail: securityScore.topThreat
            ? `${securityScore.topThreat.label} at ${fmtPct(
                securityScore.topThreat.confidence
              )} confidence.`
            : "The analyzer did not elevate a dominant threat label.",
          tone: toneFromRiskLevel(summary.risk_level),
        },
        {
          label: "Most Frequent Threat",
          value: dominantThreat?.attack ?? "No promoted category",
          detail: dominantThreat
            ? `${formatCountLabel(dominantThreat.count, "finding")} across the current session.`
            : "Threat categories populate when promoted findings are present.",
          tone: toneFromSeverityValue(dominantThreat?.severity),
        },
        {
          label: "Most Exposed IP",
          value: topRiskIp?.ip ?? "No IP hotspot",
          detail: topRiskIp
            ? `Risk score ${fmtScore(topRiskIp.ip_risk_score, 1)} with ${fmtPct(
                topRiskIp.max_confidence
              )} max confidence.`
            : "Per-IP risk ranking appears after analyzer scoring completes.",
          tone: toneFromSeverityValue(topRiskIp?.top_severity),
        },
        {
          label: "Validation Posture",
          value:
            validatedAlertsCount > 0
              ? formatCountLabel(validatedAlertsCount, "validated alert")
              : summary.suspicious > 0
              ? formatCountLabel(summary.suspicious, "suspicious event")
              : summary.suppressed > 0
              ? formatCountLabel(summary.suppressed, "suppressed result")
              : "No promoted decisions",
          detail: validationNarrative,
          tone:
            validatedAlertsCount > 0
              ? "emerald"
              : summary.suspicious > 0
              ? "amber"
              : "slate",
        },
      ],
    };
  }, [
    executiveSummary,
    report,
    riskPerIpRows,
    securityScore,
    summary,
    threatBreakdown.data,
    validatedAlertsCount,
  ]);

  const completionPercent = useMemo(() => {
    if (!job) return 0;

    const rawProgress = Number(job.progress ?? 0);
    const normalizedProgress = Number.isFinite(rawProgress)
      ? Math.max(0, Math.min(100, rawProgress))
      : 0;

    if (job.status === "done") {
      return 100;
    }

    return normalizedProgress;
  }, [job]);

  const rawArtifactsEncrypted =
    job?.artifact_protection?.enabled === true ||
    report?.meta?.artifact_protection?.enabled === true;

  const progressOverview = useMemo(
    () => [
      {
        label: "Processing Stage",
        value: job?.current_step ?? "Queued",
        detail: job?.message || "Waiting for the next analysis run.",
        tone:
          job?.status === "failed"
            ? ("rose" as DashboardTone)
            : job?.status === "cancelled"
            ? ("slate" as DashboardTone)
            : job?.status === "running"
            ? ("sky" as DashboardTone)
            : report
            ? ("emerald" as DashboardTone)
            : ("slate" as DashboardTone),
      },
      {
        label: "Completion",
        value: `${Math.round(completionPercent)}%`,
        detail: job?.status ? `Job status ${job.status.toUpperCase()}.` : "No active analyzer job.",
        tone:
          job?.status === "failed"
            ? ("rose" as DashboardTone)
            : job?.status === "cancelled"
            ? ("slate" as DashboardTone)
            : job?.status === "done"
            ? ("emerald" as DashboardTone)
            : running
            ? ("amber" as DashboardTone)
            : ("slate" as DashboardTone),
      },
      {
        label: "Artifacts",
        value:
          job?.report_available || report
            ? "Report ready"
            : running
            ? "Generating report"
            : "Awaiting output",
        detail: job?.evidence_available
          ? "Evidence export is available for this job."
          : report
          ? "Evidence exports depend on backend artifacts."
          : "Artifacts appear after analysis completes.",
        tone:
          job?.evidence_available || job?.report_available || report
            ? ("emerald" as DashboardTone)
            : running
            ? ("sky" as DashboardTone)
            : ("slate" as DashboardTone),
          },
    ],
    [completionPercent, job, report, running]
  );

  const clusterOverview = useMemo(() => {
    if (!report || report.clusters.length === 0) {
      return [] as Array<{
        label: string;
        value: string;
        detail: string;
        tone: DashboardTone;
      }>;
    }

    const dominantCluster = [...report.clusters].sort((left, right) => {
      if (right.count_flows !== left.count_flows) {
        return right.count_flows - left.count_flows;
      }
      return right.max_threat_confidence - left.max_threat_confidence;
    })[0];

    const highestConfidenceCluster = [...report.clusters].sort(
      (left, right) => right.max_threat_confidence - left.max_threat_confidence
    )[0];

    return [
      {
        label: "Clusters Identified",
        value: formatCountLabel(report.clusters.length, "cluster"),
        detail: "Clusters group related flow decisions for faster triage.",
        tone: "sky" as DashboardTone,
      },
      {
        label: "Dominant Cluster Type",
        value: dominantCluster.attack_type,
        detail: `${formatCountLabel(
          dominantCluster.count_flows,
          "related flow"
        )} in the largest cluster.`,
        tone: toneFromSeverityValue(dominantCluster.severity),
      },
      {
        label: "Highest Confidence Cluster",
        value: fmtPct(highestConfidenceCluster.max_threat_confidence),
        detail: `${highestConfidenceCluster.attack_type} from ${highestConfidenceCluster.source_ip} to ${highestConfidenceCluster.dest_ip}.`,
        tone: toneFromSeverityValue(highestConfidenceCluster.severity),
      },
    ];
  }, [report]);

  const alertOverview = useMemo(() => {
    if (!report) {
      return [] as Array<{
        label: string;
        value: string;
        detail: string;
        tone: DashboardTone;
      }>;
    }

    const highestSeverity =
      derivedSeverityCounts.critical > 0
        ? "critical"
        : derivedSeverityCounts.high > 0
        ? "high"
        : derivedSeverityCounts.medium > 0
        ? "medium"
        : summary.alerts > 0
        ? "low"
        : "informational";

    return [
      {
        label: "Confirmed Findings",
        value: formatCountLabel(confirmedAlertsCount, "confirmed finding"),
        detail: "Confirmed findings are promoted for immediate analyst review.",
        tone: confirmedAlertsCount > 0 ? ("rose" as DashboardTone) : ("slate" as DashboardTone),
      },
      {
        label: "Validated Decisions",
        value: formatCountLabel(validatedAlertsCount, "validated alert"),
        detail: "Validation reflects findings backed by the current evidence chain.",
        tone: validatedAlertsCount > 0 ? ("emerald" as DashboardTone) : ("slate" as DashboardTone),
      },
      {
        label: "Peak Severity",
        value: highestSeverity === "informational" ? "Informational" : highestSeverity.toUpperCase(),
        detail: `${formatCountLabel(summary.suppressed, "suppressed result")} are currently muted.`,
        tone: toneFromSeverityValue(highestSeverity),
      },
    ];
  }, [
    confirmedAlertsCount,
    derivedSeverityCounts.critical,
    derivedSeverityCounts.high,
    derivedSeverityCounts.medium,
    report,
    summary.alerts,
    summary.suppressed,
    validatedAlertsCount,
  ]);

  const timelineOverview = useMemo(() => {
    if (!report) {
      return [] as Array<{
        label: string;
        value: string;
        detail: string;
        tone: DashboardTone;
      }>;
    }

    const peakBucket =
      timelineChart.data.length > 0
        ? timelineChart.data.reduce((best, bucket) =>
            bucket.threats > best.threats ? bucket : best
          )
        : null;
    const confirmedPeak =
      timelineChart.data.length > 0
        ? timelineChart.data.reduce((best, bucket) =>
            bucket.confirmed > best.confirmed ? bucket : best
          )
        : null;

    return [
      {
        label: "Timeline Buckets",
        value:
          timelineChart.data.length > 0
            ? formatCountLabel(timelineChart.data.length, "bucket")
            : "No chartable buckets",
        detail:
          timelineChart.data.length > 0
            ? "Buckets are derived from the normalized event timestamps."
            : "Timeline insights will appear once time-bucketed events are available.",
        tone: timelineChart.data.length > 0 ? ("sky" as DashboardTone) : ("slate" as DashboardTone),
      },
      {
        label: "Peak Activity Window",
        value: peakBucket?.time ?? "Unavailable",
        detail: peakBucket
          ? `${formatCountLabel(peakBucket.threats, "threat event")} in the busiest bucket.`
          : "No promoted threat activity was charted for this analysis.",
        tone: peakBucket ? ("orange" as DashboardTone) : ("slate" as DashboardTone),
      },
      {
        label: "Confirmed Burst",
        value: confirmedPeak ? formatCountLabel(confirmedPeak.confirmed, "confirmed event") : "0 confirmed events",
        detail: confirmedPeak
          ? `Highest confirmed concentration occurred at ${confirmedPeak.time}.`
          : "Confirmed bursts appear when analyzer events are promoted.",
        tone: confirmedPeak?.confirmed ? ("rose" as DashboardTone) : ("slate" as DashboardTone),
      },
    ];
  }, [report, timelineChart.data]);

  const filteredClusters = useMemo(() => {
    const rows = report?.clusters ?? [];
    return rows.filter(
      (c) =>
        (clusterSeverityFilter === "all" || c.severity === clusterSeverityFilter) &&
        matchesTableSearch(clusterSearch, [
          c.severity,
          c.attack_type,
          c.source_ip,
          c.dest_ip,
          c.count_flows,
          ...c.top_dst_ports.map((item) => item.port),
        ])
    );
  }, [report, clusterSearch, clusterSeverityFilter]);

  const filteredAlerts = useMemo(() => {
    const rows = report?.alerts ?? [];
    return rows.filter((a) => {
      if (alertDecisionFilter !== "all" && a.decision !== alertDecisionFilter) {
        return false;
      }
      return matchesTableSearch(alertSearch, [
        a.time,
        fmtTime(a.time),
        a.source_ip,
        a.dest_ip,
        a.dst_port,
        a.label,
        a.ml_label,
        a.severity,
        a.decision,
        a.reason,
      ]);
    });
  }, [report, alertSearch, alertDecisionFilter]);

  const filteredTimeline = useMemo(() => {
    const raw = (report?.timeline ?? []) as unknown[];
    const rows: TimelineRow[] = Array.isArray(raw)
      ? raw.map((r: unknown, i: number) =>
          normalizeTimelineRow((r as Record<string, unknown>) ?? {}, i)
        )
      : [];
    return rows.filter((t) =>
      matchesTableSearch(timelineSearch, [
        t.time,
        fmtTime(t.time),
        t.source_ip,
        t.dest_ip,
        t.dst_port,
        t.label,
        t.severity,
        t.verdict,
      ])
    );
  }, [report, timelineSearch]);

  const chartLoading = running && !report;
  const chartError = !report ? err : null;

  const historyModal =
    historyOpen && typeof document !== "undefined"
      ? createPortal(
          <div className="fixed inset-0 z-50">
            <div
              className="absolute inset-0 cyber-backdrop"
              onClick={closeHistoryModal}
            />
            <div className="absolute inset-0 z-10 overflow-y-auto">
              <div className="flex min-h-full items-start justify-center p-3 sm:p-6 xl:p-8">
                  <motion.div
                    initial={{ opacity: 0, y: 12, scale: 0.98 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    className="relative flex w-full max-w-6xl flex-col overflow-hidden rounded-3xl border border-white/10 cyber-card shadow-2xl"
                    style={{ height: "min(88vh, 860px)" }}
                  >
                  <div className="shrink-0 border-b border-white/10 cyber-panel px-6 py-5 sm:px-8">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="space-y-2">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-2xl border tone-sky-icon">
                            <History className="w-5 h-5 text-white" />
                          </div>
                          <div>
                            <div className="text-lg font-semibold text-white">
                              Job History
                            </div>
                            <div className="text-sm text-slate-400">
                              Review recent analyzer jobs and export completed artifacts.
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                        <Badge className="border border-white/10 bg-white/5 px-3 py-1 text-slate-200">
                          {historyLoading ? "Loading jobs..." : `${jobsHistory.length} jobs`}
                        </Badge>
                        <Button
                          variant="outline"
                          onClick={() => void loadHistoryFromBackend()}
                          disabled={historyLoading}
                        >
                          <RefreshCw
                            className={cx("w-4 h-4", historyLoading && "animate-spin")}
                          />
                          Refresh
                        </Button>
                        <Button
                          variant="outline"
                          onClick={closeHistoryModal}
                        >
                          <XCircle className="w-4 h-4" />
                          Back to Analyzer
                        </Button>
                      </div>
                    </div>
                  </div>

                  <div className="min-h-0 flex-1 overflow-y-auto cyber-panel px-6 py-5 overscroll-contain sm:px-8 sm:py-6">
                    {historyError && (
                      <div className="mb-4 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
                        <div className="flex items-start gap-3">
                          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                          <div className="space-y-1">
                            <div className="font-medium">Action failed</div>
                            <div className="break-words text-rose-100/90">{historyError}</div>
                          </div>
                        </div>
                      </div>
                    )}

                    {historyLoading ? (
                      <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.03] px-6 py-12 text-center">
                        <div className="text-base font-semibold text-white">
                          Loading job history...
                        </div>
                        <div className="mt-2 text-sm text-slate-400">
                          Fetching persisted jobs from the backend registry.
                        </div>
                      </div>
                    ) : historyError ? null : jobsHistory.length === 0 ? (
                      <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.03] px-6 py-12 text-center">
                        <div className="text-base font-semibold text-white">No jobs found.</div>
                        <div className="mt-2 text-sm text-slate-400">
                          No persisted backend jobs are available yet. Run an analysis to create one.
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {jobsHistory.slice(0, 30).map((j) => {
                          const normalizedStatus = normalizeJobStatusValue(j.status);
                          const canOpenHistory = !!j.job_id;
                          const cardCanExportReport =
                            normalizedStatus === "done" && j.report_available === true;
                          const cardCanExportEvidence =
                            normalizedStatus === "done" && j.evidence_available === true;

                          return (
                            <div
                              key={j.job_id}
                              className="w-full cyber-panel rounded-2xl p-5 shadow-lg sm:p-6"
                            >
                              <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-start">
                                <div className="min-w-0 space-y-3">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
                                      Job
                                    </span>
                                    <span
                                      className={cx(
                                        "inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.16em]",
                                        jobStatusTone(j.status)
                                      )}
                                    >
                                      {j.status ?? "unknown"}
                                    </span>
                                  </div>

                                  <div className="truncate font-mono text-sm text-slate-100">
                                    {j.upload_name || j.job_id}
                                  </div>

                                  <div className="text-xs text-slate-500">{j.job_id}</div>

                                  <div className="flex flex-wrap gap-4 text-xs text-slate-400">
                                    <span>
                                      Started: {j.started_at ? fmtTime(j.started_at) : "—"}
                                    </span>
                                    <span>
                                      Finished: {j.finished_at ? fmtTime(j.finished_at) : "—"}
                                    </span>
                                    <span>Status: {j.status ?? "—"}</span>
                                    {typeof j.progress === "number" ? (
                                      <span>Progress: {j.progress}%</span>
                                    ) : null}
                                  </div>

                                  {j.message ? (
                                    <div className="text-sm text-slate-300">{j.message}</div>
                                  ) : null}
                                </div>

                                <div className="flex flex-wrap items-center gap-2 xl:justify-end">
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className="tone-sky-border"
                                    disabled={!canOpenHistory || historyLoading}
                                    onClick={() => void openHistoricalJob(j.job_id)}
                                  >
                                    {normalizedStatus === "running" ? (
                                      <RefreshCw className="w-4 h-4" />
                                    ) : (
                                      <Eye className="w-4 h-4" />
                                    )}
                                    Open
                                  </Button>

                                  <Button
                                    size="sm"
                                    variant="outline"
                                    disabled={!cardCanExportReport || exporting !== null}
                                    onClick={() => void downloadJobArtifact(j.job_id, "report")}
                                  >
                                    <FileJson className="w-4 h-4" />
                                    Report
                                  </Button>

                                  <Button
                                    size="sm"
                                    variant="outline"
                                    disabled={!cardCanExportEvidence || exporting !== null}
                                    onClick={() =>
                                      void downloadJobArtifact(j.job_id, "evidence")
                                    }
                                  >
                                    <Archive className="w-4 h-4" />
                                    Evidence
                                  </Button>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  <div className="shrink-0 border-t border-white/10 cyber-panel px-6 py-4 sm:px-8">
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                      <div className="flex flex-col gap-1 text-xs text-slate-400">
                        <span>
                          History is loaded from the backend job registry and persisted
                          state files.
                        </span>
                        <span>
                          Evidence export is enabled only for completed jobs with available
                          report and Zeek artifacts.
                        </span>
                      </div>
                      <Button
                        variant="outline"
                        onClick={closeHistoryModal}
                      >
                        <XCircle className="w-4 h-4" />
                        Close History
                      </Button>
                    </div>
                  </div>
                </motion.div>
              </div>
            </div>
          </div>,
          document.body
        )
      : null;

  return (
    <div className="relative space-y-6 pb-4" dir={isRtl ? "rtl" : "ltr"}>
      <div
        className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-96 blur-3xl opacity-80 tone-sky-spotlight"
        aria-hidden="true"
      />
      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
        <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 shadow-lg tone-sky-border">
          <div className="absolute inset-0 tone-sky-spotlight opacity-90" aria-hidden="true" />
          <div className="absolute -right-14 top-4 h-44 w-44 rounded-full bg-purple-500/10 blur-3xl" aria-hidden="true" />
          <CardContent className="relative p-6 sm:p-7">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
              <div className="flex min-w-0 items-start gap-4">
                <div className="flex h-14 w-14 items-center justify-center rounded-3xl border tone-sky-icon">
                  <FileSearch className="h-6 w-6 text-white" />
                </div>
                <div className="min-w-0 max-w-3xl pr-2">
                  <Badge className="border px-3 py-1 text-xs font-semibold uppercase tracking-widest tone-sky-chip">
                    {isArabic ? "مساحة عمل استخبارات الحركة" : "Traffic intelligence workspace"}
                  </Badge>
                  <h1 className="mt-3 text-3xl font-bold tracking-tight text-white sm:text-4xl">
                    Sentinel AI — PCAP Analyzer
                  </h1>
                  <p className="mt-2 max-w-2xl text-sm leading-relaxed text-gray-300 sm:text-base">
                    Job-based analysis • Confidence gate • Validation layer • Evidence
                    view
                  </p>
                  <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
                    <Badge className="border px-3 py-1 text-xs tone-sky-chip">
                      <Activity className="h-4 w-4" />
                      Last analysis: {lastAnalysis}
                    </Badge>
                    <Badge className="border px-3 py-1 text-xs tone-emerald-chip">
                      Demo ready
                    </Badge>
                  </div>
                </div>
              </div>

              <div className="flex shrink-0 flex-wrap items-center gap-2 self-start sm:gap-3 lg:justify-end">
                <Button
                  variant="outline"
                  onClick={resetAll}
                >
                  <TimerReset className="w-4 h-4 mr-2" />
                  New
                </Button>

                <Button
                  variant="outline"
                  onClick={() => setHistoryOpen(true)}
                >
                  <History className="w-4 h-4 mr-2" />
                  History
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 shadow-lg tone-slate-border">
        <div className="pointer-events-none absolute inset-0 tone-slate-spotlight opacity-90" aria-hidden="true" />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-slate-glow opacity-80" aria-hidden="true" />
        <CardContent className="space-y-6 px-6 py-6 sm:px-8 sm:py-7">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="flex min-w-0 items-start gap-4">
              <div className="mt-0.5 flex h-12 w-12 shrink-0 items-center justify-center rounded-3xl border tone-slate-icon">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div className="min-w-0 max-w-5xl space-y-4 pr-1">
                <div className="text-xs font-semibold uppercase tracking-widest text-gray-400">
                  Executive Summary
                </div>
                <div className="text-xl font-semibold leading-relaxed text-white sm:text-2xl">
                  {executiveOverview.headline}
                </div>
                <div className="text-sm leading-relaxed text-gray-200 sm:text-base">
                  {executiveOverview.body}
                </div>
                <div className="flex flex-wrap gap-2">
                  {executiveOverview.pills.map((pill) => (
                    <Badge
                      key={pill}
                      className="border px-3 py-1 text-xs tone-slate-chip"
                    >
                      {pill}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {executiveOverview.insights.map((insight) => (
              <InsightStatCard
                key={insight.label}
                label={insight.label}
                value={insight.value}
                detail={insight.detail}
                tone={insight.tone}
              />
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        <div className="xl:col-span-4">
          <div className="sticky top-6 space-y-6">
            <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 shadow-lg tone-slate-border">
              <div className="pointer-events-none absolute inset-0 tone-slate-spotlight opacity-90" aria-hidden="true" />
              <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-slate-glow opacity-80" aria-hidden="true" />
              <CardHeader className="pb-3">
                <CardTitle className="flex items-start gap-3 text-white">
                  <div className="flex h-12 w-12 items-center justify-center rounded-3xl border tone-slate-icon">
                    <Settings2 className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <div className="text-lg font-semibold text-white">{isArabic ? "لوحة المحلل" : "Analyzer Panel"}</div>
                    <div className="text-xs uppercase tracking-widest text-gray-400">
                      {isArabic ? "إعداد تقييم الالتقاط، والحدود، ومخرجات الأدلة" : "Configure capture scoring, thresholds, and evidence output"}
                    </div>
                  </div>
                </CardTitle>
              </CardHeader>

              <CardContent className="space-y-5">
                <div className="cyber-panel rounded-3xl p-4">
                  <div className="text-sm font-semibold text-white">{isArabic ? "رفع PCAP" : "Upload PCAP"}</div>
                  <div className="mt-2 text-sm leading-relaxed text-gray-300">
                    {isArabic ? "اختر ملف " : "Choose a "}<code className="text-gray-300">.pcap</code>{isArabic ? " أو " : " or "}{" "}
                    <code className="text-gray-300">.pcapng</code> {isArabic ? `ملفًا بحجم لا يتجاوز ${PCAP_MAX_UPLOAD_LABEL}، ثم اضبط خيارات التحليل وشغّل التحليل.` : `file up to ${PCAP_MAX_UPLOAD_LABEL}, configure the analysis options, then run analysis.`}
                  </div>

                  <div className="mt-4 space-y-2">
                    <input
                      className="cyber-file-input"
                      type="file"
                      accept=".pcap,.pcapng"
                      onChange={handleUploadFileChange}
                    />
                    {uploadFile && (
                      <div className="rounded-xl border px-3 py-2 text-xs tone-sky-chip">
                          {uploadFile.name} •{" "}
                          {fmtBytes(uploadFile.size)}
                      </div>
                    )}
                  </div>
                </div>

                <div className="cyber-panel rounded-3xl p-4 space-y-4">
                  <div className="text-sm font-semibold text-white">
                    {isArabic ? "خيارات متقدمة" : "Advanced Options"}
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-sm text-gray-200 flex items-center gap-2">
                        <Fingerprint className="h-4 w-4 text-indigo-400" />
                        {isArabic ? "وضع الثقة" : "Confidence Mode"}
                      </div>
                      <Badge
                        className={cx(
                          "border px-3 py-1 text-xs",
                          appliedConfidenceLabel ? "tone-emerald-chip" : "tone-slate-chip"
                        )}
                      >
                        {appliedConfidenceLabel
                          ? `${isArabic ? "مُطبّق" : "Applied"}: ${appliedConfidenceLabel}`
                          : `${isArabic ? "المحدد" : "Selected"}: ${confidenceMode}`}
                      </Badge>
                    </div>
                    <Select
                      value={confidenceMode}
                      onValueChange={(value: ConfidenceMode) => setConfidenceMode(value)}
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder={isArabic ? "وضع الثقة" : "Confidence Mode"} />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Strict">Strict</SelectItem>
                        <SelectItem value="Balanced">Balanced</SelectItem>
                        <SelectItem value="Relaxed">Relaxed</SelectItem>
                      </SelectContent>
                    </Select>
                    <div className="text-xs text-gray-400">
                      {isArabic ? "الوضع الصارم يقلل الإيجابيات الكاذبة. والوضع المرن يرفع عدد النتائج." : "Strict reduces false positives. Relaxed promotes more findings."}
                      {" "}
                      {isArabic ? "يُطبَّق عند بدء تحليل جديد." : "Applies when you start a new analysis."}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <div className="text-xs text-gray-400">{isArabic ? "أقصى عدد للتنبيهات" : "Max Alerts"}</div>
                      <Input
                        type="number"
                        value={maxAlerts}
                        onChange={(e) => setMaxAlerts(Number(e.target.value || 0))}
                      />
                    </div>
                    <div className="space-y-1">
                      <div className="text-xs text-gray-400">{isArabic ? "أقصى عدد للتجميعات" : "Max Clusters"}</div>
                      <Input
                        type="number"
                        value={maxClusters}
                        onChange={(e) => setMaxClusters(Number(e.target.value || 0))}
                      />
                    </div>
                  </div>

                  <label className="cyber-panel-soft flex items-center gap-2 rounded-2xl border px-3 py-2 text-sm text-white tone-emerald-border">
                    <input
                      className="h-4 w-4 rounded border-white/20"
                      type="checkbox"
                      checked={includeZeek}
                      onChange={() => setIncludeZeek((v) => !v)}
                      style={{ accentColor: "#34d399" }}
                    />
                    {isArabic ? "تضمين أدلة Zeek" : "Include Zeek Evidence"}
                  </label>
                </div>

                {err && (
                  <div className="rounded-2xl border p-3 text-sm flex items-start gap-2 tone-rose-chip">
                    <AlertTriangle className="w-4 h-4 mt-0.5" />
                    <span className="break-words">{err}</span>
                  </div>
                )}

                <div className="flex flex-col gap-2 sm:flex-row">
                  <Button
                    onClick={startAnalysis}
                    disabled={running || cancelling}
                    size="lg"
                    className="flex-1"
                  >
                    {running || cancelling ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                        {cancelling ? "Cancelling..." : "Running..."}
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 mr-2" />
                        {isArabic ? "تحليل PCAP" : "Analyze PCAP"}
                      </>
                    )}
                  </Button>

                  {job && (job.status === "queued" || job.status === "running") ? (
                    <Button
                      onClick={() => void cancelPcapAnalysis()}
                      disabled={cancelling}
                      size="lg"
                      variant="outline"
                      className="tone-rose-border"
                    >
                      {cancelling ? (
                        <>
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                          Cancelling...
                        </>
                      ) : (
                        <>
                          <XCircle className="w-4 h-4 mr-2" />
                          Cancel Analysis
                        </>
                      )}
                    </Button>
                  ) : job ? (
                    <Button
                      onClick={clearCurrentAnalysis}
                      size="lg"
                      variant="outline"
                      className="tone-slate-border"
                    >
                      <XCircle className="w-4 h-4 mr-2" />
                      Clear
                    </Button>
                  ) : null}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        <div
          id="analysis-workspace"
          ref={analysisWorkspaceRef}
          className="xl:col-span-8 space-y-6 scroll-mt-24"
        >
          <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 shadow-lg tone-sky-border">
            <div className="pointer-events-none absolute inset-0 tone-sky-spotlight opacity-90" aria-hidden="true" />
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-sky-glow opacity-80" aria-hidden="true" />
            <CardHeader className="pb-3">
              <CardTitle className="flex flex-col gap-3 text-white xl:flex-row xl:items-center xl:justify-between">
                <div className="flex items-start gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-3xl border tone-sky-icon">
                    <Activity className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <div className="text-lg font-semibold text-white">{isArabic ? "التقدّم" : "Progress"}</div>
                    <div className="text-xs uppercase tracking-widest text-gray-400">
                      {isArabic ? "قياسات المهمة المباشرة وجاهزية المخرجات" : "Live job telemetry and artifact readiness"}
                    </div>
                  </div>
                </div>

                <Badge
                  className={cx(
                    "border px-3 py-1 text-xs font-semibold uppercase tracking-widest",
                    job?.status === "done"
                      ? "tone-emerald-chip"
                      : job?.status === "cancelled"
                      ? "tone-slate-chip"
                      : job?.status === "running"
                      ? "tone-amber-chip"
                      : job?.status === "failed"
                      ? "tone-rose-chip"
                      : "tone-slate-chip"
                  )}
                >
                  <span
                    className={cx(
                      "inline-block w-2 h-2 rounded-full mr-2",
                      job?.status === "running"
                        ? "bg-emerald-400"
                        : job?.status === "cancelled"
                        ? "bg-slate-400"
                        : job?.status === "failed"
                        ? "bg-red-400"
                        : "bg-blue-400"
                    )}
                  />
                  {job?.status ? job.status.toUpperCase() : "IDLE"}
                </Badge>
                {rawArtifactsEncrypted ? (
                  <Badge className="border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-widest text-emerald-100">
                    <ShieldCheck className="mr-2 h-3.5 w-3.5" />
                    Raw artifacts encrypted at rest
                  </Badge>
                ) : null}
              </CardTitle>
            </CardHeader>

            <CardContent className="space-y-4">
              <div className="cyber-panel rounded-3xl p-4">
                <Progress value={completionPercent} className="h-3 rounded-full" />
                <div className="mt-4 flex flex-wrap items-center justify-between gap-2 text-sm">
                <div className="text-gray-300">
                  {job ? (
                    <>
                      <span className="text-white font-medium">
                        {job.message || "Running…"}
                      </span>
                      <span className="text-gray-400 ml-2">Job:</span>{" "}
                      <span className="font-mono text-indigo-400">{job.job_id}</span>
                    </>
                  ) : (
                    <span className="text-gray-400">Waiting for analysis…</span>
                  )}
                </div>
                <div className="text-gray-400 text-xs">
                  Started: {job?.started_at ? fmtTime(job.started_at) : "—"} •
                  Duration: {job?.duration_s ?? 0}s • Poll: {pollIntervalMs}ms
                </div>
              </div>
              </div>

              <div className="grid gap-3 md:grid-cols-3">
                {progressOverview.map((item) => (
                  <InsightStatCard
                    key={item.label}
                    label={item.label}
                    value={item.value}
                    detail={item.detail}
                    tone={item.tone}
                  />
                ))}
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <SecurityScoreCard result={securityScore} />
            <SeverityBreakdownCard
              data={severityBreakdown.data}
              total={severityBreakdown.totalThreats}
              loading={chartLoading}
              error={chartError}
              hasAnalysis={Boolean(report)}
            />
          </div>

          <ThreatBreakdownCard
            data={threatBreakdown.data}
            totalThreats={threatBreakdown.totalThreats}
            summaryText={threatBreakdown.summaryText}
            loading={chartLoading}
            error={chartError}
            hasAnalysis={Boolean(report)}
          />

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
            <KpiTile
              label="Total Flows"
              value={summary.total_flows}
              icon={<Network className="w-6 h-6 text-blue-300" />}
              tone="sky"
              helper="Analyzed network conversations observed in the current capture."
              badge={report ? "Capture volume" : "Awaiting PCAP"}
            />
            <KpiTile
              label="Alerts"
              value={summary.alerts}
              icon={<Shield className="w-6 h-6 text-orange-400" />}
              tone={summary.alerts > 0 ? "orange" : "emerald"}
              helper="Promoted findings returned by the analyzer scoring pipeline."
              badge={summary.alerts > 0 ? "Needs review" : "No promoted alerts"}
            />
            <KpiTile
              label="Suspicious"
              value={summary.suspicious}
              icon={<AlertTriangle className="w-6 h-6 text-yellow-400" />}
              tone="amber"
              helper="Events still pending validation or analyst escalation."
              badge={summary.suspicious > 0 ? "Watchlist" : "No pending events"}
            />

            <Card
              className={cx(
                "cyber-card cyber-glow-border group relative overflow-hidden rounded-3xl border shadow-lg",
                riskTone.border,
              )}
            >
              <div className="relative p-6">
                <div
                  className={cx("pointer-events-none absolute inset-0 opacity-90", riskTone.spotlight)}
                  aria-hidden="true"
                />
                <div
                  className={cx("pointer-events-none absolute inset-x-0 top-0 h-px opacity-90", riskTone.glow)}
                  aria-hidden="true"
                />
                <div className="relative flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                      Risk Level
                    </div>
                    <div className="mt-2">
                      <RiskPill
                        level={summary.risk_level}
                        displayLabel={summary.risk_display ?? summary.risk_level}
                      />
                    </div>
                    <div className="mt-4 text-xs text-slate-400">Overall risk score</div>
                    <div
                      className={cx(
                        "mt-1 text-[2.6rem] font-bold leading-none tracking-tight",
                        riskTone.value
                      )}
                    >
                      {fmtScore(summary.overall_risk)}
                    </div>
                    <div className="mt-3 text-xs leading-5 text-slate-300">
                      {securityScore.topThreat
                        ? `${securityScore.topThreat.label} is currently the top contributing risk.`
                        : "Risk posture will sharpen as promoted threats accumulate."}
                    </div>
                  </div>
                  <div
                    className={cx(
                      "shrink-0 flex h-12 w-12 items-center justify-center rounded-[1.1rem] border shadow-lg",
                      riskTone.iconWrap
                    )}
                  >
                    <Fingerprint className="w-6 h-6 text-indigo-50" />
                  </div>
                </div>
              </div>
            </Card>
          </div>

          <RiskPerIpCard rows={riskPerIpRows} />

          <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 shadow-lg tone-orange-border">
            <div className="pointer-events-none absolute inset-0 tone-orange-spotlight opacity-90" aria-hidden="true" />
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-orange-glow opacity-80" aria-hidden="true" />
            <CardHeader className="pb-2">
              <CardTitle className="flex flex-col gap-4 text-white xl:flex-row xl:items-center xl:justify-between">
                <div className="flex items-start gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-3xl border tone-orange-icon">
                    <Layers className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="text-lg font-semibold text-white">{isArabic ? "تجميعات الهجمات" : "Attack Clusters"}</div>
                    <div className="text-[11px] uppercase tracking-[0.24em] text-slate-400">
                      {isArabic ? "أنماط هجمات مترابطة مجمعة من أدلة التدفق المقيمة" : "Correlated attack patterns grouped from scored flow evidence"}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <Input
                      className="w-64 pl-9"
                      placeholder={isArabic ? "ابحث عن المصدر أو الهدف أو المنفذ أو الهجوم..." : "Search source, target, port, attack..."}
                      value={clusterSearch}
                      onChange={(e) => setClusterSearch(e.target.value)}
                    />
                  </div>

                  <Select
                    value={clusterSeverityFilter}
                    onValueChange={(value: "all" | Severity) =>
                      setClusterSeverityFilter(value)
                    }
                  >
                    <SelectTrigger className="w-[150px]">
                      <Filter className="mr-2 h-4 w-4 text-slate-400" />
                      <SelectValue placeholder="Severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">{isArabic ? "كل الشدات" : "All Severities"}</SelectItem>
                      <SelectItem value="CRITICAL">Critical</SelectItem>
                      <SelectItem value="HIGH">High</SelectItem>
                      <SelectItem value="MEDIUM">Medium</SelectItem>
                      <SelectItem value="INFO">Info</SelectItem>
                    </SelectContent>
                  </Select>

                  <Badge variant="outline" className="tone-orange-chip">
                    {isArabic ? `${filteredClusters.length} نتائج` : `${filteredClusters.length} matches`}
                  </Badge>

                  <Select
                    value={String(rowsClusters)}
                    onValueChange={(v: string) => setRowsClusters(Number(v))}
                  >
                    <SelectTrigger className="w-[120px]">
                      <SelectValue placeholder="Rows" />
                    </SelectTrigger>
                    <SelectContent>
                      {TABLE_ROW_OPTIONS.map((count) => (
                        <SelectItem key={`cluster-rows-${count}`} value={String(count)}>
                          {isArabic ? `الصفوف: ${count}` : `Rows: ${count}`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </CardTitle>
            </CardHeader>

            <CardContent>
              <div className="mb-3 flex items-center justify-between gap-3 text-xs text-slate-400">
                <span>
                  {isArabic ? "اضغط على صف من التجميعات لفحص التدفق التمثيلي ومسار الأدلة." : "Click a cluster row to inspect the representative flow and evidence trail."}
                  trail.
                </span>
                {clusterSearch || clusterSeverityFilter !== "all" ? (
                  <button
                    type="button"
                    className="text-orange-200 transition hover:text-orange-100"
                    onClick={() => {
                      setClusterSearch("");
                      setClusterSeverityFilter("all");
                    }}
                  >
                    Clear cluster filters
                  </button>
                ) : null}
              </div>

              {clusterOverview.length > 0 ? (
                <div className="mb-4 grid gap-3 md:grid-cols-3">
                  {clusterOverview.map((item) => (
                    <InsightStatCard
                      key={item.label}
                      label={item.label}
                      value={item.value}
                      detail={item.detail}
                      tone={item.tone}
                    />
                  ))}
                </div>
              ) : null}

              <div className="cyber-panel overflow-hidden rounded-[1.35rem]">
                <div className="overflow-x-auto min-h-[220px]">
                  <Table>
                    <TableHeader className="sticky top-0 z-10 cyber-table-head">
                      <TableRow className="border-gray-800">
                        <TableHead className="text-gray-300">Severity</TableHead>
                        <TableHead className="text-gray-300">Attack Type</TableHead>
                        <TableHead className="text-gray-300">Source IP</TableHead>
                        <TableHead className="text-gray-300">Destination IP</TableHead>
                        <TableHead className="text-gray-300">Count Flows</TableHead>
                        <TableHead className="text-gray-300">
                          Max Threat Confidence
                        </TableHead>
                      </TableRow>
                    </TableHeader>

                    <TableBody>
                      {!report && (
                        <TableRow className="border-gray-800">
                          <TableCell colSpan={6} className="py-10 text-center">
                            <ChartEmptyState
                              title={isArabic ? "لم يتم تشغيل أي تحليل بعد." : "No analysis has been run yet."}
                              description={isArabic ? "ارفع ملف PCAP لتوليد أنماط هجوم مجمعة وتدفقات تمثيلية." : "Upload a PCAP file to generate clustered attack patterns and representative flows."}
                              className="min-h-[180px] border-0 bg-transparent px-0 py-0"
                            />
                          </TableCell>
                        </TableRow>
                      )}

                      {report && filteredClusters.length === 0 && (
                        <TableRow className="border-gray-800">
                          <TableCell colSpan={6} className="py-10 text-center">
                            <ChartEmptyState
                              title="No attack clusters detected."
                              description="This analysis did not produce correlated cluster patterns under the current confidence thresholds."
                              className="min-h-[180px] border-0 bg-transparent px-0 py-0"
                            />
                          </TableCell>
                        </TableRow>
                      )}

                      {report &&
                        filteredClusters.length > 0 &&
                        filteredClusters.slice(0, rowsClusters).map((c) => (
                          <TableRow
                            key={`${c.id}-${c.source_ip}-${c.dest_ip}`}
                            className="cursor-pointer border-gray-800/80 transition-colors hover:bg-orange-500/[0.08]"
                            onClick={() => openClusterDetails(c)}
                          >
                            <TableCell>
                              <SevBadge s={c.severity} />
                            </TableCell>
                            <TableCell className="text-white font-medium">
                              {c.attack_type}
                            </TableCell>
                            <TableCell className="text-gray-200 font-mono">
                              {c.source_ip}
                            </TableCell>
                            <TableCell className="text-gray-200 font-mono">
                              {c.dest_ip}
                            </TableCell>
                            <TableCell className="text-gray-200">
                              {c.count_flows}
                            </TableCell>
                            <TableCell className="text-gray-200">
                              <div className="flex items-center justify-between gap-3">
                                <span>{fmtPct(c.max_threat_confidence)}</span>
                                <span className="inline-flex items-center gap-1 text-xs text-orange-200">
                                  Inspect <Eye className="h-3.5 w-3.5" />
                                </span>
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

          <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 shadow-lg tone-rose-border">
            <div className="pointer-events-none absolute inset-0 tone-rose-spotlight opacity-90" aria-hidden="true" />
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-rose-glow opacity-80" aria-hidden="true" />
            <CardHeader className="pb-2">
              <CardTitle className="flex flex-col gap-3 text-white xl:flex-row xl:items-center xl:justify-between">
                <div className="flex items-start gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-3xl border tone-rose-icon">
                    <AlertTriangle className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="text-lg font-semibold text-white">{isArabic ? "تفاصيل التنبيهات" : "Alerts Drilldown"}</div>
                    <div className="text-[11px] uppercase tracking-[0.24em] text-slate-400">
                      {isArabic ? "النتائج المرفوعة، وحالات القرار، والمبررات الداعمة" : "Promoted findings, decision states, and supporting rationale"}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <div className="relative">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <Input
                      className="w-64 pl-9"
                      placeholder={isArabic ? "ابحث عن IP أو التسمية أو السبب أو المضيف..." : "Search IP, label, reason, host..."}
                      value={alertSearch}
                      onChange={(e) => setAlertSearch(e.target.value)}
                    />
                  </div>

                  <Select
                    value={alertDecisionFilter}
                    onValueChange={(value: "all" | Decision) =>
                      setAlertDecisionFilter(value)
                    }
                  >
                    <SelectTrigger className="w-[160px]">
                      <Filter className="mr-2 h-4 w-4 text-slate-400" />
                      <SelectValue placeholder="Decision" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">{isArabic ? "كل القرارات" : "All Decisions"}</SelectItem>
                      <SelectItem value="CONFIRMED">Confirmed</SelectItem>
                      <SelectItem value="SUSPICIOUS">Suspicious</SelectItem>
                      <SelectItem value="IGNORED">Ignored</SelectItem>
                      <SelectItem value="DROPPED">Dropped</SelectItem>
                    </SelectContent>
                  </Select>

                  <Badge variant="outline" className="tone-rose-chip">
                    {isArabic ? `${filteredAlerts.length} نتائج` : `${filteredAlerts.length} matches`}
                  </Badge>
                  <Badge variant="outline" className="tone-orange-chip">
                    {isArabic ? `المخفية: ${summary.suppressed}` : `Suppressed: ${summary.suppressed}`}
                  </Badge>

                  <Select
                    value={String(rowsAlerts)}
                    onValueChange={(v: string) => setRowsAlerts(Number(v))}
                  >
                    <SelectTrigger className="w-[120px]">
                      <SelectValue placeholder="Rows" />
                    </SelectTrigger>
                    <SelectContent>
                      {TABLE_ROW_OPTIONS.map((count) => (
                        <SelectItem key={`alert-rows-${count}`} value={String(count)}>
                          {isArabic ? `الصفوف: ${count}` : `Rows: ${count}`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </CardTitle>
            </CardHeader>

            <CardContent>
              <div className="mb-3 flex items-center justify-between gap-3 text-xs text-slate-400">
                <span>
                  {isArabic ? "اضغط على صف تنبيه لفحص سلسلة الاستدلال، وتبويبات الأدلة، وبيانات JSON الخام." : "Click an alert row to inspect the reasoning chain, evidence tabs, and raw JSON."}
                </span>
                {alertSearch || alertDecisionFilter !== "all" ? (
                  <button
                    type="button"
                    className="text-rose-200 transition hover:text-rose-100"
                    onClick={() => {
                      setAlertSearch("");
                      setAlertSearch("");
                      setAlertDecisionFilter("all");
                    }}
                  >
                    Clear alert filters
                  </button>
                ) : null}
              </div>

              {alertOverview.length > 0 ? (
                <div className="mb-4 grid gap-3 md:grid-cols-3">
                  {alertOverview.map((item) => (
                    <InsightStatCard
                      key={item.label}
                      label={item.label}
                      value={item.value}
                      detail={item.detail}
                      tone={item.tone}
                    />
                  ))}
                </div>
              ) : null}

              <div className="cyber-panel overflow-hidden rounded-[1.35rem]">
                <div className="overflow-x-auto min-h-[240px]">
                  <Table>
                    <TableHeader className="sticky top-0 z-10 cyber-table-head">
                      <TableRow className="border-gray-800">
                        <TableHead className="text-gray-300">Time</TableHead>
                        <TableHead className="text-gray-300">
                          Source → Destination
                        </TableHead>
                        <TableHead className="text-gray-300">Dst Port</TableHead>
                        <TableHead className="text-gray-300">Label</TableHead>
                        <TableHead className="text-gray-300">
                          Threat Confidence
                        </TableHead>
                        <TableHead className="text-gray-300">Severity</TableHead>
                        <TableHead className="text-gray-300">Decision</TableHead>
                        <TableHead className="text-gray-300">Reason</TableHead>
                      </TableRow>
                    </TableHeader>

                    <TableBody>
                      {!report && (
                        <TableRow className="border-gray-800">
                          <TableCell colSpan={8} className="py-10 text-center">
                            <ChartEmptyState
                              title={isArabic ? "لم يتم تشغيل أي تحليل بعد." : "No analysis has been run yet."}
                              description={isArabic ? "شغّل تحليل PCAP لملء التنبيهات المقيمة، وسلاسل الأدلة، وقرارات التحقق." : "Run a PCAP analysis to populate scored alerts, evidence chains, and validation decisions."}
                              className="min-h-[180px] border-0 bg-transparent px-0 py-0"
                            />
                          </TableCell>
                        </TableRow>
                      )}

                      {report && filteredAlerts.length === 0 && (
                        <TableRow className="border-gray-800">
                          <TableCell colSpan={8} className="py-10 text-center">
                            <ChartEmptyState
                              title={isArabic ? "لا توجد تنبيهات مرفوعة متاحة." : "No promoted alerts are available."}
                              description={isArabic ? "لم ينتج هذا التحليل تنبيهات لمجموعة المرشحات الحالية أو حدود الثقة الحالية." : "This analysis did not produce alerts for the current filter set or confidence thresholds."}
                              className="min-h-[180px] border-0 bg-transparent px-0 py-0"
                            />
                          </TableCell>
                        </TableRow>
                      )}

                      {report &&
                        filteredAlerts.length > 0 &&
                        filteredAlerts.slice(0, rowsAlerts).map((a) => (
                          <TableRow
                            key={a.id}
                            className="cursor-pointer border-gray-800/80 transition-colors hover:bg-rose-500/[0.08]"
                            onClick={() => openAlertDetails(a)}
                          >
                            <TableCell className="text-gray-200">
                              {fmtTime(a.time)}
                            </TableCell>
                            <TableCell className="text-gray-200 font-mono">
                              {a.source_ip} → {a.dest_ip}
                            </TableCell>
                            <TableCell className="text-gray-200">{a.dst_port}</TableCell>
                            <TableCell className="text-white font-medium">{a.label}</TableCell>
                            <TableCell className="text-gray-200">
                              {fmtPct(a.threat_confidence)}
                            </TableCell>
                            <TableCell>
                              <SevBadge s={a.severity} />
                            </TableCell>
                            <TableCell>
                              <DecisionBadge d={a.decision} />
                            </TableCell>
                            <TableCell className="text-gray-300 max-w-[420px]">
                              <div className="truncate" title={a.reason}>
                                {a.reason}
                              </div>
                              <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                                <ValidationBadge validated={a.validated} />
                                {!!a.evidence_refs?.length && (
                                  <span>• Evidence: {a.evidence_refs.length}</span>
                                )}
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

          <Card className="cyber-card cyber-glow-border relative overflow-hidden rounded-3xl border border-white/10 shadow-lg tone-sky-border">
            <div className="pointer-events-none absolute inset-0 tone-sky-spotlight opacity-90" aria-hidden="true" />
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px tone-sky-glow opacity-80" aria-hidden="true" />
            <CardHeader className="pb-2">
              <CardTitle className="flex flex-col gap-3 text-white xl:flex-row xl:items-center xl:justify-between">
                <div className="flex items-start gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-3xl border tone-sky-icon">
                    <Activity className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="text-lg font-semibold text-white">{isArabic ? "الخط الزمني للنشاط" : "Activity Timeline"}</div>
                    <div className="text-[11px] uppercase tracking-[0.24em] text-slate-400">
                      {isArabic ? "نشاط المحلل المجمع زمنيًا والمربوط بالأحداث المرفوعة" : "Time-bucketed analyzer activity mapped to promoted events"}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <div className="relative">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <Input
                      className="w-64 pl-9"
                      placeholder={isArabic ? "ابحث عن الوقت أو IP أو المنفذ أو التسمية أو الشدة..." : "Search time, IP, port, label, severity..."}
                      value={timelineSearch}
                      onChange={(e) => setTimelineSearch(e.target.value)}
                    />
                  </div>

                  <Badge variant="outline" className="tone-sky-chip">
                    {isArabic ? `${filteredTimeline.length} نتائج` : `${filteredTimeline.length} matches`}
                  </Badge>

                  <Select
                    value={String(rowsTimeline)}
                    onValueChange={(v: string) => setRowsTimeline(Number(v))}
                  >
                    <SelectTrigger className="w-[120px]">
                      <SelectValue placeholder="Rows" />
                    </SelectTrigger>
                    <SelectContent>
                      {TABLE_ROW_OPTIONS.map((count) => (
                        <SelectItem
                          key={`timeline-rows-${count}`}
                          value={String(count)}
                        >
                          {isArabic ? `الصفوف: ${count}` : `Rows: ${count}`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </CardTitle>
            </CardHeader>

            <CardContent>
              <div className="mb-3 flex items-center justify-between gap-3 text-xs text-slate-400">
                <span>
                  {isArabic ? "راجع قرارات التدفق المرتبة زمنيًا الناتجة عن التحليل الحالي." : "Review the time-ordered flow decisions generated by the current analysis."}
                </span>
                {timelineSearch ? (
                  <button
                    type="button"
                    className="text-sky-200 transition hover:text-sky-100"
                    onClick={() => setTimelineSearch("")}
                  >
                    Clear timeline search
                  </button>
                ) : null}
              </div>


              {timelineOverview.length > 0 ? (
                <div className="mb-4 grid gap-3 md:grid-cols-3">
                  {timelineOverview.map((item) => (
                    <InsightStatCard
                      key={item.label}
                      label={item.label}
                      value={item.value}
                      detail={item.detail}
                      tone={item.tone}
                    />
                  ))}
                </div>
              ) : null}

              <ThreatActivityAreaChart
                data={timelineChart.data}
                loading={chartLoading}
                error={chartError}
                hasAnalysis={Boolean(report)}
                hasSourceData={timelineChart.hasSourceData}
                className="mb-4"
              />

              <div className="cyber-panel overflow-hidden rounded-[1.35rem]">
                <div className="overflow-x-auto min-h-[220px]">
                  <Table>
                    <TableHeader className="sticky top-0 z-10 cyber-table-head">
                      <TableRow className="border-gray-800">
                        <TableHead className="text-gray-300">Time</TableHead>
                        <TableHead className="text-gray-300">
                          Source → Destination
                        </TableHead>
                        <TableHead className="text-gray-300">Dst Port</TableHead>
                        <TableHead className="text-gray-300">Label</TableHead>
                        <TableHead className="text-gray-300">
                          Threat Confidence
                        </TableHead>
                        <TableHead className="text-gray-300">Severity</TableHead>
                        <TableHead className="text-gray-300">Verdict</TableHead>
                      </TableRow>
                    </TableHeader>

                    <TableBody>
                      {!report && (
                        <TableRow className="border-gray-800">
                          <TableCell colSpan={7} className="py-10 text-center">
                            <ChartEmptyState
                              title={isArabic ? "لم يتم تشغيل أي تحليل بعد." : "No analysis has been run yet."}
                              description={isArabic ? "ستظهر رؤى الخط الزمني بمجرد أن يعيد المحلل أحداثًا مرتبة زمنيًا." : "Timeline insights will appear once the analyzer returns time-ordered events."}
                              className="min-h-[180px] border-0 bg-transparent px-0 py-0"
                            />
                          </TableCell>
                        </TableRow>
                      )}

                      {report && filteredTimeline.length === 0 && (
                        <TableRow className="border-gray-800">
                          <TableCell colSpan={7} className="py-10 text-center">
                            <ChartEmptyState
                              title={isArabic ? "لا توجد بيانات خط زمني متاحة لهذا التحليل." : "No timeline data available for this analysis."}
                              description={isArabic ? "لم يتم إرجاع أي أحداث خط زمني قابلة للعرض أو البحث لهذا التحليل أو مجموعة الفلاتر الحالية." : "No chartable or searchable timeline events were returned for the current analysis or filter set."}
                              className="min-h-[180px] border-0 bg-transparent px-0 py-0"
                            />
                          </TableCell>
                        </TableRow>
                      )}

                      {report &&
                        filteredTimeline.length > 0 &&
                        filteredTimeline.slice(0, rowsTimeline).map((t) => (
                          <TableRow
                            key={t.id}
                            className="border-gray-800/80 transition-colors hover:bg-sky-500/[0.08]"
                          >
                            <TableCell className="text-gray-200">{fmtTime(t.time)}</TableCell>
                            <TableCell className="text-gray-200 font-mono">
                              {t.source_ip} → {t.dest_ip}
                            </TableCell>
                            <TableCell className="text-gray-200">
                              {t.dst_port || "—"}
                            </TableCell>
                            <TableCell className="text-white font-medium">
                              {t.label || "—"}
                            </TableCell>
                            <TableCell className="text-gray-200">
                              {fmtPct(t.threat_confidence)}
                            </TableCell>
                            <TableCell>
                              <SevBadge s={t.severity} />
                            </TableCell>
                            <TableCell>
                              <DecisionBadge d={t.verdict} />
                            </TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <AlertDetailsSheet
        detail={details}
        jobId={job?.job_id ?? null}
        open={details !== null}
        onEvidenceOpened={(evidenceKey) => {
          void handleEvidenceAccess(evidenceKey);
        }}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) {
            setDetails(null);
          }
        }}
      />

      {historyModal}
    </div>
  );
}

