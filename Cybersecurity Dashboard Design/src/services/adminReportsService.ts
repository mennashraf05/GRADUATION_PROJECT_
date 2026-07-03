import {
  ADMIN_PCAP_API_BASE,
  AdminPcapJob,
  AdminPcapOverview,
  buildPcapArtifactFetchInit,
  emptyAdminPcapOverview,
  formatAdminPcapTime,
  getDownloadFilename,
  loadAdminPcapOverview,
} from "./adminPcapOverview";

export type ReportExportFormat = "pdf" | "csv";
export type ReportModule = "pcap" | "identity" | "password" | "phishing" | "monthly" | "activity" | "high-risk-users" | "security-incidents" | "vault";
export type PcapReportStatus = "completed" | "running" | "failed" | "queued" | "unknown";
export type PcapReportRisk = "low" | "medium" | "high" | "critical" | "unknown";
export type PcapReportAnalysisMode =
  | "ML"
  | "Heuristics"
  | "Hybrid"
  | "Zeek-enriched"
  | "Unknown";

export interface ReportsOverview {
  pcap_reports_generated: number;
  completed_analysis_jobs: number;
  failed_analysis_jobs: number;
  latest_pcap_export: string | null;
  latest_pcap_export_status: string;
  usingFallback: boolean;
}

export interface PcapReportSummary {
  report_name: string;
  status: "active";
  last_generated_at: string | null;
  supported_formats: ReportExportFormat[];
  total_analyzed_files: number;
  completed_jobs: number;
  failed_jobs: number;
  latest_detected_attack_family: string;
  highest_severity_found: PcapReportRisk;
  evidence_available: boolean;
  report_available: boolean;
  latest_report_id: string | null;
  usingFallback: boolean;
}

export interface PcapReportFilters {
  dateFrom: string;
  dateTo: string;
  status: "all" | "completed" | "failed" | "running" | "queued";
  riskLevel: "all" | PcapReportRisk;
  attackFamily: string;
  exportFormat: "all" | ReportExportFormat;
  analysisMode: "all" | PcapReportAnalysisMode;
}

export interface IdentityReportFilters {
  dateFrom: string;
  dateTo: string;
  riskLevel: "all" | PcapReportRisk;
  status: "all" | "completed" | "failed" | "running" | "queued";
  source: string;
  findingsCount: "all" | "with_findings" | "no_findings";
  exportFormat: "all" | ReportExportFormat;
}

export interface RecentPcapReport {
  id: string;
  file_name: string;
  job_id: string;
  status: PcapReportStatus;
  risk_level: PcapReportRisk;
  detected_attack_family: string;
  analysis_mode: PcapReportAnalysisMode;
  generated_at: string | null;
  report_available: boolean;
  evidence_available: boolean;
}

export interface IdentityEvidenceItem {
  source_name: string;
  evidence_title: string;
  url: string;
  snippet: string;
  query_triggered: string;
  match_reason: string;
  generated_at: string | null;
}

export interface RecentIdentityReport {
  scan_id: string;
  masked_identifier: string;
  status: PcapReportStatus;
  risk_level: PcapReportRisk;
  risk_score: number;
  findings_count: number;
  sources: string[];
  generated_at: string | null;
  report_available: boolean;
  evidence: IdentityEvidenceItem[];
}

export interface IdentityReportSummary {
  report_name: "Identity Leak Summary";
  status: "active";
  last_generated: string | null;
  supported_formats: ReportExportFormat[];
  total_scans: number;
  total_findings: number;
  critical_scans: number;
  highest_severity: PcapReportRisk;
  latest_risk_score: number;
  sources_used: string[];
  evidence_available: boolean;
  report_available: boolean;
  recent_reports: RecentIdentityReport[];
  usingFallback: boolean;
}

export interface PasswordRiskReportSummary {
  report_name: "Password Risk Summary";
  status: "active";
  generated_at: string | null;
  last_generated: string | null;
  supported_formats: ReportExportFormat[];
  data_source: "password_checker";
  summary: {
    total_checks: number;
    breached_findings: number;
    weak_findings: number;
    strong_safe_checks: number;
    latest_check_at: string | null;
  };
  risk_distribution: Record<string, number>;
  strength_distribution: Record<string, number>;
  breach_summary: {
    total_breached_results: number;
    total_exposure_count: number;
    average_breach_count: number;
  };
  recommendations: string[];
  report_available: boolean;
  evidence_available: boolean;
  usingFallback: boolean;
}

export interface PasswordRiskReportFilters {
  passwordRisk: "all" | PcapReportRisk;
  passwordStrength: string;
  breachStatus: "all" | "breached" | "not_breached";
}

export interface PhishingScanReportItem {
  scan_id: string;
  user_id: number | null;
  timestamp: string | null;
  url: string;
  domain: string;
  final_category: "safe" | "suspicious" | "dangerous" | string;
  final_risk_score: number;
  risk_level: PcapReportRisk;
  ml_probability: number | string | null;
  virustotal_status: string;
  virustotal_malicious: number;
  virustotal_suspicious: number;
}

export interface PhishingIncidentsReportSummary {
  report_name: "Phishing Incidents Summary";
  status: "active";
  generated_at: string | null;
  last_generated: string | null;
  reporting_period: {
    label: string;
    start: string | null;
    end: string | null;
  };
  data_source: "phishing_scanner";
  summary: {
    total_url_scans: number;
    safe_urls: number;
    suspicious_urls: number;
    dangerous_urls: number;
    risky_urls: number;
    average_risk_score: number;
    latest_scan_time: string | null;
    virustotal_malicious_total: number;
    virustotal_suspicious_total: number;
  };
  category_distribution: Record<string, number>;
  risk_distribution: Record<string, number>;
  highest_risk_scan: PhishingScanReportItem | null;
  latest_scans: PhishingScanReportItem[];
  recommendations: string[];
  empty: boolean;
  message: string;
  supported_formats: ReportExportFormat[];
  report_available: boolean;
  evidence_available: boolean;
  usingFallback: boolean;
}

export interface PhishingIncidentsReportFilters {
  dateFrom: string;
  dateTo: string;
  riskLevel: "all" | PcapReportRisk;
  category: "all" | "safe" | "suspicious" | "dangerous";
  exportFormat: "all" | ReportExportFormat;
}

export interface UserActivityReportFilters {
  dateRange: "current_month" | "last_7_days" | "last_30_days";
  role: "all" | "admin" | "user";
  activityType: "all" | "auth" | "admin_action" | "export" | "module_activity" | "audit";
  moduleSource: string;
}

export interface HighRiskUsersReportFilters {
  dateRange: "current_month" | "last_7_days" | "last_30_days";
  riskLevel: "all" | PcapReportRisk;
  moduleSource: string;
  role: "all" | "admin" | "user";
}

export interface SecurityIncidentsReportFilters {
  dateRange: "current_month" | "last_7_days" | "last_30_days";
  severity: "all" | PcapReportRisk;
  moduleSource: string;
  incidentType: string;
  status: "all" | "open" | "investigating" | "resolved" | "dismissed" | "unknown";
}

export interface MonthlySecurityReportFilters {
  severity: "all" | PcapReportRisk;
  module: string;
}

export interface MonthlySecurityReportSummary {
  report_name: "Monthly Security Report";
  status: "active";
  generated_at: string | null;
  reporting_period: {
    label: string;
    start: string | null;
    end: string | null;
  };
  data_source: "admin_reports";
  summary: {
    reporting_period: string;
    total_events: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
    total_password_findings: number;
    total_identity_findings: number;
    total_pcap_alerts: number;
  };
  module_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  password_summary: {
    password_checks: number;
    breached_findings: number;
    weak_findings: number;
    strong_safe_checks: number;
  };
  identity_summary: {
    identity_scans: number;
    identity_exposure_findings: number;
    high_risk_exposures: number;
  };
  module_activity_summary: {
    pcap_analyses_run: number;
    pcap_completed: number;
    pcap_failed: number;
    pcap_clean_analyses: number;
    pcap_alerts_generated: number;
    identity_scans_run: number;
    identity_findings_found: number;
    password_checks_run: number;
    password_breached_results: number;
    notifications_created: number;
    admin_audit_events: number;
    user_activity_events: number;
    latest_activity_timestamp: string | null;
  };
  top_risk_areas: Array<{ title: string; count: number }>;
  recommendations: string[];
  empty: boolean;
  message: string;
  supported_formats: ReportExportFormat[];
  report_available: boolean;
  evidence_available: boolean;
  usingFallback: boolean;
}

export interface UserActivityReportSummary {
  report_name: "User Activity Report";
  status: "active";
  generated_at: string | null;
  reporting_period: {
    label: string;
    start: string | null;
    end: string | null;
  };
  summary: {
    total_activity_events: number;
    unique_actors: number;
    active_users: number;
    active_admins: number;
    total_exports: number;
    latest_activity_at: string | null;
  };
  activity_type_distribution: Record<string, number>;
  role_distribution: Record<string, number>;
  module_distribution: Record<string, number>;
  timeline: Array<{ date: string; count: number }>;
  recent_activity: Array<{
    timestamp: string | null;
    actor: string;
    actor_display_name: string;
    role: string;
    module: string;
    activity_type: string;
    action: string;
    status: string;
  }>;
  empty: boolean;
  message: string;
  supported_formats: ReportExportFormat[];
  report_available: boolean;
  usingFallback: boolean;
}

export interface HighRiskUsersReportSummary {
  report_name: "High-Risk Users Report";
  status: "active";
  generated_at: string | null;
  reporting_period: {
    label: string;
    start: string | null;
    end: string | null;
  };
  summary: {
    total_users_evaluated: number;
    high_risk_users: number;
    critical_risk_users: number;
    medium_risk_users: number;
    low_risk_users: number;
    total_risk_signals: number;
    latest_risk_signal_timestamp: string | null;
    unattributed_signals: number;
  };
  risk_level_distribution: Record<string, number>;
  module_signal_distribution: Record<string, number>;
  top_risk_users: Array<{
    user_id: number;
    actor_display_name: string;
    actor_role: string;
    risk_score: number;
    risk_level: string;
    total_signals: number;
    top_risk_source: string;
    password_signals_count: number;
    identity_signals_count: number;
    pcap_signals_count: number;
    auth_signals_count: number;
    notification_signals_count: number;
    latest_signal_timestamp: string | null;
    safe_recommendation: string;
  }>;
  empty: boolean;
  message: string;
  report_available: boolean;
  usingFallback: boolean;
}

export interface SecurityIncidentsReportSummary {
  report_name: "Security Incidents Report";
  status: "active";
  generated_at: string | null;
  reporting_period: {
    label: string;
    start: string | null;
    end: string | null;
  };
  summary: {
    total_incidents: number;
    critical_incidents: number;
    high_incidents: number;
    medium_incidents: number;
    low_incidents: number;
    open_incidents: number;
    resolved_incidents: number;
    latest_incident_timestamp: string | null;
  };
  severity_distribution: Record<string, number>;
  source_distribution: Record<string, number>;
  incident_type_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  timeline: Array<{ date: string; count: number }>;
  recent_incidents: Array<{
    incident_id: string;
    timestamp: string | null;
    severity: string;
    source: string;
    incident_type: string;
    title: string;
    status: string;
    actor_display_name: string;
    actor_role: string;
    affected_area: string;
    recommendation: string;
    risk_score: number;
  }>;
  top_risk_areas: Array<{ title: string; count: number; severity: string; recommendation: string }>;
  empty: boolean;
  message: string;
  supported_formats: ReportExportFormat[];
  report_available: boolean;
  usingFallback: boolean;
}

export interface FutureReportCategory {
  id: string;
  title: string;
  badge: "Coming Soon" | "Waiting for Module Integration" | "Connected" | "Active";
  description: string;
}

export interface ReportExportResult {
  blob: Blob;
  filename: string;
  fallback: boolean;
}

const GENERATED_REPORTS_STORAGE_KEY = "sentinel_admin_generated_pcap_reports";

function isDemoPcapReport(report: RecentPcapReport): boolean {
  const demoFileNames = new Set([
    "office_traffic_24may.pcap",
    "network_capture_23may.pcap",
    "scan_attempts_23may.pcap",
    "web_traffic_22may.pcap",
  ]);
  return report.id.startsWith("demo-pcap-report-") || demoFileNames.has(report.file_name);
}

function buildAdminJsonFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (typeof window !== "undefined") {
    const token = window.localStorage.getItem("sentinel_admin_token");
    if (token) headers.set("Authorization", `Bearer ${token}`);
  }

  return {
    ...init,
    credentials: "include",
    headers,
  };
}

function buildQuery(params: Record<string, string>) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value && value !== "all") query.set(key, value);
  });
  const serialized = query.toString();
  return serialized ? `?${serialized}` : "";
}

function statusFromJob(job: AdminPcapJob): PcapReportStatus {
  const normalized = job.status.toLowerCase();
  if (job.finished_at && !normalized.includes("fail") && !normalized.includes("error")) {
    return "completed";
  }
  if (job.started_at && !job.finished_at) {
    return "running";
  }
  if (
    normalized.includes("complete") ||
    normalized.includes("finish") ||
    normalized.includes("done") ||
    normalized.includes("succeed") ||
    normalized.includes("analyz") ||
    normalized === "success" ||
    job.report_available
  ) {
    return "completed";
  }
  if (
    normalized.includes("run") ||
    normalized.includes("process") ||
    normalized.includes("progress") ||
    normalized.includes("start")
  ) {
    return "running";
  }
  if (normalized.includes("fail") || normalized.includes("error")) return "failed";
  if (normalized.includes("queue") || normalized.includes("pending")) return "queued";
  return "unknown";
}

function riskFromJob(job: AdminPcapJob): PcapReportRisk {
  if (job.risk_level === "low") return "low";
  if (job.risk_level === "medium") return "medium";
  if (job.risk_level === "high") return "high";
  if (job.risk_level === "critical") return "critical";
  return "unknown";
}

function modeFromJob(job: AdminPcapJob): PcapReportAnalysisMode {
  if (job.zeek_used === "yes") return "Zeek-enriched";
  if (job.analysis_mode === "ML Only") return "ML";
  if (job.analysis_mode === "Heuristics Only") return "Heuristics";
  if (job.analysis_mode === "Hybrid Logic") return "Hybrid";
  return "Unknown";
}

function highestRisk(reports: RecentPcapReport[]): PcapReportRisk {
  const order: PcapReportRisk[] = ["critical", "high", "medium", "low", "unknown"];
  return order.find((risk) => reports.some((report) => report.risk_level === risk)) || "unknown";
}

function readGeneratedReports(): RecentPcapReport[] {
  if (typeof window === "undefined") return [];
  try {
    const parsed = JSON.parse(window.localStorage.getItem(GENERATED_REPORTS_STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed.filter((report) => !isDemoPcapReport(report)) : [];
  } catch {
    return [];
  }
}

function writeGeneratedReports(reports: RecentPcapReport[]) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(
    GENERATED_REPORTS_STORAGE_KEY,
    JSON.stringify(reports.filter((report) => !isDemoPcapReport(report)).slice(0, 25))
  );
}

function mergeGeneratedReports(reports: RecentPcapReport[]): RecentPcapReport[] {
  const merged = new Map<string, RecentPcapReport>();
  [...readGeneratedReports(), ...reports].forEach((report) => {
    merged.set(report.id, report);
  });
  return Array.from(merged.values()).sort((a, b) => {
    const bTime = b.generated_at ? new Date(b.generated_at).getTime() : 0;
    const aTime = a.generated_at ? new Date(a.generated_at).getTime() : 0;
    return bTime - aTime;
  });
}

function mapOverviewToRecentReports(overview: AdminPcapOverview): RecentPcapReport[] {
  const uniqueJobs = new Map<string, AdminPcapJob>();
  [...overview.latest_files, ...overview.top_suspicious_files].forEach((job) => {
    const key = job.job_id || `${job.filename}-${job.created_at || job.finished_at || "unknown"}`;
    if (!uniqueJobs.has(key)) uniqueJobs.set(key, job);
  });

  return Array.from(uniqueJobs.values()).map((job, index) => ({
    id: job.job_id || `pcap-report-${index}`,
    file_name: job.filename,
    job_id: job.job_id || "Not assigned",
    status: statusFromJob(job),
    risk_level: riskFromJob(job),
    detected_attack_family: job.detected_family,
    analysis_mode: modeFromJob(job),
    generated_at: job.finished_at || job.created_at || overview.generated_at,
    report_available: job.report_available,
    evidence_available: job.evidence_available,
  }));
}

function hasLivePcapData(overview: AdminPcapOverview): boolean {
  return (
    overview.summary.total_jobs > 0 ||
    overview.latest_files.length > 0 ||
    overview.top_suspicious_files.length > 0
  );
}

async function loadPcapOverviewWithFallback(): Promise<{
  overview: AdminPcapOverview;
  reports: RecentPcapReport[];
  usingFallback: boolean;
}> {
  try {
    const overview = await loadAdminPcapOverview();
    const reports = mergeGeneratedReports(mapOverviewToRecentReports(overview));
    if (hasLivePcapData(overview) || reports.length > 0) {
      return { overview, reports, usingFallback: false };
    }
  } catch {
    // Reports Center stays usable while backend reporting endpoints are being wired.
  }

  return {
    overview: emptyAdminPcapOverview(),
    reports: mergeGeneratedReports([]),
    usingFallback: true,
  };
}

function applyPcapFilters(
  reports: RecentPcapReport[],
  filters?: Partial<PcapReportFilters>
): RecentPcapReport[] {
  if (!filters) return reports;

  const attackFamily = (filters.attackFamily || "").trim().toLowerCase();
  const from = filters.dateFrom ? new Date(filters.dateFrom).getTime() : null;
  const to = filters.dateTo ? new Date(`${filters.dateTo}T23:59:59`).getTime() : null;

  return reports.filter((report) => {
    if (filters.status && filters.status !== "all" && report.status !== filters.status) return false;
    if (filters.riskLevel && filters.riskLevel !== "all" && report.risk_level !== filters.riskLevel) return false;
    if (filters.analysisMode && filters.analysisMode !== "all" && report.analysis_mode !== filters.analysisMode) return false;
    if (attackFamily && attackFamily !== "all" && !report.detected_attack_family.toLowerCase().includes(attackFamily)) return false;

    if ((from || to) && report.generated_at) {
      const timestamp = new Date(report.generated_at).getTime();
      if (from && timestamp < from) return false;
      if (to && timestamp > to) return false;
    }

    return true;
  });
}

export async function getReportsOverview(): Promise<ReportsOverview> {
  const { overview, reports, usingFallback } = await loadPcapOverviewWithFallback();
  const latestReport = reports[0];

  return {
    pcap_reports_generated: reports.filter((report) => report.report_available || report.status === "completed").length || overview.summary.completed_jobs,
    completed_analysis_jobs: overview.summary.completed_jobs,
    failed_analysis_jobs: overview.summary.failed_jobs,
    latest_pcap_export: latestReport?.generated_at || overview.summary.last_analysis_time,
    latest_pcap_export_status: latestReport?.report_available ? "Report available" : "Awaiting report artifact",
    usingFallback,
  };
}

export async function getPcapReportSummary(): Promise<PcapReportSummary> {
  const { overview, reports, usingFallback } = await loadPcapOverviewWithFallback();
  const latestReport = reports[0];

  return {
    report_name: "PCAP Analysis Summary",
    status: "active",
    last_generated_at: latestReport?.generated_at || overview.summary.last_analysis_time,
    supported_formats: ["pdf", "csv"],
    total_analyzed_files: overview.summary.total_uploaded_files || reports.length,
    completed_jobs: overview.summary.completed_jobs,
    failed_jobs: overview.summary.failed_jobs,
    latest_detected_attack_family:
      latestReport?.detected_attack_family ||
      overview.latest_attack_families[0]?.family ||
      "Not classified yet",
    highest_severity_found: highestRisk(reports),
    evidence_available: reports.some((report) => report.evidence_available),
    report_available: reports.some((report) => report.report_available),
    latest_report_id: latestReport?.id || null,
    usingFallback,
  };
}

export async function getRecentPcapReports(
  filters?: Partial<PcapReportFilters>
): Promise<{ reports: RecentPcapReport[]; usingFallback: boolean }> {
  const { reports, usingFallback } = await loadPcapOverviewWithFallback();
  return { reports: applyPcapFilters(reports, filters), usingFallback };
}

export async function generatePcapReport(
  filters?: Partial<PcapReportFilters>
): Promise<PcapReportSummary> {
  const { reports } = await getRecentPcapReports(filters);

  try {
    const response = await fetch(
      `${ADMIN_PCAP_API_BASE}/api/admin/reports/pcap/generate`,
      buildAdminJsonFetchInit({
        method: "POST",
        body: JSON.stringify({ filters: filters || {} }),
      })
    );
    if (!response.ok) throw new Error("PCAP report generation endpoint is not connected.");
  } catch {
    if (reports.length === 0) {
      throw new Error("No real PCAP analysis jobs are available to generate a report yet.");
    }

    const source = reports[0];
    const generatedReport: RecentPcapReport = {
      ...source,
      id: `generated-pcap-report-${Date.now()}`,
      job_id: source.job_id || `JOB-${Date.now()}`,
      status: "completed",
      generated_at: new Date().toISOString(),
      report_available: true,
      evidence_available: source.evidence_available,
    };
    writeGeneratedReports([generatedReport, ...readGeneratedReports()]);
  }

  return getPcapReportSummary();
}

function escapePdfText(value: string): string {
  return value
    .replace(/[^\x20-\x7E]/g, "-")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function buildPcapPdfBlob(report: RecentPcapReport, allReports: RecentPcapReport[]): Blob {
  const commands: string[] = [];
  const add = (command: string) => commands.push(command);
  const text = (value: string, x: number, y: number, size = 10, color = "0.94 0.97 1", font = "F1") => {
    add(`${color} rg BT /${font} ${size} Tf ${x} ${y} Td (${escapePdfText(value)}) Tj ET`);
  };
  const rect = (x: number, y: number, width: number, height: number, color: string) => {
    add(`${color} rg ${x} ${y} ${width} ${height} re f`);
  };
  const strokeRect = (x: number, y: number, width: number, height: number, color: string) => {
    add(`${color} RG ${x} ${y} ${width} ${height} re S`);
  };
  const clip = (value: string, max = 42) => {
    const normalized = value || "Not available";
    return normalized.length > max ? `${normalized.slice(0, max - 3)}...` : normalized;
  };
  const titleCase = (value: string) =>
    value
      .split(/[\s_-]+/)
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
      .join(" ");

  rect(0, 0, 612, 792, "0.95 0.97 1");
  rect(0, 666, 612, 126, "0.02 0.07 0.14");
  rect(0, 666, 612, 4, "0.12 0.38 0.90");
  text("SENTINEL AI", 48, 746, 13, "0.38 0.65 1", "F2");
  text("PCAP Analysis Summary", 48, 718, 24, "1 1 1", "F2");
  text("Generated report for completed capture analysis, risk findings, attack family classification, and export status.", 48, 696, 9, "0.74 0.82 0.93");
  text(`Generated At: ${formatAdminPcapTime(report.generated_at || new Date().toISOString())}`, 420, 746, 9, "0.80 0.88 1");
  text("PCAP REPORT", 420, 724, 10, "0.38 0.65 1", "F2");

  const cards = [
    ["File Name", clip(report.file_name, 28)],
    ["Job ID", clip(report.job_id, 26)],
    ["Status", titleCase(report.status)],
    ["Risk Level", titleCase(report.risk_level)],
    ["Attack Family", clip(report.detected_attack_family, 24)],
    ["Analysis Mode", report.analysis_mode],
    ["Report Available", report.report_available ? "Yes" : "No"],
    ["Evidence Available", report.evidence_available ? "Yes" : "No"],
  ];
  cards.forEach(([label, value], index) => {
    const col = index % 4;
    const row = Math.floor(index / 4);
    const x = 48 + col * 132;
    const y = 588 - row * 86;
    rect(x, y, 116, 62, "0.99 1 1");
    strokeRect(x, y, 116, 62, "0.78 0.84 0.92");
    text(label, x + 12, y + 40, 8, "0.36 0.44 0.56", "F2");
    text(value, x + 12, y + 20, 10, "0.06 0.10 0.18", "F2");
  });

  text("Recent PCAP Reports", 48, 392, 15, "0.06 0.10 0.18", "F2");
  rect(48, 356, 516, 24, "0.90 0.94 1");
  text("File", 58, 364, 8, "0.18 0.27 0.42", "F2");
  text("Job ID", 210, 364, 8, "0.18 0.27 0.42", "F2");
  text("Status", 330, 364, 8, "0.18 0.27 0.42", "F2");
  text("Risk", 405, 364, 8, "0.18 0.27 0.42", "F2");
  text("Attack Family", 470, 364, 8, "0.18 0.27 0.42", "F2");

  allReports.slice(0, 7).forEach((item, index) => {
    const y = 326 - index * 34;
    rect(48, y - 8, 516, 30, index % 2 === 0 ? "1 1 1" : "0.96 0.98 1");
    strokeRect(48, y - 8, 516, 30, "0.86 0.90 0.96");
    text(clip(item.file_name, 24), 58, y + 2, 8, "0.08 0.12 0.20");
    text(clip(item.job_id, 18), 210, y + 2, 8, "0.08 0.12 0.20");
    text(titleCase(item.status), 330, y + 2, 8, "0.08 0.12 0.20", "F2");
    text(titleCase(item.risk_level), 405, y + 2, 8, "0.08 0.12 0.20", "F2");
    text(clip(item.detected_attack_family, 16), 470, y + 2, 8, "0.08 0.12 0.20");
  });

  rect(0, 0, 612, 38, "0.02 0.07 0.14");
  text("Sentinel AI Reports & Export Center", 48, 15, 8, "0.74 0.82 0.93");
  text("Generated by the admin reporting workspace", 408, 15, 8, "0.74 0.82 0.93");

  const stream = `${commands.join("\n")}\n`;
  const objects = [
    "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
    "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
    "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 6 0 R >> >> /Contents 5 0 R >> endobj",
    "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    `5 0 obj << /Length ${stream.length} >> stream\n${stream}endstream endobj`,
    "6 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> endobj",
  ];
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((object) => {
    offsets.push(pdf.length);
    pdf += `${object}\n`;
  });
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach((offset) => {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  });
  pdf += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return new Blob([pdf], { type: "application/pdf" });
}

export async function exportPcapReport(
  reportId: string,
  format: ReportExportFormat
): Promise<ReportExportResult> {
  const fallbackName = `pcap-report-${reportId || "latest"}.${format}`;
  const preferredUrl = `${ADMIN_PCAP_API_BASE}/api/admin/reports/pcap/${encodeURIComponent(reportId)}/export?format=${format}`;

  const preferred = await fetch(preferredUrl, buildPcapArtifactFetchInit({ cache: "no-store" })).catch(() => null);
  if (preferred?.ok) {
    const contentType = preferred.headers.get("content-type") || "";
    if (format === "pdf" && !contentType.toLowerCase().includes("pdf")) {
      // Some existing PCAP artifact endpoints return JSON reports. Keep the PDF button as PDF-only.
    } else {
    return {
      blob: await preferred.blob(),
      filename: getDownloadFilename(preferred.headers.get("content-disposition"), fallbackName),
      fallback: false,
    };
    }
  }

  if (format === "csv") {
    const { reports } = await getRecentPcapReports();
    const header = [
      "File Name",
      "Job ID",
      "Status",
      "Risk Level",
      "Detected Attack Family",
      "Analysis Mode",
      "Generated At",
      "Report Available",
    ];
    const rows = reports.map((report) => [
      report.file_name,
      report.job_id,
      report.status,
      report.risk_level,
      report.detected_attack_family,
      report.analysis_mode,
      report.generated_at ? formatAdminPcapTime(report.generated_at) : "Not available",
      report.report_available ? "Yes" : "No",
    ]);
    const csv = [header, ...rows]
      .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","))
      .join("\r\n");

    return {
      blob: new Blob([`\uFEFF${csv}`], { type: "text/csv;charset=utf-8" }),
      filename: fallbackName,
      fallback: true,
    };
  }

  const { reports } = await getRecentPcapReports();
  const report = reports.find((item) => item.id === reportId || item.job_id === reportId) || reports[0];
  if (!report) {
    throw new Error("No real PCAP report is available to export yet.");
  }
  return {
    blob: buildPcapPdfBlob(report, reports),
    filename: fallbackName.endsWith(".pdf") ? fallbackName : `${fallbackName}.pdf`,
    fallback: true,
  };
}

export async function regeneratePcapReport(reportId: string): Promise<PcapReportSummary> {
  try {
    const response = await fetch(
      `${ADMIN_PCAP_API_BASE}/api/admin/reports/pcap/${encodeURIComponent(reportId)}/regenerate`,
      buildAdminJsonFetchInit({ method: "POST" })
    );
    if (!response.ok) throw new Error("PCAP report regeneration endpoint is not connected.");
  } catch {
    // Keep the interaction safe while the backend team wires this endpoint.
  }
  const reports = readGeneratedReports();
  const existing = reports.find((report) => report.id === reportId);
  if (existing) {
    writeGeneratedReports([
      {
        ...existing,
        id: `generated-pcap-report-${Date.now()}`,
        generated_at: new Date().toISOString(),
        status: "completed",
        report_available: true,
      },
      ...reports,
    ]);
  }
  return getPcapReportSummary();
}

function normalizeIdentityReport(payload: any): IdentityReportSummary {
  const reports = Array.isArray(payload?.recent_reports) ? payload.recent_reports : [];
  return {
    report_name: "Identity Leak Summary",
    status: "active",
    last_generated: payload?.last_generated ? String(payload.last_generated) : null,
    supported_formats: ["pdf", "csv"],
    total_scans: Number(payload?.total_scans || 0),
    total_findings: Number(payload?.total_findings || 0),
    critical_scans: Number(payload?.critical_scans || 0),
    highest_severity: String(payload?.highest_severity || "unknown").toLowerCase() as PcapReportRisk,
    latest_risk_score: Number(payload?.latest_risk_score || 0),
    sources_used: Array.isArray(payload?.sources_used) ? payload.sources_used.map(String) : [],
    evidence_available: Boolean(payload?.evidence_available),
    report_available: Boolean(payload?.report_available),
    recent_reports: reports.map((item: any): RecentIdentityReport => ({
      scan_id: String(item?.scan_id || ""),
      masked_identifier: String(item?.masked_identifier || "Unavailable"),
      status: String(item?.status || "unknown").toLowerCase() as PcapReportStatus,
      risk_level: String(item?.risk_level || "unknown").toLowerCase() as PcapReportRisk,
      risk_score: Number(item?.risk_score || 0),
      findings_count: Number(item?.findings_count || 0),
      sources: Array.isArray(item?.sources) ? item.sources.map(String) : [],
      generated_at: item?.generated_at ? String(item.generated_at) : null,
      report_available: Boolean(item?.report_available),
      evidence: Array.isArray(item?.evidence)
        ? item.evidence.map((evidence: any) => ({
            source_name: String(evidence?.source_name || "Unknown source"),
            evidence_title: String(evidence?.evidence_title || "Evidence"),
            url: String(evidence?.url || ""),
            snippet: String(evidence?.snippet || ""),
            query_triggered: String(evidence?.query_triggered || "Hidden"),
            match_reason: String(evidence?.match_reason || ""),
            generated_at: evidence?.generated_at ? String(evidence.generated_at) : null,
          }))
        : [],
    })),
    usingFallback: false,
  };
}

export async function getIdentityReportSummary(
  filters?: Partial<IdentityReportFilters>
): Promise<IdentityReportSummary> {
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/identity${buildQuery({
      date_from: filters?.dateFrom || "",
      date_to: filters?.dateTo || "",
      risk_level: filters?.riskLevel || "all",
      status: filters?.status || "all",
      source: filters?.source || "all",
      findings_count: filters?.findingsCount || "all",
    })}`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.success === false) {
    throw new Error(payload?.message || "Identity report data could not be loaded.");
  }
  return normalizeIdentityReport(payload.report || payload);
}

export async function generateIdentityReport(
  filters?: Partial<IdentityReportFilters>
): Promise<IdentityReportSummary> {
  return getIdentityReportSummary(filters);
}

export async function exportIdentityReport(format: ReportExportFormat): Promise<ReportExportResult> {
  if (format === "pdf") {
    throw new Error("Identity PDF export is not available yet.");
  }
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/identity/export?format=csv`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload?.message || "Identity CSV export failed.");
  }
  return {
    blob: await response.blob(),
    filename: getDownloadFilename(response.headers.get("content-disposition"), "identity-leak-summary.csv"),
    fallback: false,
  };
}

function normalizeNumberMap(value: any): Record<string, number> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).map(([key, count]) => [String(key), Number(count || 0)])
  );
}

function normalizePasswordRiskReport(payload: any): PasswordRiskReportSummary {
  const summary = payload?.summary && typeof payload.summary === "object" ? payload.summary : {};
  const breachSummary = payload?.breach_summary && typeof payload.breach_summary === "object" ? payload.breach_summary : {};
  return {
    report_name: "Password Risk Summary",
    status: "active",
    generated_at: payload?.generated_at ? String(payload.generated_at) : null,
    last_generated: payload?.last_generated ? String(payload.last_generated) : null,
    supported_formats: ["pdf", "csv"],
    data_source: "password_checker",
    summary: {
      total_checks: Number(summary.total_checks || 0),
      breached_findings: Number(summary.breached_findings || 0),
      weak_findings: Number(summary.weak_findings || 0),
      strong_safe_checks: Number(summary.strong_safe_checks || 0),
      latest_check_at: summary.latest_check_at ? String(summary.latest_check_at) : null,
    },
    risk_distribution: normalizeNumberMap(payload?.risk_distribution),
    strength_distribution: normalizeNumberMap(payload?.strength_distribution),
    breach_summary: {
      total_breached_results: Number(breachSummary.total_breached_results || 0),
      total_exposure_count: Number(breachSummary.total_exposure_count || 0),
      average_breach_count: Number(breachSummary.average_breach_count || 0),
    },
    recommendations: Array.isArray(payload?.recommendations)
      ? payload.recommendations.map(String)
      : [],
    report_available: Boolean(payload?.report_available),
    evidence_available: Boolean(payload?.evidence_available),
    usingFallback: false,
  };
}

export async function getPasswordRiskReportSummary(
  filters?: Partial<PasswordRiskReportFilters>
): Promise<PasswordRiskReportSummary> {
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/password-risk-summary${buildQuery({
      password_risk: filters?.passwordRisk || "all",
      password_strength: filters?.passwordStrength || "all",
      breach_status: filters?.breachStatus || "all",
    })}`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.success === false) {
    throw new Error(payload?.message || "Password Risk Summary data could not be loaded.");
  }
  return normalizePasswordRiskReport(payload.report || payload);
}

export async function generatePasswordRiskReport(
  filters?: Partial<PasswordRiskReportFilters>
): Promise<PasswordRiskReportSummary> {
  return getPasswordRiskReportSummary(filters);
}

export async function exportPasswordRiskReport(format: ReportExportFormat): Promise<ReportExportResult> {
  if (format === "pdf") {
    throw new Error("Password Risk Summary PDF export is not available yet.");
  }
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/password-risk-summary/export?format=csv`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload?.message || "Password Risk Summary CSV export failed.");
  }
  return {
    blob: await response.blob(),
    filename: getDownloadFilename(response.headers.get("content-disposition"), "password-risk-summary.csv"),
    fallback: false,
  };
}

function normalizePhishingScanItem(item: any): PhishingScanReportItem {
  return {
    scan_id: String(item?.scan_id || ""),
    user_id: item?.user_id === null || item?.user_id === undefined ? null : Number(item.user_id || 0),
    timestamp: item?.timestamp ? String(item.timestamp) : null,
    url: String(item?.url || ""),
    domain: String(item?.domain || ""),
    final_category: String(item?.final_category || "safe"),
    final_risk_score: Number(item?.final_risk_score || 0),
    risk_level: String(item?.risk_level || "unknown") as PcapReportRisk,
    ml_probability: item?.ml_probability === undefined ? null : item.ml_probability,
    virustotal_status: String(item?.virustotal_status || "clean"),
    virustotal_malicious: Number(item?.virustotal_malicious || 0),
    virustotal_suspicious: Number(item?.virustotal_suspicious || 0),
  };
}

function normalizePhishingIncidentsReport(payload: any): PhishingIncidentsReportSummary {
  const summary = payload?.summary && typeof payload.summary === "object" ? payload.summary : {};
  const period = payload?.reporting_period && typeof payload.reporting_period === "object" ? payload.reporting_period : {};
  return {
    report_name: "Phishing Incidents Summary",
    status: "active",
    generated_at: payload?.generated_at ? String(payload.generated_at) : null,
    last_generated: payload?.last_generated ? String(payload.last_generated) : null,
    reporting_period: {
      label: String(period.label || "All Time"),
      start: period.start ? String(period.start) : null,
      end: period.end ? String(period.end) : null,
    },
    data_source: "phishing_scanner",
    summary: {
      total_url_scans: Number(summary.total_url_scans || 0),
      safe_urls: Number(summary.safe_urls || 0),
      suspicious_urls: Number(summary.suspicious_urls || 0),
      dangerous_urls: Number(summary.dangerous_urls || 0),
      risky_urls: Number(summary.risky_urls || 0),
      average_risk_score: Number(summary.average_risk_score || 0),
      latest_scan_time: summary.latest_scan_time ? String(summary.latest_scan_time) : null,
      virustotal_malicious_total: Number(summary.virustotal_malicious_total || 0),
      virustotal_suspicious_total: Number(summary.virustotal_suspicious_total || 0),
    },
    category_distribution: normalizeNumberMap(payload?.category_distribution),
    risk_distribution: normalizeNumberMap(payload?.risk_distribution),
    highest_risk_scan: payload?.highest_risk_scan && typeof payload.highest_risk_scan === "object"
      ? normalizePhishingScanItem(payload.highest_risk_scan)
      : null,
    latest_scans: Array.isArray(payload?.latest_scans)
      ? payload.latest_scans.map(normalizePhishingScanItem)
      : [],
    recommendations: Array.isArray(payload?.recommendations)
      ? payload.recommendations.map(String)
      : [],
    empty: Boolean(payload?.empty),
    message: String(payload?.message || ""),
    supported_formats: Array.isArray(payload?.supported_formats) ? payload.supported_formats.map(String) as ReportExportFormat[] : ["pdf", "csv"],
    report_available: Boolean(payload?.report_available),
    evidence_available: Boolean(payload?.evidence_available),
    usingFallback: false,
  };
}

export async function getPhishingIncidentsReportSummary(
  filters?: Partial<PhishingIncidentsReportFilters>
): Promise<PhishingIncidentsReportSummary> {
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/phishing-incidents${buildQuery({
      date_from: filters?.dateFrom || "",
      date_to: filters?.dateTo || "",
      risk_level: filters?.riskLevel || "all",
      category: filters?.category || "all",
      export_format: filters?.exportFormat || "all",
    })}`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.success === false) {
    throw new Error(payload?.message || "Phishing Incidents Summary data could not be loaded.");
  }
  return normalizePhishingIncidentsReport(payload.report || payload);
}

export async function generatePhishingIncidentsReport(
  filters?: Partial<PhishingIncidentsReportFilters>
): Promise<PhishingIncidentsReportSummary> {
  return getPhishingIncidentsReportSummary(filters);
}

export async function exportPhishingIncidentsReport(
  format: ReportExportFormat,
  filters?: Partial<PhishingIncidentsReportFilters>
): Promise<ReportExportResult> {
  if (format === "pdf") {
    throw new Error("Phishing Incidents Summary PDF export is generated in the Reports & Export Center.");
  }
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/phishing-incidents/export${buildQuery({
      format: "csv",
      date_from: filters?.dateFrom || "",
      date_to: filters?.dateTo || "",
      risk_level: filters?.riskLevel || "all",
      category: filters?.category || "all",
    })}`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload?.message || "Phishing Incidents Summary CSV export failed.");
  }
  return {
    blob: await response.blob(),
    filename: getDownloadFilename(response.headers.get("content-disposition"), "phishing-incidents-summary.csv"),
    fallback: false,
  };
}

function normalizeMonthlySecurityReport(payload: any): MonthlySecurityReportSummary {
  const summary = payload?.summary && typeof payload.summary === "object" ? payload.summary : {};
  const period = payload?.reporting_period && typeof payload.reporting_period === "object" ? payload.reporting_period : {};
  const passwordSummary = payload?.password_summary && typeof payload.password_summary === "object" ? payload.password_summary : {};
  const identitySummary = payload?.identity_summary && typeof payload.identity_summary === "object" ? payload.identity_summary : {};
  const activitySummary = payload?.module_activity_summary && typeof payload.module_activity_summary === "object" ? payload.module_activity_summary : {};
  return {
    report_name: "Monthly Security Report",
    status: "active",
    generated_at: payload?.generated_at ? String(payload.generated_at) : null,
    reporting_period: {
      label: String(period.label || "Current Month"),
      start: period.start ? String(period.start) : null,
      end: period.end ? String(period.end) : null,
    },
    data_source: "admin_reports",
    summary: {
      reporting_period: String(summary.reporting_period || "current_month"),
      total_events: Number(summary.total_events || 0),
      critical: Number(summary.critical || 0),
      high: Number(summary.high || 0),
      medium: Number(summary.medium || 0),
      low: Number(summary.low || 0),
      unknown: Number(summary.unknown || 0),
      total_password_findings: Number(summary.total_password_findings || 0),
      total_identity_findings: Number(summary.total_identity_findings || 0),
      total_pcap_alerts: Number(summary.total_pcap_alerts || 0),
    },
    module_distribution: normalizeNumberMap(payload?.module_distribution),
    severity_distribution: normalizeNumberMap(payload?.severity_distribution),
    password_summary: {
      password_checks: Number(passwordSummary.password_checks || 0),
      breached_findings: Number(passwordSummary.breached_findings || 0),
      weak_findings: Number(passwordSummary.weak_findings || 0),
      strong_safe_checks: Number(passwordSummary.strong_safe_checks || 0),
    },
    identity_summary: {
      identity_scans: Number(identitySummary.identity_scans || 0),
      identity_exposure_findings: Number(identitySummary.identity_exposure_findings || 0),
      high_risk_exposures: Number(identitySummary.high_risk_exposures || 0),
    },
    module_activity_summary: {
      pcap_analyses_run: Number(activitySummary.pcap_analyses_run || 0),
      pcap_completed: Number(activitySummary.pcap_completed || 0),
      pcap_failed: Number(activitySummary.pcap_failed || 0),
      pcap_clean_analyses: Number(activitySummary.pcap_clean_analyses || 0),
      pcap_alerts_generated: Number(activitySummary.pcap_alerts_generated || 0),
      identity_scans_run: Number(activitySummary.identity_scans_run || 0),
      identity_findings_found: Number(activitySummary.identity_findings_found || 0),
      password_checks_run: Number(activitySummary.password_checks_run || 0),
      password_breached_results: Number(activitySummary.password_breached_results || 0),
      notifications_created: Number(activitySummary.notifications_created || 0),
      admin_audit_events: Number(activitySummary.admin_audit_events || 0),
      user_activity_events: Number(activitySummary.user_activity_events || 0),
      latest_activity_timestamp: activitySummary.latest_activity_timestamp ? String(activitySummary.latest_activity_timestamp) : null,
    },
    top_risk_areas: Array.isArray(payload?.top_risk_areas)
      ? payload.top_risk_areas.map((item: any) => ({
          title: String(item?.title || "Risk area"),
          count: Number(item?.count || 0),
        }))
      : [],
    recommendations: Array.isArray(payload?.recommendations)
      ? payload.recommendations.map(String)
      : [],
    empty: Boolean(payload?.empty),
    message: String(payload?.message || ""),
    supported_formats: ["pdf", "csv"],
    report_available: Boolean(payload?.report_available),
    evidence_available: Boolean(payload?.evidence_available),
    usingFallback: false,
  };
}

function normalizeUserActivityReport(payload: any): UserActivityReportSummary {
  const summary = payload?.summary && typeof payload.summary === "object" ? payload.summary : {};
  const period = payload?.reporting_period && typeof payload.reporting_period === "object" ? payload.reporting_period : {};
  return {
    report_name: "User Activity Report",
    status: "active",
    generated_at: payload?.generated_at ? String(payload.generated_at) : null,
    reporting_period: {
      label: String(period.label || "Current Month"),
      start: period.start ? String(period.start) : null,
      end: period.end ? String(period.end) : null,
    },
    summary: {
      total_activity_events: Number(summary.total_activity_events || 0),
      unique_actors: Number(summary.unique_actors || 0),
      active_users: Number(summary.active_users || 0),
      active_admins: Number(summary.active_admins || 0),
      total_exports: Number(summary.total_exports || 0),
      latest_activity_at: summary.latest_activity_at ? String(summary.latest_activity_at) : null,
    },
    activity_type_distribution: normalizeNumberMap(payload?.activity_type_distribution),
    role_distribution: normalizeNumberMap(payload?.role_distribution),
    module_distribution: normalizeNumberMap(payload?.module_distribution),
    timeline: Array.isArray(payload?.timeline)
      ? payload.timeline.map((item: any) => ({ date: String(item?.date || ""), count: Number(item?.count || 0) }))
      : [],
    recent_activity: Array.isArray(payload?.recent_activity)
      ? payload.recent_activity.map((item: any) => ({
          timestamp: item?.timestamp ? String(item.timestamp) : null,
          actor: String(item?.actor || "Unknown"),
          actor_display_name: String(item?.actor_display_name || item?.actor || "Unknown"),
          role: String(item?.role || "unknown"),
          module: String(item?.module || "Other/Unknown"),
          activity_type: String(item?.activity_type || "module_activity"),
          action: String(item?.action || "Activity event"),
          status: String(item?.status || "info"),
        }))
      : [],
    empty: Boolean(payload?.empty),
    message: String(payload?.message || ""),
    supported_formats: ["pdf", "csv"],
    report_available: Boolean(payload?.report_available),
    usingFallback: false,
  };
}

function normalizeHighRiskUsersReport(payload: any): HighRiskUsersReportSummary {
  const summary = payload?.summary && typeof payload.summary === "object" ? payload.summary : {};
  const period = payload?.reporting_period && typeof payload.reporting_period === "object" ? payload.reporting_period : {};
  return {
    report_name: "High-Risk Users Report",
    status: "active",
    generated_at: payload?.generated_at ? String(payload.generated_at) : null,
    reporting_period: {
      label: String(period.label || "Current Month"),
      start: period.start ? String(period.start) : null,
      end: period.end ? String(period.end) : null,
    },
    summary: {
      total_users_evaluated: Number(summary.total_users_evaluated || 0),
      high_risk_users: Number(summary.high_risk_users || 0),
      critical_risk_users: Number(summary.critical_risk_users || 0),
      medium_risk_users: Number(summary.medium_risk_users || 0),
      low_risk_users: Number(summary.low_risk_users || 0),
      total_risk_signals: Number(summary.total_risk_signals || 0),
      latest_risk_signal_timestamp: summary.latest_risk_signal_timestamp ? String(summary.latest_risk_signal_timestamp) : null,
      unattributed_signals: Number(summary.unattributed_signals || 0),
    },
    risk_level_distribution: normalizeNumberMap(payload?.risk_level_distribution),
    module_signal_distribution: normalizeNumberMap(payload?.module_signal_distribution),
    top_risk_users: Array.isArray(payload?.top_risk_users)
      ? payload.top_risk_users.map((item: any) => ({
          user_id: Number(item?.user_id || 0),
          actor_display_name: String(item?.actor_display_name || "Unknown User"),
          actor_role: String(item?.actor_role || "user"),
          risk_score: Number(item?.risk_score || 0),
          risk_level: String(item?.risk_level || "low"),
          total_signals: Number(item?.total_signals || 0),
          top_risk_source: String(item?.top_risk_source || "other"),
          password_signals_count: Number(item?.password_signals_count || 0),
          identity_signals_count: Number(item?.identity_signals_count || 0),
          pcap_signals_count: Number(item?.pcap_signals_count || 0),
          auth_signals_count: Number(item?.auth_signals_count || 0),
          notification_signals_count: Number(item?.notification_signals_count || 0),
          latest_signal_timestamp: item?.latest_signal_timestamp ? String(item.latest_signal_timestamp) : null,
          safe_recommendation: String(item?.safe_recommendation || "Review recent security signals."),
        }))
      : [],
    empty: Boolean(payload?.empty),
    message: String(payload?.message || ""),
    report_available: Boolean(payload?.report_available),
    usingFallback: false,
  };
}

function normalizeSecurityIncidentsReport(payload: any): SecurityIncidentsReportSummary {
  const summary = payload?.summary && typeof payload.summary === "object" ? payload.summary : {};
  const period = payload?.reporting_period && typeof payload.reporting_period === "object" ? payload.reporting_period : {};
  return {
    report_name: "Security Incidents Report",
    status: "active",
    generated_at: payload?.generated_at ? String(payload.generated_at) : null,
    reporting_period: {
      label: String(period.label || "Current Month"),
      start: period.start ? String(period.start) : null,
      end: period.end ? String(period.end) : null,
    },
    summary: {
      total_incidents: Number(summary.total_incidents || 0),
      critical_incidents: Number(summary.critical_incidents || 0),
      high_incidents: Number(summary.high_incidents || 0),
      medium_incidents: Number(summary.medium_incidents || 0),
      low_incidents: Number(summary.low_incidents || 0),
      open_incidents: Number(summary.open_incidents || 0),
      resolved_incidents: Number(summary.resolved_incidents || 0),
      latest_incident_timestamp: summary.latest_incident_timestamp ? String(summary.latest_incident_timestamp) : null,
    },
    severity_distribution: normalizeNumberMap(payload?.severity_distribution),
    source_distribution: normalizeNumberMap(payload?.source_distribution),
    incident_type_distribution: normalizeNumberMap(payload?.incident_type_distribution),
    status_distribution: normalizeNumberMap(payload?.status_distribution),
    timeline: Array.isArray(payload?.timeline)
      ? payload.timeline.map((item: any) => ({ date: String(item?.date || ""), count: Number(item?.count || 0) }))
      : [],
    recent_incidents: Array.isArray(payload?.recent_incidents)
      ? payload.recent_incidents.map((item: any) => ({
          incident_id: String(item?.incident_id || ""),
          timestamp: item?.timestamp ? String(item.timestamp) : null,
          severity: String(item?.severity || "unknown"),
          source: String(item?.source || "other"),
          incident_type: String(item?.incident_type || "other"),
          title: String(item?.title || "Security incident detected"),
          status: String(item?.status || "unknown"),
          actor_display_name: String(item?.actor_display_name || "Unknown User"),
          actor_role: String(item?.actor_role || "system"),
          affected_area: String(item?.affected_area || ""),
          recommendation: String(item?.recommendation || "Review security incident details."),
          risk_score: Number(item?.risk_score || 0),
        }))
      : [],
    top_risk_areas: Array.isArray(payload?.top_risk_areas)
      ? payload.top_risk_areas.map((item: any) => ({
          title: String(item?.title || "Security"),
          count: Number(item?.count || 0),
          severity: String(item?.severity || "unknown"),
          recommendation: String(item?.recommendation || "Review related security incidents."),
        }))
      : [],
    empty: Boolean(payload?.empty),
    message: String(payload?.message || ""),
    supported_formats: ["pdf", "csv"],
    report_available: Boolean(payload?.report_available),
    usingFallback: false,
  };
}

export async function getMonthlySecurityReportSummary(
  filters?: Partial<MonthlySecurityReportFilters>
): Promise<MonthlySecurityReportSummary> {
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/monthly-security${buildQuery({
      severity: filters?.severity || "all",
      module: filters?.module || "all",
    })}`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.success === false) {
    throw new Error(payload?.message || "Monthly Security Report data could not be loaded.");
  }
  return normalizeMonthlySecurityReport(payload.report || payload);
}

export async function getSecurityIncidentsReportSummary(
  filters?: Partial<SecurityIncidentsReportFilters>
): Promise<SecurityIncidentsReportSummary> {
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/security-incidents${buildQuery({
      date_range: filters?.dateRange || "current_month",
      severity: filters?.severity || "all",
      module_source: filters?.moduleSource || "all",
      incident_type: filters?.incidentType || "all",
      status: filters?.status || "all",
    })}`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.success === false) {
    throw new Error(payload?.message || "Security Incidents Report data could not be loaded.");
  }
  return normalizeSecurityIncidentsReport(payload.report || payload);
}

export async function getHighRiskUsersReportSummary(
  filters?: Partial<HighRiskUsersReportFilters>
): Promise<HighRiskUsersReportSummary> {
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/high-risk-users${buildQuery({
      date_range: filters?.dateRange || "current_month",
      risk_level: filters?.riskLevel || "all",
      module_source: filters?.moduleSource || "all",
      role: filters?.role || "all",
    })}`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.success === false) {
    throw new Error(payload?.message || "High-Risk Users Report data could not be loaded.");
  }
  return normalizeHighRiskUsersReport(payload.report || payload);
}

export async function getUserActivityReportSummary(
  filters?: Partial<UserActivityReportFilters>
): Promise<UserActivityReportSummary> {
  const response = await fetch(
    `${ADMIN_PCAP_API_BASE}/api/admin/reports/user-activity${buildQuery({
      date_range: filters?.dateRange || "current_month",
      role: filters?.role || "all",
      activity_type: filters?.activityType || "all",
      module_source: filters?.moduleSource || "all",
    })}`,
    buildAdminJsonFetchInit({ cache: "no-store" })
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.success === false) {
    throw new Error(payload?.message || "User Activity Report data could not be loaded.");
  }
  return normalizeUserActivityReport(payload.report || payload);
}

export async function generateUserActivityReport(
  filters?: Partial<UserActivityReportFilters>
): Promise<UserActivityReportSummary> {
  return getUserActivityReportSummary(filters);
}

export async function generateHighRiskUsersReport(
  filters?: Partial<HighRiskUsersReportFilters>
): Promise<HighRiskUsersReportSummary> {
  return getHighRiskUsersReportSummary(filters);
}

export async function generateSecurityIncidentsReport(
  filters?: Partial<SecurityIncidentsReportFilters>
): Promise<SecurityIncidentsReportSummary> {
  return getSecurityIncidentsReportSummary(filters);
}

export async function generateMonthlySecurityReport(): Promise<MonthlySecurityReportSummary> {
  return getMonthlySecurityReportSummary();
}

export function getFutureReportCategories(): FutureReportCategory[] {
  return [
    {
      id: "monthly-security",
      title: "Monthly Security Report",
      badge: "Connected",
      description: "Connected to safe monthly aggregate metrics across available security records.",
    },
    {
      id: "security-incidents",
      title: "Security Incidents Report",
      badge: "Connected",
      description: "Connected to safe normalized incidents from PCAP alerts, identity findings, password risks, notifications, auth warnings, and audit warnings.",
    },
    {
      id: "user-activity",
      title: "User Activity Report",
      badge: "Connected",
      description: "Connected to safe authenticated activity, admin audit actions, module usage, and report export aggregates.",
    },
    {
      id: "high-risk-users",
      title: "High-Risk Users Report",
      badge: "Connected",
      description: "Connected to safe password, identity, PCAP, notification, and activity risk signals.",
    },
    {
      id: "password-risk",
      title: "Password Risk Summary",
      badge: "Connected",
      description: "Connected to safe Password Checker aggregates, breach counts, strength distribution, and deterministic recommendations.",
    },
    {
      id: "phishing-incidents",
      title: "Phishing Incidents Summary",
      badge: "Connected",
      description: "Connected to Phishing Scanner results, URL risk decisions, ML probabilities, VirusTotal reputation, suspicious/dangerous detections, and export-ready phishing incident summaries.",
    },
    {
      id: "identity-leak",
      title: "Identity Leak Summary",
      badge: "Connected",
      description: "Connected to live identity scan data, exposure findings, source summaries, severity distribution, and export-ready reports.",
    },
    {
      id: "file-vault",
      title: "File Vault Activity Summary",
      badge: "Connected",
      description:
        "Connected to encrypted vault uploads, downloads, encryption events, offline access changes, failed access attempts, and integrity activity records.",
    },
  ];
}
