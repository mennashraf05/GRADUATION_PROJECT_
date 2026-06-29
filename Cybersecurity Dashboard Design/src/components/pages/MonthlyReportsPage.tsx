import React, { useEffect, useMemo, useState } from "react";
import { format } from "date-fns";
import {
  AlertTriangle,
  ArrowUp,
  CalendarDays,
  Download,
  Eye,
  FileText,
  FolderOpen,
  HardDrive,
  LoaderCircle,
  Lock,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldCheck,
  Sparkles,
  TrendingUp,
  UploadCloud,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "../ui/sheet";
import { toast } from "sonner";
import "./MonthlyReportsPage.css";

const DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:5000";

type ReportSummary = {
  report_month: string;
  generated_at: string;
  available_sections: string[];
  available_section_count: number;
  status: string;
  pdf_available: boolean;
  latest_pcap_threat_count: number;
  latest_pcap_score_change: number | null;
  latest_vault_event_count?: number;
  latest_vault_wrong_password_count?: number;
  latest_identity_scan_count?: number;
  latest_identity_alert_count?: number;
  latest_identity_confirmed_breach_count?: number;
  latest_identity_risky_asset_count?: number;
  latest_phishing_scan_count?: number;
  latest_phishing_risky_url_count?: number;
  latest_phishing_dangerous_url_count?: number;
};

type PcapThreatType = {
  name: string;
  count: number;
};

type PcapSection = {
  files_analyzed?: number;
  threats_detected?: number;
  high_alerts?: number;
  critical_alerts?: number;
  score_change?: number | string | null;
  top_threat_types?: PcapThreatType[];
  recommendations?: string[];
};

type VaultActionBreakdown = {
  name: string;
  count: number;
};

type VaultSection = {
  uploads?: number;
  downloads?: number;
  deletes?: number;
  offline_enabled?: number;
  offline_disabled?: number;
  wrong_password?: number;
  total_events?: number;
  unique_files?: number;
  total_storage_bytes?: number;
  largest_file?: string | null;
  largest_file_size_bytes?: number;
  most_active_file?: {
    filename: string;
    activity_count: number;
  } | null;
  most_failed_file?: {
    filename: string;
    wrong_password_attempts: number;
  } | null;
  recommendations?: string[];
  action_breakdown?: VaultActionBreakdown[];
};

type IdentitySummaryMap = Record<string, number | undefined>;

type IdentityAlertItem = {
  title?: string;
  severity?: string;
  created_at?: string;
  scan_id?: number;
  message?: string;
};

type IdentityHighRiskScan = {
  scan_id?: number;
  target?: string;
  risk_score?: number;
  risk_level?: string;
  total_findings?: number;
  completed_at?: string;
};

type IdentitySection = {
  total_identity_scans?: number;
  total_findings?: number;
  total_alerts?: number;
  monitored_assets_count?: number;
  risky_assets_count?: number;
  confirmed_breach_count?: number;
  confirmed_exposure_count?: number;
  possible_exposure_count?: number;
  public_mention_count?: number;
  high_risk_scans?: number;
  critical_risk_scans?: number;
  leakcheck_confirmed_breaches?: number;
  source_coverage?: IdentitySummaryMap;
  risk_summary?: IdentitySummaryMap;
  category_summary?: IdentitySummaryMap;
  recent_alerts?: IdentityAlertItem[];
  recent_high_risk_scans?: IdentityHighRiskScan[];
  recommendations?: string[];
};

type PhishingScanItem = {
  scan_id?: number | string | null;
  url?: string;
  domain?: string;
  final_category?: string;
  final_risk_score?: number;
  ml_probability?: number | string | null;
  virustotal_malicious?: number;
  virustotal_suspicious?: number;
  timestamp?: string;
};

type PhishingSection = {
  total_phishing_scans?: number;
  safe_urls?: number;
  suspicious_urls?: number;
  dangerous_urls?: number;
  risky_urls?: number;
  highest_risk_url?: PhishingScanItem | null;
  average_phishing_risk_score?: number;
  virustotal_malicious_total?: number;
  virustotal_suspicious_total?: number;
  latest_scans?: PhishingScanItem[];
  analyst_summary?: string;
  recommendations?: string[];
};

type PasswordCheckerLatestCheck = {
  checked_at?: string | null;
  masked_password?: "********";
  strength_label?: string | null;
  risk_level?: string | null;
  breached?: boolean | null;
  recommendation?: string | null;
};

type PasswordCheckerSummary = {
  status?: "Assessed" | "Not Assessed" | string;
  current_score?: number | null;
  risk_level?: string | null;
  last_checked_at?: string | null;
  total_checks?: number;
  safe_checks?: number;
  weak_checks?: number;
  breached_checks?: number | null;
  reused_checks?: number | null;
  latest_checks?: PasswordCheckerLatestCheck[];
  recommendations?: string[];
  message?: string;
};

type ReportPayload = {
  report_month: string;
  executive_summary: string[];
  password_checker_summary?: PasswordCheckerSummary;
  sections: Record<string, unknown>;
};

type ReportDetails = ReportSummary & {
  payload: ReportPayload;
};

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

function pushApiBase(candidates: string[], value: string) {
  if (value === "") {
    if (!candidates.includes("")) candidates.push("");
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

  if (envBase) return envBase;

  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      return `${window.location.protocol}//${host}:5000`;
    }
  }

  return DEFAULT_LOCAL_API_BASE;
})();

const MONTHLY_REPORT_API_BASE_CANDIDATES = (() => {
  const candidates: string[] = [];

  if (import.meta.env.DEV) pushApiBase(candidates, "");

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

function buildAuthedFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  const token = localStorage.getItem("sentinel_auth_token");

  if (token && token !== "cookie_based") {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return { ...init, credentials: "include", headers };
}

function buildCookieOnlyFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.delete("Authorization");
  return { ...init, credentials: "include", headers };
}

async function parseJsonResponse(response: Response) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}

async function refreshMonthlyReportSession(): Promise<boolean> {
  const refreshToken = localStorage.getItem("sentinel_refresh_token");

  for (const base of MONTHLY_REPORT_API_BASE_CANDIDATES) {
    try {
      const response = await fetch(buildMonthlyReportUrl("/api/auth/refresh", base), {
        method: "POST",
        credentials: "include",
        headers: refreshToken ? { "Content-Type": "application/json" } : undefined,
        body: refreshToken ? JSON.stringify({ refresh_token: refreshToken }) : undefined,
      });
      const contentType = String(response.headers.get("content-type") || "").toLowerCase();

      if (contentType.includes("text/html")) {
        continue;
      }

      const data = await parseJsonResponse(response);
      if (!response.ok || data?.success === false) {
        continue;
      }

      if (typeof data?.token === "string" && data.token) {
        localStorage.setItem("sentinel_auth_token", data.token);
      }
      if (typeof data?.refresh_token === "string" && data.refresh_token) {
        localStorage.setItem("sentinel_refresh_token", data.refresh_token);
      }

      return true;
    } catch {
      continue;
    }
  }

  return false;
}

async function fetchWithMonthlyReportAuth(
  input: RequestInfo | URL,
  init: RequestInit = {}
) {
  const cookieResponse = await fetch(input, buildCookieOnlyFetchInit(init));

  if (cookieResponse.status !== 401 && cookieResponse.status !== 403) {
    return cookieResponse;
  }

  const token = localStorage.getItem("sentinel_auth_token");
  if (token && token !== "cookie_based") {
    const tokenResponse = await fetch(input, buildAuthedFetchInit(init));
    if (tokenResponse.status !== 401 && tokenResponse.status !== 403) {
      return tokenResponse;
    }

    const refreshed = await refreshMonthlyReportSession().catch(() => false);
    if (refreshed) {
      return fetch(input, buildAuthedFetchInit(init));
    }

    return tokenResponse;
  }

  const refreshed = await refreshMonthlyReportSession().catch(() => false);
  if (refreshed) {
    return fetch(input, buildAuthedFetchInit(init));
  }

  return cookieResponse;
}

function buildMonthlyReportUrl(path: string, base: string) {
  return base ? `${base}${path}` : path;
}

async function fetchMonthlyReportResponse(
  path: string,
  init: RequestInit = {}
) {
  let lastError: unknown = null;
  let sawHtmlResponse = false;

  for (const base of MONTHLY_REPORT_API_BASE_CANDIDATES) {
    try {
      const response = await fetchWithMonthlyReportAuth(
        buildMonthlyReportUrl(path, base),
        init
      );

      const contentType = String(
        response.headers.get("content-type") || ""
      ).toLowerCase();

      if (contentType.includes("text/html")) {
        sawHtmlResponse = true;
        continue;
      }

      return response;
    } catch (error) {
      lastError = error;
    }
  }

  if (sawHtmlResponse) {
    throw new Error(
      "Monthly Reports endpoint returned HTML instead of JSON. Restart the frontend dev server and verify the backend URL."
    );
  }

  if (lastError instanceof Error) throw lastError;
  throw new Error("Unable to reach Monthly Reports endpoint.");
}

function formatDate(value?: string) {
  if (!value) return "Unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : format(parsed, "MMM d, yyyy - HH:mm");
}

function statusTone(status: string) {
  const normalized = String(status || "").toLowerCase();

  if (normalized === "completed") {
    return "mr-status mr-status-completed";
  }

  if (normalized === "failed") {
    return "mr-status mr-status-failed";
  }

  return "mr-status mr-status-pending";
}

function scoreTone(value: number | null) {
  if (value == null) return "mr-score-neutral";
  if (value > 0) return "mr-score-positive";
  if (value < 0) return "mr-score-negative";
  return "mr-score-neutral";
}

function formatScoreChange(value: number | null) {
  if (value == null) return "--";
  if (value > 0) return `+${value}`;
  return String(value);
}

function formatBytes(bytes?: number) {
  const value = Number(bytes || 0);
  if (value <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1
  );

  return `${(value / Math.pow(1024, index)).toFixed(1)} ${units[index]}`;
}

function humanize(value?: string) {
  return String(value || "")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function reportValue(value: unknown) {
  if (value === null || value === undefined || value === "") return "Not Available";
  return String(value);
}

function breachStatus(value: boolean | null | undefined) {
  if (value === true) return "Breached / Compromised";
  if (value === false) return "Not Breached";
  return "Not Available";
}

function OrbitalShieldIllustration() {
  return (
    <div className="mr-illustration">
      <svg viewBox="0 0 260 260" className="mr-illustration-svg" fill="none">
        <ellipse
          cx="130"
          cy="176"
          rx="54"
          ry="11"
          stroke="rgba(34,211,238,0.35)"
          strokeWidth="2"
        />
        <ellipse
          cx="130"
          cy="156"
          rx="101"
          ry="41"
          transform="rotate(-6 130 156)"
          stroke="rgba(0,183,255,0.75)"
          strokeWidth="2.4"
        />
        <ellipse
          cx="130"
          cy="144"
          rx="96"
          ry="36"
          transform="rotate(26 130 144)"
          stroke="rgba(0,183,255,0.28)"
          strokeWidth="1.5"
        />

        <path
          d="M130 30L183 55V117C183 148 161 176 130 191C99 176 77 148 77 117V55L130 30Z"
          fill="rgba(9,22,58,0.92)"
          stroke="#00B6FF"
          strokeWidth="3"
        />
        <path
          d="M130 43L171 64V113C171 137 154 159 130 171C106 159 89 137 89 113V64L130 43Z"
          fill="url(#shieldFill)"
          stroke="rgba(70,225,255,0.38)"
          strokeWidth="1.6"
        />
        <rect
          x="108"
          y="108"
          width="12"
          height="27"
          rx="3"
          fill="#18C8FF"
        />
        <rect
          x="124"
          y="96"
          width="12"
          height="39"
          rx="3"
          fill="#32D6FF"
        />
        <rect
          x="140"
          y="84"
          width="12"
          height="51"
          rx="3"
          fill="#52E3FF"
        />

        <defs>
          <linearGradient
            id="shieldFill"
            x1="130"
            y1="43"
            x2="130"
            y2="171"
            gradientUnits="userSpaceOnUse"
          >
            <stop stopColor="#153A85" stopOpacity="0.92" />
            <stop offset="1" stopColor="#09122E" stopOpacity="0.98" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
}

function IconShell({
  icon: Icon,
  compact = false,
}: {
  icon: React.ComponentType<{ className?: string }>;
  compact?: boolean;
}) {
  return (
    <div className={compact ? "mr-icon-shell mr-icon-shell-compact" : "mr-icon-shell"}>
      <Icon className="mr-icon" />
    </div>
  );
}

function HeroCard({
  icon,
  title,
  value,
  note,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  value: React.ReactNode;
  note: string;
}) {
  return (
    <div className="mr-hero-card">
      <div className="mr-card-head">
        <IconShell icon={icon} compact />
        <div className="mr-card-copy">
          <p className="mr-card-label">{title}</p>
          <p className="mr-card-value">{value}</p>
          <p className="mr-card-note">{note}</p>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  icon,
  title,
  value,
  note,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  value: React.ReactNode;
  note: string;
}) {
  return (
    <div className="mr-stat-card">
      <div className="mr-card-head">
        <IconShell icon={icon} />
        <div className="mr-card-copy">
          <p className="mr-card-label">{title}</p>
          <p className="mr-stat-value">{value}</p>
          <p className="mr-card-note">{note}</p>
        </div>
      </div>
      <div className="mr-wave">
        <svg width="118" height="34" viewBox="0 0 118 34" fill="none">
          <path
            d="M3 24C10 24 13 12 21 12C29 12 33 30 42 30C51 30 56 13 65 13C74 13 78 25 87 25C96 25 101 11 109 11C112 11 114 12 115 13"
            stroke="#00B6FF"
            strokeWidth="1.9"
            strokeLinecap="round"
          />
        </svg>
      </div>
    </div>
  );
}

function SectionBadge({ label }: { label: string }) {
  return <span className="mr-section-badge">{label}</span>;
}

export function MonthlyReportsPage() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [selectedReport, setSelectedReport] = useState<ReportDetails | null>(
    null
  );
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [generatingMode, setGeneratingMode] = useState<
    null | "latest_completed" | "current_month"
  >(null);
  const [driveUploadingMonth, setDriveUploadingMonth] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchReports = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetchMonthlyReportResponse("/api/reports/monthly");
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.error || "Unable to load monthly reports");
      }

      setReports(Array.isArray(data?.reports) ? data.reports : []);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to load monthly reports"
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchReports();
  }, []);

  const openReport = async (reportMonth: string) => {
    setDetailsLoading(true);
    try {
      const response = await fetchMonthlyReportResponse(
        `/api/reports/monthly/${reportMonth}`
      );
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.error || "Unable to open report");
      }

      setSelectedReport(data.report as ReportDetails);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Unable to open report");
    } finally {
      setDetailsLoading(false);
    }
  };

  const downloadReport = async (reportMonth: string) => {
    try {
      const response = await fetchMonthlyReportResponse(
        `/api/reports/monthly/${reportMonth}/download`
      );

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data?.error || "Download failed");
      }

      const contentType = String(
        response.headers.get("content-type") || ""
      ).toLowerCase();

      if (!contentType.includes("application/pdf")) {
        throw new Error("Server did not return a PDF file.");
      }

      const blob = await response.blob();
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = blobUrl;
      link.download = `sentinel-monthly-security-report-${reportMonth}.pdf`;
      link.style.display = "none";
      document.body.appendChild(link);
      link.click();
      link.remove();

      window.setTimeout(() => {
        URL.revokeObjectURL(blobUrl);
      }, 1000);
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Unable to download report"
      );
    }
  };

  const uploadReportToDrive = async (reportMonth: string) => {
    setDriveUploadingMonth(reportMonth);

    try {
      const response = await fetchMonthlyReportResponse(
        `/api/reports/monthly/${reportMonth}/upload-drive`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data?.error || "Google Drive upload failed");
      }

      const driveLink = String(data?.drive_link || data?.drive_file?.web_view_link || "");

      if (driveLink) {
        toast.success("Report uploaded to Google Drive", {
          description: "Opening the Drive file link now.",
        });
        window.open(driveLink, "_blank", "noopener,noreferrer");
      } else {
        toast.success("Report uploaded to Google Drive");
      }
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Unable to upload report to Google Drive"
      );
    } finally {
      setDriveUploadingMonth(null);
    }
  };

  const generateReport = async (
    mode: "latest_completed" | "current_month"
  ) => {
    setGeneratingMode(mode);

    try {
      const response = await fetchMonthlyReportResponse(
        "/api/reports/monthly/generate",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ generation_mode: mode }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.error || "Report generation failed");
      }

      toast.success("Monthly report generated");
      await fetchReports();

      if (data?.report?.report_month) {
        await openReport(String(data.report.report_month));
      }
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Unable to generate report"
      );
    } finally {
      setGeneratingMode(null);
    }
  };

  const latest = reports[0];

  const pcapSection = selectedReport?.payload?.sections?.pcap as
    | PcapSection
    | undefined;

  const vaultSection = selectedReport?.payload?.sections?.vault as
    | VaultSection
    | undefined;

  const identitySection = selectedReport?.payload?.sections?.identity as
    | IdentitySection
    | undefined;

  const phishingSection = selectedReport?.payload?.sections?.phishing as
    | PhishingSection
    | undefined;

  const passwordSection =
    (selectedReport?.payload?.password_checker_summary as
      | PasswordCheckerSummary
      | undefined) ||
    (selectedReport?.payload?.sections?.password_checker as
      | PasswordCheckerSummary
      | undefined);

  const activeCoverage =
    latest?.available_sections && latest.available_sections.length > 0
      ? latest.available_sections.join(" / ")
      : "pcap / vault / identity / phishing";

  const heroCards = useMemo(
    () => [
      {
        icon: CalendarDays,
        title: "Latest Cycle",
        value: latest?.report_month || "--",
        note: "Most recent archived monthly report",
      },
      {
        icon: FolderOpen,
        title: "Reports Archive",
        value: reports.length,
        note: "Stored monthly reports",
      },
      {
        icon: Shield,
        title: "ACDRTS Coverage",
        value: activeCoverage,
        note: "Live modules in this cycle",
      },
    ],
    [activeCoverage, latest?.report_month, reports.length]
  );

  const statCards = useMemo(
    () => [
      {
        icon: CalendarDays,
        title: "Latest Report Cycle",
        value: latest?.report_month || "--",
        note: "Most recent archived monthly report",
      },
      {
        icon: ShieldCheck,
        title: "Available Sections",
        value: latest?.available_section_count ?? 0,
        note: "Current live modules included in reporting",
      },
      {
        icon: AlertTriangle,
        title: "Latest PCAP Threats",
        value: latest?.latest_pcap_threat_count ?? 0,
        note: "Threat count captured from the most recent PCAP section",
      },
      {
        icon: Lock,
        title: "Latest Vault Events",
        value: latest?.latest_vault_event_count ?? 0,
        note: "Encrypted File Vault activity captured in this cycle",
      },
      {
        icon: Eye,
        title: "Identity Scans",
        value: latest?.latest_identity_scan_count ?? 0,
        note: "Identity Leak Monitor scans captured in this cycle",
      },
      {
        icon: AlertTriangle,
        title: "Confirmed Breaches",
        value: latest?.latest_identity_confirmed_breach_count ?? 0,
        note: "Confirmed identity breach findings in the latest report",
      },
      {
        icon: Shield,
        title: "Risky Assets",
        value: latest?.latest_identity_risky_asset_count ?? 0,
        note: "Monitored identity assets needing attention",
      },
      {
        icon: Eye,
        title: "Phishing Scans",
        value: latest?.latest_phishing_scan_count ?? 0,
        note: "Phishing Scanner activity captured in this cycle",
      },
      {
        icon: AlertTriangle,
        title: "Risky URLs",
        value: latest?.latest_phishing_risky_url_count ?? 0,
        note: "Suspicious plus dangerous phishing scan results",
      },
      {
        icon: Shield,
        title: "Dangerous URLs",
        value: latest?.latest_phishing_dangerous_url_count ?? 0,
        note: "Dangerous phishing URLs in the latest report",
      },
    ],
    [latest]
  );

  return (
    <div className="mr-page">
      <div className="mr-surface">
        <div className="mr-top-grid">
          <section className="mr-hero-panel">
            <div className="mr-hero-grid">
              <div className="mr-hero-head">
                <IconShell icon={FileText} />

                <div className="mr-hero-copy">
                  <h1 className="mr-title">Monthly Reports</h1>
                  <p className="mr-subtitle">
                    Track your monthly security activity in one polished view
                    across Sentinel AI.
                  </p>
                  <p className="mr-description">
                    This workspace highlights generated monthly reports,
                    surfaces PCAP activity, Encrypted File Vault activity,
                    and Identity Leak Monitor exposure summaries.
                  </p>
                </div>
              </div>

              <div className="mr-hero-illustration-wrap">
                <OrbitalShieldIllustration />
              </div>
            </div>

            <div className="mr-hero-cards">
              {heroCards.map((card) => (
                <HeroCard
                  key={card.title}
                  icon={card.icon}
                  title={card.title}
                  value={card.value}
                  note={card.note}
                />
              ))}
            </div>
          </section>

          <aside className="mr-control-panel">
            <div className="mr-control-head">
              <h2 className="mr-control-title">Control Center</h2>
              <Sparkles className="mr-control-sparkle" />
            </div>

            <p className="mr-control-copy">
              Create a finalized monthly report for your archive or generate a
              live snapshot of the current month whenever you need a quick
              security review.
            </p>
            <p className="mr-control-copy mr-control-copy-secondary">
              Fast generation, clean history, PCAP reporting, and encrypted
              vault activity summaries.
            </p>

            <div className="mr-button-stack">
              <button
                type="button"
                onClick={() => void generateReport("latest_completed")}
                disabled={generatingMode !== null}
                className="mr-button mr-button-primary"
              >
                {generatingMode === "latest_completed" ? (
                  <LoaderCircle className="mr-button-icon mr-spin" />
                ) : (
                  <RotateCcw className="mr-button-icon" />
                )}
                Generate Last Completed Month
              </button>

              <button
                type="button"
                onClick={() => void generateReport("current_month")}
                disabled={generatingMode !== null}
                className="mr-button mr-button-secondary"
              >
                {generatingMode === "current_month" ? (
                  <LoaderCircle className="mr-button-icon mr-spin" />
                ) : (
                  <RefreshCw className="mr-button-icon" />
                )}
                Generate Current Snapshot
              </button>
            </div>
          </aside>
        </div>

        <div className="mr-stats-grid">
          {statCards.map((card) => (
            <StatCard
              key={card.title}
              icon={card.icon}
              title={card.title}
              value={card.value}
              note={card.note}
            />
          ))}
        </div>

        <section className="mr-history-panel">
          <div className="mr-history-header">
            <div className="mr-history-title-row">
              <IconShell icon={CalendarDays} compact />
              <div>
                <h3 className="mr-history-title">Report History</h3>
                <p className="mr-history-copy">
                  Browse generated monthly reports, reopen previous cycles, and
                  export polished PDFs whenever needed.
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => void fetchReports()}
              className="mr-refresh-button"
            >
              <RefreshCw className="mr-button-icon" />
              Refresh
            </button>
          </div>

          <div className="mr-history-body">
            {loading ? (
              <div className="mr-loading-stack">
                <div className="mr-skeleton-block" />
                <div className="mr-skeleton-block" />
              </div>
            ) : error ? (
              <div className="mr-error-box">{error}</div>
            ) : reports.length === 0 ? (
              <div className="mr-empty-box">
                <p className="mr-empty-title">No monthly reports available yet</p>
                <p className="mr-empty-copy">
                  Start by generating a current snapshot or create the latest
                  completed monthly report to begin building your reporting
                  archive.
                </p>
              </div>
            ) : (
              <div className="mr-history-list">
                {reports.map((report) => (
                  <article key={report.report_month} className="mr-report-row">
                    <div className="mr-report-grid">
                      <div className="mr-report-main">
                        <IconShell icon={CalendarDays} compact />
                        <div>
                          <p className="mr-report-month">{report.report_month}</p>
                          <p className="mr-report-date">
                            {formatDate(report.generated_at)}
                          </p>
                        </div>
                      </div>

                      <div className="mr-report-cell">
                        <span className={statusTone(report.status)}>
                          {report.status}
                        </span>
                        <p className="mr-report-meta">
                          PCAP threats: {report.latest_pcap_threat_count ?? 0}
                        </p>
                      </div>

                      <div className="mr-report-cell">
                        <p className="mr-cell-label">Sections</p>
                        <div className="mr-section-wrap">
                          {(report.available_sections || []).length > 0 ? (
                            (report.available_sections || []).map((section) => (
                              <SectionBadge key={section} label={section} />
                            ))
                          ) : (
                            <span className="mr-dash">--</span>
                          )}
                        </div>
                      </div>

                      <div className="mr-report-cell">
                        <p className="mr-cell-label">Vault Events</p>
                        <p className="mr-cell-number">
                          {report.latest_vault_event_count ?? 0}
                        </p>
                      </div>

                      <div className="mr-report-cell">
                        <p className="mr-cell-label">Wrong Password</p>
                        <div className={`mr-score-row ${scoreTone(report.latest_vault_wrong_password_count ?? 0)}`}>
                          <span>
                            {report.latest_vault_wrong_password_count ?? 0}
                          </span>
                        </div>
                      </div>

                      <div className="mr-report-cell">
                        <p className="mr-cell-label">Identity Summary</p>
                        <p className="mr-report-meta">
                          Scans: {report.latest_identity_scan_count ?? 0}
                        </p>
                        <p className="mr-report-meta">
                          Alerts: {report.latest_identity_alert_count ?? 0}
                        </p>
                        <p className="mr-report-meta">
                          Breaches: {report.latest_identity_confirmed_breach_count ?? 0}
                        </p>
                        <p className="mr-report-meta">
                          Risky Assets: {report.latest_identity_risky_asset_count ?? 0}
                        </p>
                      </div>

                      <div className="mr-actions-cell">
                        <button
                          type="button"
                          onClick={() => void openReport(report.report_month)}
                          className="mr-row-button"
                        >
                          <Eye className="mr-button-icon" />
                          View
                        </button>

                        <button
                          type="button"
                          disabled={!report.pdf_available}
                          onClick={() => void downloadReport(report.report_month)}
                          className="mr-row-button mr-row-button-muted"
                        >
                          <Download className="mr-button-icon" />
                          PDF
                        </button>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      <Sheet
        open={!!selectedReport}
        onOpenChange={(open) => !open && setSelectedReport(null)}
      >
        <SheetContent side="right" className="mr-sheet-panel">
          <SheetHeader className="mr-sheet-header">
            <SheetTitle className="mr-sheet-title">
              {selectedReport?.report_month || "Monthly Report"}
            </SheetTitle>
            <SheetDescription className="mr-sheet-description">
              Review the full monthly report, inspect populated sections, and
              follow the security highlights captured for this reporting cycle.
            </SheetDescription>
          </SheetHeader>

          {detailsLoading ? (
            <div className="mr-sheet-body">
              <div className="mr-skeleton-block mr-skeleton-block-sheet" />
              <div className="mr-skeleton-block mr-skeleton-block-tall" />
            </div>
          ) : selectedReport ? (
            <div className="mr-sheet-body">
              <section className="mr-sheet-card">
                <div className="mr-sheet-card-head">
                  <div>
                    <p className="mr-sheet-kicker">Executive Summary</p>
                    <p className="mr-sheet-copy">
                      {selectedReport.payload.executive_summary?.join(" ") ||
                        "No summary available."}
                    </p>
                  </div>
                  <span className={statusTone(selectedReport.status)}>
                    {selectedReport.status}
                  </span>
                </div>
              </section>

              <section className="mr-sheet-card">
                <p className="mr-sheet-section-title">Available Sections</p>
                <div className="mr-section-wrap">
                  {(selectedReport.available_sections || []).map((section) => (
                    <SectionBadge key={section} label={section} />
                  ))}
                </div>
              </section>

              {pcapSection ? (
                <section className="mr-sheet-card mr-sheet-card-strong">
                  <div className="mr-sheet-heading">
                    <ShieldCheck className="mr-sheet-heading-icon" />
                    <p className="mr-sheet-section-title">
                      PCAP Security Overview
                    </p>
                  </div>

                  <div className="mr-sheet-stats-grid">
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Files Analyzed</p>
                      <p className="mr-sheet-mini-value">
                        {pcapSection.files_analyzed ?? 0}
                      </p>
                    </div>

                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Threats Detected</p>
                      <p className="mr-sheet-mini-value">
                        {pcapSection.threats_detected ?? 0}
                      </p>
                    </div>

                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">High / Critical Findings</p>
                      <p className="mr-sheet-mini-value">
                        {(pcapSection.high_alerts ?? 0) +
                          (pcapSection.critical_alerts ?? 0)}
                      </p>
                    </div>

                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Score Change</p>
                      <p className="mr-sheet-mini-value mr-sheet-mini-trend">
                        <TrendingUp className="mr-sheet-heading-icon" />
                        {pcapSection.score_change ?? "n/a"}
                      </p>
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Most Frequent Threat Types</p>
                    <div className="mr-section-wrap">
                      {(pcapSection.top_threat_types || []).length > 0 ? (
                        pcapSection.top_threat_types?.map((item) => (
                          <SectionBadge
                            key={item.name}
                            label={`${item.name} (${item.count})`}
                          />
                        ))
                      ) : (
                        <span className="mr-sheet-muted">
                          No threat breakdown available for this month.
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Recommended Next Steps</p>
                    <div className="mr-sheet-list">
                      {(pcapSection.recommendations || []).length > 0 ? (
                        pcapSection.recommendations?.map((item) => (
                          <div key={item} className="mr-sheet-list-item">
                            {item}
                          </div>
                        ))
                      ) : (
                        <div className="mr-sheet-list-item mr-sheet-muted-box">
                          No recommendations available for this report.
                        </div>
                      )}
                    </div>
                  </div>
                </section>
              ) : null}

              {vaultSection ? (
                <section className="mr-sheet-card mr-sheet-card-strong">
                  <div className="mr-sheet-heading">
                    <Lock className="mr-sheet-heading-icon" />
                    <p className="mr-sheet-section-title">
                      Encrypted File Vault Overview
                    </p>
                  </div>

                  <div className="mr-sheet-stats-grid">
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Uploads</p>
                      <p className="mr-sheet-mini-value">
                        {vaultSection.uploads ?? 0}
                      </p>
                    </div>

                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Downloads</p>
                      <p className="mr-sheet-mini-value">
                        {vaultSection.downloads ?? 0}
                      </p>
                    </div>

                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Deletes</p>
                      <p className="mr-sheet-mini-value">
                        {vaultSection.deletes ?? 0}
                      </p>
                    </div>

                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Offline Enabled</p>
                      <p className="mr-sheet-mini-value">
                        {vaultSection.offline_enabled ?? 0}
                      </p>
                    </div>

                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Offline Disabled</p>
                      <p className="mr-sheet-mini-value">
                        {vaultSection.offline_disabled ?? 0}
                      </p>
                    </div>

                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Wrong Password</p>
                      <p className="mr-sheet-mini-value">
                        {vaultSection.wrong_password ?? 0}
                      </p>
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Vault Storage Summary</p>
                    <div className="mr-sheet-stats-grid">
                      <div className="mr-sheet-mini-card">
                        <p className="mr-sheet-kicker">Total Events</p>
                        <p className="mr-sheet-mini-value">
                          {vaultSection.total_events ?? 0}
                        </p>
                      </div>

                      <div className="mr-sheet-mini-card">
                        <p className="mr-sheet-kicker">Unique Files</p>
                        <p className="mr-sheet-mini-value">
                          {vaultSection.unique_files ?? 0}
                        </p>
                      </div>

                      <div className="mr-sheet-mini-card">
                        <p className="mr-sheet-kicker">Uploaded Storage</p>
                        <p className="mr-sheet-mini-value">
                          {formatBytes(vaultSection.total_storage_bytes)}
                        </p>
                      </div>

                      <div className="mr-sheet-mini-card">
                        <p className="mr-sheet-kicker">Largest File</p>
                        <p className="mr-sheet-mini-value">
                          {vaultSection.largest_file || "n/a"}
                        </p>
                      </div>
                    </div>
                  </div>

                  {vaultSection.most_active_file ? (
                    <div className="mr-sheet-group">
                      <p className="mr-sheet-subtitle">Most Active Vault File</p>
                      <div className="mr-section-wrap">
                        <SectionBadge
                          label={`${vaultSection.most_active_file.filename} (${vaultSection.most_active_file.activity_count})`}
                        />
                      </div>
                    </div>
                  ) : null}

                  {vaultSection.most_failed_file ? (
                    <div className="mr-sheet-group">
                      <p className="mr-sheet-subtitle">Most Failed Password File</p>
                      <div className="mr-section-wrap">
                        <SectionBadge
                          label={`${vaultSection.most_failed_file.filename} (${vaultSection.most_failed_file.wrong_password_attempts})`}
                        />
                      </div>
                    </div>
                  ) : null}

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Vault Action Breakdown</p>
                    <div className="mr-section-wrap">
                      {(vaultSection.action_breakdown || []).length > 0 ? (
                        vaultSection.action_breakdown?.map((item) => (
                          <SectionBadge
                            key={item.name}
                            label={`${humanize(item.name)} (${item.count})`}
                          />
                        ))
                      ) : (
                        <span className="mr-sheet-muted">
                          No vault action breakdown available for this month.
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Recommended Next Steps</p>
                    <div className="mr-sheet-list">
                      {(vaultSection.recommendations || []).length > 0 ? (
                        vaultSection.recommendations?.map((item) => (
                          <div key={item} className="mr-sheet-list-item">
                            {item}
                          </div>
                        ))
                      ) : (
                        <div className="mr-sheet-list-item mr-sheet-muted-box">
                          No vault recommendations available for this report.
                        </div>
                      )}
                    </div>
                  </div>
                </section>
              ) : null}

              {identitySection ? (
                <section className="mr-sheet-card mr-sheet-card-strong">
                  <div className="mr-sheet-heading">
                    <Eye className="mr-sheet-heading-icon" />
                    <p className="mr-sheet-section-title">
                      Identity Leak Monitor Activity
                    </p>
                  </div>

                  <div className="mr-sheet-stats-grid">
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Total Scans</p>
                      <p className="mr-sheet-mini-value">
                        {identitySection.total_identity_scans ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Total Findings</p>
                      <p className="mr-sheet-mini-value">
                        {identitySection.total_findings ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Alerts Generated</p>
                      <p className="mr-sheet-mini-value">
                        {identitySection.total_alerts ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Confirmed Breaches</p>
                      <p className="mr-sheet-mini-value">
                        {identitySection.confirmed_breach_count ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Confirmed Exposures</p>
                      <p className="mr-sheet-mini-value">
                        {identitySection.confirmed_exposure_count ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Risky Assets</p>
                      <p className="mr-sheet-mini-value">
                        {identitySection.risky_assets_count ?? 0}
                      </p>
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Risk Level Breakdown</p>
                    <div className="mr-section-wrap">
                      {["low", "medium", "high", "critical"].map((key) => (
                        <SectionBadge
                          key={key}
                          label={`${humanize(key)} (${identitySection.risk_summary?.[key] ?? 0})`}
                        />
                      ))}
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Category Breakdown</p>
                    <div className="mr-section-wrap">
                      {[
                        "public_mention",
                        "possible_exposure",
                        "confirmed_exposure",
                        "confirmed_breach",
                      ].map((key) => (
                        <SectionBadge
                          key={key}
                          label={`${humanize(key)} (${identitySection.category_summary?.[key] ?? 0})`}
                        />
                      ))}
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Monitored Assets Status</p>
                    <div className="mr-section-wrap">
                      <SectionBadge
                        label={`Total (${identitySection.monitored_assets_count ?? 0})`}
                      />
                      <SectionBadge
                        label={`Risky (${identitySection.risky_assets_count ?? 0})`}
                      />
                      <SectionBadge
                        label={`LeakCheck Breaches (${identitySection.leakcheck_confirmed_breaches ?? 0})`}
                      />
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Recent Identity Alerts</p>
                    <div className="mr-sheet-list">
                      {(identitySection.recent_alerts || []).length > 0 ? (
                        identitySection.recent_alerts?.map((alert) => (
                          <div
                            key={`${alert.scan_id}-${alert.created_at}-${alert.title}`}
                            className="mr-sheet-list-item"
                          >
                            #{alert.scan_id ?? "-"} - {alert.title || "Identity alert"} ({alert.severity || "Medium"})
                          </div>
                        ))
                      ) : (
                        <div className="mr-sheet-list-item mr-sheet-muted-box">
                          No Identity alerts were recorded for this cycle.
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Recent High-Risk Scans</p>
                    <div className="mr-sheet-list">
                      {(identitySection.recent_high_risk_scans || []).length > 0 ? (
                        identitySection.recent_high_risk_scans?.map((scan) => (
                          <div
                            key={`${scan.scan_id}-${scan.completed_at}`}
                            className="mr-sheet-list-item"
                          >
                            #{scan.scan_id ?? "-"} - {scan.target || "No target"} - {scan.risk_level || "Low"} ({scan.total_findings ?? 0} findings)
                          </div>
                        ))
                      ) : (
                        <div className="mr-sheet-list-item mr-sheet-muted-box">
                          No high-risk Identity scans were recorded for this cycle.
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Recommendation Summary</p>
                    <div className="mr-sheet-list">
                      {(identitySection.recommendations || []).length > 0 ? (
                        identitySection.recommendations?.map((item) => (
                          <div key={item} className="mr-sheet-list-item">
                            {item}
                          </div>
                        ))
                      ) : (
                        <div className="mr-sheet-list-item mr-sheet-muted-box">
                          Identity data was not included in this archived cycle.
                        </div>
                      )}
                    </div>
                  </div>
                </section>
              ) : selectedReport.available_sections?.includes("identity") ? null : (
                <section className="mr-sheet-card">
                  <div className="mr-sheet-heading">
                    <Eye className="mr-sheet-heading-icon" />
                    <p className="mr-sheet-section-title">Identity Leak Monitor Activity</p>
                  </div>
                  <p className="mr-sheet-muted">
                    Identity data was not included in this archived cycle.
                  </p>
                </section>
              )}

              {phishingSection ? (
                <section className="mr-sheet-card mr-sheet-card-strong">
                  <div className="mr-sheet-heading">
                    <AlertTriangle className="mr-sheet-heading-icon" />
                    <p className="mr-sheet-section-title">
                      Phishing Scanner Activity
                    </p>
                  </div>

                  <div className="mr-sheet-stats-grid">
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Total Scans</p>
                      <p className="mr-sheet-mini-value">
                        {phishingSection.total_phishing_scans ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Safe URLs</p>
                      <p className="mr-sheet-mini-value">
                        {phishingSection.safe_urls ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Suspicious URLs</p>
                      <p className="mr-sheet-mini-value">
                        {phishingSection.suspicious_urls ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Dangerous URLs</p>
                      <p className="mr-sheet-mini-value">
                        {phishingSection.dangerous_urls ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">Average Risk</p>
                      <p className="mr-sheet-mini-value">
                        {phishingSection.average_phishing_risk_score ?? 0}
                      </p>
                    </div>
                    <div className="mr-sheet-mini-card">
                      <p className="mr-sheet-kicker">VT Malicious / Suspicious</p>
                      <p className="mr-sheet-mini-value">
                        {phishingSection.virustotal_malicious_total ?? 0} / {phishingSection.virustotal_suspicious_total ?? 0}
                      </p>
                    </div>
                  </div>

                  {phishingSection.highest_risk_url ? (
                    <div className="mr-sheet-group">
                      <p className="mr-sheet-subtitle">Highest Risk URL</p>
                      <div className="mr-sheet-list">
                        <div className="mr-sheet-list-item">
                          {phishingSection.highest_risk_url.domain || phishingSection.highest_risk_url.url || "Unknown URL"} - {humanize(phishingSection.highest_risk_url.final_category)} ({phishingSection.highest_risk_url.final_risk_score ?? 0})
                        </div>
                      </div>
                    </div>
                  ) : null}

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Analyst Summary</p>
                    <p className="mr-sheet-muted">
                      {phishingSection.analyst_summary || "No phishing scans were recorded during this cycle."}
                    </p>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Latest Phishing Scans</p>
                    <div className="mr-sheet-list">
                      {(phishingSection.latest_scans || []).length > 0 ? (
                        phishingSection.latest_scans?.map((scan, index) => (
                          <div
                            key={`${scan.scan_id || scan.timestamp || "phishing"}-${index}`}
                            className="mr-sheet-list-item"
                          >
                            #{scan.scan_id ?? "-"} - {scan.domain || scan.url || "Unknown URL"} - {humanize(scan.final_category)} ({scan.final_risk_score ?? 0})
                          </div>
                        ))
                      ) : (
                        <div className="mr-sheet-list-item mr-sheet-muted-box">
                          No phishing scans were recorded during this cycle.
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Recommendations</p>
                    <div className="mr-sheet-list">
                      {(phishingSection.recommendations || []).map((item) => (
                        <div key={item} className="mr-sheet-list-item">
                          {item}
                        </div>
                      ))}
                    </div>
                  </div>
                </section>
              ) : null}

              {passwordSection ? (
                <section className="mr-sheet-card mr-sheet-card-strong">
                  <div className="mr-sheet-heading">
                    <Shield className="mr-sheet-heading-icon" />
                    <p className="mr-sheet-section-title">
                      Password Checker Security Summary
                    </p>
                  </div>

                  {passwordSection.status === "Assessed" ? (
                    <>
                      <div className="mr-sheet-stats-grid">
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Assessment Status</p>
                          <p className="mr-sheet-mini-value">Assessed</p>
                        </div>
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Current Risk Level</p>
                          <p className="mr-sheet-mini-value">
                            {reportValue(passwordSection.risk_level)}
                          </p>
                        </div>
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Module Score</p>
                          <p className="mr-sheet-mini-value">
                            {reportValue(passwordSection.current_score)}
                          </p>
                        </div>
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Last Check</p>
                          <p className="mr-sheet-mini-value">
                            {reportValue(passwordSection.last_checked_at)}
                          </p>
                        </div>
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Total Checks</p>
                          <p className="mr-sheet-mini-value">
                            {passwordSection.total_checks ?? 0}
                          </p>
                        </div>
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Safe Checks</p>
                          <p className="mr-sheet-mini-value">
                            {passwordSection.safe_checks ?? 0}
                          </p>
                        </div>
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Weak Checks</p>
                          <p className="mr-sheet-mini-value">
                            {passwordSection.weak_checks ?? 0}
                          </p>
                        </div>
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Breached Checks</p>
                          <p className="mr-sheet-mini-value">
                            {reportValue(passwordSection.breached_checks)}
                          </p>
                        </div>
                        <div className="mr-sheet-mini-card">
                          <p className="mr-sheet-kicker">Reused Checks</p>
                          <p className="mr-sheet-mini-value">
                            {reportValue(passwordSection.reused_checks)}
                          </p>
                        </div>
                      </div>

                      <div className="mr-sheet-group">
                        <p className="mr-sheet-subtitle">Latest Password Checks</p>
                        <div className="mr-sheet-list">
                          {(passwordSection.latest_checks || []).length > 0 ? (
                            passwordSection.latest_checks?.map((item, index) => (
                              <div
                                key={`${item.checked_at || "password-check"}-${index}`}
                                className="mr-sheet-list-item"
                              >
                                {reportValue(item.checked_at)} - ******** - {reportValue(item.strength_label || item.risk_level)} - {breachStatus(item.breached)}
                                {item.recommendation ? ` - ${item.recommendation}` : ""}
                              </div>
                            ))
                          ) : (
                            <div className="mr-sheet-list-item mr-sheet-muted-box">
                              No password check history is available.
                            </div>
                          )}
                        </div>
                      </div>
                    </>
                  ) : (
                    <p className="mr-sheet-muted">
                      Password Checker has not been assessed yet.
                      <br />
                      No password check history is currently available for this user.
                    </p>
                  )}

                  <div className="mr-sheet-group">
                    <p className="mr-sheet-subtitle">Recommendations</p>
                    <div className="mr-sheet-list">
                      {(passwordSection.recommendations || []).map((item) => (
                        <div key={item} className="mr-sheet-list-item">
                          {item}
                        </div>
                      ))}
                    </div>
                  </div>
                </section>
              ) : null}

              {!pcapSection && !vaultSection && !identitySection && !phishingSection && !passwordSection ? (
                <section className="mr-sheet-card">
                  <div className="mr-sheet-heading">
                    <HardDrive className="mr-sheet-heading-icon" />
                    <p className="mr-sheet-section-title">No Populated Sections</p>
                  </div>
                  <p className="mr-sheet-muted">
                    This report currently has no populated module sections.
                  </p>
                </section>
              ) : null}
            </div>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}

export default MonthlyReportsPage;
