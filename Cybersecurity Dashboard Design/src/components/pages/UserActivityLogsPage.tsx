import React, { useEffect, useMemo, useState } from "react";
import { motion } from "motion/react";
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  Clock3,
  Cpu,
  Download,
  Eye,
  FileSearch,
  Filter,
  Globe,
  HardDrive,
  Lock,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  User,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { ScrollArea } from "../ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "../ui/sheet";
import { cn } from "../ui/utils";
import {
  ACTIVITY_API_BASE,
  buildActivityAuthedFetchInit,
} from "../../utils/activityLogs";
import "./MonthlyReportsPage.css";
import "./UserActivityLogsPage.css";

type ActivityModule = "auth" | "pcap" | "vault" | "identity" | "password" | "phishing";
type ActivityStatus = "success" | "failed" | "warning" | "info";
type ActivitySeverity = "low" | "medium" | "high" | "critical";

type ActivityLogItem = {
  event_id: string;
  module: ActivityModule;
  module_label?: string;
  action_type: string;
  action_label?: string;
  status: ActivityStatus;
  severity: ActivitySeverity;
  title: string;
  description: string;
  target_id?: string | null;
  target_label?: string | null;
  session_id?: string | null;
  ip_address?: string | null;
  created_at: string;
  risk_score?: number | null;
  is_sensitive: boolean;
  is_suspicious?: boolean;
  metadata?: Record<string, unknown>;
};

type FilterState = {
  search: string;
  module: "all" | ActivityModule;
  action_type: string;
  status: "all" | ActivityStatus;
  severity: "all" | ActivitySeverity;
  start_date: string;
  end_date: string;
};

const PAGE_SIZE = 12;
const SESSION_EXPIRED_MESSAGE = "Session expired, please log in again";

const defaultFilters: FilterState = {
  search: "",
  module: "all",
  action_type: "all",
  status: "all",
  severity: "all",
  start_date: "",
  end_date: "",
};

const suspiciousActionTypes = new Set([
  "new_device_login",
  "suspicious_login_detected",
  "pcap_threat_detected",
  "vault_wrong_password",
  "identity_alert_generated",
  "identity_confirmed_breach_detected",
  "password_breach_detected",
  "weak_password_detected",
  "phishing_suspicious_url_reviewed",
  "phishing_dangerous_url_detected",
]);

function normalizeModuleLabel(event: ActivityLogItem) {
  if (event.module === "auth") return "Authentication";
  if (event.module === "pcap") return "PCAP Analyzer";
  if (event.module === "vault") return "Encrypted File Vault";
  if (event.module === "identity") return "Identity Leak Monitor";
  if (event.module === "password") return "Password Checker";
  if (event.module === "phishing") return "Phishing Scanner";
  return event.module_label || "Activity";
}

function formatDateTime(value?: string | null) {
  if (!value) return "Unavailable";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatRelativeTime(value?: string | null) {
  if (!value) return "moments ago";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;

  const deltaSeconds = Math.round((Date.now() - parsed.getTime()) / 1000);
  const absSeconds = Math.abs(deltaSeconds);

  if (absSeconds < 60) return "moments ago";
  if (absSeconds < 3600) return `${Math.round(absSeconds / 60)}m ago`;
  if (absSeconds < 86400) return `${Math.round(absSeconds / 3600)}h ago`;
  return `${Math.round(absSeconds / 86400)}d ago`;
}

function formatMetric(value: number | null | undefined) {
  return Intl.NumberFormat().format(Number(value ?? 0) || 0);
}

function humanize(value?: string | null) {
  return String(value || "")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function metadataValue(value: unknown) {
  if (value == null || value === "") return "Unavailable";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function escapeCsvValue(value: unknown) {
  const stringValue = String(value ?? "");
  if (/[",\n]/.test(stringValue)) {
    return `"${stringValue.replace(/"/g, '""')}"`;
  }
  return stringValue;
}

function isSuspicious(event: ActivityLogItem) {
  if (suspiciousActionTypes.has(event.action_type)) return true;
  if (event.module === "pcap" && event.action_type.includes("threat")) return true;
  if (event.module === "vault" && event.status === "failed") return true;
  if (event.module === "identity" && ["high", "critical"].includes(event.severity)) return true;
  if (event.module === "password" && ["high", "critical"].includes(event.severity)) return true;
  if (event.module === "phishing" && ["medium", "high", "critical"].includes(event.severity)) return true;

  return Boolean(
    event.is_suspicious &&
      (event.action_type.includes("suspicious") ||
        event.action_type.includes("new_device") ||
        event.severity === "high" ||
        event.severity === "critical")
  );
}

function statusChip(status: ActivityStatus) {
  if (status === "success") return "border-cyan-400/18 bg-cyan-500/12 text-cyan-100";
  if (status === "failed") return "border-rose-400/18 bg-rose-500/12 text-rose-100";
  if (status === "warning") return "border-orange-400/18 bg-orange-500/12 text-orange-100";
  return "border-sky-400/16 bg-sky-500/12 text-sky-100";
}

function severityChip(severity: ActivitySeverity) {
  if (severity === "critical") return "border-rose-400/18 bg-rose-500/16 text-rose-100";
  if (severity === "high") return "border-indigo-400/18 bg-indigo-500/16 text-indigo-100";
  if (severity === "medium") return "border-sky-400/18 bg-sky-500/16 text-sky-100";
  return "border-cyan-400/16 bg-cyan-500/14 text-cyan-100";
}

function activityIcon(event: ActivityLogItem) {
  if (event.module === "vault") {
    if (event.action_type.includes("download")) return Download;
    if (event.action_type.includes("offline")) return HardDrive;
    if (event.action_type.includes("password")) return Lock;
    if (event.action_type.includes("delete")) return ShieldAlert;
    return ShieldCheck;
  }

  if (event.module === "pcap") {
    if (event.action_type.includes("threat")) return ShieldAlert;
    if (event.action_type.includes("report") || event.action_type.includes("evidence")) {
      return Eye;
    }
    return FileSearch;
  }

  if (event.module === "identity") {
    if (event.action_type.includes("alert") || event.action_type.includes("breach")) return ShieldAlert;
    if (event.action_type.includes("report") || event.action_type.includes("viewed")) return Eye;
    if (event.action_type.includes("asset")) return Globe;
    return FileSearch;
  }

  if (event.module === "password") {
    if (event.action_type.includes("breach") || event.action_type.includes("weak")) return ShieldAlert;
    if (event.action_type.includes("history")) return Eye;
    return Lock;
  }

  if (event.module === "phishing") {
    if (event.action_type.includes("dangerous") || event.action_type.includes("suspicious")) return ShieldAlert;
    return Globe;
  }

  if (event.action_type.includes("password")) return Lock;
  if (event.action_type.includes("device") || event.action_type.includes("profile")) {
    return User;
  }
  if (event.status === "failed" || isSuspicious(event)) return AlertTriangle;
  return ShieldCheck;
}

function summarizeTarget(event: ActivityLogItem) {
  const target =
    event.target_label ||
    String(
      event.metadata?.file_name ||
        event.metadata?.filename ||
        event.metadata?.upload_name ||
        event.metadata?.device_label ||
        event.target_id ||
        "Activity target"
    );

  return target.length > 34 ? `${target.slice(0, 31)}...` : target;
}

function eventSupportingLine(event: ActivityLogItem) {
  const parts: string[] = [];

  if (event.description) parts.push(event.description);

  if (event.module === "pcap" && event.metadata?.risk_level) {
    parts.push(`Risk ${String(event.metadata.risk_level)}`);
  }

  if (event.module === "auth" && event.metadata?.device_label) {
    parts.push(String(event.metadata.device_label));
  }

  if (event.module === "vault" && event.metadata?.filename) {
    parts.push(String(event.metadata.filename));
  }

  if (event.module === "identity") {
    if (event.metadata?.risk_level) parts.push(`Risk ${String(event.metadata.risk_level)}`);
    if (event.metadata?.total_findings != null) {
      parts.push(`${String(event.metadata.total_findings)} finding(s)`);
    }
  }

  if (event.module === "password") {
    if (event.metadata?.risk_level) parts.push(`Risk ${String(event.metadata.risk_level)}`);
    if (event.metadata?.strength_label) parts.push(String(event.metadata.strength_label));
    if (event.metadata?.breached === true) parts.push("Breach exposure");
  }

  if (event.module === "phishing") {
    if (event.metadata?.domain) parts.push(String(event.metadata.domain));
    if (event.metadata?.final_category) parts.push(humanize(String(event.metadata.final_category)));
    if (event.metadata?.final_risk_score != null) {
      parts.push(`Risk ${String(event.metadata.final_risk_score)}`);
    }
  }

  return parts.join(" | ") || event.action_label || event.title;
}

function detailItems(event: ActivityLogItem) {
  const metadata = event.metadata ?? {};

  const overview: Array<[string, string]> = [
    ["Module", normalizeModuleLabel(event)],
    ["Action", event.action_label || humanize(event.action_type)],
    ["Status", humanize(event.status)],
    ["Time", formatDateTime(event.created_at)],
  ];

  const security: Array<[string, string]> = [
    ["Severity", humanize(event.severity)],
    ["Risk score", event.risk_score != null ? String(event.risk_score) : "Unavailable"],
    ["Sensitive", event.is_sensitive ? "Yes" : "No"],
    ["Suspicious context", isSuspicious(event) ? "Elevated signal" : "None"],
  ];

  let target: Array<[string, string]>;

  if (event.module === "vault") {
    target = [
      ["File name", String(metadata.filename || event.target_label || "Unavailable")],
      ["Document ID", String(event.target_id || "Unavailable")],
      ["Operation", humanize(event.action_type)],
      ["Offline enabled", metadataValue(metadata.offline_enabled)],
    ];
  } else if (event.module === "pcap") {
    target = [
      ["File name", String(metadata.file_name || metadata.filename || metadata.upload_name || "Unavailable")],
      ["Job ID", String(metadata.job_id || metadata.analysis_job_id || event.target_id || "Unavailable")],
      ["Threat count", String(metadata.threat_count || metadata.threats_count || metadata.alerts_count || "Unavailable")],
      ["Report availability", metadataValue(metadata.report_available || metadata.report_ready || metadata.report_url)],
    ];
  } else if (event.module === "identity") {
    target = [
      ["Target", String(event.target_label || event.target_id || "Unavailable")],
      ["Scan ID", String(metadata.scan_id || event.target_id || "Unavailable")],
      ["Risk level", String(metadata.risk_level || humanize(event.severity))],
      ["Findings", metadataValue(metadata.total_findings)],
    ];
  } else if (event.module === "password") {
    target = [
      ["Target", "Password Checker"],
      ["Check ID", String(metadata.password_check_id || event.target_id || "Unavailable")],
      ["Risk level", String(metadata.risk_level || humanize(event.severity))],
      ["Strength", metadataValue(metadata.strength_label)],
    ];
  } else if (event.module === "phishing") {
    target = [
      ["Target", "Phishing"],
      ["Scan ID", String(metadata.scan_id || event.target_id || "Unavailable")],
      ["URL", String(metadata.url || "Unavailable")],
      ["Domain", String(metadata.domain || "Unavailable")],
      ["Final category", String(metadata.final_category || humanize(event.severity))],
      ["Final risk score", metadataValue(metadata.final_risk_score ?? event.risk_score)],
      ["VirusTotal malicious", metadataValue(metadata.virustotal_malicious)],
      ["VirusTotal suspicious", metadataValue(metadata.virustotal_suspicious)],
    ];
  } else {
    target = [
      ["Device", String(metadata.device_label || metadata.device || "Unavailable")],
      ["Browser", String(metadata.browser || metadata.browser_name || "Unavailable")],
      ["Session", String(event.session_id || metadata.session_id || "Unavailable")],
      ["IP", String(event.ip_address || metadata.ip_address || "Unavailable")],
    ];
  }

  const reservedKeys = new Set([
    "file_name",
    "filename",
    "upload_name",
    "job_id",
    "analysis_job_id",
    "threat_count",
    "threats_count",
    "alerts_count",
    "report_available",
    "report_ready",
    "report_url",
    "device_label",
    "device",
    "browser",
    "browser_name",
    "session_id",
    "ip_address",
    "reason",
    "suspicious_context",
    "offline_enabled",
    "scan_id",
    "risk_score",
    "risk_level",
    "total_findings",
    "sources_checked",
    "module",
    "url",
    "domain",
    "final_category",
    "final_risk_score",
    "ml_probability",
    "virustotal_malicious",
    "virustotal_suspicious",
  ]);

  const metadataEntries = Object.entries(metadata).filter(([key]) => !reservedKeys.has(key));

  return { overview, security, target, metadataEntries };
}

function EmptyState({
  title,
  description,
  onReset,
}: {
  title: string;
  description: string;
  onReset?: () => void;
}) {
  return (
    <div className="rounded-[24px] border border-sky-400/12 bg-[#081426] px-6 py-14 text-center">
      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-[22px] border border-sky-400/16 bg-sky-500/8">
        <Shield className="h-7 w-7 text-sky-100" />
      </div>
      <h3 className="mt-5 text-xl font-semibold text-white">{title}</h3>
      <p className="mx-auto mt-3 max-w-xl text-sm leading-7 text-slate-400">
        {description}
      </p>
      {onReset ? (
        <Button
          type="button"
          variant="outline"
          className="mt-6 border-sky-400/18 bg-sky-500/8 text-sky-100 hover:bg-sky-500/12"
          onClick={onReset}
        >
          Reset filters
        </Button>
      ) : null}
    </div>
  );
}

function DetailSection({
  title,
  items,
  icon: Icon,
}: {
  title: string;
  items: Array<[string, string]>;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <section className="rounded-[22px] border border-sky-400/12 bg-[#08172c] p-5">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-sky-400/14 bg-sky-500/8">
          <Icon className="h-4.5 w-4.5 text-sky-100" />
        </div>
        <div className="text-sm font-semibold text-white">{title}</div>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        {items.map(([label, value]) => (
          <div key={label} className="rounded-[16px] border border-white/8 bg-black/18 p-4">
            <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
              {label}
            </div>
            <div className="mt-2 break-all text-sm leading-6 text-slate-100">
              {value}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function ReportStyleIconShell({
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

function ReportStyleHeroCard({
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
        <ReportStyleIconShell icon={icon} compact />
        <div className="mr-card-copy">
          <p className="mr-card-label">{title}</p>
          <p className="mr-card-value">{value}</p>
          <p className="mr-card-note">{note}</p>
        </div>
      </div>
    </div>
  );
}

function ReportStyleStatCard({
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
        <ReportStyleIconShell icon={icon} />
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

function ActivityOrbitalIllustration() {
  return (
    <div className="mr-illustration">
      <svg viewBox="0 0 260 260" className="mr-illustration-svg" fill="none">
        <ellipse cx="130" cy="176" rx="54" ry="11" stroke="rgba(34,211,238,0.35)" strokeWidth="2" />
        <ellipse
          cx="130"
          cy="156"
          rx="101"
          ry="41"
          transform="rotate(-6 130 156)"
          stroke="rgba(0,183,255,0.75)"
          strokeWidth="2.4"
        />
        <path
          d="M130 30L183 55V117C183 148 161 176 130 191C99 176 77 148 77 117V55L130 30Z"
          fill="rgba(9,22,58,0.92)"
          stroke="#00B6FF"
          strokeWidth="3"
        />
        <path
          d="M130 43L171 64V113C171 137 154 159 130 171C106 159 89 137 89 113V64L130 43Z"
          fill="url(#activityShieldFill)"
          stroke="rgba(70,225,255,0.38)"
          strokeWidth="1.6"
        />
        <rect x="102" y="100" width="16" height="40" rx="4" fill="#18C8FF" />
        <rect x="122" y="88" width="16" height="52" rx="4" fill="#32D6FF" />
        <rect x="142" y="76" width="16" height="64" rx="4" fill="#52E3FF" />
        <defs>
          <linearGradient
            id="activityShieldFill"
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

function normalizeEvent(raw: any): ActivityLogItem {
  const module = String(raw?.module || "auth").toLowerCase() as ActivityModule;

  return {
    event_id: String(raw?.event_id || ""),
    module,
    module_label: normalizeModuleLabel({
      ...(raw || {}),
      module,
    } as ActivityLogItem),
    action_type: String(raw?.action_type || ""),
    action_label: String(raw?.action_label || humanize(raw?.action_type || "")),
    status: String(raw?.status || "info").toLowerCase() as ActivityStatus,
    severity: String(raw?.severity || "low").toLowerCase() as ActivitySeverity,
    title: String(raw?.title || raw?.action_label || humanize(raw?.action_type || "")),
    description: String(raw?.description || ""),
    target_id: raw?.target_id ?? "",
    target_label: raw?.target_label ?? "",
    session_id: raw?.session_id ?? "",
    ip_address: raw?.ip_address ?? "",
    created_at: String(raw?.created_at || new Date().toISOString()),
    risk_score: raw?.risk_score ?? null,
    is_sensitive: Boolean(raw?.is_sensitive),
    is_suspicious: Boolean(raw?.is_suspicious),
    metadata: raw?.metadata && typeof raw.metadata === "object" ? raw.metadata : {},
  };
}

export function UserActivityLogsPage() {
  const [logs, setLogs] = useState<ActivityLogItem[]>([]);
  const [filters, setFilters] = useState<FilterState>(defaultFilters);
  const [selectedEvent, setSelectedEvent] = useState<ActivityLogItem | null>(null);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  const buildQueryString = (customOffset = offset, customLimit = PAGE_SIZE) => {
    const params = new URLSearchParams();

    params.set("limit", String(customLimit));
    params.set("offset", String(customOffset));

    if (filters.search.trim()) params.set("search", filters.search.trim());
    if (filters.module !== "all") params.set("module", filters.module);
    if (filters.action_type !== "all") params.set("action_type", filters.action_type);
    if (filters.status !== "all") params.set("status", filters.status);
    if (filters.severity !== "all") params.set("severity", filters.severity);
    if (filters.start_date) params.set("start_date", filters.start_date);
    if (filters.end_date) params.set("end_date", filters.end_date);

    return params.toString();
  };

  const fetchLogs = async (customOffset = offset) => {
    try {
      setLoading(true);

      const res = await fetch(
        `${ACTIVITY_API_BASE}/api/activity-logs/me?${buildQueryString(customOffset)}`,
        buildActivityAuthedFetchInit()
      );

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        if (res.status === 401) {
          throw new Error(SESSION_EXPIRED_MESSAGE);
        }
        throw new Error(data.error || data.message || `Failed to load logs (${res.status})`);
      }

      const nextLogs = Array.isArray(data.logs)
        ? data.logs.map(normalizeEvent)
        : [];

      setLogs(nextLogs);
      setTotal(Number(data.total || nextLogs.length || 0));
      setOffset(Number(data.offset || customOffset || 0));
    } catch (err: any) {
      console.error("ACTIVITY LOGS ERROR:", err);
      toast.error(err.message || "Failed to load activity logs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(0);
  }, [
    filters.module,
    filters.action_type,
    filters.status,
    filters.severity,
    filters.start_date,
    filters.end_date,
  ]);

  useEffect(() => {
    const t = window.setTimeout(() => {
      fetchLogs(0);
    }, 350);

    return () => window.clearTimeout(t);
  }, [filters.search]);

  const paginatedLogs = logs;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const hasFiltersApplied = useMemo(
    () =>
      filters.search.trim() ||
      filters.module !== "all" ||
      filters.action_type !== "all" ||
      filters.status !== "all" ||
      filters.severity !== "all" ||
      filters.start_date ||
      filters.end_date,
    [filters]
  );

  const knownActionTypes = useMemo(() => {
    const set = new Set<string>();
    logs.forEach((item) => set.add(item.action_type));

    [
      "login_success",
      "login_failed",
      "logout",
      "new_device_login",
      "pcap_uploaded",
      "pcap_analysis_started",
      "pcap_analysis_completed",
      "pcap_report_downloaded",
      "vault_file_uploaded",
      "vault_file_downloaded",
      "vault_file_deleted",
      "vault_offline_enabled",
      "vault_offline_disabled",
      "vault_wrong_password",
      "identity_scan_started",
      "identity_scan_completed",
      "identity_alert_generated",
      "identity_confirmed_breach_detected",
      "identity_asset_added",
      "identity_asset_deleted",
      "identity_full_asset_scan_started",
      "identity_full_asset_scan_completed",
      "identity_scan_viewed",
      "identity_report_downloaded",
      "password_check_completed",
      "password_breach_detected",
      "weak_password_detected",
      "password_history_viewed",
      "password_history_cleared",
      "phishing_scan_completed",
      "phishing_suspicious_url_reviewed",
      "phishing_dangerous_url_detected",
    ].forEach((x) => set.add(x));

    return Array.from(set).filter(Boolean).sort();
  }, [logs]);

  const resetFilters = () => {
    setFilters(defaultFilters);
    setOffset(0);
  };

  const openEvent = async (eventId: string) => {
    const localEvent = logs.find((e) => e.event_id === eventId);

    if (localEvent) {
      setSelectedEvent(localEvent);
    }

    try {
      const res = await fetch(
        `${ACTIVITY_API_BASE}/api/activity-logs/me/${eventId}`,
        buildActivityAuthedFetchInit()
      );

      const data = await res.json().catch(() => ({}));

      if (res.ok && data.event) {
        setSelectedEvent(normalizeEvent(data.event));
      }
    } catch {
      // Keep local event if detail request fails.
    }
  };

  const exportCsv = async () => {
    try {
      const res = await fetch(
        `${ACTIVITY_API_BASE}/api/activity-logs/me/export?${buildQueryString(0, 5000)}`,
        buildActivityAuthedFetchInit()
      );

      if (!res.ok) {
        if (res.status === 401) {
          throw new Error(SESSION_EXPIRED_MESSAGE);
        }
        throw new Error(`Export failed (${res.status})`);
      }

      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const dateStamp = new Date().toISOString().slice(0, 10);

      link.href = blobUrl;
      link.download = `user-activity-logs-${dateStamp}.csv`;
      link.style.display = "none";
      document.body.appendChild(link);
      link.click();
      link.remove();

      window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
      toast.success("CSV exported successfully.");
    } catch (err: any) {
      console.error("EXPORT LOGS ERROR:", err);
      toast.error(err.message || "Export failed");
    }
  };

  const refreshData = () => {
    fetchLogs(offset);
    toast.success("Activity logs refreshed");
  };

  const heroCards = {
    total_events: total,
    successful_actions: logs.filter((e) => e.status === "success").length,
    failed_actions: logs.filter((e) => e.status === "failed").length,
    suspicious_events: logs.filter((e) => isSuspicious(e)).length,
  };

  const heroFeatureCards = [
    {
      icon: Eye,
      title: "Visibility",
      value: "Unified audit stream",
      note: "Auth, PCAP, Vault, Identity, and Phishing activity in one place.",
    },
    {
      icon: Cpu,
      title: "Scope",
      value: "Auth + PCAP + Vault + Identity + Phishing",
      note: "Built to scale without redesigning the data model.",
    },
    {
      icon: User,
      title: "Access",
      value: "User-scoped only",
      note: "Only the signed-in user can review their own events.",
    },
  ];

  const overviewStatCards = [
    {
      icon: Activity,
      title: "Timeline Health",
      value: heroCards.total_events,
      note: "All user-scoped events matching the filters",
    },
    {
      icon: ShieldCheck,
      title: "Validated Actions",
      value: heroCards.successful_actions,
      note: "Successful events currently visible on this page",
    },
    {
      icon: ShieldAlert,
      title: "Protected Failures",
      value: heroCards.failed_actions,
      note: "Denied or interrupted actions captured for review",
    },
    {
      icon: AlertTriangle,
      title: "Elevated Posture",
      value: heroCards.suspicious_events,
      note: "Suspicious or high-signal events in view",
    },
  ];

  const detailData = selectedEvent ? detailItems(selectedEvent) : null;

  return (
    <div className="mr-page ua-page">
      <div className="mr-surface">
        <div className="mr-top-grid">
          <section className="mr-hero-panel">
            <div className="mr-hero-grid">
              <div className="mr-hero-head">
                <ReportStyleIconShell icon={Activity} />
                <div className="mr-hero-copy">
                  <h1 className="mr-title">User Activity Logs</h1>
                  <p className="mr-subtitle">
                    Review sign-ins, PCAP analyzer operations, encrypted vault actions,
                    offline access, password failures, and sensitive account changes.
                  </p>
                  <p className="mr-description">
                    This workspace centralizes authenticated user activity, suspicious
                    signals, PCAP workflow events, and Encrypted File Vault audit logs.
                  </p>
                </div>
              </div>

              <div className="mr-hero-illustration-wrap">
                <ActivityOrbitalIllustration />
              </div>
            </div>

            <div className="mr-hero-cards">
              {heroFeatureCards.map((card) => (
                <ReportStyleHeroCard
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
              Search, filter, refresh, and export the live user activity stream.
            </p>

            <div className="relative mt-4 min-w-0">
              <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
              <Input
                value={filters.search}
                onChange={(event) => {
                  setOffset(0);
                  setFilters((prev) => ({ ...prev, search: event.target.value }));
                }}
                placeholder="Search anything..."
                className="h-12 rounded-2xl border-sky-400/14 bg-[#051120] pl-10 text-white placeholder:text-slate-500"
              />
            </div>

            <div className="mr-button-stack">
              <button type="button" onClick={refreshData} className="mr-button mr-button-primary">
                <RefreshCw className={cn("mr-button-icon", loading && "animate-spin")} />
                Refresh Activity
              </button>

              <button type="button" onClick={exportCsv} className="mr-button mr-button-secondary">
                <Download className="mr-button-icon" />
                Export CSV
              </button>
            </div>
          </aside>
        </div>

        <div className="mr-stats-grid">
          {overviewStatCards.map((card) => (
            <ReportStyleStatCard
              key={card.title}
              icon={card.icon}
              title={card.title}
              value={formatMetric(Number(card.value))}
              note={card.note}
            />
          ))}
        </div>

        <section className="mr-history-panel">
          <div className="mr-history-header">
            <div className="mr-history-title-row">
              <ReportStyleIconShell icon={Activity} compact />
              <div>
                <h3 className="mr-history-title">Activity Timeline</h3>
                <p className="mr-history-copy">
                  Browse the live event stream, narrow it with filters, and open any
                  event for full investigation details.
                </p>
              </div>
            </div>

            <div className="text-sm text-slate-400">
              Page {currentPage} of {totalPages}
            </div>
          </div>

          <div className="mr-history-body">
            <div className="mb-4 rounded-[22px] border border-sky-400/14 bg-[linear-gradient(180deg,rgba(4,20,42,0.94),rgba(2,11,28,0.98))] p-4">
              <div className="grid gap-3 xl:grid-cols-[repeat(4,minmax(0,1fr))_minmax(0,1.05fr)_minmax(0,1.05fr)]">
                <Select
                  value={filters.module}
                  onValueChange={(value: FilterState["module"]) => {
                    setOffset(0);
                    setFilters((prev) => ({ ...prev, module: value }));
                  }}
                >
                  <SelectTrigger className="h-11 rounded-2xl border-sky-400/14 bg-[#051120] text-white">
                    <SelectValue placeholder="Module" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Modules</SelectItem>
                    <SelectItem value="auth">Authentication</SelectItem>
                    <SelectItem value="pcap">PCAP Analyzer</SelectItem>
                    <SelectItem value="vault">Encrypted File Vault</SelectItem>
                    <SelectItem value="password">Password Checker</SelectItem>
                    <SelectItem value="identity">Identity Leak Monitor</SelectItem>
                    <SelectItem value="phishing">Phishing Scanner</SelectItem>
                  </SelectContent>
                </Select>

                <Select
                  value={filters.action_type}
                  onValueChange={(value) => {
                    setOffset(0);
                    setFilters((prev) => ({ ...prev, action_type: value }));
                  }}
                >
                  <SelectTrigger className="h-11 rounded-2xl border-sky-400/14 bg-[#051120] text-white">
                    <SelectValue placeholder="Action type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Actions</SelectItem>
                    {knownActionTypes.map((action) => (
                      <SelectItem key={action} value={action}>
                        {humanize(action)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                <Select
                  value={filters.status}
                  onValueChange={(value: FilterState["status"]) => {
                    setOffset(0);
                    setFilters((prev) => ({ ...prev, status: value }));
                  }}
                >
                  <SelectTrigger className="h-11 rounded-2xl border-sky-400/14 bg-[#051120] text-white">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    <SelectItem value="success">Success</SelectItem>
                    <SelectItem value="failed">Failed</SelectItem>
                    <SelectItem value="warning">Warning</SelectItem>
                    <SelectItem value="info">Info</SelectItem>
                  </SelectContent>
                </Select>

                <Select
                  value={filters.severity}
                  onValueChange={(value: FilterState["severity"]) => {
                    setOffset(0);
                    setFilters((prev) => ({ ...prev, severity: value }));
                  }}
                >
                  <SelectTrigger className="h-11 rounded-2xl border-sky-400/14 bg-[#051120] text-white">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severities</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                  </SelectContent>
                </Select>

                <Input
                  type="date"
                  value={filters.start_date}
                  onChange={(event) => {
                    setOffset(0);
                    setFilters((prev) => ({ ...prev, start_date: event.target.value }));
                  }}
                  className="h-11 rounded-2xl border-sky-400/14 bg-[#051120] text-white"
                />

                <Input
                  type="date"
                  value={filters.end_date}
                  onChange={(event) => {
                    setOffset(0);
                    setFilters((prev) => ({ ...prev, end_date: event.target.value }));
                  }}
                  className="h-11 rounded-2xl border-sky-400/14 bg-[#051120] text-white"
                />
              </div>

              {hasFiltersApplied ? (
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <Badge className="border-sky-300/18 bg-sky-500/10 text-sky-100">
                    <Filter className="mr-2 h-3.5 w-3.5" />
                    Filtered view
                  </Badge>
                  <Button
                    type="button"
                    variant="ghost"
                    className="h-auto px-0 text-sm text-slate-400 hover:bg-transparent hover:text-white"
                    onClick={resetFilters}
                  >
                    Clear all filters
                  </Button>
                </div>
              ) : null}
            </div>

            {loading && paginatedLogs.length === 0 ? (
              <EmptyState
                title="Loading activity events"
                description="Fetching your latest authenticated activity from the server."
              />
            ) : paginatedLogs.length === 0 && hasFiltersApplied ? (
              <EmptyState
                title="No matching activity events"
                description="The selected filters did not produce any visible events. Try widening the date range or clearing one of the filters."
                onReset={resetFilters}
              />
            ) : paginatedLogs.length === 0 ? (
              <EmptyState
                title="No activity recorded yet"
                description="Once you sign in, run analyzer jobs, use the Encrypted File Vault, or scan Identity Leak Monitor assets, this timeline will populate automatically."
              />
            ) : (
              <div className="mr-history-list">
                {paginatedLogs.map((event, index) => {
                  const Icon = activityIcon(event);
                  const suspicious = isSuspicious(event);

                  return (
                    <motion.article
                      key={event.event_id}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.02 }}
                      className="mr-report-row"
                    >
                      <div className="mr-report-grid">
                        <div className="mr-report-main">
                          <ReportStyleIconShell icon={Icon} compact />
                          <div>
                            <p className="mr-report-month">
                              {event.title || event.action_label || humanize(event.action_type)}
                            </p>
                            <p className="ua-report-support">{eventSupportingLine(event)}</p>
                          </div>
                        </div>

                        <div className="mr-report-cell">
                          <span className={cn("mr-status", statusChip(event.status))}>
                            {humanize(event.status)}
                          </span>
                          <p className="mr-report-meta">{normalizeModuleLabel(event)}</p>
                        </div>

                        <div className="mr-report-cell">
                          <p className="mr-cell-label">Target</p>
                          <div className="mr-section-wrap">
                            <span className="mr-section-badge" title={event.target_label || ""}>
                              {summarizeTarget(event)}
                            </span>
                            {suspicious ? <span className="mr-section-badge">Suspicious</span> : null}
                          </div>
                        </div>

                        <div className="mr-report-cell">
                          <p className="mr-cell-label">Severity</p>
                          <p className="mr-cell-number">{humanize(event.severity)}</p>
                        </div>

                        <div className="mr-report-cell">
                          <p className="mr-cell-label">When</p>
                          <div className="mr-score-row mr-score-neutral">
                            <Clock3 className="mr-score-arrow" />
                            <span>{formatRelativeTime(event.created_at)}</span>
                          </div>
                        </div>

                        <div className="mr-actions-cell">
                          <button
                            type="button"
                            onClick={() => openEvent(event.event_id)}
                            className="mr-row-button"
                          >
                            <Eye className="mr-button-icon" />
                            <span>View</span>
                          </button>

                          <div className="mr-row-button mr-row-button-muted">
                            <ChevronRight className="mr-button-icon" />
                            <span>{humanize(event.status)}</span>
                          </div>
                        </div>
                      </div>
                    </motion.article>
                  );
                })}

                <div className="mt-4 flex flex-col gap-3 border-t border-white/8 pt-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="text-sm text-slate-400">
                    Showing {paginatedLogs.length} of {total} events
                  </div>

                  <div className="flex items-center gap-3">
                    <Button
                      type="button"
                      variant="outline"
                      className="border-sky-400/14 bg-[#051120] text-white"
                      disabled={offset === 0 || loading}
                      onClick={() => fetchLogs(Math.max(0, offset - PAGE_SIZE))}
                    >
                      Previous
                    </Button>

                    <Button
                      type="button"
                      variant="outline"
                      className="border-sky-400/14 bg-[#051120] text-white"
                      disabled={offset + PAGE_SIZE >= total || loading}
                      onClick={() => fetchLogs(offset + PAGE_SIZE)}
                    >
                      Next
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>

      <Sheet
        open={selectedEvent !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedEvent(null);
        }}
      >
        <SheetContent
          side="right"
          className="ua-sheet-content flex h-dvh w-full max-w-2xl flex-col overflow-hidden border-l border-sky-400/16 bg-[linear-gradient(180deg,rgba(7,20,40,0.99),rgba(6,17,34,0.98))] p-0 text-white"
        >
          <SheetHeader className="shrink-0 border-b border-white/8 px-6 py-5 text-left">
            <SheetTitle className="text-2xl font-semibold text-white">
              {selectedEvent?.title || "Activity details"}
            </SheetTitle>
            <SheetDescription className="text-sm leading-7 text-slate-400">
              Event overview, security context, target intelligence, and structured metadata.
            </SheetDescription>
          </SheetHeader>

          <div className="min-h-0 flex-1 overflow-hidden">
            <ScrollArea className="ua-sheet-scroll h-full px-6">
              {selectedEvent && detailData ? (
                <div className="space-y-5 py-6">
                  <section className="rounded-[22px] border border-sky-400/14 bg-[linear-gradient(180deg,rgba(8,24,48,0.96),rgba(7,18,36,0.98))] p-5">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge className="border-sky-400/18 bg-sky-500/12 text-sky-50">
                        {normalizeModuleLabel(selectedEvent)}
                      </Badge>
                      <Badge className={statusChip(selectedEvent.status)}>
                        {humanize(selectedEvent.status)}
                      </Badge>
                      <Badge className={severityChip(selectedEvent.severity)}>
                        {humanize(selectedEvent.severity)}
                      </Badge>
                      {isSuspicious(selectedEvent) ? (
                        <Badge className="border-amber-400/16 bg-amber-500/12 text-amber-100">
                          Suspicious event
                        </Badge>
                      ) : null}
                    </div>

                    <div className="mt-4 flex items-start gap-4">
                      <div className="flex h-14 w-14 items-center justify-center rounded-[18px] border border-sky-300/14 bg-sky-500/8">
                        {React.createElement(activityIcon(selectedEvent), {
                          className: "h-6 w-6 text-sky-100",
                        })}
                      </div>
                      <div>
                        <div className="text-lg font-semibold text-white">
                          {selectedEvent.title || selectedEvent.action_label}
                        </div>
                        <div className="mt-2 text-sm leading-7 text-slate-300">
                          {selectedEvent.description || selectedEvent.action_label}
                        </div>
                      </div>
                    </div>
                  </section>

                  <DetailSection title="Event overview" items={detailData.overview} icon={Activity} />
                  <DetailSection title="Security context" items={detailData.security} icon={Shield} />
                  <DetailSection
                    title="Target details"
                    items={detailData.target}
                    icon={
                      selectedEvent.module === "pcap"
                        ? FileSearch
                        : selectedEvent.module === "vault"
                        ? HardDrive
                        : selectedEvent.module === "password"
                        ? Lock
                        : selectedEvent.module === "phishing"
                        ? Globe
                        : selectedEvent.module === "identity"
                        ? Globe
                        : Globe
                    }
                  />

                  {selectedEvent.module === "identity" &&
                  (selectedEvent.metadata?.scan_id || selectedEvent.target_id) ? (
                    <Button
                      type="button"
                      className="border-sky-400/18 bg-sky-500/12 text-sky-50 hover:bg-sky-500/18"
                      onClick={() => {
                        const scanId = String(
                          selectedEvent.metadata?.scan_id || selectedEvent.target_id || ""
                        );
                        window.location.href = `/identityleak-monitor?scan_id=${encodeURIComponent(scanId)}`;
                      }}
                    >
                      <Eye className="mr-2 h-4 w-4" />
                      Open Identity Scan
                    </Button>
                  ) : null}

                  <section className="rounded-[22px] border border-white/10 bg-white/[0.03] p-5">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-sky-300/14 bg-sky-500/8">
                        <Sparkles className="h-4.5 w-4.5 text-sky-100" />
                      </div>
                      <div className="text-sm font-semibold text-white">Metadata</div>
                    </div>

                    {detailData.metadataEntries.length > 0 ? (
                      <div className="mt-4 grid gap-3 sm:grid-cols-2">
                        {detailData.metadataEntries.map(([key, value]) => (
                          <div key={key} className="rounded-[16px] border border-white/8 bg-black/18 p-4">
                            <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                              {humanize(key)}
                            </div>
                            <pre className="mt-2 whitespace-pre-wrap break-words text-sm leading-6 text-slate-200">
                              {metadataValue(value)}
                            </pre>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="mt-4 rounded-[16px] border border-dashed border-white/8 bg-black/12 p-4 text-sm text-slate-400">
                        No additional metadata was exposed for this activity event.
                      </div>
                    )}
                  </section>
                </div>
              ) : null}
            </ScrollArea>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

export default UserActivityLogsPage;
