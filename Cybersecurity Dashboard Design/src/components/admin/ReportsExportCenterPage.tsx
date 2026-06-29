import React, { useEffect, useMemo, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  AlertTriangle,
  Calendar,
  CheckCircle2,
  Clock,
  Download,
  Eye,
  FileBarChart,
  FileDown,
  FileSearch,
  FileText,
  Filter,
  FolderLock,
  KeyRound,
  Layers,
  Loader2,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Users,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card } from "../ui/card";
import { Input } from "../ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import {
  FutureReportCategory,
  HighRiskUsersReportFilters,
  HighRiskUsersReportSummary,
  IdentityEvidenceItem,
  IdentityReportFilters,
  IdentityReportSummary,
  MonthlySecurityReportFilters,
  MonthlySecurityReportSummary,
  PcapReportFilters,
  PcapReportSummary,
  PasswordRiskReportFilters,
  PasswordRiskReportSummary,
  PhishingIncidentsReportFilters,
  PhishingIncidentsReportSummary,
  SecurityIncidentsReportFilters,
  SecurityIncidentsReportSummary,
  UserActivityReportFilters,
  UserActivityReportSummary,
  RecentPcapReport,
  RecentIdentityReport,
  ReportsOverview,
  ReportExportFormat,
  exportPcapReport,
  generateHighRiskUsersReport,
  generateIdentityReport,
  generateMonthlySecurityReport,
  generatePcapReport,
  generatePasswordRiskReport,
  generatePhishingIncidentsReport,
  generateSecurityIncidentsReport,
  generateUserActivityReport,
  getFutureReportCategories,
  getHighRiskUsersReportSummary,
  getIdentityReportSummary,
  getMonthlySecurityReportSummary,
  getPcapReportSummary,
  getPasswordRiskReportSummary,
  getPhishingIncidentsReportSummary,
  getSecurityIncidentsReportSummary,
  getUserActivityReportSummary,
  getRecentPcapReports,
  getReportsOverview,
  regeneratePcapReport,
} from "../../services/adminReportsService";
import { ADMIN_PCAP_API_BASE, formatAdminPcapTime } from "../../services/adminPcapOverview";
import "./ReportsExportCenterPage.css";

const DEFAULT_FILTERS: PcapReportFilters = {
  dateFrom: "",
  dateTo: "",
  status: "all",
  riskLevel: "all",
  attackFamily: "",
  exportFormat: "all",
  analysisMode: "all",
};

const DEFAULT_IDENTITY_FILTERS: IdentityReportFilters = {
  dateFrom: "",
  dateTo: "",
  riskLevel: "all",
  status: "all",
  source: "all",
  findingsCount: "all",
  exportFormat: "all",
};

const DEFAULT_PASSWORD_FILTERS: PasswordRiskReportFilters = {
  passwordRisk: "all",
  passwordStrength: "all",
  breachStatus: "all",
};

const DEFAULT_PHISHING_FILTERS: PhishingIncidentsReportFilters = {
  dateFrom: "",
  dateTo: "",
  riskLevel: "all",
  category: "all",
  exportFormat: "all",
};

const DEFAULT_MONTHLY_FILTERS: MonthlySecurityReportFilters = {
  severity: "all",
  module: "all",
};

const DEFAULT_ACTIVITY_FILTERS: UserActivityReportFilters = {
  dateRange: "current_month",
  role: "all",
  activityType: "all",
  moduleSource: "all",
};

const DEFAULT_HIGH_RISK_FILTERS: HighRiskUsersReportFilters = {
  dateRange: "current_month",
  riskLevel: "all",
  moduleSource: "all",
  role: "all",
};

const DEFAULT_SECURITY_INCIDENTS_FILTERS: SecurityIncidentsReportFilters = {
  dateRange: "current_month",
  severity: "all",
  moduleSource: "all",
  incidentType: "all",
  status: "all",
};

type VaultReportFilters = {
  dateFrom: string;
  dateTo: string;
  activityType: string;
  accessStatus: string;
  severity: string;
  offlineAccess: string;
  securitySignal: string;
};

const DEFAULT_VAULT_FILTERS: VaultReportFilters = {
  dateFrom: "",
  dateTo: "",
  activityType: "all",
  accessStatus: "all",
  severity: "all",
  offlineAccess: "all",
  securitySignal: "all",
};

const PASSWORD_FILTER_QUERY_PARAMS = [
  "password_risk",
  "password_strength",
  "breach_status",
];

const ACTIVITY_FILTER_QUERY_PARAMS = [
  "activity_date_range",
  "activity_role",
  "activity_type",
  "activity_module_source",
];

const HIGH_RISK_FILTER_QUERY_PARAMS = [
  "high_risk_date_range",
  "high_risk_level",
  "high_risk_module",
  "high_risk_role",
];

const MONTHLY_FILTER_QUERY_PARAMS = [
  "severity",
  "module",
];

const REPORT_FILTER_QUERY_PARAMS = [
  "date_from",
  "date_to",
  "risk_level",
  "status",
  "source",
  "findings_count",
  "attack_family",
  "export_format",
  "analysis_mode",
  "severity",
  "module",
  "page",
];

function clearReportFilterQueryParams() {
  if (typeof window === "undefined") return;

  const url = new URL(window.location.href);
  let changed = false;
  REPORT_FILTER_QUERY_PARAMS.forEach((param) => {
    if (url.searchParams.has(param)) {
      url.searchParams.delete(param);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

function clearPasswordReportFilterQueryParams() {
  if (typeof window === "undefined") return;

  const url = new URL(window.location.href);
  let changed = false;
  PASSWORD_FILTER_QUERY_PARAMS.forEach((param) => {
    if (url.searchParams.has(param)) {
      url.searchParams.delete(param);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

function clearActivityReportFilterQueryParams() {
  if (typeof window === "undefined") return;

  const url = new URL(window.location.href);
  let changed = false;
  ACTIVITY_FILTER_QUERY_PARAMS.forEach((param) => {
    if (url.searchParams.has(param)) {
      url.searchParams.delete(param);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

function clearHighRiskReportFilterQueryParams() {
  if (typeof window === "undefined") return;

  const url = new URL(window.location.href);
  let changed = false;
  HIGH_RISK_FILTER_QUERY_PARAMS.forEach((param) => {
    if (url.searchParams.has(param)) {
      url.searchParams.delete(param);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

function clearMonthlyReportFilterQueryParams() {
  if (typeof window === "undefined") return;

  const url = new URL(window.location.href);
  let changed = false;
  MONTHLY_FILTER_QUERY_PARAMS.forEach((param) => {
    if (url.searchParams.has(param)) {
      url.searchParams.delete(param);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

function normalizePasswordReportFilters(filters: PasswordRiskReportFilters): PasswordRiskReportFilters {
  return {
    passwordRisk: filters.passwordRisk || DEFAULT_PASSWORD_FILTERS.passwordRisk,
    passwordStrength: filters.passwordStrength || DEFAULT_PASSWORD_FILTERS.passwordStrength,
    breachStatus: filters.breachStatus || DEFAULT_PASSWORD_FILTERS.breachStatus,
  };
}

function arePasswordReportFiltersDefault(filters: PasswordRiskReportFilters): boolean {
  const normalized = normalizePasswordReportFilters(filters);
  return (
    normalized.passwordRisk === DEFAULT_PASSWORD_FILTERS.passwordRisk &&
    normalized.passwordStrength === DEFAULT_PASSWORD_FILTERS.passwordStrength &&
    normalized.breachStatus === DEFAULT_PASSWORD_FILTERS.breachStatus
  );
}

function arePasswordReportFiltersEqual(a: PasswordRiskReportFilters, b: PasswordRiskReportFilters): boolean {
  const left = normalizePasswordReportFilters(a);
  const right = normalizePasswordReportFilters(b);
  return (
    left.passwordRisk === right.passwordRisk &&
    left.passwordStrength === right.passwordStrength &&
    left.breachStatus === right.breachStatus
  );
}

function updatePasswordReportFilterQueryParams(filters: PasswordRiskReportFilters) {
  if (typeof window === "undefined") return;

  const normalized = normalizePasswordReportFilters(filters);
  const url = new URL(window.location.href);
  let changed = false;
  const entries: Array<[string, string]> = [
    ["password_risk", normalized.passwordRisk],
    ["password_strength", normalized.passwordStrength],
    ["breach_status", normalized.breachStatus],
  ];

  entries.forEach(([param, value]) => {
    if (!value || value === "all") {
      if (url.searchParams.has(param)) {
        url.searchParams.delete(param);
        changed = true;
      }
      return;
    }

    if (url.searchParams.get(param) !== value) {
      url.searchParams.set(param, value);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

function normalizeMonthlyReportFilters(filters: MonthlySecurityReportFilters): MonthlySecurityReportFilters {
  return {
    severity: filters.severity || DEFAULT_MONTHLY_FILTERS.severity,
    module: filters.module || DEFAULT_MONTHLY_FILTERS.module,
  };
}

function areMonthlyReportFiltersDefault(filters: MonthlySecurityReportFilters): boolean {
  const normalized = normalizeMonthlyReportFilters(filters);
  return (
    normalized.severity === DEFAULT_MONTHLY_FILTERS.severity &&
    normalized.module === DEFAULT_MONTHLY_FILTERS.module
  );
}

function areMonthlyReportFiltersEqual(a: MonthlySecurityReportFilters, b: MonthlySecurityReportFilters): boolean {
  const left = normalizeMonthlyReportFilters(a);
  const right = normalizeMonthlyReportFilters(b);
  return left.severity === right.severity && left.module === right.module;
}

function updateMonthlyReportFilterQueryParams(filters: MonthlySecurityReportFilters) {
  if (typeof window === "undefined") return;

  const normalized = normalizeMonthlyReportFilters(filters);
  const url = new URL(window.location.href);
  let changed = false;
  const entries: Array<[string, string]> = [
    ["severity", normalized.severity],
    ["module", normalized.module],
  ];

  entries.forEach(([param, value]) => {
    if (!value || value === "all") {
      if (url.searchParams.has(param)) {
        url.searchParams.delete(param);
        changed = true;
      }
      return;
    }
    if (url.searchParams.get(param) !== value) {
      url.searchParams.set(param, value);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

function normalizeActivityReportFilters(filters: UserActivityReportFilters): UserActivityReportFilters {
  return {
    dateRange: filters.dateRange || DEFAULT_ACTIVITY_FILTERS.dateRange,
    role: filters.role || DEFAULT_ACTIVITY_FILTERS.role,
    activityType: filters.activityType || DEFAULT_ACTIVITY_FILTERS.activityType,
    moduleSource: filters.moduleSource || DEFAULT_ACTIVITY_FILTERS.moduleSource,
  };
}

function areActivityReportFiltersDefault(filters: UserActivityReportFilters): boolean {
  const normalized = normalizeActivityReportFilters(filters);
  return (
    normalized.dateRange === DEFAULT_ACTIVITY_FILTERS.dateRange &&
    normalized.role === DEFAULT_ACTIVITY_FILTERS.role &&
    normalized.activityType === DEFAULT_ACTIVITY_FILTERS.activityType &&
    normalized.moduleSource === DEFAULT_ACTIVITY_FILTERS.moduleSource
  );
}

function areActivityReportFiltersEqual(a: UserActivityReportFilters, b: UserActivityReportFilters): boolean {
  const left = normalizeActivityReportFilters(a);
  const right = normalizeActivityReportFilters(b);
  return (
    left.dateRange === right.dateRange &&
    left.role === right.role &&
    left.activityType === right.activityType &&
    left.moduleSource === right.moduleSource
  );
}

function updateActivityReportFilterQueryParams(filters: UserActivityReportFilters) {
  if (typeof window === "undefined") return;

  const normalized = normalizeActivityReportFilters(filters);
  const url = new URL(window.location.href);
  let changed = false;
  const entries: Array<[string, string, string]> = [
    ["activity_date_range", normalized.dateRange, DEFAULT_ACTIVITY_FILTERS.dateRange],
    ["activity_role", normalized.role, DEFAULT_ACTIVITY_FILTERS.role],
    ["activity_type", normalized.activityType, DEFAULT_ACTIVITY_FILTERS.activityType],
    ["activity_module_source", normalized.moduleSource, DEFAULT_ACTIVITY_FILTERS.moduleSource],
  ];

  entries.forEach(([param, value, defaultValue]) => {
    if (!value || value === defaultValue || value === "all") {
      if (url.searchParams.has(param)) {
        url.searchParams.delete(param);
        changed = true;
      }
      return;
    }

    if (url.searchParams.get(param) !== value) {
      url.searchParams.set(param, value);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

function normalizeHighRiskReportFilters(filters: HighRiskUsersReportFilters): HighRiskUsersReportFilters {
  return {
    dateRange: filters.dateRange || DEFAULT_HIGH_RISK_FILTERS.dateRange,
    riskLevel: filters.riskLevel || DEFAULT_HIGH_RISK_FILTERS.riskLevel,
    moduleSource: filters.moduleSource || DEFAULT_HIGH_RISK_FILTERS.moduleSource,
    role: filters.role || DEFAULT_HIGH_RISK_FILTERS.role,
  };
}

function areHighRiskReportFiltersDefault(filters: HighRiskUsersReportFilters): boolean {
  const normalized = normalizeHighRiskReportFilters(filters);
  return (
    normalized.dateRange === DEFAULT_HIGH_RISK_FILTERS.dateRange &&
    normalized.riskLevel === DEFAULT_HIGH_RISK_FILTERS.riskLevel &&
    normalized.moduleSource === DEFAULT_HIGH_RISK_FILTERS.moduleSource &&
    normalized.role === DEFAULT_HIGH_RISK_FILTERS.role
  );
}

function areHighRiskReportFiltersEqual(a: HighRiskUsersReportFilters, b: HighRiskUsersReportFilters): boolean {
  const left = normalizeHighRiskReportFilters(a);
  const right = normalizeHighRiskReportFilters(b);
  return (
    left.dateRange === right.dateRange &&
    left.riskLevel === right.riskLevel &&
    left.moduleSource === right.moduleSource &&
    left.role === right.role
  );
}

function normalizeSecurityIncidentsReportFilters(filters: SecurityIncidentsReportFilters): SecurityIncidentsReportFilters {
  return {
    dateRange: filters.dateRange || DEFAULT_SECURITY_INCIDENTS_FILTERS.dateRange,
    severity: filters.severity || DEFAULT_SECURITY_INCIDENTS_FILTERS.severity,
    moduleSource: filters.moduleSource || DEFAULT_SECURITY_INCIDENTS_FILTERS.moduleSource,
    incidentType: filters.incidentType || DEFAULT_SECURITY_INCIDENTS_FILTERS.incidentType,
    status: filters.status || DEFAULT_SECURITY_INCIDENTS_FILTERS.status,
  };
}

function areSecurityIncidentsReportFiltersDefault(filters: SecurityIncidentsReportFilters): boolean {
  const normalized = normalizeSecurityIncidentsReportFilters(filters);
  return (
    normalized.dateRange === DEFAULT_SECURITY_INCIDENTS_FILTERS.dateRange &&
    normalized.severity === DEFAULT_SECURITY_INCIDENTS_FILTERS.severity &&
    normalized.moduleSource === DEFAULT_SECURITY_INCIDENTS_FILTERS.moduleSource &&
    normalized.incidentType === DEFAULT_SECURITY_INCIDENTS_FILTERS.incidentType &&
    normalized.status === DEFAULT_SECURITY_INCIDENTS_FILTERS.status
  );
}

function areSecurityIncidentsReportFiltersEqual(a: SecurityIncidentsReportFilters, b: SecurityIncidentsReportFilters): boolean {
  const left = normalizeSecurityIncidentsReportFilters(a);
  const right = normalizeSecurityIncidentsReportFilters(b);
  return (
    left.dateRange === right.dateRange &&
    left.severity === right.severity &&
    left.moduleSource === right.moduleSource &&
    left.incidentType === right.incidentType &&
    left.status === right.status
  );
}

function updateHighRiskReportFilterQueryParams(filters: HighRiskUsersReportFilters) {
  if (typeof window === "undefined") return;

  const normalized = normalizeHighRiskReportFilters(filters);
  const url = new URL(window.location.href);
  let changed = false;
  const entries: Array<[string, string, string]> = [
    ["high_risk_date_range", normalized.dateRange, DEFAULT_HIGH_RISK_FILTERS.dateRange],
    ["high_risk_level", normalized.riskLevel, DEFAULT_HIGH_RISK_FILTERS.riskLevel],
    ["high_risk_module", normalized.moduleSource, DEFAULT_HIGH_RISK_FILTERS.moduleSource],
    ["high_risk_role", normalized.role, DEFAULT_HIGH_RISK_FILTERS.role],
  ];

  entries.forEach(([param, value, defaultValue]) => {
    if (!value || value === defaultValue || value === "all") {
      if (url.searchParams.has(param)) {
        url.searchParams.delete(param);
        changed = true;
      }
      return;
    }
    if (url.searchParams.get(param) !== value) {
      url.searchParams.set(param, value);
      changed = true;
    }
  });

  if (changed) {
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }
}

const EMPTY_OVERVIEW: ReportsOverview = {
  pcap_reports_generated: 0,
  completed_analysis_jobs: 0,
  failed_analysis_jobs: 0,
  latest_pcap_export: null,
  latest_pcap_export_status: "Not available",
  usingFallback: false,
};

const EMPTY_SUMMARY: PcapReportSummary = {
  report_name: "PCAP Analysis Summary",
  status: "active",
  last_generated_at: null,
  supported_formats: ["pdf", "csv"],
  total_analyzed_files: 0,
  completed_jobs: 0,
  failed_jobs: 0,
  latest_detected_attack_family: "Not classified yet",
  highest_severity_found: "unknown",
  evidence_available: false,
  report_available: false,
  latest_report_id: null,
  usingFallback: false,
};

const EMPTY_IDENTITY_SUMMARY: IdentityReportSummary = {
  report_name: "Identity Leak Summary",
  status: "active",
  last_generated: null,
  supported_formats: ["pdf", "csv"],
  total_scans: 0,
  total_findings: 0,
  critical_scans: 0,
  highest_severity: "unknown",
  latest_risk_score: 0,
  sources_used: [],
  evidence_available: false,
  report_available: false,
  recent_reports: [],
  usingFallback: false,
};

const EMPTY_PASSWORD_SUMMARY: PasswordRiskReportSummary = {
  report_name: "Password Risk Summary",
  status: "active",
  generated_at: null,
  last_generated: null,
  supported_formats: ["csv"],
  data_source: "password_checker",
  summary: {
    total_checks: 0,
    breached_findings: 0,
    weak_findings: 0,
    strong_safe_checks: 0,
    latest_check_at: null,
  },
  risk_distribution: {},
  strength_distribution: {},
  breach_summary: {
    total_breached_results: 0,
    total_exposure_count: 0,
    average_breach_count: 0,
  },
  recommendations: [],
  report_available: false,
  evidence_available: false,
  usingFallback: false,
};

const EMPTY_PHISHING_SUMMARY: PhishingIncidentsReportSummary = {
  report_name: "Phishing Incidents Summary",
  status: "active",
  generated_at: null,
  last_generated: null,
  reporting_period: {
    label: "All Time",
    start: null,
    end: null,
  },
  data_source: "phishing_scanner",
  summary: {
    total_url_scans: 0,
    safe_urls: 0,
    suspicious_urls: 0,
    dangerous_urls: 0,
    risky_urls: 0,
    average_risk_score: 0,
    latest_scan_time: null,
    virustotal_malicious_total: 0,
    virustotal_suspicious_total: 0,
  },
  category_distribution: { safe: 0, suspicious: 0, dangerous: 0 },
  risk_distribution: { low: 0, medium: 0, high: 0, unknown: 0 },
  highest_risk_scan: null,
  latest_scans: [],
  recommendations: [],
  empty: true,
  message: "",
  supported_formats: ["pdf", "csv"],
  report_available: true,
  evidence_available: false,
  usingFallback: false,
};

const EMPTY_MONTHLY_SUMMARY: MonthlySecurityReportSummary = {
  report_name: "Monthly Security Report",
  status: "active",
  generated_at: null,
  reporting_period: {
    label: "Current Month",
    start: null,
    end: null,
  },
  data_source: "admin_reports",
  summary: {
    reporting_period: "current_month",
    total_events: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total_password_findings: 0,
    total_identity_findings: 0,
    total_pcap_alerts: 0,
  },
  module_distribution: {},
  severity_distribution: {},
  password_summary: {
    password_checks: 0,
    breached_findings: 0,
    weak_findings: 0,
    strong_safe_checks: 0,
  },
  identity_summary: {
    identity_scans: 0,
    identity_exposure_findings: 0,
    high_risk_exposures: 0,
  },
  module_activity_summary: {
    pcap_analyses_run: 0,
    pcap_completed: 0,
    pcap_failed: 0,
    pcap_clean_analyses: 0,
    pcap_alerts_generated: 0,
    identity_scans_run: 0,
    identity_findings_found: 0,
    password_checks_run: 0,
    password_breached_results: 0,
    notifications_created: 0,
    admin_audit_events: 0,
    user_activity_events: 0,
    latest_activity_timestamp: null,
  },
  top_risk_areas: [],
  recommendations: [],
  empty: true,
  message: "No monthly security data is available yet.",
  supported_formats: [],
  report_available: false,
  evidence_available: false,
  usingFallback: false,
};

const EMPTY_ACTIVITY_SUMMARY: UserActivityReportSummary = {
  report_name: "User Activity Report",
  status: "active",
  generated_at: null,
  reporting_period: {
    label: "Current Month",
    start: null,
    end: null,
  },
  summary: {
    total_activity_events: 0,
    unique_actors: 0,
    active_users: 0,
    active_admins: 0,
    total_exports: 0,
    latest_activity_at: null,
  },
  activity_type_distribution: {},
  role_distribution: {},
  module_distribution: {},
  timeline: [],
  recent_activity: [],
  empty: true,
  message: "No user activity data is available for this period.",
  supported_formats: [],
  report_available: false,
  usingFallback: false,
};

const EMPTY_HIGH_RISK_SUMMARY: HighRiskUsersReportSummary = {
  report_name: "High-Risk Users Report",
  status: "active",
  generated_at: null,
  reporting_period: {
    label: "Current Month",
    start: null,
    end: null,
  },
  summary: {
    total_users_evaluated: 0,
    high_risk_users: 0,
    critical_risk_users: 0,
    medium_risk_users: 0,
    low_risk_users: 0,
    total_risk_signals: 0,
    latest_risk_signal_timestamp: null,
    unattributed_signals: 0,
  },
  risk_level_distribution: {},
  module_signal_distribution: {},
  top_risk_users: [],
  empty: true,
  message: "No high-risk users were found for this period.",
  report_available: false,
  usingFallback: false,
};

const EMPTY_SECURITY_INCIDENTS_SUMMARY: SecurityIncidentsReportSummary = {
  report_name: "Security Incidents Report",
  status: "active",
  generated_at: null,
  reporting_period: {
    label: "Current Month",
    start: null,
    end: null,
  },
  summary: {
    total_incidents: 0,
    critical_incidents: 0,
    high_incidents: 0,
    medium_incidents: 0,
    low_incidents: 0,
    open_incidents: 0,
    resolved_incidents: 0,
    latest_incident_timestamp: null,
  },
  severity_distribution: {},
  source_distribution: {},
  incident_type_distribution: {},
  status_distribution: {},
  timeline: [],
  recent_incidents: [],
  top_risk_areas: [],
  empty: true,
  message: "No security incidents were found for this period.",
  supported_formats: ["pdf", "csv"],
  report_available: false,
  usingFallback: false,
};


type FileVaultActivityReportSummary = {
  report_name: string;
  status: string;
  generated_at: string | null;
  reporting_period: {
    label: string;
    start: string | null;
    end: string | null;
  };
  data_source?: string;
  summary: {
    total_documents: number;
    documents_uploaded: number;
    unique_owners: number;
    offline_enabled_documents: number;
    upload_events: number;
    encryption_events: number;
    download_events: number;
    delete_events: number;
    integrity_verified_events: number;
    wrong_password_events: number;
    access_denied_events: number;
    integrity_failures: number;
    offline_enabled_events: number;
    offline_disabled_events: number;
    suspicious_events: number;
    latest_activity_at: string | null;
    latest_upload_at: string | null;
  };
  action_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  timeline: Array<{ date: string; count: number }>;
  top_files: Array<{ target_label: string; count: number }>;
  recent_activity: Array<{
    timestamp: string | null;
    user_id: number | null;
    action_type: string;
    action: string;
    status: string;
    severity: string;
    target_label: string | null;
  }>;
  recommendations: string[];
  empty: boolean;
  message: string;
  supported_formats: string[];
  report_available: boolean;
  usingFallback: boolean;
};

const EMPTY_FILE_VAULT_SUMMARY: FileVaultActivityReportSummary = {
  report_name: "File Vault Activity Summary",
  status: "active",
  generated_at: null,
  reporting_period: {
    label: "Current Month",
    start: null,
    end: null,
  },
  data_source: "encrypted_file_vault",
  summary: {
    total_documents: 0,
    documents_uploaded: 0,
    unique_owners: 0,
    offline_enabled_documents: 0,
    upload_events: 0,
    encryption_events: 0,
    download_events: 0,
    delete_events: 0,
    integrity_verified_events: 0,
    wrong_password_events: 0,
    access_denied_events: 0,
    integrity_failures: 0,
    offline_enabled_events: 0,
    offline_disabled_events: 0,
    suspicious_events: 0,
    latest_activity_at: null,
    latest_upload_at: null,
  },
  action_distribution: {},
  severity_distribution: {},
  status_distribution: {},
  timeline: [],
  top_files: [],
  recent_activity: [],
  recommendations: [],
  empty: true,
  message: "No encrypted vault documents or vault activity records are available yet.",
  supported_formats: ["pdf", "csv"],
  report_available: false,
  usingFallback: false,
};


function formatNumber(value: unknown): string {
  const numeric = Number(value || 0);
  return Number.isFinite(numeric) ? numeric.toLocaleString() : "0";
}

function titleCase(value: string): string {
  return value
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value: unknown): string {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function csvBlob(rows: unknown[][]): Blob {
  return new Blob([`\uFEFF${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}`], {
    type: "text/csv;charset=utf-8",
  });
}

function sectionRow(section: string, item: string, value: unknown = "", count: unknown = "", timestamp: unknown = "", notes: unknown = ""): unknown[] {
  return [section, item, value, count, timestamp, notes];
}

function clipText(value: unknown, max = 72): string {
  const normalized = String(value ?? "Not available");
  return normalized.length > max ? `${normalized.slice(0, max - 3)}...` : normalized;
}

function escapePdfText(value: string): string {
  return value
    .replace(/[^\x20-\x7E]/g, "-")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function buildSimplePdfBlob(title: string, subtitle: string, rows: Array<[string, unknown]>): Blob {
  const commands: string[] = [];
  const add = (command: string) => commands.push(command);
  const text = (value: string, x: number, y: number, size = 10, color = "0.06 0.10 0.18", font = "F1") => {
    add(`${color} rg BT /${font} ${size} Tf ${x} ${y} Td (${escapePdfText(clipText(value, 96))}) Tj ET`);
  };
  const rect = (x: number, y: number, width: number, height: number, color: string) => {
    add(`${color} rg ${x} ${y} ${width} ${height} re f`);
  };
  const strokeRect = (x: number, y: number, width: number, height: number, color: string) => {
    add(`${color} RG ${x} ${y} ${width} ${height} re S`);
  };

  rect(0, 0, 612, 792, "0.95 0.97 1");
  rect(0, 682, 612, 110, "0.02 0.07 0.14");
  rect(0, 682, 612, 4, "0.12 0.38 0.90");
  text("SENTINEL AI", 48, 746, 13, "0.38 0.65 1", "F2");
  text(title, 48, 718, 22, "1 1 1", "F2");
  text(subtitle, 48, 696, 9, "0.74 0.82 0.93");
  text(`Generated At: ${formatAdminPcapTime(new Date().toISOString())}`, 396, 746, 9, "0.80 0.88 1");

  let y = 634;
  rows.slice(0, 34).forEach(([label, value], index) => {
    rect(48, y - 10, 516, 24, index % 2 === 0 ? "1 1 1" : "0.96 0.98 1");
    strokeRect(48, y - 10, 516, 24, "0.86 0.90 0.96");
    text(clipText(label, 34), 60, y - 1, 8, "0.36 0.44 0.56", "F2");
    text(clipText(value, 62), 230, y - 1, 8, "0.08 0.12 0.20");
    y -= 25;
  });

  rect(0, 0, 612, 38, "0.02 0.07 0.14");
  text("Sentinel AI Reports & Export Center", 48, 15, 8, "0.74 0.82 0.93");
  text("Safe aggregate export", 432, 15, 8, "0.74 0.82 0.93");

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

function statusBadgeClass(status: string): string {
  switch (status) {
    case "completed":
      return "reports-badge reports-badge-success";
    case "running":
      return "reports-badge reports-badge-blue";
    case "failed":
      return "reports-badge reports-badge-danger";
    case "queued":
      return "reports-badge reports-badge-warning";
    default:
      return "reports-badge reports-badge-muted";
  }
}

function riskBadgeClass(risk: string): string {
  switch (risk) {
    case "critical":
      return "reports-badge reports-badge-danger";
    case "high":
      return "reports-badge reports-badge-orange";
    case "medium":
      return "reports-badge reports-badge-warning";
    case "low":
      return "reports-badge reports-badge-success";
    default:
      return "reports-badge reports-badge-muted";
  }
}

function availabilityBadge(available: boolean) {
  return available ? (
    <span className="reports-badge reports-badge-success">Yes</span>
  ) : (
    <span className="reports-badge reports-badge-danger">No</span>
  );
}

function MiniLine({ tone = "blue" }: { tone?: "blue" | "green" | "red" | "purple" }) {
  return (
    <div className={`reports-mini-line reports-mini-line-${tone}`} aria-hidden="true">
      {[18, 32, 26, 45, 38, 52, 42, 58, 49, 64, 54, 70].map((height, index) => (
        <span key={`${tone}-${index}`} style={{ height: `${height}%` }} />
      ))}
    </div>
  );
}

function KpiCard({
  title,
  value,
  detail,
  icon: Icon,
  tone,
}: {
  title: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  tone: "blue" | "green" | "red" | "purple";
}) {
  return (
    <Card className="reports-kpi-card">
      <div className="reports-kpi-head">
        <div>
          <p className="reports-kpi-title">{title}</p>
          <p className="reports-kpi-value">{value}</p>
          <p className="reports-kpi-detail">{detail}</p>
        </div>
        <div className={`reports-kpi-icon reports-kpi-icon-${tone}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <MiniLine tone={tone} />
    </Card>
  );
}

function FutureCategoryCard({
  category,
  icon: Icon,
  onSelect,
}: {
  category: FutureReportCategory;
  icon: LucideIcon;
  onSelect?: () => void;
}) {
  const connected = category.badge === "Connected" || category.badge === "Active";
  return (
    <Card className={`reports-future-card ${connected ? "reports-future-card-active" : ""}`}>
      <div className="reports-future-icon">
        <Icon className="h-5 w-5" />
      </div>
      <h3>{category.title}</h3>
      <Badge className={connected ? "reports-badge reports-badge-success" : "reports-coming-badge"}>{category.badge}</Badge>
      <p>{category.description}</p>
      <Button disabled={!connected} variant="outline" className={connected ? "reports-action-button" : "reports-disabled-button"} onClick={onSelect}>
        {connected ? "Open Report" : "Not Connected"}
      </Button>
    </Card>
  );
}

const futureIcons: LucideIcon[] = [
  Calendar,
  ShieldAlert,
  Users,
  AlertTriangle,
  KeyRound,
  FileSearch,
  ShieldCheck,
  FolderLock,
];


function isVaultReportCategory(category: FutureReportCategory): boolean {
  const id = String(category.id || "").toLowerCase();
  const title = String(category.title || "").toLowerCase();
  return (
    id.includes("vault") ||
    title.includes("file vault") ||
    title.includes("vault activity")
  );
}

type ActiveReportModule = "pcap" | "identity" | "password" | "phishing" | "monthly" | "activity" | "highRisk" | "incidents" | "vault";

export default function ReportsExportCenterPage() {
  const [activeReportModule, setActiveReportModule] = useState<ActiveReportModule>("pcap");
  const [overview, setOverview] = useState<ReportsOverview>(EMPTY_OVERVIEW);
  const [summary, setSummary] = useState<PcapReportSummary>(EMPTY_SUMMARY);
  const [reports, setReports] = useState<RecentPcapReport[]>([]);
  const [identitySummary, setIdentitySummary] = useState<IdentityReportSummary>(EMPTY_IDENTITY_SUMMARY);
  const [passwordSummary, setPasswordSummary] = useState<PasswordRiskReportSummary>(EMPTY_PASSWORD_SUMMARY);
  const [phishingSummary, setPhishingSummary] = useState<PhishingIncidentsReportSummary>(EMPTY_PHISHING_SUMMARY);
  const [monthlySummary, setMonthlySummary] = useState<MonthlySecurityReportSummary>(EMPTY_MONTHLY_SUMMARY);
  const [activitySummary, setActivitySummary] = useState<UserActivityReportSummary>(EMPTY_ACTIVITY_SUMMARY);
  const [highRiskSummary, setHighRiskSummary] = useState<HighRiskUsersReportSummary>(EMPTY_HIGH_RISK_SUMMARY);
  const [incidentsSummary, setIncidentsSummary] = useState<SecurityIncidentsReportSummary>(EMPTY_SECURITY_INCIDENTS_SUMMARY);
  const [vaultSummary, setVaultSummary] = useState<FileVaultActivityReportSummary>(EMPTY_FILE_VAULT_SUMMARY);
  const [futureCategories] = useState(() => getFutureReportCategories());
  const [filters, setFilters] = useState<PcapReportFilters>(DEFAULT_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<PcapReportFilters>(DEFAULT_FILTERS);
  const [identityFilters, setIdentityFilters] = useState<IdentityReportFilters>(DEFAULT_IDENTITY_FILTERS);
  const [appliedIdentityFilters, setAppliedIdentityFilters] = useState<IdentityReportFilters>(DEFAULT_IDENTITY_FILTERS);
  const [passwordFilters, setPasswordFilters] = useState<PasswordRiskReportFilters>(DEFAULT_PASSWORD_FILTERS);
  const [appliedPasswordFilters, setAppliedPasswordFilters] = useState<PasswordRiskReportFilters>(DEFAULT_PASSWORD_FILTERS);
  const [phishingFilters, setPhishingFilters] = useState<PhishingIncidentsReportFilters>(DEFAULT_PHISHING_FILTERS);
  const [appliedPhishingFilters, setAppliedPhishingFilters] = useState<PhishingIncidentsReportFilters>(DEFAULT_PHISHING_FILTERS);
  const [monthlyFilters, setMonthlyFilters] = useState<MonthlySecurityReportFilters>(DEFAULT_MONTHLY_FILTERS);
  const [appliedMonthlyFilters, setAppliedMonthlyFilters] = useState<MonthlySecurityReportFilters>(DEFAULT_MONTHLY_FILTERS);
  const [activityFilters, setActivityFilters] = useState<UserActivityReportFilters>(DEFAULT_ACTIVITY_FILTERS);
  const [appliedActivityFilters, setAppliedActivityFilters] = useState<UserActivityReportFilters>(DEFAULT_ACTIVITY_FILTERS);
  const [highRiskFilters, setHighRiskFilters] = useState<HighRiskUsersReportFilters>(DEFAULT_HIGH_RISK_FILTERS);
  const [appliedHighRiskFilters, setAppliedHighRiskFilters] = useState<HighRiskUsersReportFilters>(DEFAULT_HIGH_RISK_FILTERS);
  const [incidentsFilters, setIncidentsFilters] = useState<SecurityIncidentsReportFilters>(DEFAULT_SECURITY_INCIDENTS_FILTERS);
  const [appliedIncidentsFilters, setAppliedIncidentsFilters] = useState<SecurityIncidentsReportFilters>(DEFAULT_SECURITY_INCIDENTS_FILTERS);
  const [vaultFilters, setVaultFilters] = useState<VaultReportFilters>(DEFAULT_VAULT_FILTERS);
  const [appliedVaultFilters, setAppliedVaultFilters] = useState<VaultReportFilters>(DEFAULT_VAULT_FILTERS);
  const [loading, setLoading] = useState(true);
  const [identityLoading, setIdentityLoading] = useState(true);
  const [passwordLoading, setPasswordLoading] = useState(true);
  const [phishingLoading, setPhishingLoading] = useState(true);
  const [monthlyLoading, setMonthlyLoading] = useState(true);
  const [activityLoading, setActivityLoading] = useState(true);
  const [highRiskLoading, setHighRiskLoading] = useState(true);
  const [incidentsLoading, setIncidentsLoading] = useState(true);
  const [vaultLoading, setVaultLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [identityError, setIdentityError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [phishingError, setPhishingError] = useState<string | null>(null);
  const [monthlyError, setMonthlyError] = useState<string | null>(null);
  const [activityError, setActivityError] = useState<string | null>(null);
  const [highRiskError, setHighRiskError] = useState<string | null>(null);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);
  const [regenerating, setRegenerating] = useState<string | null>(null);
  const [selectedReport, setSelectedReport] = useState<RecentPcapReport | null>(null);
  const [selectedIdentityReport, setSelectedIdentityReport] = useState<RecentIdentityReport | null>(null);
  const [selectedIdentityEvidence, setSelectedIdentityEvidence] = useState<RecentIdentityReport | null>(null);
  const pcapReportRequestId = useRef(0);
  const identityReportRequestId = useRef(0);
  const passwordReportRequestId = useRef(0);
  const phishingReportRequestId = useRef(0);
  const monthlyReportRequestId = useRef(0);
  const activityReportRequestId = useRef(0);
  const highRiskReportRequestId = useRef(0);
  const incidentsReportRequestId = useRef(0);
  const vaultReportRequestId = useRef(0);

  const passwordSummaryHasLoaded = Boolean(
    passwordSummary.generated_at ||
    passwordSummary.last_generated ||
    passwordSummary.report_available ||
    passwordSummary.summary.total_checks > 0
  );
  const monthlySummaryHasLoaded = Boolean(
    monthlySummary.generated_at ||
    monthlySummary.report_available ||
    monthlySummary.summary.total_events > 0
  );
  const usingFallback = overview.usingFallback || summary.usingFallback;
  const activeLoading = activeReportModule === "pcap" ? loading : activeReportModule === "identity" ? identityLoading : activeReportModule === "password" ? passwordLoading : activeReportModule === "phishing" ? phishingLoading : activeReportModule === "monthly" ? monthlyLoading : activeReportModule === "activity" ? activityLoading : activeReportModule === "highRisk" ? highRiskLoading : activeReportModule === "incidents" ? incidentsLoading : vaultLoading;
  const activeError = activeReportModule === "pcap" ? error : activeReportModule === "identity" ? identityError : activeReportModule === "password" ? passwordError : activeReportModule === "phishing" ? phishingError : activeReportModule === "monthly" ? monthlyError : activeReportModule === "activity" ? activityError : activeReportModule === "highRisk" ? highRiskError : activeReportModule === "incidents" ? incidentsError : vaultError;

  const attackFamilyOptions = useMemo(() => {
    const families = Array.from(
      new Set(reports.map((report) => report.detected_attack_family).filter(Boolean))
    );
    return ["all", ...families];
  }, [reports]);

  const latestReportId = summary.latest_report_id || reports[0]?.id || reports[0]?.job_id || "latest";
  const identityReports = identitySummary.recent_reports;
  const identitySourceOptions = useMemo(
    () => ["all", ...Array.from(new Set(identitySummary.sources_used.filter(Boolean)))],
    [identitySummary.sources_used],
  );
  const passwordHasData = passwordSummary.summary.total_checks > 0;
  const phishingSummaryHasLoaded = Boolean(
    phishingSummary.generated_at ||
    phishingSummary.last_generated ||
    phishingSummary.report_available ||
    phishingSummary.summary.total_url_scans > 0
  );
  const activitySummaryHasLoaded = Boolean(
    activitySummary.generated_at ||
    activitySummary.report_available ||
    activitySummary.summary.total_activity_events > 0
  );
  const highRiskSummaryHasLoaded = Boolean(
    highRiskSummary.generated_at ||
    highRiskSummary.report_available ||
    highRiskSummary.summary.total_users_evaluated > 0
  );
  const incidentsSummaryHasLoaded = Boolean(
    incidentsSummary.generated_at ||
    incidentsSummary.report_available
  );
  const vaultSummaryHasLoaded = Boolean(
    vaultSummary.generated_at ||
    vaultSummary.report_available ||
    vaultSummary.summary.total_documents > 0 ||
    vaultSummary.summary.upload_events > 0
  );
  const monthlyCoverageHasData = Object.entries(monthlySummary.module_activity_summary).some(([key, value]) => (
    key !== "latest_activity_timestamp" && Number(value || 0) > 0
  ));

  const filteredVaultRecentActivity = useMemo(() => {
    return vaultSummary.recent_activity.filter((item) => {
      const actionType = String(item.action_type || item.action || "").toLowerCase();
      const actionText = String(item.action || item.action_type || "").toLowerCase();
      const status = String(item.status || "").toLowerCase();
      const severity = String(item.severity || "").toLowerCase();
      const eventDate = item.timestamp ? new Date(item.timestamp) : null;
      const eventDateIso = eventDate && !Number.isNaN(eventDate.getTime()) ? eventDate.toISOString().slice(0, 10) : "";
      const combined = `${actionType} ${actionText} ${status} ${severity}`;

      if (appliedVaultFilters.dateFrom && (!eventDateIso || eventDateIso < appliedVaultFilters.dateFrom)) return false;
      if (appliedVaultFilters.dateTo && (!eventDateIso || eventDateIso > appliedVaultFilters.dateTo)) return false;
      if (appliedVaultFilters.activityType !== "all" && !combined.includes(appliedVaultFilters.activityType)) return false;
      if (appliedVaultFilters.accessStatus !== "all" && status !== appliedVaultFilters.accessStatus) return false;
      if (appliedVaultFilters.severity !== "all" && severity !== appliedVaultFilters.severity) return false;
      if (appliedVaultFilters.offlineAccess === "enabled" && !combined.includes("offline_enabled")) return false;
      if (appliedVaultFilters.offlineAccess === "disabled" && !combined.includes("offline_disabled")) return false;
      if (appliedVaultFilters.securitySignal === "suspicious" && !(severity === "critical" || severity === "high" || status === "failed" || status === "denied")) return false;
      if (appliedVaultFilters.securitySignal === "failed_access" && !(combined.includes("wrong_password") || combined.includes("access_denied") || status === "denied" || status === "failed")) return false;
      if (appliedVaultFilters.securitySignal === "wrong_password" && !combined.includes("wrong_password")) return false;
      if (appliedVaultFilters.securitySignal === "integrity_failure" && !(combined.includes("integrity") && (status === "failed" || severity === "critical" || severity === "high"))) return false;
      return true;
    });
  }, [appliedVaultFilters, vaultSummary.recent_activity]);

  const filteredVaultActionDistribution = useMemo(() => {
    return filteredVaultRecentActivity.reduce<Record<string, number>>((acc, item) => {
      const key = String(item.action_type || item.action || "vault_activity").toLowerCase();
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
  }, [filteredVaultRecentActivity]);

  const loadReports = async (nextFilters = appliedFilters, showToast = false) => {
    const requestId = pcapReportRequestId.current + 1;
    pcapReportRequestId.current = requestId;
    setLoading(true);
    setError(null);
    try {
      const [overviewResult, summaryResult, recentResult] = await Promise.all([
        getReportsOverview(),
        getPcapReportSummary(),
        getRecentPcapReports(nextFilters),
      ]);
      if (requestId !== pcapReportRequestId.current) return;
      setOverview(overviewResult);
      setSummary(summaryResult);
      setReports(recentResult.reports);
      setSelectedReport((current) => {
        if (!current) return recentResult.reports[0] || null;
        return recentResult.reports.find((report) => report.id === current.id) || recentResult.reports[0] || null;
      });
      if (showToast) toast.success("Reports refreshed");
      if (overviewResult.usingFallback || summaryResult.usingFallback || recentResult.usingFallback) {
        toast.info("PCAP reporting backend is partially unavailable. Showing report-ready demo data.");
      }
    } catch (loadError) {
      if (requestId !== pcapReportRequestId.current) return;
      setError(loadError instanceof Error ? loadError.message : "Reports could not be loaded.");
      toast.error("Reports could not be loaded.");
    } finally {
      if (requestId === pcapReportRequestId.current) {
        setLoading(false);
      }
    }
  };

  const loadIdentityReports = async (nextFilters = appliedIdentityFilters, showToast = false) => {
    const requestId = identityReportRequestId.current + 1;
    identityReportRequestId.current = requestId;
    setIdentityLoading(true);
    setIdentityError(null);
    try {
      const result = await getIdentityReportSummary(nextFilters);
      if (requestId !== identityReportRequestId.current) return;
      setIdentitySummary(result);
      setSelectedIdentityReport((current) => {
        if (!current) return result.recent_reports[0] || null;
        return result.recent_reports.find((report) => report.scan_id === current.scan_id) || result.recent_reports[0] || null;
      });
      if (showToast) toast.success("Identity reports refreshed");
    } catch (loadError) {
      if (requestId !== identityReportRequestId.current) return;
      setIdentityError(loadError instanceof Error ? loadError.message : "Identity reports could not be loaded.");
      toast.error("Identity reports could not be loaded.");
    } finally {
      if (requestId === identityReportRequestId.current) {
        setIdentityLoading(false);
      }
    }
  };

  const loadPasswordReport = async (nextFilters = appliedPasswordFilters, showToast = false) => {
    const safeFilters = normalizePasswordReportFilters(nextFilters);
    const requestId = passwordReportRequestId.current + 1;
    passwordReportRequestId.current = requestId;
    setPasswordLoading(true);
    setPasswordError(null);
    try {
      const result = await getPasswordRiskReportSummary(safeFilters);
      if (requestId !== passwordReportRequestId.current) return;
      setPasswordSummary(result);
      if (showToast) toast.success("Password Risk Summary refreshed");
    } catch (loadError) {
      if (requestId !== passwordReportRequestId.current) return;
      setPasswordError(loadError instanceof Error ? loadError.message : "Password Risk Summary could not be loaded.");
      toast.error("Password Risk Summary could not be loaded.");
    } finally {
      if (requestId === passwordReportRequestId.current) {
        setPasswordLoading(false);
      }
    }
  };

  const loadPhishingReport = async (nextFilters = appliedPhishingFilters, showToast = false) => {
    const requestId = phishingReportRequestId.current + 1;
    phishingReportRequestId.current = requestId;
    setPhishingLoading(true);
    setPhishingError(null);
    try {
      const result = await getPhishingIncidentsReportSummary(nextFilters);
      if (requestId !== phishingReportRequestId.current) return;
      setPhishingSummary(result);
      if (showToast) toast.success("Phishing Incidents Summary refreshed");
    } catch (loadError) {
      if (requestId !== phishingReportRequestId.current) return;
      setPhishingError(loadError instanceof Error ? loadError.message : "Phishing Incidents Summary could not be loaded.");
      toast.error("Phishing Incidents Summary could not be loaded.");
    } finally {
      if (requestId === phishingReportRequestId.current) {
        setPhishingLoading(false);
      }
    }
  };

  const loadMonthlyReport = async (nextFilters = appliedMonthlyFilters, showToast = false) => {
    const safeFilters = normalizeMonthlyReportFilters(nextFilters);
    const requestId = monthlyReportRequestId.current + 1;
    monthlyReportRequestId.current = requestId;
    setMonthlyLoading(true);
    setMonthlyError(null);
    try {
      const result = await getMonthlySecurityReportSummary(safeFilters);
      if (requestId !== monthlyReportRequestId.current) return;
      setMonthlySummary(result);
      if (showToast) toast.success("Monthly Security Report refreshed");
    } catch (loadError) {
      if (requestId !== monthlyReportRequestId.current) return;
      setMonthlyError(loadError instanceof Error ? loadError.message : "Monthly Security Report could not be loaded.");
      toast.error("Monthly Security Report could not be loaded.");
    } finally {
      if (requestId === monthlyReportRequestId.current) {
        setMonthlyLoading(false);
      }
    }
  };

  const loadActivityReport = async (nextFilters = appliedActivityFilters, showToast = false) => {
    const safeFilters = normalizeActivityReportFilters(nextFilters);
    const requestId = activityReportRequestId.current + 1;
    activityReportRequestId.current = requestId;
    setActivityLoading(true);
    setActivityError(null);
    try {
      const result = await getUserActivityReportSummary(safeFilters);
      if (requestId !== activityReportRequestId.current) return;
      setActivitySummary(result);
      if (showToast) toast.success("User Activity Report refreshed");
    } catch (loadError) {
      if (requestId !== activityReportRequestId.current) return;
      setActivityError(loadError instanceof Error ? loadError.message : "User Activity Report could not be loaded.");
      toast.error("User Activity Report could not be loaded.");
    } finally {
      if (requestId === activityReportRequestId.current) {
        setActivityLoading(false);
      }
    }
  };

  const loadHighRiskReport = async (nextFilters = appliedHighRiskFilters, showToast = false) => {
    const safeFilters = normalizeHighRiskReportFilters(nextFilters);
    const requestId = highRiskReportRequestId.current + 1;
    highRiskReportRequestId.current = requestId;
    setHighRiskLoading(true);
    setHighRiskError(null);
    try {
      const result = await getHighRiskUsersReportSummary(safeFilters);
      if (requestId !== highRiskReportRequestId.current) return;
      setHighRiskSummary(result);
      if (showToast) toast.success("High-Risk Users Report refreshed");
    } catch (loadError) {
      if (requestId !== highRiskReportRequestId.current) return;
      setHighRiskError(loadError instanceof Error ? loadError.message : "High-Risk Users Report could not be loaded.");
      toast.error("High-Risk Users Report could not be loaded.");
    } finally {
      if (requestId === highRiskReportRequestId.current) {
        setHighRiskLoading(false);
      }
    }
  };

  const loadIncidentsReport = async (nextFilters = appliedIncidentsFilters, showToast = false) => {
    const safeFilters = normalizeSecurityIncidentsReportFilters(nextFilters);
    const requestId = incidentsReportRequestId.current + 1;
    incidentsReportRequestId.current = requestId;
    setIncidentsLoading(true);
    setIncidentsError(null);
    try {
      const result = await getSecurityIncidentsReportSummary(safeFilters);
      if (requestId !== incidentsReportRequestId.current) return;
      setIncidentsSummary(result);
      if (showToast) toast.success("Security Incidents Report refreshed");
    } catch (loadError) {
      if (requestId !== incidentsReportRequestId.current) return;
      setIncidentsError(loadError instanceof Error ? loadError.message : "Security Incidents Report could not be loaded.");
      toast.error("Security Incidents Report could not be loaded.");
    } finally {
      if (requestId === incidentsReportRequestId.current) {
        setIncidentsLoading(false);
      }
    }
  };


  const loadVaultReport = async (showToast = false) => {
    const requestId = vaultReportRequestId.current + 1;
    vaultReportRequestId.current = requestId;
    setVaultLoading(true);
    setVaultError(null);
    try {
      const adminToken =
        localStorage.getItem("sentinel_admin_token") ||
        localStorage.getItem("admin_access_token") ||
        localStorage.getItem("access_token") ||
        localStorage.getItem("token") ||
        "";
      const response = await fetch(`${ADMIN_PCAP_API_BASE}/api/admin/reports/file-vault-activity-summary`, {
        credentials: "include",
        headers: adminToken ? { Authorization: `Bearer ${adminToken}` } : undefined,
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload?.success === false) {
        throw new Error(payload?.message || payload?.error || "File Vault Activity Summary could not be loaded.");
      }
      if (requestId !== vaultReportRequestId.current) return;
      setVaultSummary(payload.report || EMPTY_FILE_VAULT_SUMMARY);
      if (showToast) toast.success("File Vault Activity Summary refreshed");
    } catch (loadError) {
      if (requestId !== vaultReportRequestId.current) return;
      setVaultError(loadError instanceof Error ? loadError.message : "File Vault Activity Summary could not be loaded.");
      toast.error("File Vault Activity Summary could not be loaded.");
    } finally {
      if (requestId === vaultReportRequestId.current) {
        setVaultLoading(false);
      }
    }
  };

  useEffect(() => {
    void loadReports(DEFAULT_FILTERS);
    void loadIdentityReports(DEFAULT_IDENTITY_FILTERS);
    void loadPasswordReport();
    void loadPhishingReport(DEFAULT_PHISHING_FILTERS);
    void loadMonthlyReport(DEFAULT_MONTHLY_FILTERS);
    void loadActivityReport(DEFAULT_ACTIVITY_FILTERS);
    void loadHighRiskReport(DEFAULT_HIGH_RISK_FILTERS);
    void loadIncidentsReport(DEFAULT_SECURITY_INCIDENTS_FILTERS);
    void loadVaultReport();
  }, []);

  const applyFilters = () => {
    if (activeReportModule === "identity") {
      setAppliedIdentityFilters(identityFilters);
      void loadIdentityReports(identityFilters);
      return;
    }
    if (activeReportModule === "password") {
      const selectedPasswordFilters = normalizePasswordReportFilters(passwordFilters);
      const sameAsApplied = arePasswordReportFiltersEqual(selectedPasswordFilters, appliedPasswordFilters);
      if ((sameAsApplied && passwordSummaryHasLoaded) || (sameAsApplied && passwordLoading)) {
        updatePasswordReportFilterQueryParams(selectedPasswordFilters);
        return;
      }
      setAppliedPasswordFilters(selectedPasswordFilters);
      updatePasswordReportFilterQueryParams(selectedPasswordFilters);
      void loadPasswordReport(selectedPasswordFilters, true);
      return;
    }
    if (activeReportModule === "phishing") {
      setAppliedPhishingFilters(phishingFilters);
      void loadPhishingReport(phishingFilters, true);
      return;
    }
    if (activeReportModule === "monthly") {
      const selectedMonthlyFilters = normalizeMonthlyReportFilters(monthlyFilters);
      const sameAsApplied = areMonthlyReportFiltersEqual(selectedMonthlyFilters, appliedMonthlyFilters);
      if ((sameAsApplied && monthlySummaryHasLoaded) || (sameAsApplied && monthlyLoading)) {
        updateMonthlyReportFilterQueryParams(selectedMonthlyFilters);
        return;
      }
      setAppliedMonthlyFilters(selectedMonthlyFilters);
      updateMonthlyReportFilterQueryParams(selectedMonthlyFilters);
      void loadMonthlyReport(selectedMonthlyFilters, true);
      return;
    }
    if (activeReportModule === "activity") {
      const selectedActivityFilters = normalizeActivityReportFilters(activityFilters);
      const sameAsApplied = areActivityReportFiltersEqual(selectedActivityFilters, appliedActivityFilters);
      if ((sameAsApplied && activitySummaryHasLoaded) || (sameAsApplied && activityLoading)) {
        updateActivityReportFilterQueryParams(selectedActivityFilters);
        return;
      }
      setAppliedActivityFilters(selectedActivityFilters);
      updateActivityReportFilterQueryParams(selectedActivityFilters);
      void loadActivityReport(selectedActivityFilters, true);
      return;
    }
    if (activeReportModule === "highRisk") {
      const selectedHighRiskFilters = normalizeHighRiskReportFilters(highRiskFilters);
      const sameAsApplied = areHighRiskReportFiltersEqual(selectedHighRiskFilters, appliedHighRiskFilters);
      if ((sameAsApplied && highRiskSummaryHasLoaded) || (sameAsApplied && highRiskLoading)) {
        updateHighRiskReportFilterQueryParams(selectedHighRiskFilters);
        return;
      }
      setAppliedHighRiskFilters(selectedHighRiskFilters);
      updateHighRiskReportFilterQueryParams(selectedHighRiskFilters);
      void loadHighRiskReport(selectedHighRiskFilters, true);
      return;
    }
    if (activeReportModule === "incidents") {
      const selectedIncidentsFilters = normalizeSecurityIncidentsReportFilters(incidentsFilters);
      const sameAsApplied = areSecurityIncidentsReportFiltersEqual(selectedIncidentsFilters, appliedIncidentsFilters);
      if ((sameAsApplied && incidentsSummaryHasLoaded) || (sameAsApplied && incidentsLoading)) {
        return;
      }
      setAppliedIncidentsFilters(selectedIncidentsFilters);
      void loadIncidentsReport(selectedIncidentsFilters, true);
      return;
    }
    if (activeReportModule === "vault") {
      setAppliedVaultFilters(vaultFilters);
      void loadVaultReport(true);
      return;
    }
    setAppliedFilters(filters);
    void loadReports(filters);
  };

  const clearFilters = () => {
    if (activeReportModule === "identity") {
      setIdentityFilters(DEFAULT_IDENTITY_FILTERS);
      setAppliedIdentityFilters(DEFAULT_IDENTITY_FILTERS);
      void loadIdentityReports(DEFAULT_IDENTITY_FILTERS);
      return;
    }
    if (activeReportModule === "password") {
      const alreadyDefault = arePasswordReportFiltersDefault(passwordFilters) && arePasswordReportFiltersDefault(appliedPasswordFilters);
      setPasswordFilters(DEFAULT_PASSWORD_FILTERS);
      setAppliedPasswordFilters(DEFAULT_PASSWORD_FILTERS);
      clearPasswordReportFilterQueryParams();
      if ((alreadyDefault && passwordSummaryHasLoaded) || (alreadyDefault && passwordLoading)) {
        return;
      }
      void loadPasswordReport(DEFAULT_PASSWORD_FILTERS, true);
      return;
    }
    if (activeReportModule === "phishing") {
      const alreadyDefault = JSON.stringify(phishingFilters) === JSON.stringify(DEFAULT_PHISHING_FILTERS) && JSON.stringify(appliedPhishingFilters) === JSON.stringify(DEFAULT_PHISHING_FILTERS);
      setPhishingFilters(DEFAULT_PHISHING_FILTERS);
      setAppliedPhishingFilters(DEFAULT_PHISHING_FILTERS);
      if ((alreadyDefault && phishingSummaryHasLoaded) || (alreadyDefault && phishingLoading)) {
        return;
      }
      void loadPhishingReport(DEFAULT_PHISHING_FILTERS, true);
      return;
    }
    if (activeReportModule === "monthly") {
      const alreadyDefault = areMonthlyReportFiltersDefault(monthlyFilters) && areMonthlyReportFiltersDefault(appliedMonthlyFilters);
      setMonthlyFilters(DEFAULT_MONTHLY_FILTERS);
      setAppliedMonthlyFilters(DEFAULT_MONTHLY_FILTERS);
      clearMonthlyReportFilterQueryParams();
      if ((alreadyDefault && monthlySummaryHasLoaded) || (alreadyDefault && monthlyLoading)) {
        return;
      }
      void loadMonthlyReport(DEFAULT_MONTHLY_FILTERS, true);
      return;
    }
    if (activeReportModule === "activity") {
      const alreadyDefault = areActivityReportFiltersDefault(activityFilters) && areActivityReportFiltersDefault(appliedActivityFilters);
      setActivityFilters(DEFAULT_ACTIVITY_FILTERS);
      setAppliedActivityFilters(DEFAULT_ACTIVITY_FILTERS);
      clearActivityReportFilterQueryParams();
      if ((alreadyDefault && activitySummaryHasLoaded) || (alreadyDefault && activityLoading)) {
        return;
      }
      void loadActivityReport(DEFAULT_ACTIVITY_FILTERS, true);
      return;
    }
    if (activeReportModule === "highRisk") {
      const alreadyDefault = areHighRiskReportFiltersDefault(highRiskFilters) && areHighRiskReportFiltersDefault(appliedHighRiskFilters);
      setHighRiskFilters(DEFAULT_HIGH_RISK_FILTERS);
      setAppliedHighRiskFilters(DEFAULT_HIGH_RISK_FILTERS);
      clearHighRiskReportFilterQueryParams();
      if ((alreadyDefault && highRiskSummaryHasLoaded) || (alreadyDefault && highRiskLoading)) {
        return;
      }
      void loadHighRiskReport(DEFAULT_HIGH_RISK_FILTERS, true);
      return;
    }
    if (activeReportModule === "incidents") {
      const alreadyDefault = areSecurityIncidentsReportFiltersDefault(incidentsFilters) && areSecurityIncidentsReportFiltersDefault(appliedIncidentsFilters);
      setIncidentsFilters(DEFAULT_SECURITY_INCIDENTS_FILTERS);
      setAppliedIncidentsFilters(DEFAULT_SECURITY_INCIDENTS_FILTERS);
      if ((alreadyDefault && incidentsSummaryHasLoaded) || (alreadyDefault && incidentsLoading)) {
        return;
      }
      void loadIncidentsReport(DEFAULT_SECURITY_INCIDENTS_FILTERS, true);
      return;
    }
    if (activeReportModule === "vault") {
      setVaultFilters(DEFAULT_VAULT_FILTERS);
      setAppliedVaultFilters(DEFAULT_VAULT_FILTERS);
      void loadVaultReport(true);
      return;
    }
    setFilters(DEFAULT_FILTERS);
    setAppliedFilters(DEFAULT_FILTERS);
    void loadReports(DEFAULT_FILTERS);
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      if (activeReportModule === "identity") {
        const nextSummary = await generateIdentityReport(appliedIdentityFilters);
        setIdentitySummary(nextSummary);
        await loadIdentityReports(appliedIdentityFilters);
        toast.success("Identity report refreshed from live scan data");
        return;
      }
      if (activeReportModule === "password") {
        const nextSummary = await generatePasswordRiskReport(appliedPasswordFilters);
        setPasswordSummary(nextSummary);
        await loadPasswordReport(appliedPasswordFilters);
        toast.success("Password Risk Summary refreshed from Password Checker data");
        return;
      }
      if (activeReportModule === "phishing") {
        const nextSummary = await generatePhishingIncidentsReport(appliedPhishingFilters);
        setPhishingSummary(nextSummary);
        await loadPhishingReport(appliedPhishingFilters);
        toast.success("Phishing Incidents Summary refreshed from Phishing Scanner data");
        return;
      }
      if (activeReportModule === "monthly") {
        const nextSummary = await generateMonthlySecurityReport();
        setMonthlySummary(nextSummary);
        await loadMonthlyReport(appliedMonthlyFilters);
        toast.success("Monthly Security Report refreshed from safe aggregate data");
        return;
      }
      if (activeReportModule === "activity") {
        const nextSummary = await generateUserActivityReport(appliedActivityFilters);
        setActivitySummary(nextSummary);
        await loadActivityReport(appliedActivityFilters);
        toast.success("User Activity Report refreshed from safe activity data");
        return;
      }
      if (activeReportModule === "highRisk") {
        const nextSummary = await generateHighRiskUsersReport(appliedHighRiskFilters);
        setHighRiskSummary(nextSummary);
        await loadHighRiskReport(appliedHighRiskFilters);
        toast.success("High-Risk Users Report refreshed from safe risk signals");
        return;
      }
      if (activeReportModule === "incidents") {
        const nextSummary = await generateSecurityIncidentsReport(appliedIncidentsFilters);
        setIncidentsSummary(nextSummary);
        await loadIncidentsReport(appliedIncidentsFilters);
        toast.success("Security Incidents Report refreshed from safe incident records");
        return;
      }
      if (activeReportModule === "vault") {
        await loadVaultReport(true);
        return;
      }
      const nextSummary = await generatePcapReport(appliedFilters);
      setSummary(nextSummary);
      await loadReports(appliedFilters);
      toast.success("PCAP report generated and added to Recent PCAP Reports");
      if (nextSummary.usingFallback) {
        toast.info("Backend generation is not connected yet, so Sentinel created a report-ready local PCAP entry.");
      }
    } catch {
      toast.error(`${activeReportTitle} refresh failed safely.`);
    } finally {
      setGenerating(false);
    }
  };

  const handleExport = async (reportId: string, format: ReportExportFormat) => {
    if (exporting || !activeReportActionsEnabled) return;
    const exportKey = activeReportModule === "identity" ? `identity-${format}` : activeReportModule === "password" ? `password-${format}` : activeReportModule === "phishing" ? `phishing-${format}` : activeReportModule === "monthly" ? `monthly-${format}` : activeReportModule === "activity" ? `activity-${format}` : activeReportModule === "highRisk" ? `high-risk-${format}` : activeReportModule === "vault" ? `vault-${format}` : `${reportId}-${format}`;
    setExporting(exportKey);
    try {
      if (activeReportModule !== "pcap") {
        const result = format === "csv" ? buildAggregateCsvExport() : buildAggregatePdfExport();
        downloadBlob(result.blob, result.filename);
        toast.success(`${activeReportTitle} ${format.toUpperCase()} export ready`);
        return;
      }
      const result = await exportPcapReport(reportId, format);
      downloadBlob(result.blob, result.filename);
      toast.success(`PCAP ${format.toUpperCase()} export ready`);
      if (result.fallback) {
        toast.info("PCAP export service is not connected yet. Showing report-ready demo data.");
      }
    } catch (exportError) {
      toast.info(
        exportError instanceof Error
          ? exportError.message
          : `${activeReportTitle} export is not available yet.`
      );
    } finally {
      setExporting(null);
    }
  };

  const switchReportModule = (module: ActiveReportModule) => {
    setActiveReportModule(module);
    if (module === "identity" && !identitySummary.last_generated && !identityLoading) {
      void loadIdentityReports(appliedIdentityFilters);
    }
    if (module === "password" && !passwordSummary.generated_at && !passwordLoading) {
      void loadPasswordReport();
    }
    if (module === "phishing" && !phishingSummary.generated_at && !phishingLoading) {
      void loadPhishingReport(appliedPhishingFilters);
    }
    if (module === "monthly" && !monthlySummary.generated_at && !monthlyLoading) {
      void loadMonthlyReport(appliedMonthlyFilters);
    }
    if (module === "activity" && !activitySummary.generated_at && !activityLoading) {
      void loadActivityReport(appliedActivityFilters);
    }
    if (module === "highRisk" && !highRiskSummary.generated_at && !highRiskLoading) {
      void loadHighRiskReport(appliedHighRiskFilters);
    }
    if (module === "incidents" && !incidentsSummary.generated_at && !incidentsLoading) {
      void loadIncidentsReport(appliedIncidentsFilters);
    }
    if (module === "vault" && !vaultSummary.generated_at && !vaultLoading) {
      void loadVaultReport();
    }
  };

  const handleRegenerate = async (reportId: string) => {
    setRegenerating(reportId);
    try {
      const nextSummary = await regeneratePcapReport(reportId);
      setSummary(nextSummary);
      await loadReports(appliedFilters);
      toast.success("PCAP report regeneration requested");
    } catch {
      toast.error("PCAP report regeneration failed safely.");
    } finally {
      setRegenerating(null);
    }
  };

  const activeReportTitle =
    activeReportModule === "identity"
      ? "Identity Leak Summary"
      : activeReportModule === "password"
        ? "Password Risk Summary"
        : activeReportModule === "phishing"
          ? "Phishing Incidents Summary"
        : activeReportModule === "monthly"
          ? "Monthly Security Report"
          : activeReportModule === "activity"
            ? "User Activity Report"
            : activeReportModule === "highRisk"
              ? "High-Risk Users Report"
              : activeReportModule === "incidents"
                ? "Security Incidents Report"
                : activeReportModule === "vault"
                  ? "File Vault Activity Summary"
            : "PCAP Analysis Summary";
  const activeReportLabel =
    activeReportModule === "identity"
      ? "Identity Reporting Active"
      : activeReportModule === "password"
        ? "Password Reporting Active"
        : activeReportModule === "phishing"
          ? "Phishing Reporting Active"
        : activeReportModule === "monthly"
          ? "Monthly Reporting Active"
          : activeReportModule === "activity"
            ? "User Activity Reporting Active"
            : activeReportModule === "highRisk"
              ? "High-Risk Users Reporting Active"
              : activeReportModule === "incidents"
                ? "Security Incidents Reporting Active"
                : activeReportModule === "vault"
                  ? "File Vault Reporting Active"
            : "PCAP Reporting Active";
  const activeReportDescription =
    activeReportModule === "identity"
      ? "Identity report generation based on live identity scans, exposure findings, source summaries, severity distribution, timestamps, and safe evidence availability."
      : activeReportModule === "password"
        ? "Password Risk Summary uses safe aggregate Password Checker data only: breach counts, strength distribution, risk distribution, timestamps, and recommendations."
        : activeReportModule === "phishing"
          ? "Phishing Incidents Summary uses real Phishing Scanner results, URL risk decisions, ML probabilities, VirusTotal reputation, category distribution, and safe export-ready incident rows."
        : activeReportModule === "monthly"
          ? "Monthly Security Report uses safe aggregate records from connected security modules for a consolidated current-month overview."
          : activeReportModule === "activity"
            ? "User Activity Report combines safe authenticated activity, admin audit actions, module usage, report exports, timestamps, and aggregate distributions."
            : activeReportModule === "highRisk"
              ? "High-Risk Users Report ranks users from safe password, identity, PCAP, notification, and activity risk signals."
              : activeReportModule === "incidents"
                ? "Security Incidents Report summarizes real security incidents, alerts, findings, and suspicious risk events only."
                : activeReportModule === "vault"
                  ? "File Vault Activity Summary uses real Encrypted File Vault documents and safe vault activity logs: uploads, encryption events, downloads, deletes, failed access, integrity checks, offline access, and recommendations."
            : "PCAP report generation based on uploaded capture files, completed analysis jobs, detected attack families, severity distribution, ML/heuristic decisions, evidence availability, timestamps, and export status.";
  const activeSummaryItems: Array<[string, React.ReactNode]> =
    activeReportModule === "identity"
      ? [
          ["Report Name", identitySummary.report_name],
          ["Last Generated", formatAdminPcapTime(identitySummary.last_generated)],
          ["Supported Formats", identitySummary.supported_formats.map((format) => format.toUpperCase()).join(" / ")],
          ["Total Scans", formatNumber(identitySummary.total_scans)],
          ["Total Findings", formatNumber(identitySummary.total_findings)],
          ["Critical Scans", formatNumber(identitySummary.critical_scans)],
          ["Highest Severity", titleCase(identitySummary.highest_severity)],
          ["Latest Risk Score", `${identitySummary.latest_risk_score}`],
          ["Sources Used", identitySummary.sources_used.length ? identitySummary.sources_used.join(" / ") : "No sources yet"],
          ["Evidence / Report", `${identitySummary.evidence_available ? "Evidence" : "No evidence"} / ${identitySummary.report_available ? "Report ready" : "Report pending"}`],
        ]
      : activeReportModule === "password"
        ? [
            ["Report Name", passwordSummary.report_name],
            ["Generated At", formatAdminPcapTime(passwordSummary.generated_at)],
            ["Latest Check", formatAdminPcapTime(passwordSummary.summary.latest_check_at)],
            ["Supported Formats", passwordSummary.supported_formats.map((format) => format.toUpperCase()).join(" / ")],
            ["Total Checks", formatNumber(passwordSummary.summary.total_checks)],
            ["Breached Findings", formatNumber(passwordSummary.summary.breached_findings)],
            ["Weak Findings", formatNumber(passwordSummary.summary.weak_findings)],
            ["Strong Safe Checks", formatNumber(passwordSummary.summary.strong_safe_checks)],
            ["Exposure Count", formatNumber(passwordSummary.breach_summary.total_exposure_count)],
            ["Evidence / Report", `${passwordSummary.evidence_available ? "Risk evidence" : "No risk evidence"} / ${passwordSummary.report_available ? "Report ready" : "Report pending"}`],
          ]
        : activeReportModule === "phishing"
          ? [
              ["Report Name", phishingSummary.report_name],
              ["Generated At", formatAdminPcapTime(phishingSummary.generated_at)],
              ["Latest Scan", formatAdminPcapTime(phishingSummary.summary.latest_scan_time)],
              ["Supported Formats", phishingSummary.supported_formats.map((format) => format.toUpperCase()).join(" / ")],
              ["Total URL Scans", formatNumber(phishingSummary.summary.total_url_scans)],
              ["Safe URLs", formatNumber(phishingSummary.summary.safe_urls)],
              ["Suspicious URLs", formatNumber(phishingSummary.summary.suspicious_urls)],
              ["Dangerous URLs", formatNumber(phishingSummary.summary.dangerous_urls)],
              ["Risky URLs", formatNumber(phishingSummary.summary.risky_urls)],
              ["Average Risk Score", formatNumber(phishingSummary.summary.average_risk_score)],
              ["Highest Risk", phishingSummary.highest_risk_scan ? `${phishingSummary.highest_risk_scan.domain || phishingSummary.highest_risk_scan.url} (${phishingSummary.highest_risk_scan.final_risk_score}/100)` : "No scans yet"],
              ["Evidence / Report", `${phishingSummary.evidence_available ? "Risk evidence" : "No risk evidence"} / ${phishingSummary.report_available ? "Report ready" : "Report ready"}`],
            ]
        : activeReportModule === "monthly"
          ? [
              ["Report Name", monthlySummary.report_name],
              ["Generated At", formatAdminPcapTime(monthlySummary.generated_at)],
              ["Reporting Period", monthlySummary.reporting_period.label],
              ["Period Start", formatAdminPcapTime(monthlySummary.reporting_period.start)],
              ["Total Events", formatNumber(monthlySummary.summary.total_events)],
              ["Critical", formatNumber(monthlySummary.summary.critical)],
              ["High", formatNumber(monthlySummary.summary.high)],
              ["Password Findings", formatNumber(monthlySummary.summary.total_password_findings)],
              ["Identity Findings", formatNumber(monthlySummary.summary.total_identity_findings)],
              ["PCAP Alerts", formatNumber(monthlySummary.summary.total_pcap_alerts)],
            ]
          : activeReportModule === "activity"
            ? [
                ["Report Name", activitySummary.report_name],
                ["Generated At", formatAdminPcapTime(activitySummary.generated_at)],
                ["Reporting Period", activitySummary.reporting_period.label],
                ["Total Events", formatNumber(activitySummary.summary.total_activity_events)],
                ["Unique Actors", formatNumber(activitySummary.summary.unique_actors)],
                ["Active Users", formatNumber(activitySummary.summary.active_users)],
                ["Active Admins", formatNumber(activitySummary.summary.active_admins)],
                ["Exports / Downloads", formatNumber(activitySummary.summary.total_exports)],
                ["Latest Activity", formatAdminPcapTime(activitySummary.summary.latest_activity_at)],
                ["Recent Items", formatNumber(activitySummary.recent_activity.length)],
              ]
            : activeReportModule === "highRisk"
              ? [
                  ["Report Name", highRiskSummary.report_name],
                  ["Generated At", formatAdminPcapTime(highRiskSummary.generated_at)],
                  ["Reporting Period", highRiskSummary.reporting_period.label],
                  ["Users Evaluated", formatNumber(highRiskSummary.summary.total_users_evaluated)],
                  ["Critical Users", formatNumber(highRiskSummary.summary.critical_risk_users)],
                  ["High-Risk Users", formatNumber(highRiskSummary.summary.high_risk_users)],
                  ["Total Signals", formatNumber(highRiskSummary.summary.total_risk_signals)],
                  ["Latest Signal", formatAdminPcapTime(highRiskSummary.summary.latest_risk_signal_timestamp)],
                  ["Top Users", formatNumber(highRiskSummary.top_risk_users.length)],
                ]
              : activeReportModule === "incidents"
                ? [
                    ["Report Name", incidentsSummary.report_name],
                    ["Generated At", formatAdminPcapTime(incidentsSummary.generated_at)],
                    ["Reporting Period", incidentsSummary.reporting_period.label],
                    ["Total Incidents", formatNumber(incidentsSummary.summary.total_incidents)],
                    ["Critical Incidents", formatNumber(incidentsSummary.summary.critical_incidents)],
                    ["High Incidents", formatNumber(incidentsSummary.summary.high_incidents)],
                    ["Open Incidents", formatNumber(incidentsSummary.summary.open_incidents)],
                    ["Resolved Incidents", formatNumber(incidentsSummary.summary.resolved_incidents)],
                    ["Latest Incident", formatAdminPcapTime(incidentsSummary.summary.latest_incident_timestamp)],
                  ]
                 : activeReportModule === "vault"
                  ? [
                      ["Report Name", vaultSummary.report_name],
                      ["Generated At", formatAdminPcapTime(vaultSummary.generated_at)],
                      ["Total Documents", formatNumber(vaultSummary.summary.total_documents)],
                      ["Upload Events", formatNumber(vaultSummary.summary.upload_events)],
                      ["Download Events", formatNumber(vaultSummary.summary.download_events)],
                      ["Failed Access", formatNumber(vaultSummary.summary.wrong_password_events + vaultSummary.summary.access_denied_events)],
                      ["Integrity Failures", formatNumber(vaultSummary.summary.integrity_failures)],
                      ["Latest Activity", formatAdminPcapTime(vaultSummary.summary.latest_activity_at)],
                    ]
        : [
            ["Report Name", summary.report_name],
            ["Last Generated", formatAdminPcapTime(summary.last_generated_at)],
            ["Supported Formats", summary.supported_formats.map((format) => format.toUpperCase()).join(" / ")],
            ["Total Analyzed Files", formatNumber(summary.total_analyzed_files)],
            ["Completed Jobs", formatNumber(summary.completed_jobs)],
            ["Failed Jobs", formatNumber(summary.failed_jobs)],
            ["Latest Attack Family", summary.latest_detected_attack_family],
            ["Highest Severity", titleCase(summary.highest_severity_found)],
            ["Evidence / Report", `${summary.evidence_available ? "Evidence" : "No evidence"} / ${summary.report_available ? "Report ready" : "Report pending"}`],
          ];

  const activeReportHasLoaded =
    activeReportModule === "identity"
      ? Boolean(identitySummary.last_generated || identitySummary.total_scans > 0 || identitySummary.report_available)
      : activeReportModule === "password"
        ? passwordSummaryHasLoaded
        : activeReportModule === "phishing"
          ? phishingSummaryHasLoaded
        : activeReportModule === "monthly"
          ? monthlySummaryHasLoaded
          : activeReportModule === "activity"
            ? activitySummaryHasLoaded
            : activeReportModule === "highRisk"
              ? highRiskSummaryHasLoaded
              : activeReportModule === "incidents"
                ? incidentsSummaryHasLoaded
                : activeReportModule === "vault"
                  ? vaultSummaryHasLoaded
              : Boolean(summary.last_generated_at || summary.report_available || reports.length > 0);
  const activeReportActionsEnabled = activeReportHasLoaded && !activeLoading && !activeError;
  const activeExportKey = activeReportModule === "highRisk" ? "high-risk" : activeReportModule;

  const activeFilterRows = (): Array<[string, unknown]> => {
    if (activeReportModule === "identity") {
      return [
        ["Date From", appliedIdentityFilters.dateFrom || "All"],
        ["Date To", appliedIdentityFilters.dateTo || "All"],
        ["Risk Level", titleCase(appliedIdentityFilters.riskLevel)],
        ["Status", titleCase(appliedIdentityFilters.status)],
        ["Source", titleCase(appliedIdentityFilters.source)],
        ["Findings Count", titleCase(appliedIdentityFilters.findingsCount)],
      ];
    }
    if (activeReportModule === "password") {
      return [
        ["Password Risk", titleCase(appliedPasswordFilters.passwordRisk)],
        ["Password Strength", titleCase(appliedPasswordFilters.passwordStrength)],
        ["Breach Status", titleCase(appliedPasswordFilters.breachStatus)],
      ];
    }
    if (activeReportModule === "phishing") {
      return [
        ["Date From", appliedPhishingFilters.dateFrom || "All"],
        ["Date To", appliedPhishingFilters.dateTo || "All"],
        ["Risk Level", titleCase(appliedPhishingFilters.riskLevel)],
        ["Category", titleCase(appliedPhishingFilters.category)],
        ["Export Format", titleCase(appliedPhishingFilters.exportFormat)],
      ];
    }
    if (activeReportModule === "monthly") {
      return [
        ["Severity", titleCase(appliedMonthlyFilters.severity)],
        ["Module", titleCase(appliedMonthlyFilters.module)],
      ];
    }
    if (activeReportModule === "activity") {
      return [
        ["Date Range", titleCase(appliedActivityFilters.dateRange)],
        ["Role", titleCase(appliedActivityFilters.role)],
        ["Activity Type", titleCase(appliedActivityFilters.activityType)],
        ["Module / Source", titleCase(appliedActivityFilters.moduleSource)],
      ];
    }
    if (activeReportModule === "highRisk") {
      return [
        ["Date Range", titleCase(appliedHighRiskFilters.dateRange)],
        ["Risk Level", titleCase(appliedHighRiskFilters.riskLevel)],
        ["Module / Source", titleCase(appliedHighRiskFilters.moduleSource)],
        ["Role", titleCase(appliedHighRiskFilters.role)],
      ];
    }
    if (activeReportModule === "incidents") {
      return [
        ["Date Range", titleCase(appliedIncidentsFilters.dateRange)],
        ["Severity", titleCase(appliedIncidentsFilters.severity)],
        ["Module / Source", titleCase(appliedIncidentsFilters.moduleSource)],
        ["Incident Type", titleCase(appliedIncidentsFilters.incidentType)],
        ["Status", titleCase(appliedIncidentsFilters.status)],
      ];
    }
    if (activeReportModule === "vault") {
      return [
        ["Date From", appliedVaultFilters.dateFrom || "All"],
        ["Date To", appliedVaultFilters.dateTo || "All"],
        ["Module / Source", "Encrypted File Vault"],
        ["Vault Activity", titleCase(appliedVaultFilters.activityType)],
        ["Access Status", titleCase(appliedVaultFilters.accessStatus)],
        ["Security Level", titleCase(appliedVaultFilters.severity)],
        ["Offline Access", titleCase(appliedVaultFilters.offlineAccess)],
        ["Security Signal", titleCase(appliedVaultFilters.securitySignal)],
        ["Visible Events", formatNumber(filteredVaultRecentActivity.length)],
      ];
    }
    return [
      ["Status", titleCase(appliedFilters.status)],
      ["Risk Level", titleCase(appliedFilters.riskLevel)],
      ["Attack Family", appliedFilters.attackFamily || "All"],
      ["Analysis Mode", titleCase(appliedFilters.analysisMode)],
      ["Date From", appliedFilters.dateFrom || "All"],
      ["Date To", appliedFilters.dateTo || "All"],
    ];
  };

  const buildAggregateCsvExport = (): { blob: Blob; filename: string } => {
    if (activeReportModule === "identity") {
      return {
        filename: "identity-report.csv",
        blob: csvBlob([
          ["scan_id", "masked_identifier", "risk_level", "risk_score", "findings_count", "sources", "generated_at", "status"],
          ...identitySummary.recent_reports.map((item) => [
            item.scan_id,
            item.masked_identifier,
            item.risk_level,
            item.risk_score,
            item.findings_count,
            item.sources.join("; "),
            item.generated_at || "",
            item.status,
          ]),
        ]),
      };
    }
    if (activeReportModule === "password") {
      const rows: unknown[][] = [
        ["Section", "Item", "Value", "Count", "Timestamp", "Notes"],
        sectionRow("Report Metadata", "Report Title", passwordSummary.report_name),
        sectionRow("Report Metadata", "Generated At", "", "", passwordSummary.generated_at || passwordSummary.last_generated || ""),
        sectionRow("Report Metadata", "Data Source", titleCase(passwordSummary.data_source)),
        sectionRow("Report Metadata", "Total Checked Results", "", passwordSummary.summary.total_checks),
        sectionRow("Risk Distribution", "Critical", "", passwordSummary.risk_distribution.critical || 0),
        sectionRow("Risk Distribution", "High", "", passwordSummary.risk_distribution.high || 0),
        sectionRow("Risk Distribution", "Medium", "", passwordSummary.risk_distribution.medium || 0),
        sectionRow("Risk Distribution", "Low", "", passwordSummary.risk_distribution.low || 0),
      ];
      Object.entries(passwordSummary.strength_distribution).forEach(([strength, count]) => rows.push(sectionRow("Strength Distribution", titleCase(strength), "", count)));
      rows.push(sectionRow("Breach Summary", "Breached Results", "", passwordSummary.breach_summary.total_breached_results));
      rows.push(sectionRow("Breach Summary", "Total Exposure Count", "", passwordSummary.breach_summary.total_exposure_count));
      rows.push(sectionRow("Breach Summary", "Average Breach Count", passwordSummary.breach_summary.average_breach_count));
      rows.push(sectionRow("Breach Summary", "Latest Check", "", "", passwordSummary.summary.latest_check_at || ""));
      passwordSummary.recommendations.forEach((recommendation, index) => rows.push(sectionRow("Recommendations", `Recommendation ${index + 1}`, recommendation)));
      return { filename: "password-risk-summary.csv", blob: csvBlob(rows) };
    }
    if (activeReportModule === "phishing") {
      return {
        filename: "phishing-incidents-summary.csv",
        blob: csvBlob([
          ["scan_id", "timestamp", "url", "domain", "final_category", "final_risk_score", "ml_probability", "virustotal_status", "virustotal_malicious", "virustotal_suspicious"],
          ...phishingSummary.latest_scans.map((item) => [
            item.scan_id,
            item.timestamp || "",
            item.url,
            item.domain,
            item.final_category,
            item.final_risk_score,
            item.ml_probability ?? "",
            item.virustotal_status,
            item.virustotal_malicious,
            item.virustotal_suspicious,
          ]),
        ]),
      };
    }
    if (activeReportModule === "monthly") {
      const rows: unknown[][] = [
        ["Section", "Item", "Value", "Count", "Timestamp", "Notes"],
        sectionRow("Report Metadata", "Report Title", monthlySummary.report_name),
        sectionRow("Report Metadata", "Generated At", "", "", monthlySummary.generated_at || ""),
        sectionRow("Report Metadata", "Period", monthlySummary.reporting_period.label),
        sectionRow("Report Metadata", "Period Start", "", "", monthlySummary.reporting_period.start || ""),
        sectionRow("Report Metadata", "Period End", "", "", monthlySummary.reporting_period.end || ""),
        sectionRow("Report Metadata", "Total Events", "", monthlySummary.summary.total_events),
        sectionRow("Summary", "Total Events", "", monthlySummary.summary.total_events),
        sectionRow("Summary", "Critical", "", monthlySummary.summary.critical),
        sectionRow("Summary", "High", "", monthlySummary.summary.high),
        sectionRow("Summary", "Medium", "", monthlySummary.summary.medium),
        sectionRow("Summary", "Low", "", monthlySummary.summary.low),
        sectionRow("Summary", "Unknown", "", monthlySummary.summary.unknown),
      ];
      Object.entries(monthlySummary.module_distribution).forEach(([module, count]) => rows.push(sectionRow("Module Distribution", titleCase(module), "", count)));
      Object.entries(monthlySummary.severity_distribution).forEach(([severity, count]) => rows.push(sectionRow("Severity Distribution", titleCase(severity), "", count)));
      Object.entries(monthlySummary.module_activity_summary).forEach(([metric, value]) => {
        if (metric === "latest_activity_timestamp") rows.push(sectionRow("Module Activity / Coverage Summary", "Latest Activity Timestamp", "", "", value || ""));
        else rows.push(sectionRow("Module Activity / Coverage Summary", titleCase(metric), "", value));
      });
      monthlySummary.recommendations.forEach((recommendation, index) => rows.push(sectionRow("Recommendations", `Recommendation ${index + 1}`, recommendation)));
      return { filename: "monthly-security-report.csv", blob: csvBlob(rows) };
    }
    if (activeReportModule === "activity") {
      return {
        filename: "user-activity-report.csv",
        blob: csvBlob([
          ["Timestamp", "Actor", "Role", "Source", "Activity Type", "Action", "Status"],
          ...activitySummary.recent_activity.map((item) => [
            item.timestamp || "",
            item.actor_display_name || item.actor,
            item.role,
            item.module,
            item.activity_type,
            item.action,
            item.status,
          ]),
        ]),
      };
    }
    if (activeReportModule === "highRisk") {
      return {
        filename: "high-risk-users-report.csv",
        blob: csvBlob([
          ["User", "Role", "Risk Score", "Risk Level", "Main Risk Source", "Signals", "Latest Signal", "Recommendation"],
          ...highRiskSummary.top_risk_users.map((item) => [
            item.actor_display_name,
            item.actor_role,
            item.risk_score,
            item.risk_level,
            item.top_risk_source,
            item.total_signals,
            item.latest_signal_timestamp || "",
            item.safe_recommendation,
          ]),
        ]),
      };
    }
    if (activeReportModule === "incidents") {
      return {
        filename: "security-incidents-report.csv",
        blob: csvBlob([
          ["Time", "Severity", "Source", "Incident Type", "Title", "Status", "Actor", "Recommendation"],
          ...incidentsSummary.recent_incidents.map((item) => [
            item.timestamp || "",
            item.severity,
            item.source,
            item.incident_type,
            item.title,
            item.status,
            item.actor_display_name,
            item.recommendation,
          ]),
        ]),
      };
    }
    if (activeReportModule === "vault") {
      const rows: unknown[][] = [
        ["Section", "Item", "Value", "Count", "Timestamp", "Notes"],
        sectionRow("Report Metadata", "Report Title", vaultSummary.report_name),
        sectionRow("Report Metadata", "Generated At", "", "", vaultSummary.generated_at || ""),
        sectionRow("Report Metadata", "Reporting Period", vaultSummary.reporting_period.label),
        sectionRow("Summary", "Total Documents", "", vaultSummary.summary.total_documents),
        sectionRow("Summary", "Documents Uploaded", "", vaultSummary.summary.documents_uploaded),
        sectionRow("Summary", "Unique Owners", "", vaultSummary.summary.unique_owners),
        sectionRow("Summary", "Offline Enabled Documents", "", vaultSummary.summary.offline_enabled_documents),
        sectionRow("Summary", "Upload Events", "", vaultSummary.summary.upload_events),
        sectionRow("Summary", "Encryption Events", "", vaultSummary.summary.encryption_events),
        sectionRow("Summary", "Download Events", "", vaultSummary.summary.download_events),
        sectionRow("Summary", "Delete Events", "", vaultSummary.summary.delete_events),
        sectionRow("Summary", "Wrong Password Events", "", vaultSummary.summary.wrong_password_events),
        sectionRow("Summary", "Access Denied Events", "", vaultSummary.summary.access_denied_events),
        sectionRow("Summary", "Integrity Failures", "", vaultSummary.summary.integrity_failures),
        sectionRow("Summary", "Latest Activity", "", "", vaultSummary.summary.latest_activity_at || ""),
      ];
      Object.entries(vaultSummary.action_distribution).forEach(([action, count]) => rows.push(sectionRow("Action Distribution", titleCase(action), "", count)));
      Object.entries(vaultSummary.severity_distribution).forEach(([severity, count]) => rows.push(sectionRow("Severity Distribution", titleCase(severity), "", count)));
      filteredVaultRecentActivity.forEach((item) => rows.push(sectionRow("Recent Activity", item.action, item.target_label || "Aggregate vault event", "", item.timestamp || "", `${titleCase(item.status)} / ${titleCase(item.severity)}`)));
      vaultSummary.recommendations.forEach((recommendation, index) => rows.push(sectionRow("Recommendations", `Recommendation ${index + 1}`, recommendation)));
      return { filename: "file-vault-activity-summary.csv", blob: csvBlob(rows) };
    }
    return { filename: "report.csv", blob: csvBlob([["message"], ["No aggregate report selected"]]) };
  };

  const buildAggregatePdfExport = (): { blob: Blob; filename: string } => {
    const rows: Array<[string, unknown]> = [
      ...activeFilterRows().map(([label, value]) => [`Filter: ${label}`, value] as [string, unknown]),
      ...activeSummaryItems,
    ];
    if (activeReportModule === "identity") {
      identitySummary.recent_reports.slice(0, 8).forEach((item, index) => {
        rows.push([`Identity Row ${index + 1}`, `${titleCase(item.risk_level)} risk, ${item.findings_count} findings, ${formatAdminPcapTime(item.generated_at)}`]);
      });
      return { filename: "identity-report.pdf", blob: buildSimplePdfBlob("Identity Leak Summary", "Safe filtered identity report export", rows) };
    }
    if (activeReportModule === "password") {
      Object.entries(passwordSummary.risk_distribution).forEach(([risk, count]) => rows.push([`Risk: ${titleCase(risk)}`, count]));
      Object.entries(passwordSummary.strength_distribution).forEach(([strength, count]) => rows.push([`Strength: ${titleCase(strength)}`, count]));
      passwordSummary.recommendations.slice(0, 6).forEach((item, index) => rows.push([`Recommendation ${index + 1}`, item]));
      return { filename: "password-risk-summary.pdf", blob: buildSimplePdfBlob("Password Risk Summary", "Safe aggregate password report export", rows) };
    }
    if (activeReportModule === "phishing") {
      Object.entries(phishingSummary.category_distribution).forEach(([category, count]) => rows.push([`Category: ${titleCase(category)}`, count]));
      Object.entries(phishingSummary.risk_distribution).forEach(([risk, count]) => rows.push([`Risk Level: ${titleCase(risk)}`, count]));
      if (phishingSummary.highest_risk_scan) {
        rows.push(["Highest Risk URL / Domain", `${phishingSummary.highest_risk_scan.url} / ${phishingSummary.highest_risk_scan.domain || "Unknown"} (${phishingSummary.highest_risk_scan.final_risk_score}/100)`]);
      }
      phishingSummary.latest_scans.slice(0, 8).forEach((item, index) => rows.push([`Latest Scan ${index + 1}`, `${titleCase(item.final_category)} - ${item.domain || item.url} - ${item.final_risk_score}/100`]));
      phishingSummary.recommendations.slice(0, 6).forEach((item, index) => rows.push([`Recommendation ${index + 1}`, item]));
      return { filename: "phishing-incidents-summary.pdf", blob: buildSimplePdfBlob("Phishing Incidents Summary", "Safe phishing scanner incident summary export", rows) };
    }
    if (activeReportModule === "monthly") {
      Object.entries(monthlySummary.severity_distribution).forEach(([severity, count]) => rows.push([`Severity: ${titleCase(severity)}`, count]));
      Object.entries(monthlySummary.module_distribution).forEach(([module, count]) => rows.push([`Module: ${titleCase(module)}`, count]));
      monthlySummary.recommendations.slice(0, 6).forEach((item, index) => rows.push([`Recommendation ${index + 1}`, item]));
      return { filename: "monthly-security-report.pdf", blob: buildSimplePdfBlob("Monthly Security Report", "Safe filtered monthly report export", rows) };
    }
    if (activeReportModule === "activity") {
      Object.entries(activitySummary.activity_type_distribution).forEach(([type, count]) => rows.push([`Activity Type: ${titleCase(type)}`, count]));
      activitySummary.recent_activity.slice(0, 8).forEach((item, index) => rows.push([`Activity Row ${index + 1}`, `${item.actor_display_name || item.actor} - ${titleCase(item.module)} - ${titleCase(item.status)}`]));
      return { filename: "user-activity-report.pdf", blob: buildSimplePdfBlob("User Activity Report", "Safe filtered activity report export", rows) };
    }
    if (activeReportModule === "highRisk") {
      Object.entries(highRiskSummary.risk_level_distribution).forEach(([risk, count]) => rows.push([`Risk Level: ${titleCase(risk)}`, count]));
      Object.entries(highRiskSummary.module_signal_distribution).forEach(([module, count]) => rows.push([`Source: ${titleCase(module)}`, count]));
      highRiskSummary.top_risk_users.slice(0, 8).forEach((item, index) => rows.push([`High-Risk Row ${index + 1}`, `${item.actor_display_name} - ${titleCase(item.risk_level)} - ${titleCase(item.top_risk_source)}`]));
      return { filename: "high-risk-users-report.pdf", blob: buildSimplePdfBlob("High-Risk Users Report", "Safe filtered high-risk users export", rows) };
    }
    if (activeReportModule === "incidents") {
      Object.entries(incidentsSummary.severity_distribution).forEach(([severity, count]) => rows.push([`Severity: ${titleCase(severity)}`, count]));
      Object.entries(incidentsSummary.source_distribution).forEach(([source, count]) => rows.push([`Source: ${titleCase(source)}`, count]));
      Object.entries(incidentsSummary.incident_type_distribution).forEach(([type, count]) => rows.push([`Incident Type: ${titleCase(type)}`, count]));
      incidentsSummary.recent_incidents.slice(0, 8).forEach((item, index) => rows.push([`Incident Row ${index + 1}`, `${titleCase(item.severity)} - ${titleCase(item.source)} - ${item.title}`]));
      return { filename: "security-incidents-report.pdf", blob: buildSimplePdfBlob("Security Incidents Report", "Safe filtered security incidents export", rows) };
    }
    if (activeReportModule === "vault") {
      Object.entries(vaultSummary.action_distribution).forEach(([action, count]) => rows.push([`Action: ${titleCase(action)}`, count]));
      Object.entries(vaultSummary.severity_distribution).forEach(([severity, count]) => rows.push([`Severity: ${titleCase(severity)}`, count]));
      filteredVaultRecentActivity.slice(0, 8).forEach((item, index) => rows.push([`Vault Activity ${index + 1}`, `${item.action} - ${titleCase(item.status)} - ${formatAdminPcapTime(item.timestamp)}`]));
      vaultSummary.recommendations.slice(0, 6).forEach((item, index) => rows.push([`Recommendation ${index + 1}`, item]));
      return { filename: "file-vault-activity-summary.pdf", blob: buildSimplePdfBlob("File Vault Activity Summary", "Safe aggregate vault report export", rows) };
    }
    return { filename: "report.pdf", blob: buildSimplePdfBlob(activeReportTitle, "Safe report export", rows) };
  };

  return (
    <section className="reports-center-shell">
      <div className="reports-center-glow reports-center-glow-a" />
      <div className="reports-center-glow reports-center-glow-b" />

      <header className="reports-center-hero">
        <div>
          <div className="reports-eyebrow">
            <FileBarChart className="h-4 w-4" />
            Enterprise reporting workspace
          </div>
          <h1>Reports & Export Center</h1>
          <p>
            Generate, review, and export PCAP, Identity Leak, and Password Risk reports with a modular
            reporting structure for security modules.
          </p>
          <div className="reports-module-switch">
            <Button
              variant="outline"
              className={activeReportModule === "pcap" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("pcap")}
            >
              PCAP Analysis Summary
            </Button>
            <Button
              variant="outline"
              className={activeReportModule === "identity" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("identity")}
            >
              Identity Leak Summary
            </Button>
            <Button
              variant="outline"
              className={activeReportModule === "password" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("password")}
            >
              Password Risk Summary
            </Button>
            <Button
              variant="outline"
              className={activeReportModule === "phishing" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("phishing")}
            >
              Phishing Incidents Summary
            </Button>
            <Button
              variant="outline"
              className={activeReportModule === "monthly" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("monthly")}
            >
              Monthly Security Report
            </Button>
            <Button
              variant="outline"
              className={activeReportModule === "activity" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("activity")}
            >
              User Activity Report
            </Button>
            <Button
              variant="outline"
              className={activeReportModule === "highRisk" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("highRisk")}
            >
              High-Risk Users Report
            </Button>
            <Button
              variant="outline"
              className={activeReportModule === "incidents" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("incidents")}
            >
              Security Incidents Report
            </Button>
            <Button
              variant="outline"
              className={activeReportModule === "vault" ? "reports-module-button-active" : "reports-action-button"}
              onClick={() => switchReportModule("vault")}
            >
              File Vault Activity Summary
            </Button>
          </div>
        </div>
        <div className="reports-hero-actions">
          <Badge className="reports-active-badge">
            <span />
            {activeReportLabel}
          </Badge>
          <Button variant="outline" className="reports-action-button" disabled={activeLoading} onClick={() => activeReportModule === "identity" ? void loadIdentityReports(appliedIdentityFilters, true) : activeReportModule === "password" ? void loadPasswordReport(appliedPasswordFilters, true) : activeReportModule === "phishing" ? void loadPhishingReport(appliedPhishingFilters, true) : activeReportModule === "monthly" ? void loadMonthlyReport(appliedMonthlyFilters, true) : activeReportModule === "activity" ? void loadActivityReport(appliedActivityFilters, true) : activeReportModule === "highRisk" ? void loadHighRiskReport(appliedHighRiskFilters, true) : activeReportModule === "incidents" ? void loadIncidentsReport(appliedIncidentsFilters, true) : activeReportModule === "vault" ? void loadVaultReport(true) : void loadReports(appliedFilters, true)}>
            {activeLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Refresh Report
          </Button>
          <Button className="reports-primary-button" onClick={handleGenerate} disabled={generating}>
            {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
            {activeReportModule === "identity" ? "Generate Identity Report" : activeReportModule === "password" ? "Generate Password Report" : activeReportModule === "phishing" ? "Generate Phishing Report" : activeReportModule === "monthly" ? "Refresh Monthly Report" : activeReportModule === "activity" ? "Refresh User Activity Report" : activeReportModule === "highRisk" ? "Refresh High-Risk Users Report" : activeReportModule === "incidents" ? "Refresh Security Incidents Report" : activeReportModule === "vault" ? "Refresh Vault Report" : "Generate PCAP Report"}
          </Button>
          <Button
            variant="outline"
            className="reports-action-button"
            onClick={() => void handleExport(latestReportId, "pdf")}
            disabled={!activeReportActionsEnabled || !latestReportId || exporting !== null}
            title={!activeReportActionsEnabled ? `${activeReportTitle} is not ready to export.` : undefined}
          >
            {exporting === `${latestReportId}-pdf` || exporting === `${activeExportKey}-pdf` ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            Export PDF
          </Button>
        </div>
      </header>

      {activeError ? (
        <div className="reports-error">
          <AlertTriangle className="h-5 w-5" />
          <span>{activeError}</span>
        </div>
      ) : null}

      {usingFallback ? (
        <div className="reports-info">
          <Sparkles className="h-4 w-4" />
          PCAP reporting is running with safe fallback data until every backend report endpoint is connected.
        </div>
      ) : null}

      <div className="reports-kpi-grid">
        {activeReportModule === "identity" ? (
          <>
            <KpiCard title="Identity Scans" value={identityLoading ? "..." : formatNumber(identitySummary.total_scans)} detail="Live Identity Leak Monitor scans" icon={FileText} tone="blue" />
            <KpiCard title="Total Findings" value={identityLoading ? "..." : formatNumber(identitySummary.total_findings)} detail="Exposure findings across scans" icon={CheckCircle2} tone="green" />
            <KpiCard title="Critical Scans" value={identityLoading ? "..." : formatNumber(identitySummary.critical_scans)} detail="Critical identity risk reports" icon={XCircle} tone="red" />
            <KpiCard title="Last Identity Report" value={identityLoading ? "..." : formatAdminPcapTime(identitySummary.last_generated)} detail="Latest generated scan summary" icon={Calendar} tone="purple" />
          </>
        ) : activeReportModule === "password" ? (
          <>
            <KpiCard title="Password Checks" value={passwordLoading ? "..." : formatNumber(passwordSummary.summary.total_checks)} detail="Total Password Checker records" icon={KeyRound} tone="blue" />
            <KpiCard title="Breached Findings" value={passwordLoading ? "..." : formatNumber(passwordSummary.summary.breached_findings)} detail="Checks found in breach data" icon={ShieldAlert} tone="red" />
            <KpiCard title="Weak Findings" value={passwordLoading ? "..." : formatNumber(passwordSummary.summary.weak_findings)} detail="Weak or very weak results" icon={XCircle} tone="purple" />
            <KpiCard title="Strong Safe Checks" value={passwordLoading ? "..." : formatNumber(passwordSummary.summary.strong_safe_checks)} detail="Strong non-breached results" icon={CheckCircle2} tone="green" />
          </>
        ) : activeReportModule === "phishing" ? (
          <>
            <KpiCard title="Total URL Scans" value={phishingLoading ? "..." : formatNumber(phishingSummary.summary.total_url_scans)} detail="Successful Phishing Scanner rows" icon={FileSearch} tone="blue" />
            <KpiCard title="Risky URLs" value={phishingLoading ? "..." : formatNumber(phishingSummary.summary.risky_urls)} detail="Suspicious plus dangerous URLs" icon={ShieldAlert} tone="red" />
            <KpiCard title="Average Risk Score" value={phishingLoading ? "..." : formatNumber(phishingSummary.summary.average_risk_score)} detail="Average final URL risk score" icon={AlertTriangle} tone="purple" />
            <KpiCard title="Latest Scan" value={phishingLoading ? "..." : formatAdminPcapTime(phishingSummary.summary.latest_scan_time)} detail="Most recent phishing scan timestamp" icon={Clock} tone="green" />
          </>
        ) : activeReportModule === "monthly" ? (
          <>
            <KpiCard title="Monthly Events" value={monthlyLoading ? "..." : formatNumber(monthlySummary.summary.total_events)} detail="Safe current-month aggregate events" icon={Calendar} tone="blue" />
            <KpiCard title="Critical Events" value={monthlyLoading ? "..." : formatNumber(monthlySummary.summary.critical)} detail="Critical severity signals this month" icon={ShieldAlert} tone="red" />
            <KpiCard title="High Events" value={monthlyLoading ? "..." : formatNumber(monthlySummary.summary.high)} detail="High severity signals this month" icon={AlertTriangle} tone="purple" />
            <KpiCard title="Generated At" value={monthlyLoading ? "..." : formatAdminPcapTime(monthlySummary.generated_at)} detail="Latest report refresh timestamp" icon={FileText} tone="green" />
          </>
        ) : activeReportModule === "vault" ? (
          <>
            <KpiCard title="Vault Documents" value={vaultLoading ? "..." : formatNumber(vaultSummary.summary.total_documents)} detail="Encrypted documents stored in vault" icon={FolderLock} tone="blue" />
            <KpiCard title="Upload Events" value={vaultLoading ? "..." : formatNumber(vaultSummary.summary.upload_events)} detail="Vault uploads in reporting period" icon={FileText} tone="green" />
            <KpiCard title="Downloads / Deletes" value={vaultLoading ? "..." : `${formatNumber(vaultSummary.summary.download_events)} / ${formatNumber(vaultSummary.summary.delete_events)}`} detail="Sensitive vault file activity" icon={FileDown} tone="purple" />
            <KpiCard title="Failed Access" value={vaultLoading ? "..." : formatNumber(vaultSummary.summary.wrong_password_events + vaultSummary.summary.access_denied_events)} detail="Wrong password and denied access events" icon={ShieldAlert} tone="red" />
          </>
        ) : activeReportModule === "activity" ? (
          <>
            <KpiCard title="Activity Events" value={activityLoading ? "..." : formatNumber(activitySummary.summary.total_activity_events)} detail="Safe activity records in scope" icon={Users} tone="blue" />
            <KpiCard title="Unique Actors" value={activityLoading ? "..." : formatNumber(activitySummary.summary.unique_actors)} detail="Distinct safe actor identifiers" icon={ShieldCheck} tone="green" />
            <KpiCard title="Exports / Downloads" value={activityLoading ? "..." : formatNumber(activitySummary.summary.total_exports)} detail="Report and audit export actions" icon={FileDown} tone="purple" />
            <KpiCard title="Latest Activity" value={activityLoading ? "..." : formatAdminPcapTime(activitySummary.summary.latest_activity_at)} detail="Most recent safe event timestamp" icon={Clock} tone="red" />
          </>
        ) : activeReportModule === "highRisk" ? (
          <>
            <KpiCard title="Critical Users" value={highRiskLoading ? "..." : formatNumber(highRiskSummary.summary.critical_risk_users)} detail="Users with critical risk scores" icon={ShieldAlert} tone="red" />
            <KpiCard title="High-Risk Users" value={highRiskLoading ? "..." : formatNumber(highRiskSummary.summary.high_risk_users)} detail="Users with high risk scores" icon={AlertTriangle} tone="purple" />
            <KpiCard title="Risk Signals" value={highRiskLoading ? "..." : formatNumber(highRiskSummary.summary.total_risk_signals)} detail="Safe signals in scope" icon={FileSearch} tone="blue" />
            <KpiCard title="Latest Signal" value={highRiskLoading ? "..." : formatAdminPcapTime(highRiskSummary.summary.latest_risk_signal_timestamp)} detail="Most recent risk signal" icon={Clock} tone="green" />
          </>
        ) : activeReportModule === "incidents" ? (
          <>
            <KpiCard title="Security Incidents" value={incidentsLoading ? "..." : formatNumber(incidentsSummary.summary.total_incidents)} detail="Real security alerts and findings" icon={ShieldAlert} tone="blue" />
            <KpiCard title="Critical Incidents" value={incidentsLoading ? "..." : formatNumber(incidentsSummary.summary.critical_incidents)} detail="Critical severity incidents" icon={AlertTriangle} tone="red" />
            <KpiCard title="Open Incidents" value={incidentsLoading ? "..." : formatNumber(incidentsSummary.summary.open_incidents)} detail="Open security incidents" icon={FileSearch} tone="purple" />
            <KpiCard title="Latest Incident" value={incidentsLoading ? "..." : formatAdminPcapTime(incidentsSummary.summary.latest_incident_timestamp)} detail="Most recent incident timestamp" icon={Clock} tone="green" />
          </>
        ) : (
          <>
            <KpiCard title="PCAP Reports Generated" value={loading ? "..." : formatNumber(overview.pcap_reports_generated)} detail="Generated PCAP reports or completed analysis jobs" icon={FileText} tone="blue" />
            <KpiCard title="Completed Analysis Jobs" value={loading ? "..." : formatNumber(overview.completed_analysis_jobs)} detail="PCAP jobs completed successfully" icon={CheckCircle2} tone="green" />
            <KpiCard title="Failed Analysis Jobs" value={loading ? "..." : formatNumber(overview.failed_analysis_jobs)} detail="PCAP analysis jobs that failed" icon={XCircle} tone="red" />
            <KpiCard title="Latest PCAP Export" value={loading ? "..." : formatAdminPcapTime(overview.latest_pcap_export)} detail={overview.latest_pcap_export_status} icon={Calendar} tone="purple" />
          </>
        )}
      </div>

      <div className="reports-main-grid">
        <Card className="reports-active-card">
          <div className="reports-active-header">
            <div>
              <div className="reports-active-title-row">
                <h2>Active Report: {activeReportTitle}</h2>
                <Badge className="reports-badge reports-badge-success">Active</Badge>
              </div>
              <p>{activeReportDescription}</p>
            </div>
            <div className="reports-document-visual" aria-hidden="true">
              <FileBarChart className="h-16 w-16" />
              <span>{activeReportModule === "identity" ? "IDENTITY" : activeReportModule === "password" ? "PASSWORD" : activeReportModule === "phishing" ? "PHISHING" : activeReportModule === "monthly" ? "MONTHLY" : activeReportModule === "activity" ? "ACTIVITY" : activeReportModule === "highRisk" ? "RISK" : activeReportModule === "incidents" ? "INCIDENTS" : activeReportModule === "vault" ? "VAULT" : "PCAP"}</span>
            </div>
          </div>

          <div className="reports-summary-grid">
            {activeSummaryItems.map(([label, value]) => (
              <div key={label} className="reports-summary-item">
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>

          <div className="reports-active-actions">
            <Button className="reports-primary-button" onClick={handleGenerate} disabled={generating}>
              {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
              {activeReportModule === "identity" ? "Generate Identity Report" : activeReportModule === "password" ? "Generate Password Report" : activeReportModule === "phishing" ? "Generate Phishing Report" : activeReportModule === "monthly" ? "Refresh Monthly Report" : activeReportModule === "activity" ? "Refresh User Activity Report" : activeReportModule === "highRisk" ? "Refresh High-Risk Users Report" : activeReportModule === "incidents" ? "Refresh Security Incidents Report" : activeReportModule === "vault" ? "Refresh Vault Report" : "Generate Report"}
            </Button>
            <Button
              variant="outline"
              className="reports-action-button"
              onClick={() => void handleExport(latestReportId, "pdf")}
              disabled={!activeReportActionsEnabled || exporting !== null}
              title={!activeReportActionsEnabled ? `${activeReportTitle} is not ready to export.` : undefined}
            >
              {exporting === `${latestReportId}-pdf` || exporting === `${activeExportKey}-pdf` ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileDown className="h-4 w-4" />}
              Export PDF
            </Button>
            <Button
              variant="outline"
              className="reports-action-button"
              onClick={() => void handleExport(latestReportId, "csv")}
              disabled={!activeReportActionsEnabled || exporting !== null}
              title={!activeReportActionsEnabled ? `${activeReportTitle} is not ready to export.` : undefined}
            >
              {exporting === `${latestReportId}-csv` || exporting === `${activeExportKey}-csv` ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileDown className="h-4 w-4" />}
              Export CSV
            </Button>
            <Button
              variant="outline"
              className="reports-action-button"
              onClick={() => {
                const table = document.getElementById(activeReportModule === "identity" ? "recent-identity-reports" : activeReportModule === "password" ? "password-risk-report" : activeReportModule === "phishing" ? "phishing-incidents-report" : activeReportModule === "monthly" ? "monthly-security-report" : activeReportModule === "activity" ? "user-activity-report" : activeReportModule === "highRisk" ? "high-risk-users-report" : activeReportModule === "incidents" ? "security-incidents-report" : activeReportModule === "vault" ? "file-vault-activity-report" : "recent-pcap-reports");
                table?.scrollIntoView({ behavior: "smooth", block: "start" });
              }}
              disabled={!activeReportActionsEnabled}
            >
              <Eye className="h-4 w-4" />
              View Details
            </Button>
          </div>
        </Card>

        <Card className="reports-future-section">
          <div className="reports-card-head">
            <div>
              <h2>Future Module Report Categories</h2>
              <p>Ready for future module integration without presenting fake analytics.</p>
            </div>
            <Layers className="h-5 w-5 text-blue-300" />
          </div>
          <div className="reports-future-grid">
            {futureCategories.map((category, index) => {
              const isVaultCategory = isVaultReportCategory(category);
              const displayCategory: FutureReportCategory = isVaultCategory
                ? {
                    ...category,
                    badge: "Connected" as const,
                    description:
                      "Connected to encrypted vault documents, uploads, downloads, deletes, integrity checks, failed access, and offline access activity.",
                  }
                : category.id === "user-activity" && activityError
                  ? { ...category, badge: "Waiting for Module Integration" as const }
                  : category.id === "high-risk-users" && highRiskError
                  ? { ...category, badge: "Waiting for Module Integration" as const }
                  : category.id === "security-incidents" && incidentsError
                  ? { ...category, badge: "Waiting for Module Integration" as const }
                  : category;

              return (
                <FutureCategoryCard
                  key={category.id}
                  category={displayCategory}
                  icon={isVaultCategory ? FolderLock : futureIcons[index] || FileText}
                  onSelect={
                    isVaultCategory
                      ? () => switchReportModule("vault")
                      : category.id === "monthly-security"
                      ? () => switchReportModule("monthly")
                      : category.id === "identity-leak"
                      ? () => switchReportModule("identity")
                      : category.id === "user-activity"
                      ? () => switchReportModule("activity")
                      : category.id === "high-risk-users"
                      ? () => switchReportModule("highRisk")
                      : category.id === "security-incidents"
                      ? () => switchReportModule("incidents")
                      : category.id === "password-risk"
                        ? () => switchReportModule("password")
                      : category.id === "phishing-incidents"
                        ? () => switchReportModule("phishing")
                        : undefined
                  }
                />
              );
            })}
          </div>
        </Card>
      </div>

      <div className="reports-bottom-grid">
        <Card className="reports-filter-card">
          <div className="reports-card-head">
            <div>
              <h2>{activeReportModule === "identity" ? "Identity Report Filters" : activeReportModule === "password" ? "Password Report Scope" : activeReportModule === "phishing" ? "Phishing Report Filters" : activeReportModule === "monthly" ? "Monthly Report Scope" : activeReportModule === "activity" ? "User Activity Report Filters" : activeReportModule === "highRisk" ? "High-Risk Users Report Filters" : activeReportModule === "incidents" ? "Security Incidents Report Filters" : activeReportModule === "vault" ? "File Vault Report Scope" : "PCAP Report Filters"}</h2>
              <p>{activeReportModule === "identity" ? "Refine identity scans by risk, source, status, date, and findings." : activeReportModule === "password" ? "Password Risk Summary is aggregate-only and uses all safe Password Checker records." : activeReportModule === "phishing" ? "Refine phishing scanner results by date, risk level, category, and export format." : activeReportModule === "monthly" ? "Monthly Security Report summarizes safe current-month aggregates only." : activeReportModule === "activity" ? "Refine safe user activity by period, role, activity type, and source." : activeReportModule === "highRisk" ? "Refine high-risk users by period, risk level, source, and role." : activeReportModule === "incidents" ? "Refine real security incidents by period, severity, source, type, and status." : activeReportModule === "vault" ? "File Vault report uses the current reporting period and safe aggregate vault records only." : "Refine the recent PCAP jobs list by report-ready fields."}</p>
            </div>
            <Filter className="h-5 w-5 text-blue-300" />
          </div>
          {activeReportModule === "vault" ? (
          <>
            <div className="reports-filter-grid">
              <div className="reports-filter-span">
                <label>Date Range</label>
                <div className="reports-date-row">
                  <Input
                    type="date"
                    value={vaultFilters.dateFrom}
                    onChange={(event) => setVaultFilters((current) => ({ ...current, dateFrom: event.target.value }))}
                  />
                  <Input
                    type="date"
                    value={vaultFilters.dateTo}
                    onChange={(event) => setVaultFilters((current) => ({ ...current, dateTo: event.target.value }))}
                  />
                </div>
              </div>

              <div>
                <label>Vault Activity</label>
                <Select value={vaultFilters.activityType} onValueChange={(value: string) => setVaultFilters((current) => ({ ...current, activityType: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="upload">Upload</SelectItem>
                    <SelectItem value="encrypt">Encryption</SelectItem>
                    <SelectItem value="download">Download</SelectItem>
                    <SelectItem value="delete">Delete</SelectItem>
                    <SelectItem value="integrity">Integrity Check</SelectItem>
                    <SelectItem value="offline">Offline Access</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <label>Access Status</label>
                <Select value={vaultFilters.accessStatus} onValueChange={(value: string) => setVaultFilters((current) => ({ ...current, accessStatus: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="success">Success</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="failed">Failed</SelectItem>
                    <SelectItem value="denied">Denied</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <label>Security Level</label>
                <Select value={vaultFilters.severity} onValueChange={(value: string) => setVaultFilters((current) => ({ ...current, severity: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="unknown">Unknown</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <label>Offline Access</label>
                <Select value={vaultFilters.offlineAccess} onValueChange={(value: string) => setVaultFilters((current) => ({ ...current, offlineAccess: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="enabled">Enabled</SelectItem>
                    <SelectItem value="disabled">Disabled</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <label>Security Signal</label>
                <Select value={vaultFilters.securitySignal} onValueChange={(value: string) => setVaultFilters((current) => ({ ...current, securitySignal: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="suspicious">Suspicious Only</SelectItem>
                    <SelectItem value="failed_access">Failed Access</SelectItem>
                    <SelectItem value="wrong_password">Wrong Password</SelectItem>
                    <SelectItem value="integrity_failure">Integrity Failure</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="reports-evidence-list">
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Vault Filter Scope</h3>
                  <Badge className="reports-badge reports-badge-success">Safe</Badge>
                </div>
                <div className="reports-summary-grid">
                  <div className="reports-summary-item">
                    <span>Filters Apply To</span>
                    <strong>Recent vault activity and exports</strong>
                  </div>
                  <div className="reports-summary-item">
                    <span>Security Focus</span>
                    <strong>Failed access, wrong password, integrity failures</strong>
                  </div>
                  <div className="reports-summary-item">
                    <span>Hidden</span>
                    <strong>File contents, keys, hashes, salts</strong>
                  </div>
                </div>
              </div>
            </div>
          </>
          ) : activeReportModule === "monthly" ? (
          <div className="reports-filter-grid">
            <div>
              <label>Severity</label>
              <Select value={monthlyFilters.severity} onValueChange={(value: MonthlySecurityReportFilters["severity"]) => setMonthlyFilters((current) => ({ ...current, severity: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="unknown">Unknown</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Module / Source</label>
              <Select value={monthlyFilters.module} onValueChange={(value: MonthlySecurityReportFilters["module"]) => setMonthlyFilters((current) => ({ ...current, module: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="pcap_analyzer">PCAP Analyzer</SelectItem><SelectItem value="identity_leak_monitor">Identity Leak Monitor</SelectItem><SelectItem value="password_checker">Password Checker</SelectItem><SelectItem value="notifications">Notifications</SelectItem><SelectItem value="admin_audit_trail">Admin Audit Trail</SelectItem><SelectItem value="user_activity">User Activity</SelectItem><SelectItem value="other_unknown">Other / Unknown</SelectItem></SelectContent>
              </Select>
            </div>
          </div>
          ) : activeReportModule === "activity" ? (
          <div className="reports-filter-grid">
            <div>
              <label>Date Range</label>
              <Select value={activityFilters.dateRange} onValueChange={(value: UserActivityReportFilters["dateRange"]) => setActivityFilters((current) => ({ ...current, dateRange: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="current_month">Current Month</SelectItem><SelectItem value="last_7_days">Last 7 Days</SelectItem><SelectItem value="last_30_days">Last 30 Days</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Actor Role</label>
              <Select value={activityFilters.role} onValueChange={(value: UserActivityReportFilters["role"]) => setActivityFilters((current) => ({ ...current, role: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="admin">Admin</SelectItem><SelectItem value="user">User</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Activity Type</label>
              <Select value={activityFilters.activityType} onValueChange={(value: UserActivityReportFilters["activityType"]) => setActivityFilters((current) => ({ ...current, activityType: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="auth">Auth</SelectItem><SelectItem value="admin_action">Admin Action</SelectItem><SelectItem value="export">Export</SelectItem><SelectItem value="module_activity">Module Activity</SelectItem><SelectItem value="audit">Audit</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Module / Source</label>
              <Select value={activityFilters.moduleSource} onValueChange={(value: UserActivityReportFilters["moduleSource"]) => setActivityFilters((current) => ({ ...current, moduleSource: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="admin_audit">Admin Audit Trail</SelectItem><SelectItem value="password_checker">Password Checker</SelectItem><SelectItem value="identity_leak_monitor">Identity Leak Monitor</SelectItem><SelectItem value="pcap_analyzer">PCAP Analyzer</SelectItem><SelectItem value="reports_exports">Reports/Exports</SelectItem><SelectItem value="notifications">Notifications</SelectItem><SelectItem value="authentication">Authentication</SelectItem></SelectContent>
              </Select>
            </div>
          </div>
          ) : activeReportModule === "incidents" ? (
          <div className="reports-filter-grid">
            <div>
              <label>Date Range</label>
              <Select value={incidentsFilters.dateRange} onValueChange={(value: SecurityIncidentsReportFilters["dateRange"]) => setIncidentsFilters((current) => ({ ...current, dateRange: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="current_month">Current Month</SelectItem><SelectItem value="last_7_days">Last 7 Days</SelectItem><SelectItem value="last_30_days">Last 30 Days</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Severity</label>
              <Select value={incidentsFilters.severity} onValueChange={(value: SecurityIncidentsReportFilters["severity"]) => setIncidentsFilters((current) => ({ ...current, severity: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="unknown">Unknown</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Module / Source</label>
              <Select value={incidentsFilters.moduleSource} onValueChange={(value: SecurityIncidentsReportFilters["moduleSource"]) => setIncidentsFilters((current) => ({ ...current, moduleSource: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="pcap_analyzer">PCAP Analyzer</SelectItem><SelectItem value="identity_leak_monitor">Identity Leak Monitor</SelectItem><SelectItem value="password_checker">Password Checker</SelectItem><SelectItem value="notifications">Notifications</SelectItem><SelectItem value="authentication">Authentication</SelectItem><SelectItem value="threat_management">Threat Management</SelectItem><SelectItem value="user_activity">User Activity</SelectItem><SelectItem value="admin_audit">Admin Audit Trail</SelectItem><SelectItem value="other">Other / Unknown</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Incident Type</label>
              <Select value={incidentsFilters.incidentType} onValueChange={(value: SecurityIncidentsReportFilters["incidentType"]) => setIncidentsFilters((current) => ({ ...current, incidentType: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="network_alert">Network Alert</SelectItem><SelectItem value="identity_exposure">Identity Exposure</SelectItem><SelectItem value="password_risk">Password Risk</SelectItem><SelectItem value="security_notification">Security Notification</SelectItem><SelectItem value="auth_warning">Auth Warning</SelectItem><SelectItem value="audit_warning">Audit Warning</SelectItem><SelectItem value="threat_management">Threat Management</SelectItem><SelectItem value="other">Other</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Status</label>
              <Select value={incidentsFilters.status} onValueChange={(value: SecurityIncidentsReportFilters["status"]) => setIncidentsFilters((current) => ({ ...current, status: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="open">Open</SelectItem><SelectItem value="investigating">Investigating</SelectItem><SelectItem value="resolved">Resolved</SelectItem><SelectItem value="dismissed">Dismissed</SelectItem><SelectItem value="unknown">Unknown</SelectItem></SelectContent>
              </Select>
            </div>
          </div>
          ) : activeReportModule === "highRisk" ? (
          <div className="reports-filter-grid">
            <div>
              <label>Date Range</label>
              <Select value={highRiskFilters.dateRange} onValueChange={(value: HighRiskUsersReportFilters["dateRange"]) => setHighRiskFilters((current) => ({ ...current, dateRange: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="current_month">Current Month</SelectItem><SelectItem value="last_7_days">Last 7 Days</SelectItem><SelectItem value="last_30_days">Last 30 Days</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Risk Level</label>
              <Select value={highRiskFilters.riskLevel} onValueChange={(value: HighRiskUsersReportFilters["riskLevel"]) => setHighRiskFilters((current) => ({ ...current, riskLevel: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Module / Source</label>
              <Select value={highRiskFilters.moduleSource} onValueChange={(value: HighRiskUsersReportFilters["moduleSource"]) => setHighRiskFilters((current) => ({ ...current, moduleSource: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="password_checker">Password Checker</SelectItem><SelectItem value="identity_leak_monitor">Identity Leak Monitor</SelectItem><SelectItem value="pcap_analyzer">PCAP Analyzer</SelectItem><SelectItem value="authentication">Authentication</SelectItem><SelectItem value="notifications">Notifications</SelectItem><SelectItem value="user_activity">User Activity</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Role</label>
              <Select value={highRiskFilters.role} onValueChange={(value: HighRiskUsersReportFilters["role"]) => setHighRiskFilters((current) => ({ ...current, role: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="admin">Admin</SelectItem><SelectItem value="user">User</SelectItem></SelectContent>
              </Select>
            </div>
          </div>
          ) : activeReportModule === "phishing" ? (
          <div className="reports-filter-grid">
            <div className="reports-filter-span">
              <label>Date Range</label>
              <div className="reports-date-row">
                <Input type="date" value={phishingFilters.dateFrom} onChange={(event) => setPhishingFilters((current) => ({ ...current, dateFrom: event.target.value }))} />
                <Input type="date" value={phishingFilters.dateTo} onChange={(event) => setPhishingFilters((current) => ({ ...current, dateTo: event.target.value }))} />
              </div>
            </div>
            <div>
              <label>Risk Level</label>
              <Select value={phishingFilters.riskLevel} onValueChange={(value: PhishingIncidentsReportFilters["riskLevel"]) => setPhishingFilters((current) => ({ ...current, riskLevel: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Status / Category</label>
              <Select value={phishingFilters.category} onValueChange={(value: PhishingIncidentsReportFilters["category"]) => setPhishingFilters((current) => ({ ...current, category: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="safe">Safe</SelectItem><SelectItem value="suspicious">Suspicious</SelectItem><SelectItem value="dangerous">Dangerous</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Export Format</label>
              <Select value={phishingFilters.exportFormat} onValueChange={(value: PhishingIncidentsReportFilters["exportFormat"]) => setPhishingFilters((current) => ({ ...current, exportFormat: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="pdf">PDF</SelectItem><SelectItem value="csv">CSV</SelectItem></SelectContent>
              </Select>
            </div>
          </div>
          ) : activeReportModule === "password" ? (
          <>
            <div className="reports-filter-grid">
              <div>
                <label>Password Risk</label>
                <Select value={passwordFilters.passwordRisk} onValueChange={(value: PasswordRiskReportFilters["passwordRisk"]) => setPasswordFilters((current) => ({ ...current, passwordRisk: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem></SelectContent>
                </Select>
              </div>
              <div>
                <label>Password Strength</label>
                <Select value={passwordFilters.passwordStrength} onValueChange={(value: PasswordRiskReportFilters["passwordStrength"]) => setPasswordFilters((current) => ({ ...current, passwordStrength: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="very_weak">Very Weak</SelectItem><SelectItem value="weak">Weak</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="strong">Strong</SelectItem></SelectContent>
                </Select>
              </div>
              <div>
                <label>Breach Status</label>
                <Select value={passwordFilters.breachStatus} onValueChange={(value: PasswordRiskReportFilters["breachStatus"]) => setPasswordFilters((current) => ({ ...current, breachStatus: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="breached">Breached</SelectItem><SelectItem value="not_breached">Not Breached</SelectItem></SelectContent>
                </Select>
              </div>
            </div>
            <div className="reports-empty-state">
              <KeyRound className="h-6 w-6" />
              Password Risk Summary does not expose per-user password details or raw password values. Refresh the report to rebuild aggregate metrics.
            </div>
          </>
          ) : activeReportModule === "identity" ? (
          <div className="reports-filter-grid">
            <div className="reports-filter-span">
              <label>Date Range</label>
              <div className="reports-date-row">
                <Input type="date" value={identityFilters.dateFrom} onChange={(event) => setIdentityFilters((current) => ({ ...current, dateFrom: event.target.value }))} />
                <Input type="date" value={identityFilters.dateTo} onChange={(event) => setIdentityFilters((current) => ({ ...current, dateTo: event.target.value }))} />
              </div>
            </div>
            <div>
              <label>Risk Level</label>
              <Select value={identityFilters.riskLevel} onValueChange={(value: IdentityReportFilters["riskLevel"]) => setIdentityFilters((current) => ({ ...current, riskLevel: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="critical">Critical</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Scan Status</label>
              <Select value={identityFilters.status} onValueChange={(value: IdentityReportFilters["status"]) => setIdentityFilters((current) => ({ ...current, status: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="completed">Completed</SelectItem><SelectItem value="failed">Failed</SelectItem><SelectItem value="running">Running</SelectItem><SelectItem value="queued">Queued</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Source</label>
              <Select value={identityFilters.source} onValueChange={(value: IdentityReportFilters["source"]) => setIdentityFilters((current) => ({ ...current, source: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {identitySourceOptions.map((source) => (
                    <SelectItem key={source} value={source}>{source === "all" ? "All Sources" : source}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label>Findings Count</label>
              <Select value={identityFilters.findingsCount} onValueChange={(value: IdentityReportFilters["findingsCount"]) => setIdentityFilters((current) => ({ ...current, findingsCount: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="with_findings">With Findings</SelectItem><SelectItem value="no_findings">No Findings</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Export Format</label>
              <Select value={identityFilters.exportFormat} onValueChange={(value: IdentityReportFilters["exportFormat"]) => setIdentityFilters((current) => ({ ...current, exportFormat: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="pdf">PDF</SelectItem><SelectItem value="csv">CSV</SelectItem></SelectContent>
              </Select>
            </div>
          </div>
          ) : (
          <div className="reports-filter-grid">
            <div className="reports-filter-span">
              <label>Date Range</label>
              <div className="reports-date-row">
                <Input type="date" value={filters.dateFrom} onChange={(event) => setFilters((current) => ({ ...current, dateFrom: event.target.value }))} />
                <Input type="date" value={filters.dateTo} onChange={(event) => setFilters((current) => ({ ...current, dateTo: event.target.value }))} />
              </div>
            </div>
            <div>
              <label>Job Status</label>
              <Select value={filters.status} onValueChange={(value: PcapReportFilters["status"]) => setFilters((current) => ({ ...current, status: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="completed">Completed</SelectItem><SelectItem value="failed">Failed</SelectItem><SelectItem value="running">Running</SelectItem><SelectItem value="queued">Queued</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Risk Level</label>
              <Select value={filters.riskLevel} onValueChange={(value: PcapReportFilters["riskLevel"]) => setFilters((current) => ({ ...current, riskLevel: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="critical">Critical</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Attack Family</label>
              <Select value={filters.attackFamily || "all"} onValueChange={(value: string) => setFilters((current) => ({ ...current, attackFamily: value === "all" ? "" : value }))}>
                <SelectTrigger><SelectValue placeholder="All" /></SelectTrigger>
                <SelectContent>
                  {attackFamilyOptions.map((family) => (
                    <SelectItem key={family} value={family}>{family === "all" ? "All" : family}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label>Export Format</label>
              <Select value={filters.exportFormat} onValueChange={(value: PcapReportFilters["exportFormat"]) => setFilters((current) => ({ ...current, exportFormat: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="pdf">PDF</SelectItem><SelectItem value="csv">CSV</SelectItem></SelectContent>
              </Select>
            </div>
            <div>
              <label>Analysis Mode</label>
              <Select value={filters.analysisMode} onValueChange={(value: PcapReportFilters["analysisMode"]) => setFilters((current) => ({ ...current, analysisMode: value }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="ML">ML</SelectItem><SelectItem value="Heuristics">Heuristics</SelectItem><SelectItem value="Hybrid">Hybrid</SelectItem><SelectItem value="Zeek-enriched">Zeek-enriched</SelectItem></SelectContent>
              </Select>
            </div>
          </div>
          )}
          <div className="reports-filter-actions">
            <Button className="reports-primary-button" onClick={applyFilters}>
              <Filter className="h-4 w-4" />
              Apply Filters
            </Button>
            <Button variant="outline" className="reports-action-button" onClick={clearFilters}>
              <RefreshCw className="h-4 w-4" />
              Clear Filters
            </Button>
          </div>
        </Card>

        {activeReportModule === "incidents" ? (
        <Card className="reports-table-card" id="security-incidents-report">
          <div className="reports-card-head">
            <div>
              <h2>Security Incidents Report</h2>
              <p>Safe normalized incidents from real alerts, findings, password risks, notifications, auth warnings, and audit warnings.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{formatNumber(incidentsSummary.summary.total_incidents)} incidents</Badge>
          </div>
          {incidentsLoading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading Security Incidents Report...
            </div>
          ) : (
            <div className="reports-evidence-list">
              <div className="reports-summary-grid">
                <div className="reports-summary-item"><span>Total Incidents</span><strong>{formatNumber(incidentsSummary.summary.total_incidents)}</strong></div>
                <div className="reports-summary-item"><span>Critical</span><strong>{formatNumber(incidentsSummary.summary.critical_incidents)}</strong></div>
                <div className="reports-summary-item"><span>High</span><strong>{formatNumber(incidentsSummary.summary.high_incidents)}</strong></div>
                <div className="reports-summary-item"><span>Medium</span><strong>{formatNumber(incidentsSummary.summary.medium_incidents)}</strong></div>
                <div className="reports-summary-item"><span>Open</span><strong>{formatNumber(incidentsSummary.summary.open_incidents)}</strong></div>
                <div className="reports-summary-item"><span>Latest Incident</span><strong>{formatAdminPcapTime(incidentsSummary.summary.latest_incident_timestamp)}</strong></div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Severity Distribution</h3>
                  <Badge className="reports-badge reports-badge-blue">Incidents only</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(incidentsSummary.severity_distribution).map(([severity, count]) => (
                    <div key={severity} className="reports-summary-item"><span>{titleCase(severity)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Source Distribution</h3>
                  <Badge className="reports-badge reports-badge-success">Real records</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(incidentsSummary.source_distribution).map(([source, count]) => (
                    <div key={source} className="reports-summary-item"><span>{titleCase(source)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Incident Type Distribution</h3>
                  <Badge className="reports-badge reports-badge-blue">Normalized</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(incidentsSummary.incident_type_distribution).map(([type, count]) => (
                    <div key={type} className="reports-summary-item"><span>{titleCase(type)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Status Distribution</h3>
                  <Badge className="reports-badge reports-badge-blue">Safe status</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(incidentsSummary.status_distribution).map(([status, count]) => (
                    <div key={status} className="reports-summary-item"><span>{titleCase(status)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Timeline</h3>
                  <Badge className="reports-badge reports-badge-blue">{incidentsSummary.timeline.length} days</Badge>
                </div>
                <div className="reports-summary-grid">
                  {incidentsSummary.timeline.length === 0 ? (
                    <div className="reports-summary-item"><span>Timeline</span><strong>No incidents</strong></div>
                  ) : incidentsSummary.timeline.slice(-8).map((item) => (
                    <div key={item.date} className="reports-summary-item"><span>{item.date}</span><strong>{formatNumber(item.count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Top Risk Areas / Recommendations</h3>
                  <Badge className="reports-badge reports-badge-success">Safe summary</Badge>
                </div>
                <div className="reports-summary-grid">
                  {incidentsSummary.top_risk_areas.length === 0 ? (
                    <div className="reports-summary-item"><span>Risk Areas</span><strong>No incidents</strong></div>
                  ) : incidentsSummary.top_risk_areas.map((item) => (
                    <div key={item.title} className="reports-summary-item"><span>{item.title}</span><strong>{formatNumber(item.count)} {titleCase(item.severity)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Recent Security Incidents</h3>
                  <Badge className="reports-badge reports-badge-blue">{incidentsSummary.recent_incidents.length} rows</Badge>
                </div>
                {incidentsSummary.recent_incidents.length === 0 ? (
                  <p className="text-sm text-slate-300">No security incidents were found for this filter set.</p>
                ) : (
                  <div className="reports-table-wrap">
                    <Table className="min-w-[1120px] table-fixed">
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[160px]">Time</TableHead>
                          <TableHead className="w-[100px]">Severity</TableHead>
                          <TableHead className="w-[140px]">Source</TableHead>
                          <TableHead className="w-[140px]">Incident Type</TableHead>
                          <TableHead className="w-[220px]">Title</TableHead>
                          <TableHead className="w-[110px]">Status</TableHead>
                          <TableHead className="w-[140px]">Actor</TableHead>
                          <TableHead className="w-[250px]">Recommendation</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {incidentsSummary.recent_incidents.map((item) => (
                          <TableRow key={item.incident_id}>
                            <TableCell className="text-slate-400">{formatAdminPcapTime(item.timestamp)}</TableCell>
                            <TableCell><span className={riskBadgeClass(item.severity)}>{titleCase(item.severity)}</span></TableCell>
                            <TableCell className="text-slate-300">{titleCase(item.source)}</TableCell>
                            <TableCell className="text-slate-300">{titleCase(item.incident_type)}</TableCell>
                            <TableCell className="break-words text-white">{item.title}</TableCell>
                            <TableCell><span className={statusBadgeClass(item.status)}>{titleCase(item.status)}</span></TableCell>
                            <TableCell className="text-slate-300">{item.actor_display_name}</TableCell>
                            <TableCell className="break-words text-slate-300">{item.recommendation}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>
            </div>
          )}
        </Card>
        ) : activeReportModule === "highRisk" ? (
        <Card className="reports-table-card" id="high-risk-users-report">
          <div className="reports-card-head">
            <div>
              <h2>High-Risk Users Report</h2>
              <p>Safe aggregate ranking from password, identity, PCAP, notification, authentication, and activity risk signals.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{formatNumber(highRiskSummary.top_risk_users.length)} users</Badge>
          </div>
          {highRiskLoading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading High-Risk Users Report...
            </div>
          ) : (
            <div className="reports-evidence-list">
              <div className="reports-summary-grid">
                <div className="reports-summary-item"><span>Users Evaluated</span><strong>{formatNumber(highRiskSummary.summary.total_users_evaluated)}</strong></div>
                <div className="reports-summary-item"><span>Critical Users</span><strong>{formatNumber(highRiskSummary.summary.critical_risk_users)}</strong></div>
                <div className="reports-summary-item"><span>High-Risk Users</span><strong>{formatNumber(highRiskSummary.summary.high_risk_users)}</strong></div>
                <div className="reports-summary-item"><span>Medium Users</span><strong>{formatNumber(highRiskSummary.summary.medium_risk_users)}</strong></div>
                <div className="reports-summary-item"><span>Total Signals</span><strong>{formatNumber(highRiskSummary.summary.total_risk_signals)}</strong></div>
                <div className="reports-summary-item"><span>Latest Signal</span><strong>{formatAdminPcapTime(highRiskSummary.summary.latest_risk_signal_timestamp)}</strong></div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Risk Level Distribution</h3>
                  <Badge className="reports-badge reports-badge-blue">Safe scores</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(highRiskSummary.risk_level_distribution).map(([level, count]) => (
                    <div key={level} className="reports-summary-item"><span>{titleCase(level)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Module Signal Distribution</h3>
                  <Badge className="reports-badge reports-badge-success">Aggregate only</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(highRiskSummary.module_signal_distribution).map(([module, count]) => (
                    <div key={module} className="reports-summary-item"><span>{titleCase(module)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>High-Risk Users</h3>
                  <Badge className="reports-badge reports-badge-blue">{highRiskSummary.top_risk_users.length} rows</Badge>
                </div>
                {highRiskSummary.top_risk_users.length === 0 ? (
                  <p className="text-sm text-slate-300">No high-risk users were found for this filter set.</p>
                ) : (
                  <div className="reports-table-wrap">
                    <Table className="min-w-[980px] table-fixed">
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[180px]">User</TableHead>
                          <TableHead className="w-[90px]">Role</TableHead>
                          <TableHead className="w-[100px]">Risk Score</TableHead>
                          <TableHead className="w-[110px]">Risk Level</TableHead>
                          <TableHead className="w-[150px]">Main Risk Source</TableHead>
                          <TableHead className="w-[90px]">Signals</TableHead>
                          <TableHead className="w-[170px]">Latest Signal</TableHead>
                          <TableHead className="w-[240px]">Recommendation</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {highRiskSummary.top_risk_users.map((item) => (
                          <TableRow key={`${item.actor_role}-${item.user_id}`}>
                            <TableCell className="text-white">{item.actor_display_name}</TableCell>
                            <TableCell><span className="reports-badge reports-badge-muted">{titleCase(item.actor_role)}</span></TableCell>
                            <TableCell className="text-slate-300">{formatNumber(item.risk_score)}</TableCell>
                            <TableCell><span className={riskBadgeClass(item.risk_level)}>{titleCase(item.risk_level)}</span></TableCell>
                            <TableCell className="text-slate-300">{titleCase(item.top_risk_source)}</TableCell>
                            <TableCell className="text-slate-300">{formatNumber(item.total_signals)}</TableCell>
                            <TableCell className="text-slate-400">{formatAdminPcapTime(item.latest_signal_timestamp)}</TableCell>
                            <TableCell className="break-words text-slate-300">{item.safe_recommendation}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>
            </div>
          )}
        </Card>

        ) : activeReportModule === "vault" ? (
        <Card className="reports-table-card" id="file-vault-activity-report">
          <div className="reports-card-head">
            <div>
              <h2>File Vault Activity Summary</h2>
              <p>Safe aggregate report from Encrypted File Vault documents and vault activity logs. File contents, hashes, salts, and encryption keys are not exposed.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{formatNumber(vaultSummary.summary.total_documents)} documents</Badge>
          </div>
          {vaultLoading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading File Vault Activity Summary...
            </div>
          ) : vaultSummary.empty ? (
            <div className="reports-evidence-list">
              <div className="reports-empty-state">
                <FolderLock className="h-6 w-6" />
                No vault activity yet. Upload or use a vault file to populate this report.
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Minimum Data Needed</h3>
                  <Badge className="reports-badge reports-badge-blue">Next step</Badge>
                </div>
                <div className="reports-summary-grid">
                  <div className="reports-summary-item">
                    <span>Start</span>
                    <strong>Upload an encrypted vault file</strong>
                  </div>
                  <div className="reports-summary-item">
                    <span>Then</span>
                    <strong>Download, delete, or verify integrity</strong>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="reports-evidence-list">
              <div className="reports-summary-grid">
                <div className="reports-summary-item"><span>Total Documents</span><strong>{formatNumber(vaultSummary.summary.total_documents)}</strong></div>
                <div className="reports-summary-item"><span>Uploaded</span><strong>{formatNumber(vaultSummary.summary.documents_uploaded)}</strong></div>
                <div className="reports-summary-item"><span>Downloads</span><strong>{formatNumber(vaultSummary.summary.download_events)}</strong></div>
                <div className="reports-summary-item"><span>Deletes</span><strong>{formatNumber(vaultSummary.summary.delete_events)}</strong></div>
                <div className="reports-summary-item"><span>Failed Access</span><strong>{formatNumber(vaultSummary.summary.wrong_password_events + vaultSummary.summary.access_denied_events)}</strong></div>
                <div className="reports-summary-item"><span>Integrity Failures</span><strong>{formatNumber(vaultSummary.summary.integrity_failures)}</strong></div>
                <div className="reports-summary-item"><span>Offline Enabled</span><strong>{formatNumber(vaultSummary.summary.offline_enabled_documents)}</strong></div>
                <div className="reports-summary-item"><span>Latest Activity</span><strong>{formatAdminPcapTime(vaultSummary.summary.latest_activity_at)}</strong></div>
              </div>

              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Action Distribution</h3>
                  <Badge className="reports-badge reports-badge-success">Real vault logs</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.keys(filteredVaultActionDistribution).length === 0 ? (
                    <div className="reports-summary-item"><span>Vault Actions</span><strong>No activity data for selected filters</strong></div>
                  ) : Object.entries(filteredVaultActionDistribution).map(([action, count]) => (
                    <div key={action} className="reports-summary-item"><span>{titleCase(action)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>

              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Recent Vault Activity</h3>
                  <Badge className="reports-badge reports-badge-blue">{filteredVaultRecentActivity.length} items</Badge>
                </div>
                {filteredVaultRecentActivity.length === 0 ? (
                  <p className="text-sm text-slate-300">No recent vault activity is available.</p>
                ) : (
                  <div className="reports-table-wrap">
                    <Table className="min-w-[900px] table-fixed">
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[180px]">Timestamp</TableHead>
                          <TableHead className="w-[150px]">Action</TableHead>
                          <TableHead className="w-[110px]">Status</TableHead>
                          <TableHead className="w-[110px]">Severity</TableHead>
                          <TableHead className="w-[240px]">Target</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredVaultRecentActivity.map((item, index) => (
                          <TableRow key={`${item.timestamp}-${item.action_type}-${index}`}>
                            <TableCell className="text-slate-400">{formatAdminPcapTime(item.timestamp)}</TableCell>
                            <TableCell className="text-white">{item.action}</TableCell>
                            <TableCell><span className={statusBadgeClass(item.status)}>{titleCase(item.status)}</span></TableCell>
                            <TableCell><span className={riskBadgeClass(item.severity)}>{titleCase(item.severity)}</span></TableCell>
                            <TableCell className="break-words text-slate-300">{item.target_label || "Aggregate vault event"}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>

              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Recommendations</h3>
                  <Badge className="reports-badge reports-badge-blue">{vaultSummary.recommendations.length} items</Badge>
                </div>
                <div className="space-y-2">
                  {vaultSummary.recommendations.map((item) => (
                    <p key={item} className="text-sm text-slate-300">- {item}</p>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>
        ) : activeReportModule === "activity" ? (
        <Card className="reports-table-card" id="user-activity-report">
          <div className="reports-card-head">
            <div>
              <h2>User Activity Report</h2>
              <p>Safe aggregate activity report across authenticated user actions, admin audit events, module usage, and report exports.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{formatNumber(activitySummary.summary.total_activity_events)} events</Badge>
          </div>
          {activityLoading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading User Activity Report...
            </div>
          ) : activitySummary.empty ? (
            <div className="reports-empty-state">
              <Users className="h-6 w-6" />
              No user activity data is available for this period.
            </div>
          ) : (
            <div className="reports-evidence-list">
              <div className="reports-summary-grid">
                <div className="reports-summary-item"><span>Total Events</span><strong>{formatNumber(activitySummary.summary.total_activity_events)}</strong></div>
                <div className="reports-summary-item"><span>Unique Actors</span><strong>{formatNumber(activitySummary.summary.unique_actors)}</strong></div>
                <div className="reports-summary-item"><span>Active Users</span><strong>{formatNumber(activitySummary.summary.active_users)}</strong></div>
                <div className="reports-summary-item"><span>Active Admins</span><strong>{formatNumber(activitySummary.summary.active_admins)}</strong></div>
                <div className="reports-summary-item"><span>Exports / Downloads</span><strong>{formatNumber(activitySummary.summary.total_exports)}</strong></div>
                <div className="reports-summary-item"><span>Latest Activity</span><strong>{formatAdminPcapTime(activitySummary.summary.latest_activity_at)}</strong></div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Activity Type Distribution</h3>
                  <Badge className="reports-badge reports-badge-success">Aggregate only</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.keys(activitySummary.activity_type_distribution).length === 0 ? (
                    <div className="reports-summary-item"><span>Activity Types</span><strong>No activity data</strong></div>
                  ) : Object.entries(activitySummary.activity_type_distribution).map(([type, count]) => (
                    <div key={type} className="reports-summary-item"><span>{titleCase(type)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Role Distribution</h3>
                  <Badge className="reports-badge reports-badge-blue">Safe actors</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(activitySummary.role_distribution).map(([role, count]) => (
                    <div key={role} className="reports-summary-item"><span>{titleCase(role)}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Module / Source Distribution</h3>
                  <Badge className="reports-badge reports-badge-blue">Real records</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(activitySummary.module_distribution).map(([module, count]) => (
                    <div key={module} className="reports-summary-item"><span>{module}</span><strong>{formatNumber(count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Timeline</h3>
                  <Badge className="reports-badge reports-badge-blue">{activitySummary.timeline.length} days</Badge>
                </div>
                <div className="reports-summary-grid">
                  {activitySummary.timeline.slice(-8).map((item) => (
                    <div key={item.date} className="reports-summary-item"><span>{item.date}</span><strong>{formatNumber(item.count)}</strong></div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Recent Safe Activity</h3>
                  <Badge className="reports-badge reports-badge-blue">{activitySummary.recent_activity.length} items</Badge>
                </div>
                {activitySummary.recent_activity.length === 0 ? (
                  <p className="text-sm text-slate-300">No recent safe activity is available for this filter set.</p>
                ) : (
                  <div className="reports-table-wrap">
                    <Table className="min-w-[980px] table-fixed">
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[180px]">Timestamp</TableHead>
                          <TableHead className="w-[140px]">Actor</TableHead>
                          <TableHead className="w-[100px]">Role</TableHead>
                          <TableHead className="w-[180px]">Module</TableHead>
                          <TableHead className="w-[140px]">Type</TableHead>
                          <TableHead className="w-[220px]">Action</TableHead>
                          <TableHead className="w-[110px]">Status</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {activitySummary.recent_activity.map((item, index) => (
                          <TableRow key={`${item.timestamp}-${index}`}>
                            <TableCell className="text-slate-400">{formatAdminPcapTime(item.timestamp)}</TableCell>
                            <TableCell className="text-slate-300">{item.actor_display_name || item.actor}</TableCell>
                            <TableCell><span className="reports-badge reports-badge-muted">{titleCase(item.role)}</span></TableCell>
                            <TableCell className="text-slate-300">{item.module}</TableCell>
                            <TableCell className="text-slate-300">{titleCase(item.activity_type)}</TableCell>
                            <TableCell className="break-words text-white">{item.action}</TableCell>
                            <TableCell><span className={statusBadgeClass(item.status)}>{titleCase(item.status)}</span></TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>
            </div>
          )}
        </Card>
        ) : activeReportModule === "monthly" ? (
        <Card className="reports-table-card" id="monthly-security-report">
          <div className="reports-card-head">
            <div>
              <h2>Monthly Security Report</h2>
              <p>Current-month safe aggregate report across available security records. Sensitive payloads are not included.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{formatNumber(monthlySummary.summary.total_events)} events</Badge>
          </div>
          {monthlyLoading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading Monthly Security Report...
            </div>
          ) : monthlySummary.empty && !monthlyCoverageHasData ? (
            <div className="reports-empty-state">
              <Calendar className="h-6 w-6" />
              No monthly security data is available yet. Run security checks and generate alerts to populate this report.
            </div>
          ) : (
            <div className="reports-evidence-list">
              <div className="reports-summary-grid">
                <div className="reports-summary-item"><span>Total Events</span><strong>{formatNumber(monthlySummary.summary.total_events)}</strong></div>
                <div className="reports-summary-item"><span>Critical</span><strong>{formatNumber(monthlySummary.summary.critical)}</strong></div>
                <div className="reports-summary-item"><span>High</span><strong>{formatNumber(monthlySummary.summary.high)}</strong></div>
                <div className="reports-summary-item"><span>Medium</span><strong>{formatNumber(monthlySummary.summary.medium)}</strong></div>
                <div className="reports-summary-item"><span>Low</span><strong>{formatNumber(monthlySummary.summary.low)}</strong></div>
                <div className="reports-summary-item"><span>Generated</span><strong>{formatAdminPcapTime(monthlySummary.generated_at)}</strong></div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Module Distribution</h3>
                  <Badge className="reports-badge reports-badge-success">Aggregate only</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.keys(monthlySummary.module_distribution).length === 0 ? (
                    <div className="reports-summary-item"><span>Modules</span><strong>No module data yet</strong></div>
                  ) : (
                    Object.entries(monthlySummary.module_distribution).map(([module, count]) => (
                      <div key={module} className="reports-summary-item">
                        <span>{module}</span>
                        <strong>{formatNumber(count)}</strong>
                      </div>
                    ))
                  )}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Severity Distribution</h3>
                  <Badge className="reports-badge reports-badge-blue">Current month</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.entries(monthlySummary.severity_distribution).map(([severity, count]) => (
                    <div key={severity} className="reports-summary-item">
                      <span>{titleCase(severity)}</span>
                      <strong>{formatNumber(count)}</strong>
                    </div>
                  ))}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Password Summary</h3>
                  <Badge className="reports-badge reports-badge-blue">Safe aggregates</Badge>
                </div>
                <div className="reports-summary-grid">
                  <div className="reports-summary-item"><span>Password Checks</span><strong>{formatNumber(monthlySummary.password_summary.password_checks)}</strong></div>
                  <div className="reports-summary-item"><span>Breached Findings</span><strong>{formatNumber(monthlySummary.password_summary.breached_findings)}</strong></div>
                  <div className="reports-summary-item"><span>Weak Findings</span><strong>{formatNumber(monthlySummary.password_summary.weak_findings)}</strong></div>
                  <div className="reports-summary-item"><span>Strong Safe Checks</span><strong>{formatNumber(monthlySummary.password_summary.strong_safe_checks)}</strong></div>
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Identity Summary</h3>
                  <Badge className="reports-badge reports-badge-blue">Safe aggregates</Badge>
                </div>
                <div className="reports-summary-grid">
                  <div className="reports-summary-item"><span>Identity Scans</span><strong>{formatNumber(monthlySummary.identity_summary.identity_scans)}</strong></div>
                  <div className="reports-summary-item"><span>Exposure Findings</span><strong>{formatNumber(monthlySummary.identity_summary.identity_exposure_findings)}</strong></div>
                  <div className="reports-summary-item"><span>High-Risk Exposures</span><strong>{formatNumber(monthlySummary.identity_summary.high_risk_exposures)}</strong></div>
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Module Activity / Coverage Summary</h3>
                  <Badge className="reports-badge reports-badge-blue">Coverage only</Badge>
                </div>
                <div className="reports-summary-grid">
                  <div className="reports-summary-item"><span>PCAP Analyses Run</span><strong>{formatNumber(monthlySummary.module_activity_summary.pcap_analyses_run)}</strong></div>
                  <div className="reports-summary-item"><span>PCAP Completed</span><strong>{formatNumber(monthlySummary.module_activity_summary.pcap_completed)}</strong></div>
                  <div className="reports-summary-item"><span>PCAP Failed</span><strong>{formatNumber(monthlySummary.module_activity_summary.pcap_failed)}</strong></div>
                  <div className="reports-summary-item"><span>PCAP Clean Analyses</span><strong>{formatNumber(monthlySummary.module_activity_summary.pcap_clean_analyses)}</strong></div>
                  <div className="reports-summary-item"><span>PCAP Alerts Generated</span><strong>{formatNumber(monthlySummary.module_activity_summary.pcap_alerts_generated)}</strong></div>
                  <div className="reports-summary-item"><span>Identity Scans Run</span><strong>{formatNumber(monthlySummary.module_activity_summary.identity_scans_run)}</strong></div>
                  <div className="reports-summary-item"><span>Identity Findings</span><strong>{formatNumber(monthlySummary.module_activity_summary.identity_findings_found)}</strong></div>
                  <div className="reports-summary-item"><span>Password Checks Run</span><strong>{formatNumber(monthlySummary.module_activity_summary.password_checks_run)}</strong></div>
                  <div className="reports-summary-item"><span>Password Breached Results</span><strong>{formatNumber(monthlySummary.module_activity_summary.password_breached_results)}</strong></div>
                  <div className="reports-summary-item"><span>Notifications Created</span><strong>{formatNumber(monthlySummary.module_activity_summary.notifications_created)}</strong></div>
                  <div className="reports-summary-item"><span>Admin Audit Events</span><strong>{formatNumber(monthlySummary.module_activity_summary.admin_audit_events)}</strong></div>
                  <div className="reports-summary-item"><span>User Activity Events</span><strong>{formatNumber(monthlySummary.module_activity_summary.user_activity_events)}</strong></div>
                  <div className="reports-summary-item"><span>Latest Activity</span><strong>{formatAdminPcapTime(monthlySummary.module_activity_summary.latest_activity_timestamp)}</strong></div>
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Top Risk Areas</h3>
                  <Badge className="reports-badge reports-badge-blue">{monthlySummary.top_risk_areas.length} items</Badge>
                </div>
                {monthlySummary.top_risk_areas.length === 0 ? (
                  <p className="text-sm text-slate-300">No repeated risk areas are available for this month yet.</p>
                ) : (
                  <div className="reports-summary-grid">
                    {monthlySummary.top_risk_areas.map((item) => (
                      <div key={item.title} className="reports-summary-item">
                        <span>{item.title}</span>
                        <strong>{formatNumber(item.count)}</strong>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Recommendations</h3>
                  <Badge className="reports-badge reports-badge-blue">{monthlySummary.recommendations.length} items</Badge>
                </div>
                <div className="space-y-2">
                  {monthlySummary.recommendations.map((item) => (
                    <p key={item} className="text-sm text-slate-300">- {item}</p>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>
        ) : activeReportModule === "phishing" ? (
        <Card className="reports-table-card" id="phishing-incidents-report">
          <div className="reports-card-head">
            <div>
              <h2>Recent Phishing Scanner Results</h2>
              <p>Latest phishing URL scans and export-ready incident summaries available to the admin workspace.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{formatNumber(phishingSummary.latest_scans.length)} results</Badge>
          </div>
          {phishingSummary.highest_risk_scan ? (
            <div className="reports-selected-report">
              <div><span>Selected Scan</span><strong>#{phishingSummary.highest_risk_scan.scan_id}</strong></div>
              <div><span>URL / Domain</span><strong>{phishingSummary.highest_risk_scan.domain || phishingSummary.highest_risk_scan.url}</strong></div>
              <div><span>Final Category</span><strong>{titleCase(phishingSummary.highest_risk_scan.final_category)}</strong></div>
              <div><span>Final Risk Score</span><strong>{phishingSummary.highest_risk_scan.final_risk_score}/100</strong></div>
              <div><span>Scanned</span><strong>{formatAdminPcapTime(phishingSummary.highest_risk_scan.timestamp)}</strong></div>
            </div>
          ) : null}
          {phishingLoading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading phishing scanner results...
            </div>
          ) : phishingSummary.latest_scans.length === 0 ? (
            <div className="reports-empty-state">
              <FileSearch className="h-6 w-6" />
              No phishing incidents available yet.
            </div>
          ) : (
            <div className="reports-evidence-list">
              <div className="reports-summary-grid">
                <div className="reports-summary-item"><span>Total URL Scans</span><strong>{formatNumber(phishingSummary.summary.total_url_scans)}</strong></div>
                <div className="reports-summary-item"><span>Safe URLs</span><strong>{formatNumber(phishingSummary.summary.safe_urls)}</strong></div>
                <div className="reports-summary-item"><span>Suspicious URLs</span><strong>{formatNumber(phishingSummary.summary.suspicious_urls)}</strong></div>
                <div className="reports-summary-item"><span>Dangerous URLs</span><strong>{formatNumber(phishingSummary.summary.dangerous_urls)}</strong></div>
                <div className="reports-summary-item"><span>Risky URLs</span><strong>{formatNumber(phishingSummary.summary.risky_urls)}</strong></div>
                <div className="reports-summary-item"><span>Average Risk Score</span><strong>{formatNumber(phishingSummary.summary.average_risk_score)}</strong></div>
                <div className="reports-summary-item"><span>VT Malicious Total</span><strong>{formatNumber(phishingSummary.summary.virustotal_malicious_total)}</strong></div>
                <div className="reports-summary-item"><span>VT Suspicious Total</span><strong>{formatNumber(phishingSummary.summary.virustotal_suspicious_total)}</strong></div>
              </div>
              <div className="reports-table-wrap">
                <Table className="min-w-[1100px] table-fixed">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[300px]">URL / Domain</TableHead>
                      <TableHead className="w-[130px]">Category</TableHead>
                      <TableHead className="w-[110px]">Risk Score</TableHead>
                      <TableHead className="w-[190px]">VirusTotal</TableHead>
                      <TableHead className="w-[160px]">Scanned At</TableHead>
                      <TableHead className="w-[130px]">ML Probability</TableHead>
                      <TableHead className="w-[100px]">Malicious</TableHead>
                      <TableHead className="w-[100px]">Suspicious</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {phishingSummary.latest_scans.map((item) => (
                      <TableRow key={`${item.scan_id}-${item.timestamp || item.url}`}>
                        <TableCell className="break-words font-medium text-white">
                          {item.url}
                          <div className="text-xs text-slate-400">{item.domain || "Unknown domain"}</div>
                        </TableCell>
                        <TableCell><span className={riskBadgeClass(item.risk_level)}>{titleCase(item.final_category)}</span></TableCell>
                        <TableCell className="font-semibold text-white">{item.final_risk_score}/100</TableCell>
                        <TableCell className="text-slate-300">{titleCase(item.virustotal_status)} ({item.virustotal_malicious} malicious / {item.virustotal_suspicious} suspicious)</TableCell>
                        <TableCell className="text-slate-400">{formatAdminPcapTime(item.timestamp)}</TableCell>
                        <TableCell className="text-slate-300">{item.ml_probability ?? "N/A"}</TableCell>
                        <TableCell className="text-slate-300">{formatNumber(item.virustotal_malicious)}</TableCell>
                        <TableCell className="text-slate-300">{formatNumber(item.virustotal_suspicious)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Recommendations</h3>
                  <Badge className="reports-badge reports-badge-blue">{phishingSummary.recommendations.length} items</Badge>
                </div>
                <div className="space-y-2">
                  {phishingSummary.recommendations.map((item) => (
                    <p key={item} className="text-sm text-slate-300">- {item}</p>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>
        ) : activeReportModule === "password" ? (
        <Card className="reports-table-card" id="password-risk-report">
          <div className="reports-card-head">
            <div>
              <h2>Password Risk Summary</h2>
              <p>Safe aggregate report from Password Checker checks. Raw passwords, hashes, and user-entered text are not included.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{formatNumber(passwordSummary.summary.total_checks)} checks</Badge>
          </div>
          {passwordLoading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading Password Risk Summary...
            </div>
          ) : !passwordHasData ? (
            <div className="reports-empty-state">
              <KeyRound className="h-6 w-6" />
              No password risk data is available yet. Run password checks to populate this report.
            </div>
          ) : (
            <div className="reports-evidence-list">
              <div className="reports-summary-grid">
                {Object.entries(passwordSummary.risk_distribution).map(([risk, count]) => (
                  <div key={risk} className="reports-summary-item">
                    <span>{titleCase(risk)} Risk</span>
                    <strong>{formatNumber(count)}</strong>
                  </div>
                ))}
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Strength Distribution</h3>
                  <Badge className="reports-badge reports-badge-success">Aggregate only</Badge>
                </div>
                <div className="reports-summary-grid">
                  {Object.keys(passwordSummary.strength_distribution).length === 0 ? (
                    <div className="reports-summary-item">
                      <span>Strength Labels</span>
                      <strong>No labels yet</strong>
                    </div>
                  ) : (
                    Object.entries(passwordSummary.strength_distribution).map(([label, count]) => (
                      <div key={label} className="reports-summary-item">
                        <span>{label}</span>
                        <strong>{formatNumber(count)}</strong>
                      </div>
                    ))
                  )}
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Breach Summary</h3>
                  <Badge className={passwordSummary.breach_summary.total_breached_results > 0 ? "reports-badge reports-badge-danger" : "reports-badge reports-badge-success"}>
                    {passwordSummary.breach_summary.total_breached_results > 0 ? "Exposure found" : "No exposure"}
                  </Badge>
                </div>
                <div className="reports-summary-grid">
                  <div className="reports-summary-item"><span>Total Breached Results</span><strong>{formatNumber(passwordSummary.breach_summary.total_breached_results)}</strong></div>
                  <div className="reports-summary-item"><span>Total Exposure Count</span><strong>{formatNumber(passwordSummary.breach_summary.total_exposure_count)}</strong></div>
                  <div className="reports-summary-item"><span>Average Breach Count</span><strong>{formatNumber(passwordSummary.breach_summary.average_breach_count)}</strong></div>
                  <div className="reports-summary-item"><span>Latest Check</span><strong>{formatAdminPcapTime(passwordSummary.summary.latest_check_at)}</strong></div>
                </div>
              </div>
              <div className="reports-evidence-card">
                <div className="reports-active-title-row">
                  <h3>Recommendations</h3>
                  <Badge className="reports-badge reports-badge-blue">{passwordSummary.recommendations.length} items</Badge>
                </div>
                <div className="space-y-2">
                  {passwordSummary.recommendations.map((item) => (
                    <p key={item} className="text-sm text-slate-300">- {item}</p>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>
        ) : activeReportModule === "identity" ? (
        <Card className="reports-table-card" id="recent-identity-reports">
          <div className="reports-card-head">
            <div>
              <h2>Recent Identity Leak Reports</h2>
              <p>Recent scan summaries from Identity Leak Monitor with masked identifiers and safe evidence.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{identityReports.length} results</Badge>
          </div>
          {selectedIdentityReport ? (
            <div className="reports-selected-report">
              <div><span>Selected Scan</span><strong>#{selectedIdentityReport.scan_id}</strong></div>
              <div><span>Masked Identifier</span><strong>{selectedIdentityReport.masked_identifier}</strong></div>
              <div><span>Risk Level</span><strong>{titleCase(selectedIdentityReport.risk_level)}</strong></div>
              <div><span>Generated</span><strong>{formatAdminPcapTime(selectedIdentityReport.generated_at)}</strong></div>
            </div>
          ) : null}
          {identityLoading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading identity reports...
            </div>
          ) : identityReports.length === 0 ? (
            <div className="reports-empty-state">
              <FileSearch className="h-6 w-6" />
              No Identity Leak reports match the current filters.
            </div>
          ) : (
            <div className="reports-table-wrap">
              <Table className="min-w-[1240px] table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[100px]">Scan ID</TableHead>
                    <TableHead className="w-[170px]">Masked Identifier</TableHead>
                    <TableHead className="w-[120px]">Status</TableHead>
                    <TableHead className="w-[120px]">Risk Level</TableHead>
                    <TableHead className="w-[110px]">Risk Score</TableHead>
                    <TableHead className="w-[130px]">Findings Count</TableHead>
                    <TableHead className="w-[180px]">Sources</TableHead>
                    <TableHead className="w-[160px]">Generated At</TableHead>
                    <TableHead className="w-[140px]">Report Available</TableHead>
                    <TableHead className="w-[170px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {identityReports.map((report) => (
                    <TableRow key={report.scan_id}>
                      <TableCell className="font-mono text-xs text-slate-400">#{report.scan_id}</TableCell>
                      <TableCell className="break-words font-medium text-white">{report.masked_identifier}</TableCell>
                      <TableCell><span className={statusBadgeClass(report.status)}>{titleCase(report.status)}</span></TableCell>
                      <TableCell><span className={riskBadgeClass(report.risk_level)}>{titleCase(report.risk_level)}</span></TableCell>
                      <TableCell className="font-semibold text-white">{report.risk_score}</TableCell>
                      <TableCell className="text-slate-300">{report.findings_count}</TableCell>
                      <TableCell className="break-words text-slate-300">{report.sources.join(" / ") || "No sources"}</TableCell>
                      <TableCell className="text-slate-400">{formatAdminPcapTime(report.generated_at)}</TableCell>
                      <TableCell>{availabilityBadge(report.report_available)}</TableCell>
                      <TableCell>
                        <div className="reports-row-actions">
                          <Button size="sm" variant="outline" title="View Evidence" onClick={() => { setSelectedIdentityReport(report); setSelectedIdentityEvidence(report); }}>
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button size="sm" variant="outline" title="Export Report PDF" disabled>
                            <FileDown className="h-4 w-4 text-red-300" />
                          </Button>
                          <Button size="sm" variant="outline" title="Export CSV" disabled={exporting !== null} onClick={() => void handleExport("identity", "csv")}>
                            <FileDown className="h-4 w-4 text-emerald-300" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Card>
        ) : (
        <Card className="reports-table-card" id="recent-pcap-reports">
          <div className="reports-card-head">
            <div>
              <h2>Recent PCAP Reports</h2>
              <p>Latest PCAP jobs and report artifacts available to the admin workspace.</p>
            </div>
            <Badge className="reports-badge reports-badge-blue">{reports.length} results</Badge>
          </div>
          {selectedReport ? (
            <div className="reports-selected-report">
              <div>
                <span>Selected Report</span>
                <strong>{selectedReport.file_name}</strong>
              </div>
              <div>
                <span>Job ID</span>
                <strong>{selectedReport.job_id}</strong>
              </div>
              <div>
                <span>Attack Family</span>
                <strong>{selectedReport.detected_attack_family}</strong>
              </div>
              <div>
                <span>Generated</span>
                <strong>{formatAdminPcapTime(selectedReport.generated_at)}</strong>
              </div>
            </div>
          ) : null}
          {loading ? (
            <div className="reports-empty-state">
              <Loader2 className="h-6 w-6 animate-spin" />
              Loading PCAP reports...
            </div>
          ) : reports.length === 0 ? (
            <div className="reports-empty-state">
              <FileSearch className="h-6 w-6" />
              No PCAP reports match the current filters.
            </div>
          ) : (
            <div className="reports-table-wrap">
              <Table className="min-w-[1160px] table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[190px]">File Name</TableHead>
                    <TableHead className="w-[150px]">Job ID</TableHead>
                    <TableHead className="w-[120px]">Status</TableHead>
                    <TableHead className="w-[120px]">Risk Level</TableHead>
                    <TableHead className="w-[180px]">Detected Attack Family</TableHead>
                    <TableHead className="w-[150px]">Analysis Mode</TableHead>
                    <TableHead className="w-[160px]">Generated At</TableHead>
                    <TableHead className="w-[140px]">Report Available</TableHead>
                    <TableHead className="w-[210px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reports.map((report) => (
                    <TableRow key={report.id}>
                      <TableCell className="break-words font-medium text-white">{report.file_name}</TableCell>
                      <TableCell className="font-mono text-xs text-slate-400">{report.job_id}</TableCell>
                      <TableCell><span className={statusBadgeClass(report.status)}>{titleCase(report.status)}</span></TableCell>
                      <TableCell><span className={riskBadgeClass(report.risk_level)}>{titleCase(report.risk_level)}</span></TableCell>
                      <TableCell className="break-words text-slate-300">{report.detected_attack_family}</TableCell>
                      <TableCell className="text-slate-300">{report.analysis_mode}</TableCell>
                      <TableCell className="text-slate-400">{formatAdminPcapTime(report.generated_at)}</TableCell>
                      <TableCell>{availabilityBadge(report.report_available)}</TableCell>
                      <TableCell>
                        <div className="reports-row-actions">
                          <Button size="sm" variant="outline" title="View" onClick={() => setSelectedReport(report)}>
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button size="sm" variant="outline" title="Download PDF" disabled={exporting !== null} onClick={() => void handleExport(report.id, "pdf")}>
                            <FileDown className="h-4 w-4 text-red-300" />
                          </Button>
                          <Button size="sm" variant="outline" title="Download CSV" disabled={exporting !== null} onClick={() => void handleExport(report.id, "csv")}>
                            <FileDown className="h-4 w-4 text-emerald-300" />
                          </Button>
                          <Button size="sm" variant="outline" title="Regenerate" disabled={regenerating === report.id} onClick={() => void handleRegenerate(report.id)}>
                            {regenerating === report.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCcw className="h-4 w-4" />}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Card>
        )}
      </div>
      {selectedIdentityEvidence ? (
        <div className="reports-modal-backdrop" role="dialog" aria-modal="true">
          <div className="reports-evidence-modal">
            <div className="reports-card-head">
              <div>
                <h2>Identity Evidence</h2>
                <p>Limited evidence view with private account details hidden.</p>
              </div>
              <Button variant="outline" className="reports-action-button" onClick={() => setSelectedIdentityEvidence(null)}>
                Close
              </Button>
            </div>
            <div className="reports-summary-grid">
              {[
                ["Scan ID", `#${selectedIdentityEvidence.scan_id}`],
                ["Masked Identifier", selectedIdentityEvidence.masked_identifier],
                ["Risk Score", `${selectedIdentityEvidence.risk_score}`],
                ["Severity", titleCase(selectedIdentityEvidence.risk_level)],
                ["Findings Count", formatNumber(selectedIdentityEvidence.findings_count)],
                ["Generated At", formatAdminPcapTime(selectedIdentityEvidence.generated_at)],
              ].map(([label, value]) => (
                <div key={label} className="reports-summary-item">
                  <span>{label}</span>
                  <strong>{value}</strong>
                </div>
              ))}
            </div>
            <div className="reports-evidence-list">
              {selectedIdentityEvidence.evidence.length === 0 ? (
                <div className="reports-empty-state">
                  <FileSearch className="h-6 w-6" />
                  No safe evidence snippets are available for this scan.
                </div>
              ) : (
                selectedIdentityEvidence.evidence.map((item: IdentityEvidenceItem, index) => (
                  <div key={`${item.source_name}-${index}`} className="reports-evidence-card">
                    <div className="reports-active-title-row">
                      <h3>{item.evidence_title}</h3>
                      <Badge className="reports-badge reports-badge-blue">{item.source_name}</Badge>
                    </div>
                    <p>{item.snippet || "No snippet available."}</p>
                    <div className="reports-summary-grid">
                      <div className="reports-summary-item"><span>URL</span><strong>{item.url || "Unavailable"}</strong></div>
                      <div className="reports-summary-item"><span>Query Triggered</span><strong>{item.query_triggered || "Hidden"}</strong></div>
                      <div className="reports-summary-item"><span>Match Reason</span><strong>{item.match_reason || "Public exposure signal"}</strong></div>
                      <div className="reports-summary-item"><span>Generated At</span><strong>{formatAdminPcapTime(item.generated_at)}</strong></div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
