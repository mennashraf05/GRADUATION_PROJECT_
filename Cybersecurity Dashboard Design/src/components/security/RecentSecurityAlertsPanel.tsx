import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "motion/react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Shield,
  ShieldAlert,
  Siren,
  Radar,
  Eye,
  Sparkles,
  Server,
  Trash2,
  X,
} from "lucide-react";

import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import { cn } from "../ui/utils";
import { useLanguage } from "../../contexts/LanguageContext";
import { playCriticalSound, playWarningSound } from "../../utils/soundNotifications";
import {
  type AlertSeverity,
  type DashboardPcapAlert,
  RECENT_PCAP_ALERT_EVENT,
  RECENT_PCAP_ALERT_CACHE_KEY,
  RECENT_PCAP_ALERT_UPDATED_AT_KEY,
  buildDashboardAlertsFromReport,
  formatRelativeTime,
  humanizeIndicatorLabel,
  isSummaryAnalysisResult as isSummaryAlertSummary,
  mergeDashboardAlerts,
  normalizeDashboardPcapAlert,
  parseTimestampEpoch,
  persistRecentPcapAlertCache,
  readRecentPcapAlertCache,
} from "../../utils/recentPcapAlerts";

const DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:5000";
const DEFAULT_EMPTY_MESSAGE = "No visible alerts";
const ALERT_LIMIT_OPTIONS = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
const ENABLE_PCAP_ALERTS_MOCK_FALLBACK =
  String(import.meta.env.VITE_ENABLE_PCAP_ALERTS_MOCK || "")
    .trim()
    .toLowerCase() === "true";

type AlertFeedMode = "live" | "notifications" | "sample" | "empty";

type LoadAlertsOptions = {
  showLoader?: boolean;
  preserveVisibleOnFallback?: boolean;
  retryCanonical?: boolean;
};

type NotificationAlertSeverity =
  | "info"
  | "success"
  | "warning"
  | "critical"
  | "error";

type NotificationAlertItem = {
  id: number | string;
  user_id?: number;
  type?: string;
  severity?: NotificationAlertSeverity | string | null;
  title?: string;
  message?: string;
  body?: string;
  job_id?: string | null;
  metadata?: Record<string, unknown>;
  is_read?: boolean;
  created_at?: string | null;
};

type VaultAiRiskItem = {
  id?: string;
  action_type?: string;
  type?: string;
  name?: string;
  title?: string;
  description?: string;
  message?: string;
  scope?: "user" | "file" | string;
  severity?: AlertSeverity | string;
  risk_score?: number;
  score?: number;
  count?: number;
  window_minutes?: number;
  target_label?: string | null;
  created_at?: string | null;
};

type IdentityAlertItem = {
  id?: number | string;
  scan_id?: number | string;
  module?: string;
  title?: string;
  message?: string;
  severity?: string;
  created_at?: string | null;
  user_id?: number;
  is_read?: boolean;
  email_status?: string;
};

type DashboardAlertWithSource = DashboardPcapAlert & {
  source_type?: string;
  vault_scope?: string;
  target_label?: string;
  risk_score?: number;
  count?: number;
  window_minutes?: number;
  identity_scan_id?: number;
  identity_email_status?: string;
};

type AlertVisual = {
  icon: React.ComponentType<{ className?: string }>;
  cardClass: string;
  iconWrapClass: string;
  iconClass: string;
  badgeClass: string;
  chipClass: string;
  timeClass: string;
  accentClass: string;
  glowClass: string;
  pulseClass?: string;
  label: string;
};

type FeedModeVisual = {
  label: string;
  badgeClass: string;
  dotClass: string;
};

type AlertMetadataItem = {
  label: string;
  value: string;
  monospace?: boolean;
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

const PCAP_ALERTS_API_BASE_CANDIDATES = (() => {
  const candidates: string[] = [];

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

  if (import.meta.env.DEV) {
    pushApiBase(candidates, "");
  }

  pushApiBase(candidates, DEFAULT_LOCAL_API_BASE);
  return candidates;
})();

const PCAP_ALERTS_PATH_CANDIDATES = ["/api/pcap/alerts", "/pcap/alerts"];
const PCAP_ALERTS_CLEAR_PATH_CANDIDATES = [
  "/api/pcap/alerts/clear",
  "/api/pcap/alerts/dismiss-visible",
  "/pcap/alerts/clear",
  "/pcap/alerts/dismiss-visible",
];
const JOB_HISTORY_PATH_CANDIDATES = ["/jobs", "/pcap/jobs"];

function buildJobStatusPath(jobId: string) {
  return `/job/${encodeURIComponent(jobId)}`;
}

const ALERT_VISUALS: Record<AlertSeverity, AlertVisual> = {
  normal: {
    icon: CheckCircle2,
    cardClass:
      "border-emerald-500/22 bg-emerald-500/[0.05] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] hover:border-emerald-400/32 hover:bg-emerald-500/[0.07]",
    iconWrapClass:
      "border-emerald-400/18 bg-emerald-500/10",
    iconClass: "text-emerald-100",
    badgeClass: "border-emerald-300/18 bg-emerald-400/12 text-emerald-50",
    chipClass:
      "border-emerald-300/12 bg-emerald-400/8 text-emerald-100/90 hover:bg-emerald-400/12",
    timeClass: "text-emerald-100/70",
    accentClass: "from-emerald-400 via-emerald-400 to-emerald-400/0",
    glowClass: "bg-transparent",
    label: "NORMAL",
  },
  low: {
    icon: Shield,
    cardClass:
      "border-cyan-500/22 bg-cyan-500/[0.05] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] hover:border-cyan-400/32 hover:bg-cyan-500/[0.07]",
    iconWrapClass:
      "border-cyan-400/18 bg-cyan-500/10",
    iconClass: "text-cyan-100",
    badgeClass: "border-cyan-300/18 bg-cyan-400/12 text-cyan-50",
    chipClass:
      "border-cyan-300/12 bg-cyan-400/8 text-cyan-100/90 hover:bg-cyan-400/12",
    timeClass: "text-cyan-100/70",
    accentClass: "from-cyan-400 via-cyan-400 to-cyan-400/0",
    glowClass: "bg-transparent",
    label: "LOW",
  },
  medium: {
    icon: AlertTriangle,
    cardClass:
      "border-amber-500/22 bg-amber-500/[0.05] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] hover:border-amber-400/32 hover:bg-amber-500/[0.07]",
    iconWrapClass:
      "border-amber-400/18 bg-amber-500/10",
    iconClass: "text-amber-100",
    badgeClass: "border-amber-300/18 bg-amber-400/12 text-amber-50",
    chipClass:
      "border-amber-300/12 bg-amber-400/8 text-amber-100/90 hover:bg-amber-400/12",
    timeClass: "text-amber-100/70",
    accentClass: "from-amber-400 via-amber-400 to-amber-400/0",
    glowClass: "bg-transparent",
    label: "MEDIUM",
  },
  high: {
    icon: ShieldAlert,
    cardClass:
      "border-red-500/22 bg-red-500/[0.05] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] hover:border-red-400/32 hover:bg-red-500/[0.07]",
    iconWrapClass:
      "border-red-400/18 bg-red-500/10",
    iconClass: "text-red-100",
    badgeClass: "border-red-300/18 bg-red-400/12 text-red-50",
    chipClass:
      "border-red-300/12 bg-red-400/8 text-red-100/90 hover:bg-red-400/12",
    timeClass: "text-red-100/70",
    accentClass: "from-red-400 via-red-400 to-red-400/0",
    glowClass: "bg-transparent",
    label: "HIGH",
  },
  critical: {
    icon: Siren,
    cardClass:
      "border-rose-500/24 bg-rose-500/[0.06] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] hover:border-rose-400/34 hover:bg-rose-500/[0.08]",
    iconWrapClass:
      "border-rose-400/20 bg-rose-500/12",
    iconClass: "text-rose-50",
    badgeClass: "border-rose-300/20 bg-rose-400/14 text-rose-50",
    chipClass:
      "border-rose-300/12 bg-rose-400/8 text-rose-50/90 hover:bg-rose-400/12",
    timeClass: "text-rose-50/74",
    accentClass: "from-rose-400 via-rose-400 to-rose-400/0",
    glowClass: "bg-transparent",
    pulseClass: "animate-pulse",
    label: "CRITICAL",
  },
};

const SUMMARY_RESULT_VISUAL: AlertVisual = {
  icon: Eye,
  cardClass:
    "border-sky-500/18 bg-[linear-gradient(180deg,rgba(8,20,40,0.96),rgba(8,18,35,0.92))] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] hover:border-sky-400/28 hover:bg-[linear-gradient(180deg,rgba(9,24,46,0.97),rgba(9,21,40,0.94))]",
  iconWrapClass: "border-sky-400/16 bg-sky-500/10",
  iconClass: "text-sky-100",
  badgeClass: "border-sky-300/18 bg-sky-400/12 text-sky-50",
  chipClass:
    "border-sky-300/12 bg-sky-400/8 text-sky-100/90 hover:bg-sky-400/12",
  timeClass: "text-sky-100/72",
  accentClass: "from-sky-400 via-sky-400 to-sky-400/0",
  glowClass: "bg-transparent",
  label: "RESULT",
};

const FEED_MODE_VISUALS: Record<AlertFeedMode, FeedModeVisual> = {
  live: {
    label: "Live feed",
    badgeClass: "border-cyan-400/18 bg-cyan-500/10 text-cyan-100",
    dotClass: "bg-cyan-300",
  },
  notifications: {
    label: "Analyst queue",
    badgeClass: "border-amber-400/18 bg-amber-500/10 text-amber-100",
    dotClass: "bg-amber-300",
  },
  sample: {
    label: "Sample data",
    badgeClass: "border-slate-300/15 bg-white/[0.05] text-slate-200",
    dotClass: "bg-slate-300",
  },
  empty: {
    label: "Monitoring idle",
    badgeClass: "border-white/10 bg-white/[0.04] text-slate-300",
    dotClass: "bg-slate-500",
  },
};

const DEFAULT_SECURE_FETCH_TIMEOUT_MS = 15000;

function buildCookieOnlyFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.delete("Authorization");
  return {
    ...init,
    credentials: "include",
    headers,
  };
}

function buildAuthedFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  const token = localStorage.getItem("sentinel_auth_token");
  if (token && token !== "cookie_based") {
    headers.set("Authorization", `Bearer ${token}`);
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
  timeoutMs: number = DEFAULT_SECURE_FETCH_TIMEOUT_MS
) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    window.clearTimeout(timer);
  }
}

async function fetchWithPcapAlertAuth(
  input: RequestInfo | URL,
  init: RequestInit = {}
) {
  const cookieResponse = await fetchWithTimeout(
    input,
    buildCookieOnlyFetchInit(init)
  );
  if (cookieResponse.status !== 401 && cookieResponse.status !== 403) {
    return cookieResponse;
  }

  const storedToken =
    typeof window !== "undefined"
      ? localStorage.getItem("sentinel_auth_token")
      : null;
  if (storedToken && storedToken !== "cookie_based") {
    return fetchWithTimeout(input, buildAuthedFetchInit(init));
  }

  return cookieResponse;
}

function buildApiUrl(path: string, base: string) {
  return base ? `${base}${path}` : path;
}

function logPcapAlertEndpointDiagnostic(
  action: string,
  url: string,
  response: Response,
  payload?: Record<string, unknown>
) {
  if (!import.meta.env.DEV) {
    return;
  }

  const contentType = String(response.headers.get("content-type") || "");
  const payloadKeys = payload ? Object.keys(payload).sort() : [];
  console.debug("[pcap-alerts]", action, {
    url,
    status: response.status,
    contentType,
    payloadKeys,
  });
}

function isPersistedPcapAlertId(value: unknown): value is string {
  return /^\d+$/.test(String(value || "").trim());
}

async function readJsonResponse(
  response: Response,
  fallbackMessage: string
): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!text.trim()) {
    return {};
  }

  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    throw new Error(fallbackMessage);
  }
}

function formatAbsoluteTime(value?: string | null) {
  if (!value) return "";
  const timestamp = parseTimestampEpoch(value);
  if (!timestamp) return value;
  return new Date(timestamp).toLocaleString();
}

function normalizeNotificationAlertSeverity(
  rawSeverity: NotificationAlertItem["severity"],
  rawType: string
): AlertSeverity {
  const severity = String(rawSeverity ?? "").trim().toLowerCase();
  const type = String(rawType || "").trim().toLowerCase();

  if (severity === "critical") return "critical";
  if (severity === "error") return "high";
  if (severity === "warning") return "medium";
  if (severity === "info") return "low";
  if (severity === "success") return "normal";

  if (type === "critical_detected") return "critical";
  if (type === "suspicious_detected") return "medium";
  if (type === "job_failed") return "high";
  return "low";
}

function normalizeNotificationAlert(
  raw: NotificationAlertItem,
  index: number
): DashboardPcapAlert | null {
  const metadata =
    raw.metadata && typeof raw.metadata === "object" ? raw.metadata : {};
  const notificationType = String(raw.type ?? "").trim().toLowerCase();
  const isThreatNotification =
    notificationType === "critical_detected" ||
    notificationType === "suspicious_detected";

  if (!isThreatNotification) {
    return null;
  }

  return normalizeDashboardPcapAlert(
    {
      id: String(raw.id ?? `notification-alert-${index}`),
      job_id: raw.job_id ?? null,
      type: "pcap_alert",
      status: raw.is_read ? "reviewed" : "new",
      title: String(raw.title ?? "PCAP security notification"),
      message: String(raw.message ?? raw.body ?? "PCAP activity requires review."),
      severity: normalizeNotificationAlertSeverity(raw.severity, notificationType),
      created_at: String(raw.created_at ?? ""),
      source_type: "notification",
      attack_type:
        metadata.top_attack_type != null
          ? String(metadata.top_attack_type)
          : undefined,
      protocol: metadata.protocol != null ? String(metadata.protocol) : undefined,
      src_ip:
        metadata.top_src_ip != null ? String(metadata.top_src_ip) : undefined,
      dst_ip:
        metadata.top_dst_ip != null ? String(metadata.top_dst_ip) : undefined,
      user_id:
        typeof raw.user_id === "number" && raw.user_id > 0
          ? raw.user_id
          : undefined,
    },
    index
  );
}

function buildMockPcapAlerts(): DashboardPcapAlert[] {
  const now = Date.now();
  return [
    normalizeDashboardPcapAlert(
      {
        id: "mock-pcap-1",
        type: "pcap_alert",
        title: "Potential SYN Flood Activity",
        message:
          "Repeated TCP connection attempts from 10.10.4.24 to 172.16.0.14 over TCP/443 were promoted for review at 91% confidence.",
        severity: "high",
        attack_type: "syn_flood",
        protocol: "TCP",
        src_ip: "10.10.4.24",
        dst_ip: "172.16.0.14",
        created_at: new Date(now - 4 * 60 * 1000).toISOString(),
        status: "new",
      },
      0
    ),
    normalizeDashboardPcapAlert(
      {
        id: "mock-pcap-2",
        type: "pcap_alert",
        title: "Suspicious Port Scan Detected",
        message:
          "Port scan indicators were observed from 192.168.8.19 to 10.0.2.44 across multiple service ports during the latest PCAP session.",
        severity: "medium",
        attack_type: "port_scan",
        protocol: "TCP",
        src_ip: "192.168.8.19",
        dst_ip: "10.0.2.44",
        created_at: new Date(now - 11 * 60 * 1000).toISOString(),
        status: "new",
      },
      1
    ),
    normalizeDashboardPcapAlert(
      {
        id: "mock-pcap-3",
        type: "pcap_alert",
        title: "Beaconing Behavior Observed",
        message:
          "Low-volume beaconing traffic was observed toward 45.12.88.19 over HTTPS and correlated with suspicious repeated sessions.",
        severity: "low",
        attack_type: "beaconing",
        protocol: "HTTPS",
        src_ip: "10.0.1.33",
        dst_ip: "45.12.88.19",
        created_at: new Date(now - 28 * 60 * 1000).toISOString(),
        status: "reviewed",
      },
      2
    ),
    normalizeDashboardPcapAlert(
      {
        id: "mock-pcap-4",
        type: "pcap_alert",
        title: "Possible Data Exfiltration Activity",
        message:
          "High-volume outbound traffic to 203.0.113.9 matched exfiltration heuristics and should be reviewed immediately.",
        severity: "critical",
        attack_type: "data_exfiltration",
        protocol: "TLS",
        src_ip: "10.0.3.12",
        dst_ip: "203.0.113.9",
        created_at: new Date(now - 54 * 60 * 1000).toISOString(),
        status: "new",
      },
      3
    ),
    normalizeDashboardPcapAlert(
      {
        id: "mock-pcap-5",
        type: "pcap_alert",
        title: "Suspicious Repeated Failed Connections",
        message:
          "Multiple failed connection attempts from 172.20.2.15 to 10.0.0.21 were promoted for investigation in the current PCAP session.",
        severity: "medium",
        attack_type: "failed_connections",
        protocol: "TCP",
        src_ip: "172.20.2.15",
        dst_ip: "10.0.0.21",
        created_at: new Date(now - 73 * 60 * 1000).toISOString(),
        status: "new",
      },
      4
    ),
  ];
}

async function fetchPcapAlerts(limit: number): Promise<DashboardPcapAlert[]> {
  let lastError: unknown = null;
  let sawInvalidHtmlResponse = false;

  for (const base of PCAP_ALERTS_API_BASE_CANDIDATES) {
    for (const path of PCAP_ALERTS_PATH_CANDIDATES) {
      try {
        const response = await fetchWithPcapAlertAuth(
          buildApiUrl(`${path}?limit=${limit}`, base),
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
          "PCAP alerts endpoint returned an invalid response."
        );

        if (!response.ok) {
          throw new Error(
            String(
              payload.error ||
                payload.message ||
                "Failed to load recent PCAP alerts."
            )
          );
        }

        const rawAlerts = Array.isArray(payload.alerts)
          ? (payload.alerts as Array<Record<string, unknown>>)
          : [];

        return mergeDashboardAlerts(
          rawAlerts.map((item, index) => normalizeDashboardPcapAlert(item, index)),
          [],
          limit
        );
      } catch (error) {
        lastError = error;
      }
    }
  }

  if (sawInvalidHtmlResponse) {
    throw new Error(
      "PCAP alerts endpoint returned an invalid response. Verify the dev proxy or backend URL."
    );
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("Failed to load recent PCAP alerts.");
}

async function dismissVisiblePcapAlerts(
  alertIds: string[] = [],
  options: { dismissAllVisible?: boolean } = {}
): Promise<number> {
  const dismissAllVisible = options.dismissAllVisible === true;
  const numericAlertIds = Array.from(
    new Set(
      alertIds
        .map((value) => String(value || "").trim())
        .filter((value) => /^\d+$/.test(value))
    )
  );
  if (!dismissAllVisible && numericAlertIds.length === 0) {
    throw new Error("No backend-managed alerts are available to clear.");
  }

  let lastError: unknown = null;
  let sawInvalidHtmlResponse = false;

  for (const base of PCAP_ALERTS_API_BASE_CANDIDATES) {
    for (const path of PCAP_ALERTS_CLEAR_PATH_CANDIDATES) {
      try {
        const endpointUrl = buildApiUrl(path, base);
        const response = await fetchWithPcapAlertAuth(endpointUrl, {
          method: "POST",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(
            dismissAllVisible
              ? { dismiss_all_visible: true }
              : { alert_ids: numericAlertIds }
          ),
        });
        const contentType = String(
          response.headers.get("content-type") || ""
        ).toLowerCase();

        if (contentType.includes("text/html")) {
          logPcapAlertEndpointDiagnostic("clear-non-json", endpointUrl, response);
          sawInvalidHtmlResponse = true;
          continue;
        }

        if (response.status === 404) {
          logPcapAlertEndpointDiagnostic("clear-not-found", endpointUrl, response);
          continue;
        }

        const payload = await readJsonResponse(
          response,
          "Clear alerts endpoint returned an invalid response."
        );
        logPcapAlertEndpointDiagnostic("clear-response", endpointUrl, response, payload);

        if (!response.ok) {
          if (response.status === 401 || response.status === 403) {
            throw new Error(
              String(
                payload.error ||
                  payload.message ||
                  "You are not allowed to clear these alerts. Please sign in again."
              )
            );
          }
          throw new Error(
            String(
              payload.error ||
                payload.message ||
                "Unable to clear visible alerts."
            )
          );
        }

        if (payload.ok !== true) {
          throw new Error("Unable to clear visible alerts.");
        }

        if (typeof payload.dismissed_count === "number") {
          return payload.dismissed_count;
        }

        if (typeof payload.message === "string" && payload.message.trim()) {
          return 0;
        }

        throw new Error("Clear alerts endpoint returned an invalid response.");
      } catch (error) {
        lastError = error;
        if (
          error instanceof Error &&
          !(
            error.name === "AbortError" ||
            /failed to fetch|network|load failed/i.test(error.message)
          )
        ) {
          throw error;
        }
      }
    }
  }

  if (sawInvalidHtmlResponse) {
    throw new Error(
      "Clear alerts endpoint returned an invalid response. Verify the dev proxy or backend URL."
    );
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("Unable to clear visible alerts.");
}

async function fetchNotificationBackfillAlerts(
  limit: number
): Promise<DashboardPcapAlert[]> {
  let lastError: unknown = null;
  let sawInvalidHtmlResponse = false;

  for (const base of PCAP_ALERTS_API_BASE_CANDIDATES) {
    try {
      const response = await fetchWithPcapAlertAuth(
        buildApiUrl(
          `/notifications?limit=${Math.max(limit * 4, 12)}&offset=0`,
          base
        ),
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

      const payload = await readJsonResponse(
        response,
        "Notifications endpoint returned an invalid response."
      );

      if (!response.ok) {
        throw new Error(
          String(
            payload.error ||
              payload.message ||
              "Failed to load PCAP notification alerts."
          )
        );
      }

      const notifications = Array.isArray(payload.notifications)
        ? (payload.notifications as NotificationAlertItem[])
        : [];

      return mergeDashboardAlerts(
        notifications
          .map((item, index) => normalizeNotificationAlert(item, index))
          .filter((item): item is DashboardPcapAlert => item !== null),
        [],
        limit
      );
    } catch (error) {
      lastError = error;
    }
  }

  if (sawInvalidHtmlResponse) {
    throw new Error(
      "Notifications endpoint returned an invalid response. Verify the dev proxy or backend URL."
    );
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("Failed to load PCAP notification alerts.");
}


function normalizeVaultSeverity(rawSeverity: unknown, riskScore: number): AlertSeverity {
  const severity = String(rawSeverity || "").trim().toLowerCase();

  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium" || severity === "warning") return "medium";
  if (severity === "low" || severity === "info") return "low";
  if (severity === "safe" || severity === "normal" || severity === "success") return "normal";

  if (riskScore >= 90) return "critical";
  if (riskScore >= 80) return "high";
  if (riskScore >= 60) return "medium";
  if (riskScore > 0) return "low";
  return "normal";
}

function normalizeIdentitySeverity(rawSeverity: unknown): AlertSeverity {
  const severity = String(rawSeverity || "").trim().toLowerCase();

  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium" || severity === "warning") return "medium";
  if (severity === "low" || severity === "info") return "low";
  if (severity === "safe" || severity === "normal" || severity === "success") return "normal";
  return "medium";
}

function vaultRiskTitle(item: VaultAiRiskItem) {
  const raw = [
    item.action_type,
    item.type,
    item.name,
    item.title,
    item.message,
    item.description,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (raw.includes("password") || raw.includes("wrong vault")) return "Wrong Password Attempts";
  if (raw.includes("download")) return "Download Activity";
  if (raw.includes("delete") || raw.includes("deletion")) return "File Deletion";
  if (raw.includes("offline")) return "Offline Access";

  return String(item.title || "Vault AI Risk");
}

function normalizeVaultAiAlert(
  raw: VaultAiRiskItem,
  index: number
): DashboardAlertWithSource {
  const riskScore = Math.max(0, Math.min(100, Number(raw.risk_score ?? raw.score ?? 0)));
  const severity = normalizeVaultSeverity(raw.severity, riskScore);
  const scope = String(raw.scope || "user").trim().toLowerCase();
  const target = String(raw.target_label || "").trim();
  const title = vaultRiskTitle(raw);
  const count = Number(raw.count ?? 1);
  const description =
    String(raw.message || raw.description || "").trim() ||
    `${scope === "file" ? "File-level" : "User-level"} vault risk detected.`;

  const normalized = normalizeDashboardPcapAlert(
    {
      id: String(raw.id || `vault-ai-alert-${index}`),
      type: "vault_ai_alert",
      status: "new",
      title,
      message: description,
      severity,
      created_at: String(raw.created_at || new Date().toISOString()),
      source_type: "vault_ai",
      attack_type: title,
      filename: target || undefined,
      threats_count: count,
      top_pattern: title,
    } as Record<string, unknown>,
    index
  ) as DashboardAlertWithSource;

  normalized.source_type = "vault_ai";
  normalized.vault_scope = scope;
  normalized.target_label = target;
  normalized.risk_score = riskScore;
  normalized.count = count;
  normalized.window_minutes = Number(raw.window_minutes ?? 60);

  return normalized;
}

async function fetchVaultAiAlerts(limit: number): Promise<DashboardAlertWithSource[]> {
  const response = await fetchWithPcapAlertAuth(
    buildApiUrl("/api/ai/vault/analyze", API_BASE_URL),
    {
      method: "POST",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  const contentType = String(response.headers.get("content-type") || "").toLowerCase();
  if (contentType.includes("text/html")) {
    throw new Error("Vault AI endpoint returned an invalid response.");
  }

  const payload = await readJsonResponse(
    response,
    "Vault AI endpoint returned an invalid response."
  );

  if (!response.ok) {
    throw new Error(
      String(payload.error || payload.message || "Failed to load Vault AI alerts.")
    );
  }

  const rawAlerts = Array.isArray(payload.active_risks)
    ? (payload.active_risks as VaultAiRiskItem[])
    : Array.isArray(payload.suspicious_patterns)
    ? (payload.suspicious_patterns as VaultAiRiskItem[])
    : Array.isArray(payload.patterns)
    ? (payload.patterns as VaultAiRiskItem[])
    : [];

  return rawAlerts
    .map((item, index) => normalizeVaultAiAlert(item, index))
    .filter((item) => item.severity !== "normal")
    .slice(0, limit);
}

function normalizeIdentityAlert(
  raw: IdentityAlertItem,
  index: number
): DashboardAlertWithSource {
  const scanId = Number(raw.scan_id ?? 0);
  const normalized = normalizeDashboardPcapAlert(
    {
      id: String(raw.id || `identity-alert-${index}`),
      job_id: null,
      type: "pcap_alert",
      status: raw.is_read ? "reviewed" : "new",
      title: String(raw.title || "Identity exposure detected"),
      message: String(raw.message || "Identity Leak Monitor generated an exposure alert."),
      severity: normalizeIdentitySeverity(raw.severity),
      created_at: String(raw.created_at || new Date().toISOString()),
      source_type: "identity",
      attack_type: "Identity Exposure",
      top_pattern: "Identity Exposure",
      user_id: typeof raw.user_id === "number" ? raw.user_id : undefined,
    } as Record<string, unknown>,
    index
  ) as DashboardAlertWithSource;

  normalized.source_type = "identity";
  normalized.identity_scan_id = Number.isFinite(scanId) && scanId > 0 ? scanId : undefined;
  normalized.identity_email_status = raw.email_status ? String(raw.email_status) : undefined;

  return normalized;
}

async function fetchIdentityAlerts(limit: number): Promise<DashboardAlertWithSource[]> {
  let lastError: unknown = null;
  let sawInvalidHtmlResponse = false;

  for (const base of PCAP_ALERTS_API_BASE_CANDIDATES) {
    try {
      const response = await fetchWithPcapAlertAuth(
        buildApiUrl(`/api/identity/alerts?limit=${limit}`, base),
        {
          cache: "no-store",
        }
      );
      const contentType = String(response.headers.get("content-type") || "").toLowerCase();

      if (contentType.includes("text/html")) {
        sawInvalidHtmlResponse = true;
        continue;
      }

      if (response.status === 404) {
        continue;
      }

      const payload = await readJsonResponse(
        response,
        "Identity alerts endpoint returned an invalid response."
      );

      if (!response.ok) {
        throw new Error(
          String(payload.error || payload.message || "Failed to load Identity alerts.")
        );
      }

      const rawAlerts = Array.isArray(payload.alerts)
        ? (payload.alerts as IdentityAlertItem[])
        : [];

      return rawAlerts
        .map((item, index) => normalizeIdentityAlert(item, index))
        .slice(0, limit);
    } catch (error) {
      lastError = error;
    }
  }

  if (sawInvalidHtmlResponse) {
    throw new Error("Identity alerts endpoint returned an invalid response.");
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("Failed to load Identity alerts.");
}

async function fetchRecentJobReportAlerts(
  limit: number
): Promise<DashboardPcapAlert[]> {
  let lastError: unknown = null;
  let sawInvalidHtmlResponse = false;

  for (const base of PCAP_ALERTS_API_BASE_CANDIDATES) {
    for (const path of JOB_HISTORY_PATH_CANDIDATES) {
      try {
        const response = await fetchWithPcapAlertAuth(
          buildApiUrl(`${path}?limit=${Math.max(limit * 3, 12)}`, base),
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

      const payload = await readJsonResponse(
        response,
        "PCAP job history endpoint returned an invalid response."
      );

      if (!response.ok) {
        if (
          response.status === 401 ||
          response.status === 403 ||
          response.status === 404
        ) {
          continue;
        }
        throw new Error(
          String(
            payload.error ||
              payload.message ||
              "Failed to load recent PCAP job history."
            )
          );
        }

        const jobs = Array.isArray(payload.jobs)
          ? (payload.jobs as Array<Record<string, unknown>>)
          : [];
        const completedJobs = jobs
          .filter(
            (job) =>
              String(job.status ?? "").trim().toLowerCase() === "done" &&
              job.report_available === true &&
              String(job.job_id ?? "").trim() !== ""
          )
          .slice(0, Math.max(limit, 3));

        let merged: DashboardPcapAlert[] = [];
        for (const job of completedJobs) {
          const jobId = String(job.job_id ?? "").trim();
          if (!jobId) {
            continue;
          }

          const jobResponse = await fetchWithPcapAlertAuth(
            buildApiUrl(buildJobStatusPath(jobId), base),
            {
              cache: "no-store",
            }
          );
          const jobContentType = String(
            jobResponse.headers.get("content-type") || ""
          ).toLowerCase();

          if (jobContentType.includes("text/html")) {
            sawInvalidHtmlResponse = true;
            continue;
          }

          const jobPayload = await readJsonResponse(
            jobResponse,
            "PCAP job details endpoint returned an invalid response."
          );

          if (!jobResponse.ok) {
            if (
              jobResponse.status === 401 ||
              jobResponse.status === 403 ||
              jobResponse.status === 404
            ) {
              continue;
            }
            continue;
          }

          const report =
            jobPayload.report &&
            typeof jobPayload.report === "object" &&
            !Array.isArray(jobPayload.report)
              ? (jobPayload.report as Record<string, unknown>)
              : null;

          if (!report) {
            continue;
          }

          const reportAlerts = buildDashboardAlertsFromReport(report, {
            jobId,
            uploadName: String(job.upload_name ?? ""),
            fallbackCreatedAt:
              jobPayload.finished_at ??
              jobPayload.started_at ??
              jobPayload.created_at ??
              null,
            maxItems: limit,
          });

          merged = mergeDashboardAlerts(merged, reportAlerts, limit);
          if (merged.length >= limit) {
            break;
          }
        }

        if (merged.length > 0) {
          return merged;
        }
      } catch (error) {
        lastError = error;
      }
    }
  }

  if (sawInvalidHtmlResponse) {
    throw new Error(
      "PCAP job report fallback returned an invalid response. Verify the dev proxy or backend URL."
    );
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("Failed to load fallback PCAP job alerts.");
}

function buildMetadataChips(alert: DashboardPcapAlert) {
  const chips: string[] = [];
  const summaryResult = isSummaryAnalysisResult(alert);
  const sourceType = String((alert as DashboardAlertWithSource).source_type || "").toLowerCase();

  if (sourceType === "vault_ai") {
    const vaultAlert = alert as DashboardAlertWithSource;
    chips.push(vaultAlert.vault_scope === "file" ? "File-level" : "User-level");
    if (vaultAlert.target_label) chips.push(vaultAlert.target_label);
    if (typeof vaultAlert.risk_score === "number") chips.push(`Risk ${vaultAlert.risk_score}/100`);
    if (typeof vaultAlert.count === "number") chips.push(`Count ${vaultAlert.count}`);
    return chips.slice(0, 4);
  }

  if (sourceType === "identity") {
    const identityAlert = alert as DashboardAlertWithSource;
    chips.push("Identity Leak Monitor");
    if (identityAlert.identity_scan_id) chips.push(`Scan #${identityAlert.identity_scan_id}`);
    if (identityAlert.identity_email_status) chips.push(`Email ${identityAlert.identity_email_status}`);
    chips.push(alert.severity);
    return chips.slice(0, 4);
  }

  if (sourceType === "password_checker") {
    chips.push("Password Checker");
    if (alert.risk_label) chips.push(formatPasswordAlertLabel(alert.risk_label));
    chips.push(alert.severity);
    return chips.slice(0, 4);
  }

  if (alert.attack_type && !summaryResult) {
    chips.push(alert.attack_type.replace(/[_-]+/g, " "));
  }

  if (alert.protocol) {
    chips.push(alert.protocol.toUpperCase());
  }

  if (alert.src_ip && alert.dst_ip) {
    chips.push(`${alert.src_ip} → ${alert.dst_ip}`);
  } else if (alert.src_ip) {
    chips.push(alert.src_ip);
  } else if (alert.dst_ip) {
    chips.push(alert.dst_ip);
  }

  if (summaryResult) {
    if (alert.flows_analyzed > 0) {
      chips.push(`${alert.flows_analyzed} flows`);
    }
    if (alert.threats_count > 0) {
      chips.push(`${alert.threats_count} findings`);
    }
    if (alert.filename) {
      chips.push(alert.filename);
    }
  }

  if (alert.job_id) {
    chips.push(`job ${alert.job_id}`);
  }

  return chips.slice(0, 4);
}

function buildAlertMetadataItems(alert: DashboardPcapAlert): AlertMetadataItem[] {
  const items: AlertMetadataItem[] = [];
  const summaryResult = isSummaryAnalysisResult(alert);
  const sourceType = String((alert as DashboardAlertWithSource).source_type || "").toLowerCase();

  if (sourceType === "vault_ai") {
    const vaultAlert = alert as DashboardAlertWithSource;

    items.push({
      label: "Scope",
      value: vaultAlert.vault_scope === "file" ? "File-level" : "User-level",
    });

    if (vaultAlert.target_label) {
      items.push({
        label: "Target",
        value: vaultAlert.target_label,
        monospace: true,
      });
    }

    if (typeof vaultAlert.risk_score === "number") {
      items.push({
        label: "Risk",
        value: `${vaultAlert.risk_score}/100`,
      });
    }

    if (typeof vaultAlert.count === "number") {
      items.push({
        label: "Count",
        value: String(vaultAlert.count),
      });
    }

    return items.slice(0, 4);
  }

  if (sourceType === "identity") {
    const identityAlert = alert as DashboardAlertWithSource;

    items.push({
      label: "Module",
      value: "Identity Leak Monitor",
    });

    if (identityAlert.identity_scan_id) {
      items.push({
        label: "Scan",
        value: `#${identityAlert.identity_scan_id}`,
        monospace: true,
      });
    }

    items.push({
      label: "Signal",
      value: "Exposure alert",
    });

    if (identityAlert.identity_email_status) {
      items.push({
        label: "Email",
        value: identityAlert.identity_email_status,
      });
    }

    return items.slice(0, 4);
  }

  if (sourceType === "password_checker") {
    items.push({
      label: "Module",
      value: "Password Checker",
    });

    items.push({
      label: "Category",
      value: "Passwords",
    });

    items.push({
      label: "Evidence",
      value: alert.severity === "critical" ? "Breach match" : "Password hygiene",
    });

    return items.slice(0, 4);
  }

  const routeLabel =
    alert.src_ip && alert.dst_ip
      ? `${alert.src_ip} -> ${alert.dst_ip}`
      : alert.src_ip || alert.dst_ip || "";

  if (summaryResult) {
    if (alert.flows_analyzed > 0) {
      items.push({
        label: "Scope",
        value: `${alert.flows_analyzed} flows reviewed`,
      });
    }

    if (alert.threats_count > 0) {
      items.push({
        label: "Findings",
        value: `${alert.threats_count} promoted finding${
          alert.threats_count === 1 ? "" : "s"
        }`,
      });
    }

    if (alert.filename) {
      items.push({
        label: "Capture",
        value: alert.filename,
        monospace: true,
      });
    }
  } else {
    if (alert.attack_type) {
      items.push({
        label: "Pattern",
        value: humanizeIndicatorLabel(alert.attack_type.replace(/[_-]+/g, " ")),
      });
    }

    if (alert.protocol) {
      items.push({
        label: "Protocol",
        value: alert.protocol.toUpperCase(),
      });
    }

    if (routeLabel) {
      items.push({
        label: "Path",
        value: routeLabel,
        monospace: true,
      });
    }
  }

  if (alert.job_id) {
    items.push({
      label: "Job",
      value: alert.job_id,
      monospace: true,
    });
  }

  return items.slice(0, 4);
}

function isSummaryAnalysisResult(alert: DashboardPcapAlert) {
  return isSummaryAlertSummary(alert);
}

function formatPasswordAlertLabel(value: unknown) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "passwords") return "Passwords";
  if (normalized === "password_checker") return "Password Checker";
  return String(value || "").trim();
}

function formatAlertStateLabel(status?: DashboardPcapAlert["status"]) {
  if (status === "reviewed") return "Reviewed";
  if (status === "new") return "New";
  return null;
}

function alertStateBadgeClass(status?: DashboardPcapAlert["status"]) {
  if (status === "reviewed") {
    return "border-white/10 bg-white/[0.05] text-slate-300";
  }

  return "border-sky-400/18 bg-sky-500/10 text-sky-100";
}

function alertSourceLabel(alert: DashboardPcapAlert) {
  const sourceType = String((alert as DashboardAlertWithSource).source_type || "").toLowerCase();
  if (sourceType === "vault_ai") return "VAULT AI";
  if (sourceType === "identity") return "IDENTITY";
  if (sourceType === "password_checker") return "PASSWORDS";
  if (sourceType === "notification") return "NOTIFICATION";
  return "PCAP";
}

function countBySeverity(alerts: DashboardPcapAlert[], severity: AlertSeverity) {
  return alerts.filter((alert) => alert.severity === severity).length;
}

function countNeedsAttention(alerts: DashboardPcapAlert[]) {
  return alerts.filter(
    (alert) =>
      alert.severity === "medium" ||
      alert.severity === "high" ||
      alert.severity === "critical"
  ).length;
}

function topAttackType(alerts: DashboardPcapAlert[]) {
  const counts = new Map<string, number>();

  for (const alert of alerts) {
    if (isSummaryAnalysisResult(alert)) {
      continue;
    }
    const key = String(alert.attack_type || "general").trim().toLowerCase();
    counts.set(key, (counts.get(key) || 0) + 1);
  }

  if (counts.size === 0) {
    return alerts.length > 0 ? "Analysis Result" : "n/a";
  }

  let topKey = "general";
  let topCount = 0;

  counts.forEach((value, key) => {
    if (value > topCount) {
      topKey = key;
      topCount = value;
    }
  });

  return humanizeIndicatorLabel(topKey);
}

function SummaryTile({
  icon: Icon,
  label,
  value,
  className,
  iconClassName,
  valueClassName,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
  className?: string;
  iconClassName?: string;
  valueClassName?: string;
}) {
  return (
    <div
      className={cn(
        "relative min-h-[92px] overflow-hidden rounded-2xl border bg-slate-950/35 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] backdrop-blur-sm",
        className
      )}
    >
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-200/18 to-transparent" />
      <div className="flex items-start gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04]">
          <Icon className={cn("h-4 w-4 text-slate-300", iconClassName)} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-[11px] font-semibold uppercase text-slate-400">
            {label}
          </div>
          <div className={cn("mt-2 truncate text-2xl font-semibold leading-7 text-white", valueClassName)}>
            {value}
          </div>
        </div>
      </div>
    </div>
  );
}
function analysisResultTileSpanClass(item: AlertMetadataItem, totalItems: number) {
  const label = item.label.trim().toLowerCase();

  if (label === "scope" || label === "flows" || label === "findings") {
    return "md:col-span-6";
  }

  if (label === "capture") {
    return "md:col-span-6";
  }

  if (label === "job" || label === "job id") {
    return "md:col-span-12";
  }

  if (totalItems === 1) {
    return "md:col-span-12";
  }

  if (totalItems === 2) {
    return "md:col-span-6";
  }

  return "md:col-span-6";
}
function AnalysisResultDetailTile({
  item,
  totalItems,
}: {
  item: AlertMetadataItem;
  totalItems: number;
}) {
  return (
    <div
      title={item.value}
      className={cn(
        "group/tile relative overflow-hidden rounded-[20px] border border-white/[0.05] bg-slate-950/24 px-4 py-3.5 transition-all duration-300 hover:border-sky-400/15 hover:bg-slate-950/34",
        analysisResultTileSpanClass(item, totalItems)
      )}
    >
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent opacity-70" />
      <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-400/78">
        {item.label}
      </div>
      <div
        className={cn(
          "mt-2.5 text-[14px] font-semibold leading-6 text-slate-100",
          item.monospace &&
            "font-mono text-[12.5px] leading-5 text-slate-300 [overflow-wrap:anywhere]"
        )}
      >
        {item.value}
      </div>
    </div>
  );
}

function AlertMetadataPills({
  alertId,
  items,
}: {
  alertId: string | number;
  items: AlertMetadataItem[];
}) {
  if (items.length === 0) {
    return null;
  }

  return (
    <div className="rsa-alert-chips">
      {items.map((item) => (
        <span
          key={`${alertId}-${item.label}-${item.value}`}
          title={item.value}
          className={cn(
            "rsa-alert-chip",
            item.monospace && "font-mono text-[10.5px]"
          )}
        >
          <span className="shrink-0 text-slate-500">{item.label}:</span>
          <span className="truncate text-slate-100">{item.value}</span>
        </span>
      ))}
    </div>
  );
}

function AlertFeedCard({
  alert,
  visual,
  Icon,
  metadataItems,
  stateLabel,
  summaryResult,
  clickableResult,
  clearingAlerts,
  language,
  onOpenResult,
  onDismiss,
}: {
  alert: DashboardPcapAlert;
  visual: AlertVisual;
  Icon: React.ComponentType<{ className?: string }>;
  metadataItems: AlertMetadataItem[];
  stateLabel: string | null;
  summaryResult: boolean;
  clickableResult: boolean;
  clearingAlerts: boolean;
  language: string;
  onOpenResult: (alert: DashboardPcapAlert) => void;
  onDismiss: (alert: DashboardPcapAlert) => void;
}) {
  const sourceLabel = summaryResult
    ? language === "arabic"
      ? "نتيجة التحليل"
      : "Analysis Result"
    : alertSourceLabel(alert);

  return (
    <div className="relative z-10 w-full min-w-0">
      <div className="grid w-full min-w-0 grid-cols-1 gap-4 lg:grid-cols-[64px_minmax(0,1fr)_auto] lg:items-start">
      <div
        className={cn(
          "flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl border shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]",
          visual.iconWrapClass
        )}
      >
        <Icon
          className={cn(
            "h-7 w-7",
            visual.iconClass,
            alert.severity === "critical" ? visual.pulseClass : ""
          )}
        />
      </div>

      <div className="min-w-0 space-y-3">
        <div className="space-y-3">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              {stateLabel ? (
                <span
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] font-semibold uppercase",
                    alertStateBadgeClass(alert.status)
                  )}
                >
                  {stateLabel}
                </span>
              ) : null}

              <span className="rounded-full border border-white/10 bg-slate-950/35 px-3 py-1 text-[11px] font-semibold uppercase text-slate-300">
                {sourceLabel}
              </span>
            </div>

            <div className="text-lg font-semibold leading-6 text-white">
              {alert.title}
            </div>
            <div className="max-w-[78ch] text-sm leading-6 text-slate-300">
              {alert.message}
            </div>
          </div>

          <div className="flex shrink-0 flex-wrap items-center gap-2 lg:hidden">
            {summaryResult && alert.job_id ? (
              <button
                type="button"
                className={cn(
                  "inline-flex h-9 items-center justify-center rounded-full border px-3 text-[11px] font-semibold uppercase transition-all duration-200 hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/40",
                  visual.badgeClass
                )}
                onClick={(event) => {
                  event.stopPropagation();
                  onOpenResult(alert);
                }}
                title={
                  language === "arabic"
                    ? "افتح نتيجة هذا التحليل"
                    : "Open this analysis result"
                }
              >
                {visual.label}
              </button>
            ) : (
              <Badge
                className={cn(
                  "rounded-full border px-3 py-1.5 text-[11px] font-semibold uppercase",
                  visual.badgeClass
                )}
              >
                {visual.label}
              </Badge>
            )}

            <span
              className={cn(
                "inline-flex h-9 items-center gap-1.5 rounded-full border border-white/10 bg-slate-950/30 px-3 text-[11px]",
                visual.timeClass
              )}
              title={formatAbsoluteTime(alert.created_at)}
            >
              <Clock3 className="h-3.5 w-3.5" />
              {alert.relative_time}
            </span>

            {isPersistedPcapAlertId(alert.id) ? (
              <button
                type="button"
                className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-slate-950/35 text-slate-300 transition-colors hover:border-rose-300/25 hover:bg-rose-400/10 hover:text-rose-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-300/35"
                title="Dismiss"
                aria-label="Dismiss alert"
                disabled={clearingAlerts}
                onClick={(event) => {
                  event.stopPropagation();
                  onDismiss(alert);
                }}
              >
                <X className="h-4 w-4" />
              </button>
            ) : null}
          </div>
        </div>

        {clickableResult ? (
          <span className="block text-[11px] leading-5 text-slate-400/76">
            {language === "arabic"
              ? "يفتح مساحة عمل التحليل المحفوظة"
              : "Opens the saved analysis workspace"}
          </span>
        ) : null}

        <AlertMetadataPills alertId={alert.id} items={metadataItems} />
      </div>

      <div className="hidden min-w-0 shrink-0 flex-wrap items-start justify-end gap-2 lg:flex lg:max-w-[220px] lg:self-start">
        {summaryResult && alert.job_id ? (
          <button
            type="button"
            className={cn(
              "inline-flex h-9 items-center justify-center rounded-full border px-3 text-[11px] font-semibold uppercase transition-all duration-200 hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/40",
              visual.badgeClass
            )}
            onClick={(event) => {
              event.stopPropagation();
              onOpenResult(alert);
            }}
            title={
              language === "arabic"
                ? "Ø§ÙØªØ­ Ù†ØªÙŠØ¬Ø© Ù‡Ø°Ø§ Ø§Ù„ØªØ­Ù„ÙŠÙ„"
                : "Open this analysis result"
            }
          >
            {visual.label}
          </button>
        ) : (
          <Badge
            className={cn(
              "rounded-full border px-3 py-1.5 text-[11px] font-semibold uppercase",
              visual.badgeClass
            )}
          >
            {visual.label}
          </Badge>
        )}

        <span
          className={cn(
            "inline-flex h-9 items-center gap-1.5 rounded-full border border-white/10 bg-slate-950/30 px-3 text-[11px]",
            visual.timeClass
          )}
          title={formatAbsoluteTime(alert.created_at)}
        >
          <Clock3 className="h-3.5 w-3.5" />
          {alert.relative_time}
        </span>

        {isPersistedPcapAlertId(alert.id) ? (
          <button
            type="button"
            className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-slate-950/35 text-slate-300 transition-colors hover:border-rose-300/25 hover:bg-rose-400/10 hover:text-rose-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-300/35"
            title="Dismiss"
            aria-label="Dismiss alert"
            disabled={clearingAlerts}
            onClick={(event) => {
              event.stopPropagation();
              onDismiss(alert);
            }}
          >
            <X className="h-4 w-4" />
          </button>
        ) : null}
      </div>
      </div>
    </div>
  );
}

function playAlertFeedSound(items: DashboardPcapAlert[]) {
  const hasCritical = items.some((item) => item.severity === "critical");
  const hasWarning = items.some(
    (item) => item.severity === "medium" || item.severity === "high"
  );

  if (hasCritical) {
    playCriticalSound();
  } else if (hasWarning) {
    playWarningSound();
  }
}

function normalizeRenderedMetadataChip(chip: string) {
  return chip
    .replace(/Ã¢â€ â€™/g, "->")
    .replace(/â†’/g, "->")
    .trim();
}

function isJobMetadataChip(chip: string) {
  return /^job\s+/i.test(chip);
}

function isFileMetadataChip(chip: string) {
  return /\.(pcap|pcapng|cap|csv|json|zip|bin)$/i.test(chip);
}

function waitForAlertRefresh(ms: number) {
  return new Promise<void>((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

export function RecentSecurityAlertsPanel({
  className,
}: {
  className?: string;
}) {
  const { language, isRtl, formatNumber } = useLanguage();
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<DashboardPcapAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [clearingAlerts, setClearingAlerts] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feedNotice, setFeedNotice] = useState<string | null>(null);
  const [feedMode, setFeedMode] = useState<AlertFeedMode>("empty");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const alertsRef = useRef<DashboardPcapAlert[]>([]);
  const feedModeRef = useRef<AlertFeedMode>("empty");
  const [displayLimit, setDisplayLimit] = useState<number>(() => {
    if (typeof window === "undefined") {
      return 10;
    }

    const stored = Number(
      window.localStorage.getItem("sentinel_recent_security_alert_limit") || 10
    );
    return ALERT_LIMIT_OPTIONS.includes(stored) ? stored : 10;
  });

  const alertsAreEqual = (
    current: DashboardPcapAlert[],
    next: DashboardPcapAlert[]
  ) => {
    if (current.length !== next.length) {
      return false;
    }

    return current.every((item, index) => {
      const other = next[index];
      return (
        item.job_id === other.job_id &&
        item.attack_type === other.attack_type &&
        item.protocol === other.protocol &&
        item.src_ip === other.src_ip &&
        item.dst_ip === other.dst_ip &&
        item.created_at === other.created_at &&
        item.severity === other.severity &&
        item.type === other.type
      );
    });
  };

  useEffect(() => {
    alertsRef.current = alerts;
  }, [alerts]);

  useEffect(() => {
    feedModeRef.current = feedMode;
  }, [feedMode]);

  const loadAlerts = async ({
    showLoader = true,
    preserveVisibleOnFallback = true,
    retryCanonical = false,
  }: LoadAlertsOptions = {}) => {
    if (showLoader) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }

    setError(null);

    const cachedAlerts = readRecentPcapAlertCache(displayLimit);
    let vaultAiAlerts: DashboardAlertWithSource[] = [];
    let identityAlerts: DashboardAlertWithSource[] = [];

    try {
      vaultAiAlerts = await fetchVaultAiAlerts(displayLimit);
    } catch {
      vaultAiAlerts = [];
    }

    try {
      identityAlerts = await fetchIdentityAlerts(displayLimit);
    } catch {
      identityAlerts = [];
    }

    let canonicalFeedResolved = false;
    let pcapError: Error | null = null;
    let reportFallbackError: Error | null = null;
    let notificationError: Error | null = null;

    try {
      const applyAlertFeed = (
        incoming: DashboardPcapAlert[],
        mode: AlertFeedMode,
        options: {
          persistCache?: boolean;
          playSound?: boolean;
          secondary?: DashboardPcapAlert[];
        } = {}
      ) => {
        const nextItems = mergeDashboardAlerts(
          [...identityAlerts, ...vaultAiAlerts, ...incoming],
          options.secondary ?? (mode === "notifications" ? [] : cachedAlerts),
          displayLimit
        );
        const latestAlertTimestamp =
          parseTimestampEpoch(nextItems[0]?.created_at) || Date.now();
        const updatedAt = new Date(latestAlertTimestamp);
        const shouldUpdate =
          !alertsAreEqual(alertsRef.current, nextItems) ||
          feedModeRef.current !== mode;

        if (!shouldUpdate) {
          return;
        }

        setAlerts(nextItems);
        setFeedMode(mode);
        setLastUpdated(updatedAt);

        if (options.persistCache !== false && mode !== "notifications") {
          persistRecentPcapAlertCache(nextItems, {
            jobId: nextItems[0]?.job_id ?? null,
            updatedAt: updatedAt.toISOString(),
          });
        }

        if (options.playSound !== false) {
          playAlertFeedSound(nextItems);
        }
      };

      const canonicalAttemptDelays = retryCanonical
        ? [0, 150, 400]
        : [0];

      for (const delayMs of canonicalAttemptDelays) {
        try {
          if (delayMs > 0) {
            await waitForAlertRefresh(delayMs);
          }
          const items = await fetchPcapAlerts(displayLimit);
          canonicalFeedResolved = true;
          if (items.length > 0) {
            applyAlertFeed(items, "live", {
              secondary: [],
            });
            return;
          }
        } catch (fetchError) {
          pcapError =
            fetchError instanceof Error
              ? fetchError
              : new Error("Failed to load recent PCAP alerts.");
        }
      }

      if (!canonicalFeedResolved) {
        try {
          const reportItems = await fetchRecentJobReportAlerts(displayLimit);
          if (reportItems.length > 0) {
            applyAlertFeed(reportItems, "live", {
              secondary: alertsRef.current,
            });
            return;
          }
        } catch (fetchError) {
          reportFallbackError =
            fetchError instanceof Error
              ? fetchError
              : new Error("Failed to load recent PCAP job report alerts.");
        }
      }

      if (!canonicalFeedResolved && cachedAlerts.length > 0) {
        applyAlertFeed(cachedAlerts, "live", {
          persistCache: false,
          playSound: false,
          secondary: preserveVisibleOnFallback ? alertsRef.current : [],
        });
        return;
      }

      if (canonicalFeedResolved) {
        if (vaultAiAlerts.length > 0 || identityAlerts.length > 0) {
          applyAlertFeed([], "live", {
            secondary: [],
          });
          return;
        }

        setAlerts([]);
        setFeedMode("empty");
        setLastUpdated(new Date());
        setError(null);
        return;
      }

      try {
        const notificationItems = await fetchNotificationBackfillAlerts(
          displayLimit
        );
        if (notificationItems.length > 0) {
          if (preserveVisibleOnFallback && alertsRef.current.length > 0) {
            return;
          }
          applyAlertFeed(notificationItems, "notifications", {
            persistCache: false,
          });
          return;
        }
      } catch (fetchError) {
        notificationError =
          fetchError instanceof Error
            ? fetchError
            : new Error("Failed to load PCAP notification alerts.");
      }

      if (vaultAiAlerts.length > 0 || identityAlerts.length > 0) {
        applyAlertFeed([], "live", {
          secondary: [],
        });
        return;
      }

      if (ENABLE_PCAP_ALERTS_MOCK_FALLBACK) {
        setAlerts(buildMockPcapAlerts());
        setFeedMode("sample");
        setLastUpdated(new Date());
        return;
      }

      if (preserveVisibleOnFallback && alertsRef.current.length > 0) {
        if (pcapError || reportFallbackError || notificationError) {
          setError(
            pcapError?.message ||
              reportFallbackError?.message ||
              notificationError?.message ||
              "Failed to load recent PCAP alerts."
          );
        }
        return;
      }

      setAlerts([]);
      setFeedMode("empty");
      setLastUpdated(new Date());

      if (pcapError || reportFallbackError || notificationError) {
        setError(
          pcapError?.message ||
            reportFallbackError?.message ||
            notificationError?.message ||
            "Failed to load recent PCAP alerts."
        );
      }
    } finally {
      if (showLoader) {
        setLoading(false);
      } else {
        setRefreshing(false);
      }
    }
  };

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(
      "sentinel_recent_security_alert_limit",
      String(displayLimit)
    );
  }, [displayLimit]);

  useEffect(() => {
    const cachedAlerts = readRecentPcapAlertCache(displayLimit);
    if (cachedAlerts.length > 0) {
      const latestAlertTimestamp =
        parseTimestampEpoch(cachedAlerts[0]?.created_at) || Date.now();
      setAlerts(cachedAlerts);
      setFeedMode("live");
      setLastUpdated(new Date(latestAlertTimestamp));
      setError(null);
      return;
    }

    setAlerts([]);
    setFeedMode("empty");
    setLastUpdated(null);
  }, [displayLimit]);

  useEffect(() => {
    void loadAlerts({
      showLoader: false,
      preserveVisibleOnFallback: true,
      retryCanonical: true,
    });
  }, [displayLimit]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const handlePcapAlertsUpdated = () => {
      void loadAlerts({
        showLoader: false,
        preserveVisibleOnFallback: true,
        retryCanonical: true,
      });
    };

    const handleStorageEvent = (event: StorageEvent) => {
      if (event.key === RECENT_PCAP_ALERT_UPDATED_AT_KEY) {
        void loadAlerts({
          showLoader: false,
          preserveVisibleOnFallback: true,
          retryCanonical: true,
        });
      }
    };

    window.addEventListener(RECENT_PCAP_ALERT_EVENT, handlePcapAlertsUpdated);
    window.addEventListener("storage", handleStorageEvent);

    return () => {
      window.removeEventListener(RECENT_PCAP_ALERT_EVENT, handlePcapAlertsUpdated);
      window.removeEventListener("storage", handleStorageEvent);
    };
  }, [displayLimit]);

  const feedVisual = FEED_MODE_VISUALS[feedMode];
  const latestAnalysis = useMemo(
    () => alerts.find((alert) => isSummaryAnalysisResult(alert)) ?? null,
    [alerts]
  );

  const summary = useMemo(() => {
    return {
      total: alerts.length,
      critical: countBySeverity(alerts, "critical"),
      needsAttention: countNeedsAttention(alerts),
      dominantAttack:
        latestAnalysis?.top_pattern || topAttackType(alerts) || "n/a",
    };
  }, [alerts, latestAnalysis]);

  const moduleCoverage = useMemo(
    () => [
      {
        label: "PCAP",
        detail: "Traffic visibility & session context",
        icon: Radar,
        className: "tone-sky-chip",
        iconClassName: "border-cyan-300/15 bg-cyan-400/10 text-cyan-100",
      },
      {
        label: "Phishing",
        detail: "Threat screening & link review",
        icon: AlertTriangle,
        className: "tone-amber-chip",
        iconClassName: "border-amber-300/15 bg-amber-400/10 text-amber-100",
      },
      {
        label: "Passwords",
        detail: "Access hygiene & trust posture",
        icon: Shield,
        className: "tone-emerald-chip",
        iconClassName: "border-emerald-300/15 bg-emerald-400/10 text-emerald-100",
      },
      {
        label: "Identity",
        detail: "Exposure awareness & account watch",
        icon: Eye,
        className: "tone-orange-chip",
        iconClassName: "border-orange-300/15 bg-orange-400/10 text-orange-100",
      },
      {
        label: "Vault",
        detail: "Protected storage & access control",
        icon: Server,
        className: "tone-rose-chip",
        iconClassName: "border-rose-300/15 bg-rose-400/10 text-rose-100",
      },
    ],
    []
  );

  const openAlertResult = (alert: DashboardPcapAlert) => {
    if (!alert.job_id) {
      return;
    }
    navigate(`/pcap-analyzer?job=${encodeURIComponent(alert.job_id)}#analysis-workspace`);
  };

  const forgetRecentAlertCache = () => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.removeItem(RECENT_PCAP_ALERT_CACHE_KEY);
    window.localStorage.setItem(
      RECENT_PCAP_ALERT_UPDATED_AT_KEY,
      new Date().toISOString()
    );
  };

  const handleClearVisibleAlerts = async (targetAlert?: DashboardPcapAlert) => {
    const visibleAlerts = targetAlert ? [targetAlert] : alertsRef.current;
    if (visibleAlerts.length === 0 || clearingAlerts) {
      return;
    }

    const confirmed = targetAlert
      ? true
      : window.confirm(
          "Clear all visible alerts from your feed? This will not delete reports or evidence."
        );
    if (!confirmed) {
      return;
    }

    setClearingAlerts(true);
    setError(null);
    setFeedNotice(null);

    try {
      const idsToDismiss = visibleAlerts.map((alert) => alert.id);
      if (targetAlert && !isPersistedPcapAlertId(targetAlert.id)) {
        throw new Error("This alert is not managed by the backend yet.");
      }
      await dismissVisiblePcapAlerts(
        targetAlert ? [targetAlert.id] : [],
        { dismissAllVisible: !targetAlert }
      );
      const dismissedIds = new Set(idsToDismiss);
      const nextAlerts = alertsRef.current.filter(
        (alert) => !dismissedIds.has(alert.id)
      );
      setAlerts(nextAlerts);
      forgetRecentAlertCache();
      setFeedMode(nextAlerts.length === 0 ? "empty" : feedModeRef.current);
      setLastUpdated(new Date());
      setFeedNotice(
        targetAlert ? "Alert dismissed." : "Visible alerts cleared."
      );
    } catch (clearError) {
      setError(
        clearError instanceof Error
          ? clearError.message
          : "Unable to clear visible alerts."
      );
    } finally {
      setClearingAlerts(false);
    }
  };

  return (
    <Card
      className={cn(
        "relative h-fit w-full overflow-hidden rounded-3xl border border-cyan-500/20 bg-gradient-to-br from-[#061a2e] via-[#07152a] to-[#111235] p-4 shadow-[0_0_40px_rgba(14,165,233,0.12)] sm:p-5 lg:p-6",
        className
      )}
      dir={isRtl ? "rtl" : "ltr"}
    >
      <div
        className="pointer-events-none absolute inset-0 tone-sky-spotlight opacity-90"
        aria-hidden="true"
      />
      <div
        className="absolute inset-x-0 top-0 h-px tone-sky-glow opacity-80"
        aria-hidden="true"
      />
      <style>
        {`
          .rsa-alert-card {
            position: relative;
            width: 100%;
            max-width: 100%;
            overflow: hidden;
            border-radius: 24px;
            border: 1px solid rgba(255,255,255,0.10);
            background: linear-gradient(135deg, rgba(2,6,23,0.72), rgba(15,23,42,0.52), rgba(49,46,129,0.32));
            padding: 24px;
          }

          .rsa-alert-body {
            position: relative;
            z-index: 1;
            display: grid;
            grid-template-columns: 64px minmax(0, 1fr) auto;
            gap: 20px;
            align-items: start;
            width: 100%;
            min-width: 0;
          }

          .rsa-alert-icon {
            width: 56px;
            height: 56px;
            border-radius: 16px;
            border: 1px solid rgba(251,113,133,0.35);
            background: rgba(244,63,94,0.12);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
          }

          .rsa-alert-main {
            min-width: 0;
            display: flex;
            flex-direction: column;
            gap: 10px;
          }

          .rsa-alert-badges,
          .rsa-alert-status,
          .rsa-alert-chips {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
          }

          .rsa-alert-status {
            justify-content: flex-end;
            white-space: nowrap;
          }

          .rsa-alert-chips {
            margin-top: 4px;
          }

          .rsa-alert-chip {
            display: inline-flex;
            max-width: 100%;
            align-items: center;
            gap: 6px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.10);
            background: rgba(2,6,23,0.35);
            padding: 8px 12px;
            font-size: 12px;
            line-height: 16px;
            color: #e2e8f0;
          }

          @media (max-width: 900px) {
            .rsa-alert-body {
              grid-template-columns: 1fr;
            }

            .rsa-alert-status {
              justify-content: flex-start;
              white-space: normal;
            }
          }
        `}
      </style>

      <CardHeader className="relative border-0 p-0">
        <div className="space-y-5">
          <div className="min-w-0">
            <div className="flex items-start gap-3">
              <div className="relative flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-cyan-300/20 bg-cyan-400/10 shadow-[0_0_24px_rgba(56,189,248,0.14)]">
                <Radar className="h-6 w-6 text-cyan-100" />
                <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-cyan-300" />
              </div>

              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <CardTitle className="text-2xl font-semibold text-white">
                    {language === "arabic" ? "أحدث التنبيهات الأمنية" : "Recent Security Alerts"}
                  </CardTitle>

                  <Badge
                    className={cn(
                      "rounded-full border px-3 py-1 text-[11px] font-semibold",
                      feedVisual.badgeClass
                    )}
                  >
                    <span className="mr-2 inline-flex items-center">
                      <span
                        className={cn(
                          "h-2 w-2 rounded-full",
                          feedVisual.dotClass,
                          feedMode === "live" ? "animate-pulse" : ""
                        )}
                      />
                    </span>
                    {feedVisual.label}
                  </Badge>
                </div>

                <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-300">
                  {language === "arabic"
                    ? "رؤية أمنية موحدة تتضمن نتائج ذات أولوية، وسياق التحقيق، والمؤشرات المراقبة لحسابك النشط."
                    : "Unified security insights with prioritized findings, investigation context, and monitored indicators tailored to your active account."}
                </p>

                <div className="mb-4 mt-4 flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-cyan-400/20 bg-slate-950/30 px-3 py-2 text-xs font-medium text-cyan-100">
                    {language === "arabic" ? "تغذية موحدة للمحلل" : "Unified analyst feed"}
                  </span>
                  <span className="rounded-full border border-white/10 bg-slate-950/30 px-3 py-2 text-xs font-medium text-slate-300">
                    {language === "arabic" ? "تحديث عند وصول تنبيه جديد" : "Refresh on new alerts"}
                  </span>
                  <span className="rounded-full border border-white/10 bg-slate-950/30 px-3 py-2 text-xs font-medium text-slate-300">
                    {language === "arabic" ? "سياق عبر كل الوحدات" : "Cross-module context"}
                  </span>
                  {lastUpdated ? (
                    <span className="rounded-full border border-white/10 bg-slate-950/30 px-3 py-2 text-xs font-medium text-slate-300">
                      {language === "arabic"
                        ? `تم التحديث ${formatRelativeTime(lastUpdated.toISOString())}`
                        : `Updated ${formatRelativeTime(lastUpdated.toISOString())}`}
                    </span>
                  ) : null}
                </div>

                <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
                  {moduleCoverage.map((module) => {
                    const ModuleIcon = module.icon;
                    return (
                    <div
                      key={module.label}
                      className={cn(
                        "group/module flex min-h-[92px] min-w-0 items-center rounded-2xl border p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] transition-colors duration-200 hover:border-white/20",
                        module.className
                      )}
                    >
                      <div className="flex min-w-0 items-center gap-3">
                        <span
                          className={cn(
                            "flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border",
                            module.iconClassName
                          )}
                        >
                          <ModuleIcon className="h-5 w-5" />
                        </span>
                        <div className="min-w-0">
                          <div className="truncate text-xs font-semibold uppercase text-white">
                            {module.label}
                          </div>
                          <div className="mt-1 line-clamp-2 text-xs leading-5 text-slate-300">
                            {module.detail}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
                </div>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <SummaryTile
                icon={Activity}
                label={language === "arabic" ? "الإجمالي الظاهر" : "Total Visible"}
                value={formatNumber(summary.total)}
                className="border-white/8 bg-white/[0.04]"
              />

              <SummaryTile
                icon={Siren}
                label={language === "arabic" ? "حرج" : "Critical"}
                value={formatNumber(summary.critical)}
                className="border-rose-400/12 bg-rose-400/5"
                iconClassName="text-rose-200/70"
                valueClassName="text-rose-50"
              />

              <SummaryTile
                icon={Eye}
                label={language === "arabic" ? "تحتاج مراجعة" : "Needs Review"}
                value={formatNumber(summary.needsAttention)}
                className="border-amber-400/12 bg-amber-400/5"
                iconClassName="text-amber-200/70"
                valueClassName="text-amber-50"
              />

              <SummaryTile
                icon={Sparkles}
                label={language === "arabic" ? "النمط الأبرز" : "Top Pattern"}
                value={
                  <span className="truncate capitalize">{summary.dominantAttack}</span>
                }
                className="border-cyan-400/12 bg-cyan-400/5"
                iconClassName="text-cyan-200/70"
                valueClassName="text-sm text-cyan-50"
              />
            </div>
          </div>

          <div className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-slate-950/25 p-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2 rounded-xl border border-white/10 bg-slate-950/30 px-3 py-2">
                <span className="text-[11px] font-semibold uppercase text-slate-400">
                  {language === "arabic" ? "التنبيهات" : "Alerts"}
                </span>
                <Select
                  value={String(displayLimit)}
                  onValueChange={(value) => {
                    const parsed = Number(value);
                    if (ALERT_LIMIT_OPTIONS.includes(parsed)) {
                      setDisplayLimit(parsed);
                    }
                  }}
                >
                  <SelectTrigger className="h-8 min-w-[88px] rounded-lg border-white/10 bg-[#0b1220] px-2.5 text-xs text-slate-100 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="border-white/10 bg-[#111827] text-slate-200">
                    {ALERT_LIMIT_OPTIONS.map((count) => (
                      <SelectItem
                        key={`recent-alert-limit-${count}`}
                        value={String(count)}
                      >
                        {count}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <Badge className="rounded-full border border-white/10 bg-slate-950/30 px-3 py-1.5 text-xs font-medium text-slate-300">
                {language === "arabic" ? `${formatNumber(alerts.length)} ظاهر` : `${alerts.length} visible`}
              </Badge>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={alerts.length === 0 || clearingAlerts}
                className="h-9 rounded-xl border border-white/10 bg-slate-950/55 px-3.5 text-xs text-slate-100 transition-all duration-200 hover:border-rose-500/25 hover:bg-slate-900 hover:text-rose-50 disabled:cursor-not-allowed disabled:opacity-50"
                onClick={() => void handleClearVisibleAlerts()}
              >
                <Trash2
                  className={cn(
                    "mr-1.5 h-3.5 w-3.5",
                    clearingAlerts ? "animate-pulse" : ""
                  )}
                />
                {clearingAlerts ? "Clearing" : "Clear Alerts"}
              </Button>

              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-9 rounded-xl border border-white/10 bg-slate-950/55 px-3.5 text-xs text-slate-100 transition-all duration-200 hover:border-cyan-500/25 hover:bg-slate-900 hover:text-cyan-50"
                onClick={() =>
                  void loadAlerts({
                    showLoader: true,
                    preserveVisibleOnFallback: false,
                    retryCanonical: true,
                  })
                }
              >
                <RefreshCw
                  className={cn(
                    "mr-1.5 h-3.5 w-3.5",
                    refreshing ? "animate-spin" : ""
                  )}
                />
                {refreshing
                  ? language === "arabic"
                    ? "جارٍ التحديث"
                    : "Refreshing"
                  : language === "arabic"
                  ? "تحديث"
                  : "Refresh"}
              </Button>
            </div>
          </div>
        </div>
      </CardHeader>

      <CardContent className="relative mt-5 space-y-4 p-0">
        {feedNotice ? (
          <div className="rounded-[18px] border border-emerald-400/18 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-50">
            {feedNotice}
          </div>
        ) : null}

        {loading ? (
          <div className="space-y-3">
            {[0, 1, 2].map((item) => (
              <div
                key={item}
                className="relative overflow-hidden rounded-3xl border border-white/10 bg-slate-950/35 p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]"
              >
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
                <div className="relative flex items-start gap-3">
                  <div className="h-9 w-9 animate-pulse rounded-xl bg-white/10" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="h-4 w-2/5 animate-pulse rounded-full bg-white/10" />
                        <div className="mt-2.5 h-3 w-full animate-pulse rounded-full bg-white/5" />
                        <div className="mt-2 h-3 w-4/5 animate-pulse rounded-full bg-white/5" />
                      </div>
                      <div className="h-7 w-24 animate-pulse rounded-full bg-white/8" />
                    </div>

                    <div className="mt-3 flex flex-wrap gap-1.5">
                      <div className="h-6 w-28 animate-pulse rounded-full bg-white/6" />
                      <div className="h-6 w-20 animate-pulse rounded-full bg-white/6" />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : error ? (
          <div className="overflow-hidden rounded-2xl border border-rose-500/18 bg-rose-950/25 px-4 py-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-rose-300/20 bg-rose-400/12">
                  <ShieldAlert className="h-[18px] w-[18px] text-rose-100" />
                </div>

                <div>
                  <div className="text-sm font-semibold text-rose-50">
                    {language === "arabic" ? "تعذر تحميل أحدث التنبيهات الأمنية" : "Unable to load recent security alerts"}
                  </div>
                  <div className="mt-2 text-sm leading-6 text-rose-100/80">
                    {error}
                  </div>

                  {ENABLE_PCAP_ALERTS_MOCK_FALLBACK ? (
                    <div className="mt-3 text-xs text-rose-100/70">
                      {language === "arabic"
                        ? "تم تفعيل البيانات التجريبية لهذا النظام عند عدم توفر التغذية الحية."
                        : "Sample fallback is enabled for this environment when no live feed is available."}
                    </div>
                  ) : null}
                </div>
              </div>

              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-8 rounded-xl border border-rose-300/20 bg-rose-400/10 px-3 text-xs text-rose-50 hover:bg-rose-400/14"
                onClick={() =>
                  void loadAlerts({
                    showLoader: true,
                    preserveVisibleOnFallback: false,
                    retryCanonical: true,
                  })
                }
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                {language === "arabic" ? "إعادة المحاولة" : "Retry"}
              </Button>
            </div>
          </div>
        ) : alerts.length === 0 ? (
          <div className="overflow-hidden rounded-2xl border border-dashed border-slate-800 bg-slate-950/36 px-5 py-7 text-center shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.04] shadow-[0_12px_28px_rgba(15,23,42,0.14)]">
              <Server className="h-5 w-5 text-slate-300" />
            </div>

            <div className="mt-4 text-base font-semibold text-white">
              {language === "arabic" ? "لا توجد تنبيهات أمنية حديثة" : DEFAULT_EMPTY_MESSAGE}
            </div>

            <div className="mx-auto mt-1.5 max-w-xl text-[13px] leading-5 text-slate-400">
              {language === "arabic"
                ? "شغّل تحليل PCAP وستظهر أحدث النتائج الخاصة بحسابك هنا تلقائيًا مع تصنيف الخطورة وسياق البروتوكول."
                : "New security findings will appear here when available. Cleared alerts do not delete reports or evidence."}
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {alerts.map((alert, index) => {
              const summaryResult = isSummaryAnalysisResult(alert);
              const visual = summaryResult
                ? SUMMARY_RESULT_VISUAL
                : ALERT_VISUALS[alert.severity];
              const Icon = visual.icon;
              const metadataItems = buildAlertMetadataItems(alert)
                .map((item) => ({
                  ...item,
                  value: normalizeRenderedMetadataChip(item.value),
                }))
                .filter((item) => item.value.trim().length > 0)
                .slice(0, 4);
              const stateLabel = formatAlertStateLabel(alert.status);
              const clickableResult = summaryResult && Boolean(alert.job_id);
              return (
                <motion.article
                  key={`${alert.id}-${alert.created_at}`}
                  initial={{ opacity: 0, y: 10, scale: 0.995 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{
                    duration: 0.2,
                    delay: Math.min(index * 0.03, 0.18),
                  }}
                  whileHover={{ y: -2 }}
                  role={clickableResult ? "button" : undefined}
                  tabIndex={clickableResult ? 0 : undefined}
                  onClick={clickableResult ? () => openAlertResult(alert) : undefined}
                  onKeyDown={
                    clickableResult
                      ? (event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            openAlertResult(alert);
                          }
                        }
                      : undefined
                  }
                  className={cn(
                    "rsa-alert-card group transition-all duration-200",
                    clickableResult &&
                      "cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/45 focus-visible:ring-offset-0"
                  )}
                >
                  <div
                    className={cn(
                      "absolute bottom-4 left-0 top-4 w-[3px] rounded-r-full bg-gradient-to-b opacity-85",
                      visual.accentClass
                    )}
                  />
                  <div
                    className={cn(
                      "pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100",
                      visual.glowClass
                    )}
                    aria-hidden="true"
                  />
                  <div
                    className={cn(
                      "absolute inset-x-0 top-0 h-px bg-gradient-to-r opacity-60",
                      visual.accentClass
                    )}
                  />

                  <div className="rsa-alert-body">
                    <div className="rsa-alert-icon">
                      <Icon
                        className={cn(
                          "h-6 w-6",
                          visual.iconClass,
                          alert.severity === "critical" ? visual.pulseClass : ""
                        )}
                      />
                    </div>

                    <div className="rsa-alert-main">
                      <div className="rsa-alert-badges">
                        {stateLabel ? (
                          <span
                            className={cn(
                              "rounded-full border px-3 py-1 text-[11px] font-semibold uppercase",
                              alertStateBadgeClass(alert.status)
                            )}
                          >
                            {stateLabel}
                          </span>
                        ) : null}

                        <span className="rounded-full border border-white/10 bg-slate-950/35 px-3 py-1 text-[11px] font-semibold uppercase text-slate-300">
                          {summaryResult
                            ? language === "arabic"
                              ? "Ù†ØªÙŠØ¬Ø© Ø§Ù„ØªØ­Ù„ÙŠÙ„"
                              : "Analysis Result"
                            : alertSourceLabel(alert)}
                        </span>
                      </div>

                      <div className="space-y-2">
                        <div className="text-base font-semibold leading-6 text-slate-50 lg:text-lg">
                          {alert.title}
                        </div>
                        <div className="max-w-[78ch] text-sm leading-relaxed text-slate-300">
                          {alert.message}
                        </div>
                      </div>

                      <AlertMetadataPills alertId={alert.id} items={metadataItems} />

                      {clickableResult ? (
                        <span className="block text-[11px] leading-5 text-slate-400/76">
                          {language === "arabic"
                            ? "ÙŠÙØªØ­ Ù…Ø³Ø§Ø­Ø© Ø¹Ù…Ù„ Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ù…Ø­ÙÙˆØ¸Ø©"
                            : "Opens the saved analysis workspace"}
                        </span>
                      ) : null}
                    </div>

                    <div className="rsa-alert-status">
                      {summaryResult && alert.job_id ? (
                        <button
                          type="button"
                          className={cn(
                            "inline-flex h-9 items-center justify-center rounded-full border px-3 text-[11px] font-semibold uppercase transition-all duration-200 hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/40",
                            visual.badgeClass
                          )}
                          onClick={(event) => {
                            event.stopPropagation();
                            openAlertResult(alert);
                          }}
                          title={
                            language === "arabic"
                              ? "Ø§ÙØªØ­ Ù†ØªÙŠØ¬Ø© Ù‡Ø°Ø§ Ø§Ù„ØªØ­Ù„ÙŠÙ„"
                              : "Open this analysis result"
                          }
                        >
                          {visual.label}
                        </button>
                      ) : (
                        <Badge
                          className={cn(
                            "rounded-full border px-3 py-1.5 text-[11px] font-semibold uppercase",
                            visual.badgeClass
                          )}
                        >
                          {visual.label}
                        </Badge>
                      )}

                      <span
                        className={cn(
                          "inline-flex h-9 items-center gap-1.5 rounded-full border border-white/10 bg-slate-950/30 px-3 text-[11px]",
                          visual.timeClass
                        )}
                        title={formatAbsoluteTime(alert.created_at)}
                      >
                        <Clock3 className="h-3.5 w-3.5" />
                        {alert.relative_time}
                      </span>

                      {isPersistedPcapAlertId(alert.id) ? (
                        <button
                          type="button"
                          className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-slate-950/35 text-slate-300 transition-colors hover:border-rose-300/25 hover:bg-rose-400/10 hover:text-rose-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-300/35"
                          title="Dismiss"
                          aria-label="Dismiss alert"
                          disabled={clearingAlerts}
                          onClick={(event) => {
                            event.stopPropagation();
                            void handleClearVisibleAlerts(alert);
                          }}
                        >
                          <X className="h-4 w-4" />
                        </button>
                        ) : null}
                    </div>
                  </div>
                </motion.article>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}




