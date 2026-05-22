import React, { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "motion/react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Bell,
  BellRing,
  CheckCheck,
  ChevronRight,
  Download,
  RefreshCw,
  ShieldAlert,
  Siren,
  TriangleAlert,
} from "lucide-react";
import { toast } from "sonner";
import { playCriticalSound, playWarningSound, playSuccessSound } from "../utils/soundNotifications";
import {
  RECENT_PCAP_ALERT_EVENT,
  RECENT_PCAP_ALERT_UPDATED_AT_KEY,
} from "../utils/recentPcapAlerts";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { cn } from "./ui/utils";

const DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:5000";
const VAULT_AI_NOTIFICATION_INTERVAL_MS = 15000;
const VAULT_AI_MIN_NOTIFY_SCORE = 80;

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

const NOTIFICATION_API_BASE_CANDIDATES = (() => {
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

type NotificationType =
  | "job_started"
  | "job_completed"
  | "job_failed"
  | "report_ready"
  | "evidence_ready"
  | "suspicious_detected"
  | "critical_detected"
  | "vault_threat_detected"
  | "identity_leak"
  | "password_security";

type NotificationSeverity =
  | "info"
  | "success"
  | "warning"
  | "critical"
  | "error";

type NotificationItem = {
  id: number | string;
  user_id?: number;
  module?: string;
  source?: string;
  source_id?: number | string;
  scan_id?: number | string | null;
  action_url?: string | null;
  type: NotificationType | string;
  severity?: NotificationSeverity | string | null;
  title: string;
  message?: string;
  body?: string;
  job_id?: string | null;
  metadata?: Record<string, unknown>;
  is_read: boolean;
  created_at?: string | null;
};

type VaultAiRiskItem = {
  id?: string;
  action_type?: string;
  type?: string;
  name?: string;
  title?: string;
  message?: string;
  description?: string;
  scope?: string;
  severity?: string;
  risk_score?: number;
  score?: number;
  count?: number;
  target_label?: string | null;
  filename?: string | null;
};

function isAdminConsoleRoute() {
  if (typeof window === "undefined") return false;
  return window.location.pathname.startsWith("/admin");
}

function getStoredAuthToken() {
  if (typeof window === "undefined") return null;
  if (isAdminConsoleRoute()) {
    return (
      localStorage.getItem("sentinel_admin_token") ||
      localStorage.getItem("sentinel_auth_token")
    );
  }
  return localStorage.getItem("sentinel_auth_token");
}

function buildAuthedFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  const token = getStoredAuthToken();
  if (token && token !== "cookie_based") {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return {
    ...init,
    credentials: "include",
    headers,
  };
}

function buildCookieOnlyFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.delete("Authorization");
  return {
    ...init,
    credentials: "include",
    headers,
  };
}

async function fetchWithNotificationAuth(
  input: RequestInfo | URL,
  init: RequestInit = {}
) {
  const cookieResponse = await fetch(input, buildCookieOnlyFetchInit(init));
  if (cookieResponse.status !== 401 && cookieResponse.status !== 403) {
    return cookieResponse;
  }

  const storedToken = getStoredAuthToken();
  if (storedToken && storedToken !== "cookie_based") {
    return fetch(input, buildAuthedFetchInit(init));
  }

  return cookieResponse;
}

function buildNotificationUrl(path: string, base: string) {
  return base ? `${base}${path}` : path;
}

function getNotificationApiPath(path: string) {
  if (!isAdminConsoleRoute()) {
    return path;
  }
  return path.replace(/^\/notifications/, "/api/admin/notifications");
}

async function fetchNotificationResponse(
  path: string,
  init: RequestInit = {}
) {
  let lastError: unknown = null;
  let sawInvalidHtmlResponse = false;

  for (const base of NOTIFICATION_API_BASE_CANDIDATES) {
    try {
      const response = await fetchWithNotificationAuth(
        buildNotificationUrl(getNotificationApiPath(path), base),
        init
      );
      const contentType = String(
        response.headers.get("content-type") || ""
      ).toLowerCase();

      if (contentType.includes("text/html")) {
        sawInvalidHtmlResponse = true;
        continue;
      }

      return response;
    } catch (error) {
      lastError = error;
    }
  }

  if (sawInvalidHtmlResponse) {
    throw new Error(
      "Notifications endpoint returned an invalid response. Restart the dev server or verify the backend URL."
    );
  }

  throw lastError instanceof Error ? lastError : new Error("Failed to fetch");
}

function normalizeNotificationType(type: string, metadata?: Record<string, unknown>) {
  const rawType = String(type || "").trim().toLowerCase();
  if (rawType === "high_risk_detected") {
    const riskLevel = String(metadata?.risk_level || "").trim().toLowerCase();
    return riskLevel === "critical" ? "critical_detected" : "suspicious_detected";
  }
  if (rawType === "export_ready") {
    const artifactType = String(metadata?.artifact_type || "").trim().toLowerCase();
    return artifactType === "evidence" ? "evidence_ready" : "report_ready";
  }
  if (rawType === "vault_threat_detected") {
    const riskLevel = String(metadata?.risk_level || "").trim().toLowerCase();
    return riskLevel === "critical" ? "critical_detected" : "suspicious_detected";
  }
  if (rawType === "identity_leak") {
    return "identity_leak";
  }
  if (rawType === "password_security") {
    return "password_security";
  }
  return rawType;
}

function normalizeNotificationSeverity(
  severity: NotificationItem["severity"],
  type: string
): NotificationSeverity {
  const rawSeverity = String(severity || "").trim().toLowerCase();
  if (
    rawSeverity === "info" ||
    rawSeverity === "success" ||
    rawSeverity === "warning" ||
    rawSeverity === "critical" ||
    rawSeverity === "error"
  ) {
    return rawSeverity;
  }

  switch (normalizeNotificationType(type)) {
    case "identity_leak":
      return "warning";
    case "job_failed":
      return "error";
    case "job_completed":
    case "report_ready":
      return "success";
    case "evidence_ready":
      return "info";
    case "suspicious_detected":
      return "warning";
    case "critical_detected":
      return "critical";
    default:
      return "info";
  }
}

function normalizeNotificationItem(raw: NotificationItem): NotificationItem {
  const metadata =
    raw.metadata && typeof raw.metadata === "object" ? raw.metadata : {};
  const normalizedType = normalizeNotificationType(String(raw.type || ""), metadata);
  const normalizedSeverity = normalizeNotificationSeverity(raw.severity, normalizedType);
  const message = String(raw.message || raw.body || "").trim();
  const jobId = String(raw.job_id || metadata.job_id || "").trim() || null;
  const scanId = raw.scan_id || metadata.scan_id || null;
  const actionUrl =
    String(raw.action_url || metadata.action_url || "").trim() ||
    (scanId ? `/identityleak-monitor?scan_id=${encodeURIComponent(String(scanId))}` : null);

  return {
    ...raw,
    type: normalizedType,
    severity: normalizedSeverity,
    message,
    body: message,
    job_id: jobId,
    scan_id: scanId,
    action_url: actionUrl,
    metadata,
  };
}

function formatRelativeTime(value?: string | null) {
  if (!value) return "just now";
  const created = new Date(value).getTime();
  if (Number.isNaN(created)) return "just now";

  const diffMs = Date.now() - created;
  const diffMin = Math.max(0, Math.floor(diffMs / 60000));
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return new Date(value).toLocaleDateString();
}

function getNotificationVisual(item: NotificationItem) {
  const type = normalizeNotificationType(String(item.type || ""), item.metadata);
  const severity = normalizeNotificationSeverity(item.severity, type);
  const riskLevel = String(item.metadata?.risk_level || item.severity || "").trim();

  if (type === "password_security") {
    if (severity === "critical") {
      return {
        icon: ShieldAlert,
        accentClass: "bg-red-400/80",
        iconWrapClass: "border-red-500/20 bg-red-500/10",
        iconColor: "text-red-200",
        badge: "Password",
        badgeClass: "border-red-500/20 bg-red-500/10 text-red-200",
      };
    }
    if (severity === "warning") {
      return {
        icon: ShieldAlert,
        accentClass: "bg-amber-400/80",
        iconWrapClass: "border-amber-500/20 bg-amber-500/10",
        iconColor: "text-amber-200",
        badge: "Password",
        badgeClass: "border-amber-500/20 bg-amber-500/10 text-amber-200",
      };
    }
    return {
      icon: ShieldAlert,
      accentClass: "bg-cyan-400/80",
      iconWrapClass: "border-cyan-500/20 bg-cyan-500/10",
      iconColor: "text-cyan-200",
      badge: "Password",
      badgeClass: "border-cyan-500/20 bg-cyan-500/10 text-cyan-200",
    };
  }

  if (severity === "critical" || type === "critical_detected") {
    return {
      icon: ShieldAlert,
      accentClass: "bg-red-400/80",
      iconWrapClass: "border-red-500/20 bg-red-500/10",
      iconColor: "text-red-200",
      badge: "Critical",
      badgeClass: "border-red-500/20 bg-red-500/10 text-red-200",
    };
  }

  if (severity === "error" || type === "job_failed") {
    return {
      icon: TriangleAlert,
      accentClass: "bg-rose-400/80",
      iconWrapClass: "border-rose-500/20 bg-rose-500/10",
      iconColor: "text-rose-200",
      badge: type === "identity_leak" ? riskLevel || "High" : "Failed",
      badgeClass: "border-rose-500/20 bg-rose-500/10 text-rose-200",
    };
  }

  if (severity === "warning" || type === "suspicious_detected") {
    return {
      icon: TriangleAlert,
      accentClass: "bg-amber-400/80",
      iconWrapClass: "border-amber-500/20 bg-amber-500/10",
      iconColor: "text-amber-200",
      badge: type === "identity_leak" ? riskLevel || "Medium" : "Warning",
      badgeClass: "border-amber-500/20 bg-amber-500/10 text-amber-200",
    };
  }

  if (type === "job_started") {
    return {
      icon: BellRing,
      accentClass: "bg-cyan-400/80",
      iconWrapClass: "border-cyan-500/20 bg-cyan-500/10",
      iconColor: "text-cyan-200",
      badge: "Queued",
      badgeClass: "border-cyan-500/20 bg-cyan-500/10 text-cyan-200",
    };
  }

  if (type === "report_ready" || type === "evidence_ready") {
    return {
      icon: Download,
      accentClass: "bg-blue-400/80",
      iconWrapClass: "border-blue-500/20 bg-blue-500/10",
      iconColor: "text-blue-200",
      badge: type === "evidence_ready" ? "Evidence" : "Report",
      badgeClass: "border-blue-500/20 bg-blue-500/10 text-blue-200",
    };
  }

  if (severity === "success" || type === "job_completed") {
    return {
      icon: CheckCheck,
      accentClass: "bg-emerald-400/80",
      iconWrapClass: "border-emerald-500/20 bg-emerald-500/10",
      iconColor: "text-emerald-200",
      badge: "Completed",
      badgeClass: "border-emerald-500/20 bg-emerald-500/10 text-emerald-200",
    };
  }

  return {
    icon: Siren,
    accentClass: "bg-slate-400/80",
    iconWrapClass: "border-slate-700 bg-slate-800/80",
    iconColor: "text-slate-300",
    badge: "Notice",
    badgeClass: "border-white/10 bg-white/[0.04] text-slate-300",
  };
}

function getNotificationActionLabel(item: NotificationItem) {
  const type = normalizeNotificationType(String(item.type || ""), item.metadata);
  if (type === "identity_leak") return "Open Scan";
  if (type === "report_ready") return "Open Report";
  if (type === "evidence_ready") return "Open Artifacts";
  return "Open Job";
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


function getVaultRiskScore(risk: VaultAiRiskItem) {
  return Math.max(0, Math.min(100, Number(risk.risk_score ?? risk.score ?? 0)));
}

function normalizeVaultRiskSeverity(rawSeverity: unknown, riskScore: number): NotificationSeverity {
  const severity = String(rawSeverity || "").trim().toLowerCase();

  if (severity === "critical") return "critical";
  if (severity === "high") return "warning";
  if (severity === "medium" || severity === "warning") return "warning";
  if (severity === "error") return "error";

  if (riskScore >= 90) return "critical";
  if (riskScore >= 80) return "warning";

  return "info";
}

function getVaultRiskTitle(risk: VaultAiRiskItem) {
  const raw = [
    risk.action_type,
    risk.type,
    risk.name,
    risk.title,
    risk.message,
    risk.description,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (raw.includes("password") || raw.includes("wrong vault")) {
    return "Wrong Password Attempts";
  }

  if (raw.includes("download")) {
    return "Download Activity";
  }

  if (raw.includes("delete") || raw.includes("deletion")) {
    return "File Deletion";
  }

  if (raw.includes("offline")) {
    return "Offline Access";
  }

  if (raw.includes("upload")) {
    return "File Upload";
  }

  return String(risk.title || risk.name || "Vault AI Threat");
}

function getVaultActiveRisks(payload: Record<string, unknown>): VaultAiRiskItem[] {
  const raw =
    payload.active_risks ||
    payload.suspicious_patterns ||
    payload.patterns ||
    payload.risks ||
    (payload.summary &&
    typeof payload.summary === "object" &&
    !Array.isArray(payload.summary)
      ? (payload.summary as Record<string, unknown>).active_risks
      : []);

  return Array.isArray(raw) ? (raw as VaultAiRiskItem[]) : [];
}

function buildVaultRiskFingerprint(risk: VaultAiRiskItem) {
  return [
    getVaultRiskTitle(risk),
    String(risk.scope || "user").toLowerCase(),
    String(risk.target_label || risk.filename || "no-target"),
    String(risk.count || 0),
    String(getVaultRiskScore(risk)),
  ].join("|");
}

function buildVaultNotificationItem(risk: VaultAiRiskItem): NotificationItem {
  const riskScore = getVaultRiskScore(risk);
  const severity = normalizeVaultRiskSeverity(risk.severity, riskScore);
  const riskLevel = riskScore >= 90 || severity === "critical" ? "critical" : "high";
  const scope =
    String(risk.scope || "user").toLowerCase() === "file"
      ? "File-level"
      : "User-level";
  const target = String(risk.target_label || risk.filename || "No specific target");
  const count = Number(risk.count ?? 1);
  const title = `${riskLevel === "critical" ? "Critical" : "High"} Vault Threat: ${getVaultRiskTitle(risk)}`;
  const message = `${scope} • Risk ${riskScore}/100 • Count ${count} • Target: ${target}`;

  return {
    id: -Math.abs(Date.now() + Math.floor(Math.random() * 1000)),
    type: "vault_threat_detected",
    severity,
    title,
    message,
    body: message,
    job_id: null,
    metadata: {
      module: "vault",
      risk_level: riskLevel,
      risk_score: riskScore,
      scope,
      target,
      count,
      fingerprint: buildVaultRiskFingerprint(risk),
    },
    is_read: false,
    created_at: new Date().toISOString(),
  };
}

async function fetchVaultAiRiskNotifications(): Promise<NotificationItem[]> {
  const response = await fetchNotificationResponse("/api/ai/vault/analyze", {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source: "notification_center" }),
  });

  const payload = await readJsonResponse(
    response,
    "Vault AI endpoint returned an invalid response."
  );

  if (!response.ok) {
    return [];
  }

  return getVaultActiveRisks(payload)
    .filter((risk) => {
      const score = getVaultRiskScore(risk);
      const severity = normalizeVaultRiskSeverity(risk.severity, score);
      return (
        score >= VAULT_AI_MIN_NOTIFY_SCORE ||
        severity === "critical" ||
        severity === "warning"
      );
    })
    .map(buildVaultNotificationItem);
}

export function NotificationCenter() {
  const navigate = useNavigate();
  const location = useLocation();
  const panelRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const hasBootstrappedRef = useRef(false);
  const seenIdsRef = useRef<Set<string>>(new Set());
  const seenVaultRiskFingerprintsRef = useRef<Set<string>>(new Set());
  const vaultWatcherRunningRef = useRef(false);

  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [markingId, setMarkingId] = useState<number | string | null>(null);
  const [markingAll, setMarkingAll] = useState(false);
  const [panelStyle, setPanelStyle] = useState<React.CSSProperties | null>(null);

  const hasNotifications = notifications.length > 0;

  const emitNotificationToasts = (items: NotificationItem[]) => {
    const nextIds = new Set(items.map((item) => String(item.id)));
    if (!hasBootstrappedRef.current) {
      seenIdsRef.current = nextIds;
      hasBootstrappedRef.current = true;
      return;
    }

    const newItems = items.filter((item) => !seenIdsRef.current.has(String(item.id)));
    seenIdsRef.current = nextIds;

    for (const item of newItems) {
      const severity = normalizeNotificationSeverity(item.severity, String(item.type || ""));
      if (severity === "critical") {
        toast.error(item.title, {
          description: item.message || "Critical analyzer event detected.",
        });
        playCriticalSound();
      } else if (severity === "warning") {
        toast.warning(item.title, {
          description: item.message || "Warning alert detected.",
        });
        playWarningSound();
      } else if (severity === "success") {
        toast.success(item.title, {
          description: item.message || "Operation completed successfully.",
        });
        playSuccessSound();
      }
    }
  };

  const fetchUnreadCount = async () => {
    try {
      const response = await fetchNotificationResponse(
        "/notifications/unread-count",
        {
          cache: "no-store",
        }
      );
      const payload = await readJsonResponse(
        response,
        "Notification unread count returned an invalid response. Check the dev proxy configuration."
      );
      if (!response.ok) {
        if (response.status === 401) {
          setUnreadCount(0);
        }
        return;
      }
      setUnreadCount(Number(payload.unread_count ?? 0) || 0);
    } catch {
      // Keep badge state as-is on transient polling failures.
    }
  };

  const fetchNotifications = async (showLoader = false) => {
    if (showLoader) setLoading(true);
    setError(null);

    try {
      const response = await fetchNotificationResponse(
        "/notifications?limit=20&offset=0",
        {
          cache: "no-store",
        }
      );
      const payload = await readJsonResponse(
        response,
        "Notifications endpoint returned an invalid response. Check the dev proxy configuration."
      );
      if (!response.ok) {
        throw new Error(
          String(payload?.error || payload?.message || "Failed to load notifications.")
        );
      }

      const rawItems = Array.isArray(payload.notifications)
        ? (payload.notifications as NotificationItem[])
        : [];
      const items = rawItems.map(normalizeNotificationItem);
      emitNotificationToasts(items);
      setNotifications(items);
      setUnreadCount(Number(payload.unread_count ?? 0) || 0);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Failed to load notifications."
      );
    } finally {
      if (showLoader) setLoading(false);
    }
  };

  const checkVaultAiNotifications = async () => {
    if (vaultWatcherRunningRef.current) {
      return;
    }

    vaultWatcherRunningRef.current = true;

    try {
      const vaultItems = await fetchVaultAiRiskNotifications();
      const newItems = vaultItems.filter((item) => {
        const fingerprint = String(item.metadata?.fingerprint || item.id);

        if (seenVaultRiskFingerprintsRef.current.has(fingerprint)) {
          return false;
        }

        seenVaultRiskFingerprintsRef.current.add(fingerprint);
        return true;
      });

      if (newItems.length === 0) {
        return;
      }

      for (const item of newItems) {
        const severity = normalizeNotificationSeverity(item.severity, String(item.type || ""));

        if (severity === "critical") {
          toast.error(item.title, {
            description: item.message || "Critical Vault AI threat detected.",
          });
          playCriticalSound();
        } else {
          toast.warning(item.title, {
            description: item.message || "High Vault AI threat detected.",
          });
          playWarningSound();
        }
      }

      setNotifications((prev) => {
        const merged = [...newItems, ...prev];
        return merged.slice(0, 20);
      });
      setUnreadCount((prev) => prev + newItems.length);
    } catch {
      // Vault AI notification polling is optional and should not break the notification center.
    } finally {
      vaultWatcherRunningRef.current = false;
    }
  };

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    void checkVaultAiNotifications();

    const interval = window.setInterval(() => {
      void checkVaultAiNotifications();
    }, VAULT_AI_NOTIFICATION_INTERVAL_MS);

    return () => {
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const handleRecentPcapUpdated = () => {
      if (isOpen) {
        void fetchNotifications(false);
      } else {
        void fetchUnreadCount();
      }
    };

    const handleStorageEvent = (event: StorageEvent) => {
      if (event.key === RECENT_PCAP_ALERT_UPDATED_AT_KEY) {
        handleRecentPcapUpdated();
      }
    };

    window.addEventListener(RECENT_PCAP_ALERT_EVENT, handleRecentPcapUpdated);
    window.addEventListener("storage", handleStorageEvent);

    return () => {
      window.removeEventListener(RECENT_PCAP_ALERT_EVENT, handleRecentPcapUpdated);
      window.removeEventListener("storage", handleStorageEvent);
    };
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    void fetchNotifications(true);
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) {
      setPanelStyle(null);
      return;
    }

    const updatePanelPosition = () => {
      const rect = buttonRef.current?.getBoundingClientRect();
      if (!rect) {
        return;
      }

      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;
      const horizontalPadding = 12;
      const panelWidth = Math.min(480, Math.max(320, viewportWidth - horizontalPadding * 2));
      const right = Math.max(horizontalPadding, viewportWidth - rect.right);
      const top = Math.min(rect.bottom + 14, Math.max(16, viewportHeight - 180));
      const maxHeight = Math.max(240, viewportHeight - top - 16);

      setPanelStyle({
        position: "fixed",
        top,
        right,
        width: panelWidth,
        maxHeight,
        zIndex: 250,
        pointerEvents: "auto",
      });
    };

    updatePanelPosition();
    window.addEventListener("resize", updatePanelPosition);
    window.addEventListener("scroll", updatePanelPosition, true);
    return () => {
      window.removeEventListener("resize", updatePanelPosition);
      window.removeEventListener("scroll", updatePanelPosition, true);
    };
  }, [isOpen]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (
        isOpen &&
        !panelRef.current?.contains(target) &&
        !buttonRef.current?.contains(target)
      ) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen]);

  useEffect(() => {
    setIsOpen(false);
  }, [location.pathname, location.search]);

  const markNotificationRead = async (notificationId: number | string) => {
    setMarkingId(notificationId);
    setError(null);
    try {
      const response = await fetchNotificationResponse(
        "/notifications/read",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: notificationId }),
        }
      );
      const payload = await readJsonResponse(
        response,
        "Notification update returned an invalid response."
      );
      if (!response.ok) {
        throw new Error(
          String(payload?.error || payload?.message || "Failed to update notification.")
        );
      }

      setNotifications((prev) =>
        prev.map((item) =>
          String(item.id) === String(notificationId) ? { ...item, is_read: true } : item
        )
      );
      setUnreadCount(Number(payload.unread_count ?? 0) || 0);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Failed to update notification."
      );
    } finally {
      setMarkingId(null);
    }
  };

  const markAllRead = async () => {
    setMarkingAll(true);
    setError(null);
    try {
      const response = await fetchNotificationResponse(
        "/notifications/read-all",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        }
      );
      const payload = await readJsonResponse(
        response,
        "Mark-all notifications returned an invalid response."
      );
      if (!response.ok) {
        throw new Error(
          String(payload?.error || payload?.message || "Failed to mark notifications as read.")
        );
      }
      setNotifications((prev) => prev.map((item) => ({ ...item, is_read: true })));
      setUnreadCount(Number(payload.unread_count ?? 0) || 0);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to mark notifications as read."
      );
    } finally {
      setMarkingAll(false);
    }
  };

  const openNotification = async (item: NotificationItem) => {
    if (!item.is_read) {
      await markNotificationRead(item.id);
    }

    const actionUrl = String(item.action_url || item.metadata?.action_url || "").trim();
    const scanId = String(item.scan_id || item.metadata?.scan_id || "").trim();
    if (normalizeNotificationType(String(item.type || ""), item.metadata) === "identity_leak") {
      setIsOpen(false);
      navigate(actionUrl || `/identityleak-monitor${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`);
      return;
    }

    const jobId = String(item.job_id || item.metadata?.job_id || "").trim();
    if (!jobId) {
      return;
    }

    setIsOpen(false);
    if (isAdminConsoleRoute()) {
      navigate(`/admin/console?section=pcap-analysis&job=${encodeURIComponent(jobId)}`);
      return;
    }
    navigate(`/pcap-analyzer?job=${encodeURIComponent(jobId)}`);
  };

  const unreadBadge = useMemo(() => {
    if (unreadCount <= 0) return null;
    return unreadCount > 99 ? "99+" : String(unreadCount);
  }, [unreadCount]);

  const panelBodyMaxHeight =
    typeof panelStyle?.maxHeight === "number"
      ? Math.max(160, panelStyle.maxHeight - 132)
      : undefined;

  const panelContent =
    isOpen && panelStyle
      ? createPortal(
          <AnimatePresence>
            <motion.div
              ref={panelRef}
              initial={{ opacity: 0, y: 10, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.98 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              style={panelStyle}
              className="z-[250] flex flex-col overflow-hidden rounded-[24px] border border-slate-700/90 bg-[linear-gradient(180deg,rgba(2,6,23,0.98)_0%,rgba(4,12,26,0.99)_52%,rgba(2,6,23,1)_100%)] shadow-[0_28px_90px_rgba(2,6,23,0.82)] backdrop-blur-xl"
            >
              <div className="border-b border-slate-700/80 bg-slate-950/95 px-5 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-500/14">
                        <BellRing className="h-5 w-5 text-cyan-200" />
                      </div>
                      <div>
                        <div className="text-sm font-semibold text-white">
                          Notification Center
                        </div>
                        <div className="text-xs text-slate-300">
                          {isAdminConsoleRoute()
                            ? "System-wide admin alerts, detections, and job updates"
                            : "Analyzer events, risks, and job updates for your account"}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-9 rounded-xl border border-slate-600 bg-slate-900 text-slate-100 hover:bg-slate-800"
                      onClick={() => void fetchNotifications(true)}
                      disabled={loading}
                    >
                      <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
                      Refresh
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-9 rounded-xl border border-slate-600 bg-slate-900 text-slate-100 hover:bg-slate-800"
                      onClick={() => void markAllRead()}
                      disabled={markingAll || unreadCount === 0}
                    >
                      <CheckCheck className="mr-2 h-4 w-4" />
                      Mark all
                    </Button>
                  </div>
                </div>

                <div className="mt-4 flex items-center gap-3 text-xs text-slate-300">
                  <Badge className="rounded-full border border-cyan-400/30 bg-cyan-500/16 text-cyan-50">
                    {unreadCount} unread
                  </Badge>
                  <span>{notifications.length} recent notifications</span>
                </div>
              </div>

              <div
                className="overflow-y-auto bg-slate-950/92 px-3 py-3"
                style={
                  panelBodyMaxHeight
                    ? { maxHeight: `${panelBodyMaxHeight}px` }
                    : undefined
                }
              >
                {loading ? (
                  <div className="space-y-3 px-2 py-2">
                    {[0, 1, 2].map((index) => (
                      <div
                        key={index}
                        className="rounded-2xl border border-slate-700/80 bg-slate-900/95 p-4"
                      >
                        <div className="mb-3 h-4 w-40 animate-pulse rounded bg-white/10" />
                        <div className="mb-2 h-3 w-full animate-pulse rounded bg-white/5" />
                        <div className="h-3 w-2/3 animate-pulse rounded bg-white/5" />
                      </div>
                    ))}
                  </div>
                ) : error ? (
                  <div className="rounded-2xl border border-rose-500/20 bg-rose-950/40 px-4 py-5 text-sm text-rose-200">
                    {error}
                  </div>
                ) : !hasNotifications ? (
                  <div className="rounded-[24px] border border-dashed border-slate-700/80 bg-slate-900/92 px-6 py-10 text-center">
                    <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-700/80 bg-slate-900">
                      <Bell className="h-6 w-6 text-slate-400" />
                    </div>
                    <div className="text-base font-semibold text-slate-100">
                      No notifications yet
                    </div>
                    <div className="mt-2 text-sm leading-6 text-slate-300">
                      Analyzer updates will appear here when jobs start, complete,
                      fail, or detect notable threat activity.
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {notifications.map((item) => {
                      const visual = getNotificationVisual(item);
                      const Icon = visual.icon;
                      const jobId = String(item.job_id || item.metadata?.job_id || "").trim();
                      const moduleLabel = String(item.module || item.metadata?.module || "").trim();
                      const scanId = String(item.scan_id || item.metadata?.scan_id || "").trim();
                      const actionUrl = String(item.action_url || item.metadata?.action_url || "").trim();
                      const hasAction = Boolean(jobId || actionUrl || scanId);
                      const timestampLabel = formatRelativeTime(item.created_at);

                      return (
                        <div
                          key={String(item.id)}
                          className={`group relative overflow-hidden rounded-[22px] border p-4 shadow-[0_14px_34px_rgba(2,6,23,0.38)] transition-all ${
                            item.is_read
                              ? "border-slate-700/80 bg-slate-900/92"
                              : "border-slate-600/90 bg-slate-900/98"
                          }`}
                        >
                          <div
                            className={cn(
                              "absolute bottom-4 left-0 top-4 w-[3px] rounded-r-full",
                              visual.accentClass
                            )}
                          />
                          <div className="flex gap-4">
                            <div
                              className={cn(
                                "flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border",
                                visual.iconWrapClass
                              )}
                            >
                              <Icon className={`h-5 w-5 ${visual.iconColor}`} />
                            </div>

                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-start justify-between gap-3">
                                <div className="min-w-0">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <div className="truncate text-sm font-semibold text-white">
                                      {item.title}
                                    </div>
                                    <Badge
                                      className={`rounded-full border px-2.5 py-0.5 text-[10px] font-medium ${visual.badgeClass}`}
                                    >
                                      {visual.badge}
                                    </Badge>
                                  </div>
                                  <div className="mt-2 text-sm leading-6 text-slate-100">
                                    {item.message || "Notification received."}
                                  </div>
                                  {moduleLabel ? (
                                    <div className="mt-2 text-xs font-medium text-cyan-200">
                                      {moduleLabel}
                                    </div>
                                  ) : null}
                                </div>

                                <div
                                  className="shrink-0 text-xs text-slate-300"
                                  title={
                                    item.created_at
                                      ? new Date(item.created_at).toLocaleString()
                                      : ""
                                  }
                                >
                                  {timestampLabel}
                                </div>
                              </div>

                              {jobId ? (
                                <div className="mt-3 text-xs text-slate-300">
                                  Linked job{" "}
                                  <span className="font-mono text-slate-100">{jobId}</span>
                                </div>
                              ) : null}
                              {!jobId && scanId ? (
                                <div className="mt-3 text-xs text-slate-300">
                                  Identity scan{" "}
                                  <span className="font-mono text-slate-100">#{scanId}</span>
                                </div>
                              ) : null}

                              <div className="mt-4 flex flex-wrap items-center gap-2">
                                {hasAction ? (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    className="h-9 rounded-xl border border-cyan-400/30 bg-cyan-500/16 text-cyan-50 hover:bg-cyan-500/22"
                                    onClick={() => void openNotification(item)}
                                  >
                                    {getNotificationActionLabel(item)}
                                    <ChevronRight className="ml-1 h-4 w-4" />
                                  </Button>
                                ) : null}

                                {!item.is_read ? (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    className="h-9 rounded-xl border border-slate-600 bg-slate-900 text-slate-100 hover:bg-slate-800"
                                    onClick={() => void markNotificationRead(item.id)}
                                    disabled={String(markingId) === String(item.id)}
                                  >
                                    Mark read
                                  </Button>
                                ) : null}
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </motion.div>
          </AnimatePresence>,
          document.body
        )
      : null;

  return (
    <div className="relative z-[260] shrink-0 pointer-events-auto">
      <Button
        ref={buttonRef}
        type="button"
        variant="ghost"
        size="sm"
        className="relative z-[261] h-10 w-10 rounded-2xl border border-slate-700 bg-slate-950/90 text-slate-100 transition-all hover:bg-slate-900 hover:text-white"
        onClick={() => setIsOpen((prev) => !prev)}
      >
        <Bell className="h-5 w-5" />
        {unreadBadge ? (
          <span className="absolute -right-1 -top-1 inline-flex min-h-5 min-w-5 items-center justify-center rounded-full border border-[#020617] bg-cyan-400 px-1.5 text-[10px] font-semibold text-[#020617]">
            {unreadBadge}
          </span>
        ) : null}
      </Button>
      {panelContent}
    </div>
  );
}
