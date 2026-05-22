export type ActivityModule = "auth" | "pcap" | "vault" | "identity";
export type ActivityStatus = "success" | "failed" | "warning" | "info";
export type ActivitySeverity = "low" | "medium" | "high" | "critical";

export type ActivityLogItem = {
  event_id: string;
  module: ActivityModule;
  module_label: string;
  action_type: string;
  action_label: string;
  title: string;
  description: string;
  status: ActivityStatus;
  severity: ActivitySeverity;
  risk_score: number | null;
  target_type: string | null;
  target_id: string | null;
  target_label: string | null;
  ip_address: string | null;
  session_id: string | null;
  is_sensitive: boolean;
  is_suspicious: boolean;
  created_at: string | null;
  metadata?: Record<string, unknown>;
};

export type ActivityLogsSummary = {
  cards: {
    total_events: number;
    successful_actions: number;
    failed_actions: number;
    suspicious_events: number;
    threat_related_events: number;
  };
  insights: {
    last_successful_login: ActivityLogItem | null;
    last_failed_login: ActivityLogItem | null;
    last_completed_pcap_analysis: ActivityLogItem | null;
    last_threat_event: ActivityLogItem | null;
    last_suspicious_event: ActivityLogItem | null;
  };
  count: number;
  user_id: number;
};

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

export const ACTIVITY_API_BASE = (() => {
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

export function buildActivityAuthedFetchInit(
  init: RequestInit = {}
): RequestInit {
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

export async function trackActivityEvent(input: {
  module: ActivityModule;
  action_type: string;
  description?: string;
  target_type?: string;
  target_id?: string;
  target_label?: string;
  metadata?: Record<string, unknown>;
}) {
  const response = await fetch(
    `${ACTIVITY_API_BASE}/api/activity-logs/track`,
    buildActivityAuthedFetchInit({
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    })
  );

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const message =
      typeof payload?.error === "string" && payload.error.trim()
        ? payload.error
        : "Activity tracking failed.";
    throw new Error(message);
  }

  return response.json().catch(() => ({}));
}
