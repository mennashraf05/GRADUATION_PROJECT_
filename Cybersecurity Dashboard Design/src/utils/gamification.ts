import { toast } from "sonner";

const DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:5000";
const DEFAULT_REQUEST_TIMEOUT_MS = 15000;

export const GAMIFICATION_UPDATED_EVENT = "sentinel-gamification-updated";
export const GAMIFICATION_UPDATED_AT_KEY = "sentinel_gamification_updated_at";

export type GamificationProfile = {
  total_points: number;
  current_level: number;
  current_level_name: string;
  next_level: number | null;
  next_level_name: string | null;
  points_to_next_level: number;
  level_progress_percent: number;
  current_streak: number;
  longest_streak: number;
  total_scans: number;
  total_reviewed_alerts: number;
  total_badges: number;
  last_activity_at: string | null;
  last_badge: {
    badge_code: string;
    badge_title: string;
    awarded_at: string | null;
  } | null;
};

export type GamificationBadge = {
  badge_code: string;
  badge_title: string;
  badge_description: string;
  rarity: string;
  unlocked: boolean;
  awarded_at: string | null;
  progress_current?: number;
  progress_target?: number;
};

export type GamificationChallenge = {
  challenge_code: string;
  challenge_type: "daily" | "weekly";
  title: string;
  description: string;
  target_value: number;
  current_value: number;
  reward_points: number;
  status: "active" | "completed" | "expired";
  starts_at: string;
  expires_at: string;
  completed_at: string | null;
};

export type GamificationHistoryItem = {
  event_type: string;
  points_awarded: number;
  created_at: string | null;
  human_readable_reason: string;
  job_id: string | null;
  alert_id: string | null;
};

export type GamificationOverview = {
  profile: GamificationProfile;
  badges: {
    unlocked: GamificationBadge[];
    locked: GamificationBadge[];
  };
  challenges: {
    daily: GamificationChallenge[];
    weekly: GamificationChallenge[];
  };
  history: GamificationHistoryItem[];
};

export type GamificationAlertContext = {
  review: {
    review_status: string;
    disposition: string | null;
    first_viewed_at: string | null;
    reviewed_at: string | null;
    last_viewed_at: string | null;
  } | null;
  notes: Array<{
    id: number;
    note_body: string;
    created_at: string | null;
  }>;
};

export type GamificationEventRequest = {
  event_type:
    | "report_accessed"
    | "report_opened"
    | "alert_viewed"
    | "evidence_accessed"
    | "evidence_opened"
    | "alert_reviewed"
    | "investigation_note_added"
    | "alert_marked_true_positive"
    | "alert_marked_false_positive";
  job_id: string;
  alert_id?: string | null;
  evidence_key?: string | null;
  evidence_context?: string | null;
  access_method?: string | null;
  note_body?: string | null;
};

export type GamificationEventResponse = {
  accepted: boolean;
  reason?: string;
  points_gained: number;
  total_points?: number;
  current_level?: number;
  current_level_name?: string;
  level_progress_percent?: number;
  badges_unlocked?: Array<{
    badge_code: string;
    badge_title: string;
    badge_description: string;
    rarity: string;
    awarded_at: string;
  }>;
  level_ups?: Array<{
    level: number;
    level_name: string;
  }>;
  streak_updated?: boolean;
  current_streak?: number;
  history_message?: string | null;
  reward_breakdown?: Array<{
    event_type: string;
    points_awarded: number;
    created_at: string | null;
    message: string;
  }>;
  alert_context?: GamificationAlertContext;
};

function normalizeGamificationTimestamp(value: string | null | undefined): string | null {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return null;
  }
  if (
    trimmed.endsWith("Z") ||
    /[+-]\d{2}:\d{2}$/.test(trimmed)
  ) {
    return trimmed;
  }
  return `${trimmed}Z`;
}

export function formatGamificationTimestamp(value: string | null | undefined): string {
  const normalized = normalizeGamificationTimestamp(value);
  if (!normalized) {
    return "Just now";
  }

  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed)) {
    return String(value || "");
  }

  return new Date(parsed).toLocaleString();
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

const API_BASE_URL = (() => {
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

async function readJsonResponse<T>(response: Response, fallbackMessage: string): Promise<T> {
  const text = await response.text();
  if (!text.trim()) {
    throw new Error(fallbackMessage);
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(fallbackMessage);
  }
}

function buildApiUrl(path: string): string {
  return API_BASE_URL ? `${API_BASE_URL}${path}` : path;
}

export function broadcastGamificationUpdated() {
  if (typeof window === "undefined") {
    return;
  }
  const stamp = new Date().toISOString();
  window.localStorage.setItem(GAMIFICATION_UPDATED_AT_KEY, stamp);
  window.dispatchEvent(new Event(GAMIFICATION_UPDATED_EVENT));
}

async function fetchGamificationJson<T>(path: string): Promise<T> {
  const response = await fetchWithTimeout(
    buildApiUrl(path),
    buildAuthedFetchInit({
      cache: "no-store",
    })
  );

  const payload = await readJsonResponse<T & { error?: string }>(
    response,
    "Gamification API returned invalid JSON."
  );

  if (!response.ok) {
    throw new Error(
      typeof (payload as { error?: string }).error === "string"
        ? (payload as { error?: string }).error || "Gamification request failed."
        : "Gamification request failed."
    );
  }

  return payload;
}

export async function fetchGamificationOverview(): Promise<GamificationOverview> {
  return fetchGamificationJson<GamificationOverview>("/api/gamification/overview");
}

export async function fetchGamificationAlertContext(
  jobId: string,
  alertId: string
): Promise<GamificationAlertContext> {
  const search = new URLSearchParams({
    job_id: jobId,
    alert_id: alertId,
  });
  return fetchGamificationJson<GamificationAlertContext>(
    `/api/gamification/alert-context?${search.toString()}`
  );
}

export async function recordGamificationEvent(
  payload: GamificationEventRequest
): Promise<GamificationEventResponse> {
  const response = await fetchWithTimeout(
    buildApiUrl("/api/gamification/events"),
    buildAuthedFetchInit({
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
  );

  const body = await readJsonResponse<
    GamificationEventResponse & { error?: string }
  >(response, "Gamification event response was not valid JSON.");

  if (!response.ok) {
    throw new Error(body.error || "Failed to record gamification event.");
  }

  if (body.accepted) {
    broadcastGamificationUpdated();
  }

  return body;
}

export function showGamificationToasts(result: GamificationEventResponse) {
  if (!result.accepted) {
    return;
  }

  if (result.points_gained > 0 && result.history_message) {
    toast.success(result.history_message);
  }

  for (const badge of result.badges_unlocked || []) {
    toast.success(`Badge unlocked: ${badge.badge_title}`);
  }

  for (const levelUp of result.level_ups || []) {
    if (levelUp.level > 0 && levelUp.level_name) {
      toast.success(`Level up: ${levelUp.level_name}`);
    }
  }
}
