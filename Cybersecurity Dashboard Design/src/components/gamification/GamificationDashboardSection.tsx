import React, { useEffect, useMemo, useState } from "react";

import { Alert } from "../ui/alert";
import { useLanguage } from "../../contexts/LanguageContext";
import { useGamification } from "../../hooks/useGamification";
import { ActiveChallengesCard } from "./ActiveChallengesCard";
import { BadgeCollectionCard } from "./BadgeCollectionCard";
import { RewardHistoryCard } from "./RewardHistoryCard";
import { SecurityProgressCard } from "./SecurityProgressCard";
import type {
  GamificationBadge,
  GamificationChallenge,
  GamificationHistoryItem,
} from "../../utils/gamification";

type PasswordHistoryRecord = {
  checked_at?: unknown;
  strength_label?: unknown;
  risk_level?: unknown;
  breached?: unknown;
  score?: unknown;
};

type PasswordChallenge = {
  title: string;
  description: string;
  current: number;
  target: number;
  reward: number;
};

type PasswordBadge = {
  title: string;
  unlocked: boolean;
};

type PasswordHistoryState = {
  records: PasswordHistoryRecord[];
  loading: boolean;
  unavailable: boolean;
};

type PasswordGamificationAdapter = {
  daily: GamificationChallenge[];
  weekly: GamificationChallenge[];
  unlockedBadges: GamificationBadge[];
  lockedBadges: GamificationBadge[];
  rewards: GamificationHistoryItem[];
};

const PASSWORD_HISTORY_ENDPOINT = "/api/password/history";
const PASSWORD_REQUEST_TIMEOUT_MS = 12000;

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

function buildPasswordApiUrl(path: string): string {
  const envBase = normalizeApiBase(String(import.meta.env.VITE_API_BASE_URL || ""));
  if (import.meta.env.DEV) {
    return path;
  }
  if (envBase) {
    return `${envBase}${path}`;
  }
  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      return `${window.location.protocol}//${host}:5000${path}`;
    }
  }
  return `http://127.0.0.1:5000${path}`;
}

function buildPasswordHistoryRequest(): RequestInit {
  const headers = new Headers();
  if (typeof window !== "undefined") {
    const token = window.localStorage.getItem("sentinel_auth_token");
    if (token && token !== "cookie_based") {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }

  return {
    cache: "no-store",
    credentials: "include",
    headers,
  };
}

async function fetchPasswordHistory(): Promise<PasswordHistoryRecord[]> {
  const controller = new AbortController();
  const timer = window.setTimeout(
    () => controller.abort(),
    PASSWORD_REQUEST_TIMEOUT_MS
  );

  try {
    const response = await fetch(buildPasswordApiUrl(PASSWORD_HISTORY_ENDPOINT), {
      ...buildPasswordHistoryRequest(),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error("Password history is unavailable.");
    }

    const payload: unknown = await response.json();
    if (Array.isArray(payload)) {
      return payload.filter(isPasswordHistoryRecord);
    }
    if (
      payload &&
      typeof payload === "object" &&
      Array.isArray((payload as { history?: unknown }).history)
    ) {
      return (payload as { history: unknown[] }).history.filter(
        isPasswordHistoryRecord
      );
    }
    if (
      payload &&
      typeof payload === "object" &&
      Array.isArray((payload as { records?: unknown }).records)
    ) {
      return (payload as { records: unknown[] }).records.filter(
        isPasswordHistoryRecord
      );
    }

    return [];
  } finally {
    window.clearTimeout(timer);
  }
}

function isPasswordHistoryRecord(value: unknown): value is PasswordHistoryRecord {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function parsePasswordDate(value: unknown): Date | null {
  if (typeof value !== "string" && typeof value !== "number") {
    return null;
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function toDateKey(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function isSameDay(left: Date, right: Date): boolean {
  return toDateKey(left) === toDateKey(right);
}

function startOfWeek(date: Date): Date {
  const next = new Date(date);
  next.setHours(0, 0, 0, 0);
  const day = next.getDay();
  const diff = day === 0 ? 6 : day - 1;
  next.setDate(next.getDate() - diff);
  return next;
}

function isThisWeek(date: Date, now: Date): boolean {
  const start = startOfWeek(now);
  const end = new Date(start);
  end.setDate(start.getDate() + 7);
  return date >= start && date < end;
}

function normalizeText(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isBreached(record: PasswordHistoryRecord): boolean {
  return record.breached === true;
}

function isStrongResult(record: PasswordHistoryRecord): boolean {
  const strength = normalizeText(record.strength_label);
  if (strength.includes("strong") || strength.includes("excellent")) {
    return true;
  }

  return typeof record.score === "number" && record.score >= 80;
}

function isSafeResult(record: PasswordHistoryRecord): boolean {
  const risk = normalizeText(record.risk_level);
  if (!risk) {
    return false;
  }

  return !isBreached(record) && (risk === "low" || risk === "safe");
}

function clampProgress(value: number, target: number): number {
  return Math.min(Math.max(value, 0), target);
}

function buildCurrentStreak(records: PasswordHistoryRecord[], now: Date): number {
  const checkedDays = new Set(
    records
      .map((record) => parsePasswordDate(record.checked_at))
      .filter((date): date is Date => Boolean(date))
      .map(toDateKey)
  );

  let streak = 0;
  const cursor = new Date(now);
  cursor.setHours(0, 0, 0, 0);

  while (checkedDays.has(toDateKey(cursor))) {
    streak += 1;
    cursor.setDate(cursor.getDate() - 1);
  }

  return streak;
}

function usePasswordHistory(): PasswordHistoryState {
  const [state, setState] = useState<PasswordHistoryState>({
    records: [],
    loading: true,
    unavailable: false,
  });

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const records = await fetchPasswordHistory();
        if (active) {
          setState({ records, loading: false, unavailable: false });
        }
      } catch {
        if (active) {
          setState({ records: [], loading: false, unavailable: true });
        }
      }
    };

    void load();

    return () => {
      active = false;
    };
  }, []);

  return state;
}

function toPasswordChallenge(
  challenge: PasswordChallenge,
  challengeType: "daily" | "weekly",
  code: string,
  now: Date
): GamificationChallenge {
  const completed = challenge.current >= challenge.target;
  const startsAt = new Date(now);
  startsAt.setHours(0, 0, 0, 0);
  const expiresAt = new Date(startsAt);
  expiresAt.setDate(expiresAt.getDate() + (challengeType === "daily" ? 1 : 7));

  return {
    challenge_code: `password_${challengeType}_${code}`,
    challenge_type: challengeType,
    title: challenge.title,
    description: challenge.description,
    target_value: challenge.target,
    current_value: clampProgress(challenge.current, challenge.target),
    reward_points: challenge.reward,
    status: completed ? "completed" : "active",
    starts_at: startsAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    completed_at: completed ? now.toISOString() : null,
  };
}

function toPasswordBadge(
  title: string,
  description: string,
  unlocked: boolean,
  current: number,
  target: number,
  awardedAt: string | null
): GamificationBadge {
  return {
    badge_code: `password_${title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "")}`,
    badge_title: title,
    badge_description: description,
    rarity: "common",
    unlocked,
    awarded_at: unlocked ? awardedAt : null,
    progress_current: Math.min(Math.max(current, 0), target),
    progress_target: target,
  };
}

function buildPasswordGamificationAdapter(records: PasswordHistoryRecord[]): PasswordGamificationAdapter {
  const now = new Date();
  const datedRecords = records
    .map((record) => ({
      record,
      checkedAt: parsePasswordDate(record.checked_at),
    }))
    .filter(
      (item): item is { record: PasswordHistoryRecord; checkedAt: Date } =>
        Boolean(item.checkedAt)
    );

  const todayRecords = datedRecords
    .filter(({ checkedAt }) => isSameDay(checkedAt, now))
    .map(({ record }) => record);
  const weeklyRecords = datedRecords
    .filter(({ checkedAt }) => isThisWeek(checkedAt, now))
    .map(({ record }) => record);
  const latestTimestamp =
    datedRecords
      .map(({ checkedAt }) => checkedAt.toISOString())
      .sort()
      .reverse()[0] || null;

  const totalChecks = records.length;
  const safeResults = records.filter(isSafeResult).length;
  const strongResults = records.filter(isStrongResult).length;
  const breachedReviewed = records.filter(isBreached).length;
  const weeklyStrongSafe = weeklyRecords.filter(
    (record) => isStrongResult(record) && isSafeResult(record)
  ).length;

  const daily = [
    toPasswordChallenge(
      {
        title: "Check 1 password today",
        description: "Run one password check today.",
        current: todayRecords.length > 0 ? 1 : 0,
        target: 1,
        reward: 5,
      },
      "daily",
      "check_one",
      now
    ),
    toPasswordChallenge(
      {
        title: "Get one safe password result today",
        description: "Get one non-breached low-risk password result today.",
        current: todayRecords.some(isSafeResult) ? 1 : 0,
        target: 1,
        reward: 8,
      },
      "daily",
      "safe_result",
      now
    ),
  ];

  const weekly = [
    toPasswordChallenge(
      {
        title: "Complete 3 password checks this week",
        description: "Run three password checks this week.",
        current: weeklyRecords.length,
        target: 3,
        reward: 15,
      },
      "weekly",
      "three_checks",
      now
    ),
    toPasswordChallenge(
      {
        title: "Get 2 strong and safe password results this week",
        description: "Get two strong and non-breached password results this week.",
        current: weeklyStrongSafe,
        target: 2,
        reward: 20,
      },
      "weekly",
      "strong_safe",
      now
    ),
    toPasswordChallenge(
      {
        title: "Review any breached password result this week",
        description: "Identify at least one breached password finding this week.",
        current: weeklyRecords.some(isBreached) ? 1 : 0,
        target: 1,
        reward: 10,
      },
      "weekly",
      "breach_review",
      now
    ),
  ];

  const badges = [
    toPasswordBadge("First Password Check", "Run your first password breach check.", totalChecks > 0, totalChecks, 1, latestTimestamp),
    toPasswordBadge("Safe Password Result", "Get at least one safe password result.", safeResults > 0, safeResults, 1, latestTimestamp),
    toPasswordBadge("Strong Password Habit", "Use a password that reaches strong or excellent strength.", strongResults > 0, strongResults, 1, latestTimestamp),
    toPasswordBadge("Breach Aware", "Review at least one breached password finding.", breachedReviewed > 0, breachedReviewed, 1, latestTimestamp),
    toPasswordBadge("Weekly Password Analyst", "Complete at least three password checks this week.", weeklyRecords.length >= 3, weeklyRecords.length, 3, latestTimestamp),
  ];

  const completedChallenges = [...daily, ...weekly].filter((challenge) => challenge.status === "completed");
  const rewards = completedChallenges.map((challenge): GamificationHistoryItem => ({
    event_type: `password_${challenge.challenge_code}`,
    points_awarded: challenge.reward_points,
    created_at: latestTimestamp,
    human_readable_reason: `Password: ${challenge.title}`,
    job_id: null,
    alert_id: null,
  }));

  return {
    daily,
    weekly,
    unlockedBadges: badges.filter((badge) => badge.unlocked),
    lockedBadges: badges.filter((badge) => !badge.unlocked),
    rewards,
  };
}

function mergeChallenges(
  existing: GamificationChallenge[],
  additions: GamificationChallenge[]
): GamificationChallenge[] {
  const seen = new Set(existing.map((item) => `${item.challenge_type}:${item.challenge_code}:${item.title}`.toLowerCase()));
  return [
    ...existing,
    ...additions.filter((item) => {
      const key = `${item.challenge_type}:${item.challenge_code}:${item.title}`.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
  ];
}

function mergeBadges(existing: GamificationBadge[], additions: GamificationBadge[]): GamificationBadge[] {
  const seen = new Set(existing.map((item) => `${item.badge_code}:${item.badge_title}`.toLowerCase()));
  return [
    ...existing,
    ...additions.filter((item) => {
      const key = `${item.badge_code}:${item.badge_title}`.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
  ];
}

function mergeHistory(existing: GamificationHistoryItem[], additions: GamificationHistoryItem[]): GamificationHistoryItem[] {
  const seen = new Set(existing.map((item) => `${item.event_type}:${item.created_at}:${item.human_readable_reason}`.toLowerCase()));
  return [
    ...existing,
    ...additions.filter((item) => {
      const key = `${item.event_type}:${item.created_at}:${item.human_readable_reason}`.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
  ].sort((left, right) => {
    const leftTime = Date.parse(left.created_at || "");
    const rightTime = Date.parse(right.created_at || "");
    return (Number.isFinite(rightTime) ? rightTime : 0) - (Number.isFinite(leftTime) ? leftTime : 0);
  });
}

export function GamificationDashboardSection() {
  const { isRtl } = useLanguage();
  const { overview, loading, error } = useGamification();
  const { records: passwordRecords } = usePasswordHistory();
  const passwordItems = useMemo(
    () => buildPasswordGamificationAdapter(passwordRecords),
    [passwordRecords]
  );
  const mergedDaily = useMemo(
    () => mergeChallenges(overview?.challenges?.daily ?? [], passwordItems.daily),
    [overview?.challenges?.daily, passwordItems.daily]
  );
  const mergedWeekly = useMemo(
    () => mergeChallenges(overview?.challenges?.weekly ?? [], passwordItems.weekly),
    [overview?.challenges?.weekly, passwordItems.weekly]
  );
  const mergedUnlockedBadges = useMemo(
    () => mergeBadges(overview?.badges?.unlocked ?? [], passwordItems.unlockedBadges),
    [overview?.badges?.unlocked, passwordItems.unlockedBadges]
  );
  const mergedLockedBadges = useMemo(
    () => mergeBadges(overview?.badges?.locked ?? [], passwordItems.lockedBadges),
    [overview?.badges?.locked, passwordItems.lockedBadges]
  );
  const mergedHistory = useMemo(
    () => mergeHistory(overview?.history ?? [], passwordItems.rewards),
    [overview?.history, passwordItems.rewards]
  );

  return (
    <div className="space-y-3" dir={isRtl ? "rtl" : "ltr"}>
      {error ? (
        <Alert className="border-amber-400/20 bg-amber-400/10 text-amber-50">
          {error}
        </Alert>
      ) : null}

      <div className="grid gap-3 xl:grid-cols-[1.2fr_0.8fr]">
        <SecurityProgressCard profile={overview?.profile ?? null} loading={loading} />
        <ActiveChallengesCard
          daily={mergedDaily}
          weekly={mergedWeekly}
        />
      </div>

      <div className="grid gap-3 xl:grid-cols-[1fr_1fr]">
        <BadgeCollectionCard
          unlocked={mergedUnlockedBadges}
          locked={mergedLockedBadges}
        />
        <RewardHistoryCard history={mergedHistory} />
      </div>
    </div>
  );
}
