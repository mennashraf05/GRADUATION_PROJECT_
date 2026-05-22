export type NotificationChannel = "Email" | "Telegram";
export type NotificationSeverity = "Critical" | "High" | "Medium" | "Low";
export type DeliveryStatus = "Sent" | "Failed" | "Skipped" | "Queued";
export type RecipientStatus = "Active" | "Paused";

export interface NotificationsSummary {
  activeRecipients: number;
  enabledChannels: number;
  criticalRoutes: number;
  failedDeliveries: number;
}

export interface NotificationRecipient {
  id: string;
  name: string;
  role: string;
  email: string;
  telegramChatId: string;
  status: RecipientStatus;
  preferredChannels: NotificationChannel[];
}

export interface NotificationChannelConfig {
  id: "email" | "telegram";
  name: string;
  provider: "SMTP" | "Telegram Bot";
  enabled: boolean;
  connected: boolean;
  status: "connected" | "not_configured" | "failed";
  description: string;
  lastTestSent: string;
  lastTestAt: string | null;
}

export interface NotificationRoutingRule {
  id: string;
  alertType: string;
  severity: NotificationSeverity;
  recipients: string;
  channels: NotificationChannel[];
  frequency: string;
  silentHoursOverride: boolean;
  status: "Active" | "Paused";
}

export interface SilentHoursPolicy {
  enabled: boolean;
  from: string;
  to: string;
  allowCritical: boolean;
  timezone: string;
}

export interface NotificationHistoryItem {
  id: string;
  alertName: string;
  recipient: string;
  channel: NotificationChannel;
  severity: NotificationSeverity;
  deliveryStatus: DeliveryStatus;
  time: string;
  failureReason: string;
}

export interface NotificationSettings {
  severityFilter: "critical" | "high-critical" | "medium-above" | "all";
  frequency: "instant" | "15-minutes" | "hourly" | "daily" | "weekly";
  emailEnabled: boolean;
  telegramEnabled: boolean;
  telegramChatId: string;
  silentHours: SilentHoursPolicy;
}

interface NotificationStore {
  recipients: NotificationRecipient[];
  channels: NotificationChannelConfig[];
  rules: NotificationRoutingRule[];
  history: NotificationHistoryItem[];
  settings: NotificationSettings;
}

const STORAGE_KEY = "sentinel_admin_notification_control_center_v3";
const LEGACY_STORAGE_KEYS = [
  "sentinel_admin_notification_control_center_v1",
  "sentinel_admin_notification_control_center_v2",
];
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

const DEFAULT_RECIPIENTS: NotificationRecipient[] = [
  {
    id: "admin-user",
    name: "Admin User",
    role: "Admin",
    email: "menna20032004@gmail.com",
    telegramChatId: "Configured server chat",
    status: "Active",
    preferredChannels: ["Email", "Telegram"],
  },
  {
    id: "security-analyst",
    name: "Security Analyst",
    role: "Analyst",
    email: "",
    telegramChatId: "",
    status: "Active",
    preferredChannels: ["Email", "Telegram"],
  },
];

const DEFAULT_CHANNELS: NotificationChannelConfig[] = [
  {
    id: "email",
    name: "Email Alerts",
    provider: "SMTP",
    enabled: true,
    connected: true,
    status: "connected",
    description: "Send admin security alerts through the configured SMTP email channel.",
    lastTestSent: "Not tested yet",
    lastTestAt: null,
  },
  {
    id: "telegram",
    name: "Telegram Alerts",
    provider: "Telegram Bot",
    enabled: true,
    connected: true,
    status: "connected",
    description: "Send high-priority security alerts to the admin or security response team through the configured Telegram bot.",
    lastTestSent: "Not tested yet",
    lastTestAt: null,
  },
];

const DEFAULT_RULES: NotificationRoutingRule[] = [
  {
    id: "pcap-critical",
    alertType: "PCAP Critical Attack",
    severity: "Critical",
    recipients: "Admin + Security Analyst",
    channels: ["Telegram", "Email"],
    frequency: "Instant",
    silentHoursOverride: true,
    status: "Active",
  },
  {
    id: "pcap-failed-job",
    alertType: "Failed PCAP Analysis Job",
    severity: "Medium",
    recipients: "Admin",
    channels: ["Email"],
    frequency: "Hourly Digest",
    silentHoursOverride: false,
    status: "Active",
  },
  {
    id: "high-risk-user",
    alertType: "High Risk User",
    severity: "High",
    recipients: "Admin",
    channels: ["Telegram"],
    frequency: "Instant",
    silentHoursOverride: true,
    status: "Active",
  },
  {
    id: "report-export-completed",
    alertType: "Report Export Completed",
    severity: "Low",
    recipients: "Admin",
    channels: ["Email"],
    frequency: "Daily Summary",
    silentHoursOverride: false,
    status: "Active",
  },
  {
    id: "password-risk-summary",
    alertType: "Password Risk Summary",
    severity: "Medium",
    recipients: "Admin",
    channels: ["Email"],
    frequency: "Daily Summary",
    silentHoursOverride: false,
    status: "Active",
  },
  {
    id: "phishing-incident-summary",
    alertType: "Phishing Incident Summary",
    severity: "High",
    recipients: "Admin + Analyst",
    channels: ["Telegram", "Email"],
    frequency: "Instant",
    silentHoursOverride: true,
    status: "Active",
  },
];

const DEFAULT_HISTORY: NotificationHistoryItem[] = [];

const DEFAULT_SETTINGS: NotificationSettings = {
  severityFilter: "medium-above",
  frequency: "hourly",
  emailEnabled: true,
  telegramEnabled: true,
  telegramChatId: "",
  silentHours: {
    enabled: true,
    from: "23:00",
    to: "08:00",
    allowCritical: true,
    timezone: "Local system time",
  },
};

function defaultStore(): NotificationStore {
  return {
    recipients: DEFAULT_RECIPIENTS,
    channels: DEFAULT_CHANNELS,
    rules: DEFAULT_RULES,
    history: DEFAULT_HISTORY,
    settings: DEFAULT_SETTINGS,
  };
}

function cloneStore(store: NotificationStore): NotificationStore {
  return JSON.parse(JSON.stringify(store)) as NotificationStore;
}

function readStore(): NotificationStore {
  if (typeof window === "undefined") return defaultStore();

  try {
    LEGACY_STORAGE_KEYS.forEach((key) => window.localStorage.removeItem(key));
    const parsed = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || "{}") as Partial<NotificationStore>;
    return {
      ...defaultStore(),
      ...parsed,
      settings: {
        ...DEFAULT_SETTINGS,
        ...(parsed.settings || {}),
        silentHours: {
          ...DEFAULT_SETTINGS.silentHours,
          ...(parsed.settings?.silentHours || {}),
        },
      },
    };
  } catch {
    return defaultStore();
  }
}

function writeStore(next: NotificationStore): NotificationStore {
  const store = cloneStore(next);
  if (typeof window !== "undefined") {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  }
  return store;
}

function mutateStore(mutator: (store: NotificationStore) => void): NotificationStore {
  const store = readStore();
  mutator(store);
  return writeStore(store);
}

function buildAdminJsonFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  if (typeof window !== "undefined") {
    const adminToken = window.localStorage.getItem("sentinel_admin_token");
    const userToken = window.localStorage.getItem("sentinel_auth_token");
    const token = adminToken || userToken;
    if (token) headers.set("Authorization", `Bearer ${token}`);
  }

  return {
    ...init,
    credentials: "include",
    headers,
  };
}

function endpoint(path: string): string {
  return `${API_BASE}${path}`;
}

async function tryJsonFetch<T>(path: string, init?: RequestInit): Promise<T | null> {
  try {
    const response = await fetch(endpoint(path), buildAdminJsonFetchInit(init));
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

async function requestJson<T extends { message?: string; success?: boolean }>(
  path: string,
  init?: RequestInit
): Promise<{ ok: boolean; data: T | null; message: string }> {
  try {
    const response = await fetch(endpoint(path), buildAdminJsonFetchInit(init));
    const text = await response.text();
    let data: T | null = null;
    if (text) {
      try {
        data = JSON.parse(text) as T;
      } catch {
        data = null;
      }
    }
    return {
      ok: response.ok,
      data,
      message:
        data?.message ||
        (response.status === 401
          ? "Admin authorization required. Sign in to the Admin Console again."
          : `Backend returned HTTP ${response.status}.`),
    };
  } catch (error) {
    return {
      ok: false,
      data: null,
      message: error instanceof Error ? error.message : "Backend request failed.",
    };
  }
}

function formatNow(): string {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date());
}

function formatLastTest(value: string | null | undefined): string {
  if (!value) return "Not tested yet";
  const testedAt = new Date(value);
  if (Number.isNaN(testedAt.getTime())) return "Not tested yet";

  const diffMs = Date.now() - testedAt.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return "less than 1 min ago";
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours} hr ago`;

  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(testedAt);
}

function channelIdFromChannel(channel: NotificationChannel): NotificationChannelConfig["id"] {
  if (channel === "Email") return "email";
  return "telegram";
}

function calculateSummary(store: NotificationStore): NotificationsSummary {
  return {
    activeRecipients: store.recipients.filter((recipient) => recipient.status === "Active").length,
    enabledChannels: store.channels.filter((channel) => channel.enabled).length,
    criticalRoutes: store.rules.filter(
      (rule) => rule.status === "Active" && (rule.severity === "Critical" || rule.silentHoursOverride)
    ).length,
    failedDeliveries: store.history.filter((item) => item.deliveryStatus === "Failed").length,
  };
}

function mapBackendChannel(raw: any, fallback: NotificationChannelConfig): NotificationChannelConfig {
  const status = String(raw?.status || "").toLowerCase();
  const configured = raw?.configured;
  const lastTestAt = typeof raw?.lastTestAt === "string" && raw.lastTestAt.trim()
    ? raw.lastTestAt
    : fallback.lastTestAt;
  const normalizedStatus: NotificationChannelConfig["status"] =
    status === "failed" ? "failed" : status === "connected" || status === "active" ? "connected" : "not_configured";
  return {
    ...fallback,
    enabled: Boolean(raw?.enabled),
    connected: raw?.verified === true || raw?.connected === true || configured === true || status === "active" || status === "connected",
    status: normalizedStatus,
    description: typeof raw?.description === "string" && raw.description.trim() ? raw.description : fallback.description,
    lastTestAt,
    lastTestSent: formatLastTest(lastTestAt),
  };
}

async function refreshBackendChannels(store: NotificationStore): Promise<NotificationStore> {
  const payload =
    await tryJsonFetch<{ channels?: any[] }>("/api/admin/notification-control/status") ||
    await tryJsonFetch<{ channels?: any[] }>("/api/integrations/channels");
  if (!payload?.channels?.length) return store;

  const nextChannels = store.channels.map((channel) => {
    const raw = payload.channels?.find((item) => String(item?.id || "").toLowerCase() === channel.id);
    return raw ? mapBackendChannel(raw, channel) : channel;
  });

  return writeStore({ ...store, channels: nextChannels });
}

async function refreshBackendRecipients(store: NotificationStore): Promise<NotificationStore> {
  const statusPayload = await tryJsonFetch<{
    recipient?: { id?: string; name?: string; email?: string; role?: string; telegram_chat_id?: string };
  }>("/api/admin/notification-control/status");
  const adminPayload = statusPayload?.recipient
    ? null
    : await tryJsonFetch<{ admin?: { id?: number; name?: string; email?: string; role?: string } }>("/api/admin/auth/me");
  const userPayload = adminPayload?.admin
    ? null
    : await tryJsonFetch<{ user?: { id?: number; full_name?: string; email?: string; phone?: string } }>("/api/auth/me");

  const account = statusPayload?.recipient || adminPayload?.admin || userPayload?.user;
  const email = String(account?.email || "").trim();
  if (!email) return store;

  const name = String((account as any)?.name || (account as any)?.full_name || email.split("@")[0]).trim();
  const role = String((account as any)?.role || "Admin").trim();
  const primary: NotificationRecipient = {
    id: "current-account",
    name,
    role,
    email,
    telegramChatId: String((account as any)?.telegram_chat_id || "").trim(),
    status: "Active",
    preferredChannels: ["Email", "Telegram"],
  };

  const customRecipients = store.recipients.filter(
    (recipient) => recipient.id !== "admin-user" && recipient.id !== "current-account" && recipient.email.trim()
  );

  return writeStore({ ...store, recipients: [primary, ...customRecipients] });
}

export async function refreshNotificationControlCenter(): Promise<NotificationStore> {
  let store = readStore();
  store = await refreshBackendRecipients(store);
  store = await refreshBackendChannels(store);
  return cloneStore(store);
}

function normalizeSettings(raw: any): NotificationSettings | null {
  if (!raw || typeof raw !== "object") return null;
  const severityFilter = String(raw.severityFilter || "");
  const frequency = String(raw.frequency || "");
  const silentHours = raw.silentHours && typeof raw.silentHours === "object" ? raw.silentHours : {};
  const validSeverity: NotificationSettings["severityFilter"][] = ["critical", "high-critical", "medium-above", "all"];
  const validFrequency: NotificationSettings["frequency"][] = ["instant", "15-minutes", "hourly", "daily", "weekly"];

  return {
    severityFilter: validSeverity.includes(severityFilter as NotificationSettings["severityFilter"])
      ? severityFilter as NotificationSettings["severityFilter"]
      : DEFAULT_SETTINGS.severityFilter,
    frequency: validFrequency.includes(frequency as NotificationSettings["frequency"])
      ? frequency as NotificationSettings["frequency"]
      : DEFAULT_SETTINGS.frequency,
    silentHours: {
      ...DEFAULT_SETTINGS.silentHours,
      enabled: typeof silentHours.enabled === "boolean" ? silentHours.enabled : DEFAULT_SETTINGS.silentHours.enabled,
      from: typeof silentHours.from === "string" ? silentHours.from : DEFAULT_SETTINGS.silentHours.from,
      to: typeof silentHours.to === "string" ? silentHours.to : DEFAULT_SETTINGS.silentHours.to,
      allowCritical: typeof silentHours.allowCritical === "boolean" ? silentHours.allowCritical : DEFAULT_SETTINGS.silentHours.allowCritical,
      timezone: typeof silentHours.timezone === "string" ? silentHours.timezone : DEFAULT_SETTINGS.silentHours.timezone,
    },
    emailEnabled: typeof raw.emailEnabled === "boolean" ? raw.emailEnabled : DEFAULT_SETTINGS.emailEnabled,
    telegramEnabled: typeof raw.telegramEnabled === "boolean" ? raw.telegramEnabled : DEFAULT_SETTINGS.telegramEnabled,
    telegramChatId: typeof raw.telegramChatId === "string" ? raw.telegramChatId : DEFAULT_SETTINGS.telegramChatId,
  };
}

export async function getNotificationsSummary(): Promise<NotificationsSummary> {
  return calculateSummary(readStore());
}

export async function getNotificationRecipients(): Promise<NotificationRecipient[]> {
  return cloneStore(readStore()).recipients;
}

export async function getNotificationChannels(): Promise<NotificationChannelConfig[]> {
  return cloneStore(readStore()).channels;
}

export async function getNotificationRules(): Promise<NotificationRoutingRule[]> {
  return cloneStore(readStore()).rules;
}

export async function getNotificationHistory(): Promise<NotificationHistoryItem[]> {
  return cloneStore(readStore()).history;
}

export async function clearNotificationHistory(): Promise<NotificationHistoryItem[]> {
  return mutateStore((store) => {
    store.history = [];
  }).history;
}

export async function getNotificationSettings(): Promise<NotificationSettings> {
  const payload = await tryJsonFetch<{ settings?: NotificationSettings }>("/api/admin/notification-control/settings");
  const backendSettings = normalizeSettings(payload?.settings);
  if (backendSettings) {
    mutateStore((store) => {
      store.settings = backendSettings;
    });
    return backendSettings;
  }
  return cloneStore(readStore()).settings;
}

export async function saveNotificationSettings(settings: NotificationSettings): Promise<{ ok: true }> {
  const normalized = normalizeSettings(settings) || DEFAULT_SETTINGS;
  const payload = await requestJson<{ success?: boolean; message?: string; settings?: NotificationSettings }>(
    "/api/admin/notification-control/settings",
    {
      method: "PATCH",
      body: JSON.stringify(normalized),
    }
  );
  if (!payload.ok || payload.data?.success === false) {
    throw new Error(payload.message);
  }
  mutateStore((store) => {
    store.settings = normalizeSettings(payload.data?.settings) || normalized;
  });
  return { ok: true };
}

export async function updateNotificationRecipient(
  recipientId: string,
  updates: Partial<NotificationRecipient>
): Promise<NotificationRecipient[]> {
  return mutateStore((store) => {
    store.recipients = store.recipients.map((recipient) =>
      recipient.id === recipientId ? { ...recipient, ...updates } : recipient
    );
  }).recipients;
}

export async function addNotificationRecipient(): Promise<NotificationRecipient[]> {
  return mutateStore((store) => {
    const number = store.recipients.length + 1;
    store.recipients = [
      ...store.recipients,
      {
        id: `responder-${Date.now()}`,
        name: `Responder ${number}`,
        role: "Responder",
        email: `responder${number}@sentinel.ai`,
        telegramChatId: "",
        status: "Paused",
        preferredChannels: ["Email"],
      },
    ];
  }).recipients;
}

export async function addNotificationRule(): Promise<NotificationRoutingRule[]> {
  return mutateStore((store) => {
    store.rules = [
      ...store.rules,
      {
        id: `routing-rule-${Date.now()}`,
        alertType: "New Security Alert",
        severity: "Medium",
        recipients: "Admin",
        channels: ["Email"],
        frequency: "Instant",
        silentHoursOverride: false,
        status: "Paused",
      },
    ];
  }).rules;
}

export async function updateNotificationRule(
  ruleId: string,
  updates: Partial<NotificationRoutingRule>
): Promise<NotificationRoutingRule[]> {
  return mutateStore((store) => {
    store.rules = store.rules.map((rule) => (rule.id === ruleId ? { ...rule, ...updates } : rule));
  }).rules;
}

export async function updateNotificationChannel(
  channelId: NotificationChannelConfig["id"],
  enabled: boolean
): Promise<NotificationChannelConfig[]> {
  if (channelId === "email") {
    await tryJsonFetch(`/api/integrations/channels/${channelId}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    });
  } else if (channelId === "telegram") {
    const currentSettings = await getNotificationSettings();
    await saveNotificationSettings({ ...currentSettings, telegramEnabled: enabled });
  }

  return mutateStore((store) => {
    store.channels = store.channels.map((channel) =>
      channel.id === channelId ? { ...channel, enabled } : channel
    );
  }).channels;
}

export async function sendTestNotification(input: {
  recipientId: string;
  channel: NotificationChannel;
  severity: NotificationSeverity;
}): Promise<{ status: "Success" | "Failed" | "Pending"; message: string; history: NotificationHistoryItem[]; channels: NotificationChannelConfig[] }> {
  const store = readStore();
  const recipient = store.recipients.find((item) => item.id === input.recipientId);
  const channel = store.channels.find((item) => item.id === channelIdFromChannel(input.channel));
  let status: DeliveryStatus = "Sent";
  let failureReason = "-";
  let successMessage = `${input.channel} test notification sent successfully.`;

  if (!recipient || recipient.status !== "Active") {
    status = "Skipped";
    failureReason = "Recipient is not active";
  } else if (!channel?.enabled || !channel.connected) {
    status = "Failed";
    failureReason = `${input.channel} channel is disabled or not connected`;
  } else {
    const deliveryResult = await requestJson<{ success?: boolean; message?: string; tested_at?: string }>("/api/admin/notification-control/test", {
      method: "POST",
      body: JSON.stringify({
        recipient: {
          id: recipient.id,
          name: recipient.name,
          email: recipient.email,
          telegram_chat_id: recipient.telegramChatId,
        },
        channel: input.channel.toLowerCase(),
        severity: input.severity,
      }),
    });
    if (!deliveryResult.ok || deliveryResult.data?.success === false) {
      status = "Failed";
      failureReason = deliveryResult.message;
    } else if (deliveryResult.data?.message) {
      successMessage = deliveryResult.data.message;
    }
    const testedAt = status === "Sent" ? (deliveryResult.data?.tested_at || new Date().toISOString()) : null;
    if (testedAt) {
      channel.lastTestAt = testedAt;
      channel.lastTestSent = formatLastTest(testedAt);
    }
  }

  const alertName = `Test ${input.severity} ${input.channel} Alert`;
  const historyItem: NotificationHistoryItem = {
    id: `test-${Date.now()}`,
    alertName,
    recipient: recipient?.name || "Selected recipient",
    channel: input.channel,
    severity: input.severity,
    deliveryStatus: status,
    time: formatNow(),
    failureReason,
  };

  const nextStore = mutateStore((current) => {
    current.history = [historyItem, ...current.history].slice(0, 50);
    current.channels = current.channels.map((item) =>
      item.id === channelIdFromChannel(input.channel)
        ? {
            ...item,
            status: status === "Sent" ? "connected" : "failed",
            connected: status === "Sent" ? true : item.connected,
            lastTestAt: status === "Sent" ? channel?.lastTestAt || new Date().toISOString() : item.lastTestAt,
            lastTestSent: status === "Sent" ? formatLastTest(channel?.lastTestAt) : item.lastTestSent,
          }
        : item
    );
  });

  return {
    status: status === "Sent" ? "Success" : status === "Queued" ? "Pending" : "Failed",
    message:
      status === "Sent"
        ? successMessage
        : `${input.channel} test notification was ${status.toLowerCase()}: ${failureReason}.`,
    history: nextStore.history,
    channels: nextStore.channels,
  };
}
