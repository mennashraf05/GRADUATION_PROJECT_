export const RECENT_PCAP_ALERT_CACHE_KEY =
  "sentinel_recent_pcap_alert_payload";
export const RECENT_PCAP_ALERT_UPDATED_AT_KEY =
  "sentinel_pcap_alerts_updated_at";
export const RECENT_PCAP_ALERT_EVENT = "sentinel:pcap-alerts-updated";
export const ACTIVE_RECENT_PCAP_ALERT_SCOPE_KEY =
  "sentinel_active_recent_pcap_alert_scope";
const PCAP_REPORT_SNAPSHOT_KEY_PREFIX = "sentinel_pcap_report_snapshot:";

export type PcapReportSnapshotEntry = {
  jobId: string;
  updatedAt: string | null;
  report: Record<string, unknown>;
};

export type AlertSeverity = "normal" | "low" | "medium" | "high" | "critical";
export type DashboardPcapAlertStatus = "new" | "reviewed";
export type DashboardPcapAlertType = "analysis_result" | "pcap_alert";

export interface DashboardPcapAlert {
  id: string;
  job_id: string | null;
  type: DashboardPcapAlertType;
  status: DashboardPcapAlertStatus;
  title: string;
  message: string;
  severity: AlertSeverity;
  risk_label: string;
  threats_count: number;
  flows_analyzed: number;
  top_pattern: string | null;
  filename: string | null;
  created_at: string;
  relative_time: string;
  source: "pcap";
  source_type?: string;
  attack_type?: string;
  protocol?: string;
  src_ip?: string;
  dst_ip?: string;
  user_id?: number;
}

type RawRecord = Record<string, unknown>;

type CacheScopeUser = {
  id?: unknown;
  email?: unknown;
};

function firstText(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (value == null) {
      continue;
    }
    const text = String(value).trim();
    if (text) {
      return text;
    }
  }
  return undefined;
}

function toOptionalInt(value: unknown): number | undefined {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return undefined;
  }
  return Math.round(numeric);
}

function toPositiveInt(value: unknown): number {
  const numeric = toOptionalInt(value);
  return numeric && numeric > 0 ? numeric : 0;
}

function toOptionalObject(value: unknown): RawRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as RawRecord)
    : undefined;
}

function toPathFilename(value: unknown): string | undefined {
  const text = firstText(value);
  if (!text) {
    return undefined;
  }
  const normalized = text.replace(/\\/g, "/");
  const name = normalized.split("/").filter(Boolean).pop();
  return name || undefined;
}

function normalizeEmailScope(value: unknown): string | null {
  const text = firstText(value);
  if (!text) {
    return null;
  }
  return `email:${text.toLowerCase()}`;
}

function normalizeUserScope(value: unknown): string | null {
  const userId = toOptionalInt(value);
  if (!userId || userId <= 0) {
    return null;
  }
  return `user:${userId}`;
}

function normalizeCacheScope(value: unknown): string | null {
  const text = firstText(value);
  return text || null;
}

function getCurrentRecentPcapAlertScope(): string | null {
  if (typeof window === "undefined") {
    return null;
  }

  return (
    normalizeCacheScope(
      window.localStorage.getItem(ACTIVE_RECENT_PCAP_ALERT_SCOPE_KEY)
    ) ||
    normalizeEmailScope(window.localStorage.getItem("userEmail")) ||
    normalizeEmailScope(window.localStorage.getItem("verifiedEmail"))
  );
}

function resolveCacheScope(
  alerts: DashboardPcapAlert[] = [],
  fallbackUser?: CacheScopeUser | null
): string | null {
  for (const alert of alerts) {
    const alertScope = normalizeUserScope(alert.user_id);
    if (alertScope) {
      return alertScope;
    }
  }

  return (
    normalizeUserScope(fallbackUser?.id) ||
    normalizeEmailScope(fallbackUser?.email) ||
    getCurrentRecentPcapAlertScope()
  );
}

export function setActiveRecentPcapAlertScopeForUser(
  user?: CacheScopeUser | null
): void {
  if (typeof window === "undefined") {
    return;
  }

  const scope =
    normalizeUserScope(user?.id) || normalizeEmailScope(user?.email);

  if (scope) {
    window.localStorage.setItem(ACTIVE_RECENT_PCAP_ALERT_SCOPE_KEY, scope);
    return;
  }

  window.localStorage.removeItem(ACTIVE_RECENT_PCAP_ALERT_SCOPE_KEY);
}

export function clearRecentPcapAlertSessionCache(): void {
  if (typeof window === "undefined") {
    return;
  }

  const keysToRemove: string[] = [];
  for (let index = 0; index < window.localStorage.length; index += 1) {
    const key = window.localStorage.key(index);
    if (!key) {
      continue;
    }
    if (
      key === RECENT_PCAP_ALERT_CACHE_KEY ||
      key === RECENT_PCAP_ALERT_UPDATED_AT_KEY ||
      key === ACTIVE_RECENT_PCAP_ALERT_SCOPE_KEY ||
      key.startsWith(PCAP_REPORT_SNAPSHOT_KEY_PREFIX)
    ) {
      keysToRemove.push(key);
    }
  }

  keysToRemove.forEach((key) => {
    window.localStorage.removeItem(key);
  });
}

function severityRank(severity: AlertSeverity): number {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  if (severity === "low") return 1;
  return 0;
}

function clampConfidencePercent(value: unknown): number | null {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return null;
  }
  if (numeric > 1) {
    return Math.max(0, Math.min(100, Math.round(numeric)));
  }
  return Math.max(0, Math.min(100, Math.round(numeric * 100)));
}

export function parseTimestampEpoch(value: unknown): number {
  if (value == null || value === "") {
    return 0;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      return 0;
    }
    return value > 1e11 ? value : value * 1000;
  }

  const raw = String(value).trim();
  if (!raw) {
    return 0;
  }

  if (/^-?\d+(\.\d+)?$/.test(raw)) {
    const numeric = Number(raw);
    if (!Number.isFinite(numeric)) {
      return 0;
    }
    return numeric > 1e11 ? numeric : numeric * 1000;
  }

  const normalized =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(raw)
      ? `${raw}Z`
      : raw;
  const parsed = new Date(normalized).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function toIsoTimestamp(value: unknown, fallback?: unknown): string {
  const timestamp =
    parseTimestampEpoch(value) ||
    parseTimestampEpoch(fallback) ||
    Date.now();
  return new Date(timestamp).toISOString();
}

export function formatRelativeTime(value: unknown): string {
  const timestamp = parseTimestampEpoch(value);
  if (!timestamp) {
    return "just now";
  }

  const diffMs = Date.now() - timestamp;
  const diffMinutes = Math.max(0, Math.floor(diffMs / 60000));
  if (diffMinutes < 1) return "just now";
  if (diffMinutes < 60) return `${diffMinutes} min ago`;

  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) {
    return `${diffHours} hour${diffHours === 1 ? "" : "s"} ago`;
  }

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) {
    return `${diffDays} day${diffDays === 1 ? "" : "s"} ago`;
  }

  return new Date(timestamp).toLocaleDateString();
}

export function normalizeAlertSeverity(raw: unknown): AlertSeverity {
  const value = String(raw ?? "").trim().toLowerCase();
  if (value === "critical") return "critical";
  if (value === "high" || value === "danger" || value === "error") return "high";
  if (
    value === "medium" ||
    value === "warning" ||
    value === "suspicious"
  ) {
    return "medium";
  }
  if (value === "low" || value === "info" || value === "informational") {
    return "low";
  }
  return "normal";
}

export function normalizeAlertStatus(
  raw: unknown
): DashboardPcapAlertStatus {
  return String(raw ?? "").trim().toLowerCase() === "reviewed"
    ? "reviewed"
    : "new";
}

export function humanizeIndicatorLabel(raw: unknown): string {
  const value = String(raw ?? "").trim();
  if (!value) return "General";

  const normalized = value
    .replace(/[\s-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();

  const specialCases: Record<string, string> = {
    ddos: "DDoS",
    dos: "DoS",
    dos_hulk: "DoS Hulk",
    syn_flood: "SYN Flood",
    dns_tunneling: "DNS Tunneling",
    port_scan: "Port Scan",
    brute_force: "Brute Force",
    data_exfiltration: "Data Exfiltration",
    failed_connections: "Failed Connections",
  };

  if (specialCases[normalized]) {
    return specialCases[normalized];
  }

  const acronyms: Record<string, string> = {
    ddos: "DDoS",
    dos: "DoS",
    dns: "DNS",
    syn: "SYN",
    tcp: "TCP",
    udp: "UDP",
    tls: "TLS",
    ssl: "SSL",
    http: "HTTP",
    https: "HTTPS",
    ip: "IP",
  };

  return normalized
    .split("_")
    .filter(Boolean)
    .map((part) => {
      const lowered = part.toLowerCase();
      if (acronyms[lowered]) {
        return acronyms[lowered];
      }
      return `${part.charAt(0).toUpperCase()}${part.slice(1).toLowerCase()}`;
    })
    .join(" ");
}

function deriveAlertType(rawType: unknown, raw: RawRecord): DashboardPcapAlertType {
  const explicit = String(rawType ?? "").trim().toLowerCase();
  const hasSummarySignals =
    toPositiveInt(raw.flows_analyzed) > 0 ||
    toPositiveInt(raw.threats_count) > 0 ||
    Boolean(firstText(raw.top_pattern, raw.filename, raw.risk_label));

  if (
    explicit === "pcap_alert" ||
    explicit === "alert" ||
    explicit === "finding" ||
    explicit === "cluster"
  ) {
    return "pcap_alert";
  }

  if (explicit === "analysis_result" && hasSummarySignals) {
    return "analysis_result";
  }

  if (explicit === "analysis_result") {
    return "pcap_alert";
  }

  return hasSummarySignals ? "analysis_result" : "pcap_alert";
}

function buildDetailTitle(attackType: string, severity: AlertSeverity): string {
  const label = humanizeIndicatorLabel(attackType);
  if (severity === "critical") {
    return `${label} requires immediate review`;
  }
  if (severity === "high") {
    return `${label} activity detected`;
  }
  if (severity === "medium") {
    return `Potential ${label} activity`;
  }
  if (severity === "low") {
    return `${label} activity observed`;
  }
  return `PCAP finding: ${label}`;
}

function buildSummaryTitle(topPattern: string | null, severity: AlertSeverity): string {
  if (topPattern) {
    const label = humanizeIndicatorLabel(topPattern);
    if (severity === "critical") {
      return `${label} dominated this PCAP session`;
    }
    if (severity === "high") {
      return `${label} was the top promoted pattern`;
    }
    if (severity === "medium") {
      return `${label} was promoted for analyst review`;
    }
    if (severity === "low") {
      return `${label} was the main observed pattern`;
    }
    return `${label} summary is ready for review`;
  }

  if (severity === "critical") return "Critical PCAP analysis result";
  if (severity === "high") return "High-risk PCAP analysis result";
  if (severity === "medium") return "PCAP analysis result needs review";
  if (severity === "low") return "Capture review completed";
  return "Network activity reviewed";
}

function isCalmRiskLabel(riskLabel: string): boolean {
  return /low|normal|no significant|baseline|stable/i.test(riskLabel);
}

function buildEndpointText(
  srcIp?: string,
  dstIp?: string,
  dstPort?: number,
  protocol?: string
): string | null {
  const segments: string[] = [];
  if (srcIp) {
    segments.push(srcIp);
  }
  if (dstIp) {
    segments.push(`to ${dstIp}`);
  }
  if (protocol) {
    segments.push(`over ${protocol}`);
  }
  if (dstPort && dstPort > 0) {
    segments.push(`port ${dstPort}`);
  }
  return segments.length > 0 ? segments.join(" ") : null;
}

function buildDetailMessage(
  attackType: string,
  srcIp?: string,
  dstIp?: string,
  protocol?: string,
  dstPort?: number,
  confidence?: unknown,
  reason?: unknown,
  count?: unknown
): string {
  const detail = firstText(reason);
  if (detail) {
    return detail.endsWith(".") ? detail : `${detail}.`;
  }

  const attackLabel = humanizeIndicatorLabel(attackType);
  const endpoint = buildEndpointText(srcIp, dstIp, dstPort, protocol);
  const occurrenceCount = toPositiveInt(count);
  const confidencePercent = clampConfidencePercent(confidence);

  const parts: string[] = [`${attackLabel} indicators were observed`];
  if (endpoint) {
    parts.push(endpoint);
  }
  if (confidencePercent != null) {
    parts.push(`at ${confidencePercent}% confidence`);
  }
  if (occurrenceCount > 1) {
    parts.push(`across ${occurrenceCount} correlated flows`);
  }

  const message = parts.join(" ");
  return message.endsWith(".") ? message : `${message}.`;
}

function buildSummaryMessage(
  narrative: string | undefined,
  flowsAnalyzed: number,
  threatsCount: number,
  riskLabel: string
): string {
  const parts: string[] = [];
  if (narrative) {
    parts.push(narrative.replace(/\.+$/, ""));
  }

  const metrics: string[] = [];
  if (flowsAnalyzed > 0) {
    metrics.push(`${flowsAnalyzed} flows were analyzed`);
  }
  if (threatsCount > 0) {
    metrics.push(
      `${threatsCount} promoted finding${threatsCount === 1 ? "" : "s"} were recorded`
    );
  }
  if (riskLabel) {
    if (!isCalmRiskLabel(riskLabel)) {
      metrics.push(`overall risk was assessed as ${riskLabel}`);
    } else if (!narrative) {
      metrics.push("traffic remained within the expected operating baseline");
    }
  }

  if (metrics.length > 0) {
    parts.push(metrics.join(", "));
  }

  const message = parts.join(". ").trim();
  if (!message) {
    return "PCAP analysis completed and is ready for review.";
  }
  return message.endsWith(".") ? message : `${message}.`;
}

function normalizeProtocol(raw: unknown): string | undefined {
  const value = firstText(raw);
  return value ? value.toUpperCase() : undefined;
}

export function normalizeDashboardPcapAlert(
  raw: RawRecord,
  index = 0
): DashboardPcapAlert {
  const createdAt = toIsoTimestamp(
    raw.created_at ?? raw.timestamp ?? raw.time ?? raw.ts,
    Date.now()
  );
  const attackType = firstText(raw.attack_type, raw.label, raw.ml_label);
  const protocol = normalizeProtocol(
    raw.protocol ??
      raw.zeek_proto ??
      raw.proto ??
      raw.service ??
      raw.zeek_service
  );
  const srcIp = firstText(raw.src_ip, raw.source_ip);
  const dstIp = firstText(raw.dst_ip, raw.dest_ip);
  const flowsAnalyzed = toPositiveInt(raw.flows_analyzed);
  const threatsCount = toPositiveInt(raw.threats_count);
  const topPattern = firstText(raw.top_pattern);
  const filename = firstText(raw.filename) ?? toPathFilename(raw.pcap_path);
  const severity = normalizeAlertSeverity(raw.severity);
  const type = deriveAlertType(raw.type, raw);
  const defaultTitle =
    type === "analysis_result"
      ? buildSummaryTitle(topPattern ?? attackType ?? null, severity)
      : buildDetailTitle(attackType ?? "General", severity);
  const defaultMessage =
    type === "analysis_result"
      ? buildSummaryMessage(
          firstText(raw.message, raw.summary, raw.security_summary),
          flowsAnalyzed,
          threatsCount,
          firstText(raw.risk_label, raw.risk_display, raw.risk_level) || ""
        )
      : buildDetailMessage(
          attackType ?? "General",
          srcIp,
          dstIp,
          protocol,
          toPositiveInt(raw.dst_port ?? raw.destination_port),
          raw.confidence,
          raw.message ?? raw.reason,
          raw.count_flows ?? raw.count
        );

  const userId = toOptionalInt(raw.user_id);

  return {
    id:
      firstText(raw.id) ||
      `pcap-alert-${index}-${type}-${parseTimestampEpoch(createdAt)}`,
    job_id: firstText(raw.job_id) || null,
    type,
    status: normalizeAlertStatus(raw.status),
    title: firstText(raw.title) || defaultTitle,
    message: firstText(raw.message) || defaultMessage,
    severity,
    risk_label: firstText(raw.risk_label, raw.risk_display, raw.risk_level) || "",
    threats_count: threatsCount,
    flows_analyzed: flowsAnalyzed,
    top_pattern: topPattern || null,
    filename: filename || null,
    created_at: createdAt,
    relative_time: firstText(raw.relative_time) || formatRelativeTime(createdAt),
    source: "pcap",
    source_type: firstText(raw.source_type),
    attack_type: attackType,
    protocol,
    src_ip: srcIp,
    dst_ip: dstIp,
    user_id: userId && userId > 0 ? userId : undefined,
  };
}

function pickTopPattern(
  summaryRaw: RawRecord,
  alerts: RawRecord[],
  clusters: RawRecord[]
): string | null {
  const topRisk = toOptionalObject(summaryRaw.top_risk);
  const direct = firstText(
    topRisk?.name,
    summaryRaw.top_pattern,
    alerts[0]?.attack_type,
    alerts[0]?.label,
    alerts[0]?.ml_label,
    clusters[0]?.attack_type,
    clusters[0]?.label
  );
  return direct || null;
}

function buildSummaryAlertFromReport(
  rawReport: RawRecord,
  options: {
    jobId?: string | null;
    uploadName?: string | null;
    fallbackCreatedAt?: unknown;
  } = {}
): DashboardPcapAlert {
  const summaryRaw = toOptionalObject(rawReport.summary) || {};
  const metaRaw = toOptionalObject(rawReport.meta) || {};
  const alerts = Array.isArray(rawReport.alerts)
    ? (rawReport.alerts.filter(
        (item): item is RawRecord =>
          Boolean(item) && typeof item === "object" && !Array.isArray(item)
      ) as RawRecord[])
    : [];
  const clusters = Array.isArray(rawReport.clusters)
    ? (rawReport.clusters.filter(
        (item): item is RawRecord =>
          Boolean(item) && typeof item === "object" && !Array.isArray(item)
      ) as RawRecord[])
    : [];

  const createdAt = toIsoTimestamp(
    metaRaw.generated_at ?? summaryRaw.generated_at,
    options.fallbackCreatedAt
  );
  const flowsAnalyzed = toPositiveInt(summaryRaw.total_flows);
  const threatsCount = Math.max(
    toPositiveInt(summaryRaw.alerts_count),
    toPositiveInt(summaryRaw.alerts),
    alerts.length,
    clusters.length
  );
  const topPattern = pickTopPattern(summaryRaw, alerts, clusters);
  const riskLabel =
    firstText(summaryRaw.risk_display, summaryRaw.risk_level) || "Normal";
  const severity = normalizeAlertSeverity(
    summaryRaw.risk_level ??
      toOptionalObject(summaryRaw.top_risk)?.severity ??
      (threatsCount > 0 ? "medium" : "normal")
  );
  const filename =
    firstText(options.uploadName) || toPathFilename(metaRaw.pcap_path) || null;
  const srcIp = firstText(
    Array.isArray(summaryRaw.top_attackers)
      ? toOptionalObject(summaryRaw.top_attackers[0])?.src_ip
      : undefined
  );

  return normalizeDashboardPcapAlert(
    {
      id: `${firstText(options.jobId) || "pcap"}-summary`,
      job_id: firstText(options.jobId) || null,
      type: "analysis_result",
      status: "new",
      title: buildSummaryTitle(topPattern, severity),
      message: buildSummaryMessage(
        firstText(summaryRaw.security_summary, summaryRaw.summary),
        flowsAnalyzed,
        threatsCount,
        riskLabel
      ),
      severity,
      risk_label: riskLabel,
      threats_count: threatsCount,
      flows_analyzed: flowsAnalyzed,
      top_pattern: topPattern,
      filename,
      created_at: createdAt,
      attack_type: topPattern,
      src_ip: srcIp,
      source_type: "pcap_job_summary",
    },
    0
  );
}

function buildDetailAlertsFromReport(
  rawReport: RawRecord,
  options: {
    jobId?: string | null;
    uploadName?: string | null;
    fallbackCreatedAt?: unknown;
    maxItems?: number;
  } = {}
): DashboardPcapAlert[] {
  const fallbackCreatedAt = options.fallbackCreatedAt;
  const rawAlerts = Array.isArray(rawReport.alerts)
    ? rawReport.alerts
    : [];
  const rawClusters = Array.isArray(rawReport.clusters)
    ? rawReport.clusters
    : [];
  const sourceItems =
    rawAlerts.length > 0 ? rawAlerts : rawClusters;
  const sourceTypePrefix = rawAlerts.length > 0 ? "pcap_job_alert" : "pcap_job_cluster";
  const maxItems = Math.max(0, options.maxItems ?? 12);

  const normalized = sourceItems
    .filter(
      (item): item is RawRecord =>
        Boolean(item) && typeof item === "object" && !Array.isArray(item)
    )
    .map((item, index) => {
      const topDstPorts = Array.isArray(item.top_dst_ports)
        ? item.top_dst_ports
        : [];
      const firstPort = toOptionalObject(topDstPorts[0])?.port;

      return normalizeDashboardPcapAlert(
        {
          id:
            firstText(item.id) ||
            `${firstText(options.jobId) || "pcap"}-${sourceTypePrefix}-${index}`,
          job_id: firstText(options.jobId) || null,
          type: "pcap_alert",
          status: "new",
          title: buildDetailTitle(
            firstText(item.attack_type, item.label, item.ml_label) || "General",
            normalizeAlertSeverity(
              item.severity ?? item.verdict ?? item.decision
            )
          ),
          message: buildDetailMessage(
            firstText(item.attack_type, item.label, item.ml_label) || "General",
            firstText(item.src_ip, item.source_ip),
            firstText(item.dst_ip, item.dest_ip),
            normalizeProtocol(
              item.protocol ??
                item.zeek_proto ??
                item.proto ??
                item.service ??
                item.zeek_service
            ),
            toPositiveInt(item.dst_port ?? item.destination_port ?? firstPort),
            item.confidence ??
              item.threat_confidence ??
              item.max_threat_confidence ??
              item.ml_confidence ??
              item.max_ml_confidence,
            item.reason,
            item.count_flows ?? item.count,
          ),
          severity: normalizeAlertSeverity(
            item.severity ?? item.verdict ?? item.decision
          ),
          risk_label: firstText(item.verdict, item.decision, item.severity) || "",
          threats_count: Math.max(
            1,
            toPositiveInt(item.count_flows ?? item.count)
          ),
          flows_analyzed: 0,
          top_pattern: null,
          filename: firstText(options.uploadName) || null,
          created_at: toIsoTimestamp(
            item.time ?? item.timestamp ?? item.ts,
            fallbackCreatedAt
          ),
          relative_time: formatRelativeTime(
            item.time ?? item.timestamp ?? item.ts ?? fallbackCreatedAt
          ),
          source_type: sourceTypePrefix,
          attack_type: firstText(item.attack_type, item.label, item.ml_label),
          protocol: normalizeProtocol(
            item.protocol ??
              item.zeek_proto ??
              item.proto ??
              item.service ??
              item.zeek_service
          ),
          src_ip: firstText(item.src_ip, item.source_ip),
          dst_ip: firstText(item.dst_ip, item.dest_ip),
        },
        index + 1
      );
    })
    .sort((left, right) => {
      const timeDiff =
        parseTimestampEpoch(right.created_at) -
        parseTimestampEpoch(left.created_at);
      if (timeDiff !== 0) {
        return timeDiff;
      }
      return severityRank(right.severity) - severityRank(left.severity);
    });

  return maxItems > 0 ? normalized.slice(0, maxItems) : normalized;
}

export function buildDashboardAlertsFromReport(
  rawReport: RawRecord,
  options: {
    jobId?: string | null;
    uploadName?: string | null;
    fallbackCreatedAt?: unknown;
    maxItems?: number;
  } = {}
): DashboardPcapAlert[] {
  const maxItems = Math.max(1, options.maxItems ?? 10);
  const summaryAlert = buildSummaryAlertFromReport(rawReport, options);
  const detailAlerts = buildDetailAlertsFromReport(rawReport, {
    ...options,
    maxItems: Math.max(0, maxItems - 1),
  });

  return mergeDashboardAlerts([summaryAlert, ...detailAlerts], [], maxItems);
}

export function isSummaryAnalysisResult(alert: DashboardPcapAlert): boolean {
  return (
    alert.type === "analysis_result" &&
    (alert.flows_analyzed > 0 ||
      alert.threats_count > 0 ||
      Boolean(alert.top_pattern) ||
      Boolean(alert.filename))
  );
}

function buildAlertFingerprint(alert: DashboardPcapAlert): string {
  if (isSummaryAnalysisResult(alert)) {
    return `${alert.job_id || "pcap"}:summary`;
  }

  return [
    alert.job_id || "pcap",
    alert.attack_type || alert.title,
    alert.protocol || "",
    alert.src_ip || "",
    alert.dst_ip || "",
    alert.created_at,
    alert.severity,
  ].join("|");
}

export function mergeDashboardAlerts(
  primary: DashboardPcapAlert[],
  secondary: DashboardPcapAlert[],
  limit = 10
): DashboardPcapAlert[] {
  const merged: DashboardPcapAlert[] = [];
  const seen = new Set<string>();

  for (const item of [...primary, ...secondary]) {
    const fingerprint = buildAlertFingerprint(item);
    if (seen.has(fingerprint)) {
      continue;
    }
    seen.add(fingerprint);
    merged.push({
      ...item,
      relative_time: formatRelativeTime(item.created_at),
    });
  }

  merged.sort((left, right) => {
    const timeDiff =
      parseTimestampEpoch(right.created_at) -
      parseTimestampEpoch(left.created_at);
    if (timeDiff !== 0) {
      return timeDiff;
    }
    return severityRank(right.severity) - severityRank(left.severity);
  });

  return merged.slice(0, Math.max(1, limit));
}

export function persistRecentPcapAlertCache(
  alerts: DashboardPcapAlert[],
  options: {
    jobId?: string | null;
    updatedAt?: string | null;
    user?: CacheScopeUser | null;
  } = {}
): void {
  if (typeof window === "undefined") {
    return;
  }

  try {
    const normalized = mergeDashboardAlerts(alerts, [], Math.max(alerts.length, 1));
    const scope = resolveCacheScope(normalized, options.user);
    if (!scope) {
      return;
    }
    const updatedAt = firstText(options.updatedAt) || new Date().toISOString();
    const payload = {
      scope,
      updated_at: updatedAt,
      job_id: firstText(options.jobId) || normalized[0]?.job_id || null,
      alerts: normalized,
    };
    window.localStorage.setItem(
      RECENT_PCAP_ALERT_CACHE_KEY,
      JSON.stringify(payload)
    );
  } catch {
    // Best-effort cache only.
  }
}

export function readRecentPcapAlertCache(limit = 10): DashboardPcapAlert[] {
  if (typeof window === "undefined") {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(RECENT_PCAP_ALERT_CACHE_KEY);
    if (!raw) {
      return [];
    }

    const parsed = JSON.parse(raw) as {
      scope?: unknown;
      alerts?: unknown;
    };
    const currentScope = getCurrentRecentPcapAlertScope();
    const storedScope = normalizeCacheScope(parsed.scope);
    if (!currentScope || !storedScope || storedScope !== currentScope) {
      return [];
    }
    const alerts = Array.isArray(parsed.alerts)
      ? parsed.alerts
          .filter(
            (item): item is RawRecord =>
              Boolean(item) && typeof item === "object" && !Array.isArray(item)
          )
          .map((item, index) => normalizeDashboardPcapAlert(item, index))
      : [];

    return mergeDashboardAlerts(alerts, [], limit);
  } catch {
    return [];
  }
}

export function persistPcapReportSnapshot(
  jobId: string | null | undefined,
  report: Record<string, unknown>,
  user?: CacheScopeUser | null
): void {
  if (typeof window === "undefined") {
    return;
  }

  const normalizedJobId = firstText(jobId);
  if (!normalizedJobId || !report || typeof report !== "object" || Array.isArray(report)) {
    return;
  }

  const scope = resolveCacheScope([], user);
  if (!scope) {
    return;
  }

  try {
    window.localStorage.setItem(
      `${PCAP_REPORT_SNAPSHOT_KEY_PREFIX}${normalizedJobId}`,
      JSON.stringify({
        scope,
        job_id: normalizedJobId,
        updated_at: new Date().toISOString(),
        report,
      })
    );
  } catch {
    // Best-effort cache only.
  }
}

export function readPcapReportSnapshot(
  jobId: string | null | undefined
): Record<string, unknown> | null {
  const entry = readPcapReportSnapshotEntry(jobId);
  return entry?.report ?? null;
}

export function readPcapReportSnapshotEntry(
  jobId: string | null | undefined
): PcapReportSnapshotEntry | null {
  if (typeof window === "undefined") {
    return null;
  }

  const normalizedJobId = firstText(jobId);
  if (!normalizedJobId) {
    return null;
  }

  try {
    const raw = window.localStorage.getItem(
      `${PCAP_REPORT_SNAPSHOT_KEY_PREFIX}${normalizedJobId}`
    );
    if (!raw) {
      return null;
    }

    const parsed = JSON.parse(raw) as {
      scope?: unknown;
      job_id?: unknown;
      updated_at?: unknown;
      report?: unknown;
    };
    const currentScope = getCurrentRecentPcapAlertScope();
    const storedScope = normalizeCacheScope(parsed.scope);

    if (!currentScope || !storedScope || storedScope !== currentScope) {
      return null;
    }

    if (
      parsed.report &&
      typeof parsed.report === "object" &&
      !Array.isArray(parsed.report)
    ) {
      return {
        jobId: firstText(parsed.job_id, normalizedJobId) || normalizedJobId,
        updatedAt: firstText(parsed.updated_at) || null,
        report: parsed.report as Record<string, unknown>,
      };
    }

    return null;
  } catch {
    return null;
  }
}

export function broadcastRecentPcapAlertsUpdated(updatedAt?: string): void {
  if (typeof window === "undefined") {
    return;
  }

  const value = firstText(updatedAt) || new Date().toISOString();
  window.dispatchEvent(new CustomEvent(RECENT_PCAP_ALERT_EVENT));
  window.localStorage.setItem(RECENT_PCAP_ALERT_UPDATED_AT_KEY, value);
}
