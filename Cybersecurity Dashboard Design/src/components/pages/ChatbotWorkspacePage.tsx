import React, { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  ShieldCheck,
  Send,
  Download,
  Trash2,
  Zap,
  Activity,
  FileText,
  AlertTriangle,
  Cpu,
  Network,
  Eye,
  Layers,
  GitBranch,
  BarChart3,
  MessageSquare,
  Paperclip,
  Shield,
  Database,
  Lock,
  Copy,
  ThumbsUp,
  User,
} from "lucide-react";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  providerUsed?: "ollama" | "gemini" | "fallback";
  selectedProvider?: ChatbotProviderPreference;
  fallbackUsed?: boolean;
  fallbackReason?: string | null;
}

const DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:5000";
const CHATBOT_PROVIDER_STORAGE_KEY = "sentinel_chatbot_provider_preference";

type ChatbotProviderPreference = "auto" | "ollama" | "gemini" | "fallback";

const CHATBOT_PROVIDER_OPTIONS: Array<{ value: ChatbotProviderPreference; label: string; helper: string }> = [
  { value: "auto", label: "Auto", helper: "Try Ollama, then Gemini, then fallback." },
  { value: "ollama", label: "Local Ollama", helper: "Keep requests local; fallback only if unavailable." },
  { value: "gemini", label: "Gemini Cloud", helper: "Use backend Gemini, then Ollama, then fallback." },
  { value: "fallback", label: "Fallback Only", helper: "Use rule-based answers only." },
];

function normalizeChatbotProviderPreference(value: unknown): ChatbotProviderPreference {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "ollama" || normalized === "gemini" || normalized === "fallback") return normalized;
  return "auto";
}

function readChatbotProviderPreference(): ChatbotProviderPreference {
  if (typeof window === "undefined") return "auto";
  return normalizeChatbotProviderPreference(window.localStorage.getItem(CHATBOT_PROVIDER_STORAGE_KEY));
}

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

const CHATBOT_API_BASE = (() => {
  const envBase = normalizeApiBase(
    String((import.meta as any).env?.VITE_API_BASE_URL || "")
  );
  if ((import.meta as any).env?.DEV) return "";
  if (envBase) return envBase;
  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      return `${window.location.protocol}//${host}:5000`;
    }
  }
  return DEFAULT_LOCAL_API_BASE;
})();

const RESPONSES: Record<string, string> = {
  vault_overview: `The **Encrypted File Vault** protects sensitive files by combining secure storage, access control, activity logging, and AI-based behavioral risk detection.

The main workflow is:

1. **Upload** - the user uploads a file into the vault.
2. **Protected storage** - the file is stored as a protected vault asset.
3. **Password-based access** - downloading requires the correct vault password.
4. **Activity logging** - download, delete, offline access, and wrong password attempts are written into activity logs.
5. **Vault AI analysis** - the dashboard analyzes vault behavior and detects suspicious patterns.
6. **Alerts and reports** - risky vault behavior appears in Recent Security Alerts and Monthly Reports.

So the vault is not just file storage. It is connected to monitoring, AI scoring, alerts, and reporting.`,

  vault_ai: `The **Vault AI risk model** is rule-based and behavior-driven.

It looks at vault activity such as:

- wrong password attempts
- repeated downloads
- file deletions
- offline access events

Then it calculates:

- **risk_score**
- **severity**
- **active risks**
- **top risk**
- **user-level signals**
- **file-level signals**

The hybrid rule is:

**Final Risk = highest active risk between user-level and file-level signals**

This makes the model stronger because it can detect both general suspicious user behavior and targeted attacks against a specific file.`,

  vault_hybrid: `The **hybrid vault model** combines two views:

1. **User-level risk**
   - Looks at the user's overall behavior across the vault.
   - Example: many wrong password attempts across different files.

2. **File-level risk**
   - Looks at suspicious activity against a specific file.
   - Example: repeated wrong password attempts against one PDF.

The final score uses the highest active signal:

**Final Risk = max(user-level risk, file-level risk)**

This is useful because a user may look normal overall while one specific file is under attack, or one user may behave suspiciously across many files.`,

  vault_thresholds: `The current **Vault AI thresholds** are rule-based:

- **Wrong Password Attempts**
  - 1 attempt -> Low / informational risk if enabled
  - 3+ attempts -> High risk
  - 6+ attempts -> Critical risk

- **Download Activity**
  - 5+ downloads -> Medium risk
  - 10+ downloads -> High risk

- **File Deletion**
  - 3+ deletions -> High risk

- **Offline Access**
  - 3+ offline activations -> Medium risk

The logic is based on:

**Frequency + Time Window + Action Sensitivity**

Wrong passwords are more sensitive because they may indicate brute force behavior. Deletes are dangerous because they may indicate destructive behavior. Downloads and offline access can be normal, but become risky when repeated.`,

  vault_alerts: `Vault AI is integrated with **Recent Security Alerts**.

When active vault risks exist, the alerts panel can show:

- alert type, such as Wrong Password Attempts or Download Activity
- scope, such as User-level or File-level
- target file
- risk score
- count
- severity

This turns raw vault activity into analyst-ready security alerts.

Example:

**Wrong Password Attempts**
- Scope: File-level
- Target: report.pdf
- Risk: 85/100
- Count: 3

That means the vault is connected to the same monitoring workflow as the rest of the dashboard.`,

  vault_reports: `Vault data is integrated into **Monthly Reports** and PDF export.

The report can include:

- total vault events
- uploads
- downloads
- deletions
- offline enabled / disabled
- wrong password attempts
- most active file
- most failed password file
- Vault AI final risk
- active risk count
- user-level and file-level signals
- Vault AI risk breakdown
- recommendations

This makes the vault useful for both real-time monitoring and historical monthly security review.`,

  vault_files: `The most important vault-related files in this project are:

- **Backend/app.py**
  - Vault API routes
  - Vault AI endpoint: /api/ai/vault/analyze
  - Hybrid risk analysis logic

- **Backend/activity_logs.py**
  - Stores vault actions such as wrong password, download, delete, and offline access

- **src/components/pages/SimpleDashboard.tsx**
  - Shows Vault AI score, AI monitoring, multi-risk breakdown, and vault assets

- **src/components/security/RecentSecurityAlertsPanel.tsx**
  - Displays Vault AI alerts inside Recent Security Alerts

- **Backend/reports/monthly_security_report_service.py**
  - Builds monthly vault summaries and Vault AI risk data

- **Backend/reports/monthly_security_report_renderer.py**
  - Renders Vault and Vault AI data into the exported PDF

- **src/components/pages/MonthlyReportsPage.tsx**
  - Displays vault monthly report data in the frontend`,

  vault_nextsteps: `The strongest next steps for the **Encrypted File Vault** integration are:

1. **Keep the dashboard as the live view**
   - Vault AI score, current risk, and active patterns.

2. **Use Recent Security Alerts as the investigation feed**
   - Show active vault threats as structured alerts.

3. **Use Monthly Reports as the historical view**
   - Summarize vault activity and export it to PDF.

4. **Optionally add real-time refresh**
   - Auto-refresh Vault AI every few seconds or after vault actions.

5. **Optionally add sidebar risk badges**
   - Show Safe, High, or Critical beside File Vault in the sidebar.

The project already has the core vault integration: Dashboard + Alerts + Monthly Reports + PDF Export.`,
  pipeline: `The **PCAP pipeline** in this project follows a fixed order:

1. **Request intake** - \`/analyze-pcap\` or \`/analyze-local\` accepts the PCAP request.
2. **Ownership and job reuse** - the backend resolves ownership context, computes an \`analysis_key\`, and can reuse an equivalent active job.
3. **Packet export** - \`tshark\` exports packet rows to CSV.
4. **Flow building** - \`build_cic_features_from_tshark_csv()\` aggregates packets into the CIC-like flow schema.
5. **ML inference** - \`predict_flows()\` adds \`ml_label\` and \`ml_confidence\`.
6. **Context and heuristics** - \`build_flow_context_features()\` and \`apply_heuristics()\` enrich each flow.
7. **Optional Zeek enrichment** - if enabled, Zeek runs in parallel and later loads \`conn\`, \`dns\`, \`http\`, and \`ssl\` evidence.
8. **Final scoring** - \`fuse_scores()\` computes suppression, validation, support, verdict, final score, and reason.
9. **Comparison and report** - base vs enriched outputs are compared, then \`build_report()\` emits \`meta\`, \`summary\`, \`clusters\`, \`alerts\`, and \`timeline\`.

The architecture that must remain unchanged is:
**tshark -> CIC -> ML -> base context -> heuristics -> optional Zeek -> fuse_scores -> comparison -> report**.`,

  severity: `In this project, **raw ML output is not the same as the final surfaced result**.

- \`ml_label -> severity\` is only an early signal
- \`signal_verdict\` is the preliminary result after ML + base context
- \`verdict\` is the final surfaced result after suppression and support checks
- \`final_score\` is **not** raw ML confidence
- \`confidence\` in alert and timeline rows is set equal to \`final_score\`

Important scorer rules:

- \`confidence_tier()\` returns **ignore**, **suspicious**, or **confirmed**
- \`validation_fail_reason()\` can force suppression
- \`context_support_level()\` controls how far a family can surface
- \`Normal\` always ends with **final_score = 0.0**

For non-Normal verdicts, the project enforces floors and caps:

- **Low** floor \`0.20\`, cap \`0.30\`
- **Medium** floor \`0.40\`, cap \`0.60\`
- **High** floor \`0.65\`, cap \`0.82\`
- **Critical** floor \`0.85\`, cap \`0.97\`

So the safe answer is: **ML confidence starts the process, but the final verdict depends on context, validation, suppression, and bounded scoring rules.**`,

  suppressed: `Suppression in the current PCAP subsystem is driven by the scorer, not by a simple static threshold list.

The most important project rules are:

- \`should_suppress()\` removes obvious noise and impossible label-context combinations early
- \`validation_fail_reason()\` can suppress a row even after the label looks severe
- support and context checks decide whether a signal can surface as a final verdict

Operationally, that means:

- suppression happens before the final surfaced verdict is trusted
- the frontend does **not** currently rely on an explicit \`summary.suppressed\` field
- evidence affects suppression only indirectly through validation, support, and reason building

So if an alert disappears, the accurate explanation is:
**it was likely filtered by suppression or validation logic inside the scorer, not just hidden by the UI.**`,

  zeek: `In this project, **Zeek is optional enrichment**, not the first stage of the base pipeline.

When enabled:

- Zeek runs in parallel after the base ML/context path has started
- the loader later brings in \`conn\`, \`dns\`, \`http\`, and \`ssl\` evidence
- base and enriched outputs are compared with deterministic stable keys

The most important merge rules are:

- **Conn evidence** is the strongest merge source and is protocol-aware in the merge key
- **DNS, HTTP, and SSL summaries** merge on endpoint, port, and time-bucket keys
- fallback matching is only allowed when the pair key is unique, the base pair row count is small, and the protocol-specific fallback guard passes
- HTTP fallback only applies when actual HTTP fallback evidence exists
- SSL fallback only applies when actual SSL fallback evidence exists

Evidence does not directly overwrite verdicts. It influences the result indirectly through:

- \`validation_fail_reason()\`
- \`context_support_level()\`
- \`build_reason()\``,

  report: `The backend report contract for the current PCAP subsystem is:

- **meta** - includes \`analysis_mode\` and compact \`comparison\`
- **summary** - includes \`total_flows\`, \`alerts_count\`, \`suspicious\`, \`malicious\`, \`overall_risk\`, \`risk_level\`, and \`top_attackers\`
- **clusters**
- **alerts**
- **timeline**

Frontend-critical notes from the project docs:

- the frontend currently ignores most of \`meta\`
- it relies on summary fields, cluster rows, alert rows, and timeline rows
- backend does **not** emit explicit \`summary.suppressed\`
- \`confidence\` in alert and timeline rows is the post-validation final score, not raw ML confidence
- \`meta.run_folder\` is currently a mode label, not a filesystem folder path

So the safest project-accurate answer is: the report is built around **meta, summary, clusters, alerts, and timeline**, with summary and row contracts driving the frontend.`,

  nextsteps: `For a safe analyst workflow in this project, the strongest next steps are:

1. **Confirm the pipeline mode** - check whether the run is base-only or Zeek-enriched.
2. **Review summary and alerts together** - use \`summary.overall_risk\`, \`risk_level\`, and \`alerts_count\` as the entry point.
3. **Inspect surfaced verdicts, not raw ML only** - final decisions come after suppression, validation, support, and score bounds.
4. **Check evidence merges** - especially whether conn, dns, http, or ssl enrichment changed support or reasoning.
5. **Review comparison integrity** - confirm \`base_only_rows = 0\` and \`enriched_only_rows = 0\` when comparing enriched runs.
6. **Validate report contract stability** - make sure \`summary\`, \`clusters\`, \`alerts\`, and \`timeline\` still render correctly in the frontend.

If you want, I can also explain the safest checklist for changing the pipeline without breaking the model or report contract.`,

  files: `The most important PCAP files and functions in this project are:

- **Backend/app.py**
  - \`analyze_pcap()\`
  - \`analyze_local()\`
  - \`run_pcap_pipeline()\`
  - \`build_detection_comparison_summary()\`
  - \`merge_conn_evidence()\`
  - \`merge_summary_evidence()\`

- **Extraction and inference**
  - \`Backend/pcap_engine/tshark_runner.py\` -> \`run_tshark_export()\`
  - \`Backend/pcap_engine/cic_stream_features.py\` -> \`build_cic_features_from_tshark_csv()\`
  - \`Backend/pcap_engine/ml_infer.py\` -> \`prepare_inference_frame()\`, \`predict_flows()\`

- **Detection logic**
  - \`flow_features.py\` -> \`build_flow_context_features()\`
  - \`heuristics.py\` -> \`apply_heuristics()\`
  - \`security_logic.py\` -> verdict, support, validation, floors, caps, and reasons
  - \`scorer.py\` -> \`fuse_scores()\`

- **Zeek enrichment**
  - \`zeek_runner.py\` -> \`run_zeek()\`
  - \`zeek_loader.py\` -> \`load_conn()\`, \`load_dns()\`, \`load_http()\`, \`load_ssl()\`

- **Reporting and jobs**
  - \`reporter.py\` -> \`build_report()\`, \`cluster_alerts()\`
  - \`jobs.py\` -> \`create_or_reuse_active()\`, \`submit()\`, \`update()\``,

  risks: `The top runtime risks called out in the project docs are:

- localhost auth fallback can hide frontend auth propagation issues during development
- large PCAPs are expensive in disk, CPU, memory, and intermediate CSV size
- concurrency can pressure RAM, disk I/O, CPU, and WSL Zeek runtime
- schema drift between tshark export, CIC output, model columns, and evidence fields can cause hard failures
- evidence merge safety depends on keeping fallback guards strict
- frontend is sensitive to shape changes in \`summary\`, \`clusters\`, \`alerts\`, and \`timeline\`

In short: the highest-risk areas are **pipeline contract stability, evidence merge safety, and report shape compatibility**.`,

  default: `I am in **PCAP Analyzer** mode and can answer using the current project contract.

The safest topics to ask about are:

- the exact pipeline order
- how final verdict differs from raw ML confidence
- how suppression works in the scorer
- how Zeek enrichment merges into the base run
- what the backend report actually emits
- which files and functions control the subsystem
- top runtime risks and safe-change rules

If you want a precise answer, ask about one of those areas directly.`,
};


function buildVaultAiFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  const token = localStorage.getItem("sentinel_auth_token");

  if (token && token !== "cookie_based") {
    headers.set("Authorization", `Bearer ${token}`);
  }

  headers.set("Content-Type", "application/json");

  return {
    ...init,
    credentials: "include",
    headers,
  };
}

function buildAuthedJsonFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  const token = localStorage.getItem("sentinel_auth_token");

  if (token && token !== "cookie_based") {
    headers.set("Authorization", `Bearer ${token}`);
  }

  headers.set("Content-Type", "application/json");

  return {
    ...init,
    credentials: "include",
    headers,
  };
}

function normalizeVaultSeverity(value: unknown) {
  const normalized = String(value || "safe").toLowerCase();
  if (normalized === "critical") return "Critical";
  if (normalized === "high") return "High";
  if (normalized === "medium") return "Medium";
  if (normalized === "low") return "Low";
  return "Safe";
}

function getVaultRiskName(risk: any) {
  const raw = String(
    risk?.name ||
      risk?.pattern ||
      risk?.type ||
      risk?.action_type ||
      risk?.title ||
      ""
  ).toLowerCase();

  if (raw.includes("password")) return "Wrong Password Attempts";
  if (raw.includes("download")) return "Download Activity";
  if (raw.includes("delete")) return "File Deletion";
  if (raw.includes("offline")) return "Offline Access";
  if (raw.includes("upload")) return "File Upload";

  return String(risk?.name || risk?.pattern || risk?.type || "Vault Activity");
}

function getVaultRiskScoreFromPayload(data: any) {
  return Number(
    data?.overall_risk_score ??
      data?.final_risk_score ??
      data?.risk_score ??
      data?.summary?.risk_score ??
      0
  );
}

function getVaultRisksFromPayload(data: any): any[] {
  const possible =
    data?.active_risks ||
    data?.risks ||
    data?.patterns ||
    data?.summary?.active_risks ||
    data?.summary?.patterns ||
    [];

  return Array.isArray(possible) ? possible : [];
}

function shouldRunLiveVaultAnalysis(content: string, moduleId: string) {
  const lower = content.toLowerCase().trim();

  return (
    moduleId === "vault" &&
    (
      lower === "analyze my current vault ai risk" ||
      lower.includes("analyze my current vault") ||
      lower.includes("current vault risk") ||
      lower.includes("live vault") ||
      lower.includes("vault now")
    )
  );
}

async function fetchLiveVaultAiResponse(): Promise<string> {
  try {
    const response = await fetch(
      "/api/ai/vault/analyze",
      buildVaultAiFetchInit({
        method: "POST",
        body: JSON.stringify({ source: "chatbot" }),
      })
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data?.error || "Vault AI analysis request failed.");
    }

    const risks = getVaultRisksFromPayload(data);
    const riskScore = getVaultRiskScoreFromPayload(data);
    const securityRemaining = Math.max(0, 100 - riskScore);
    const severity = normalizeVaultSeverity(
      data?.overall_status ||
        data?.severity ||
        data?.risk_level ||
        data?.summary?.severity
    );

    const topRisk = risks[0];
    const topRiskName = topRisk ? getVaultRiskName(topRisk) : "No active risk";
    const topRiskScore = Number(
      topRisk?.risk_score ??
        topRisk?.score ??
        topRisk?.risk ??
        riskScore
    );
    const topRiskCount = Number(topRisk?.count ?? topRisk?.event_count ?? 0);
    const target =
      topRisk?.target_label ||
      topRisk?.target ||
      topRisk?.filename ||
      topRisk?.file_name ||
      "No specific target";

    if (!risks.length || riskScore === 0) {
      return `**Live Vault AI Analysis**

Current result:

- Risk Score: **0/100**
- Security Remaining: **100%**
- Severity: **Safe**
- Active Risks: **0**
- Top Risk: **No active risk**

Interpretation:

The vault does not currently show suspicious behavior in the active analysis window.

Recommended action:

- Continue normal monitoring
- Review Monthly Reports for historical activity
- Re-run this analysis after any download, delete, wrong password, or offline access event`;
    }

    return `**Live Vault AI Analysis**

Current result:

- Risk Score: **${riskScore}/100**
- Security Remaining: **${securityRemaining}%**
- Severity: **${severity}**
- Active Risks: **${risks.length}**
- Top Risk: **${topRiskName}**

Top risk details:

- Target: **${target}**
- Risk: **${topRiskScore}/100**
- Count: **${topRiskCount || "N/A"}**

Interpretation:

The current vault activity contains one or more suspicious behavior signals. The final risk is based on the highest active user-level or file-level signal.

Recommended action:

- Review the target file and recent activity logs
- Confirm whether the activity was expected
- Investigate repeated wrong passwords, downloads, deletions, or offline access events`;
  } catch (error) {
    return `**Live Vault AI Analysis failed**

I could not reach the Vault AI endpoint.

Check:

- Backend is running
- Endpoint exists: **POST /api/ai/vault/analyze**
- You are logged in
- CORS / proxy settings are correct

Technical message:

${error instanceof Error ? error.message : "Unknown error"}`;
  }
}

type ChatbotLlmResponse = {
  content: string;
  providerUsed?: "ollama" | "gemini" | "fallback";
  selectedProvider?: ChatbotProviderPreference;
  fallbackUsed?: boolean;
  fallbackReason?: string | null;
  model?: string | null;
};

function normalizeLlmModule(moduleId: string) {
  if (moduleId === "vault") return "file_vault";
  if (moduleId === "score") return "security_score";
  if (moduleId === "security-score") return "security_score";
  if (moduleId === "identity-leak") return "identity";
  if (moduleId === "identity_leak") return "identity";
  return moduleId;
}

function inferLlmModuleFromMessage(message: string, moduleId: string) {
  const normalizedModule = normalizeLlmModule(moduleId);
  const text = message.toLowerCase();
  const identityAliases = [
    "identity leak",
    "leaked identity",
    "data leak",
    "breach",
    "exposed email",
    "exposed username",
    "exposed domain",
    "leaked email",
    "dark web",
    "darkweb",
    "osint",
    "public exposure",
    "github leak",
    "duckduckgo leak",
    "risky assets",
    "protection rate",
    "identity scan",
    "identity risk",
    "leaked account",
    "تسريب الهوية",
    "فحص الهوية",
    "مخاطر الهوية",
    "الأصول الخطرة",
    "الاصول الخطرة",
  ];

  if (identityAliases.some((alias) => text.includes(alias))) {
    return "identity";
  }

  return normalizedModule;
}

function formatFallbackReason(reason?: string | null) {
  if (reason === "ollama_not_running") return "Ollama is not running. Using safe fallback mode.";
  if (reason === "ollama_model_missing") return "The selected Ollama model is not available locally. Using safe fallback mode.";
  if (reason === "ollama_timeout") return "Ollama response timed out. Using safe fallback mode.";
  if (reason === "ollama_error") return "Ollama returned an error. Using safe fallback mode.";
  if (reason === "invalid_ollama_response") return "Ollama returned an invalid response. Using safe fallback mode.";
  if (reason === "gemini_disabled" || reason === "missing_api_key") return "Gemini is not configured. Using a safe alternative.";
  if (reason === "gemini_timeout") return "Gemini response timed out. Using a safe alternative.";
  if (reason === "gemini_rate_limit") return "Gemini is rate limited. Using a safe alternative.";
  if (reason === "gemini_safety_blocked") return "Gemini could not answer safely. Using fallback mode.";
  if (reason === "gemini_error" || reason === "invalid_gemini_response") return "Gemini is unavailable. Using a safe alternative.";
  if (reason === "password_rule_based_fallback") return "Password Checker fallback response used because the selected provider was unavailable.";
  if (reason === "llm_disabled") return "LLM chatbot is disabled. Using safe fallback mode.";
  if (reason === "provider_not_available") return "Configured LLM provider is unavailable. Using safe fallback mode.";
  return reason ? "Selected provider unavailable, safe response used." : undefined;
}

function providerBadgeLabel(provider?: Message["providerUsed"]) {
  if (provider === "ollama") return "Local Ollama Assistant";
  if (provider === "gemini") return "Gemini Assistant";
  return "Fallback Mode";
}

function providerBadgeColors(provider?: Message["providerUsed"]) {
  if (provider === "ollama") {
    return { color: "#67E8F9", border: "rgba(103,232,249,0.28)", background: "rgba(14,165,233,0.1)" };
  }
  if (provider === "gemini") {
    return { color: "#C4B5FD", border: "rgba(196,181,253,0.3)", background: "rgba(139,92,246,0.12)" };
  }
  return { color: "#FBBF24", border: "rgba(251,191,36,0.28)", background: "rgba(251,191,36,0.1)" };
}

function providerSwitchHelper(selected?: ChatbotProviderPreference, actual?: Message["providerUsed"], fallbackReason?: string | null) {
  if (!selected || !actual || selected === actual || (selected === "auto" && actual === "ollama")) return undefined;
  if (selected === "auto" && actual === "gemini") return "Gemini was used because local Ollama was unavailable.";
  if (actual === "fallback") return "Fallback response used because the selected provider was unavailable.";
  if (selected === "gemini" && actual === "ollama") return "Local Ollama was used because Gemini was unavailable.";
  return formatFallbackReason(fallbackReason);
}

async function fetchLlmChatbotResponse(message: string, moduleId: string, providerPreference: ChatbotProviderPreference): Promise<ChatbotLlmResponse> {
  try {
    const endpoint = `${CHATBOT_API_BASE}/api/chatbot/llm`;
    const response = await fetch(
      endpoint,
      buildAuthedJsonFetchInit({
        method: "POST",
        body: JSON.stringify({
          message,
          module: inferLlmModuleFromMessage(message, moduleId),
          provider_preference: providerPreference,
        }),
      })
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const serverMessage = data?.message || data?.error || "Chatbot request failed.";
      console.error("Chatbot request failed", {
        status: response.status,
        statusText: response.statusText,
        endpoint,
        payload: data,
      });
      throw new Error(`HTTP ${response.status}: ${serverMessage}`);
    }

    const actualProvider = data?.provider === "gemini"
      ? "gemini"
      : data?.provider === "ollama" || data?.provider_used === "ollama"
      ? "ollama"
      : "fallback";

    return {
      content: String(data?.answer || data?.reply || "No chatbot answer was returned."),
      providerUsed: actualProvider,
      selectedProvider: normalizeChatbotProviderPreference(data?.selected_provider || providerPreference),
      fallbackUsed: Boolean(data?.fallback_used || actualProvider === "fallback"),
      fallbackReason: data?.fallback_reason ?? null,
      model: data?.model ?? null,
    };
  } catch (error) {
    console.error("Chatbot unavailable", error);
    return {
      content: getResponse(message, moduleId),
      providerUsed: "fallback",
      selectedProvider: providerPreference,
      fallbackUsed: true,
      fallbackReason: "provider_not_available",
      model: null,
    };
  }
}

async function fetchIdentityChatbotResponse(message: string, scanId: number | null): Promise<string> {
  try {
    const endpoint = `${CHATBOT_API_BASE}/api/chatbot/identity`;
    const response = await fetch(
      endpoint,
      buildAuthedJsonFetchInit({
        method: "POST",
        body: JSON.stringify({
          message,
          scan_id: scanId || undefined,
          include_latest_scan: true,
        }),
      })
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const serverMessage = data?.message || data?.error || "Identity chatbot request failed.";
      console.error("Identity chatbot request failed", {
        status: response.status,
        statusText: response.statusText,
        endpoint,
        payload: data,
      });
      throw new Error(`HTTP ${response.status}: ${serverMessage}`);
    }

    return String(data?.answer || "No Identity chatbot answer was returned.");
  } catch (error) {
    console.error("Identity chatbot unavailable", error);
    return "I’m having trouble loading your Identity Leak Monitor data right now. Please try again in a moment.";
  }
}

async function fetchPcapChatbotResponse(message: string, analysisId: string | null): Promise<string> {
  try {
    const endpoint = `${CHATBOT_API_BASE}/api/chatbot/pcap`;
    const response = await fetch(
      endpoint,
      buildAuthedJsonFetchInit({
        method: "POST",
        body: JSON.stringify({
          message,
          analysis_id: analysisId || undefined,
          include_latest_analysis: true,
        }),
      })
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const serverMessage = data?.message || data?.error || "PCAP chatbot request failed.";
      console.error("PCAP chatbot request failed", {
        status: response.status,
        statusText: response.statusText,
        endpoint,
        payload: data,
      });
      throw new Error(`HTTP ${response.status}: ${serverMessage}`);
    }

    return String(data?.answer || "No PCAP chatbot answer was returned.");
  } catch (error) {
    console.error("PCAP chatbot unavailable", error);
    return "I'm having trouble loading your PCAP analysis data right now. Please try again in a moment or open the PCAP Analyzer page to review your latest report.";
  }
}

function getResponse(input: string, moduleId = "pcap"): string {
  const lower = input.toLowerCase().trim();

  if (moduleId === "vault") {
    // Exact Quick Action mapping first.
    // This prevents generic words like "file", "vault", or "ai" from sending the user to the wrong response.
    if (lower === "summarize the encrypted file vault") {
      return RESPONSES.vault_overview;
    }

    if (lower === "explain vault ai risk detection") {
      return RESPONSES.vault_ai;
    }

    if (lower === "explain hybrid user-level and file-level risk") {
      return RESPONSES.vault_hybrid;
    }

    if (lower === "what are the vault ai risk score thresholds?") {
      return RESPONSES.vault_thresholds;
    }

    if (lower === "how vault ai appears in recent security alerts") {
      return RESPONSES.vault_alerts;
    }

    if (lower === "how vault ai appears in monthly reports and pdf") {
      return RESPONSES.vault_reports;
    }

    if (lower === "which files control the vault ai integration?") {
      return RESPONSES.vault_files;
    }

    if (lower === "professional next steps for the vault module") {
      return RESPONSES.vault_nextsteps;
    }

    // Flexible fallback mapping for manually typed questions.
    if (
      lower.includes("threshold") ||
      lower.includes("case") ||
      lower.includes("score threshold")
    ) {
      return RESPONSES.vault_thresholds;
    }

    if (
      lower.includes("hybrid") ||
      lower.includes("user-level") ||
      lower.includes("file-level")
    ) {
      return RESPONSES.vault_hybrid;
    }

    if (
      lower.includes("recent security alerts") ||
      lower.includes("security alerts") ||
      lower.includes("alert")
    ) {
      return RESPONSES.vault_alerts;
    }

    if (
      lower.includes("monthly") ||
      lower.includes("report") ||
      lower.includes("pdf")
    ) {
      return RESPONSES.vault_reports;
    }

    if (
      lower.includes("which files") ||
      lower.includes("control the vault") ||
      lower.includes("files control") ||
      lower.includes("integration files") ||
      lower.includes("important files")
    ) {
      return RESPONSES.vault_files;
    }

    if (
      lower.includes("next") ||
      lower.includes("step") ||
      lower.includes("improve") ||
      lower.includes("professional")
    ) {
      return RESPONSES.vault_nextsteps;
    }

    if (
      lower.includes("risk detection") ||
      lower.includes("vault ai") ||
      lower.includes("detect")
    ) {
      return RESPONSES.vault_ai;
    }

    return RESPONSES.vault_overview;
  }

  if (lower.includes("file") || lower.includes("function") || lower.includes("where is")) return RESPONSES.files;
  if (lower.includes("risk") || lower.includes("runtime") || lower.includes("danger")) return RESPONSES.risks;
  if (lower.includes("pipeline") || lower.includes("summarize") || lower.includes("pcap")) return RESPONSES.pipeline;
  if (lower.includes("severity") || lower.includes("score") || lower.includes("confidence") || lower.includes("verdict")) return RESPONSES.severity;
  if (lower.includes("suppress") || lower.includes("alert")) return RESPONSES.suppressed;
  if (lower.includes("zeek") || lower.includes("evidence") || lower.includes("merge")) return RESPONSES.zeek;
  if (lower.includes("report") || lower.includes("contain") || lower.includes("emit")) return RESPONSES.report;
  if (lower.includes("next") || lower.includes("step") || lower.includes("checklist")) return RESPONSES.nextsteps;
  return RESPONSES.default;
}

const MODULE_QUICK_ACTIONS: Record<string, Array<{ icon: React.FC<any>; label: string; color: string }>> = {
  password: [
    { icon: ShieldCheck, label: "How can I make my password stronger?", color: "#34D399" },
    { icon: AlertTriangle, label: "Was my password breached?", color: "#FB7185" },
    { icon: BarChart3, label: "What does password risk mean?", color: "#22D3EE" },
    { icon: FileText, label: "Explain my latest password check", color: "#38BDF8" },
    { icon: Zap, label: "What should I do after a breached password?", color: "#F59E0B" },
    { icon: Cpu, label: "How is password strength calculated?", color: "#0EA5E9" },
    { icon: GitBranch, label: "What is password reuse risk?", color: "#818CF8" },
    { icon: Activity, label: "How can I improve my password score?", color: "#A78BFA" },
    { icon: Database, label: "Is my password history safe?", color: "#34D399" },
    { icon: Lock, label: "Why should I use MFA?", color: "#22D3EE" },
  ],
  pcap: [
    { icon: Network, label: "Summarize my latest PCAP analysis", color: "#0EA5E9" },
    { icon: AlertTriangle, label: "What threats were detected?", color: "#F59E0B" },
    { icon: Shield, label: "Why is this PCAP risky?", color: "#FB7185" },
    { icon: BarChart3, label: "Explain the severity", color: "#22D3EE" },
    { icon: Zap, label: "What should I do next?", color: "#34D399" },
    { icon: Eye, label: "Which IPs should I review?", color: "#818CF8" },
    { icon: GitBranch, label: "What is a suspicious flow?", color: "#38BDF8" },
    { icon: Activity, label: "What does confidence mean?", color: "#A78BFA" },
    { icon: Layers, label: "ML vs heuristics", color: "#22D3EE" },
    { icon: FileText, label: "Was the latest PCAP clean?", color: "#34D399" },
    { icon: Cpu, label: "Explain the PCAP Analyzer project module", color: "#0EA5E9" },
    { icon: GitBranch, label: "How does the PCAP pipeline work?", color: "#38BDF8" },
    { icon: Database, label: "What does the PCAP report contain?", color: "#A78BFA" },
    { icon: ShieldCheck, label: "How PCAP connects to logs and reports", color: "#34D399" },
  ],
  vault: [
    { icon: Lock, label: "Summarize the Encrypted File Vault", color: "#A78BFA" },
    { icon: ShieldCheck, label: "Explain Vault AI risk detection", color: "#34D399" },
    { icon: Layers, label: "Explain hybrid user-level and file-level risk", color: "#818CF8" },
    { icon: BarChart3, label: "What are the Vault AI risk score thresholds?", color: "#22D3EE" },
    { icon: AlertTriangle, label: "How Vault AI appears in Recent Security Alerts", color: "#F59E0B" },
    { icon: FileText, label: "How Vault AI appears in Monthly Reports and PDF", color: "#38BDF8" },
    { icon: Database, label: "Which files control the Vault AI integration?", color: "#A78BFA" },
    { icon: Activity, label: "Analyze my current Vault AI risk", color: "#34D399" },
    { icon: Zap, label: "Professional next steps for the Vault module", color: "#F472B6" },
  ],
  identity: [
    { icon: FileText, label: "Summarize my latest identity leak scan", color: "#FB7185" },
    { icon: AlertTriangle, label: "What identity risks were found?", color: "#F59E0B" },
    { icon: Zap, label: "What should I do after an identity leak?", color: "#34D399" },
    { icon: FileText, label: "Summarize my latest identity scan", color: "#FB7185" },
    { icon: AlertTriangle, label: "Why is my risk level high?", color: "#F59E0B" },
    { icon: Eye, label: "Explain my findings", color: "#22D3EE" },
    { icon: Zap, label: "What should I do next?", color: "#34D399" },
    { icon: BarChart3, label: "What is Protection Rate?", color: "#818CF8" },
    { icon: Database, label: "Show risky assets summary", color: "#A78BFA" },
    { icon: Layers, label: "Explain the Identity project module", color: "#38BDF8" },
    { icon: GitBranch, label: "How does the Identity scan workflow work?", color: "#22D3EE" },
    { icon: Activity, label: "How is Identity risk calculated?", color: "#F472B6" },
    { icon: ShieldCheck, label: "How Identity connects to logs and reports", color: "#34D399" },
  ],
  security_score: [
    { icon: BarChart3, label: "Explain my security score", color: "#22D3EE" },
    { icon: Zap, label: "How can I improve my score?", color: "#34D399" },
    { icon: AlertTriangle, label: "Which component is weakest?", color: "#F59E0B" },
    { icon: Activity, label: "Why is my score low or high?", color: "#A78BFA" },
    { icon: Layers, label: "How is the score calculated?", color: "#818CF8" },
  ],
  reports: [
    { icon: Database, label: "What reports are available?", color: "#A78BFA" },
    { icon: FileText, label: "Summarize the latest reports", color: "#38BDF8" },
    { icon: Download, label: "Can I export this report?", color: "#34D399" },
    { icon: Layers, label: "What does the Reports Center contain?", color: "#22D3EE" },
    { icon: ShieldCheck, label: "How do reports help review and document findings?", color: "#F59E0B" },
  ],
};

const QUICK_ACTIONS = MODULE_QUICK_ACTIONS.pcap;

const MODULE_OPTIONS = [
  { id: "password", label: "Password Checker", shortLabel: "Password", color: "#34D399", prompt: "Ask about password strength, entropy, reuse, breach exposure, and password security guidance..." },
  { id: "vault", label: "Encrypted File Vault", shortLabel: "Vault", color: "#A78BFA", prompt: "Ask about Vault AI, hybrid risk, wrong passwords, downloads, deletes, offline access, alerts, or reports..." },
  { id: "phishing", label: "Phishing Scanner", shortLabel: "Phishing", color: "#FBBF24", prompt: "Ask about phishing indicators, suspicious links, sender checks, and email analysis..." },
  { id: "identity", label: "Identity Leak Monitor", shortLabel: "Identity", color: "#FB7185", prompt: "Ask about leaked identities, breach monitoring, exposed accounts, and risk alerts..." },
  { id: "security_score", label: "Security Score", shortLabel: "Score", color: "#22D3EE", prompt: "Ask about score status, weakest components, and how to improve your security posture..." },
  { id: "reports", label: "Reports Center", shortLabel: "Reports", color: "#A78BFA", prompt: "Ask about available reports, exports, summaries, and documentation workflows..." },
  { id: "pcap", label: "PCAP Analyzer", shortLabel: "PCAP", color: "#0EA5E9", prompt: "Ask Sentinel AI anything about your PCAP analysis..." },
];

const DEFAULT_MODULE = MODULE_OPTIONS.find((module) => module.id === "pcap") ?? MODULE_OPTIONS[0];

const MODULE_CONTEXT: Record<
  string,
  {
    panels: Array<{
      icon: typeof Layers;
      title: string;
      badge: string;
      color: string;
      stat: string;
      description: string;
    }>;
    systems: Array<{ label: string; status: string; color: string }>;
  }
> = {
  password: {
    panels: [
      { icon: Layers, title: "Breach Check", badge: "Core", color: "#34D399", stat: "HIBP-style", description: "Checks whether submitted passwords appear in breach-style datasets or exposure counts." },
      { icon: BarChart3, title: "Risk Logic", badge: "Strength", color: "#22D3EE", stat: "Entropy Focus", description: "Helps explain weak patterns, reuse risk, entropy, and practical hardening guidance for safer credentials." },
      { icon: GitBranch, title: "History", badge: "Tracking", color: "#818CF8", stat: "Per User", description: "Stores safe password-check metadata for authenticated users so security hygiene can be reviewed over time." },
    ],
    systems: [
      { label: "Breach Check", status: "Ready", color: "#34D399" },
      { label: "Strength Guide", status: "Active", color: "#22D3EE" },
      { label: "History Log", status: "Available", color: "#818CF8" },
      { label: "User Context", status: "Verified", color: "#0EA5E9" },
    ],
  },
  vault: {
    panels: [
      { icon: Layers, title: "Hybrid AI Model", badge: "AI", color: "#A78BFA", stat: "User + File", description: "Combines user-level behavior and file-level targeted activity, then uses the highest active risk as the final Vault AI score." },
      { icon: BarChart3, title: "Risk Scoring", badge: "Rules", color: "#22D3EE", stat: "0-100", description: "Scores wrong passwords, downloads, deletions, and offline access using frequency, time window, and action sensitivity." },
      { icon: GitBranch, title: "Alert Bridge", badge: "Alerts", color: "#818CF8", stat: "Live Feed", description: "Vault AI risks can appear in Recent Security Alerts with scope, target file, risk, count, and severity." },
      { icon: MessageSquare, title: "Reports Bridge", badge: "PDF", color: "#34D399", stat: "Monthly", description: "Monthly Reports and PDF Export include vault totals, Vault AI final risk, top risk, and risk breakdown." },
    ],
    systems: [
      { label: "Vault AI", status: "Active", color: "#A78BFA" },
      { label: "Hybrid Risk", status: "Ready", color: "#34D399" },
      { label: "Alerts Bridge", status: "Connected", color: "#22D3EE" },
      { label: "PDF Reports", status: "Integrated", color: "#818CF8" },
    ],
  },
  phishing: {
    panels: [
      { icon: Layers, title: "Scan Flow", badge: "Core", color: "#FBBF24", stat: "URL Analysis", description: "Validates submitted URLs, runs ML-based prediction, then maps results into safer user-facing risk categories." },
      { icon: BarChart3, title: "Risk Output", badge: "ML", color: "#22D3EE", stat: "Guided", description: "The scanner returns a suspiciousness decision plus practical next-step guidance instead of a bare model score." },
      { icon: GitBranch, title: "History", badge: "Tracking", color: "#818CF8", stat: "Saved", description: "Past scans can be stored and reviewed so phishing checks become an ongoing workflow instead of a one-off action." },
      { icon: MessageSquare, title: "Module Scope", badge: "Phishing", color: "#34D399", stat: "Social Defense", description: "This mode focuses on malicious links, phishing indicators, sender trust, and user-safe recommendations." },
    ],
    systems: [
      { label: "URL Validation", status: "Ready", color: "#FBBF24" },
      { label: "ML Scan", status: "Active", color: "#22D3EE" },
      { label: "Risk Mapper", status: "Nominal", color: "#34D399" },
      { label: "History Log", status: "Available", color: "#818CF8" },
    ],
  },
  identity: {
    panels: [
      { icon: Layers, title: "Exposure Monitor", badge: "Core", color: "#FB7185", stat: "Asset Scan", description: "Tracks whether monitored assets appear in breach-related data and supports both targeted and broader scans." },
      { icon: BarChart3, title: "Coverage", badge: "Monitoring", color: "#22D3EE", stat: "Protection Rate", description: "Includes breach statistics, asset status, monitoring state, and protection-rate style metrics." },
      { icon: GitBranch, title: "Scan Modes", badge: "Workflow", color: "#818CF8", stat: "Auto Scan", description: "Supports asset listing, specific-asset checks, full scans, and optional recurring monitoring behavior." },
      { icon: MessageSquare, title: "Module Scope", badge: "Identity", color: "#34D399", stat: "Exposure", description: "This mode focuses on breach exposure awareness, leaked identity tracking, and risk visibility." },
    ],
    systems: [
      { label: "Asset Monitor", status: "Ready", color: "#FB7185" },
      { label: "Leak Scan", status: "Active", color: "#22D3EE" },
      { label: "Auto Scan", status: "Available", color: "#34D399" },
      { label: "Protection Rate", status: "Tracked", color: "#818CF8" },
    ],
  },
  security_score: {
    panels: [
      { icon: BarChart3, title: "Overall Score", badge: "Posture", color: "#22D3EE", stat: "0-100", description: "Summarizes user security health across connected Sentinel AI modules." },
      { icon: Layers, title: "Components", badge: "Weighted", color: "#818CF8", stat: "4 Areas", description: "Uses Password Checker, File Vault, Phishing Scanner, and Identity Leak evidence when available." },
      { icon: AlertTriangle, title: "Weakest Area", badge: "Priority", color: "#F59E0B", stat: "Focus", description: "Helps prioritize the module that needs attention first." },
      { icon: Zap, title: "Improvements", badge: "Actions", color: "#34D399", stat: "Guided", description: "Turns module health into practical remediation steps." },
    ],
    systems: [
      { label: "Score Engine", status: "Ready", color: "#22D3EE" },
      { label: "Module Weights", status: "25% Each", color: "#818CF8" },
      { label: "Weakest Component", status: "Tracked", color: "#F59E0B" },
      { label: "Recommendations", status: "Active", color: "#34D399" },
    ],
  },
  reports: {
    panels: [
      { icon: Database, title: "Report Catalog", badge: "Center", color: "#A78BFA", stat: "Summaries", description: "Collects security summaries for documentation and analyst review." },
      { icon: FileText, title: "Security Evidence", badge: "Review", color: "#38BDF8", stat: "Context", description: "Can summarize PCAP, Identity, Security Score, alerts, and activity where implemented." },
      { icon: Download, title: "Exports", badge: "Artifacts", color: "#34D399", stat: "Scoped", description: "Explains implemented export formats without claiming unavailable outputs." },
      { icon: ShieldCheck, title: "Review Support", badge: "Docs", color: "#F59E0B", stat: "Decisions", description: "Helps document findings, review trends, and prepare summaries." },
    ],
    systems: [
      { label: "Report Summaries", status: "Ready", color: "#A78BFA" },
      { label: "Exports", status: "Scoped", color: "#34D399" },
      { label: "Review Support", status: "Supported", color: "#F59E0B" },
      { label: "Evidence Links", status: "Contextual", color: "#38BDF8" },
    ],
  },
  pcap: {
    panels: [
      { icon: Layers, title: "Architecture", badge: "Core", color: "#0EA5E9", stat: "9 Stages", description: "Pipeline order is fixed: tshark -> CIC -> ML -> base context -> heuristics -> optional Zeek -> fuse_scores -> comparison -> report." },
      { icon: BarChart3, title: "Scoring Logic", badge: "ML", color: "#22D3EE", stat: "Floors & Caps", description: "Final surfaced results depend on suppression, validation, support checks, and bounded final_score rules instead of raw ML confidence alone." },
      { icon: GitBranch, title: "Evidence Merge", badge: "Correlation", color: "#818CF8", stat: "Conn Strongest", description: "Conn evidence is the strongest merge source, while DNS, HTTP, and SSL summaries merge through guarded endpoint, port, and time-bucket rules." },
      { icon: MessageSquare, title: "Report Contract", badge: "Backend", color: "#34D399", stat: "5 Outputs", description: "The backend emits meta, summary, clusters, alerts, and timeline, with the frontend relying mainly on summary and row contracts." },
    ],
    systems: [
      { label: "tshark Export", status: "Ready", color: "#34D399" },
      { label: "ML Inference", status: "Active", color: "#0EA5E9" },
      { label: "Zeek Enrichment", status: "Optional", color: "#22D3EE" },
      { label: "Report Builder", status: "Verified", color: "#818CF8" },
    ],
  },
};

function createInitialMessage(module: (typeof MODULE_OPTIONS)[number]): Message {
  const moduleIntros: Record<string, string> = {
    password: `You are now in Password Checker mode.

- Review password strength, entropy, and reuse risk
- Explain weak patterns and practical hardening steps
- Interpret password audit findings in a safe analyst-friendly way`,
    vault: `You are now in **Encrypted File Vault** mode.

- Explain secure vault storage and access protection
- Interpret Vault AI risk scores and hybrid user/file-level signals
- Explain wrong password, download, delete, and offline access risks
- Summarize how vault risks appear in Dashboard, Alerts, Monthly Reports, and PDF Export`,
    phishing: `You are now in **Phishing Scanner** mode.

- Review suspicious email signals, sender trust, and URL indicators
- Explain phishing reasoning in a clear investigation style
- Help summarize whether a message looks safe, suspicious, or malicious`,
    identity: `You are now in **Identity Leak Monitor** mode.

- Review leaked accounts, breach exposure, and identity risk
- Explain what exposed data means for the user or organization
- Help summarize monitoring results and response priorities`,
    security_score: `You are now in **Security Score** mode.

- Explain the overall security score and component health
- Identify weak areas across Password, Vault, Phishing, and Identity modules
- Suggest practical steps to improve the score`,
    reports: `You are now in **Reports Center** mode.

- Explain available reports and exports
- Summarize recent report context when available
- Help review and document findings safely`,
    threat: `You are now in **AI Threat Detector** mode.

- Explain anomaly detection logic and threat scoring
- Help interpret suspicious behavior and alert context
- Summarize analyst-ready findings for detected activity`,
    pcap: `You are now in **PCAP Analyzer** mode.

- Review network traffic evidence and flow behavior
- Explain scoring logic, evidence merging, and reporting workflow
- Help interpret PCAP findings in an analyst-ready format`,
    settings: `You are now in **Settings** mode.

- Explain thresholds, configuration choices, and workflow preferences
- Help understand how system settings affect analysis behavior
- Summarize platform-level controls across the project`,
  };

  if (module.id === "password") {
    return {
      id: `init-${module.id}`,
      role: "assistant",
      content: `Welcome to Sentinel AI Assistant - your project-wide cybersecurity copilot.

You are now in Password Checker mode.

It can help you:
- Review password strength, entropy, and reuse risk
- Explain weak patterns and practical hardening steps
- Interpret password audit findings in a safe analyst-friendly way

Ask anything about Password Checker, and I will answer in the context of that module.`,
      timestamp: new Date(Date.now() - 180000),
    };
  }

  return {
    id: `init-${module.id}`,
    role: "assistant",
    content: `Welcome to **Sentinel AI Assistant** - your project-wide cybersecurity copilot.

${moduleIntros[module.id]}

Ask anything about **${module.label}**, and I will answer in the context of that module.`,
    timestamp: new Date(Date.now() - 180000),
  };
}

const glassStrong: React.CSSProperties = {
  background: "rgba(4, 14, 34, 0.88)",
  backdropFilter: "blur(32px)",
  WebkitBackdropFilter: "blur(32px)",
  border: "1px solid rgba(14,165,233,0.2)",
  borderRadius: "20px",
};

function hexToRgb(hex: string): string {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  if (!r) return "14,165,233";
  return `${parseInt(r[1], 16)},${parseInt(r[2], 16)},${parseInt(r[3], 16)}`;
}

function formatTime(d: Date) {
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function renderContent(content: string) {
  return content.split("\n").map((line, i) => {
    if (line === "") return <div key={i} style={{ height: "6px" }} />;

    const parseLine = (text: string) =>
      text.split(/\*\*(.*?)\*\*/g).map((part, j) =>
        j % 2 === 1 ? (
          <span key={j} style={{ color: "#38BDF8", fontWeight: 600 }}>
            {part}
          </span>
        ) : (
          part
        )
      );

    if (/^\d+\./.test(line)) {
      return (
        <div key={i} style={{ display: "flex", gap: "10px", marginTop: "6px", alignItems: "flex-start" }}>
          <span style={{ color: "#0EA5E9", fontWeight: 600, minWidth: "20px", fontSize: "13px" }}>
            {line.match(/^\d+\./)?.[0]}
          </span>
          <span style={{ flex: 1 }}>{parseLine(line.replace(/^\d+\.\s*/, ""))}</span>
        </div>
      );
    }

    if (line.startsWith("- ") || line.startsWith("• ")) {
      return (
        <div key={i} style={{ display: "flex", gap: "10px", marginTop: "4px", alignItems: "flex-start" }}>
          <span style={{ color: "#22D3EE", marginTop: "2px", fontSize: "10px" }}>◆</span>
          <span style={{ flex: 1 }}>{parseLine(line.replace(/^[-•]\s*/, ""))}</span>
        </div>
      );
    }

    return (
      <div key={i} style={{ marginTop: i > 0 ? "3px" : 0 }}>
        {parseLine(line)}
      </div>
    );
  });
}

function PulsingDot() {
  return (
    <div style={{ position: "relative", width: "8px", height: "8px" }}>
      <div
        style={{
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          background: "#34D399",
          animation: "sentinelPulse 2s ease-in-out infinite",
        }}
      />
      <div style={{ position: "absolute", inset: 0, borderRadius: "50%", background: "#34D399" }} />
      <style>{`@keyframes sentinelPulse { 0%,100%{transform:scale(1);opacity:1} 50%{transform:scale(2.2);opacity:0} }`}</style>
    </div>
  );
}

function HeaderButton({
  icon: Icon,
  label,
  onClick,
  variant,
}: {
  icon: React.FC<any>;
  label: string;
  onClick: () => void;
  variant: "primary" | "danger";
}) {
  const [hovered, setHovered] = useState(false);
  const c =
    variant === "primary"
      ? {
          bg: hovered ? "rgba(14,165,233,0.2)" : "rgba(14,165,233,0.08)",
          border: hovered ? "rgba(14,165,233,0.5)" : "rgba(14,165,233,0.2)",
          color: "#0EA5E9",
          shadow: hovered ? "0 0 16px rgba(14,165,233,0.25)" : "none",
        }
      : {
          bg: hovered ? "rgba(239,68,68,0.15)" : "rgba(239,68,68,0.06)",
          border: hovered ? "rgba(239,68,68,0.4)" : "rgba(239,68,68,0.15)",
          color: hovered ? "#F87171" : "rgba(148,163,184,0.6)",
          shadow: hovered ? "0 0 16px rgba(239,68,68,0.15)" : "none",
        };

  return (
    <button
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "7px",
        padding: "9px 16px",
        borderRadius: "10px",
        background: c.bg,
        border: `1px solid ${c.border}`,
        color: c.color,
        cursor: "pointer",
        transition: "all 0.22s ease",
        boxShadow: c.shadow,
        fontSize: "13px",
        fontWeight: 500,
        letterSpacing: "0.01em",
        whiteSpace: "nowrap",
      }}
    >
      <Icon size={14} strokeWidth={2} />
      {label}
    </button>
  );
}

function QuickActionChip({
  action,
  onClick,
  disabled,
  index,
}: {
  action: (typeof QUICK_ACTIONS)[0];
  onClick: () => void;
  disabled: boolean;
  index: number;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <motion.button
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.06 + 0.2, duration: 0.4 }}
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        padding: "9px 16px",
        borderRadius: "40px",
        whiteSpace: "nowrap",
        flexShrink: 0,
        fontSize: "13px",
        fontWeight: 500,
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "all 0.22s ease",
        backdropFilter: "blur(16px)",
        WebkitBackdropFilter: "blur(16px)",
        opacity: disabled ? 0.5 : 1,
        transform: hovered && !disabled ? "translateY(-1px)" : "none",
        background: hovered ? `rgba(${hexToRgb(action.color)}, 0.15)` : "rgba(6,18,42,0.7)",
        border: hovered ? `1px solid rgba(${hexToRgb(action.color)}, 0.5)` : "1px solid rgba(14,165,233,0.12)",
        color: hovered ? action.color : "rgba(148,163,184,0.8)",
        boxShadow: hovered
          ? `0 0 20px rgba(${hexToRgb(action.color)}, 0.2), 0 4px 12px rgba(0,0,0,0.3)`
          : "0 2px 8px rgba(0,0,0,0.2)",
      }}
    >
      <action.icon size={13} strokeWidth={2} color={hovered ? action.color : "rgba(148,163,184,0.7)"} />
      {action.label}
    </motion.button>
  );
}

function MessageBubble({ message, index }: { message: Message; index: number }) {
  const isAI = message.role === "assistant";
  return (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1], delay: index * 0.03 }}
      style={{
        display: "flex",
        flexDirection: isAI ? "row" : "row-reverse",
        gap: "12px",
        alignItems: "flex-start",
        marginBottom: "20px",
      }}
    >
      <div
        style={{
          width: "36px",
          height: "36px",
          borderRadius: "10px",
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: isAI
            ? "linear-gradient(135deg,rgba(14,165,233,0.25),rgba(34,211,238,0.15))"
            : "linear-gradient(135deg,rgba(99,102,241,0.25),rgba(139,92,246,0.15))",
          border: isAI ? "1px solid rgba(14,165,233,0.4)" : "1px solid rgba(99,102,241,0.4)",
          boxShadow: isAI ? "0 0 12px rgba(14,165,233,0.2)" : "0 0 12px rgba(99,102,241,0.2)",
        }}
      >
        {isAI ? (
          <ShieldCheck size={16} color="#0EA5E9" strokeWidth={1.8} />
        ) : (
          <User size={16} color="#818CF8" strokeWidth={1.8} />
        )}
      </div>

      <div style={{ maxWidth: "75%", display: "flex", flexDirection: "column", gap: "6px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", justifyContent: isAI ? "flex-start" : "flex-end" }}>
          <span
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: isAI ? "#0EA5E9" : "#818CF8",
              letterSpacing: "0.08em",
              textTransform: "uppercase",
            }}
          >
            {isAI ? "Sentinel AI" : "You"}
          </span>
          <span style={{ fontSize: "10px", color: "rgba(148,163,184,0.5)" }}>{formatTime(message.timestamp)}</span>
          {isAI && message.providerUsed && (
            <span
              title={formatFallbackReason(message.fallbackReason)}
              style={{
                fontSize: "10px",
                color: providerBadgeColors(message.providerUsed).color,
                border: `1px solid ${providerBadgeColors(message.providerUsed).border}`,
                background: providerBadgeColors(message.providerUsed).background,
                borderRadius: "999px",
                padding: "2px 7px",
              }}
            >
              {providerBadgeLabel(message.providerUsed)}
            </span>
          )}
        </div>

        <div
          style={{
            padding: "14px 18px",
            borderRadius: isAI ? "4px 16px 16px 16px" : "16px 4px 16px 16px",
            background: isAI
              ? "linear-gradient(135deg,rgba(6,22,48,0.9),rgba(8,28,60,0.9))"
              : "linear-gradient(135deg,rgba(30,27,75,0.85),rgba(49,46,129,0.7))",
            border: isAI ? "1px solid rgba(14,165,233,0.2)" : "1px solid rgba(99,102,241,0.25)",
            boxShadow: "0 4px 24px rgba(0,0,0,0.3)",
            backdropFilter: "blur(20px)",
            WebkitBackdropFilter: "blur(20px)",
            fontSize: "14px",
            lineHeight: "1.65",
            color: isAI ? "rgba(226,232,240,0.95)" : "rgba(214,219,240,0.95)",
          }}
        >
          {renderContent(message.content)}
        </div>

        {isAI && (
          <div style={{ display: "flex", gap: "6px", paddingLeft: "4px" }}>
            {providerSwitchHelper(message.selectedProvider, message.providerUsed, message.fallbackReason) && (
              <span style={{ fontSize: "11px", color: "rgba(148,163,184,0.68)", padding: "3px 2px" }}>
                {providerSwitchHelper(message.selectedProvider, message.providerUsed, message.fallbackReason)}
              </span>
            )}
            {[{ icon: Copy, label: "Copy" }, { icon: ThumbsUp, label: "Like" }].map(({ icon: Icon, label }) => (
              <button
                key={label}
                title={label}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                  padding: "3px 8px",
                  borderRadius: "6px",
                  background: "transparent",
                  border: "1px solid rgba(14,165,233,0.1)",
                  color: "rgba(100,116,139,0.8)",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                  fontSize: "10px",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(14,165,233,0.1)";
                  e.currentTarget.style.color = "#0EA5E9";
                  e.currentTarget.style.borderColor = "rgba(14,165,233,0.3)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "transparent";
                  e.currentTarget.style.color = "rgba(100,116,139,0.8)";
                  e.currentTarget.style.borderColor = "rgba(14,165,233,0.1)";
                }}
              >
                <Icon size={11} strokeWidth={1.8} />
              </button>
            ))}
          </div>
        )}
      </div>
    </motion.div>
  );
}

function TypingIndicator() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 10 }}
      transition={{ duration: 0.3 }}
      style={{ display: "flex", alignItems: "flex-start", gap: "12px", marginBottom: "20px" }}
    >
      <div
        style={{
          width: "36px",
          height: "36px",
          borderRadius: "10px",
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "linear-gradient(135deg,rgba(14,165,233,0.25),rgba(34,211,238,0.15))",
          border: "1px solid rgba(14,165,233,0.4)",
          boxShadow: "0 0 12px rgba(14,165,233,0.2)",
        }}
      >
        <ShieldCheck size={16} color="#0EA5E9" strokeWidth={1.8} />
      </div>
      <div>
        <div style={{ fontSize: "11px", fontWeight: 600, color: "#0EA5E9", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: "6px" }}>
          Sentinel AI
        </div>
        <div
          style={{
            padding: "14px 20px",
            borderRadius: "4px 16px 16px 16px",
            background: "linear-gradient(135deg,rgba(6,22,48,0.9),rgba(8,28,60,0.9))",
            border: "1px solid rgba(14,165,233,0.2)",
            boxShadow: "0 4px 24px rgba(0,0,0,0.3)",
            backdropFilter: "blur(20px)",
            WebkitBackdropFilter: "blur(20px)",
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <span style={{ fontSize: "11px", color: "rgba(148,163,184,0.7)", marginRight: "4px" }}>Analyzing</span>
          {[0, 1, 2].map((i) => (
            <motion.span
              key={i}
              style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#0EA5E9", display: "inline-block" }}
              animate={{ opacity: [0.3, 1, 0.3], scale: [0.8, 1.2, 0.8] }}
              transition={{ duration: 1.2, repeat: Infinity, delay: i * 0.2, ease: "easeInOut" }}
            />
          ))}
        </div>
      </div>
    </motion.div>
  );
}

function ChatInput({
  value,
  onChange,
  onKeyDown,
  onSend,
  disabled,
  textareaRef,
  placeholder,
}: {
  value: string;
  onChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLTextAreaElement>) => void;
  onSend: () => void;
  disabled: boolean;
  textareaRef: React.RefObject<HTMLTextAreaElement | null>;
  placeholder: string;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-end",
        gap: "12px",
        padding: "10px 14px",
        borderRadius: "14px",
        transition: "all 0.25s ease",
        background: focused ? "rgba(6,22,55,0.9)" : "rgba(4,14,34,0.8)",
        border: focused ? "1px solid rgba(14,165,233,0.4)" : "1px solid rgba(14,165,233,0.15)",
        boxShadow: focused ? "0 0 0 3px rgba(14,165,233,0.06), 0 0 24px rgba(14,165,233,0.12)" : "0 2px 8px rgba(0,0,0,0.2)",
      }}
    >
      <button
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: "34px",
          height: "34px",
          borderRadius: "8px",
          background: "rgba(14,165,233,0.06)",
          border: "1px solid rgba(14,165,233,0.12)",
          color: "rgba(100,116,139,0.7)",
          cursor: "pointer",
          flexShrink: 0,
        }}
      >
        <Paperclip size={14} strokeWidth={1.8} />
      </button>
      <textarea
        ref={textareaRef}
        value={value}
        onChange={onChange}
        onKeyDown={onKeyDown}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        disabled={disabled}
        placeholder={placeholder}
        rows={1}
        style={{
          flex: 1,
          background: "transparent",
          border: "none",
          outline: "none",
          resize: "none",
          color: "rgba(226,232,240,0.95)",
          fontSize: "14px",
          lineHeight: "1.6",
          padding: "4px 0",
          maxHeight: "140px",
          overflowY: "hidden",
          fontFamily: "inherit",
        }}
      />
      <button
        onClick={onSend}
        disabled={disabled || !value.trim()}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: "36px",
          height: "36px",
          borderRadius: "10px",
          flexShrink: 0,
          transition: "all 0.22s ease",
          background: value.trim() && !disabled ? "linear-gradient(135deg,#0EA5E9,#06B6D4)" : "rgba(14,165,233,0.08)",
          border: value.trim() && !disabled ? "1px solid rgba(14,165,233,0.5)" : "1px solid rgba(14,165,233,0.1)",
          color: value.trim() && !disabled ? "#fff" : "rgba(100,116,139,0.4)",
          cursor: value.trim() && !disabled ? "pointer" : "not-allowed",
          boxShadow: value.trim() && !disabled ? "0 0 20px rgba(14,165,233,0.4),0 4px 12px rgba(0,0,0,0.3)" : "none",
        }}
      >
        <Send size={15} strokeWidth={2} />
      </button>
    </div>
  );
}

type ModuleInfoPanel = {
  icon: React.FC<any>;
  title: string;
  badge: string;
  color: string;
  stat: string;
  description: string;
};

function InfoCard({ panel, index }: { panel: ModuleInfoPanel; index: number }) {
  const [hovered, setHovered] = useState(false);
  const rgb = hexToRgb(panel.color);
  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.08 + 0.3, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        padding: "16px",
        borderRadius: "14px",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        cursor: "default",
        transition: "all 0.25s ease",
        background: hovered ? `rgba(${rgb},0.07)` : "rgba(6,18,42,0.65)",
        border: hovered ? `1px solid rgba(${rgb},0.35)` : "1px solid rgba(14,165,233,0.12)",
        boxShadow: hovered ? `0 0 24px rgba(${rgb},0.12),0 8px 24px rgba(0,0,0,0.3)` : "0 4px 16px rgba(0,0,0,0.2)",
        transform: hovered ? "translateY(-2px)" : "none",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div
            style={{
              width: "32px",
              height: "32px",
              borderRadius: "8px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: `rgba(${rgb},0.15)`,
              border: `1px solid rgba(${rgb},0.3)`,
              boxShadow: hovered ? `0 0 12px rgba(${rgb},0.3)` : "none",
              transition: "box-shadow 0.25s ease",
            }}
          >
            <panel.icon size={15} color={panel.color} strokeWidth={1.8} />
          </div>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "rgba(226,232,240,0.9)" }}>{panel.title}</span>
        </div>
        <span
          style={{
            fontSize: "10px",
            fontWeight: 600,
            color: panel.color,
            background: `rgba(${rgb},0.12)`,
            border: `1px solid rgba(${rgb},0.25)`,
            borderRadius: "20px",
            padding: "2px 8px",
            letterSpacing: "0.05em",
          }}
        >
          {panel.badge}
        </span>
      </div>
      <p style={{ margin: "0 0 10px", fontSize: "12px", lineHeight: "1.6", color: "rgba(100,116,139,0.85)" }}>{panel.description}</p>
      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
        <div style={{ height: "2px", flex: 1, borderRadius: "1px", background: `linear-gradient(90deg,rgba(${rgb},0.6),rgba(${rgb},0.1))` }} />
        <span style={{ fontSize: "11px", fontWeight: 600, color: panel.color, letterSpacing: "0.04em" }}>{panel.stat}</span>
      </div>
    </motion.div>
  );
}

function SystemStatus({ systems }: { systems: Array<{ label: string; status: string; color: string }> }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.65, duration: 0.5 }}
      style={{
        padding: "16px",
        borderRadius: "14px",
        background: "rgba(6,18,42,0.65)",
        border: "1px solid rgba(14,165,233,0.12)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
        <Lock size={13} color="#818CF8" strokeWidth={1.8} />
        <span style={{ fontSize: "11px", fontWeight: 600, color: "rgba(148,163,184,0.7)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
          System Status
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {systems.map((sys) => (
          <div key={sys.label} style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: "12px", color: "rgba(100,116,139,0.85)" }}>{sys.label}</span>
            <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
              <div style={{ width: "6px", height: "6px", borderRadius: "50%", background: sys.color, boxShadow: `0 0 6px ${sys.color}` }} />
              <span style={{ fontSize: "11px", fontWeight: 600, color: sys.color }}>{sys.status}</span>
            </div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: "14px", paddingTop: "10px", borderTop: "1px solid rgba(14,165,233,0.08)", display: "flex", alignItems: "center", gap: "6px" }}>
        <ShieldCheck size={12} color="#34D399" strokeWidth={2} />
        <span style={{ fontSize: "11px", color: "rgba(52,211,153,0.8)" }}>All systems operational</span>
      </div>
    </motion.div>
  );
}

function CyberBackground() {
  return (
    <>
      <div
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage:
            "linear-gradient(rgba(14,165,233,0.035) 1px,transparent 1px),linear-gradient(90deg,rgba(14,165,233,0.035) 1px,transparent 1px)",
          backgroundSize: "52px 52px",
          pointerEvents: "none",
        }}
      />
      <div
        style={{
          position: "absolute",
          top: "-250px",
          left: "-250px",
          width: "700px",
          height: "700px",
          background: "radial-gradient(circle,rgba(14,165,233,0.09) 0%,rgba(14,165,233,0.02) 50%,transparent 70%)",
          borderRadius: "50%",
          pointerEvents: "none",
        }}
      />
      <div
        style={{
          position: "absolute",
          bottom: "-250px",
          right: "-200px",
          width: "600px",
          height: "600px",
          background: "radial-gradient(circle,rgba(99,102,241,0.09) 0%,rgba(99,102,241,0.02) 50%,transparent 70%)",
          borderRadius: "50%",
          pointerEvents: "none",
        }}
      />
      <div
        style={{
          position: "absolute",
          top: "30%",
          left: "50%",
          transform: "translateX(-50%)",
          width: "800px",
          height: "400px",
          background: "radial-gradient(ellipse,rgba(14,165,233,0.04) 0%,transparent 70%)",
          pointerEvents: "none",
        }}
      />
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: "1px",
          background:
            "linear-gradient(90deg,transparent 0%,rgba(14,165,233,0.3) 30%,rgba(34,211,238,0.4) 50%,rgba(14,165,233,0.3) 70%,transparent 100%)",
          pointerEvents: "none",
        }}
      />
      <div
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage: "radial-gradient(circle,rgba(14,165,233,0.12) 1px,transparent 1px)",
          backgroundSize: "104px 104px",
          backgroundPosition: "26px 26px",
          pointerEvents: "none",
          opacity: 0.4,
        }}
      />
    </>
  );
}

export function ChatbotWorkspacePage() {
  const [activeModule, setActiveModule] = useState(DEFAULT_MODULE);
  const [messages, setMessages] = useState<Message[]>(() => [createInitialMessage(DEFAULT_MODULE)]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [providerPreference, setProviderPreference] = useState<ChatbotProviderPreference>(() => readChatbotProviderPreference());
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const chatRef = useRef<HTMLDivElement>(null);
  const identityScanId = (() => {
    if (typeof window === "undefined") return null;
    const raw = new URLSearchParams(window.location.search).get("scan_id");
    const parsed = raw ? Number(raw) : NaN;
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
  })();
  const pcapAnalysisId = (() => {
    if (typeof window === "undefined") return null;
    const params = new URLSearchParams(window.location.search);
    return params.get("analysis_id") || params.get("job_id") || null;
  })();

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isTyping]);

  useEffect(() => {
    setMessages([createInitialMessage(activeModule)]);
    setInput("");
    setIsTyping(false);
    if (textareaRef.current) textareaRef.current.style.height = "auto";
  }, [activeModule]);

  useEffect(() => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(CHATBOT_PROVIDER_STORAGE_KEY, providerPreference);
    }
  }, [providerPreference]);

  const activeContext = MODULE_CONTEXT[activeModule.id];

  const sendMessage = async (content: string, moduleOverride?: string) => {
    if (!content.trim() || isTyping) return;
    const targetModuleId = moduleOverride || activeModule.id;

    setMessages((prev) => [
      ...prev,
      { id: `u-${Date.now()}`, role: "user", content: content.trim(), timestamp: new Date() },
    ]);
    setInput("");
    setIsTyping(true);

    if (textareaRef.current) textareaRef.current.style.height = "auto";

    await new Promise((r) => setTimeout(r, 900 + Math.random() * 500));

    let assistantContent: string;
    let providerUsed: Message["providerUsed"];
    let selectedProvider: Message["selectedProvider"];
    let fallbackUsed: boolean | undefined;
    let fallbackReason: string | null | undefined;
    if (shouldRunLiveVaultAnalysis(content, targetModuleId)) {
      assistantContent = await fetchLiveVaultAiResponse();
    } else {
      const assistantResponse = await fetchLlmChatbotResponse(content, targetModuleId, providerPreference);
      assistantContent = assistantResponse.content;
      providerUsed = assistantResponse.providerUsed;
      selectedProvider = assistantResponse.selectedProvider;
      fallbackUsed = assistantResponse.fallbackUsed;
      fallbackReason = assistantResponse.fallbackReason;
    }

    setIsTyping(false);
    setMessages((prev) => [
      ...prev,
      {
        id: `a-${Date.now()}`,
        role: "assistant",
        content: assistantContent,
        timestamp: new Date(),
        providerUsed,
        selectedProvider,
        fallbackUsed,
        fallbackReason,
      },
    ]);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void sendMessage(input);
    }
  };

  const handleTextareaChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    e.target.style.height = "auto";
    e.target.style.height = Math.min(e.target.scrollHeight, 140) + "px";
  };

  const clearChat = () => {
    setMessages([createInitialMessage(activeModule)]);
    setIsTyping(false);
  };

  const downloadChat = () => {
    const text = messages
      .map((m) => `[${m.role.toUpperCase()}] ${m.timestamp.toLocaleTimeString()}\n${m.content}`)
      .join("\n\n---------------------------------\n\n");
    const blob = new Blob([`SENTINEL AI - CHAT EXPORT\n${"=".repeat(40)}\n\n${text}`], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-ai-chat-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      style={{
        height: "auto",
        overflowY: "visible",
        overflowX: "hidden",
        width: "100%",
        maxWidth: "100%",
        boxSizing: "border-box",
        background: "linear-gradient(145deg,#020B18 0%,#020E20 35%,#030F28 65%,#020B18 100%)",
        position: "relative",
        fontFamily: "'Inter','Space Grotesk',system-ui,sans-serif",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <CyberBackground />

      <div
        style={{
          position: "relative",
          zIndex: 1,
          display: "flex",
          flexDirection: "column",
          height: "auto",
          maxWidth: "100%",
          width: "100%",
          margin: "0 auto",
          padding: "16px 20px",
          gap: "16px",
          boxSizing: "border-box",
          overflowY: "visible",
          overflowX: "hidden",
        }}
      >
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          style={{
            ...glassStrong,
            padding: "20px 28px",
            display: "flex",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "20px",
            flexShrink: 0,
            boxShadow: "0 0 0 1px rgba(14,165,233,0.1),0 8px 32px rgba(0,0,0,0.4),0 0 80px rgba(14,165,233,0.06)",
            background: "linear-gradient(135deg,rgba(4,14,34,0.92) 0%,rgba(6,22,55,0.88) 50%,rgba(4,14,34,0.92) 100%)",
            borderColor: "rgba(14,165,233,0.22)",
          }}
        >
          <div
            style={{
              width: "52px",
              height: "52px",
              borderRadius: "14px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "linear-gradient(135deg,rgba(14,165,233,0.2),rgba(34,211,238,0.1))",
              border: "1px solid rgba(14,165,233,0.35)",
              boxShadow: "0 0 24px rgba(14,165,233,0.3),0 0 48px rgba(14,165,233,0.1),inset 0 1px 0 rgba(255,255,255,0.05)",
              flexShrink: 0,
              position: "relative",
            }}
          >
            <Shield size={24} color="#0EA5E9" strokeWidth={1.6} />
            <div
              style={{
                position: "absolute",
                top: "4px",
                right: "4px",
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: "#22D3EE",
                boxShadow: "0 0 6px #22D3EE",
              }}
            />
          </div>

          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
              <h1
                style={{
                  margin: 0,
                  fontSize: "22px",
                  fontWeight: 700,
                  background: "linear-gradient(90deg,#E2E8F0,#94A3B8)",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  backgroundClip: "text",
                  letterSpacing: "-0.01em",
                  lineHeight: 1.2,
                  fontFamily: "'Space Grotesk','Inter',sans-serif",
                }}
              >
                Sentinel AI Assistant
              </h1>
              <div
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "4px 10px",
                  borderRadius: "20px",
                  background: "rgba(14,165,233,0.12)",
                  border: "1px solid rgba(14,165,233,0.3)",
                  boxShadow: "0 0 10px rgba(14,165,233,0.1)",
                }}
              >
                <Cpu size={10} color="#0EA5E9" strokeWidth={2} />
                <span style={{ fontSize: "11px", fontWeight: 600, color: "#0EA5E9", letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  {activeModule.label}
                </span>
              </div>
              <div
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "4px 10px",
                  borderRadius: "20px",
                  background: "rgba(52,211,153,0.1)",
                  border: "1px solid rgba(52,211,153,0.25)",
                }}
              >
                <PulsingDot />
                <span style={{ fontSize: "11px", fontWeight: 600, color: "#34D399", letterSpacing: "0.06em" }}>Ready</span>
              </div>
            </div>
          </div>

          <div style={{ display: "flex", gap: "10px", flexShrink: 0, flexWrap: "wrap", marginLeft: "auto", alignItems: "center" }}>
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "7px 10px",
                borderRadius: "10px",
                background: "rgba(6,18,42,0.66)",
                border: "1px solid rgba(14,165,233,0.18)",
                color: "rgba(226,232,240,0.86)",
              }}
              title={CHATBOT_PROVIDER_OPTIONS.find((option) => option.value === providerPreference)?.helper}
            >
              <Cpu size={13} color="#67E8F9" strokeWidth={1.8} />
              <span style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "rgba(148,163,184,0.78)" }}>
                Provider
              </span>
              <select
                value={providerPreference}
                onChange={(event) => setProviderPreference(normalizeChatbotProviderPreference(event.target.value))}
                disabled={isTyping}
                style={{
                  minWidth: "132px",
                  border: "1px solid rgba(14,165,233,0.2)",
                  borderRadius: "8px",
                  background: "rgba(2,8,23,0.9)",
                  color: "#E2E8F0",
                  padding: "6px 8px",
                  fontSize: "12px",
                  fontWeight: 600,
                  outline: "none",
                  cursor: isTyping ? "not-allowed" : "pointer",
                }}
              >
                {CHATBOT_PROVIDER_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <HeaderButton icon={Trash2} label="Clear Chat" onClick={clearChat} variant="danger" />
            <HeaderButton icon={Download} label="Download" onClick={downloadChat} variant="primary" />
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.15 }}
          style={{ flexShrink: 0 }}
        >
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "14px" }}>
            {MODULE_OPTIONS.map((module) => {
              const isActive = activeModule.id === module.id;
              return (
                <button
                  key={module.id}
                  onClick={() => setActiveModule(module)}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    padding: "8px 14px",
                    borderRadius: "999px",
                    border: `1px solid ${isActive ? module.color : "rgba(14,165,233,0.12)"}`,
                    background: isActive ? `rgba(${hexToRgb(module.color)},0.14)` : "rgba(6,18,42,0.55)",
                    color: isActive ? module.color : "rgba(148,163,184,0.8)",
                    cursor: "pointer",
                    fontSize: "12px",
                    fontWeight: 600,
                    letterSpacing: "0.03em",
                    transition: "all 0.2s ease",
                    boxShadow: isActive ? `0 0 18px rgba(${hexToRgb(module.color)},0.18)` : "none",
                  }}
                >
                  {module.shortLabel}
                </button>
              );
            })}
          </div>
          {(MODULE_QUICK_ACTIONS[activeModule.id] || []).length > 0 && (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px", paddingLeft: "2px" }}>
                <Zap size={13} color="#F59E0B" strokeWidth={2} />
                <span style={{ fontSize: "11px", fontWeight: 600, color: "rgba(148,163,184,0.65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
                  Quick Actions
                </span>
              </div>
              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  overflowX: "visible",
                  overflowY: "visible",
                  paddingBottom: "4px",
                  scrollbarWidth: "none",
                  flexWrap: "wrap",
                }}
              >
                {(MODULE_QUICK_ACTIONS[activeModule.id] || []).map((action, i) => (
                  <QuickActionChip key={action.label} action={action} onClick={() => void sendMessage(action.label, activeModule.id === "pcap" ? "pcap" : activeModule.id)} disabled={isTyping} index={i} />
                ))}
              </div>
            </>
          )}
        </motion.div>

        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "16px",
            flex: "0 0 auto",
            minHeight: "auto",
            alignItems: "stretch",
            width: "100%",
            maxWidth: "100%",
            overflow: "visible",
          }}
        >
          <div
            style={{
              ...glassStrong,
              flex: "1 1 720px",
              display: "flex",
              flexDirection: "column",
              minWidth: 0,
              overflow: "visible",
              boxShadow: "0 0 0 1px rgba(14,165,233,0.08),0 8px 40px rgba(0,0,0,0.5),0 0 60px rgba(14,165,233,0.04)",
              width: "100%",
              maxWidth: "100%",
            }}
          >
            <div style={{ padding: "14px 20px", borderBottom: "1px solid rgba(14,165,233,0.1)", display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
              <Activity size={14} color="#0EA5E9" strokeWidth={1.8} />
              <span style={{ fontSize: "12px", color: "rgba(148,163,184,0.8)", letterSpacing: "0.06em", textTransform: "uppercase", fontWeight: 500 }}>
                Live Session
              </span>
              <div style={{ flex: 1 }} />
              <span style={{ fontSize: "11px", color: "rgba(100,116,139,0.7)" }}>
                {messages.length} message{messages.length !== 1 ? "s" : ""}
              </span>
            </div>

            <div
              ref={chatRef}
              style={{
                flex: "0 0 auto",
                overflowY: "visible",
                overflowX: "visible",
                padding: "24px 20px 8px",
              }}
            >
              {messages.map((msg, i) => (
                <MessageBubble key={msg.id} message={msg} index={i} />
              ))}
              <AnimatePresence>{isTyping && <TypingIndicator />}</AnimatePresence>
              <div ref={messagesEndRef} />
            </div>

            <div style={{ padding: "16px 20px", borderTop: "1px solid rgba(14,165,233,0.1)", flexShrink: 0 }}>
              <ChatInput
                value={input}
                onChange={handleTextareaChange}
                onKeyDown={handleKeyDown}
                onSend={() => void sendMessage(input)}
                disabled={isTyping}
                textareaRef={textareaRef}
                placeholder={activeModule.prompt}
              />
            </div>
          </div>

          <div
            style={{
              flex: "0 1 300px",
              width: "100%",
              maxWidth: "100%",
              display: "flex",
              flexDirection: "column",
              gap: "12px",
              overflowY: "visible",
              overflowX: "visible",
              minWidth: 0,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px", paddingLeft: "4px" }}>
              <Database size={13} color="#0EA5E9" strokeWidth={1.8} />
              <span style={{ fontSize: "11px", fontWeight: 600, color: "rgba(148,163,184,0.7)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
                Knowledge Context
              </span>
            </div>
            {activeContext.panels.map((panel, i) => (
              <InfoCard key={panel.title} panel={panel} index={i} />
            ))}
            <SystemStatus systems={activeContext.systems} />
          </div>
        </div>
      </div>
    </div>
  );
}

export default ChatbotWorkspacePage;
