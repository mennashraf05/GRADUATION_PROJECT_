import React, { useEffect, useMemo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { RecentSecurityAlertsPanel } from '../security/RecentSecurityAlertsPanel';
import { NetworkSecurityScoreCard } from '../security/NetworkSecurityScoreCard';
import { GamificationDashboardSection } from '../gamification/GamificationDashboardSection';
import { useLanguage } from '../../contexts/LanguageContext';
import {
  AlertTriangle,
  Brain,
  CalendarRange,
  Lock,
  Shield,
  Sparkles,
} from 'lucide-react';
import { Button } from '../ui/button';
import { useNavigate } from 'react-router-dom';

const DEFAULT_LOCAL_API_BASE = 'http://127.0.0.1:5000';

type VaultDocument = {
  id: number;
  filename: string;
  size_bytes?: number;
  offline_enabled?: boolean;
};

type VaultPattern = {
  type?: string;
  name?: string;
  action_type?: string;
  title?: string;
  count?: number;
  severity?: string;
  risk_score?: number;
  score?: number;
  scope?: string;
  target_label?: string;
  message?: string;
  description?: string;
};

type VaultAiResult = {
  risk_score?: number;
  final_risk_score?: number;
  severity?: string;
  active_risks?: VaultPattern[];
  user_risks?: VaultPattern[];
  file_risks?: VaultPattern[];
  suspicious_patterns?: VaultPattern[];
  patterns?: VaultPattern[];
  created_alert?: boolean;
  alert_created?: boolean;
  message?: string;
};

type SecurityScorePayload = {
  global_score?: number | null;
  score?: number | null;
  overall_score?: number | null;
  risk_level?: 'Excellent' | 'Good' | 'Moderate' | 'High Risk' | 'Critical' | 'Not Assessed';
  status?: 'Excellent' | 'Good' | 'Moderate' | 'High Risk' | 'Critical' | 'Needs Attention' | 'not_assessed' | 'setup_incomplete';
  message?: string;
  modules: Record<
    'password' | 'vault' | 'file_vault' | 'phishing' | 'identity',
    {
      internal_score?: number | null;
      contribution?: number | null;
      assessed?: boolean;
      weight?: number;
      score?: number | null;
      module_score?: number | null;
      weighted_score?: number | null;
      available?: boolean;
      status: 'Excellent' | 'Good' | 'Moderate' | 'High Risk' | 'Critical' | 'Not Assessed' | 'safe' | 'warning' | 'risky' | 'unknown' | 'not_checked' | 'no_files' | 'no_scans' | 'no_scan';
      risk_level?: string;
      label?: string;
      summary?: string;
      recommendation?: string;
    }
  >;
  last_updated?: string | null;
  generated_at?: string;
};

function normalizeApiBase(raw: string) {
  const trimmed = String(raw || '').trim().replace(/\/$/, '');
  if (!trimmed) return '';
  try {
    const url = new URL(trimmed);
    if (typeof window !== 'undefined') {
      const currentHost = window.location.hostname;
      const isCurrentLocal = currentHost === 'localhost' || currentHost === '127.0.0.1';
      const isTargetLocal = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
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
  if (value === '') {
    if (!candidates.includes('')) candidates.push('');
    return;
  }
  const normalized = normalizeApiBase(value);
  if (normalized && !candidates.includes(normalized)) {
    candidates.push(normalized);
  }
}

const API_BASE_URL = (() => {
  const envBase = normalizeApiBase(String(import.meta.env.VITE_API_BASE_URL || ''));
  if (envBase) return envBase;
  if (typeof window !== 'undefined') {
    const host = window.location.hostname;
    if (host === 'localhost' || host === '127.0.0.1') {
      return `${window.location.protocol}//${host}:5000`;
    }
  }
  return DEFAULT_LOCAL_API_BASE;
})();

const MONTHLY_REPORT_API_BASE_CANDIDATES = (() => {
  const candidates: string[] = [];
  if (import.meta.env.DEV) {
    pushApiBase(candidates, '');
  }
  pushApiBase(candidates, API_BASE_URL);
  if (typeof window !== 'undefined') {
    const host = window.location.hostname;
    const protocol = window.location.protocol;
    if (host) {
      pushApiBase(candidates, `${protocol}//${host}:5000`);
      pushApiBase(candidates, `http://${host}:5000`);
    }
    if (host === 'localhost' || host === '127.0.0.1') {
      pushApiBase(candidates, 'http://127.0.0.1:5000');
      pushApiBase(candidates, 'http://localhost:5000');
    }
  }
  pushApiBase(candidates, DEFAULT_LOCAL_API_BASE);
  return candidates;
})();

function buildAuthedFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  const token = localStorage.getItem('sentinel_auth_token');
  if (token && token !== 'cookie_based') {
    headers.set('Authorization', `Bearer ${token}`);
  }
  return { ...init, credentials: 'include', headers };
}

function buildCookieOnlyFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.delete('Authorization');
  return { ...init, credentials: 'include', headers };
}

async function fetchWithMonthlyReportAuth(input: RequestInfo | URL, init: RequestInit = {}) {
  const cookieResponse = await fetch(input, buildCookieOnlyFetchInit(init));
  if (cookieResponse.status !== 401 && cookieResponse.status !== 403) {
    return cookieResponse;
  }
  const token = localStorage.getItem('sentinel_auth_token');
  if (token && token !== 'cookie_based') {
    return fetch(input, buildAuthedFetchInit(init));
  }
  return cookieResponse;
}

function buildMonthlyReportUrl(path: string, base: string) {
  return base ? `${base}${path}` : path;
}

async function fetchMonthlyReportResponse(path: string, init: RequestInit = {}) {
  for (const base of MONTHLY_REPORT_API_BASE_CANDIDATES) {
    const response = await fetchWithMonthlyReportAuth(buildMonthlyReportUrl(path, base), init);
    const contentType = String(response.headers.get('content-type') || '').toLowerCase();
    if (contentType.includes('text/html')) {
      continue;
    }
    return response;
  }
  throw new Error('Monthly Reports endpoint returned HTML instead of JSON.');
}

function formatBytes(bytes?: number) {
  const value = Number(bytes || 0);
  if (value <= 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / Math.pow(1024, index)).toFixed(1)} ${units[index]}`;
}

function humanize(value?: string) {
  return String(value || '')
    .replaceAll('_', ' ')
    .replaceAll('-', ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

function normalizeSeverity(value?: string) {
  return String(value || 'safe').trim().toLowerCase();
}

function severityColor(value?: string) {
  const sev = normalizeSeverity(value);
  if (sev === 'critical') return 'text-red-400';
  if (sev === 'high') return 'text-orange-400';
  if (sev === 'medium' || sev === 'warning') return 'text-yellow-300';
  if (sev === 'low' || sev === 'info') return 'text-blue-300';
  return 'text-green-400';
}

function severityBorder(value?: string) {
  const sev = normalizeSeverity(value);
  if (sev === 'critical') return 'border-red-500/30';
  if (sev === 'high') return 'border-orange-500/30';
  if (sev === 'medium' || sev === 'warning') return 'border-yellow-500/30';
  if (sev === 'low' || sev === 'info') return 'border-blue-500/30';
  return 'border-green-500/30';
}

function securityScoreColor(status?: string) {
  const value = String(status || '').toLowerCase();
  if (value === 'critical') return 'text-red-400';
  if (value === 'high risk') return 'text-orange-400';
  if (value === 'needs attention' || value === 'moderate') return 'text-yellow-300';
  if (value === 'good') return 'text-cyan-300';
  if (value === 'not assessed' || value === 'not_assessed') return 'text-gray-300';
  return 'text-green-400';
}

function securityScoreBorder(status?: string) {
  const value = String(status || '').toLowerCase();
  if (value === 'critical') return 'border-red-500/30';
  if (value === 'high risk') return 'border-orange-500/30';
  if (value === 'needs attention' || value === 'moderate') return 'border-yellow-500/30';
  if (value === 'good') return 'border-cyan-500/30';
  if (value === 'not assessed' || value === 'not_assessed') return 'border-gray-500/30';
  return 'border-green-500/30';
}

function securityScoreToneClass(score: number) {
  if (score <= 20) return 'text-red-400';
  if (score <= 40) return 'text-orange-400';
  if (score <= 60) return 'text-yellow-300';
  if (score <= 80) return 'text-cyan-300';
  return 'text-green-400';
}

function formatContribution(value: number | null | undefined) {
  const numeric = Number(value ?? 0);
  const bounded = Math.max(0, Math.min(25, Number.isFinite(numeric) ? numeric : 0));
  return Number.isInteger(bounded) ? `+${bounded}%` : `+${bounded.toFixed(1)}%`;
}

function formatSecurityTimestamp(value?: string | null) {
  if (!value) return 'Not updated yet';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function patternRiskScore(pattern: VaultPattern) {
  const direct = Number(pattern.risk_score ?? pattern.score ?? 0);
  if (Number.isFinite(direct) && direct > 0) {
    return Math.max(0, Math.min(100, direct));
  }

  const sev = normalizeSeverity(pattern.severity);
  if (sev === 'critical') return 95;
  if (sev === 'high') return 82;
  if (sev === 'medium' || sev === 'warning') return 65;
  if (sev === 'low' || sev === 'info') return 35;
  return 0;
}

function patternTitle(pattern: VaultPattern) {
  const raw = [
    pattern.type,
    pattern.name,
    (pattern as any).action_type,
    (pattern as any).title,
    pattern.message,
    pattern.description,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  if (raw.includes('password') || raw.includes('wrong vault')) return 'Wrong Password Attempts';
  if (raw.includes('download')) return 'Download Activity';
  if (raw.includes('delete') || raw.includes('deletion')) return 'File Deletion';
  if (raw.includes('offline')) return 'Offline Access';

  return 'Suspicious Activity';
}

function riskLabelFromScore(score: number) {
  if (score >= 90) return 'Critical';
  if (score >= 80) return 'High';
  if (score >= 60) return 'Medium';
  if (score > 0) return 'Low';
  return 'Safe';
}

function patternScopeLabel(pattern: VaultPattern) {
  return pattern.scope === 'file' ? 'File-level' : 'User-level';
}

function patternGroupKey(pattern: VaultPattern) {
  return pattern.target_label || 'All Vault Files';
}

function groupedPatternTitle(targetLabel: string) {
  return targetLabel === 'All Vault Files' ? 'All Vault Files' : targetLabel;
}

export function SimpleDashboard() {
  const { language, isRtl, formatNumber } = useLanguage();
  const navigate = useNavigate();

  const [latestReport, setLatestReport] = useState<any>(null);
  const [vaultDocs, setVaultDocs] = useState<VaultDocument[]>([]);
  const [vaultLoading, setVaultLoading] = useState(false);
  const [vaultAiLoading, setVaultAiLoading] = useState(false);
  const [vaultAiResult, setVaultAiResult] = useState<VaultAiResult | null>(null);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [lastVaultAnalysisAt, setLastVaultAnalysisAt] = useState<string | null>(null);
  const [securityScoreData, setSecurityScoreData] = useState<SecurityScorePayload | null>(null);
  const [securityScoreLoading, setSecurityScoreLoading] = useState(true);

  const vaultStorageBytes = useMemo(
    () => vaultDocs.reduce((sum, doc) => sum + Number(doc.size_bytes || 0), 0),
    [vaultDocs]
  );

  const vaultOfflineCount = useMemo(
    () => vaultDocs.filter(doc => Boolean(doc.offline_enabled)).length,
    [vaultDocs]
  );

  const vaultPatterns = useMemo(() => {
    const raw =
      vaultAiResult?.active_risks ||
      vaultAiResult?.suspicious_patterns ||
      vaultAiResult?.patterns ||
      [];
    return Array.isArray(raw) ? raw : [];
  }, [vaultAiResult]);

  const sortedVaultPatterns = useMemo(() => {
    return [...vaultPatterns].sort((a, b) => patternRiskScore(b) - patternRiskScore(a));
  }, [vaultPatterns]);

  const groupedVaultPatterns = useMemo(() => {
    const groups = new Map<string, { targetLabel: string; patterns: VaultPattern[]; maxRisk: number; topSeverity: string }>();

    for (const pattern of sortedVaultPatterns) {
      const targetLabel = patternGroupKey(pattern);
      const risk = patternRiskScore(pattern);
      const severity = pattern.severity || riskLabelFromScore(risk);
      const current = groups.get(targetLabel);

      if (!current) {
        groups.set(targetLabel, {
          targetLabel,
          patterns: [pattern],
          maxRisk: risk,
          topSeverity: severity,
        });
        continue;
      }

      current.patterns.push(pattern);
      if (risk > current.maxRisk) {
        current.maxRisk = risk;
        current.topSeverity = severity;
      }
    }

    return Array.from(groups.values()).sort((a, b) => b.maxRisk - a.maxRisk);
  }, [sortedVaultPatterns]);

  const vaultRiskScore = Math.max(
    0,
    Math.min(100, Number(vaultAiResult?.final_risk_score ?? vaultAiResult?.risk_score ?? 0))
  );
  const vaultSeverity = String(
    vaultAiResult?.severity || (vaultRiskScore > 0 ? riskLabelFromScore(vaultRiskScore).toLowerCase() : 'safe')
  );
  const vaultSecurityScore = Math.max(0, Math.min(100, 100 - vaultRiskScore));
  const rawSecurityScore =
    securityScoreData?.global_score ??
    securityScoreData?.score ??
    securityScoreData?.overall_score ??
    0;
  const combinedSecurityScore = Math.max(0, Math.min(100, Number(rawSecurityScore) || 0));
  const combinedSecurityStatus = securityScoreData?.risk_level || securityScoreData?.status || 'Not Assessed';
  const globalScoreDisplay = securityScoreLoading && !securityScoreData ? '--' : `${combinedSecurityScore}%`;
  const topVaultPattern = sortedVaultPatterns[0];
  const hasActiveThreat =
    sortedVaultPatterns.length > 0 ||
    vaultRiskScore >= 50 ||
    normalizeSeverity(vaultSeverity) === 'critical' ||
    normalizeSeverity(vaultSeverity) === 'high';

  const monitoringStatus = vaultAiResult
    ? vaultPatterns.length > 0
      ? `${humanize(vaultSeverity)} risk detected`
      : 'AI monitoring active'
    : 'Awaiting AI analysis';

  const securityModules = [
    {
      key: 'password',
      label: 'Password Checker',
      data: securityScoreData?.modules?.password,
    },
    {
      key: 'file_vault',
      label: 'File Vault',
      data: securityScoreData?.modules?.file_vault || securityScoreData?.modules?.vault,
    },
    {
      key: 'phishing',
      label: 'Phishing Scanner',
      data: securityScoreData?.modules?.phishing,
    },
    {
      key: 'identity',
      label: 'Identity Leak Monitor',
      data: securityScoreData?.modules?.identity,
    },
  ] as const;

  const securityLastUpdated =
    securityScoreData?.last_updated || securityScoreData?.generated_at || null;

  const fetchVaultDocuments = async () => {
    setVaultLoading(true);
    setVaultError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/documents`, buildAuthedFetchInit());
      const data = await response.json().catch(() => []);

      if (!response.ok) {
        throw new Error(data?.error || data?.message || 'Failed to load vault data');
      }

      setVaultDocs(Array.isArray(data) ? data : []);
    } catch (err: unknown) {
      setVaultError(err instanceof Error ? err.message : String(err));
    } finally {
      setVaultLoading(false);
    }
  };

  const analyzeVaultBehavior = async () => {
    setVaultAiLoading(true);
    setVaultError(null);

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/ai/vault/analyze`,
        buildAuthedFetchInit({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data?.error || data?.message || 'Vault AI analysis failed');
      }

      setVaultAiResult(data);
      setLastVaultAnalysisAt(new Date().toLocaleString());
    } catch (err: unknown) {
      setVaultError(err instanceof Error ? err.message : String(err));
    } finally {
      setVaultAiLoading(false);
    }
  };

  const fetchSecurityScore = async () => {
    setSecurityScoreLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/security/global-score`, buildAuthedFetchInit());
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        return;
      }

      setSecurityScoreData(data as SecurityScorePayload);
    } catch {
      // Keep the last successful score visible to avoid dashboard flicker.
    } finally {
      setSecurityScoreLoading(false);
    }
  };

  useEffect(() => {
    const fetchLatestReport = async () => {
      try {
        const response = await fetchMonthlyReportResponse('/api/reports/monthly/latest');
        const data = await response.json();
        if (!response.ok) {
          return;
        }
        setLatestReport(data?.report || null);
      } catch {
        setLatestReport(null);
      }
    };

    fetchLatestReport();
    fetchVaultDocuments();
    fetchSecurityScore();
    analyzeVaultBehavior();
  }, []);

  useEffect(() => {
    const refreshScoreWhenVisible = () => {
      if (document.visibilityState === 'visible') {
        fetchSecurityScore();
      }
    };

    window.addEventListener('focus', fetchSecurityScore);
    document.addEventListener('visibilitychange', refreshScoreWhenVisible);

    return () => {
      window.removeEventListener('focus', fetchSecurityScore);
      document.removeEventListener('visibilitychange', refreshScoreWhenVisible);
    };
  }, []);

  return (
    <div className="space-y-4" dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Header */}
      <div>
        <div>
          <h1 className="text-2xl font-bold text-white">
            {language === 'arabic' ? 'Ù„ÙˆØ­Ø© Ø§Ù„ØªØ­ÙƒÙ… Ø§Ù„Ø£Ù…Ù†ÙŠØ©' : 'Security Dashboard'}
          </h1>
          <p className="mt-1 text-sm text-gray-400">
            {language === 'arabic'
              ? 'Ù…Ø±Ø§Ù‚Ø¨Ø© ÙˆØªØ­Ù„ÙŠÙ„Ø§Øª Ø§Ù„Ø£Ù…Ù† Ø§Ù„Ø³ÙŠØ¨Ø±Ø§Ù†ÙŠ ÙÙŠ Ø§Ù„ÙˆÙ‚Øª Ø§Ù„ÙØ¹Ù„ÙŠ'
              : 'Real-time cybersecurity monitoring and analytics'}
          </p>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className={`cyber-card ${securityScoreBorder(combinedSecurityStatus)}`}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 px-4 pt-4 pb-2">
            <CardTitle className="text-sm font-medium text-white">
              {language === 'arabic' ? 'Ø¯Ø±Ø¬Ø© Ø§Ù„Ø£Ù…Ø§Ù† Ø§Ù„ÙƒÙ„ÙŠØ©' : 'Security Score'}
            </CardTitle>
            <Shield className={`h-4 w-4 ${securityScoreColor(combinedSecurityStatus)}`} />
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className={`text-2xl font-bold leading-none ${securityScoreColor(combinedSecurityStatus)}`}>
              {globalScoreDisplay}
            </div>
            <p className={`text-xs font-semibold mt-1 ${securityScoreColor(combinedSecurityStatus)}`}>
              {combinedSecurityStatus}
            </p>
            <p className="text-[11px] text-gray-500 mt-1">
              Last updated: {formatSecurityTimestamp(securityLastUpdated)}
            </p>
            <div className="mt-3 space-y-1.5">
              {securityModules.map(({ key, label, data }) => {
                const assessed = Boolean(data?.assessed);
                const contribution = Number(data?.contribution ?? 0);
                const moduleStatus = assessed ? String(data?.status || 'Not Assessed') : 'Not Assessed';
                const moduleTone = assessed
                  ? securityScoreColor(moduleStatus)
                  : 'text-gray-500';
                const contributionTone = assessed
                  ? securityScoreToneClass(contribution * 4)
                  : 'text-gray-500';

                return (
                  <div key={key} className="flex items-center justify-between gap-3 rounded-md bg-white/[0.03] px-2.5 py-1.5">
                    <span className="truncate text-[11px] font-medium text-gray-300">{label}</span>
                    <div className="flex shrink-0 items-center gap-1.5 text-[11px] font-semibold">
                      <span className={moduleTone}>{moduleStatus}</span>
                      <span className="text-gray-600">•</span>
                      <span className={contributionTone}>
                        {assessed ? formatContribution(contribution) : '+0%'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        <NetworkSecurityScoreCard />

        <Card className={`cyber-card ${severityBorder(vaultSeverity)}`}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 px-4 pt-4 pb-2">
            <CardTitle className="text-sm font-medium text-white">
              {language === 'arabic' ? 'Ù…Ø±Ø§Ù‚Ø¨Ø© Ø§Ù„Ø°ÙƒØ§Ø¡ Ø§Ù„Ø§ØµØ·Ù†Ø§Ø¹ÙŠ' : 'AI Monitoring'}
            </CardTitle>
            <Sparkles className={`h-4 w-4 ${severityColor(vaultSeverity)}`} />
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className={`text-xl font-bold ${severityColor(vaultSeverity)}`}>
              {humanize(vaultSeverity)}
            </div>
            <p className="mt-1.5 text-xs text-gray-400">{monitoringStatus}</p>
            <p className="text-[11px] text-gray-500 mt-1">
              {lastVaultAnalysisAt ? `Last analysis: ${lastVaultAnalysisAt}` : 'Run analysis to update status'}
            </p>
          </CardContent>
        </Card>

        <Card className="cyber-card border-purple-500/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 px-4 pt-4 pb-2">
            <CardTitle className="text-sm font-medium text-white">
              {language === 'arabic' ? 'Ù…Ù„ÙØ§Øª Ø§Ù„Ø®Ø²Ù†Ø©' : 'Vault Assets'}
            </CardTitle>
            <Lock className="h-4 w-4 text-purple-400" />
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="text-xl font-bold text-purple-400">
              {vaultLoading ? '--' : formatNumber(vaultDocs.length)}
            </div>
            <p className="mt-1.5 text-xs text-gray-400">
              {formatBytes(vaultStorageBytes)} stored â€¢ {vaultOfflineCount} offline
            </p>
          </CardContent>
        </Card>
      </div>

      {vaultAiResult ? (
        <Card className={`cyber-card ${severityBorder(vaultSeverity)}`}>
          <CardHeader className="px-4 pt-4 pb-2 sm:px-5">
            <CardTitle className="text-white flex items-center gap-2">
              <Brain className={`h-4 w-4 ${severityColor(vaultSeverity)}`} />
              AI Vault Behavior Summary
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4 sm:px-5">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
                <p className="text-xs uppercase tracking-wide text-gray-400">Risk Score</p>
                <p className={`mt-1.5 text-xl font-bold ${severityColor(vaultSeverity)}`}>
                  {vaultRiskScore}/100
                </p>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
                <p className="text-xs uppercase tracking-wide text-gray-400">Severity</p>
                <p className={`mt-1.5 text-xl font-bold ${severityColor(vaultSeverity)}`}>
                  {humanize(vaultSeverity)}
                </p>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
                <p className="text-xs uppercase tracking-wide text-gray-400">Patterns</p>
                <p className="mt-1.5 text-xl font-bold text-white">{sortedVaultPatterns.length}</p>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
                <p className="text-xs uppercase tracking-wide text-gray-400">AI Alert</p>
                <p className="mt-1.5 text-xl font-bold text-white">
                  {vaultAiResult.created_alert || vaultAiResult.alert_created || hasActiveThreat ? 'Active Threat' : 'No alert'}
                </p>
              </div>
            </div>

            <div className="mt-3 rounded-xl border border-white/10 bg-slate-950/30 p-3">
              <div className="mb-3 flex flex-col gap-1 lg:flex-row lg:items-center lg:justify-between">
                <p className="text-sm font-semibold text-white">Multi-risk Breakdown</p>
                <p className="text-xs text-gray-400">
                  Final risk = highest user-level or file-level signal
                </p>
              </div>

              {groupedVaultPatterns.length === 0 ? (
                <p className="text-sm text-gray-400">
                  No suspicious vault behavior detected in the latest analysis.
                </p>
              ) : (
                <div className="space-y-3">
                  {groupedVaultPatterns.map((group) => (
                    <div
                      key={group.targetLabel}
                      className={`rounded-xl border ${severityBorder(group.topSeverity)} bg-slate-950/25 p-3`}
                    >
                      <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
                        <div>
                          <p className={`text-sm font-semibold ${severityColor(group.topSeverity)}`}>
                            {groupedPatternTitle(group.targetLabel)}
                          </p>
                          <p className="text-xs text-gray-400 mt-1">
                            {group.patterns.length} risk signal{group.patterns.length === 1 ? '' : 's'} detected for this target
                          </p>
                        </div>

                        <div className="flex flex-wrap gap-2 text-xs">
                          <span className={`rounded-full border px-2 py-1 ${severityBorder(group.topSeverity)} ${severityColor(group.topSeverity)}`}>
                            Top Risk {group.maxRisk}/100
                          </span>
                          <span className="rounded-full border border-white/10 px-2 py-1 text-gray-200">
                            {humanize(group.topSeverity)}
                          </span>
                        </div>
                      </div>

                      <div className="space-y-2">
                        {group.patterns.map((pattern, index) => {
                          const patternScore = patternRiskScore(pattern);
                          const patternSeverity = pattern.severity || riskLabelFromScore(patternScore);

                          return (
                            <div
                              key={`${group.targetLabel}-${pattern.type || pattern.name || 'pattern'}-${index}`}
                              className="rounded-lg border border-white/10 bg-black/10 p-3"
                            >
                              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                                <div>
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className="rounded-full border border-purple-400/30 px-2 py-1 text-xs text-purple-300">
                                      {patternScopeLabel(pattern)}
                                    </span>
                                    <p className={`text-sm font-semibold ${severityColor(patternSeverity)}`}>
                                      {patternTitle(pattern)}
                                    </p>
                                  </div>

                                  <p className="text-xs text-gray-300 mt-2">
                                    {pattern.message || pattern.description || 'Suspicious vault activity was detected.'}
                                  </p>
                                </div>

                                <div className="flex flex-wrap gap-2 text-xs">
                                  <span className={`rounded-full border px-2 py-1 ${severityBorder(patternSeverity)} ${severityColor(patternSeverity)}`}>
                                    {humanize(patternSeverity)}
                                  </span>
                                  <span className="rounded-full border border-white/10 px-2 py-1 text-gray-200">
                                    Risk {patternScore}/100
                                  </span>
                                  <span className="rounded-full border border-white/10 px-2 py-1 text-gray-200">
                                    Count {pattern.count ?? 1}
                                  </span>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {topVaultPattern ? (
                <div className="mt-3 rounded-lg border border-white/10 bg-slate-950/30 p-3">
                  <p className="text-xs text-gray-400">
                    Final top signal:{" "}
                    <span className={severityColor(topVaultPattern.severity || riskLabelFromScore(patternRiskScore(topVaultPattern)))}>
                      {patternTitle(topVaultPattern)} ({patternRiskScore(topVaultPattern)}/100)
                    </span>
                  </p>
                </div>
              ) : null}
            </div>
          </CardContent>
        </Card>
      ) : null}

      {latestReport ? (
        <Card className="cyber-card border-amber-500/20 bg-[radial-gradient(circle_at_top_left,_rgba(251,191,36,0.14),_transparent_35%),linear-gradient(180deg,rgba(15,23,42,0.92),rgba(2,6,23,0.92))]">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 px-4 pt-4 pb-2 sm:px-5">
            <div>
              <CardTitle className="text-white">Latest Monthly Report</CardTitle>
              <p className="mt-1.5 text-sm text-gray-400">
                Cross-platform report summary with PCAP, Vault, and Identity coverage available now.
              </p>
            </div>
            <CalendarRange className="h-5 w-5 text-amber-300" />
          </CardHeader>
          <CardContent className="flex flex-col gap-3 px-4 pb-4 sm:px-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-6">
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-gray-500">Month</p>
                <p className="mt-1.5 text-base font-semibold text-white">{latestReport.report_month}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-gray-500">Threat Count</p>
                <p className="mt-1.5 text-base font-semibold text-white">{latestReport.latest_pcap_threat_count ?? 0}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-gray-500">Vault Events</p>
                <p className="mt-1.5 text-base font-semibold text-white">{latestReport.latest_vault_event_count ?? 0}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-gray-500">Wrong Password</p>
                <p className="mt-1.5 text-base font-semibold text-white">{latestReport.latest_vault_wrong_password_count ?? 0}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-gray-500">Identity Scans</p>
                <p className="mt-1.5 text-base font-semibold text-white">{latestReport.latest_identity_scan_count ?? 0}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-gray-500">Identity Breaches</p>
                <p className="mt-1.5 text-base font-semibold text-white">{latestReport.latest_identity_confirmed_breach_count ?? 0}</p>
              </div>
            </div>
            <Button onClick={() => navigate('/monthly-reports')} className="bg-amber-400 text-slate-950 hover:bg-amber-300">
              Open Report
            </Button>
          </CardContent>
        </Card>
      ) : null}

      <GamificationDashboardSection />

      {/* Recent Alerts */}
      <RecentSecurityAlertsPanel />
    </div>
  );
}
