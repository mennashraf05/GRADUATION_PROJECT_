import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Badge } from '../ui/badge';
import { Progress } from '../ui/progress';
import { useLanguage } from '../../contexts/LanguageContext';
import {
  Globe,
  Search,
  AlertTriangle,
  XCircle,
  CheckCircle,
  Clock,
  Activity,
  Brain,
  Database,
  Link,
  Radar,
  Shield,
  Sparkles,
  Zap,
  Download,
  FileText,
  Trash2,
  Lock,
} from 'lucide-react';

/* =========================
   Configuration
========================= */
const BASE_API_URL = import.meta.env.VITE_API_BASE_URL || 'https://localhost:5000';
const SCAN_API_URL = `${BASE_API_URL}/api/v1/scan-url`;
const SCANS_API_URL = `${BASE_API_URL}/api/v1/scans`;
const scanDeleteApiUrl = (scanId: number) => `${BASE_API_URL}/api/v1/scan/${scanId}`;
const NOTIFICATIONS_UPDATED_EVENT = 'sentinel:notifications-updated';
const NOTIFICATIONS_UPDATED_AT_KEY = 'sentinel_notifications_updated_at';

/* =========================
   Types
========================= */
type ScanStatus = 'safe' | 'suspicious' | 'dangerous';

interface ScanResult {
  status: ScanStatus;
  score: number;
  details: string[];
  domain?: string;
  virustotal?: VirusTotalReputation;
  mlProbability: number;
  mlCategory: string;
  mlScore?: number;
  trustedDomain: boolean;
  finalGuidance?: string;
}

interface ScanError {
  message: string;
}

interface ScanHistoryItem {
  id: number;
  url: string;
  category: ScanStatus;
  risk_score: number;
  created_at?: string;
}

interface ScanHistoryApiRow {
  id?: number;
  scan_id?: number;
  url?: string;
  category?: string;
  result?: string;
  status?: string;
  risk_score?: number;
  risk?: number;
  created_at?: string;
  timestamp?: string;
}

interface VirusTotalReputation {
  available?: boolean;
  domain?: string;
  source?: string;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reputation?: string;
  message?: string;
}

interface ScanApiResponse {
  domain?: string;
  ml_result?: {
    probability?: number;
    trusted_domain?: boolean;
  };
  risk_score?: number;
  category?: string;
  guidance?: string;
  virustotal?: VirusTotalReputation;
  final_category?: string;
  final_risk_score?: number;
  final_guidance?: string;
}

interface ScanStatItem {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  description: string;
  accent: string;
}

const INVALID_URL_MESSAGE = 'Please enter a valid URL, for example https://github.com';
const SESSION_ERROR_MESSAGE = 'Your session has expired or you are not logged in. Please log in again.';
const NETWORK_ERROR_MESSAGE = 'Cannot connect to the server. Please check that the backend is running.';
const SERVER_ERROR_MESSAGE = 'Server error while scanning. Please try again later.';
const EMPTY_HISTORY_EXPORT_MESSAGE = 'No scan history to export yet.';

const normalizeStatus = (value: unknown): ScanStatus | null => {
  const normalized = String(value || '').toLowerCase();
  if (normalized === 'safe' || normalized === 'suspicious' || normalized === 'dangerous') {
    return normalized;
  }
  if (normalized === 'phishing') return 'dangerous';
  return null;
};

const normalizeVirusTotalReputation = (value: unknown): VirusTotalReputation | undefined => {
  if (!value || typeof value !== 'object') return undefined;
  const vt = value as VirusTotalReputation;
  return {
    available: Boolean(vt.available),
    domain: vt.domain,
    source: vt.source || 'virustotal',
    malicious: Number(vt.malicious || 0),
    suspicious: Number(vt.suspicious || 0),
    harmless: Number(vt.harmless || 0),
    undetected: Number(vt.undetected || 0),
    reputation: vt.reputation || 'unavailable',
    message: vt.message,
  };
};

const normalizeUrlInput = (value: string): { url?: string; error?: string } => {
  const trimmed = value.trim();
  if (!trimmed) return { error: INVALID_URL_MESSAGE };

  if (/^https?\//i.test(trimmed) && !/^https?:\/\//i.test(trimmed)) {
    return { error: INVALID_URL_MESSAGE };
  }

  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  try {
    const parsed = new URL(candidate);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || !parsed.hostname.includes('.')) {
      return { error: INVALID_URL_MESSAGE };
    }
    return { url: parsed.toString() };
  } catch {
    return { error: INVALID_URL_MESSAGE };
  }
};

const normalizeHistoryRows = (rows: unknown): ScanHistoryItem[] => {
  if (!Array.isArray(rows)) return [];

  return rows.reduce<ScanHistoryItem[]>((items, row, index) => {
    const scan = row as ScanHistoryApiRow;
    const category = normalizeStatus(scan.category ?? scan.result ?? scan.status);
    const riskScore = Number(scan.risk_score ?? scan.risk);

    if (!scan.url || !category || !Number.isFinite(riskScore)) return items;

    items.push({
      id: Number(scan.scan_id ?? scan.id ?? index),
      url: scan.url,
      category,
      risk_score: riskScore,
      created_at: scan.timestamp ?? scan.created_at,
    });
    return items;
  }, []);
};

const readErrorMessage = async (res: Response): Promise<string | null> => {
  try {
    const data = await res.json();
    return data?.message || data?.error || null;
  } catch {
    return null;
  }
};

const getStoredAuthToken = () => {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('sentinel_auth_token');
};

const buildAuthedFetchInit = (init: RequestInit = {}): RequestInit => {
  const headers = new Headers(init.headers || undefined);
  const token = getStoredAuthToken();
  if (token && token !== 'cookie_based') {
    headers.set('Authorization', `Bearer ${token}`);
  }
  return {
    ...init,
    credentials: 'include',
    headers,
  };
};

const fetchWithAuth = async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const cookieResponse = await fetch(input, {
    ...init,
    credentials: 'include',
  });
  if (cookieResponse.status !== 401 && cookieResponse.status !== 403) {
    return cookieResponse;
  }

  const token = getStoredAuthToken();
  if (token && token !== 'cookie_based') {
    return fetch(input, buildAuthedFetchInit(init));
  }

  return cookieResponse;
};

const notifyNotificationsUpdated = () => {
  if (typeof window === 'undefined') return;
  const stamp = new Date().toISOString();
  window.dispatchEvent(new CustomEvent(NOTIFICATIONS_UPDATED_EVENT, { detail: { stamp, source: 'phishing_scanner' } }));
  window.localStorage.setItem(NOTIFICATIONS_UPDATED_AT_KEY, stamp);
};

const formatVirusTotalStatus = (reputation?: string) => {
  if (reputation === 'clean') return 'Clean';
  if (reputation === 'suspicious') return 'Suspicious';
  if (reputation === 'malicious') return 'Malicious';
  if (reputation === 'rate_limited') return 'Rate limited';
  if (reputation === 'unknown') return 'Unknown';
  return 'Unavailable';
};

const buildScanResult = (data: ScanApiResponse): { result?: ScanResult; error?: string } => {
  const status = normalizeStatus(data.final_category ?? data.category);
  const score = Number(data.final_risk_score ?? data.risk_score);
  const virustotal = normalizeVirusTotalReputation(data.virustotal);

  if (!status || !Number.isFinite(score)) {
    return { error: SERVER_ERROR_MESSAGE };
  }

  return {
    result: {
      status,
      score,
      details: [
        `ML Probability: ${(Number(data.ml_result?.probability || 0) * 100).toFixed(2)}%`,
        `ML Risk Category: ${data.category || status}`,
        `Final Risk Category: ${status}`,
        `Trusted Domain: ${data.ml_result?.trusted_domain ? 'Yes' : 'No'}`,
        data.final_guidance || data.guidance,
      ].filter(Boolean),
      domain: data.domain,
      virustotal,
      mlProbability: Number(data.ml_result?.probability || 0),
      mlCategory: data.category || status,
      mlScore: Number(data.risk_score),
      trustedDomain: Boolean(data.ml_result?.trusted_domain),
      finalGuidance: data.final_guidance || data.guidance,
    },
  };
};

const getStatusTone = (status: ScanStatus) => {
  if (status === 'safe') {
    return {
      text: 'text-emerald-300',
      border: 'border-emerald-400/25',
      bg: 'bg-emerald-500/10',
      glow: 'shadow-[0_18px_48px_rgba(16,185,129,0.10)]',
      ring: 'from-emerald-400 to-cyan-300',
    };
  }
  if (status === 'suspicious') {
    return {
      text: 'text-amber-300',
      border: 'border-amber-400/25',
      bg: 'bg-amber-500/10',
      glow: 'shadow-[0_18px_48px_rgba(245,158,11,0.10)]',
      ring: 'from-amber-300 to-orange-400',
    };
  }
  return {
    text: 'text-rose-300',
    border: 'border-rose-400/25',
    bg: 'bg-rose-500/10',
    glow: 'shadow-[0_18px_48px_rgba(244,63,94,0.10)]',
    ring: 'from-rose-400 to-red-500',
  };
};

const getVirusTotalTone = (reputation?: string) => {
  if (reputation === 'clean') return 'border-emerald-400/20 bg-emerald-500/10 text-emerald-200';
  if (reputation === 'suspicious') return 'border-amber-400/20 bg-amber-500/10 text-amber-200';
  if (reputation === 'malicious') return 'border-rose-400/22 bg-rose-500/10 text-rose-200';
  return 'border-sky-400/18 bg-sky-500/10 text-sky-200';
};

const getStatusIcon = (status: ScanStatus) => {
  if (status === 'safe') return <CheckCircle className="w-4 h-4 text-emerald-300" />;
  if (status === 'suspicious') return <AlertTriangle className="w-4 h-4 text-amber-300" />;
  return <XCircle className="w-4 h-4 text-rose-300" />;
};

const getStatusBadge = (status: ScanStatus) => {
  if (status === 'safe')
    return <Badge className="border-emerald-400/25 bg-emerald-500/10 text-emerald-200">Safe</Badge>;
  if (status === 'suspicious')
    return <Badge className="border-amber-400/25 bg-amber-500/10 text-amber-200">Suspicious</Badge>;
  return <Badge className="border-rose-400/25 bg-rose-500/10 text-rose-200">Dangerous</Badge>;
};

const getScoreColor = (score: number) => {
  if (score <= 39) return 'text-emerald-300';
  if (score <= 69) return 'text-amber-300';
  return 'text-rose-300';
};

const getDecisionExplanation = (result: ScanResult) => {
  const reputation = result.virustotal?.reputation;
  if (reputation === 'malicious') {
    return 'Final risk was increased because VirusTotal reported malicious detections.';
  }
  if (result.mlCategory === 'dangerous' && reputation === 'clean') {
    return 'Final decision remains dangerous because ML detected high phishing probability.';
  }
  if (!result.virustotal?.available) {
    return 'VirusTotal reputation is unavailable; final decision is based on ML analysis.';
  }
  return 'Final decision combines ML analysis with VirusTotal domain reputation.';
};

const buildStats = (
  scanHistory: ScanHistoryItem[],
  formatNumber: (value: number) => string
): ScanStatItem[] => {
  const totalScans = scanHistory.length;
  const safeCount = scanHistory.filter(s => s.category === 'safe').length;
  const dangerousCount = scanHistory.filter(s => s.category === 'dangerous').length;
  const safePercentage = totalScans ? (safeCount / totalScans) * 100 : 0;

  return [
    { label: 'Total Scans', value: formatNumber(totalScans), icon: Activity, color: 'text-blue-600', description: 'All time scans', accent: 'from-blue-500 to-cyan-500' },
    { label: 'Safe URLs', value: formatNumber(safeCount), icon: CheckCircle, color: 'text-emerald-600', description: 'This is great!', accent: 'from-emerald-500 to-teal-500' },
    { label: 'Threats Detected', value: formatNumber(dangerousCount), icon: AlertTriangle, color: 'text-rose-600', description: 'Stay alert!', accent: 'from-rose-500 to-red-500' },
    { label: 'Safety Rate', value: `${safePercentage.toFixed(0)}%`, icon: Shield, color: 'text-violet-600', description: 'Keep it secure', accent: 'from-violet-500 to-indigo-500' },
  ];
};

const pageShellStyle: React.CSSProperties = {
  fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
};

const compactPageStyle: React.CSSProperties = {
  ...pageShellStyle,
  background: 'transparent',
};

const heroGridStyle: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
  gap: '32px',
  alignItems: 'center',
};

const compactStatsGridStyle: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
  gap: '16px',
};

const mainActionGridStyle: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
  gap: '22px',
};

const analysisGridStyle: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
  gap: '22px',
};

const PANEL_CARD_CLASS =
  'relative overflow-hidden rounded-[22px] border border-slate-600/35 bg-[linear-gradient(180deg,rgba(15,29,49,0.98),rgba(9,20,36,0.99))] shadow-[0_18px_44px_rgba(2,6,23,0.26)]';

const SOFT_PANEL_CLASS =
  'rounded-2xl border border-white/10 bg-[rgba(5,15,28,0.62)] shadow-inner shadow-black/10';

const ICON_TILE_CLASS =
  'flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-sky-400/20 bg-sky-500/12 text-sky-100';

const PILL_CLASS =
  'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] font-semibold';

const formatScanTime = (value?: string) => {
  if (!value) return 'Unavailable';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
};

const escapePdfText = (value: string) =>
  value.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');

const buildHistoryPdf = (scanHistory: ScanHistoryItem[]) => {
  const createdAt = new Date().toLocaleString();
  const lines = [
    'Sentinel AI - Phishing Scanner History',
    `Generated: ${createdAt}`,
    `Total scans: ${scanHistory.length}`,
    '',
    ...scanHistory.flatMap((scan, index) => [
      `${index + 1}. ${scan.url}`,
      `   Status: ${scan.category}`,
      `   Risk Score: ${scan.risk_score}/100`,
      `   Date: ${scan.created_at || 'Unavailable'}`,
      '',
    ]),
  ];

  const textCommands = lines
    .slice(0, 42)
    .map((line, index) => `BT /F1 10 Tf 42 ${790 - index * 16} Td (${escapePdfText(line)}) Tj ET`)
    .join('\n');

  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${textCommands.length} >>\nstream\n${textCommands}\nendstream`,
  ];

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach((offset) => {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;

  return new Blob([pdf], { type: 'application/pdf' });
};

const downloadBlob = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
};

/* =========================
   Component
========================= */
export function PhishingScannerPage() {
  const { isRtl, formatNumber } = useLanguage();
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [isClearingHistory, setIsClearingHistory] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<ScanError | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);

  /* =========================
     Fetch Scan History
  ========================== */
  const fetchScanHistory = async () => {
    try {
      const res = await fetchWithAuth(SCANS_API_URL);
      if (!res.ok) return;
      const data = await res.json();
      setScanHistory(normalizeHistoryRows(data));
    } catch (err) {
      console.error('Failed to load scan history', err);
    }
  };

  useEffect(() => {
    fetchScanHistory();
  }, []);

  /* =========================
     Handle Scan
  ========================== */
  const handleScan = async () => {
    const normalizedInput = normalizeUrlInput(url);
    if (normalizedInput.error || !normalizedInput.url) {
      setScanResult(null);
      setScanError({ message: normalizedInput.error || INVALID_URL_MESSAGE });
      return;
    }

    setIsScanning(true);
    setScanResult(null);
    setScanError(null);

    try {
      const res = await fetchWithAuth(SCAN_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: normalizedInput.url }),
      });

      if (!res.ok) {
        const backendMessage = await readErrorMessage(res);
        if (res.status === 400) {
          setScanError({ message: backendMessage || INVALID_URL_MESSAGE });
        } else if (res.status === 401) {
          setScanError({ message: SESSION_ERROR_MESSAGE });
        } else if (res.status >= 500) {
          setScanError({ message: SERVER_ERROR_MESSAGE });
        } else {
          setScanError({ message: backendMessage || 'Unable to scan this URL. Please try again.' });
        }
        return;
      }

      const data = await res.json();
      const normalizedResult = buildScanResult(data);

      if (normalizedResult.error || !normalizedResult.result) {
        setScanError({ message: normalizedResult.error || SERVER_ERROR_MESSAGE });
        return;
      }

      setScanResult(normalizedResult.result);
      setUrl(normalizedInput.url);

      fetchScanHistory();
      if (data.notification_created) {
        notifyNotificationsUpdated();
      }
    } catch (err) {
      console.error(err);
      setScanError({ message: NETWORK_ERROR_MESSAGE });
    } finally {
      setIsScanning(false);
    }
  };

  const handleClearHistory = async () => {
    if (scanHistory.length === 0 || isClearingHistory) return;

    setIsClearingHistory(true);
    setScanError(null);

    try {
      const responses = await Promise.all(
        scanHistory.map((scan) =>
          fetchWithAuth(scanDeleteApiUrl(scan.id), {
            method: 'DELETE',
          })
        )
      );

      if (responses.some((res) => !res.ok)) {
        setScanError({ message: 'Could not clear scan history. Please try again.' });
        return;
      }

      setScanHistory([]);
    } catch (err) {
      console.error(err);
      setScanError({ message: NETWORK_ERROR_MESSAGE });
    } finally {
      setIsClearingHistory(false);
    }
  };

  const handleDownloadHistoryPdf = () => {
    if (scanHistory.length === 0) {
      setScanError({ message: EMPTY_HISTORY_EXPORT_MESSAGE });
      return;
    }

    const pdf = buildHistoryPdf(scanHistory);
    downloadBlob(pdf, `phishing-scan-history-${new Date().toISOString().slice(0, 10)}.pdf`);
  };

  const stats = buildStats(scanHistory, formatNumber);

  /* =========================
     Render
  ========================== */
  return (
    <div
      className="min-h-full w-full max-w-none space-y-6 px-0 py-3 text-slate-100 sm:px-1 lg:px-2"
      dir={isRtl ? 'rtl' : 'ltr'}
      style={compactPageStyle}
    >
      <section
        className="relative overflow-hidden rounded-[26px] border border-sky-300/12 bg-[radial-gradient(circle_at_70%_30%,rgba(80,70,170,0.22),transparent_34%),linear-gradient(135deg,rgba(12,28,52,0.99),rgba(9,20,37,0.99))] shadow-[0_22px_54px_rgba(2,6,23,0.30)]"
        style={{ padding: '34px' }}
      >
        <div className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-sky-300/45 to-transparent" />
        <div className="pointer-events-none absolute right-24 top-10 h-48 w-48 rounded-full bg-violet-500/16 blur-3xl" />
        <div className="relative" style={heroGridStyle}>
          <div className="flex min-h-[220px] flex-col justify-center gap-6">
            <div className="flex items-start gap-4 sm:gap-5">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-cyan-300/16 bg-cyan-500/18 text-cyan-50 shadow-[0_14px_34px_rgba(14,165,233,0.18)]">
                <Shield className="h-8 w-8" />
              </div>
              <div className="min-w-0 pt-1">
                <p className="mb-2 text-[11px] font-bold uppercase tracking-[0.16em] text-cyan-300">Sentinel AI URL Defense</p>
                <h1 className="text-3xl font-bold leading-tight tracking-normal text-white sm:text-4xl lg:text-[42px]">
                  Phishing URL Scanner
                </h1>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300 sm:text-base">
                  Real-time phishing detection using ML, dynamic scoring, and domain reputation intelligence.
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2.5 sm:ml-[76px]">
              <span className={`${PILL_CLASS} border-cyan-400/25 bg-cyan-500/12 text-cyan-100`}>
                <Sparkles className="h-3.5 w-3.5" />
                ML + VirusTotal Enabled
              </span>
              <span className={`${PILL_CLASS} border-violet-400/25 bg-violet-500/12 text-violet-100`}>
                <Activity className="h-3.5 w-3.5" />
                Dynamic Risk Scoring
              </span>
              <span className={`${PILL_CLASS} border-sky-400/25 bg-sky-500/12 text-sky-100`}>
                <Radar className="h-3.5 w-3.5" />
                Real-time Protection
              </span>
            </div>
          </div>

          <div
            className="relative overflow-hidden rounded-[22px] border border-white/12 bg-white/[0.055] shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_18px_44px_rgba(2,6,23,0.24)] backdrop-blur"
            style={{ padding: '30px' }}
          >
            <div className="pointer-events-none absolute -right-10 -top-10 h-32 w-32 rounded-full bg-sky-500/10 blur-2xl" />
            <div className="relative mb-7 flex items-start justify-between gap-5">
              <div>
                <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-cyan-300">Protection Layers</p>
                <p className="mt-1 text-2xl font-bold text-white">Live URL Intelligence</p>
              </div>
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-sky-400/20 bg-sky-500/10 text-sky-100">
                <Radar className="h-5 w-5" />
              </div>
            </div>
            <div className="relative space-y-4">
              <div className="flex items-center gap-4">
                <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-violet-500/20">
                  <Brain className="h-5 w-5 text-violet-200" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-white">Machine Learning</p>
                  <p className="text-xs text-slate-400">AI-based threat analysis</p>
                </div>
                <CheckCircle className="h-4 w-4 shrink-0 text-emerald-300" />
              </div>
              <div className="flex items-center gap-4">
                <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-cyan-500/18">
                  <Globe className="h-5 w-5 text-cyan-200" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-white">Domain Reputation</p>
                  <p className="text-xs text-slate-400">VirusTotal enrichment</p>
                </div>
                <CheckCircle className="h-4 w-4 shrink-0 text-emerald-300" />
              </div>
              <div className="flex items-center gap-4">
                <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-emerald-500/16">
                  <Lock className="h-5 w-5 text-emerald-200" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-white">Session Protected</p>
                  <p className="text-xs text-slate-400">History is tied to your account</p>
                </div>
                <CheckCircle className="h-4 w-4 shrink-0 text-emerald-300" />
              </div>
            </div>
          </div>
        </div>
      </section>

      <section style={compactStatsGridStyle}>
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card
              key={stat.label}
              className={`${PANEL_CARD_CLASS} group transition duration-300 hover:-translate-y-0.5 hover:border-sky-300/20`}
              style={{ padding: '24px' }}
            >
              <CardContent className="relative min-h-[112px] !p-0">
                <div className={`absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-gradient-to-r ${stat.accent} opacity-95`} />
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-slate-300">{stat.label}</p>
                    <p className="mt-5 text-4xl font-bold leading-none text-white">{stat.value}</p>
                    <p className="mt-2 text-xs text-slate-400">{stat.description}</p>
                  </div>
                  <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br ${stat.accent} p-3 shadow-[0_10px_22px_rgba(37,99,235,0.16)] opacity-80 transition group-hover:scale-105 group-hover:opacity-100`}>
                    <Icon className="h-5 w-5 text-white" />
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </section>

      <section style={mainActionGridStyle}>
        <Card className={PANEL_CARD_CLASS} style={{ padding: '28px' }}>
          <div className="pointer-events-none absolute -right-16 -top-16 h-40 w-40 rounded-full bg-blue-500/10 blur-3xl" />
          <CardHeader className="relative !p-0">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <CardTitle className="flex items-center gap-3 text-2xl text-white">
                  Scan a URL
                </CardTitle>
                <p className="mt-2 text-sm leading-6 text-slate-400">Enter a domain or full URL to check for phishing risk.</p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="relative mt-8 space-y-4 !p-0">
            <div className="space-y-4">
              <Label className="sr-only">Enter URL</Label>
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
                <div className="relative min-w-0 flex-1">
                  <Link className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                  <Input
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="github.com"
                    className="h-12 rounded-xl border-slate-600/35 bg-[#061225] pl-11 text-base text-white placeholder:text-slate-500 shadow-inner shadow-black/20 focus-visible:ring-2 focus-visible:ring-sky-400/50 focus-visible:ring-offset-0"
                  />
                </div>
                <Button
                  onClick={handleScan}
                  disabled={isScanning || !url.trim()}
                  className="h-12 shrink-0 rounded-xl bg-blue-600 px-7 text-sm font-semibold text-white shadow-[0_14px_32px_rgba(37,99,235,0.25)] transition hover:bg-blue-500 disabled:opacity-60 sm:w-[128px]"
                >
                  {isScanning ? (
                    <span className="inline-flex items-center gap-2">
                      <Radar className="h-4 w-4 animate-pulse" />
                      Scanning...
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-2">
                      <Zap className="h-4 w-4" />
                      Scan
                    </span>
                  )}
                </Button>
              </div>
              <p className="text-xs text-slate-500">Example: github.com</p>
            </div>

            {isScanning && (
              <div className="space-y-2 rounded-xl border border-sky-400/18 bg-sky-500/10 p-3">
                <div className="flex items-center justify-between text-xs font-semibold text-sky-100">
                  <span>Analyzing lexical signals and reputation data</span>
                  <span>Live</span>
                </div>
                <Progress value={65} />
              </div>
            )}

            {scanError && (
              <div className="rounded-xl border border-amber-400/25 bg-amber-500/10 p-3 text-sm text-amber-100">
                {scanError.message}
              </div>
            )}
          </CardContent>
        </Card>

        {scanResult ? (() => {
            const tone = getStatusTone(scanResult.status);
            return (
              <Card className={`${PANEL_CARD_CLASS} ${tone.border} ${tone.glow}`} style={{ padding: '28px' }}>
                <CardContent className="!p-0">
                  <div className="flex min-h-[138px] flex-col justify-center gap-5">
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-500">Scan Result</p>
                        <p className={`mt-2 text-3xl font-bold capitalize ${tone.text}`}>{scanResult.status}</p>
                      </div>
                      <div className="flex items-end gap-1 text-white">
                        <span className="text-5xl font-bold leading-none sm:text-6xl">{scanResult.score}</span>
                        <span className="mb-2 text-sm font-semibold text-slate-400">/100</span>
                      </div>
                    </div>

                    <div className={`rounded-xl border ${tone.border} ${tone.bg} px-4 py-3 text-sm leading-6 text-slate-100`}>
                      {scanResult.finalGuidance}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })() : (
            <Card className={PANEL_CARD_CLASS} style={{ padding: '28px' }}>
              <div className="pointer-events-none absolute -right-16 -top-16 h-44 w-44 rounded-full bg-violet-500/10 blur-3xl" />
              <CardContent className="relative flex min-h-[212px] flex-col justify-center gap-5 !p-0">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-violet-300/18 bg-violet-500/10 text-violet-200">
                      <Radar className="h-5 w-5" />
                    </span>
                    <div>
                      <p className="text-xl font-bold text-white">Result preview</p>
                      <p className="text-xs text-slate-400">Waiting for a URL scan</p>
                    </div>
                  </div>
                  <span className="shrink-0 rounded-full border border-slate-500/20 bg-white/[0.035] px-3 py-1 text-xs font-semibold text-slate-300">
                    Ready
                  </span>
                </div>

                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="rounded-xl border border-white/8 bg-white/[0.035] p-3">
                    <p className="text-xs uppercase tracking-[0.14em] text-slate-500">Score</p>
                    <p className="mt-2 text-2xl font-bold text-white">--/100</p>
                  </div>
                  <div className="rounded-xl border border-white/8 bg-white/[0.035] p-3">
                    <p className="text-xs uppercase tracking-[0.14em] text-slate-500">ML</p>
                    <p className="mt-2 text-sm font-semibold text-slate-300">Pending</p>
                  </div>
                  <div className="rounded-xl border border-white/8 bg-white/[0.035] p-3">
                    <p className="text-xs uppercase tracking-[0.14em] text-slate-500">Reputation</p>
                    <p className="mt-2 text-sm font-semibold text-slate-300">Pending</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
      </section>

      {scanResult && (
        <section style={analysisGridStyle}>
          <div className={PANEL_CARD_CLASS} style={{ padding: '30px' }}>
            <div className="mb-6 flex items-center justify-between gap-4 text-violet-200">
              <div className="flex min-w-0 items-center gap-3">
                <Brain className="h-5 w-5" />
                <p className="text-lg font-semibold text-white">Machine Learning Analysis</p>
              </div>
              <Badge className="shrink-0 border-violet-400/25 bg-violet-500/10 text-violet-100">ML</Badge>
            </div>
            <div className="space-y-4 text-sm">
              <div className="flex items-center justify-between gap-6">
                <span className="text-slate-400">ML Probability</span>
                <span className="min-w-[92px] text-right font-semibold text-rose-300">{(scanResult.mlProbability * 100).toFixed(2)}%</span>
              </div>
              <div className="flex items-center justify-between gap-6">
                <span className="text-slate-400">ML Risk Category</span>
                <span className="min-w-[92px] text-right font-semibold capitalize text-white">{scanResult.mlCategory}</span>
              </div>
              <div className="flex items-center justify-between gap-6">
                <span className="text-slate-400">Trusted Domain</span>
                <span className="min-w-[92px] text-right font-semibold text-white">{scanResult.trustedDomain ? 'Yes' : 'No'}</span>
              </div>
              <div className="flex items-center justify-between gap-6">
                <span className="text-slate-400">Original ML Score</span>
                <span className="min-w-[92px] text-right font-semibold text-white">{Number.isFinite(scanResult.mlScore) ? `${scanResult.mlScore}/100` : 'Unavailable'}</span>
              </div>
            </div>
          </div>

          <div
            className={`rounded-[22px] border shadow-[0_18px_42px_rgba(2,6,23,0.24)] ${getVirusTotalTone(scanResult.virustotal?.reputation)}`}
            style={{ padding: '30px' }}
          >
            <div className="mb-6 flex items-center justify-between gap-4">
              <div className="flex min-w-0 items-center gap-3">
                <Database className="h-5 w-5" />
                <p className="text-lg font-semibold text-white">VirusTotal Domain Reputation</p>
              </div>
              <Badge className="shrink-0 border-current/20 bg-white/10 text-current">
                {formatVirusTotalStatus(scanResult.virustotal?.reputation)}
              </Badge>
            </div>
            <div className="space-y-4 text-sm">
              <div className="flex items-center justify-between gap-6">
                <span className="opacity-70">Domain Checked</span>
                <span className="min-w-[132px] truncate text-right font-semibold">{scanResult.virustotal?.domain || scanResult.domain || 'Unknown'}</span>
              </div>
              <div className="flex items-center justify-between gap-6">
                <span className="opacity-70">Status</span>
                <span className="min-w-[132px] text-right font-semibold">{formatVirusTotalStatus(scanResult.virustotal?.reputation)}</span>
              </div>
              <div className="flex items-center justify-between gap-6">
                <span className="opacity-70">Malicious Count</span>
                <span className="min-w-[132px] text-right font-semibold">{scanResult.virustotal?.malicious || 0}</span>
              </div>
              <div className="flex items-center justify-between gap-6">
                <span className="opacity-70">Suspicious Count</span>
                <span className="min-w-[132px] text-right font-semibold">{scanResult.virustotal?.suspicious || 0}</span>
              </div>
            </div>
            {scanResult.virustotal?.message && (
              <p className="mt-4 rounded-xl bg-white/[0.045] p-3 text-xs leading-5 opacity-85">{scanResult.virustotal.message}</p>
            )}
          </div>
        </section>
      )}

      <Card className={PANEL_CARD_CLASS}>
        <div className="pointer-events-none absolute -right-16 -top-20 h-44 w-44 rounded-full bg-sky-500/8 blur-3xl" />
        <CardHeader className="relative !px-7 !pb-3 !pt-7 sm:!px-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-3">
              <div>
                <CardTitle className="text-xl text-white">Scan History</CardTitle>
                <p className="mt-1 text-sm text-slate-400">Saved URL scan activity for your account</p>
              </div>
            </div>
            <div className="flex flex-col gap-2 sm:flex-row">
              <Button
                type="button"
                onClick={handleDownloadHistoryPdf}
                disabled={scanHistory.length === 0}
                className="h-9 rounded-xl border border-sky-400/25 bg-sky-500/10 px-3.5 text-xs text-sky-100 hover:bg-sky-500/16 disabled:opacity-50"
              >
                <Download className="mr-2 h-4 w-4" />
                Download PDF
              </Button>
              <Button
                type="button"
                onClick={handleClearHistory}
                disabled={scanHistory.length === 0 || isClearingHistory}
                className="h-9 rounded-xl border border-rose-400/25 bg-rose-500/10 px-3.5 text-xs text-rose-100 hover:bg-rose-500/16 disabled:opacity-50"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                {isClearingHistory ? 'Clearing...' : 'Clear History'}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="relative !px-7 !pb-7 !pt-3 sm:!px-8">
          {scanHistory.length === 0 ? (
            <div className={`${SOFT_PANEL_CLASS} flex flex-col items-center justify-center gap-3 !px-7 !py-10 text-center`}>
              <div className={ICON_TILE_CLASS}>
                <FileText className="h-6 w-6" />
              </div>
              <div>
                <p className="text-base font-semibold text-white">No scans yet</p>
                <p className="mt-1 text-sm text-slate-400">Start by checking a URL.</p>
              </div>
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl border border-white/8">
              <div className="overflow-x-auto">
              <Table className="min-w-[820px]">
                <TableHeader>
                  <TableRow className="border-white/8 bg-white/[0.035] hover:bg-white/[0.035]">
                    <TableHead className="px-5 py-4 text-xs font-semibold text-slate-400">URL</TableHead>
                    <TableHead className="px-5 py-4 text-xs font-semibold text-slate-400">Status</TableHead>
                    <TableHead className="px-5 py-4 text-xs font-semibold text-slate-400">Risk Score</TableHead>
                    <TableHead className="px-5 py-4 text-xs font-semibold text-slate-400">ML Category</TableHead>
                    <TableHead className="px-5 py-4 text-xs font-semibold text-slate-400">Scan Time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scanHistory.map((scan, index) => (
                    <TableRow key={`${scan.id}-${scan.created_at || index}`} className="border-white/8 hover:bg-white/[0.035]">
                      <TableCell className="max-w-[520px] truncate px-5 py-4 font-mono text-xs text-slate-200">{scan.url}</TableCell>
                      <TableCell className="px-5 py-4">{getStatusBadge(scan.category)}</TableCell>
                      <TableCell className={`px-5 py-4 text-sm font-bold ${getScoreColor(scan.risk_score)}`}>
                        {scan.risk_score}/100
                      </TableCell>
                      <TableCell className="px-5 py-4 text-sm font-semibold capitalize text-slate-200">{scan.category}</TableCell>
                      <TableCell className="px-5 py-4 text-xs text-slate-400">{formatScanTime(scan.created_at)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
