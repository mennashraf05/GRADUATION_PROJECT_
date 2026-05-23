import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'motion/react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  Database,
  Download,
  Eye,
  History,
  Link as LinkIcon,
  Loader2,
  Radar,
  RefreshCw,
  Search,
  Shield,
  User,
  Mail,
  Globe,
  Info,
  Plus,
  Trash2,
  X,
  Zap,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Badge } from '../ui/badge';
import { useLanguage } from '../../contexts/LanguageContext';
import {
  broadcastGamificationUpdated,
  fetchGamificationOverview,
  formatGamificationTimestamp,
  type GamificationOverview,
} from '../../utils/gamification';

type SourceKey = 'duckduckgo' | 'github' | 'gitlab' | 'stackexchange' | 'leakcheck';
type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical' | string;

interface SourceStatus {
  status?: string;
  reason?: string;
}

interface IdentityFinding {
  id?: number;
  source: string;
  category: string;
  severity: string;
  title?: string;
  url?: string;
  matched_field?: string;
  matched_value?: string;
  evidence?: string;
  found_in_search?: boolean;
  found_in_page?: boolean;
  confidence?: number;
}

interface IdentityScan {
  id?: number;
  scan_id?: number;
  email?: string | null;
  username?: string | null;
  domain?: string | null;
  status?: string;
  risk_score: number;
  risk_level: RiskLevel;
  recommendation?: string;
  sources_checked: number;
  source_status?: Partial<Record<SourceKey, string | SourceStatus>>;
  total_findings: number;
  created_at?: string;
  completed_at?: string;
  findings?: IdentityFinding[];
  confirmed_breach_count?: number;
}

interface IdentityAlert {
  id: number;
  scan_id: number;
  title: string;
  message: string;
  severity: string;
  created_at: string;
  is_read?: boolean;
  email_status?: 'sent' | 'failed' | 'skipped' | string;
  email_sent_at?: string | null;
  email_error?: string | null;
}

type AssetType = 'email' | 'username' | 'domain';

interface CurrentUser {
  email?: string;
  username?: string;
  name?: string;
  full_name?: string;
}

interface IdentityAsset {
  id: number;
  asset_type: AssetType;
  asset_value: string;
  label?: string | null;
  status?: string;
  last_scan_id?: number | null;
  last_risk_score?: number;
  last_risk_level?: RiskLevel;
  last_findings_count?: number;
  exposure_findings_count?: number;
  last_checked_at?: string | null;
  auto_scan_enabled?: boolean;
  created_at?: string;
}

interface AddAssetResponse {
  success?: boolean;
  already_exists?: boolean;
  message?: string;
  asset?: IdentityAsset & { already_exists?: boolean };
}

interface AssetCandidate {
  assetType: AssetType;
  assetValue: string;
  label?: string;
}

interface FullScanSummary {
  status: 'completed' | 'empty' | string;
  message?: string;
  total_assets_scanned?: number;
  risky_assets?: number;
  clean_assets?: number;
  total_findings?: number;
  highest_risk_level?: RiskLevel;
  results?: Array<{
    asset_id: number;
    scan_id: number;
    risk_level: RiskLevel;
    total_findings: number;
  }>;
}

const API_BASE_URL =
  import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');
const IDENTITY_API_BASE = `${API_BASE_URL}/api/identity`;

const SOURCE_LABELS: Record<SourceKey, string> = {
  duckduckgo: 'DuckDuckGo',
  github: 'GitHub',
  gitlab: 'GitLab',
  stackexchange: 'Stack Exchange',
  leakcheck: 'LeakCheck',
};

const CATEGORY_LABELS: Record<string, string> = {
  public_mention: 'Public Mention',
  possible_exposure: 'Possible Exposure',
  confirmed_exposure: 'Confirmed Exposure',
  confirmed_breach: 'Confirmed Breach',
};

const PUBLIC_EMAIL_PROVIDERS = new Set([
  'gmail.com',
  'yahoo.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'icloud.com',
]);

function normalizeScanId(scan: IdentityScan): number | null {
  const value = scan.scan_id ?? scan.id;
  return typeof value === 'number' ? value : value ? Number(value) : null;
}

function statusText(value: string | SourceStatus | undefined): string {
  if (!value) return 'not checked';
  if (typeof value === 'string') return value;
  return value.reason ? `${value.status || 'unknown'} - ${value.reason}` : value.status || 'unknown';
}

function statusTone(value: string | SourceStatus | undefined): string {
  const normalized = statusText(value).toLowerCase();
  if (normalized.includes('checked') || normalized.includes('active')) {
    return 'border-green-500/30 bg-green-500/10 text-green-300';
  }
  if (normalized.includes('failed')) {
    return 'border-red-500/30 bg-red-500/10 text-red-300';
  }
  return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300';
}

function riskTone(level: RiskLevel): string {
  const normalized = String(level || '').toLowerCase();
  if (normalized === 'critical') return 'border-red-500/40 bg-red-500/15 text-red-300';
  if (normalized === 'high') return 'border-orange-500/40 bg-orange-500/15 text-orange-300';
  if (normalized === 'medium') return 'border-yellow-500/40 bg-yellow-500/15 text-yellow-300';
  return 'border-green-500/40 bg-green-500/15 text-green-300';
}

function categoryTone(category: string): string {
  if (category === 'confirmed_breach' || category === 'confirmed_exposure') {
    return 'border-red-500/30 bg-red-500/10 text-red-300';
  }
  if (category === 'possible_exposure') {
    return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300';
  }
  return 'border-green-500/30 bg-green-500/10 text-green-300';
}

function sourceLabel(source: string): string {
  return source
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .replace('Api', 'API');
}

function evidenceSource(finding: IdentityFinding): string {
  if (finding.category === 'confirmed_breach') return 'Confirmed Breach';
  if (finding.found_in_search && finding.found_in_page) return 'Search + Page';
  if (finding.found_in_page) return 'Page Verified';
  if (finding.found_in_search) return 'Search Result';
  return 'Unverified';
}

function compactTarget(scan: IdentityScan): string {
  return [scan.email, scan.username, scan.domain].filter(Boolean).join(' / ') || 'No target';
}

function detectAssetType(value: string, hintedType?: string): AssetType {
  const normalizedHint = String(hintedType || '').toLowerCase();
  if (normalizedHint === 'email' || normalizedHint === 'username' || normalizedHint === 'domain') {
    return normalizedHint;
  }
  const trimmed = value.trim();
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return 'email';
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(trimmed.replace(/^www\./i, ''))) return 'domain';
  return 'username';
}

function normalizeAssetValue(assetType: AssetType, value: string): string {
  const trimmed = value.trim();
  if (assetType === 'email') return trimmed.toLowerCase();
  if (assetType === 'domain') return trimmed.toLowerCase().replace(/^www\./, '').replace(/\/+$/, '');
  return trimmed;
}

function assetKey(assetType: AssetType, value: string): string {
  return `${assetType}:${normalizeAssetValue(assetType, value).toLowerCase()}`;
}

function scanAssetCandidates(scan: IdentityScan): AssetCandidate[] {
  return [
    scan.email ? { assetType: 'email' as const, assetValue: scan.email, label: 'Scan email' } : null,
    scan.username ? { assetType: 'username' as const, assetValue: scan.username, label: 'Scan username' } : null,
    scan.domain ? { assetType: 'domain' as const, assetValue: scan.domain, label: 'Scan domain' } : null,
  ].filter(Boolean) as AssetCandidate[];
}

function findingAssetCandidate(finding: IdentityFinding): AssetCandidate | null {
  const rawValue = String(finding.matched_value || '').trim();
  if (!rawValue) return null;
  const assetType = detectAssetType(rawValue, finding.matched_field);
  return {
    assetType,
    assetValue: normalizeAssetValue(assetType, rawValue),
    label: finding.title ? `Finding: ${finding.title}` : 'Identity finding',
  };
}

function safeNumber(value: unknown): number {
  const parsed = Number(value || 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

function emailDomain(emailValue: string): string {
  const domainPart = emailValue.split('@')[1]?.trim().toLowerCase() || '';
  return domainPart && !PUBLIC_EMAIL_PROVIDERS.has(domainPart) ? domainPart : '';
}

function leakCheckSafeUsername(value: string): string {
  const normalized = value.trim();
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,62}[A-Za-z0-9])?$/.test(normalized)) {
    return '';
  }
  return normalized;
}

function assetStatusTone(status?: string): string {
  const normalized = String(status || 'pending').toLowerCase();
  if (normalized === 'clean') return 'border-green-500/30 bg-green-500/10 text-green-300';
  if (normalized === 'risky') return 'border-red-500/30 bg-red-500/10 text-red-300';
  if (normalized === 'scanning') return 'border-blue-500/30 bg-blue-500/10 text-blue-300';
  return 'border-slate-500/30 bg-slate-500/10 text-slate-300';
}

function emailStatusTone(status?: string): string {
  const normalized = String(status || 'skipped').toLowerCase();
  if (normalized === 'sent') return 'border-green-500/30 bg-green-500/10 text-green-300';
  if (normalized === 'failed') return 'border-red-500/30 bg-red-500/10 text-red-300';
  return 'border-slate-500/30 bg-slate-500/10 text-slate-300';
}

function emailStatusLabel(status?: string): string {
  const normalized = String(status || 'skipped').toLowerCase();
  if (normalized === 'sent') return 'Email sent';
  if (normalized === 'failed') return 'Email failed';
  return 'Email skipped';
}

function isAssetRisky(asset: IdentityAsset): boolean {
  const level = String(asset.last_risk_level || 'Low').toLowerCase();
  return ['medium', 'high', 'critical'].includes(level) || safeNumber(asset.exposure_findings_count) > 0;
}

function protectionTone(rate: number): { text: string; border: string; badge: string; label: string } {
  if (rate >= 80) {
    return {
      text: 'text-green-300',
      border: 'border-green-500/30 bg-green-500/10',
      badge: 'border-green-500/30 bg-green-500/10 text-green-300',
      label: 'Safe',
    };
  }
  if (rate >= 50) {
    return {
      text: 'text-yellow-300',
      border: 'border-yellow-500/30 bg-yellow-500/10',
      badge: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300',
      label: 'Moderate',
    };
  }
  return {
    text: 'text-red-300',
    border: 'border-red-500/30 bg-red-500/10',
    badge: 'border-red-500/30 bg-red-500/10 text-red-300',
    label: 'Needs attention',
  };
}

export function IdentityLeakMonitorPage() {
  const { isRtl, formatNumber, formatDateTime } = useLanguage();
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [domain, setDomain] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [statusMessage, setStatusMessage] = useState('Ready. Enter at least one field to start.');
  const [statusError, setStatusError] = useState(false);
  const [report, setReport] = useState<IdentityScan | null>(null);
  const [history, setHistory] = useState<IdentityScan[]>([]);
  const [alerts, setAlerts] = useState<IdentityAlert[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isMyIdentityScanning, setIsMyIdentityScanning] = useState(false);
  const [isFullAssetsScanning, setIsFullAssetsScanning] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [viewingSaved, setViewingSaved] = useState(false);
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [assets, setAssets] = useState<IdentityAsset[]>([]);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [assetType, setAssetType] = useState<AssetType>('email');
  const [assetValue, setAssetValue] = useState('');
  const [assetLabel, setAssetLabel] = useState('');
  const [fullScanSummary, setFullScanSummary] = useState<FullScanSummary | null>(null);
  const [loadedNotificationScanId, setLoadedNotificationScanId] = useState<number | null>(null);
  const [gamification, setGamification] = useState<GamificationOverview | null>(null);
  const [gamificationLoading, setGamificationLoading] = useState(false);
  const [addingAssetKey, setAddingAssetKey] = useState<string | null>(null);

  const requestJson = async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const headers = new Headers(init?.headers || undefined);
    headers.set('Accept', 'application/json');
    if (init?.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    const response = await fetch(`${IDENTITY_API_BASE}${path}`, {
      ...init,
      credentials: 'include',
      headers,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload?.error || payload?.message || `Request failed (${response.status})`);
    }
    return payload as T;
  };

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const payload = await requestJson<{ scans?: IdentityScan[] }>('/scans');
      setHistory(Array.isArray(payload.scans) ? payload.scans : []);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  const loadAlerts = async () => {
    setAlertsLoading(true);
    try {
      const payload = await requestJson<{ alerts?: IdentityAlert[] }>('/alerts');
      setAlerts(Array.isArray(payload.alerts) ? payload.alerts : []);
    } catch {
      setAlerts([]);
    } finally {
      setAlertsLoading(false);
    }
  };

  const loadAssets = async () => {
    setAssetsLoading(true);
    try {
      const payload = await requestJson<{ assets?: IdentityAsset[] }>('/assets');
      setAssets(Array.isArray(payload.assets) ? payload.assets : []);
    } catch {
      setAssets([]);
    } finally {
      setAssetsLoading(false);
    }
  };

  const loadCurrentUser = async () => {
    try {
      const response = await fetch(`${API_BASE_URL || ''}/api/auth/me`, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      const payload = await response.json().catch(() => ({}));
      setCurrentUser(payload?.user || null);
    } catch {
      const fallbackEmail = localStorage.getItem('userEmail') || '';
      setCurrentUser(fallbackEmail ? { email: fallbackEmail } : null);
    }
  };

  const loadGamification = async () => {
    setGamificationLoading(true);
    try {
      setGamification(await fetchGamificationOverview());
    } catch {
      setGamification(null);
    } finally {
      setGamificationLoading(false);
    }
  };

  useEffect(() => {
    void loadHistory();
    void loadAlerts();
    void loadAssets();
    void loadCurrentUser();
    void loadGamification();
  }, []);

  const metrics = useMemo(() => {
    const totalScans = assets.length;
    const breachedAssets = assets.filter(isAssetRisky).length;
    const totalBreaches = history.reduce(
      (sum, scan) =>
        sum +
        (typeof scan.confirmed_breach_count !== 'undefined'
          ? safeNumber(scan.confirmed_breach_count)
          : (scan.findings || []).filter((finding) => finding.category === 'confirmed_breach').length),
      0
    );
    const safeAssets = Math.max(totalScans - breachedAssets, 0);
    const protectionRate = totalScans ? Math.round((safeAssets / totalScans) * 100) : 0;
    return { totalScans, breachedAssets, safeAssets, totalBreaches, protectionRate };
  }, [assets, history]);

  const monitoredAssetKeys = useMemo(
    () => new Set(assets.map((asset) => assetKey(asset.asset_type, asset.asset_value))),
    [assets]
  );

  const setState = (message: string, isError = false) => {
    setStatusMessage(message);
    setStatusError(isError);
  };

  const addCandidateToAssets = async (candidate: AssetCandidate) => {
    const normalizedValue = normalizeAssetValue(candidate.assetType, candidate.assetValue);
    const key = assetKey(candidate.assetType, normalizedValue);
    if (!normalizedValue || monitoredAssetKeys.has(key)) return;

    setAddingAssetKey(key);
    try {
      const payload = await requestJson<AddAssetResponse>('/assets', {
        method: 'POST',
        body: JSON.stringify({
          asset_type: candidate.assetType,
          asset_value: normalizedValue,
          label: candidate.label || '',
        }),
      });
      setState(payload.already_exists ? 'Asset is already monitored.' : 'Asset added successfully.');
      await loadAssets();
    } catch {
      setState('Could not add asset. Please try again.', true);
    } finally {
      setAddingAssetKey(null);
    }
  };

  const renderAddAssetButton = (candidate: AssetCandidate | null) => {
    if (!candidate) return null;
    const normalizedValue = normalizeAssetValue(candidate.assetType, candidate.assetValue);
    if (!normalizedValue) return null;
    const key = assetKey(candidate.assetType, normalizedValue);
    const alreadyMonitored = monitoredAssetKeys.has(key);
    const isAdding = addingAssetKey === key;

    return (
      <Button
        type="button"
        size="sm"
        variant="outline"
        className={alreadyMonitored ? 'border-green-500/30 text-green-300' : 'border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10'}
        disabled={alreadyMonitored || Boolean(addingAssetKey)}
        onClick={(event) => {
          event.stopPropagation();
          void addCandidateToAssets(candidate);
        }}
      >
        {isAdding ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : alreadyMonitored ? <Shield className="mr-2 h-4 w-4" /> : <Plus className="mr-2 h-4 w-4" />}
        {alreadyMonitored ? 'Already Monitored' : '+ Add to Assets'}
      </Button>
    );
  };

  const startScan = async () => {
    const payload = {
      email: email.trim(),
      username: username.trim(),
      domain: domain.trim(),
    };

    if (!payload.email && !payload.username && !payload.domain) {
      setState('Please enter an email, username, or domain.', true);
      return;
    }

    setIsScanning(true);
    setViewingSaved(false);
    setState('Searching public web sources, GitHub, GitLab, Stack Exchange, and LeakCheck...');
    try {
      const data = await requestJson<IdentityScan>('/web-scan', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const scanId = normalizeScanId(data);
      setReport(data);
      setSelectedScanId(scanId);
      setState(`Completed. Scan #${scanId || '-'} returned ${formatNumber(data.total_findings || 0)} finding(s).`);
      broadcastGamificationUpdated();
      await Promise.all([loadHistory(), loadAlerts(), loadAssets(), loadGamification()]);
    } catch (error) {
      setState(error instanceof Error ? error.message : 'Public web scan failed.', true);
    } finally {
      setIsScanning(false);
    }
  };

  const scanMyIdentity = async () => {
    const userEmail = currentUser?.email?.trim() || localStorage.getItem('userEmail')?.trim() || '';
    const displayName = currentUser?.username?.trim() || currentUser?.name?.trim() || currentUser?.full_name?.trim() || '';
    const payload = {
      email: userEmail,
      username: leakCheckSafeUsername(displayName),
      domain: emailDomain(userEmail),
    };

    if (!payload.email && !payload.username) {
      setState('Could not find your profile email or username. Add an asset or run a manual scan.', true);
      return;
    }

    setIsMyIdentityScanning(true);
    setViewingSaved(false);
    setFullScanSummary(null);
    setState('Scanning your profile identity...');
    try {
      const data = await requestJson<IdentityScan>('/web-scan', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const scanId = normalizeScanId(data);
      setReport(data);
      setSelectedScanId(scanId);
      setState(`Completed. Scan #${scanId || '-'} checked your identity and returned ${formatNumber(data.total_findings || 0)} finding(s).`);
      broadcastGamificationUpdated();
      await Promise.all([loadHistory(), loadAlerts(), loadAssets(), loadGamification()]);
    } catch (error) {
      setState(error instanceof Error ? error.message : 'Scan My Identity failed.', true);
    } finally {
      setIsMyIdentityScanning(false);
    }
  };

  const scanAllAssets = async () => {
    setIsFullAssetsScanning(true);
    setViewingSaved(false);
    setFullScanSummary(null);
    setState('Scanning all monitored assets...');
    try {
      const summary = await requestJson<FullScanSummary>('/full-scan-assets', { method: 'POST' });
      setFullScanSummary(summary);
      if (summary.status === 'empty') {
        setState(summary.message || 'No monitored assets found. Add assets first.', true);
        return;
      }
      setState(`Completed. Scanned ${formatNumber(summary.total_assets_scanned || 0)} monitored asset(s).`);
      broadcastGamificationUpdated();
      const lastScanId = summary.results?.[summary.results.length - 1]?.scan_id;
      if (lastScanId) {
        await loadScan(lastScanId);
      }
      await Promise.all([loadHistory(), loadAlerts(), loadAssets(), loadGamification()]);
    } catch (error) {
      setState(error instanceof Error ? error.message : 'Full asset scan failed.', true);
    } finally {
      setIsFullAssetsScanning(false);
    }
  };

  const addAsset = async () => {
    if (!assetValue.trim()) {
      setState('Enter an asset value first.', true);
      return;
    }
    try {
      const payload = await requestJson<AddAssetResponse>('/assets', {
        method: 'POST',
        body: JSON.stringify({
          asset_type: assetType,
          asset_value: assetValue.trim(),
          label: assetLabel.trim(),
        }),
      });
      setAssetValue('');
      setAssetLabel('');
      setState(payload.already_exists ? 'Asset is already monitored.' : 'Asset added successfully.');
      await loadAssets();
    } catch (error) {
      setState(error instanceof Error ? error.message : 'Could not add asset. Please try again.', true);
    }
  };

  const deleteAsset = async (assetId: number) => {
    try {
      await requestJson<{ status: string }>(`/assets/${assetId}`, { method: 'DELETE' });
      setState('Monitored asset removed.');
      await loadAssets();
    } catch (error) {
      setState(error instanceof Error ? error.message : 'Could not remove monitored asset.', true);
    }
  };

  const clearHistory = async () => {
    if (!window.confirm('Clear your Identity Leak Monitor scan history and alerts? Monitored assets will stay saved.')) {
      return;
    }
    try {
      const payload = await requestJson<{ deleted_scans?: number }>('/scans', { method: 'DELETE' });
      setReport(null);
      setSelectedScanId(null);
      setViewingSaved(false);
      setFullScanSummary(null);
      setState(`Scan history cleared. Removed ${formatNumber(payload.deleted_scans || 0)} scan(s).`);
      await Promise.all([loadHistory(), loadAlerts(), loadAssets()]);
    } catch (error) {
      setState(error instanceof Error ? error.message : 'Could not clear scan history.', true);
    }
  };

  const loadScan = async (scanId: number, loadedMessage?: string) => {
    setState(`Loading saved scan #${scanId}...`);
    try {
      const [scan, findingPayload] = await Promise.all([
        requestJson<IdentityScan>(`/scans/${scanId}`),
        requestJson<{ findings?: IdentityFinding[] }>(`/findings/${scanId}`),
      ]);
      const findings = Array.isArray(findingPayload.findings)
        ? findingPayload.findings
        : Array.isArray(scan.findings)
          ? scan.findings
          : [];
      const hydrated = {
        ...scan,
        scan_id: scan.id || scan.scan_id || scanId,
        findings,
        total_findings: safeNumber(scan.total_findings || findings.length),
      };
      setReport(hydrated);
      setViewingSaved(true);
      setSelectedScanId(scanId);
      setState(loadedMessage || `Loaded scan #${scanId} from history.`);
      window.requestAnimationFrame(() => {
        document.getElementById('identity-results')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    } catch (error) {
      setState(error instanceof Error ? error.message : 'Could not load saved scan details.', true);
    }
  };

  useEffect(() => {
    const rawScanId = searchParams.get('scan_id');
    const scanId = rawScanId ? Number(rawScanId) : 0;
    if (!Number.isFinite(scanId) || scanId <= 0 || loadedNotificationScanId === scanId) {
      return;
    }
    setLoadedNotificationScanId(scanId);
    void loadScan(scanId, `Loaded scan #${scanId} from notification.`);
  }, [searchParams, loadedNotificationScanId]);

  const downloadReport = async () => {
    if (!report) return;
    const scanId = normalizeScanId(report);
    if (!scanId) {
      setState('Save or load a scan before downloading the PDF report.', true);
      return;
    }
    try {
      setState(`Preparing PDF report for scan #${scanId}...`);
      const response = await fetch(`${IDENTITY_API_BASE}/scans/${scanId}/report.pdf`, {
        credentials: 'include',
        headers: { Accept: 'application/pdf' },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload?.error || `PDF download failed (${response.status})`);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = href;
      link.download = `identity-leak-report-scan-${scanId}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(href);
      setState(`PDF report downloaded for scan #${scanId}.`);
    } catch (error) {
      setState(error instanceof Error ? error.message : 'PDF download failed.', true);
    }
  };

  const refreshIdentityData = async () => {
    setIsRefreshing(true);
    setState('Refreshing scan history and alerts...');
    try {
      await Promise.all([loadHistory(), loadAlerts(), loadAssets(), loadCurrentUser(), loadGamification()]);
      if (selectedScanId) {
        await loadScan(selectedScanId);
      } else {
        setState('Identity data refreshed.');
      }
    } finally {
      setIsRefreshing(false);
    }
  };

  const clearCurrentSearch = () => {
    setEmail('');
    setUsername('');
    setDomain('');
    setReport(null);
    setFullScanSummary(null);
    setSelectedScanId(null);
    setViewingSaved(false);
    setState('Ready. Enter at least one field to start.');
  };

  const sourceStatuses = report?.source_status || {};
  const findings = report?.findings || [];
  const activeScanId = report ? normalizeScanId(report) : null;
  const selectedAlert = activeScanId
    ? alerts.find((alert) => Number(alert.scan_id) === Number(activeScanId))
    : null;
  const weeklyAnalysisChallenge = gamification?.challenges.weekly.find(
    (challenge) => challenge.challenge_code === 'complete_three_scans'
  );
  const identityRewards = (gamification?.history || []).filter(
    (item) =>
      item.event_type === 'identity_scan_completed' ||
      String(item.job_id || '').startsWith('identity-scan-') ||
      item.human_readable_reason.toLowerCase().includes('identity')
  );
  const protection = protectionTone(metrics.protectionRate);
  const protectionHelper = metrics.totalScans
    ? `${formatNumber(metrics.safeAssets)} of ${formatNumber(metrics.totalScans)} monitored assets are currently low risk.`
    : 'Add monitored assets to calculate protection rate.';

  return (
    <div className="space-y-6" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-gradient-to-r from-red-500 to-blue-600 shadow-[0_0_30px_rgba(59,130,246,0.25)]">
            <Eye className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Identity Leak Monitor</h1>
            <p className="mt-1 text-gray-400">Public web exposure scanning with saved history, alerts, and evidence review.</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            className="border-blue-500/30 text-blue-300 hover:bg-blue-500/10"
            onClick={() => void refreshIdentityData()}
            disabled={isRefreshing}
          >
            {isRefreshing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
            Refresh
          </Button>
          <Button
            className="bg-gradient-to-r from-red-600 to-blue-700 hover:from-red-700 hover:to-blue-800"
            onClick={scanMyIdentity}
            disabled={isScanning || isMyIdentityScanning || isFullAssetsScanning}
          >
            {isMyIdentityScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Zap className="mr-2 h-4 w-4" />}
            Scan My Identity
          </Button>
          <Button
            className="bg-gradient-to-r from-cyan-600 to-blue-700 hover:from-cyan-700 hover:to-blue-800"
            onClick={scanAllAssets}
            disabled={isScanning || isMyIdentityScanning || isFullAssetsScanning}
          >
            {isFullAssetsScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Radar className="mr-2 h-4 w-4" />}
            Scan All Assets
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <Card className="cyber-card overflow-hidden">
          <CardContent className="flex min-h-[156px] flex-col justify-between !px-8 !py-7">
            <div>
              <p className="text-sm text-gray-400">Monitored Assets</p>
              <p className="mt-1 text-xs text-gray-500">Emails, usernames, and domains</p>
            </div>
            <div className="flex items-end justify-between gap-3">
              <p className="text-3xl font-semibold text-white">{formatNumber(metrics.totalScans)}</p>
              <Badge className="border-blue-500/30 bg-blue-500/10 text-blue-300">Tracked</Badge>
            </div>
            <p className="text-xs leading-5 text-gray-400">
              {metrics.totalScans ? `${formatNumber(metrics.totalScans)} asset${metrics.totalScans === 1 ? '' : 's'} under monitoring.` : 'Add assets to start monitoring.'}
            </p>
          </CardContent>
        </Card>
        <Card className="cyber-card overflow-hidden">
          <CardContent className="flex min-h-[156px] flex-col justify-between !px-8 !py-7">
            <div>
              <p className="text-sm text-gray-400">Risky Assets</p>
              <p className="mt-1 text-xs text-gray-500">Medium, high, critical, or exposed</p>
            </div>
            <div className="flex items-end justify-between gap-3">
              <p className="text-3xl font-semibold text-red-300">{formatNumber(metrics.breachedAssets)}</p>
              <Badge className={metrics.breachedAssets ? 'border-red-500/30 bg-red-500/10 text-red-300' : 'border-green-500/30 bg-green-500/10 text-green-300'}>
                {metrics.breachedAssets ? 'Review' : 'Clear'}
              </Badge>
            </div>
            <p className="text-xs leading-5 text-gray-400">
              {metrics.breachedAssets ? `${formatNumber(metrics.breachedAssets)} monitored asset${metrics.breachedAssets === 1 ? '' : 's'} need attention.` : 'No risky monitored assets right now.'}
            </p>
          </CardContent>
        </Card>
        <Card className="cyber-card overflow-hidden">
          <CardContent className="flex min-h-[156px] flex-col justify-between !px-8 !py-7">
            <div>
              <p className="text-sm text-gray-400">Total Breaches</p>
              <p className="mt-1 text-xs text-gray-500">Confirmed breach findings</p>
            </div>
            <div className="flex items-end justify-between gap-3">
              <p className="text-3xl font-semibold text-yellow-300">{formatNumber(metrics.totalBreaches)}</p>
              <Badge className={metrics.totalBreaches ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300' : 'border-slate-500/30 bg-slate-500/10 text-slate-300'}>
                Evidence
              </Badge>
            </div>
            <p className="text-xs leading-5 text-gray-400">
              {metrics.totalBreaches ? `${formatNumber(metrics.totalBreaches)} confirmed breach finding${metrics.totalBreaches === 1 ? '' : 's'} across scan history.` : 'No confirmed breaches recorded.'}
            </p>
          </CardContent>
        </Card>
        <Card className={`cyber-card overflow-hidden ${protection.border}`}>
          <CardContent className="flex min-h-[156px] flex-col justify-center !px-8 !py-7">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-sm text-gray-400">Protection Rate</p>
                <p className="mt-1 text-xs text-gray-500">Safe assets percentage</p>
              </div>
              <div className="group relative">
                <Info className="h-4 w-4 text-gray-400" />
                <div className="pointer-events-none absolute right-0 top-6 z-20 hidden w-72 rounded-lg border border-white/10 bg-slate-950 p-3 text-xs leading-5 text-gray-300 shadow-xl group-hover:block">
                  Protection Rate shows the percentage of monitored emails, usernames, and domains that are currently low risk.
                </div>
              </div>
            </div>
            <div className="mt-3 flex items-end justify-between gap-3">
              <p className={`text-3xl font-semibold ${protection.text}`}>{metrics.protectionRate}%</p>
              <Badge className={protection.badge}>{protection.label}</Badge>
            </div>
            <p className="mt-3 text-xs leading-5 text-gray-400">{protectionHelper}</p>
            <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
              <span className="rounded-lg border border-green-500/20 bg-green-500/10 px-2 py-1 text-green-200">Safe: {formatNumber(metrics.safeAssets)}</span>
              <span className="rounded-lg border border-red-500/20 bg-red-500/10 px-2 py-1 text-red-200">Risky: {formatNumber(metrics.breachedAssets)}</span>
              <span className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-gray-300">Total: {formatNumber(metrics.totalScans)}</span>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="cyber-card border-cyan-500/15">
        <CardHeader className="!px-6 !pt-6">
          <CardTitle className="flex flex-wrap items-center justify-between gap-3 text-white">
            <span className="flex items-center">
              <Zap className="mr-2 h-5 w-5 text-cyan-400" />
              Identity Gamification
            </span>
            <Button
              size="sm"
              variant="outline"
              className="border-cyan-500/30 text-cyan-200 hover:bg-cyan-500/10"
              onClick={() => void loadGamification()}
              disabled={gamificationLoading}
            >
              {gamificationLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              Refresh
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 !px-6 !pb-6 lg:grid-cols-3">
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-gray-500">Unified Points</p>
            <p className="mt-2 text-2xl font-semibold text-white">
              {gamification ? formatNumber(gamification.profile.total_points) : '-'}
            </p>
            <p className="mt-1 text-xs text-gray-400">
              Identity scan rewards are included in the unified Rewards History.
            </p>
          </div>
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-gray-500">Weekly Analysis Challenge</p>
            <p className="mt-2 text-lg font-semibold text-white">
              {weeklyAnalysisChallenge
                ? `${formatNumber(weeklyAnalysisChallenge.current_value)} / ${formatNumber(weeklyAnalysisChallenge.target_value)}`
                : '-'}
            </p>
            <p className="mt-1 text-xs text-gray-400">
              Identity scans count toward “Complete 3 analyses this week”.
            </p>
          </div>
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-gray-500">Latest Identity Reward</p>
            {identityRewards[0] ? (
              <>
                <p className="mt-2 text-sm font-semibold text-white">
                  +{formatNumber(identityRewards[0].points_awarded)} points
                </p>
                <p className="mt-1 text-xs leading-5 text-gray-400">
                  {identityRewards[0].human_readable_reason}
                </p>
                <p className="mt-1 text-[11px] text-gray-500">
                  {formatGamificationTimestamp(identityRewards[0].created_at)}
                </p>
              </>
            ) : (
              <p className="mt-2 text-xs leading-5 text-gray-400">
                Run an Identity scan to earn the Identity scan completion reward.
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="cyber-card">
        <CardHeader className="!px-8 !pt-8">
          <CardTitle className="flex items-center text-white">
            <Search className="mr-2 h-5 w-5 text-blue-400" />
            Start Public Web Scan
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5 !px-8 !pb-8">
          <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3">
            <div className="min-w-0">
              <label className="mb-2 block text-sm text-gray-400">Email</label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                <Input className="h-12 rounded-2xl pl-11 pr-4" placeholder="name@example.com" value={email} onChange={(event) => setEmail(event.target.value)} />
              </div>
            </div>
            <div className="min-w-0">
              <label className="mb-2 block text-sm text-gray-400">Username</label>
              <div className="relative">
                <User className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                <Input className="h-12 rounded-2xl pl-11 pr-4" placeholder="public_username" value={username} onChange={(event) => setUsername(event.target.value)} />
              </div>
            </div>
            <div className="min-w-0 md:col-span-2 xl:col-span-1">
              <label className="mb-2 block text-sm text-gray-400">Domain</label>
              <div className="relative">
                <Globe className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                <Input className="h-12 rounded-2xl pl-11 pr-4" placeholder="example.com" value={domain} onChange={(event) => setDomain(event.target.value)} />
              </div>
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <Button
              onClick={startScan}
              disabled={isScanning || isMyIdentityScanning || isFullAssetsScanning || (!email.trim() && !username.trim() && !domain.trim())}
              className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700"
            >
              {isScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Radar className="mr-2 h-4 w-4" />}
              Start Web Scan
            </Button>
            <Button
              variant="outline"
              disabled={!report}
              onClick={() => void downloadReport()}
              className="min-h-12 rounded-2xl border-cyan-400/40 bg-cyan-500/10 px-5 font-semibold text-cyan-100 shadow-[0_0_22px_rgba(34,211,238,0.12)] hover:border-cyan-300/60 hover:bg-cyan-500/20 hover:text-white"
            >
              <Download className="mr-2 h-4 w-4" />
              Download PDF Report
            </Button>
            <Button
              variant="outline"
              onClick={clearCurrentSearch}
              disabled={isScanning || isMyIdentityScanning || isFullAssetsScanning}
              className="border-slate-500/30 text-slate-200 hover:bg-slate-500/10"
            >
              <X className="mr-2 h-4 w-4" />
              Clear Current Search
            </Button>
          </div>
          <div
            className={`rounded-xl border px-5 py-4 text-sm leading-6 ${
              statusError
                ? 'border-red-500/30 bg-red-500/10 text-red-200'
                : 'border-blue-500/20 bg-blue-500/10 text-gray-300'
            }`}
          >
            {statusMessage}
          </div>
        </CardContent>
      </Card>

      {fullScanSummary && fullScanSummary.status !== 'empty' ? (
        <Card className="cyber-card">
          <CardHeader>
            <CardTitle className="flex items-center text-white">
              <Radar className="mr-2 h-5 w-5 text-cyan-400" />
              Full Asset Scan Summary
            </CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-5">
            <div className="rounded-xl border border-white/10 bg-gray-900/40 p-4">
              <p className="text-sm text-gray-400">Total Assets Scanned</p>
              <p className="mt-2 text-2xl font-semibold text-white">{formatNumber(fullScanSummary.total_assets_scanned || 0)}</p>
            </div>
            <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4">
              <p className="text-sm text-red-200">Risky Assets</p>
              <p className="mt-2 text-2xl font-semibold text-red-100">{formatNumber(fullScanSummary.risky_assets || 0)}</p>
            </div>
            <div className="rounded-xl border border-green-500/20 bg-green-500/10 p-4">
              <p className="text-sm text-green-200">Clean Assets</p>
              <p className="mt-2 text-2xl font-semibold text-green-100">{formatNumber(fullScanSummary.clean_assets || 0)}</p>
            </div>
            <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/10 p-4">
              <p className="text-sm text-yellow-200">Total Findings</p>
              <p className="mt-2 text-2xl font-semibold text-yellow-100">{formatNumber(fullScanSummary.total_findings || 0)}</p>
            </div>
            <div className="rounded-xl border border-white/10 bg-gray-900/40 p-4">
              <p className="text-sm text-gray-400">Highest Risk Level</p>
              <Badge className={`mt-3 ${riskTone(fullScanSummary.highest_risk_level || 'Low')}`}>
                {fullScanSummary.highest_risk_level || 'Low'}
              </Badge>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <Card className="cyber-card">
        <CardHeader>
          <CardTitle className="flex items-center justify-between gap-3 text-white">
            <span className="flex items-center"><Shield className="mr-2 h-5 w-5 text-blue-400" />Monitored Assets</span>
            <Button size="sm" variant="outline" className="border-blue-500/30 text-blue-300 hover:bg-blue-500/10" onClick={() => void loadAssets()}>
              {assetsLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-[160px_minmax(0,1fr)_minmax(0,1fr)_auto]">
            <div className="flex rounded-2xl border border-blue-500/20 bg-slate-950/60 p-1">
              {(['email', 'username', 'domain'] as AssetType[]).map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setAssetType(type)}
                  className={`flex-1 rounded-xl px-2 py-2 text-xs font-semibold capitalize transition ${
                    assetType === type ? 'bg-blue-500/20 text-blue-100' : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {type}
                </button>
              ))}
            </div>
            <Input className="h-11 rounded-2xl" placeholder="Asset value" value={assetValue} onChange={(event) => setAssetValue(event.target.value)} />
            <Input className="h-11 rounded-2xl" placeholder="Label optional" value={assetLabel} onChange={(event) => setAssetLabel(event.target.value)} />
            <Button onClick={addAsset} className="h-11 rounded-2xl bg-blue-600 hover:bg-blue-700">
              <Plus className="mr-2 h-4 w-4" />
              Add Asset
            </Button>
          </div>

          {assets.length === 0 ? (
            <div className="rounded-xl border border-white/10 bg-gray-900/40 px-4 py-8 text-center text-gray-400">
              {assetsLoading ? 'Loading monitored assets...' : 'No monitored assets yet.'}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table className="min-w-[980px]">
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Risk Level</TableHead>
                    <TableHead>Breaches/Findings</TableHead>
                    <TableHead>Last Check</TableHead>
                    <TableHead>Auto</TableHead>
                    <TableHead></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((asset) => (
                    <TableRow
                      key={asset.id}
                      onClick={() => asset.last_scan_id && void loadScan(asset.last_scan_id)}
                      className={`transition ${
                        asset.last_scan_id
                          ? 'cursor-pointer hover:bg-cyan-500/10'
                          : 'cursor-default'
                      } ${
                        selectedScanId === asset.last_scan_id
                          ? 'bg-cyan-500/10'
                          : ''
                      }`}
                    >
                      <TableCell>
                        <div className="font-medium text-white">{asset.label || asset.asset_value}</div>
                        <div className="mt-1 text-xs text-gray-500">
                          {asset.label ? asset.asset_value : asset.last_scan_id ? `Click to view scan #${asset.last_scan_id}` : 'Run Scan All Assets to generate a result'}
                        </div>
                      </TableCell>
                      <TableCell className="capitalize text-gray-300">{asset.asset_type}</TableCell>
                      <TableCell>
                        <Badge className={assetStatusTone(asset.status)}>{asset.status || 'pending'}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={riskTone(asset.last_risk_level || 'Low')}>{asset.last_risk_level || 'Low'}</Badge>
                      </TableCell>
                      <TableCell className="text-gray-300">{formatNumber(asset.last_findings_count || 0)}</TableCell>
                      <TableCell className="text-gray-400">{asset.last_checked_at ? formatDateTime(asset.last_checked_at) : '-'}</TableCell>
                      <TableCell>
                        <Badge className={asset.auto_scan_enabled ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-slate-500/30 bg-slate-500/10 text-slate-300'}>
                          {asset.auto_scan_enabled ? 'On' : 'Off'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          className="border-red-500/30 text-red-300 hover:bg-red-500/10"
                          onClick={(event) => {
                            event.stopPropagation();
                            void deleteAsset(asset.id);
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {report && (
        <motion.div id="identity-results" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
          {viewingSaved ? (
            <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm font-medium text-cyan-200">
              Viewing saved scan #{normalizeScanId(report)}
            </div>
          ) : null}

          <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
            <Card className="cyber-card overflow-hidden">
              <CardContent className="flex min-h-[108px] flex-col justify-center !p-6">
                <p className="text-sm text-gray-400">Risk Score</p>
                <p className="mt-2 text-3xl font-semibold text-white">{formatNumber(report.risk_score || 0)}</p>
              </CardContent>
            </Card>
            <Card className="cyber-card overflow-hidden">
              <CardContent className="flex min-h-[108px] flex-col justify-center !p-6">
                <p className="text-sm text-gray-400">Risk Level</p>
                <Badge className={`mt-3 ${riskTone(report.risk_level)}`}>{report.risk_level || 'Low'}</Badge>
              </CardContent>
            </Card>
            <Card className="cyber-card overflow-hidden">
              <CardContent className="flex min-h-[108px] flex-col justify-center !p-6">
                <p className="text-sm text-gray-400">Sources Checked</p>
                <p className="mt-2 text-3xl font-semibold text-white">{formatNumber(report.sources_checked || 0)}</p>
              </CardContent>
            </Card>
            <Card className="cyber-card overflow-hidden">
              <CardContent className="flex min-h-[108px] flex-col justify-center !p-6">
                <p className="text-sm text-gray-400">Total Findings</p>
                <p className="mt-2 text-3xl font-semibold text-white">{formatNumber(report.total_findings || findings.length)}</p>
              </CardContent>
            </Card>
          </div>

          <Card className="cyber-card">
            <CardContent className="space-y-5 !p-7 md:!p-8">
              <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-gray-400">Recommendation</p>
                  <p className="mt-2 max-w-5xl text-base leading-7 text-gray-100">{report.recommendation || 'No confirmed public exposure was found. Continue periodic monitoring.'}</p>
                </div>
                <p className="shrink-0 text-sm text-gray-500">Last scan: {report.completed_at ? formatDateTime(report.completed_at) : '-'}</p>
              </div>
              <div className="flex flex-wrap gap-3 pt-1">
                {(Object.keys(SOURCE_LABELS) as SourceKey[]).map((key) => (
                  <Badge key={key} className={`rounded-full px-4 py-2 text-sm font-semibold ${statusTone(sourceStatuses[key])}`}>
                    {SOURCE_LABELS[key]}: {statusText(sourceStatuses[key])}
                  </Badge>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-2 border-t border-white/10 pt-4">
                <span className="text-sm text-gray-400">Monitor this scan:</span>
                {scanAssetCandidates(report).map((candidate) => (
                  <div key={assetKey(candidate.assetType, candidate.assetValue)}>
                    {renderAddAssetButton(candidate)}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="cyber-card border-blue-500/15">
            <CardContent className="flex flex-col gap-4 !p-5 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex items-start gap-3">
                <div
                  className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${
                    selectedAlert
                      ? 'border-red-500/30 bg-red-500/10 text-red-200'
                      : 'border-green-500/30 bg-green-500/10 text-green-200'
                  }`}
                >
                  {selectedAlert ? <AlertTriangle className="h-5 w-5" /> : <Shield className="h-5 w-5" />}
                </div>
                <div>
                  <p className="text-sm font-semibold text-white">Security Alert Status</p>
                  {selectedAlert ? (
                    <p className="mt-1 text-sm leading-6 text-gray-300">
                      Alert #{selectedAlert.id} was created for scan #{selectedAlert.scan_id}: {selectedAlert.title}
                    </p>
                  ) : (
                    <p className="mt-1 text-sm leading-6 text-gray-300">
                      No Security Alert was created for this scan because it is {report.risk_level || 'Low'} risk with {formatNumber(report.total_findings || findings.length)} finding(s).
                    </p>
                  )}
                </div>
              </div>
              {selectedAlert ? (
                <Badge className={riskTone(selectedAlert.severity)}>{selectedAlert.severity}</Badge>
              ) : (
                <Badge className="border-green-500/30 bg-green-500/10 text-green-300">No alert-worthy finding</Badge>
              )}
            </CardContent>
          </Card>

          <Card className="cyber-card overflow-hidden">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <Database className="mr-2 h-5 w-5 text-blue-400" />
                Findings
              </CardTitle>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <div className="rounded-xl border border-green-500/20 bg-green-500/10 px-4 py-8 text-center text-green-200">
                  No public exposure findings were detected.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table className="min-w-[1460px]">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Source</TableHead>
                        <TableHead>Category</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Matched Field</TableHead>
                        <TableHead>Evidence</TableHead>
                        <TableHead>Found In Page</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>Link</TableHead>
                        <TableHead>Asset</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {findings.map((finding, index) => (
                        <TableRow key={`${finding.source}-${finding.url || index}`}>
                          <TableCell className="text-white">{sourceLabel(finding.source)}</TableCell>
                          <TableCell>
                            <Badge className={categoryTone(finding.category)}>
                              {CATEGORY_LABELS[finding.category] || finding.category || 'Public Mention'}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={riskTone(finding.severity)}>{finding.severity || 'Low'}</Badge>
                          </TableCell>
                          <TableCell>
                            <div className="text-gray-300">{finding.matched_field || '-'}</div>
                            <div className="mt-1 max-w-[180px] truncate text-xs text-gray-500">{finding.matched_value || ''}</div>
                          </TableCell>
                          <TableCell className="max-w-[420px] text-gray-300">
                            <div className="font-medium text-white">{finding.title || '-'}</div>
                            <div className="mt-1 text-sm leading-6 text-gray-400">{finding.evidence || '-'}</div>
                          </TableCell>
                          <TableCell>
                            <Badge className={finding.found_in_page ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-slate-500/30 bg-slate-500/10 text-slate-300'}>
                              {evidenceSource(finding)}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-gray-300">{formatNumber(safeNumber(finding.confidence))}%</TableCell>
                          <TableCell>
                            {finding.url ? (
                              <a className="inline-flex items-center text-cyan-300 hover:text-cyan-200" href={finding.url} target="_blank" rel="noreferrer">
                                <LinkIcon className="mr-1 h-4 w-4" />
                                Open
                              </a>
                            ) : (
                              <span className="text-gray-500">-</span>
                            )}
                          </TableCell>
                          <TableCell>{renderAddAssetButton(findingAssetCandidate(finding))}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card className="cyber-card">
          <CardHeader>
            <CardTitle className="flex items-center justify-between gap-3 text-white">
              <span className="flex items-center"><History className="mr-2 h-5 w-5 text-blue-400" />Scan History</span>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="border-red-500/30 text-red-300 hover:bg-red-500/10"
                  onClick={() => void clearHistory()}
                  disabled={historyLoading || history.length === 0}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Clear History
                </Button>
                <Button size="sm" variant="outline" className="border-blue-500/30 text-blue-300 hover:bg-blue-500/10" onClick={() => void loadHistory()}>
                  {historyLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                </Button>
              </div>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {history.length === 0 ? (
              <div className="rounded-xl border border-white/10 bg-gray-900/40 px-4 py-6 text-center text-gray-400">
                {historyLoading ? 'Loading history...' : 'No scans yet.'}
              </div>
            ) : (
              history.map((scan) => {
                const scanId = normalizeScanId(scan);
                return (
                  <div
                    key={scanId || scan.created_at}
                    role="button"
                    tabIndex={0}
                    onClick={() => scanId && void loadScan(scanId)}
                    onKeyDown={(event) => {
                      if ((event.key === 'Enter' || event.key === ' ') && scanId) {
                        event.preventDefault();
                        void loadScan(scanId);
                      }
                    }}
                    className={`w-full rounded-xl border p-4 text-left transition ${
                      selectedScanId === scanId
                        ? 'border-cyan-400/60 bg-cyan-500/10'
                        : 'border-white/10 bg-gray-900/40 hover:border-cyan-400/40 hover:bg-gray-800/60'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-semibold text-white">#{scanId} - {compactTarget(scan)}</span>
                      <Badge className={riskTone(scan.risk_level)}>{scan.risk_level || 'Low'}</Badge>
                    </div>
                    <div className="mt-2 text-sm text-gray-400">
                      {scan.created_at ? formatDateTime(scan.created_at) : '-'} - {formatNumber(scan.total_findings || 0)} finding(s)
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {scanAssetCandidates(scan).map((candidate) => (
                        <div key={assetKey(candidate.assetType, candidate.assetValue)}>
                          {renderAddAssetButton(candidate)}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>

        <Card className="cyber-card">
          <CardHeader>
            <CardTitle className="flex items-center justify-between gap-3 text-white">
              <span className="flex items-center"><AlertTriangle className="mr-2 h-5 w-5 text-red-400" />Alerts</span>
              <Button size="sm" variant="outline" className="border-blue-500/30 text-blue-300 hover:bg-blue-500/10" onClick={() => void loadAlerts()}>
                {alertsLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {alerts.length === 0 ? (
              <div className="rounded-xl border border-white/10 bg-gray-900/40 px-4 py-6 text-center text-gray-400">
                {alertsLoading ? 'Loading alerts...' : 'No alerts yet.'}
              </div>
            ) : (
              alerts.map((alert) => {
                const alertScan = history.find((scan) => Number(normalizeScanId(scan)) === Number(alert.scan_id));
                return (
                  <div
                    key={alert.id}
                    role="button"
                    tabIndex={0}
                    onClick={() => alert.scan_id && void loadScan(alert.scan_id)}
                    onKeyDown={(event) => {
                      if ((event.key === 'Enter' || event.key === ' ') && alert.scan_id) {
                        event.preventDefault();
                        void loadScan(alert.scan_id);
                      }
                    }}
                    className="w-full rounded-xl border border-white/10 bg-gray-900/40 p-4 text-left transition hover:border-red-400/40 hover:bg-gray-800/60"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-semibold text-white">{alert.title}</span>
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={emailStatusTone(alert.email_status)}>{emailStatusLabel(alert.email_status)}</Badge>
                        <Badge className={riskTone(alert.severity)}>{alert.severity}</Badge>
                      </div>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-gray-400">{alert.message}</p>
                    <p className="mt-2 text-xs text-gray-500">
                      {alert.created_at ? formatDateTime(alert.created_at) : '-'}
                      {alert.email_status === 'failed' && alert.email_error ? ` - ${alert.email_error}` : ''}
                    </p>
                    {alertScan ? (
                      <div className="mt-3 flex flex-wrap gap-2">
                        {scanAssetCandidates(alertScan).map((candidate) => (
                          <div key={assetKey(candidate.assetType, candidate.assetValue)}>
                            {renderAddAssetButton(candidate)}
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="cyber-card border-blue-500/10">
        <CardContent className="flex items-start gap-3 p-4 text-sm text-gray-400">
          <Shield className="mt-0.5 h-4 w-4 flex-shrink-0 text-blue-400" />
          <p>
            Manual scans, Scan My Identity, Scan All Assets, and PDF reports use safe public sources only.
            Sentinel AI does not store passwords, does not query HIBP, does not use Tor or login-required pages,
            and sends only validated supported identifiers to LeakCheck Public API.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
