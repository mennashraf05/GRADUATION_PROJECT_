import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Progress } from '../ui/progress';
import { Button } from '../ui/button';
import { RecentSecurityAlertsPanel } from '../security/RecentSecurityAlertsPanel';
import { NetworkSecurityScoreCard } from '../security/NetworkSecurityScoreCard';
import {
  Shield,
  TrendingUp,
  Eye,
  Users,
  Lock,
  AlertTriangle,
  Brain,
  RefreshCw,
  HardDrive,
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line
} from 'recharts';
import { useLanguage } from '../../contexts/LanguageContext';

type VaultDocument = {
  id: number;
  filename: string;
  size_bytes?: number;
  offline_enabled?: boolean;
};

type VaultPattern = {
  type?: string;
  name?: string;
  count?: number;
  severity?: string;
  message?: string;
  description?: string;
};

type VaultAiResult = {
  risk_score?: number;
  severity?: string;
  suspicious_patterns?: VaultPattern[];
  patterns?: VaultPattern[];
  created_alert?: boolean;
  alert_created?: boolean;
  message?: string;
};

const API_BASE_URL =
  (import.meta as any).env?.VITE_API_BASE_URL || 'http://127.0.0.1:5000';

function buildAuthedFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  const token = localStorage.getItem('sentinel_auth_token');

  if (token && token !== 'cookie_based') {
    headers.set('Authorization', `Bearer ${token}`);
  }

  return {
    ...init,
    credentials: 'include',
    headers,
  };
}

function formatBytes(bytes?: number) {
  const value = Number(bytes || 0);
  if (value <= 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1
  );

  return `${(value / Math.pow(1024, index)).toFixed(1)} ${units[index]}`;
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

function humanize(value?: string) {
  return String(value || '')
    .replaceAll('_', ' ')
    .replaceAll('-', ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

export function DashboardPage() {
  const { t, isRtl } = useLanguage();

  const [vaultDocs, setVaultDocs] = useState<VaultDocument[]>([]);
  const [vaultLoading, setVaultLoading] = useState(false);
  const [vaultAiLoading, setVaultAiLoading] = useState(false);
  const [vaultAiResult, setVaultAiResult] = useState<VaultAiResult | null>(null);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [lastVaultAnalysisAt, setLastVaultAnalysisAt] = useState<string | null>(null);

  const vaultStorageBytes = useMemo(
    () => vaultDocs.reduce((sum, doc) => sum + Number(doc.size_bytes || 0), 0),
    [vaultDocs]
  );

  const vaultOfflineCount = useMemo(
    () => vaultDocs.filter(doc => Boolean(doc.offline_enabled)).length,
    [vaultDocs]
  );

  const vaultPatterns = useMemo(() => {
    const raw = vaultAiResult?.suspicious_patterns || vaultAiResult?.patterns || [];
    return Array.isArray(raw) ? raw : [];
  }, [vaultAiResult]);

  const vaultRiskScore = Number(vaultAiResult?.risk_score ?? 0);
  const vaultSeverity = String(vaultAiResult?.severity || (vaultRiskScore > 0 ? 'medium' : 'safe'));
  const securityScore = Math.max(0, Math.min(100, 100 - vaultRiskScore));

  const topVaultPattern = vaultPatterns[0];
  const monitoringStatus = vaultAiResult
    ? vaultPatterns.length > 0
      ? `${humanize(vaultSeverity)} risk detected`
      : 'AI monitoring active'
    : 'Awaiting AI analysis';

  const threatData = [
    { name: t('dashboard.threat.malware'), value: 23, color: '#EF4444' },
    { name: t('dashboard.threat.phishing'), value: 31, color: '#F59E0B' },
    { name: t('dashboard.threat.ransomware'), value: 15, color: '#EF4444' },
    { name: t('dashboard.threat.dataBreach'), value: 18, color: '#F97316' },
    { name: t('dashboard.threat.safe'), value: 13, color: '#10B981' },
  ];

  const weeklyStats = [
    { day: t('dashboard.day.mon'), threats: 12, blocked: 11 },
    { day: t('dashboard.day.tue'), threats: 19, blocked: 18 },
    { day: t('dashboard.day.wed'), threats: 15, blocked: 14 },
    { day: t('dashboard.day.thu'), threats: 27, blocked: 25 },
    { day: t('dashboard.day.fri'), threats: 22, blocked: 20 },
    { day: t('dashboard.day.sat'), threats: 8, blocked: 8 },
    { day: t('dashboard.day.sun'), threats: 5, blocked: 5 },
  ];

  const performanceData = [
    { time: '00:00', cpu: 45, memory: 62, network: 30 },
    { time: '04:00', cpu: 52, memory: 68, network: 45 },
    { time: '08:00', cpu: 78, memory: 85, network: 67 },
    { time: '12:00', cpu: 82, memory: 91, network: 78 },
    { time: '16:00', cpu: 75, memory: 88, network: 82 },
    { time: '20:00', cpu: 68, memory: 75, network: 55 },
  ];

  const fetchVaultDocuments = async () => {
    setVaultLoading(true);
    setVaultError(null);

    try {
      const res = await fetch(
        `${API_BASE_URL}/api/documents`,
        buildAuthedFetchInit()
      );

      const data = await res.json().catch(() => []);

      if (!res.ok) {
        throw new Error(data?.error || data?.message || 'Failed to load vault data');
      }

      setVaultDocs(Array.isArray(data) ? data : []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setVaultError(msg);
    } finally {
      setVaultLoading(false);
    }
  };

  const analyzeVaultBehavior = async () => {
    setVaultAiLoading(true);
    setVaultError(null);

    try {
      const res = await fetch(
        `${API_BASE_URL}/api/ai/vault/analyze`,
        buildAuthedFetchInit({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data?.error || data?.message || 'Vault AI analysis failed');
      }

      setVaultAiResult(data);
      setLastVaultAnalysisAt(new Date().toLocaleString());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setVaultError(msg);
    } finally {
      setVaultAiLoading(false);
    }
  };

  useEffect(() => {
    void fetchVaultDocuments();
    void analyzeVaultBehavior();
  }, []);

  return (
    <div className="space-y-6" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white">{t('dashboard.headerTitle')}</h1>
          <p className="text-gray-400 mt-1">{t('dashboard.headerDescription')}</p>
        </div>

        <Button
          onClick={analyzeVaultBehavior}
          disabled={vaultAiLoading}
          className="bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700"
        >
          {vaultAiLoading ? (
            <>
              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              Analyzing Vault...
            </>
          ) : (
            <>
              <Brain className="w-4 h-4 mr-2" />
              Analyze Vault AI
            </>
          )}
        </Button>
      </div>

      {vaultError && (
        <Card className="cyber-card border-red-500/30">
          <CardContent className="py-3 px-4 text-red-200 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            <span>{vaultError}</span>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card className={`cyber-card ${severityBorder(vaultSeverity)}`}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white">AI Security Score</CardTitle>
              <Shield className={`h-4 w-4 ${severityColor(vaultSeverity)}`} />
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${severityColor(vaultSeverity)}`}>
                {securityScore}%
              </div>
              <div className="mt-2">
                <Progress value={securityScore} className="h-2" />
              </div>
              <p className="text-xs text-gray-400 mt-2">
                Vault risk score: {vaultRiskScore}/100
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <NetworkSecurityScoreCard />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className={`cyber-card ${severityBorder(vaultSeverity)}`}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white">AI Monitoring</CardTitle>
              <Eye className={`h-4 w-4 ${severityColor(vaultSeverity)}`} />
            </CardHeader>
            <CardContent>
              <div className={`text-xl font-bold ${severityColor(vaultSeverity)}`}>
                {humanize(vaultSeverity)}
              </div>
              <p className="text-xs text-gray-400 mt-2">{monitoringStatus}</p>
              <p className="text-[11px] text-gray-500 mt-1">
                {lastVaultAnalysisAt ? `Last analysis: ${lastVaultAnalysisAt}` : 'Run analysis to update status'}
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card className="cyber-card border-purple-500/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white">Vault Assets</CardTitle>
              <Lock className="h-4 w-4 text-purple-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-400">
                {vaultLoading ? '--' : vaultDocs.length}
              </div>
              <p className="text-xs text-gray-400 mt-2">
                {formatBytes(vaultStorageBytes)} stored • {vaultOfflineCount} offline
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {vaultAiResult && (
        <Card className={`cyber-card ${severityBorder(vaultSeverity)}`}>
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Brain className={`w-5 h-5 ${severityColor(vaultSeverity)}`} />
              AI Vault Behavior Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
                <p className="text-xs uppercase tracking-wide text-gray-400">Risk Score</p>
                <p className={`text-2xl font-bold mt-2 ${severityColor(vaultSeverity)}`}>
                  {vaultRiskScore}/100
                </p>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
                <p className="text-xs uppercase tracking-wide text-gray-400">Severity</p>
                <p className={`text-2xl font-bold mt-2 ${severityColor(vaultSeverity)}`}>
                  {humanize(vaultSeverity)}
                </p>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
                <p className="text-xs uppercase tracking-wide text-gray-400">Patterns</p>
                <p className="text-2xl font-bold text-white mt-2">{vaultPatterns.length}</p>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
                <p className="text-xs uppercase tracking-wide text-gray-400">AI Alert</p>
                <p className="text-2xl font-bold text-white mt-2">
                  {vaultAiResult.created_alert || vaultAiResult.alert_created ? 'Created' : 'No alert'}
                </p>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-white/10 bg-slate-950/30 p-4">
              <p className="text-sm font-semibold text-white mb-3">Detected Vault Patterns</p>

              {vaultPatterns.length === 0 ? (
                <p className="text-sm text-gray-400">
                  No suspicious vault behavior detected in the latest analysis.
                </p>
              ) : (
                <div className="space-y-2">
                  {vaultPatterns.map((pattern, index) => (
                    <div
                      key={`${pattern.type || pattern.name || 'pattern'}-${index}`}
                      className="flex items-start justify-between gap-3 rounded-lg border border-red-500/20 bg-red-500/5 p-3"
                    >
                      <div>
                        <p className="text-sm font-semibold text-red-100">
                          {humanize(pattern.type || pattern.name || 'Suspicious pattern')}
                        </p>
                        <p className="text-xs text-gray-300 mt-1">
                          {pattern.message || pattern.description || 'Suspicious vault activity was detected.'}
                        </p>
                      </div>
                      <div className="text-xs text-red-200 whitespace-nowrap">
                        Count: {pattern.count ?? 1}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {topVaultPattern && (
                <p className="text-xs text-gray-400 mt-3">
                  Top pattern: {humanize(topVaultPattern.type || topVaultPattern.name)}
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="lg:col-span-2"
        >
          <RecentSecurityAlertsPanel />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white">{t('dashboard.threatDistribution')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatData}
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={80}
                      dataKey="value"
                    >
                      {threatData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: '#ffffff'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="space-y-2 mt-4">
                {threatData.map((item, index) => (
                  <div key={index} className="flex items-center justify-between text-sm">
                    <div className="flex items-center">
                      <div
                        className="w-3 h-3 rounded-full mr-2"
                        style={{ backgroundColor: item.color }}
                      />
                      <span className="text-gray-300">{item.name}</span>
                    </div>
                    <span className="text-white font-medium">{item.value}%</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
        >
          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <TrendingUp className="w-5 h-5 mr-2 text-green-400" />
                {t('dashboard.weeklyThreatStatistics')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={weeklyStats}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="day" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: '#ffffff'
                      }}
                    />
                    <Bar dataKey="threats" fill="#EF4444" name={t('dashboard.threatsDetected')} />
                    <Bar dataKey="blocked" fill="#10B981" name={t('dashboard.threatsBlocked')} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
        >
          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white">{t('dashboard.systemPerformance')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={performanceData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="time" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: '#ffffff'
                      }}
                    />
                    <Line type="monotone" dataKey="cpu" stroke="#3B82F6" name={t('dashboard.cpuPercent')} strokeWidth={2} />
                    <Line type="monotone" dataKey="memory" stroke="#10B981" name={t('dashboard.memoryPercent')} strokeWidth={2} />
                    <Line type="monotone" dataKey="network" stroke="#F59E0B" name={t('dashboard.networkPercent')} strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
