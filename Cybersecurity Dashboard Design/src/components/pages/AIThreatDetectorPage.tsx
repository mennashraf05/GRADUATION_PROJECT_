import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Badge } from '../ui/badge';
import { Progress } from '../ui/progress';
import {
  Brain,
  AlertTriangle,
  Activity,
  TrendingUp,
  Eye,
  Database,
  Zap,
  Shield
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  LineChart,
  Line,
  BarChart,
  Bar,
} from 'recharts';

// ================== Types ==================

type ThreatRisk = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

interface ThreatRow {
  id: string;
  time: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  port: number;
  prediction: string;
  risk: ThreatRisk;
  confidence: number;
  dataset: 'LYCOS-IDS2017' | 'RT_IOT2022' | string;
  blocked?: boolean;
  features?: Record<string, number | string>;
}

interface ModelInfo {
  name: string;
  ok: boolean;
  lastRetrain: string;
  overallAccuracy: number;
  macroF1: number;
  datasetSummary: {
    lycosFlows: number;
    rtIotFlows: number;
  };
}

interface AnomalyPoint {
  time: string;
  benign: number;
  malicious: number;
}

interface LiveThreatPoint {
  time: string;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

interface PipelineResponse {
  metrics?: {
    detected_threats_last_1h?: number;
    high_critical_alerts?: number;
    benign_flows?: number;
  };
  model?: {
    name?: string;
    ok?: boolean;
    last_retrain?: string;
    overall_accuracy?: number;
    macro_f1?: number;
    dataset_summary?: { lycos_flows?: number; rt_iot_flows?: number };
  };
  timeline?: {
    anomaly_series?: AnomalyPoint[];
    live_threat_series?: LiveThreatPoint[];
  };
  threats?: Array<Partial<ThreatRow>>;
}

interface VaultPattern {
  type?: string;
  name?: string;
  title?: string;
  description?: string;
  count?: number;
  severity?: string;
}

interface VaultAIResponse {
  risk_score?: number;
  severity?: string;
  suspicious_patterns?: VaultPattern[];
  patterns?: VaultPattern[];
  created_alert?: boolean;
  alert_created?: boolean;
  message?: string;
  summary?: string;
}

const API_BASE_URL =
  String((import.meta as any).env?.VITE_API_BASE_URL || 'http://127.0.0.1:5000').replace(/\/$/, '');

// -------- Report types --------
interface ReportMetrics {
  labels: string[];
  confusion_matrix: number[][];
  per_class_f1: Record<string, number>;
  overall_accuracy: number;
  macro_f1: number;
}

interface TopAttack {
  label: string;
  count: number;
}

interface ReportStats {
  top_attacks: TopAttack[];
  total_threats: number;
}

interface ReportResponse {
  status: string;
  metrics?: ReportMetrics;
  stats?: ReportStats;
}

// ================== Component ==================

export function AIThreatDetectorPage() {
  // main metrics & states
  const [detectedThreats, setDetectedThreats] = useState<number>(0);
  const [highCriticalAlerts, setHighCriticalAlerts] = useState<number>(0);
  const [benignFlows, setBenignFlows] = useState<number>(0);
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);

  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [anomalySeries, setAnomalySeries] = useState<AnomalyPoint[]>([]);
  const [liveThreatSeries, setLiveThreatSeries] = useState<LiveThreatPoint[]>([]);

  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // UI selection / filters
  const [selectedThreat, setSelectedThreat] = useState<ThreatRow | null>(null);
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);
  const [searchText, setSearchText] = useState<string>('');
  const [selectedAttackType, setSelectedAttackType] = useState<string>('All');
  const [selectedRisks, setSelectedRisks] = useState<Record<ThreatRisk, boolean>>({
    LOW: true,
    MEDIUM: true,
    HIGH: true,
    CRITICAL: true,
  });

  // progress simulation (visual)
  const [progress, setProgress] = useState<number>(0);

  // =========== NEW: tabs + report state ===========
  const [activeTab, setActiveTab] = useState<'overview' | 'report'>('overview');
  const [reportData, setReportData] = useState<ReportResponse | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  // helper: format confidence to percentage
  const formatConfidence = (c: number) => {
    const v = c > 1 ? c : c * 100;
    return `${Math.round(v)}%`;
  };

  // badge colors
  const riskColors: Record<ThreatRisk, string> = {
    LOW: 'bg-green-600/10 text-green-300 border-green-600/20',
    MEDIUM: 'bg-yellow-600/10 text-yellow-300 border-yellow-600/20',
    HIGH: 'bg-orange-600/10 text-orange-300 border-orange-600/20',
    CRITICAL: 'bg-red-600/10 text-red-300 border-red-600/20',
  };

  const getRiskBadge = (risk: ThreatRisk) => (
    <Badge className={`${riskColors[risk] ?? 'bg-gray-600/10 text-gray-300'} px-2 py-0.5`}>
      {risk}
    </Badge>
  );

  // derive attack types from current threats
  const attackTypeOptions = useMemo(() => {
    const setTypes = new Set<string>(threats.map(t => t.prediction));
    return ['All', ...Array.from(setTypes)];
  }, [threats]);

  // filtered threats derived from filters
  const filteredThreats = useMemo(() => {
    return threats.filter(t => {
      if (!selectedRisks[t.risk]) return false;
      if (selectedAttackType !== 'All' && t.prediction !== selectedAttackType) return false;
      if (searchText) {
        const q = searchText.trim();
        if (!t.src_ip.includes(q) && !t.dst_ip.includes(q)) return false;
      }
      return true;
    });
  }, [threats, selectedRisks, selectedAttackType, searchText]);

  // small time formatter
  const formatTime = (isoOrStr: string) => {
    try {
      const d = new Date(isoOrStr);
      if (!isNaN(d.getTime())) {
        return d.toLocaleString();
      }
    } catch {
      // ignore
    }
    return isoOrStr;
  };

  // Runs the full AI threat analysis pipeline
  const handleRunThreatPipeline = async () => {
    setIsRunning(true);
    setError(null);
    setProgress(6);
    try {
      const res = await fetch(`${API_BASE_URL}/threat/run-pipeline`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || res.statusText || 'Pipeline request failed');
      }
      setProgress(20);
      const data: PipelineResponse = await res.json();
      setProgress(45);

      // metrics
      setDetectedThreats(data.metrics?.detected_threats_last_1h ?? 0);
      setHighCriticalAlerts(data.metrics?.high_critical_alerts ?? 0);
      setBenignFlows(data.metrics?.benign_flows ?? 0);

      setProgress(65);

      // model info mapping
      if (data.model) {
        setModelInfo({
          name: data.model.name ?? 'Unknown',
          ok: !!data.model.ok,
          lastRetrain: data.model.last_retrain ?? '',
          overallAccuracy: data.model.overall_accuracy ?? 0,
          macroF1: data.model.macro_f1 ?? 0,
          datasetSummary: {
            lycosFlows: data.model.dataset_summary?.lycos_flows ?? 0,
            rtIotFlows: data.model.dataset_summary?.rt_iot_flows ?? 0,
          },
        });
      } else {
        setModelInfo(null);
      }

      setProgress(80);

      // timeline charts
      setAnomalySeries(data.timeline?.anomaly_series ?? []);
      setLiveThreatSeries(data.timeline?.live_threat_series ?? []);

      setProgress(90);

      // threats list mapping
      if (Array.isArray(data.threats)) {
        const mapped = data.threats.map((t): ThreatRow => ({
          id: String(t.id ?? `${Math.random()}`),
          time: t.time ?? new Date().toISOString(),
          src_ip: (t as any).src_ip ?? (t as any).srcIP ?? '',
          dst_ip: (t as any).dst_ip ?? (t as any).dstIP ?? '',
          protocol: (t as any).protocol ?? (t as any).proto ?? 'tcp',
          port: (t as any).port ?? 0,
          prediction: (t as any).prediction ?? 'Unknown',
          risk: ((t as any).risk ?? 'LOW') as ThreatRisk,
          confidence: (t as any).confidence ?? 0,
          dataset: (t as any).dataset ?? 'Unknown',
          features: (t as any).features ?? undefined,
          blocked: (t as any).blocked ?? false,
        }));
        setThreats(mapped);
      } else {
        setThreats([]);
      }

      setLastUpdated(new Date().toLocaleString());
      setProgress(100);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg || 'Unknown error');
      setProgress(0);
    } finally {
      setTimeout(() => {
        setIsRunning(false);
        setProgress(0);
      }, 700);
    }
  };

  // close details panel
  const closeDetails = () => {
    setSelectedThreat(null);
    setDrawerOpen(false);
  };

  // insight bullets generator (simple heuristics)
  const generateInsights = (t: ThreatRow) => {
    const bullets: string[] = [];
    const pred = t.prediction.toLowerCase();
    if (pred.includes('ddos') || pred.includes('dos')) {
      bullets.push('Very high packet rate suggests volumetric attack (DDoS).');
      bullets.push('Minimal response bytes indicate victim saturation.');
    } else if (pred.includes('portscan') || pred.includes('scan')) {
      bullets.push('Multiple target ports probed in short timeframe.');
      bullets.push('Short-lived connections with many distinct destination ports.');
    } else if (pred.includes('brute') || pred.includes('force')) {
      bullets.push('Repeated login attempts pattern detected.');
      bullets.push('High number of small requests to authentication endpoints.');
    } else {
      bullets.push('Pattern deviates from normal baseline — suspicious activity.');
      bullets.push('Check session duration and payload sizes for anomalies.');
    }
    return bullets;
  };

  // auto-hide error
  useEffect(() => {
    if (error) {
      const id = setTimeout(() => setError(null), 8000);
      return () => clearTimeout(id);
    }
    return;
  }, [error]);

  // =========== NEW: load report when switching tab ===========
  const loadReport = async () => {
    setReportLoading(true);
    setReportError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/threat/report`);
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || res.statusText || 'Report request failed');
      }
      const data: ReportResponse = await res.json();
      setReportData(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setReportError(msg);
    } finally {
      setReportLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'report' && !reportData && !reportLoading) {
      loadReport();
    }
  }, [activeTab]); // intentionally not adding loadReport/reportData in deps

  // derived data for report tab
  const confusionLabels = reportData?.metrics?.labels ?? [];
  const confusionMatrix = reportData?.metrics?.confusion_matrix ?? [];
  const topAttacks = reportData?.stats?.top_attacks ?? [];
  const totalThreatsLogged = reportData?.stats?.total_threats ?? 0;

  const f1ChartData = useMemo(() => {
    const perClass = reportData?.metrics?.per_class_f1;
    if (!perClass) return [];
    return Object.entries(perClass).map(([label, f1]) => ({
      label,
      f1: Math.round(((f1 as number) ?? 0) * 100),
    }));
  }, [reportData]);

  // ================== JSX ==================
  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
        <Card className="cyber-card border-indigo-500/30 overflow-hidden relative">
          <div className="absolute inset-0 bg-gradient-to-r from-[#0f172a] via-[#111827] to-[#0b1224] opacity-80" />
          <CardContent className="relative p-6">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-indigo-500 to-blue-500 flex items-center justify-center shadow-lg shadow-indigo-500/25">
                  <Brain className="w-7 h-7 text-white" />
                </div>
                <div>
                  <h1 className="text-3xl font-bold text-white">AI Threat Detector</h1>
                  <p className="text-gray-400 mt-1">
                    Advanced machine learning threat detection and analysis
                  </p>
                  <p className="text-xs text-indigo-200/80 mt-2 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-indigo-300" />
                    <span>
                      Real-time monitoring • Updated {lastUpdated ? lastUpdated : 'just now'}
                    </span>
                  </p>
                  {modelInfo && (
                    <div className="mt-2 text-xs text-gray-300">
                      Model:{' '}
                      <span className={modelInfo.ok ? 'text-green-300' : 'text-red-300'}>
                        {modelInfo.name}
                      </span>
                      <span className="ml-2">• Last retrain: {modelInfo.lastRetrain}</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <Button
                  onClick={handleRunThreatPipeline}
                  disabled={isRunning}
                  className="bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 shadow-lg shadow-indigo-500/30"
                >
                  {isRunning ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                      Running...
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4 mr-2" />
                      Run AI Threat Pipeline
                    </>
                  )}
                </Button>
              </div>
            </div>

            {isRunning && (
              <div className="mt-4">
                <Progress value={progress} className="h-2 rounded" />
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* error banner */}
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <Card className="cyber-card border-red-600/20">
            <CardContent className="py-3 px-4 flex items-center justify-between text-red-200">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5" />
                <span>Failed to run AI threat pipeline: {error}</span>
              </div>
              <div>
                <Button size="sm" variant="ghost" onClick={() => setError(null)}>
                  Dismiss
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {vaultAnalysisError && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <Card className="cyber-card border-yellow-600/20">
            <CardContent className="py-3 px-4 flex items-center justify-between text-yellow-100">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5" />
                <span>Vault AI analysis failed: {vaultAnalysisError}</span>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setVaultAnalysisError(null)}>
                Dismiss
              </Button>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {vaultAnalysis && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="cyber-card border-cyan-500/30 bg-[#0f172a]/70">
            <CardHeader>
              <CardTitle className="text-white flex items-center justify-between gap-3">
                <span className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-cyan-300" />
                  Vault AI Behavior Analysis
                </span>
                <Badge className={getVaultSeverityBadgeClass(vaultAnalysis.severity)}>
                  {String(vaultAnalysis.severity || 'LOW').toUpperCase()}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
                  <p className="text-gray-400 text-sm">Vault Risk Score</p>
                  <p className="text-3xl font-bold text-white mt-1">
                    {vaultAnalysis.risk_score ?? 0}
                    <span className="text-sm text-gray-400"> / 100</span>
                  </p>
                </div>

                <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
                  <p className="text-gray-400 text-sm">AI Alert Created</p>
                  <p className="text-2xl font-bold text-white mt-1">
                    {vaultAnalysis.created_alert || vaultAnalysis.alert_created ? 'Yes' : 'No'}
                  </p>
                </div>

                <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
                  <p className="text-gray-400 text-sm">Detected Patterns</p>
                  <p className="text-2xl font-bold text-white mt-1">
                    {(vaultAnalysis.suspicious_patterns || vaultAnalysis.patterns || []).length}
                  </p>
                </div>
              </div>

              <p className="text-sm text-gray-300 mt-4">
                {vaultAnalysis.summary || vaultAnalysis.message || 'Vault behavior was analyzed using recent activity logs.'}
              </p>

              <div className="mt-4 space-y-2">
                {(vaultAnalysis.suspicious_patterns || vaultAnalysis.patterns || []).length === 0 ? (
                  <div className="text-sm text-gray-400 rounded-lg border border-gray-700/60 p-3">
                    No suspicious Vault patterns were detected in the selected activity window.
                  </div>
                ) : (
                  (vaultAnalysis.suspicious_patterns || vaultAnalysis.patterns || []).map((pattern, index) => (
                    <div
                      key={`${pattern.type || pattern.name || index}`}
                      className="rounded-lg border border-cyan-500/15 bg-[#0b1224] p-3"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-white font-medium">
                          {pattern.title || pattern.name || pattern.type || `Pattern ${index + 1}`}
                        </p>
                        {typeof pattern.count === 'number' && (
                          <Badge className="bg-cyan-600/10 text-cyan-200 border-cyan-600/20">
                            {pattern.count} events
                          </Badge>
                        )}
                      </div>
                      {pattern.description && (
                        <p className="text-sm text-gray-400 mt-1">{pattern.description}</p>
                      )}
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Tabs: Overview / Report */}
      <div className="mt-2 flex items-center gap-4 border-b border-gray-800/70 pb-2">
        <button
          className={`text-sm px-3 py-1 rounded-t-md ${
            activeTab === 'overview'
              ? 'text-white border-b-2 border-indigo-500'
              : 'text-gray-400 hover:text-gray-200'
          }`}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button
          className={`text-sm px-3 py-1 rounded-t-md ${
            activeTab === 'report'
              ? 'text-white border-b-2 border-indigo-500'
              : 'text-gray-400 hover:text-gray-200'
          }`}
          onClick={() => setActiveTab('report')}
        >
          Report
        </button>
      </div>

      {/* ================= OVERVIEW TAB ================= */}
      {activeTab === 'overview' && (
        <>
          {/* Metric cards */}
 {/* === TOP METRICS (3 CARDS فقط) === */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Detected Threats */}
        <Card className="cyber-card border border-red-600/20 bg-[#0f172a]/60 rounded-2xl">
  <CardContent className="px-6 py-5 flex items-center justify-between">
    <div className="space-y-1">
              <p className="text-gray-400 text-sm">Detected Threats (Last 1h)</p>
              <p className="text-2xl font-bold text-white">{detectedThreats}</p>
              <span className="inline-flex text-xs px-2 py-1 rounded-md bg-red-500/10 text-red-200">
                Live
              </span>
            </div>
            <div className="w-12 h-12 rounded-xl bg-[#0b1224] border border-white/5 flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-red-400" />
            </div>
          </CardContent>
        </Card>

        {/* High / Critical Alerts */}
       <Card className="cyber-card border border-red-600/20 bg-[#0f172a]/60 rounded-2xl">
  <CardContent className="px-6 py-5 flex items-center justify-between">
     <div className="space-y-1">
              <p className="text-gray-400 text-sm">High / Critical Alerts</p>
              <p className="text-2xl font-bold text-white">{highCriticalAlerts}</p>
              <span className="inline-flex text-xs px-2 py-1 rounded-md bg-orange-500/10 text-orange-200">
                Live
              </span>
            </div>
            <div className="w-12 h-12 rounded-xl bg-[#0b1224] border border-white/5 flex items-center justify-center">
              <Shield className="w-6 h-6 text-orange-400" />
            </div>
          </CardContent>
        </Card>

        {/* Benign Flows */}
       <Card className="cyber-card border border-red-600/20 bg-[#0f172a]/60 rounded-2xl">
  <CardContent className="px-6 py-5 flex items-center justify-between">
      <div className="space-y-1">
              <p className="text-gray-400 text-sm">Benign Flows</p>
              <p className="text-2xl font-bold text-white">{benignFlows}</p>
              <span className="inline-flex text-xs px-2 py-1 rounded-md bg-blue-500/10 text-blue-200">
                Live
              </span>
            </div>
            <div className="w-12 h-12 rounded-xl bg-[#0b1224] border border-white/5 flex items-center justify-center">
              <Database className="w-6 h-6 text-blue-400" />
            </div>
          </CardContent>
        </Card>
      </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <Card className="cyber-card">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    <Activity className="w-5 h-5 text-indigo-400" />
                    Anomaly Detection
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-64">
                    {anomalySeries.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-gray-400">
                        No anomaly data yet — run "Run AI Threat Pipeline" to populate this chart.
                      </div>
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={anomalySeries}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="time" stroke="#94a3b8" />
                          <YAxis
                            tickLine={false}
                            axisLine={false}
                            tick={{ fontSize: 12, fill: "#94a3b8" }}
                            domain={['auto', 'auto']} // أو domain={[0, 'dataMax + 2']}
                          />

                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#0f172a',
                              border: '1px solid #1f2937',
                              borderRadius: 8,
                              color: '#fff',
                            }}
                          />
                          <Area
                            type="monotone"
                            dataKey="benign"
                            stackId="1"
                            stroke="#0EA5E9"
                            fill="#0EA5E9"
                            fillOpacity={0.25}
                            name="Benign"
                          />
                          <Area
                            type="monotone"
                            dataKey="malicious"
                            stackId="1"
                            stroke="#EF4444"
                            fill="#EF4444"
                            fillOpacity={0.25}
                            name="Malicious"
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>

            <div>
              <Card className="cyber-card">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    <TrendingUp className="w-5 h-5 text-purple-400" />
                    Live Threats
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-64">
                    {liveThreatSeries.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-gray-400">
                        No live threat timeline — run "Run AI Threat Pipeline" to populate this chart.
                      </div>
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={liveThreatSeries}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="time" stroke="#94a3b8" />
                          <YAxis
                           tickLine={false}
                            axisLine={false}
                            tick={{ fontSize: 12, fill: "#94a3b8" }}
                            domain={['auto', 'auto']} // أو domain={[0, 'dataMax + 2']}
                          />

                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#0f172a',
                              border: '1px solid #1f2937',
                              borderRadius: 8,
                              color: '#fff',
                            }}
                          />
                          <Line type="monotone" dataKey="low" stroke="#34D399" strokeWidth={2} dot={false} name="Low" />
                          <Line
                            type="monotone"
                            dataKey="medium"
                            stroke="#FBBF24"
                            strokeWidth={2}
                            dot={false}
                            name="Medium"
                          />
                          <Line
                            type="monotone"
                            dataKey="high"
                            stroke="#FB923C"
                            strokeWidth={2}
                            dot={false}
                            name="High"
                          />
                          <Line
                            type="monotone"
                            dataKey="critical"
                            stroke="#EF4444"
                            strokeWidth={2}
                            dot={false}
                            name="Critical"
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Filters + Live Threat Table */}
          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Brain className="w-5 h-5 text-indigo-400" /> Live Threat Table
                </span>

                <div className="flex items-center gap-3">
                  <input
                    className="px-3 py-1 rounded bg-[#0b1224] text-gray-200"
                    placeholder="Search IP..."
                    value={searchText}
                    onChange={e => setSearchText(e.target.value)}
                  />
                  <select
                    className="px-3 py-1 rounded bg-[#0b1224] text-gray-200"
                    value={selectedAttackType}
                    onChange={e => setSelectedAttackType(e.target.value)}
                  >
                    {attackTypeOptions.map(a => (
                      <option key={a} value={a}>
                        {a}
                      </option>
                    ))}
                  </select>
                  <div className="flex items-center gap-2 text-sm text-gray-300">
                    {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as ThreatRisk[]).map(r => (
                      <label key={r} className="inline-flex items-center gap-1">
                        <input
                          type="checkbox"
                          checked={!!selectedRisks[r]}
                          onChange={() =>
                            setSelectedRisks(prev => ({
                              ...prev,
                              [r]: !prev[r],
                            }))
                          }
                        />
                        <span className="ml-1">{r}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </CardTitle>
            </CardHeader>

            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow className="border-gray-700">
                    <TableHead className="text-gray-300">Time</TableHead>
                    <TableHead className="text-gray-300">Source IP</TableHead>
                    <TableHead className="text-gray-300">Destination IP</TableHead>
                    <TableHead className="text-gray-300">Protocol / Port</TableHead>
                    <TableHead className="text-gray-300">Prediction</TableHead>
                    <TableHead className="text-gray-300">Risk</TableHead>
                    <TableHead className="text-gray-300">Confidence</TableHead>
                    <TableHead className="text-gray-300">Data Source</TableHead>
                    <TableHead className="text-gray-300">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredThreats.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="text-center text-gray-400 py-8">
                        No live threats — run "Run AI Threat Pipeline" to simulate or start receiving events.
                      </td>
                    </tr>
                  ) : (
                    filteredThreats.map((t, i) => (
                      <motion.tr
                        key={t.id}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.03 * i }}
                        className="hover:bg-gray-800/40"
                      >
                        <TableCell className="text-white text-sm">{formatTime(t.time)}</TableCell>
                        <TableCell className="text-gray-200 font-mono text-sm">{t.src_ip}</TableCell>
                        <TableCell className="text-gray-200 font-mono text-sm">{t.dst_ip}</TableCell>
                        <TableCell className="text-gray-200 text-sm">
                          {t.protocol.toUpperCase()} / {t.port}
                        </TableCell>
                        <TableCell className="text-white text-sm font-medium">{t.prediction}</TableCell>
                        <TableCell>{getRiskBadge(t.risk)}</TableCell>
                        <TableCell
                          className={`font-medium ${
                            (t.confidence > 1 ? t.confidence : t.confidence * 100) >= 90
                              ? 'text-green-400'
                              : (t.confidence > 1 ? t.confidence : t.confidence * 100) >= 70
                              ? 'text-yellow-400'
                              : 'text-red-400'
                          }`}
                        >
                          {formatConfidence(t.confidence)}
                        </TableCell>
                        <TableCell className="text-gray-400 text-sm">{t.dataset}</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => {
                                setSelectedThreat(t);
                                setDrawerOpen(true);
                              }}
                              className="text-blue-400 border-blue-400/30 hover:bg-blue-400/10"
                            >
                              <Eye className="w-3 h-3 mr-1" />
                              View
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={t.blocked}
                              onClick={() => {
                                setThreats(prev =>
                                  prev.map(x =>
                                    x.id === t.id ? { ...x, blocked: true } : x,
                                  ),
                                );
                              }}
                              className={`border-red-400/30 hover:bg-red-400/10 ${
                                t.blocked ? 'text-red-200 opacity-60 cursor-default' : 'text-red-400'
                              }`}
                            >
                              <Shield className="w-3 h-3 mr-1" />
                              {t.blocked ? 'Blocked' : 'Block'}
                            </Button>
                          </div>
                        </TableCell>
                      </motion.tr>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Threat Details Drawer */}
         {/* Threat Details Drawer */}
{drawerOpen && selectedThreat && (
  <>
    {/* خلفية غامقة تغطي الصفحة */}
    <div
      className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40"
      onClick={closeDetails}
    />

    {/* البوكس نفسه */}
    <div className="fixed right-4 top-16 w-96 h-[80vh] bg-slate-950 border border-gray-700 rounded-xl shadow-lg p-4 z-50 overflow-auto">
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-white font-semibold text-lg">Threat Details</h3>
          <p className="text-gray-400 text-sm mt-1">
            {selectedThreat.prediction} • {selectedThreat.dataset}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={closeDetails}>
            Close
          </Button>
        </div>
      </div>

      <div className="mt-3 space-y-3">
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
          <div>
            <div className="text-gray-400 text-xs">Time</div>
            <div className="text-gray-200">{formatTime(selectedThreat.time)}</div>
          </div>
          <div>
            <div className="text-gray-400 text-xs">Risk</div>
            <div className="mt-1">{getRiskBadge(selectedThreat.risk)}</div>
          </div>
          <div>
            <div className="text-gray-400 text-xs">Source IP</div>
            <div className="text-gray-200 font-mono">{selectedThreat.src_ip}</div>
          </div>
          <div>
            <div className="text-gray-400 text-xs">Destination IP</div>
            <div className="text-gray-200 font-mono">{selectedThreat.dst_ip}</div>
          </div>
          <div>
            <div className="text-gray-400 text-xs">Protocol / Port</div>
            <div className="text-gray-200">
              {selectedThreat.protocol.toUpperCase()} / {selectedThreat.port}
            </div>
          </div>
          <div>
            <div className="text-gray-400 text-xs">Confidence</div>
            <div className="text-green-400 font-semibold">
              {formatConfidence(selectedThreat.confidence)}
            </div>
          </div>
          <div>
            <div className="text-gray-400 text-xs">Dataset</div>
            <div className="text-gray-300">{selectedThreat.dataset}</div>
          </div>
          <div>
            <div className="text-gray-400 text-xs">Blocked</div>
            <div className="text-gray-200">
              {selectedThreat.blocked ? 'Yes' : 'No'}
            </div>
          </div>
        </div>

        <div className="pt-3 border-t border-gray-800 mt-2">
          <h4 className="text-white text-sm font-semibold mb-1">AI Insight</h4>
          <ul className="list-disc list-inside text-xs text-gray-300 space-y-1">
            {generateInsights(selectedThreat).map((b, idx) => (
              <li key={idx}>{b}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  </>
)}
        </>
      )}
      {/* ================= REPORT TAB ================= */}
      {activeTab === 'report' && (
        <div className="mt-4 grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Left side: confusion matrix + F1 chart */}
          <div className="xl:col-span-2 space-y-6">
            <Card className="cyber-card">
              <CardHeader>
                <CardTitle className="text-white text-sm flex items-center gap-2">
                  <Brain className="w-4 h-4 text-indigo-400" />
                  Model Performance (Test Set)
                </CardTitle>
              </CardHeader>
              <CardContent>
                {reportLoading && (
                  <div className="h-40 flex items-center justify-center text-gray-400">
                    Loading report...
                  </div>
                )}
                {reportError && (
                  <div className="text-red-300 text-sm">
                    Failed to load report: {reportError}
                  </div>
                )}
                {!reportLoading && !reportError && confusionMatrix.length > 0 && (
                  <div className="space-y-4">
                    <div className="overflow-x-auto">
                      <table className="min-w-full text-xs text-gray-200">
                        <thead>
                          <tr>
                            <th className="p-2 text-left text-gray-400">
                              Actual \\ Predicted
                            </th>
                            {confusionLabels.map(lbl => (
                              <th
                                key={lbl}
                                className="p-2 text-center text-gray-300"
                              >
                                {lbl}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {confusionMatrix.map((row, i) => (
                            <tr
                              key={confusionLabels[i] ?? i}
                              className="border-t border-gray-800"
                            >
                              <td className="p-2 text-gray-300 font-medium">
                                {confusionLabels[i] ?? i}
                              </td>
                              {row.map((val, j) => (
                                <td key={j} className="p-2 text-center">
                                  <span className="inline-flex px-2 py-1 rounded bg-slate-900/70">
                                    {val}
                                  </span>
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <p className="text-[11px] text-gray-400">
                      Based on the held-out test set (LYCOS-IDS2017 + RT_IOT2022).
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="cyber-card">
              <CardHeader>
                <CardTitle className="text-white text-sm">
                  Per-Class F1 Score
                </CardTitle>
              </CardHeader>
              <CardContent>
                {f1ChartData.length === 0 ? (
                  <div className="h-48 flex items-center justify-center text-gray-400">
                    No F1 data available yet. Train the model first.
                  </div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                     <BarChart data={f1ChartData}>
  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
  <XAxis dataKey="label" stroke="#94a3b8" tick={{ fontSize: 11 }} />
  <YAxis
    stroke="#94a3b8"
    domain={[0, 100]}           // 🟢 مهم: من 0 لـ 100 %
  />
  <Tooltip
    contentStyle={{
      backgroundColor: '#0f172a',
      border: '1px solid #1f2937',
      borderRadius: 8,
      color: '#fff',
    }}
    formatter={(value) => [`${value}%`, 'F1']}
  />
  <Bar dataKey="f1" name="F1 (%)" />
</BarChart>

                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Right side: top attacks from logged pipeline runs */}
          <div className="space-y-6">
            <Card className="cyber-card">
              <CardHeader>
                <CardTitle className="text-white text-sm">
                  Top Attack Types (Logged)
                </CardTitle>
              </CardHeader>
              <CardContent>
                {topAttacks.length === 0 ? (
                  <div className="h-40 flex items-center justify-center text-gray-400">
                    No threats logged yet. Run the AI Threat Pipeline to generate data.
                  </div>
                ) : (
                  <div className="space-y-3">
                    <p className="text-xs text-gray-400">
                      Total logged threats:{' '}
                      <span className="text-indigo-300">{totalThreatsLogged}</span>
                    </p>
                    <ul className="space-y-2 text-sm">
                      {topAttacks.map((t, idx) => (
                        <li
                          key={t.label}
                          className="flex items-center justify-between border-b border-gray-800/80 pb-1"
                        >
                          <span className="text-gray-200">
                            {idx + 1}. <span className="font-medium">{t.label}</span>
                          </span>
                          <span className="text-indigo-300 font-mono">
                            {t.count} flows
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      )}

    </div>
  );
}
