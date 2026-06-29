import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clipboard,
  Download,
  Eye,
  FileText,
  Filter,
  Lock,
  RefreshCw,
  Search,
  ShieldAlert,
  Sliders,
  UserCog,
  XCircle,
} from 'lucide-react';
import { toast } from 'sonner@2.0.3';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '../ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';

const API_BASE_URL =
  import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');

function normalizeApiBase(value: string) {
  return value.trim().replace(/\/+$/, '');
}

function pushAuditApiCandidate(candidates: string[], value: string) {
  const normalized = normalizeApiBase(value);
  if (value === '') {
    if (!candidates.includes('')) candidates.push('');
    return;
  }
  if (normalized && !candidates.includes(normalized)) {
    candidates.push(normalized);
  }
}

function auditApiCandidates() {
  const candidates: string[] = [];
  pushAuditApiCandidate(candidates, API_BASE_URL);
  pushAuditApiCandidate(candidates, String(import.meta.env.VITE_API_BASE_URL || ''));

  if (typeof window !== 'undefined') {
    const { protocol, hostname } = window.location;
    if (hostname) {
      pushAuditApiCandidate(candidates, `${protocol}//${hostname}:5000`);
      pushAuditApiCandidate(candidates, `http://${hostname}:5000`);
    }
  }

  pushAuditApiCandidate(candidates, 'http://127.0.0.1:5000');
  pushAuditApiCandidate(candidates, 'http://localhost:5000');
  return candidates;
}

async function fetchAuditResponse(queryString: string, token: string | null) {
  let lastError: unknown = null;
  const isValidationLabFilter = new URLSearchParams(queryString).get('module') === 'validation_lab';

  for (const base of auditApiCandidates()) {
    try {
      const response = await fetch(`${base}/api/admin/audit-logs?${queryString}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const contentType = String(response.headers.get('content-type') || '').toLowerCase();
      if (contentType.includes('text/html')) {
        continue;
      }
      const payload = (await response.json().catch(() => ({}))) as Partial<AuditResponse> & {
        message?: string;
      };
      if (!response.ok) {
        throw new Error(payload.message || 'Audit trail could not be loaded. Please refresh or check the backend connection.');
      }
      const total = Number(payload.total ?? 0);
      if (isValidationLabFilter && total === 0 && base === '' && auditApiCandidates().length > 1) {
        continue;
      }
      return payload;
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error('Audit trail could not be loaded. Please refresh or check the backend connection.');
}

type AuditStatus = 'success' | 'failed' | 'warning' | 'skipped';
type AuditSeverity = 'low' | 'medium' | 'high' | 'critical';

interface AdminAuditItem {
  id: string;
  actor_name: string;
  actor_email: string;
  actor_role: string;
  action_type: string;
  action_label: string;
  module: string;
  module_label?: string;
  target_type: string;
  target_id: string;
  target_label: string;
  status: AuditStatus;
  severity: AuditSeverity;
  ip_address: string;
  user_agent: string;
  metadata: Record<string, unknown>;
  created_at: string | null;
}

interface AuditSummary {
  total_events: number;
  successful_events: number;
  failed_events: number;
  high_risk_events: number;
  critical_events: number;
  unique_admins: number;
}

interface AuditResponse {
  items: AdminAuditItem[];
  total: number;
  page: number;
  limit: number;
  summary: AuditSummary;
  filter_options?: {
    action_types?: AuditFilterOption[];
    modules?: AuditFilterOption[];
  };
}

interface AuditFilterOption {
  value: string;
  label: string;
}

const EMPTY_SUMMARY: AuditSummary = {
  total_events: 0,
  successful_events: 0,
  failed_events: 0,
  high_risk_events: 0,
  critical_events: 0,
  unique_admins: 0,
};

const REAL_ADMIN_MODULE_OPTIONS: AuditFilterOption[] = [
  { value: 'admin_authentication', label: 'Admin Authentication' },
  { value: 'users_roles', label: 'Users & Roles' },
  { value: 'threat_management', label: 'Threat Management' },
  { value: 'pcap_analysis', label: 'PCAP Analysis' },
  { value: 'validation_lab', label: 'Validation Lab' },
  { value: 'admin_audit', label: 'Admin Audit Trail' },
  { value: 'notifications', label: 'Notifications' },
  { value: 'reports_center', label: 'Reports Center' },
  { value: 'settings', label: 'Settings' },
  { value: 'password_checker', label: 'Password Checker' },
  { value: 'phishing_scanner', label: 'Phishing Scanner' },
  { value: 'file_vault', label: 'File Vault' },
  { value: 'identity_leak', label: 'Identity Leak Monitor' },
];

const MODULE_LABELS_BY_KEY: Record<string, string> = {
  admin_authentication: 'Admin Authentication',
  admin_auth: 'Admin Authentication',
  authentication: 'Admin Authentication',
  auth: 'Admin Authentication',
  users_roles: 'Users & Roles',
  users_and_roles: 'Users & Roles',
  threat_management: 'Threat Management',
  threats: 'Threat Management',
  pcap_analysis: 'PCAP Analysis',
  pcap_analyzer: 'PCAP Analysis',
  pcap: 'PCAP Analysis',
  validation_lab: 'Validation Lab',
  security_validation_lab: 'Validation Lab',
  security_lab: 'Validation Lab',
  admin_audit: 'Admin Audit Trail',
  admin_audit_trail: 'Admin Audit Trail',
  audit: 'Admin Audit Trail',
  notifications: 'Notifications',
  reports_center: 'Reports Center',
  reports_exports: 'Reports Center',
  reports: 'Reports Center',
  settings: 'Settings',
  password_checker: 'Password Checker',
  password: 'Password Checker',
  phishing_scanner: 'Phishing Scanner',
  phishing: 'Phishing Scanner',
  file_vault: 'File Vault',
  vault: 'File Vault',
  encrypted_file_vault: 'File Vault',
  identity_leak: 'Identity Leak Monitor',
  identity: 'Identity Leak Monitor',
  identity_monitor: 'Identity Leak Monitor',
  identity_leak_monitor: 'Identity Leak Monitor',
  osint_monitor: 'Identity Leak Monitor',
};

function normalizeModuleKey(value: string) {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

function cleanReadableLabel(value: string) {
  const cleaned = value.trim().replace(/[_-]+/g, ' ');
  return cleaned ? cleaned.replace(/\b\w/g, (letter) => letter.toUpperCase()) : 'Unknown Module';
}

function getAuditModuleLabel(moduleValue: string, explicitLabel?: string) {
  if (explicitLabel?.trim()) return explicitLabel.trim();
  const key = normalizeModuleKey(moduleValue || '');
  return MODULE_LABELS_BY_KEY[key] || cleanReadableLabel(moduleValue || '');
}

function normalizeFilterOptions(options: AuditFilterOption[] | undefined) {
  const seen = new Set<string>();
  return (options || [])
    .filter((option) => option?.value?.trim())
    .map((option) => ({ value: option.value.trim(), label: (option.label || option.value).trim() }))
    .filter((option) => {
      const key = option.value.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function getAdminInitials(name: string, email: string) {
  const source = name || email || 'Admin';
  return (
    source
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase() || '')
      .join('') || 'AD'
  );
}

function formatRelativeTime(value: string | null) {
  if (!value) return 'Unknown';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return 'Unknown';
  const minutes = Math.max(0, Math.floor((Date.now() - parsed.getTime()) / 60000));
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function statusClass(status: string) {
  if (status === 'success') return 'border-emerald-400/40 bg-emerald-500/15 text-emerald-200';
  if (status === 'failed') return 'border-rose-400/40 bg-rose-500/15 text-rose-200';
  if (status === 'skipped') return 'border-slate-400/40 bg-slate-500/15 text-slate-200';
  return 'border-amber-400/40 bg-amber-500/15 text-amber-200';
}

function severityClass(severity: string) {
  if (severity === 'critical') return 'border-red-400/40 bg-red-500/15 text-red-200';
  if (severity === 'high') return 'border-orange-400/40 bg-orange-500/15 text-orange-200';
  if (severity === 'medium') return 'border-blue-400/40 bg-blue-500/15 text-blue-200';
  return 'border-cyan-400/40 bg-cyan-500/15 text-cyan-200';
}

function moduleClass(module: string) {
  if (module.includes('PCAP')) return 'border-cyan-400/30 bg-cyan-500/12 text-cyan-100';
  if (module.includes('Phishing')) return 'border-sky-400/30 bg-sky-500/12 text-sky-100';
  if (module.includes('Users')) return 'border-blue-400/30 bg-blue-500/12 text-blue-100';
  if (module.includes('Threat')) return 'border-orange-400/30 bg-orange-500/12 text-orange-100';
  return 'border-slate-500/30 bg-slate-500/12 text-slate-100';
}

function buildAuditEventScope(item: AdminAuditItem) {
  return item.target_type || item.module || 'Admin event';
}

function buildSafeAuditEventJson(item: AdminAuditItem) {
  const { target_id: _targetId, target_label: _targetLabel, ...safeEvent } = item;
  return {
    ...safeEvent,
    event_scope: buildAuditEventScope(item),
    privacy_note: 'Target identifiers are hidden from the admin audit view.',
  };
}

export default function AdminAuditTrailPage() {
  const [items, setItems] = useState<AdminAuditItem[]>([]);
  const [summary, setSummary] = useState<AuditSummary>(EMPTY_SUMMARY);
  const [selectedEvent, setSelectedEvent] = useState<AdminAuditItem | null>(null);
  const [isDetailsOpen, setIsDetailsOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState('');
  const [actionTypeOptions, setActionTypeOptions] = useState<AuditFilterOption[]>([]);
  const [moduleOptions, setModuleOptions] = useState<AuditFilterOption[]>(REAL_ADMIN_MODULE_OPTIONS);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState({
    search: '',
    action_type: 'all',
    module: 'all',
    status: 'all',
    severity: 'all',
    start_date: '',
    end_date: '',
  });
  const limit = 20;

  const queryString = useMemo(() => {
    const query = new URLSearchParams();
    query.set('page', String(page));
    query.set('limit', String(limit));
    Object.entries(filters).forEach(([key, value]) => {
      if (value && value !== 'all') query.set(key, value);
    });
    return query.toString();
  }, [filters, page]);

  const loadAuditLogs = async () => {
    setLoading(true);
    setError('');
    const token = localStorage.getItem('sentinel_admin_token');
    try {
      const payload = await fetchAuditResponse(queryString, token);
      const nextItems = Array.isArray(payload.items) ? payload.items : [];
      const nextActionOptions = normalizeFilterOptions(payload.filter_options?.action_types);
      const nextModuleOptions = normalizeFilterOptions(payload.filter_options?.modules);
      setActionTypeOptions(nextActionOptions.length ? nextActionOptions : normalizeFilterOptions(
        nextItems.map((item) => ({ value: item.action_type, label: item.action_type.replaceAll('_', ' ') }))
      ));
      if (payload.filter_options) {
        setModuleOptions(nextModuleOptions);
      } else {
        setModuleOptions(REAL_ADMIN_MODULE_OPTIONS);
      }
      setItems(nextItems);
      setSummary(payload.summary || EMPTY_SUMMARY);
      setTotal(Number(payload.total || nextItems.length));
      setSelectedEvent((current) => nextItems.find((item) => item.id === current?.id) || nextItems[0] || null);
    } catch (loadError) {
      setError('Audit trail could not be loaded. Please refresh or check the backend connection.');
      setItems([]);
      setSummary(EMPTY_SUMMARY);
      setTotal(0);
      setSelectedEvent(null);
    } finally {
      setLoading(false);
    }
  };

  const refreshAuditLogs = async () => {
    await loadAuditLogs();
    toast.success('Audit trail refreshed');
  };

  useEffect(() => {
    void loadAuditLogs();
  }, [queryString]);

  const metricCards = [
    { label: 'Total Admin Events', value: summary.total_events, helper: 'Filtered audit events', icon: Activity, glow: 'border-cyan-400/35 shadow-cyan-500/10' },
    { label: 'Successful Actions', value: summary.successful_events, helper: 'Completed admin actions', icon: CheckCircle2, glow: 'border-emerald-400/35 shadow-emerald-500/10' },
    { label: 'Failed Actions', value: summary.failed_events, helper: 'Rejected or failed actions', icon: XCircle, glow: 'border-rose-400/35 shadow-rose-500/10' },
    { label: 'High Risk Actions', value: summary.high_risk_events, helper: 'High or critical severity', icon: ShieldAlert, glow: 'border-orange-400/35 shadow-orange-500/10' },
    { label: 'Critical Actions', value: summary.critical_events, helper: 'Requires close review', icon: AlertTriangle, glow: 'border-red-400/35 shadow-red-500/10' },
    { label: 'Active Admins', value: summary.unique_admins, helper: 'Unique admin identities', icon: UserCog, glow: 'border-blue-400/35 shadow-blue-500/10' },
  ];

  const watchlist = items
    .filter((item) => item.severity === 'critical' || item.severity === 'high')
    .slice(0, 5);

  const pageCount = Math.max(1, Math.ceil(total / limit));
  const showingStart = total === 0 ? 0 : (page - 1) * limit + 1;
  const showingEnd = Math.min(page * limit, total);
  const filterDefinitions: Array<{
    key: 'action_type' | 'module' | 'status' | 'severity';
    label: string;
    options: AuditFilterOption[];
  }> = [
    { key: 'action_type', label: 'Action Type', options: actionTypeOptions },
    { key: 'module', label: 'Module', options: moduleOptions },
    {
      key: 'status',
      label: 'Status',
      options: ['success', 'failed', 'warning', 'skipped'].map((value) => ({ value, label: value })),
    },
    {
      key: 'severity',
      label: 'Severity',
      options: ['low', 'medium', 'high', 'critical'].map((value) => ({ value, label: value })),
    },
  ];

  const updateFilter = (key: keyof typeof filters, value: string) => {
    setPage(1);
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const clearFilters = () => {
    setPage(1);
    setFilters({
      search: '',
      action_type: 'all',
      module: 'all',
      status: 'all',
      severity: 'all',
      start_date: '',
      end_date: '',
    });
  };

  const exportCsv = async () => {
    const token = localStorage.getItem('sentinel_admin_token');
    setExporting(true);
    try {
      const query = new URLSearchParams(queryString);
      query.delete('page');
      query.delete('limit');
      const response = await fetch(`${API_BASE_URL || ''}/api/admin/audit-logs/export?${query.toString()}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) throw new Error('Export failed');
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'admin-audit-trail.csv';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      toast.success('Audit trail exported');
      void loadAuditLogs();
    } catch {
      toast.error('Audit trail export failed');
    } finally {
      setExporting(false);
    }
  };

  const detailsPanel = selectedEvent ? (
    <div className="space-y-3">
      <div className="rounded-2xl border border-slate-700/70 bg-[#101827] p-4">
        <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Admin Identity</p>
        <div className="mt-3 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500 to-purple-500 text-sm font-bold text-white">
            {getAdminInitials(selectedEvent.actor_name, selectedEvent.actor_email)}
          </div>
          <div className="min-w-0">
            <p className="truncate font-semibold text-white">{selectedEvent.actor_name}</p>
            <p className="break-all text-sm text-slate-300">{selectedEvent.actor_email || 'No email recorded'}</p>
          </div>
        </div>
      </div>
      {[
        ['Action Details', selectedEvent.action_label, selectedEvent.action_type],
        ['Event Scope', selectedEvent.target_type || getAuditModuleLabel(selectedEvent.module, selectedEvent.module_label) || 'Admin event', getAuditModuleLabel(selectedEvent.module, selectedEvent.module_label) || 'Security monitoring event'],
        ['Request Context', selectedEvent.ip_address || 'Unknown IP', selectedEvent.user_agent || 'No user agent recorded'],
        ['Timestamp', selectedEvent.created_at ? new Date(selectedEvent.created_at).toLocaleString() : 'Unknown', selectedEvent.actor_role],
      ].map(([label, primary, secondary]) => (
        <div key={label} className="rounded-2xl border border-slate-700/70 bg-[#101827] p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-slate-400">{label}</p>
          <p className="mt-2 break-words text-sm font-semibold text-white">{primary}</p>
          <p className="mt-1 break-words text-xs leading-5 text-slate-300">{secondary}</p>
        </div>
      ))}
      <div className="rounded-2xl border border-slate-700/70 bg-[#101827] p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Metadata</p>
          <Button
            size="sm"
            variant="outline"
            className="h-8 gap-2 border-cyan-400/30 bg-cyan-500/10 text-cyan-100 hover:bg-cyan-500/20"
            onClick={() => {
              navigator.clipboard.writeText(JSON.stringify(buildSafeAuditEventJson(selectedEvent), null, 2));
              toast.success('Event JSON copied');
            }}
          >
            <Clipboard className="h-3.5 w-3.5" />
            Copy Event JSON
          </Button>
        </div>
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-700/70 bg-[#07111f] p-3 text-xs leading-5 text-cyan-100">
          {JSON.stringify(selectedEvent.metadata || {}, null, 2)}
        </pre>
      </div>
    </div>
  ) : (
    <div className="rounded-2xl border border-dashed border-white/10 bg-slate-950/40 p-6 text-sm text-slate-400">
      Select an audit event to inspect its request context and metadata.
    </div>
  );

  return (
    <div className="space-y-5">
      <div className="relative overflow-hidden rounded-3xl border border-slate-700/80 bg-[#101827] px-8 py-7 shadow-[0_24px_70px_rgba(2,6,23,0.30)]">
        <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/60 to-transparent" />
        <div className="pointer-events-none absolute -right-24 -top-28 h-56 w-56 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="relative flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex min-w-0 gap-3">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-cyan-400/25 bg-cyan-500/10 shadow-[0_0_24px_rgba(34,211,238,0.10)]">
              <ShieldAlert className="h-5 w-5 text-cyan-200" />
            </div>
            <div className="min-w-0">
              <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-cyan-200">Audit Command Center</p>
              <h1 className="mt-1 text-2xl font-semibold text-white">Admin Audit Trail</h1>
              <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-300">
                Track sensitive administrator actions, access changes, exports, emergency controls, and system events across the platform.
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            <Button
              type="button"
              variant="outline"
              className="h-10 gap-2 border-white/10 bg-white/5 px-3 text-white hover:bg-white/10"
              onClick={() => void refreshAuditLogs()}
              disabled={loading}
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh Logs
            </Button>
            <Button
              type="button"
              variant="outline"
              className="h-10 gap-2 border-cyan-400/30 bg-cyan-500/10 px-3 text-cyan-100 hover:bg-cyan-500/15"
              onClick={exportCsv}
              disabled={exporting || loading}
            >
              <Download className="h-4 w-4" />
              Export CSV
            </Button>
          </div>
        </div>
      </div>

      <div
        className="grid gap-3"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))' }}
      >
        {metricCards.map((metric) => {
          const Icon = metric.icon;
          return (
            <Card key={metric.label} className={`overflow-hidden border bg-[#101827] px-4 py-3.5 shadow-lg ${metric.glow}`}>
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[10px] font-semibold uppercase leading-4 tracking-[0.14em] text-slate-300">{metric.label}</p>
                  <p className="mt-2 text-3xl font-semibold leading-none text-white">{metric.value.toLocaleString()}</p>
                  <p className="mt-1.5 text-xs leading-4 text-slate-400">{metric.helper}</p>
                </div>
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-white/5">
                  <Icon className="h-4 w-4 text-cyan-200" />
                </div>
              </div>
              <div className="mt-3 flex h-5 items-end gap-1">
                {[34, 46, 31, 58, 44, 68, 54, 72].map((height, index) => (
                  <span key={index} className="flex-1 rounded-t bg-cyan-400/20" style={{ height: `${height}%` }} />
                ))}
              </div>
            </Card>
          );
        })}
      </div>

      <Card className="border-slate-700/80 bg-[#101827] p-4 shadow-[0_18px_55px_rgba(2,6,23,0.24)]">
        <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-blue-400/25 bg-blue-500/10">
              <Filter className="h-5 w-5 text-blue-200" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Filter Audit Events</h2>
              <p className="text-sm text-slate-300">Focus by actor, action, module, severity, or date window.</p>
            </div>
          </div>
          <Button type="button" variant="ghost" className="h-9 w-fit gap-2 text-slate-300 hover:text-white" onClick={clearFilters}>
            <Sliders className="h-4 w-4" />
            Clear Filters
          </Button>
        </div>
        <div
          className="grid gap-3"
          style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}
        >
          <div className="relative" style={{ gridColumn: '1 / -1' }}>
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <Input
              value={filters.search}
              onChange={(event) => updateFilter('search', event.target.value)}
              placeholder="Search admin action, module, status, IP..."
              className="h-11 border-white/10 bg-[#0F172A] pl-10"
            />
          </div>
          {filterDefinitions.map(({ key, label, options }) => (
            <Select key={key} value={filters[key]} onValueChange={(value) => updateFilter(key, value)}>
              <SelectTrigger className="h-11 border-white/10 bg-[#0F172A]">
                <SelectValue placeholder={label} />
              </SelectTrigger>
              <SelectContent className="border-white/10 bg-[#1E293B]">
                <SelectItem value="all">{`All ${label}`}</SelectItem>
                {options.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ))}
          <div className="space-y-1">
            <Label className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">Start date</Label>
            <Input
              type="date"
              aria-label="Start date"
              value={filters.start_date}
              onChange={(event) => updateFilter('start_date', event.target.value)}
              className="h-11 border-white/10 bg-[#0F172A]"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">End date</Label>
            <Input
              type="date"
              aria-label="End date"
              value={filters.end_date}
              onChange={(event) => updateFilter('end_date', event.target.value)}
              className="h-11 border-white/10 bg-[#0F172A]"
            />
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-6 2xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card className="overflow-hidden border-slate-700/80 bg-[#101827] shadow-[0_24px_70px_rgba(2,6,23,0.28)]">
          <div className="flex flex-col gap-3 border-b border-white/10 px-8 py-6 md:flex-row md:items-center md:justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">Audit Activity Log</h2>
              <p className="mt-1 text-sm text-slate-300">Sensitive administrator actions across Sentinel AI.</p>
            </div>
            <Badge className="w-fit border border-cyan-400/30 bg-cyan-500/12 text-cyan-100">{total.toLocaleString()} events</Badge>
          </div>
          {loading ? (
            <div className="p-8 text-sm text-slate-300">Loading admin audit trail...</div>
          ) : error ? (
            <div className="p-8 text-sm text-rose-200">Audit trail could not be loaded. Please refresh or check the backend connection.</div>
          ) : items.length === 0 ? (
            <div className="p-8 text-sm text-slate-300">No audit activity found for the selected filters.</div>
          ) : (
            <div className="overflow-x-auto px-4">
              <Table className="min-w-[980px] table-fixed">
                <TableHeader>
                  <TableRow className="border-white/10 hover:bg-transparent">
                    <TableHead className="w-[110px] px-4 py-4 text-slate-300">Time</TableHead>
                    <TableHead className="w-[240px] px-4 py-4 text-slate-300">Admin</TableHead>
                    <TableHead className="w-[300px] px-4 py-4 text-slate-300">Action</TableHead>
                    <TableHead className="w-[180px] px-4 py-4 text-slate-300">Module</TableHead>
                    <TableHead className="w-[120px] px-4 py-4 text-slate-300">Status</TableHead>
                    <TableHead className="w-[120px] px-4 py-4 text-slate-300">Severity</TableHead>
                    <TableHead className="w-[140px] px-4 py-4 text-slate-300">IP Address</TableHead>
                    <TableHead className="w-[48px] px-4 py-4" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((item) => (
                    <TableRow
                      key={item.id}
                      className={`cursor-pointer border-white/10 hover:bg-white/5 ${selectedEvent?.id === item.id ? 'bg-cyan-500/[0.05]' : ''}`}
                      onClick={() => {
                        setSelectedEvent(item);
                        setIsDetailsOpen(true);
                      }}
                    >
                      <TableCell className="whitespace-nowrap px-4 py-5 align-top text-sm text-slate-300">{formatRelativeTime(item.created_at)}</TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-500 to-purple-500 text-xs font-bold text-white">
                            {getAdminInitials(item.actor_name, item.actor_email)}
                          </div>
                          <div className="min-w-0">
                            <p className="break-words text-sm font-medium text-white">{item.actor_name}</p>
                            <p className="break-all text-xs leading-4 text-slate-400">{item.actor_email}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <div className="min-w-0">
                          <p className="break-words text-sm font-medium leading-5 text-white">{item.action_label}</p>
                          <Badge variant="outline" className="mt-1 max-w-full break-all border-white/10 bg-slate-900/80 text-[10px] text-slate-300">
                            {item.action_type}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <Badge className={moduleClass(getAuditModuleLabel(item.module, item.module_label))}>
                          {getAuditModuleLabel(item.module, item.module_label)}
                        </Badge>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <Badge className={statusClass(item.status)}>{item.status}</Badge>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <Badge className={severityClass(item.severity)}>{item.severity}</Badge>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top font-mono text-xs text-slate-400">{item.ip_address || 'Unknown'}</TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <ArrowRight className="h-4 w-4 text-slate-500" />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          <div className="flex flex-col gap-3 border-t border-white/10 px-8 py-5 md:flex-row md:items-center md:justify-between">
            <p className="text-sm text-slate-400">
              Showing {showingStart} to {showingEnd} of {total} events
            </p>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((current) => Math.max(1, current - 1))}>
                Previous
              </Button>
              <Badge className="border border-white/10 bg-white/5 text-slate-200">
                Page {page} of {pageCount}
              </Badge>
              <Button size="sm" variant="outline" disabled={page >= pageCount} onClick={() => setPage((current) => Math.min(pageCount, current + 1))}>
                Next
              </Button>
            </div>
          </div>
        </Card>

        <div className="space-y-6">
          <Card className="border-slate-700/80 bg-[#101827] p-6">
            <div className="mb-5 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-orange-400/25 bg-orange-500/10">
                <Lock className="h-5 w-5 text-orange-200" />
              </div>
              <div>
                <h3 className="font-semibold text-white">Sensitive Actions Watchlist</h3>
                <p className="text-sm text-slate-300">Latest high-impact admin events</p>
              </div>
            </div>
            <div className="space-y-3">
              {watchlist.length === 0 ? (
                <p className="rounded-2xl border border-dashed border-white/10 p-4 text-sm text-slate-400">No sensitive actions in the current filter.</p>
              ) : (
                watchlist.map((item) => (
                  <button
                    key={item.id}
                    className="w-full rounded-2xl border border-white/10 bg-slate-950/35 px-6 py-4 text-left transition-colors hover:bg-white/5"
                    onClick={() => {
                      setSelectedEvent(item);
                      setIsDetailsOpen(true);
                    }}
                  >
                    <div className="flex gap-3">
                      <div className={`mt-1 h-2.5 w-2.5 rounded-full ${item.severity === 'critical' ? 'bg-red-400' : 'bg-orange-400'}`} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-white">{item.action_label}</p>
                        <p className="mt-1 truncate text-xs text-slate-400">
                          {item.actor_name} - {formatRelativeTime(item.created_at)} - {getAuditModuleLabel(item.module, item.module_label)}
                        </p>
                      </div>
                    </div>
                  </button>
                ))
              )}
            </div>
          </Card>

          <Card className="hidden border-slate-700/80 bg-[#101827] p-5 2xl:block">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-cyan-400/25 bg-cyan-500/10">
                <Eye className="h-5 w-5 text-cyan-200" />
              </div>
              <div>
                <h3 className="font-semibold text-white">Audit Event Details</h3>
                <p className="text-sm text-slate-300">Selected event context</p>
              </div>
            </div>
            {detailsPanel}
          </Card>
        </div>
      </div>

      <Sheet open={isDetailsOpen} onOpenChange={setIsDetailsOpen}>
        <SheetContent className="w-full max-w-[620px] overflow-y-auto border-white/10 bg-[#0B0F19] text-white sm:w-[620px] 2xl:hidden">
          <SheetHeader>
            <SheetTitle>Audit Event Details</SheetTitle>
            <SheetDescription className="text-slate-400">Selected admin action context and metadata.</SheetDescription>
          </SheetHeader>
          <div className="mt-6 pb-8">{detailsPanel}</div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
