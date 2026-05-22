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

type AuditStatus = 'success' | 'failed' | 'warning';
type AuditSeverity = 'low' | 'medium' | 'high' | 'critical';

interface AdminAuditItem {
  id: string;
  actor_name: string;
  actor_email: string;
  actor_role: string;
  action_type: string;
  action_label: string;
  module: string;
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
}

const EMPTY_SUMMARY: AuditSummary = {
  total_events: 0,
  successful_events: 0,
  failed_events: 0,
  high_risk_events: 0,
  critical_events: 0,
  unique_admins: 0,
};

// Demo fallback only for local/demo sessions when the backend is empty or unavailable.
const DEMO_AUDIT_ITEMS: AdminAuditItem[] = [
  {
    id: 'demo-1',
    actor_name: 'Sarah Admin',
    actor_email: 'sarah.admin@sentinel.local',
    actor_role: 'Admin',
    action_type: 'model_retrain_requested',
    action_label: 'Requested model retraining',
    module: 'AI Governance',
    target_type: 'model',
    target_id: '',
    target_label: '',
    status: 'warning',
    severity: 'high',
    ip_address: '10.10.12.8',
    user_agent: 'Sentinel Admin Console',
    metadata: { confidence_window: '30d', approval: 'manual_review' },
    created_at: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
  },
  {
    id: 'demo-2',
    actor_name: 'Ahmed Admin',
    actor_email: 'ahmed.admin@sentinel.local',
    actor_role: 'Admin',
    action_type: 'report_exported',
    action_label: 'Exported PCAP analysis report',
    module: 'PCAP Analysis',
    target_type: 'pcap_job',
    target_id: '',
    target_label: '',
    status: 'success',
    severity: 'high',
    ip_address: '10.10.12.14',
    user_agent: 'Sentinel Admin Console',
    metadata: { export_type: 'report', format: 'json' },
    created_at: new Date(Date.now() - 32 * 60 * 1000).toISOString(),
  },
  {
    id: 'demo-3',
    actor_name: 'Security Lead',
    actor_email: 'lead@sentinel.local',
    actor_role: 'Admin',
    action_type: 'emergency_mode_enabled',
    action_label: 'Enabled emergency mode',
    module: 'Emergency Controls',
    target_type: 'account',
    target_id: '',
    target_label: '',
    status: 'success',
    severity: 'critical',
    ip_address: '10.10.10.5',
    user_agent: 'Sentinel Admin Console',
    metadata: { revoked_sessions: 3, protection_minutes: 30 },
    created_at: new Date(Date.now() - 71 * 60 * 1000).toISOString(),
  },
  {
    id: 'demo-4',
    actor_name: 'Operations Admin',
    actor_email: 'operations.admin@sentinel.local',
    actor_role: 'Admin',
    action_type: 'role_changed',
    action_label: 'Changed user role from user to analyst',
    module: 'Users & Roles',
    target_type: 'user',
    target_id: '',
    target_label: '',
    status: 'success',
    severity: 'medium',
    ip_address: '10.10.12.22',
    user_agent: 'Sentinel Admin Console',
    metadata: { previous_role: 'User', new_role: 'Analyst' },
    created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: 'demo-5',
    actor_name: 'Sarah Admin',
    actor_email: 'sarah.admin@sentinel.local',
    actor_role: 'Admin',
    action_type: 'alert_resolved',
    action_label: 'Resolved high severity alert',
    module: 'Threat Management',
    target_type: 'alert',
    target_id: '',
    target_label: '',
    status: 'success',
    severity: 'high',
    ip_address: '10.10.12.8',
    user_agent: 'Sentinel Admin Console',
    metadata: { resolution: 'false_positive_after_triage' },
    created_at: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
  },
];

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
  return 'border-amber-400/40 bg-amber-500/15 text-amber-200';
}

function severityClass(severity: string) {
  if (severity === 'critical') return 'border-red-400/40 bg-red-500/15 text-red-200';
  if (severity === 'high') return 'border-orange-400/40 bg-orange-500/15 text-orange-200';
  if (severity === 'medium') return 'border-blue-400/40 bg-blue-500/15 text-blue-200';
  return 'border-cyan-400/40 bg-cyan-500/15 text-cyan-200';
}

function moduleClass(module: string) {
  if (module.includes('AI')) return 'border-purple-400/30 bg-purple-500/12 text-purple-100';
  if (module.includes('PCAP')) return 'border-cyan-400/30 bg-cyan-500/12 text-cyan-100';
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

function buildSummaryFromItems(items: AdminAuditItem[]): AuditSummary {
  return {
    total_events: items.length,
    successful_events: items.filter((item) => item.status === 'success').length,
    failed_events: items.filter((item) => item.status === 'failed').length,
    high_risk_events: items.filter((item) => item.severity === 'high' || item.severity === 'critical').length,
    critical_events: items.filter((item) => item.severity === 'critical').length,
    unique_admins: new Set(items.map((item) => item.actor_email || item.actor_name)).size,
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
  const [isDemoFallback, setIsDemoFallback] = useState(false);
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
      const response = await fetch(`${API_BASE_URL || ''}/api/admin/audit-logs?${queryString}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const payload = (await response.json().catch(() => ({}))) as Partial<AuditResponse> & {
        message?: string;
      };
      if (!response.ok) {
        throw new Error(payload.message || 'Audit trail could not be loaded. Please refresh or check the backend connection.');
      }
      const nextItems = Array.isArray(payload.items) ? payload.items : [];
      if (nextItems.length === 0 && page === 1) {
        setItems(DEMO_AUDIT_ITEMS);
        setSummary(buildSummaryFromItems(DEMO_AUDIT_ITEMS));
        setTotal(DEMO_AUDIT_ITEMS.length);
        setSelectedEvent(DEMO_AUDIT_ITEMS[0]);
        setIsDemoFallback(true);
      } else {
        setItems(nextItems);
        setSummary(payload.summary || EMPTY_SUMMARY);
        setTotal(Number(payload.total || nextItems.length));
        setSelectedEvent((current) => current || nextItems[0] || null);
        setIsDemoFallback(false);
      }
    } catch (loadError) {
      setError('Audit trail could not be loaded. Please refresh or check the backend connection.');
      setItems(DEMO_AUDIT_ITEMS);
      setSummary(buildSummaryFromItems(DEMO_AUDIT_ITEMS));
      setTotal(DEMO_AUDIT_ITEMS.length);
      setSelectedEvent(DEMO_AUDIT_ITEMS[0]);
      setIsDemoFallback(true);
    } finally {
      setLoading(false);
    }
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
        ['Event Scope', selectedEvent.target_type || selectedEvent.module || 'Admin event', selectedEvent.module || 'Security monitoring event'],
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
                Track sensitive administrator actions, access changes, exports, emergency controls, and model governance events across the platform.
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            <Button variant="outline" className="h-10 gap-2 border-white/10 bg-white/5 px-3 text-white hover:bg-white/10" onClick={() => void loadAuditLogs()}>
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh Logs
            </Button>
            <Button variant="outline" className="h-10 gap-2 border-cyan-400/30 bg-cyan-500/10 px-3 text-cyan-100 hover:bg-cyan-500/15" onClick={exportCsv} disabled={exporting}>
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
          <Button variant="ghost" className="h-9 w-fit gap-2 text-slate-300 hover:text-white" onClick={clearFilters}>
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
          {[
            ['action_type', 'Action Type', ['all', 'admin_login', 'admin_logout', 'role_changed', 'report_exported', 'settings_updated', 'model_retrain_requested', 'user_locked', 'user_unlocked', 'audit_logs_exported']],
            ['module', 'Module', ['all', 'Admin Authentication', 'Users & Roles', 'Threat Management', 'PCAP Analysis', 'AI Governance', 'Admin Audit Trail']],
            ['status', 'Status', ['all', 'success', 'failed', 'warning']],
            ['severity', 'Severity', ['all', 'low', 'medium', 'high', 'critical']],
          ].map(([key, label, options]) => (
            <Select key={key as string} value={filters[key as keyof typeof filters]} onValueChange={(value) => updateFilter(key as keyof typeof filters, value)}>
              <SelectTrigger className="h-11 border-white/10 bg-[#0F172A]">
                <SelectValue placeholder={label as string} />
              </SelectTrigger>
              <SelectContent className="border-white/10 bg-[#1E293B]">
                {(options as string[]).map((option) => (
                  <SelectItem key={option} value={option}>
                    {option === 'all' ? `All ${label}` : option.replaceAll('_', ' ')}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ))}
          <Input type="date" value={filters.start_date} onChange={(event) => updateFilter('start_date', event.target.value)} className="h-11 border-white/10 bg-[#0F172A]" />
          <Input type="date" value={filters.end_date} onChange={(event) => updateFilter('end_date', event.target.value)} className="h-11 border-white/10 bg-[#0F172A]" />
        </div>
      </Card>

      {isDemoFallback && (
        <div className="rounded-2xl border border-amber-400/25 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
          Showing safe demo fallback audit events until live admin audit data is available.
        </div>
      )}

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
          ) : error && !isDemoFallback ? (
            <div className="p-8 text-sm text-rose-200">Audit trail could not be loaded. Please refresh or check the backend connection.</div>
          ) : items.length === 0 ? (
            <div className="p-8 text-sm text-slate-300">No admin actions found for the selected filters.</div>
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
                        <Badge className={moduleClass(item.module)}>{item.module}</Badge>
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
              <Button size="sm" variant="outline" disabled={page <= 1 || isDemoFallback} onClick={() => setPage((current) => Math.max(1, current - 1))}>
                Previous
              </Button>
              <Badge className="border border-white/10 bg-white/5 text-slate-200">
                Page {page} of {pageCount}
              </Badge>
              <Button size="sm" variant="outline" disabled={page >= pageCount || isDemoFallback} onClick={() => setPage((current) => Math.min(pageCount, current + 1))}>
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
                        <p className="mt-1 truncate text-xs text-slate-400">{item.actor_name} - {formatRelativeTime(item.created_at)}</p>
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
