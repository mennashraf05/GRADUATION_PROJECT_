import React, { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { 
  Shield, Users, AlertTriangle, Package, Search, Bell, 
  Settings, Activity, Database, Calendar, FileText, Link2,
  ChevronRight, Download, RefreshCw, Lock, Unlock, Mail,
  MoreVertical, Filter, Plus, Play, Pause, CheckCircle,
  XCircle, Clock, TrendingUp, Server, Cpu, HardDrive,
  Globe, MessageSquare, Zap, Eye, Edit, Trash2, UserPlus,
  Send, BarChart3, PieChart, AlertCircle, Check, X, ShieldAlert, ShieldCheck,
  ArrowUpDown, ChevronDown, UserCog, FileSearch, Sliders,
  LogOut
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Switch } from '../ui/switch';
import { Slider } from '../ui/slider';
import { Avatar, AvatarFallback } from '../ui/avatar';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from '../ui/dialog';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '../ui/dropdown-menu';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '../ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Textarea } from '../ui/textarea';
import { LineChart, Line, BarChart, Bar, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { toast } from 'sonner@2.0.3';
import { NotificationCenter } from '../NotificationCenter';
import AdminAuditTrailPage from '../admin/AdminAuditTrailPage';
import PcapAnalysisAdminControl from '../admin/PcapAnalysisAdminControl';
import ReportsExportCenterPage from '../admin/ReportsExportCenterPage';
import NotificationControlCenterPage from '../admin/NotificationControlCenterPage';
import SecurityValidationLabPage from '../admin/SecurityValidationLabPage';
import {
  NotificationSettings,
  getNotificationSettings,
  saveNotificationSettings,
} from '../../services/adminNotificationsService';

type SectionType = 'overview' | 'users' | 'alerts' | 'modules' | 'threat-intel' | 'pcap-analysis' | 'security-lab' | 'jobs' | 'system-health' | 'audit-logs' | 'notifications' | 'integrations' | 'reports' | 'settings';

const ADMIN_VISIBLE_ROLES = new Set(['Admin', 'User']);
const ADMIN_SECTIONS = new Set<SectionType>([
  'overview',
  'users',
  'alerts',
  'pcap-analysis',
  'security-lab',
  'audit-logs',
  'notifications',
  'reports',
  'settings',
]);

function sectionFromSearch(search: string): SectionType {
  const section = new URLSearchParams(search).get('section') as SectionType | null;
  return section && ADMIN_SECTIONS.has(section) ? section : 'overview';
}

interface User {
  id: string;
  name: string;
  email: string;
  status: 'Active' | 'Suspended' | 'Under Investigation' | 'High Risk';
  role: string;
  twoFA: boolean;
  lastLogin: string;
  lastLoginAt: string | null;
  createdAt: string;
  riskLevel: 'Low' | 'Medium' | 'High';
  alertsCount: number;
  linkedAccountsCount: number;
  recentSecurityEvents: Array<{
    title: string;
    description: string;
    severity: string;
    status: string;
    createdAt: string | null;
  }>;
  riskSummary: string;
  auditPreview: Array<{
    action: string;
    summary: string;
    createdAt: string | null;
  }>;
}

interface RoleSummary {
  id: string;
  name: string;
  description: string;
  count: number;
}

interface PermissionSummary {
  key: string;
  admin: boolean;
  user: boolean;
}

interface InviteUserFormState {
  name: string;
  email: string;
  role: string;
  twoFA: boolean;
}

interface AdminIdentity {
  displayName: string;
  email: string;
  role: string;
}

interface AdminUserSummary {
  total_users: number;
  active_today: number;
  active_users?: number;
  active_sessions?: number;
  high_risk_users: number;
  without_2fa: number;
}

const API_BASE_URL =
  import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');

function formatRelativeAdminTime(value: string | null | undefined): string {
  if (!value) {
    return 'Never';
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return 'Unknown';
  }

  const diffMs = Date.now() - parsed.getTime();
  const minutes = Math.max(0, Math.floor(diffMs / 60000));

  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? '' : 's'} ago`;
  return parsed.toISOString().slice(0, 10);
}

function formatAdminDateTime(value: string | null | undefined): string {
  if (!value) {
    return 'Unknown';
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatAdminNumber(value: number | null | undefined): string {
  return Number(value || 0).toLocaleString();
}

function maskEmail(value: string | null | undefined): string {
  const email = String(value || '').trim();
  if (!email || !email.includes('@')) return email ? 'masked-user' : 'Unavailable';
  const [localPart, domain] = email.split('@');
  const prefix = localPart.slice(0, Math.min(3, Math.max(1, localPart.length)));
  return `${prefix}***@${domain}`;
}

function normalizePrivacyStatus(value: unknown): Alert['status'] {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'false positive' || normalized === 'false_positive') return 'False Positive';
  if (normalized === 'acknowledged' || normalized === 'under investigation' || normalized === 'under_investigation' || normalized === 'resolved') {
    return 'Acknowledged';
  }
  return 'New';
}

function isPcapThreatAlert(alert: Alert): boolean {
  return alert.sourceModule === 'PCAP Analyzer' && (alert.threatDetected || alert.severity === 'Critical' || alert.severity === 'High');
}

function primaryAlertViewAction(alert: Alert): 'view-evidence' | 'view-report' {
  return alert.sourceModule === 'PCAP Analyzer' && !isPcapThreatAlert(alert) ? 'view-report' : 'view-evidence';
}

const ADMIN_HIDDEN_EVIDENCE_FIELDS = [
  'target',
  'query',
  'user',
  'email',
  'account',
  'identifier',
  'profile',
  'linked account',
  'affected',
];

function isAdminSafeEvidenceEntry(key: string, value: unknown): boolean {
  const normalizedKey = key.replace(/[_-]/g, ' ').toLowerCase();
  if (ADMIN_HIDDEN_EVIDENCE_FIELDS.some((field) => normalizedKey.includes(field))) {
    return false;
  }
  const text = String(value ?? '').trim();
  if (!text) return false;
  if (/\S+@\S+\.\S+/.test(text)) return false;
  if (/menna/i.test(text)) return false;
  return true;
}

function buildAdminSafeEvidence(rawEvidence: unknown): Record<string, string | number | null> {
  if (!rawEvidence || typeof rawEvidence !== 'object') return {};
  return Object.fromEntries(
    Object.entries(rawEvidence as Record<string, unknown>).filter(([key, value]) =>
      isAdminSafeEvidenceEntry(key, value),
    ),
  ) as Record<string, string | number | null>;
}

function sanitizeAdminThreatText(value: unknown, fallback = ''): string {
  const text = String(value ?? fallback ?? '').trim();
  if (!text) return fallback;
  return text
    .replace(/\s*Affected user:\s*[^.]+\.?/gi, '')
    .replace(/\S+@\S+\.\S+/g, '[hidden]')
    .replace(/\bmenna[\w.-]*\b/gi, '[hidden]')
    .trim() || fallback;
}

interface Alert {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  status: 'New' | 'Acknowledged' | 'False Positive';
  title: string;
  description: string;
  sourceModule: 'PCAP Analyzer' | 'Phishing Scanner' | 'Password Checker' | 'File Vault' | 'Identity Leak Monitor' | 'Other/Unknown';
  affectedUserName: string;
  affectedUserEmail: string;
  maskedUserIdentifier: string;
  confidence: number;
  timestamp: string | null;
  time: string;
  linkedAccountsCount: number;
  ipAddress: string | null;
  deviceContext: string | null;
  investigationSummary: string;
  evidence: Record<string, string | number | null>;
  allowedActions: string[];
  evidenceAvailable: boolean;
  threatDetected: boolean;
  summary: string;
  scanId: string | null;
  analysisId: string | null;
  auditPreview: Array<{
    label: string;
    actor: string;
    createdAt: string | null;
  }>;
}

interface ThreatSummary {
  total_alerts: number;
  critical_alerts: number;
  under_investigation: number;
  resolved_today: number;
}

interface AdminPcapSummary {
  total_jobs: number;
  failed_jobs: number;
  failed_jobs_24h: number;
  running_jobs: number;
  queued_jobs: number;
  completed_jobs: number;
  average_processing_time_seconds: number | null;
}

interface Job {
  id: string;
  name: string;
  module: string;
  type: string;
  nextRun: string;
  lastRun: string;
  status: 'Success' | 'Failed' | 'Running';
  duration: string;
}

interface AuditLog {
  id: string;
  time: string;
  actor: string;
  action: string;
  ip: string;
  result: 'Success' | 'Failed';
}

interface RecentAdminActivity {
  id: string;
  icon: React.ElementType;
  text: string;
  time: string;
  color: string;
}

const AdminConsolePage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [activeSection, setActiveSection] = useState<SectionType>(() => sectionFromSearch(location.search));
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isUserDrawerOpen, setIsUserDrawerOpen] = useState(false);
  const [isAlertDrawerOpen, setIsAlertDrawerOpen] = useState(false);
  const [isCreateRoleOpen, setIsCreateRoleOpen] = useState(false);
  const [isCreateJobOpen, setIsCreateJobOpen] = useState(false);
  const [isModuleConfigOpen, setIsModuleConfigOpen] = useState(false);
  const [selectedModule, setSelectedModule] = useState<string>('');
  const [activeUsersTab, setActiveUsersTab] = useState<'users' | 'roles' | 'permissions'>('users');
  const [userSearch, setUserSearch] = useState('');
  const [debouncedUserSearch, setDebouncedUserSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [roleFilter, setRoleFilter] = useState('all');
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<RoleSummary[]>([]);
  const [permissions, setPermissions] = useState<PermissionSummary[]>([]);
  const [threats, setThreats] = useState<Alert[]>([]);
  const [threatSummary, setThreatSummary] = useState<ThreatSummary>({
    total_alerts: 0,
    critical_alerts: 0,
    under_investigation: 0,
    resolved_today: 0,
  });
  const [userSummary, setUserSummary] = useState<AdminUserSummary>({
    total_users: 0,
    active_today: 0,
    active_users: 0,
    active_sessions: 0,
    high_risk_users: 0,
    without_2fa: 0,
  });
  const [pcapSummary, setPcapSummary] = useState<AdminPcapSummary>({
    total_jobs: 0,
    failed_jobs: 0,
    failed_jobs_24h: 0,
    running_jobs: 0,
    queued_jobs: 0,
    completed_jobs: 0,
    average_processing_time_seconds: null,
  });
  const [threatSearch, setThreatSearch] = useState('');
  const [debouncedThreatSearch, setDebouncedThreatSearch] = useState('');
  const [threatSeverityFilter, setThreatSeverityFilter] = useState('all');
  const [threatStatusFilter, setThreatStatusFilter] = useState('all');
  const [threatModuleFilter, setThreatModuleFilter] = useState('all');
  const [threatTimeRangeFilter, setThreatTimeRangeFilter] = useState('7d');
  const [usersLoading, setUsersLoading] = useState(false);
  const [rolesLoading, setRolesLoading] = useState(false);
  const [permissionsLoading, setPermissionsLoading] = useState(false);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [threatsLoading, setThreatsLoading] = useState(false);
  const [threatSummaryLoading, setThreatSummaryLoading] = useState(false);
  const [pcapSummaryLoading, setPcapSummaryLoading] = useState(false);
  const [usersError, setUsersError] = useState('');
  const [rolesError, setRolesError] = useState('');
  const [permissionsError, setPermissionsError] = useState('');
  const [summaryError, setSummaryError] = useState('');
  const [threatsError, setThreatsError] = useState('');
  const [threatSummaryError, setThreatSummaryError] = useState('');
  const [pcapSummaryError, setPcapSummaryError] = useState('');
  const [recentActivity, setRecentActivity] = useState<RecentAdminActivity[]>([]);
  const [recentActivityLoading, setRecentActivityLoading] = useState(false);
  const [recentActivityError, setRecentActivityError] = useState('');
  const [adminIdentity, setAdminIdentity] = useState<AdminIdentity>({
    displayName: localStorage.getItem('sentinel_admin_name') || 'Admin',
    email: localStorage.getItem('sentinel_admin_email') || '',
    role: 'Admin',
  });
  const [notificationPreferences, setNotificationPreferences] = useState<NotificationSettings | null>(null);
  const [notificationPreferencesLoading, setNotificationPreferencesLoading] = useState(false);
  const [inviteForm, setInviteForm] = useState<InviteUserFormState>({
    name: '',
    email: '',
    role: 'User',
    twoFA: true,
  });

  const recentAlertWindow = useMemo(() => {
    const start = new Date();
    start.setHours(0, 0, 0, 0);
    start.setDate(start.getDate() - 6);
    return start;
  }, []);

  const recentThreats = useMemo(
    () => threats.filter((alert) => {
      if (!alert.timestamp) return false;
      const parsed = new Date(alert.timestamp);
      return !Number.isNaN(parsed.getTime()) && parsed >= recentAlertWindow && parsed <= new Date();
    }),
    [recentAlertWindow, threats],
  );

  const alertsChartData = useMemo(() => {
    const dayFormatter = new Intl.DateTimeFormat(undefined, { weekday: 'short' });
    const dayKey = (date: Date) => [
      date.getFullYear(),
      String(date.getMonth() + 1).padStart(2, '0'),
      String(date.getDate()).padStart(2, '0'),
    ].join('-');
    const today = new Date();
    const days = Array.from({ length: 7 }, (_, index) => {
      const date = new Date(today);
      date.setHours(0, 0, 0, 0);
      date.setDate(today.getDate() - (6 - index));
      return {
        key: dayKey(date),
        date: dayFormatter.format(date),
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
      };
    });
    const byDay = new Map(days.map((day) => [day.key, day]));

    recentThreats.forEach((alert) => {
      if (!alert.timestamp) return;
      const parsed = new Date(alert.timestamp);
      if (Number.isNaN(parsed.getTime())) return;
      const bucket = byDay.get(dayKey(parsed));
      if (!bucket) return;
      bucket[alert.severity] += 1;
    });

    return days;
  }, [recentThreats]);

  const alertSourceData = useMemo(() => {
    const sourceOrder: Alert['sourceModule'][] = [
      'PCAP Analyzer',
      'Phishing Scanner',
      'Password Checker',
      'File Vault',
      'Identity Leak Monitor',
      'Other/Unknown',
    ];
    const counts = recentThreats.reduce<Record<string, number>>((accumulator, alert) => {
      accumulator[alert.sourceModule] = (accumulator[alert.sourceModule] || 0) + 1;
      return accumulator;
    }, {});

    return sourceOrder.map((source) => ({
      source,
      count: counts[source] || 0,
    }));
  }, [recentThreats]);

  const openIncidentCount = useMemo(
    () => threats.filter((alert) => alert.status !== 'Acknowledged' && alert.status !== 'False Positive').length,
    [threats],
  );

  const newIncidentCount = useMemo(() => {
    const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
    return threats.filter((alert) => {
      if (alert.status === 'Acknowledged' || alert.status === 'False Positive' || !alert.timestamp) return false;
      const parsed = new Date(alert.timestamp);
      return !Number.isNaN(parsed.getTime()) && parsed.getTime() >= dayAgo;
    }).length;
  }, [threats]);

  const averageAlertLatencyMs = useMemo(() => {
    const openAlerts = threats.filter((alert) => (
      alert.status !== 'Acknowledged' &&
      alert.status !== 'False Positive' &&
      Boolean(alert.timestamp)
    ));
    const ages = openAlerts
      .map((alert) => {
        const parsed = new Date(String(alert.timestamp));
        return Number.isNaN(parsed.getTime()) ? null : Date.now() - parsed.getTime();
      })
      .filter((value): value is number => value !== null && value >= 0);

    if (ages.length === 0) return 0;
    return Math.round(ages.reduce((total, value) => total + value, 0) / ages.length);
  }, [threats]);

  const formatLatency = (valueMs: number): string => {
    if (valueMs < 1000) return `${valueMs}ms`;
    const minutes = Math.round(valueMs / 60000);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.round(minutes / 60);
    if (hours < 48) return `${hours}h`;
    return `${Math.round(hours / 24)}d`;
  };

  const jobs: Job[] = [
    { id: '1', name: 'Breach Scan Hourly', module: 'Password Checker', type: 'Cron', nextRun: 'In 15 min', lastRun: '45 min ago', status: 'Success', duration: '2.3s' },
    { id: '2', name: 'Monthly Report', module: 'Reports', type: 'Scheduled', nextRun: 'In 8 days', lastRun: '2 days ago', status: 'Failed', duration: '45.2s' },
    { id: '3', name: 'Identity Leak Scan', module: 'Identity Leak Monitor', type: 'Cron', nextRun: 'In 2 hours', lastRun: '1 hour ago', status: 'Success', duration: '12.5s' },
    { id: '4', name: 'Threat Intel Sync', module: 'Threat Intel', type: 'Cron', nextRun: 'In 30 min', lastRun: '3.5 hours ago', status: 'Running', duration: '5m 12s' },
  ];

  const auditLogs: AuditLog[] = [
    { id: '1', time: '2 min ago', actor: 'sarah.j@company.com', action: 'User Created', ip: '192.168.1.100', result: 'Success' },
    { id: '2', time: '15 min ago', actor: 'mike.chen@company.com', action: 'Role Updated', ip: '192.168.1.105', result: 'Success' },
    { id: '3', time: '1 hour ago', actor: 'System', action: 'Job Executed', ip: '127.0.0.1', result: 'Success' },
    { id: '4', time: '2 hours ago', actor: 'emma.d@company.com', action: 'Access Updated', ip: '192.168.1.110', result: 'Success' },
    { id: '5', time: '3 hours ago', actor: 'admin@company.com', action: 'Module Toggled', ip: '192.168.1.101', result: 'Success' },
  ];

  const modules = [
    { id: 'password', name: 'Password Breach Checker', description: 'Check passwords against HIBP database', enabled: true, icon: Lock },
    { id: 'file-vault', name: 'File Vault', description: 'Encrypted file storage with AES-256', enabled: true, icon: Database },
    { id: 'phishing', name: 'Phishing Scanner', description: 'Scan URLs for phishing threats', enabled: true, icon: Shield },
    { id: 'identity-leak', name: 'Identity Leak Monitor', description: 'Monitor identity leak for credentials', enabled: false, icon: Globe },
    { id: 'chatbot', name: 'Security Chatbot', description: 'AI-powered security assistant', enabled: true, icon: MessageSquare },
  ];

  const buildAdminRequestInit = (init: RequestInit = {}): RequestInit => {
    const headers = new Headers(init.headers || {});
    const adminToken = localStorage.getItem('sentinel_admin_token');

    if (!headers.has('Content-Type') && init.method && init.method !== 'GET') {
      headers.set('Content-Type', 'application/json');
    }
    if (adminToken) {
      headers.set('Authorization', `Bearer ${adminToken}`);
    }

    return {
      ...init,
      headers,
    };
  };

  const requestAdmin = async <T,>(path: string, init: RequestInit = {}): Promise<T> => {
    const response = await fetch(`${API_BASE_URL || ''}${path}`, buildAdminRequestInit(init));
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401) {
      localStorage.removeItem('sentinel_admin_token');
      navigate('/admin/login');
    }
    if (!response.ok || payload?.success === false) {
      throw new Error(payload?.message || `Request failed (${response.status})`);
    }
    return payload as T;
  };

  const loadAdminIdentity = async () => {
    try {
      const result = await requestAdmin<{
        admin?: {
          name?: string;
          email?: string;
          role?: string;
        };
      }>('/api/admin/auth/me');
      const admin = result.admin || {};
      const email = String(admin.email || '').trim();
      const displayName = String(admin.name || email || 'Admin').trim();
      setAdminIdentity({
        displayName,
        email,
        role: String(admin.role || 'Admin').trim() || 'Admin',
      });
      localStorage.setItem('sentinel_admin_name', displayName);
      if (email) {
        localStorage.setItem('sentinel_admin_email', email);
      }
    } catch {
      setAdminIdentity((current) => ({
        ...current,
        displayName: current.displayName || current.email || 'Admin',
      }));
    }
  };

  const loadNotificationPreferences = async () => {
    setNotificationPreferencesLoading(true);
    try {
      const settings = await getNotificationSettings();
      setNotificationPreferences(settings);
    } catch (error) {
      toast.error('Notification preferences could not be loaded', {
        description: error instanceof Error ? error.message : 'Check admin authentication and backend status.',
      });
    } finally {
      setNotificationPreferencesLoading(false);
    }
  };

  const updateNotificationPreferences = async (updates: Partial<NotificationSettings>) => {
    const base = notificationPreferences || await getNotificationSettings();
    const next: NotificationSettings = {
      ...base,
      ...updates,
      silentHours: {
        ...base.silentHours,
        ...(updates.silentHours || {}),
      },
    };
    setNotificationPreferences(next);
  };

  const saveAdminNotificationPreferences = async () => {
    if (!notificationPreferences) return;
    setNotificationPreferencesLoading(true);
    try {
      await saveNotificationSettings(notificationPreferences);
      toast.success('Notification preferences saved', {
        description: 'Admin alerts will use the selected email, Telegram, severity, and frequency preferences.',
      });
      await loadNotificationPreferences();
    } catch (error) {
      toast.error('Notification preferences could not be saved', {
        description: error instanceof Error ? error.message : 'Check admin authentication and backend status.',
      });
    } finally {
      setNotificationPreferencesLoading(false);
    }
  };

  const mapAdminUser = (payload: any): User => ({
    id: String(payload?.id ?? ''),
    name: String(payload?.name ?? payload?.email ?? 'User'),
    email: String(payload?.email ?? ''),
    status: payload?.status === 'Suspended'
      ? 'Suspended'
      : payload?.status === 'Under Investigation'
        ? 'Under Investigation'
        : payload?.status === 'High Risk'
          ? 'High Risk'
          : 'Active',
    role: ADMIN_VISIBLE_ROLES.has(String(payload?.role ?? 'User'))
      ? String(payload?.role ?? 'User')
      : 'User',
    twoFA: Boolean(payload?.two_factor_enabled ?? payload?.twoFA),
    lastLogin: payload?.lastLoginAt ? formatAdminDateTime(payload?.lastLoginAt) : 'Never',
    lastLoginAt: payload?.lastLoginAt ? String(payload.lastLoginAt) : null,
    createdAt: String(payload?.createdAt ?? ''),
    riskLevel: payload?.risk_level === 'High'
      ? 'High'
      : payload?.risk_level === 'Medium'
        ? 'Medium'
        : 'Low',
    alertsCount: Number(payload?.alerts_count ?? 0),
    linkedAccountsCount: Number(payload?.linked_accounts_count ?? 0),
    recentSecurityEvents: Array.isArray(payload?.recent_security_events)
      ? payload.recent_security_events.map((event: any) => ({
          title: String(event?.title ?? 'Security event'),
          description: String(event?.description ?? ''),
          severity: String(event?.severity ?? 'low'),
          status: String(event?.status ?? 'info'),
          createdAt: event?.createdAt ? String(event.createdAt) : null,
        }))
      : [],
    riskSummary: String(payload?.risk_summary ?? 'No elevated security signals detected.'),
    auditPreview: Array.isArray(payload?.audit_preview)
      ? payload.audit_preview.map((entry: any) => ({
          action: String(entry?.action ?? 'Audit event'),
          summary: String(entry?.summary ?? ''),
          createdAt: entry?.createdAt ? String(entry.createdAt) : null,
        }))
      : [],
  });

  const mapThreatAlert = (payload: any): Alert => {
    const severity = String(payload?.severity ?? '').trim().toLowerCase();

    return {
      id: String(payload?.id ?? ''),
      title: sanitizeAdminThreatText(payload?.title, 'Security alert'),
      description: sanitizeAdminThreatText(payload?.description ?? payload?.message, ''),
      sourceModule: payload?.source_module === 'PCAP Analyzer'
        ? 'PCAP Analyzer'
        : payload?.source_module === 'Phishing Scanner'
          ? 'Phishing Scanner'
          : payload?.source_module === 'Password Checker'
          ? 'Password Checker'
          : payload?.source_module === 'File Vault'
            ? 'File Vault'
            : payload?.source_module === 'Identity Leak Monitor'
              ? 'Identity Leak Monitor'
              : 'Other/Unknown',
      affectedUserName: String(payload?.affected_user_name ?? 'Unknown user'),
      affectedUserEmail: String(payload?.masked_user_identifier || maskEmail(payload?.affected_user_email)),
      severity: severity === 'critical'
        ? 'Critical'
        : severity === 'high'
          ? 'High'
          : severity === 'medium' || severity === 'warning'
            ? 'Medium'
            : 'Low',
      status: payload?.status === 'Under Investigation'
        ? 'Acknowledged'
        : normalizePrivacyStatus(payload?.status),
      confidence: Math.max(0, Math.min(100, Number(payload?.confidence ?? 0))),
      timestamp: payload?.timestamp ? String(payload.timestamp) : null,
      time: payload?.timestamp ? formatAdminDateTime(payload.timestamp) : 'Unknown',
      linkedAccountsCount: Number(payload?.linked_accounts_count ?? 0),
      ipAddress: payload?.ip_address ? String(payload.ip_address) : null,
      deviceContext: payload?.device_context ? String(payload.device_context) : null,
      investigationSummary: sanitizeAdminThreatText(payload?.investigation_summary, 'No investigation summary available.'),
      evidence: payload?.evidence && typeof payload.evidence === 'object'
        ? buildAdminSafeEvidence(payload.evidence)
        : {},
      maskedUserIdentifier: String(payload?.masked_user_identifier || maskEmail(payload?.affected_user_email)),
      allowedActions: Array.isArray(payload?.allowed_actions)
        ? payload.allowed_actions.map((action: any) => String(action))
        : [],
      evidenceAvailable: Boolean(payload?.evidence_available ?? true),
      threatDetected: Boolean(payload?.threat_detected ?? (
        payload?.source_module === 'PCAP Analyzer'
          ? severity === 'critical' || severity === 'high'
          : true
      )),
      summary: sanitizeAdminThreatText(
        payload?.summary || payload?.investigation_summary || payload?.description,
        'Security event summary is available.',
      ),
      scanId: payload?.scan_id !== undefined && payload?.scan_id !== null ? String(payload.scan_id) : null,
      analysisId: payload?.analysis_id !== undefined && payload?.analysis_id !== null ? String(payload.analysis_id) : null,
      auditPreview: Array.isArray(payload?.audit_preview)
        ? payload.audit_preview.map((entry: any) => ({
            label: String(entry?.label ?? 'Audit event'),
            actor: String(entry?.actor ?? 'System'),
            createdAt: entry?.createdAt ? String(entry.createdAt) : null,
          }))
        : [],
    };
  };

  const loadUsers = async () => {
    setUsersLoading(true);
    setUsersError('');

    try {
      const query = new URLSearchParams();
      if (debouncedUserSearch.trim()) query.set('q', debouncedUserSearch.trim());
      if (statusFilter !== 'all') query.set('status', statusFilter);
      if (roleFilter !== 'all') query.set('role', roleFilter);

      const result = await requestAdmin<{ users: any[] }>(
        `/api/admin/users${query.toString() ? `?${query.toString()}` : ''}`,
      );
      setUsers((result.users || []).map(mapAdminUser));
      setSelectedUser((current) => {
        if (!current) return current;
        return (result.users || []).map(mapAdminUser).find((user) => user.id === current.id) || current;
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load users';
      setUsersError(message);
      toast.error(message);
    } finally {
      setUsersLoading(false);
    }
  };

  const loadRoles = async () => {
    setRolesLoading(true);
    setRolesError('');
    try {
      const result = await requestAdmin<{ roles: RoleSummary[] }>('/api/admin/roles');
      setRoles(result.roles || []);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load roles';
      setRolesError(message);
    } finally {
      setRolesLoading(false);
    }
  };

  const loadUserSummary = async () => {
    setSummaryLoading(true);
    setSummaryError('');
    try {
      const result = await requestAdmin<{ summary: AdminUserSummary }>('/api/admin/users/summary');
      setUserSummary(result.summary || {
        total_users: 0,
        active_today: 0,
        active_users: 0,
        active_sessions: 0,
        high_risk_users: 0,
        without_2fa: 0,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load user summary';
      setSummaryError(message);
    } finally {
      setSummaryLoading(false);
    }
  };

  const loadPermissions = async () => {
    setPermissionsLoading(true);
    setPermissionsError('');
    try {
      const result = await requestAdmin<{ permissions: PermissionSummary[] }>('/api/admin/permissions');
      setPermissions(result.permissions || []);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load permissions';
      setPermissionsError(message);
    } finally {
      setPermissionsLoading(false);
    }
  };

  const loadThreats = async () => {
    setThreatsLoading(true);
    setThreatsError('');
    try {
      const query = new URLSearchParams();
      if (debouncedThreatSearch.trim()) query.set('q', debouncedThreatSearch.trim());
      if (threatSeverityFilter !== 'all') query.set('severity', threatSeverityFilter);
      if (threatStatusFilter !== 'all') query.set('status', threatStatusFilter);
      if (threatModuleFilter !== 'all') query.set('module', threatModuleFilter);
      if (threatTimeRangeFilter !== 'all') query.set('range', threatTimeRangeFilter);

      const result = await requestAdmin<{ alerts: any[] }>(
        `/api/admin/threats${query.toString() ? `?${query.toString()}` : ''}`,
      );
      const mappedAlerts = (result.alerts || []).map(mapThreatAlert);
      setThreats(mappedAlerts);
      setSelectedAlert((current) =>
        current ? mappedAlerts.find((alert) => alert.id === current.id) || current : current,
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load threats';
      setThreatsError(message);
      toast.error(message);
    } finally {
      setThreatsLoading(false);
    }
  };

  const loadThreatSummary = async () => {
    setThreatSummaryLoading(true);
    setThreatSummaryError('');
    try {
      const query = new URLSearchParams();
      if (debouncedThreatSearch.trim()) query.set('q', debouncedThreatSearch.trim());
      if (threatSeverityFilter !== 'all') query.set('severity', threatSeverityFilter);
      if (threatStatusFilter !== 'all') query.set('status', threatStatusFilter);
      if (threatModuleFilter !== 'all') query.set('module', threatModuleFilter);
      if (threatTimeRangeFilter !== 'all') query.set('range', threatTimeRangeFilter);

      const result = await requestAdmin<{ summary: ThreatSummary }>(
        `/api/admin/threats/summary${query.toString() ? `?${query.toString()}` : ''}`,
      );
      setThreatSummary(result.summary || {
        total_alerts: 0,
        critical_alerts: 0,
        under_investigation: 0,
        resolved_today: 0,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load threat summary';
      setThreatSummaryError(message);
    } finally {
      setThreatSummaryLoading(false);
    }
  };

  const loadPcapSummary = async () => {
    setPcapSummaryLoading(true);
    setPcapSummaryError('');
    try {
      const result = await requestAdmin<{ summary?: Partial<AdminPcapSummary> }>('/api/admin/pcap/overview?limit=100');
      const summary = result.summary || {};
      setPcapSummary({
        total_jobs: Number(summary.total_jobs || 0),
        failed_jobs: Number(summary.failed_jobs || 0),
        failed_jobs_24h: Number(summary.failed_jobs_24h ?? summary.failed_jobs ?? 0),
        running_jobs: Number(summary.running_jobs || 0),
        queued_jobs: Number(summary.queued_jobs || 0),
        completed_jobs: Number(summary.completed_jobs || 0),
        average_processing_time_seconds:
          summary.average_processing_time_seconds === null ||
          summary.average_processing_time_seconds === undefined
            ? null
            : Number(summary.average_processing_time_seconds),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load PCAP job summary';
      setPcapSummaryError(message);
    } finally {
      setPcapSummaryLoading(false);
    }
  };

  const mapRecentAdminActivity = (payload: any): RecentAdminActivity => {
    const actionType = String(payload?.action_type || '').toLowerCase();
    const moduleName = String(payload?.module || '').trim();
    const label = String(payload?.action_label || payload?.action_type || 'Administrative action').trim();
    const actor = String(payload?.actor_name || payload?.actor_email || 'Admin').trim();
    const status = String(payload?.status || 'success').toLowerCase();
    const severity = String(payload?.severity || 'medium').toLowerCase();

    let icon: React.ElementType = Activity;
    if (actionType.includes('user') || actionType.includes('invite')) icon = UserPlus;
    else if (actionType.includes('role') || moduleName.includes('Roles')) icon = UserCog;
    else if (actionType.includes('alert') || actionType.includes('threat')) icon = ShieldAlert;
    else if (actionType.includes('login') || actionType.includes('session')) icon = Lock;
    else if (actionType.includes('export') || actionType.includes('report')) icon = FileText;
    else if (actionType.includes('pcap')) icon = FileSearch;

    const color = status === 'failed'
      ? 'text-red-400'
      : severity === 'critical' || severity === 'high'
        ? 'text-orange-400'
        : status === 'warning'
          ? 'text-yellow-400'
          : 'text-green-400';
    const text = `${label}${moduleName ? ` in ${moduleName}` : ''}${actor ? ` by ${actor}` : ''}`;

    return {
      id: String(payload?.id || `${label}-${moduleName}-${payload?.created_at || Math.random()}`),
      icon,
      text,
      time: formatRelativeAdminTime(payload?.created_at ? String(payload.created_at) : null),
      color,
    };
  };

  const loadRecentActivity = async () => {
    setRecentActivityLoading(true);
    setRecentActivityError('');
    try {
      const result = await requestAdmin<{ items: any[] }>('/api/admin/audit-logs?limit=10');
      setRecentActivity((result.items || []).slice(0, 5).map(mapRecentAdminActivity));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load recent activity';
      setRecentActivityError(message);
    } finally {
      setRecentActivityLoading(false);
    }
  };

  const buildThreatQueryString = () => {
    const query = new URLSearchParams();
    if (debouncedThreatSearch.trim()) query.set('q', debouncedThreatSearch.trim());
    if (threatSeverityFilter !== 'all') query.set('severity', threatSeverityFilter);
    if (threatStatusFilter !== 'all') query.set('status', threatStatusFilter);
    if (threatModuleFilter !== 'all') query.set('module', threatModuleFilter);
    if (threatTimeRangeFilter !== 'all') query.set('range', threatTimeRangeFilter);
    return query.toString();
  };

  const handleThreatExport = async () => {
    try {
      const query = buildThreatQueryString();
      const response = await fetch(
        `${API_BASE_URL || ''}/api/admin/threats/export${query ? `?${query}` : ''}`,
        buildAdminRequestInit({ method: 'GET' }),
      );

      if (response.status === 401) {
        localStorage.removeItem('sentinel_admin_token');
        navigate('/admin/login');
        return;
      }

      if (!response.ok) {
        let message = `Export failed (${response.status})`;
        try {
          const payload = await response.json();
          message = payload?.message || message;
        } catch {
          // Ignore JSON parsing errors for CSV responses.
        }
        throw new Error(message);
      }

      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      const disposition = response.headers.get('Content-Disposition') || '';
      const matchedFilename = disposition.match(/filename="?([^"]+)"?/i);
      link.href = downloadUrl;
      link.download = matchedFilename?.[1] || 'sentinel-threat-alerts.csv';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
      toast.success('Alerts exported successfully');
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to export alerts');
    }
  };

  const adminInitials = useMemo(() => {
    const source = adminIdentity.displayName || adminIdentity.email || 'Admin';
    const initials = source
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase() || '')
      .join('');
    return initials || source.slice(0, 2).toUpperCase() || 'AD';
  }, [adminIdentity.displayName, adminIdentity.email]);

  useEffect(() => {
    void loadAdminIdentity();
  }, []);

  useEffect(() => {
    setActiveSection(sectionFromSearch(location.search));
  }, [location.search]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setDebouncedUserSearch(userSearch);
    }, 300);

    return () => window.clearTimeout(timeout);
  }, [userSearch]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setDebouncedThreatSearch(threatSearch);
    }, 300);

    return () => window.clearTimeout(timeout);
  }, [threatSearch]);

  useEffect(() => {
    if (activeSection !== 'users') {
      return;
    }
    void loadUsers();
  }, [activeSection, debouncedUserSearch, statusFilter, roleFilter]);

  useEffect(() => {
    if (activeSection !== 'users' && activeSection !== 'overview') {
      return;
    }
    void loadUserSummary();
  }, [activeSection]);

  useEffect(() => {
    if (activeSection !== 'users') {
      return;
    }
    void loadRoles();
    void loadPermissions();
  }, [activeSection]);

  useEffect(() => {
    if (activeSection !== 'alerts' && activeSection !== 'overview') {
      return;
    }
    void loadThreats();
    void loadThreatSummary();
  }, [
    activeSection,
    debouncedThreatSearch,
    threatSeverityFilter,
    threatStatusFilter,
    threatModuleFilter,
    threatTimeRangeFilter,
  ]);

  useEffect(() => {
    if (activeSection !== 'settings') {
      return;
    }
    void loadNotificationPreferences();
  }, [activeSection]);

  useEffect(() => {
    if (activeSection !== 'overview') {
      return;
    }
    void loadRecentActivity();
    void loadPcapSummary();
  }, [activeSection]);

  const roleCards = useMemo(
    () =>
      roles.length > 0
        ? roles.filter((role) => ADMIN_VISIBLE_ROLES.has(role.name))
        : [
            { id: 'Admin', name: 'Admin', description: 'Full access to all features and settings', count: 0 },
            { id: 'User', name: 'User', description: 'Standard access to assigned features', count: 0 },
          ],
    [roles],
  );

  const topAlertTypes = useMemo(() => {
    const counts = threats.reduce<Record<string, number>>((accumulator, alert) => {
      const key = alert.title?.trim() || 'Untitled alert';
      accumulator[key] = (accumulator[key] || 0) + 1;
      return accumulator;
    }, {});

    const sorted = Object.entries(counts)
      .sort((left, right) => right[1] - left[1])
      .slice(0, 4)
      .map(([label, count]) => ({ label, count }));

    return sorted.length > 0
      ? sorted
      : [{ label: 'No alert types available', count: 0 }];
  }, [threats]);

  const severityBreakdown = useMemo(
    () =>
      (['Critical', 'High', 'Medium', 'Low'] as const).map((severity) => ({
        severity,
        count: threats.filter((alert) => alert.severity === severity).length,
      })),
    [threats],
  );

  const alertScopeBreakdown = useMemo(() => {
    const counts = threats.reduce<Record<string, number>>((accumulator, alert) => {
      const key = alert.sourceModule?.trim() || 'Security event';
      accumulator[key] = (accumulator[key] || 0) + 1;
      return accumulator;
    }, {});

    const sorted = Object.entries(counts)
      .sort((left, right) => right[1] - left[1])
      .slice(0, 4)
      .map(([label, count]) => ({ label, count }));

    return sorted.length > 0
      ? sorted
      : [{ label: 'No module activity yet', count: 0 }];
  }, [threats]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'High': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'Medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'Low': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Active': case 'Success': return 'bg-green-500/20 text-green-400 border-green-500/50';
      case 'Suspended': case 'Failed': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'High Risk': return 'bg-red-500/20 text-red-300 border-red-500/50';
      case 'New': case 'Running': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      case 'Acknowledged': case 'Under Investigation': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'False Positive': return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  const getRiskLevelColor = (riskLevel: User['riskLevel']) => {
    switch (riskLevel) {
      case 'High':
        return 'bg-red-500/15 text-red-200 border-red-500/30';
      case 'Medium':
        return 'bg-amber-500/15 text-amber-200 border-amber-500/30';
      default:
        return 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30';
    }
  };

  const getAlertsBadgeColor = (alertsCount: number) => {
    if (alertsCount >= 5) {
      return 'bg-red-500/20 text-red-100 border-red-400/50 shadow-[0_0_0_1px_rgba(248,113,113,0.12),0_10px_25px_rgba(127,29,29,0.18)]';
    }
    if (alertsCount >= 2) return 'bg-amber-500/15 text-amber-200 border-amber-500/30';
    return 'bg-slate-500/15 text-slate-300 border-slate-500/25';
  };

  const getTwoFactorColor = (enabled: boolean) =>
    enabled
      ? 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30'
      : 'bg-red-500/15 text-red-200 border-red-500/30';

  const getUserRowClassName = (user: User) => {
    if (user.riskLevel === 'High' || user.status === 'High Risk') {
      return 'border-red-400/12 bg-red-500/[0.045] shadow-[inset_0_1px_0_rgba(248,113,113,0.04)] hover:bg-red-500/[0.075]';
    }
    if (user.status === 'Under Investigation' || user.alertsCount >= 5) {
      return 'border-amber-400/12 bg-amber-500/[0.04] shadow-[inset_0_1px_0_rgba(251,191,36,0.04)] hover:bg-amber-500/[0.07]';
    }
    return 'border-white/10 hover:bg-white/5';
  };

  const getModuleBadgeColor = (moduleName: Alert['sourceModule']) => {
    switch (moduleName) {
      case 'PCAP Analyzer':
        return 'bg-violet-500/15 text-violet-200 border-violet-500/30';
      case 'Phishing Scanner':
        return 'bg-sky-500/15 text-sky-200 border-sky-500/30';
      case 'Password Checker':
        return 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30';
      case 'File Vault':
        return 'bg-indigo-500/15 text-indigo-200 border-indigo-500/30';
      default:
        return 'bg-fuchsia-500/15 text-fuchsia-200 border-fuchsia-500/30';
    }
  };

  const getThreatRowClassName = (alert: Alert) => {
    if (alert.severity === 'Critical') {
      return 'border-l border-l-red-400/40 bg-red-500/[0.035] hover:bg-red-500/[0.06]';
    }
    if (alert.status === 'Acknowledged') {
      return 'border-l border-l-amber-400/40 bg-amber-500/[0.03] hover:bg-amber-500/[0.055]';
    }
    if ((alert.severity === 'High' || alert.severity === 'Critical') && alert.confidence >= 90) {
      return 'border-l border-l-orange-400/35 bg-orange-500/[0.028] hover:bg-orange-500/[0.05]';
    }
    return 'border-white/10 hover:bg-white/5';
  };

  const sidebarSections = [
    { id: 'overview' as SectionType, label: 'Overview', icon: BarChart3 },
    { id: 'users' as SectionType, label: 'Users & Roles', icon: Users },
    { id: 'alerts' as SectionType, label: 'Threat Management', icon: AlertTriangle },
    { id: 'pcap-analysis' as SectionType, label: 'PCAP Analysis', icon: FileSearch },
    { id: 'security-lab' as SectionType, label: 'Validation Lab', icon: ShieldCheck },
    { id: 'audit-logs' as SectionType, label: 'Admin Audit Trail', icon: FileSearch },
    { id: 'notifications' as SectionType, label: 'Notifications', icon: Bell },
    { id: 'reports' as SectionType, label: 'Reports Center', icon: FileText },
    { id: 'settings' as SectionType, label: 'Settings', icon: Settings },
  ];

  const handleInviteUser = async () => {
    const email = inviteForm.email.trim().toLowerCase();
    const name = inviteForm.name.trim();

    if (!email || !name) {
      toast.error('Enter a name and email to invite the user');
      return;
    }

    try {
      const result = await requestAdmin<{
        message?: string;
        invitation_email_sent?: boolean;
        invite_link?: string | null;
      }>('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({
          name,
          email,
          role: inviteForm.role,
          twoFA: inviteForm.twoFA,
        }),
      });
      if (result.invitation_email_sent === false) {
        toast.warning('Invitation created, but email was not sent', {
          description: result.invite_link
            ? `SMTP failed. Setup link: ${result.invite_link}`
            : result.message || 'Check SMTP settings before sending another email invitation.',
          duration: 12000,
        });
      } else {
        toast.success(result.message || 'Invitation sent successfully');
      }
      setInviteForm({
        name: '',
        email: '',
        role: 'User',
        twoFA: true,
      });
      setIsCreateRoleOpen(false);
      await loadUsers();
      await loadRoles();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to send invitation');
    }
  };

  const handleUserStatusToggle = async (user: User) => {
    const nextStatus = user.status === 'Active' ? 'Suspended' : 'Active';
    try {
      await requestAdmin(`/api/admin/users/${user.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus }),
      });
      toast.success(`${user.name} is now ${nextStatus.toLowerCase()}`);
      await loadUsers();
      await loadRoles();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to update user status');
    }
  };

  const handleUserRefresh = async () => {
    try {
      await loadUsers();
      toast.success('Users data refreshed');
    } catch {
      toast.error('Failed to refresh users');
    }
  };

  const handleEmailUser = (user: User) => {
    window.location.href = `mailto:${encodeURIComponent(user.email)}?subject=${encodeURIComponent(
      'Sentinel AI account support',
    )}`;
  };

  const handleDeleteUser = async (user: User) => {
    const confirmed = window.confirm(
      `Delete ${user.name} permanently? This will remove the user and related admin-visible records.`,
    );

    if (!confirmed) {
      return;
    }

    try {
      await requestAdmin(`/api/admin/users/${user.id}`, {
        method: 'DELETE',
      });

      if (selectedUser?.id === user.id) {
        setSelectedUser(null);
        setIsUserDrawerOpen(false);
      }

      toast.success(`${user.name} deleted successfully`);
      await loadUsers();
      await loadRoles();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to delete user');
    }
  };

  const resetUserFilters = () => {
    setUserSearch('');
    setStatusFilter('all');
    setRoleFilter('all');
  };

  const resetThreatFilters = () => {
    setThreatSearch('');
    setThreatSeverityFilter('all');
    setThreatStatusFilter('all');
    setThreatModuleFilter('all');
    setThreatTimeRangeFilter('7d');
  };

  const logAdminAlertAction = async (
    action: string,
    alert: Alert,
    previousStatus?: Alert['status'],
    newStatus?: Alert['status'],
  ) => {
    try {
      await requestAdmin('/api/admin/threats/audit-action', {
        method: 'POST',
        body: JSON.stringify({
          alert_id: alert.id,
          module: alert.sourceModule,
          action,
          previous_status: previousStatus || alert.status,
          new_status: newStatus || alert.status,
        }),
      });
    } catch {
      // Monitoring should remain available even if audit logging is temporarily unavailable.
    }
  };

  const handleAlertView = (alert: Alert) => {
    setSelectedAlert(alert);
    setIsAlertDrawerOpen(true);
    void logAdminAlertAction(
      primaryAlertViewAction(alert) === 'view-report' ? 'report_viewed' : 'evidence_viewed',
      alert,
    );
  };

  const handleAlertAction = (action: string, alert: Alert) => {
    const normalizedStatus: Alert['status'] =
      action === 'false-positive'
        ? 'False Positive'
        : 'Acknowledged';
    const previousStatus = alert.status;

    setThreats((current) =>
      current.map((item) =>
        item.id === alert.id
          ? {
              ...item,
              status: normalizedStatus,
            }
          : item,
      ),
    );
    setSelectedAlert((current) =>
      current?.id === alert.id
        ? {
            ...current,
            status: normalizedStatus,
          }
          : current,
    );
    void logAdminAlertAction(
      action === 'false-positive' ? 'marked_false_positive' : 'acknowledged',
      alert,
      previousStatus,
      normalizedStatus,
    );
    toast.success(`Security event marked as ${normalizedStatus.toLowerCase()}`);
  };

  const handleJobAction = (action: string, job: Job) => {
    toast.success(`Job "${job.name}" ${action}`);
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-white">
      {/* Top Header */}
      <div className="fixed top-0 left-0 right-0 h-16 bg-[#1E293B] border-b border-white/10 z-30 flex items-center justify-between px-6">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-400" />
            <span className="font-semibold">Sentinel AI Admin</span>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <NotificationCenter />

          <div className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.04] px-3 py-1.5">
            <Avatar className="h-9 w-9">
              <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-500 text-xs text-white">
                {adminInitials}
              </AvatarFallback>
            </Avatar>
            <div className="hidden min-w-0 text-left md:block">
              <p className="max-w-[180px] truncate text-sm font-semibold text-white">
                {adminIdentity.displayName}
              </p>
              <p className="max-w-[180px] truncate text-xs text-slate-400">
                {adminIdentity.email || adminIdentity.role}
              </p>
            </div>
          </div>

          <Button
            variant="outline"
            size="sm"
            className="gap-2 border-red-500/30 text-red-400 hover:bg-red-500/10 hover:text-red-300"
            onClick={async () => {
              const adminToken = localStorage.getItem('sentinel_admin_token');
              if (adminToken) {
                try {
                  await fetch(`${API_BASE_URL || ''}/api/admin/auth/logout`, {
                    method: 'POST',
                    headers: { Authorization: `Bearer ${adminToken}` },
                  });
                } catch {
                  // Local sign-out should still proceed if audit logging is unreachable.
                }
              }
              localStorage.removeItem('sentinel_admin_token');
              localStorage.removeItem('sentinel_admin_name');
              localStorage.removeItem('sentinel_admin_email');
              navigate('/admin/login');
            }}
          >
            <LogOut className="w-4 h-4" />
            Logout
          </Button>
        </div>
      </div>

      {/* Sidebar */}
      <div className="fixed left-0 top-16 bottom-0 w-64 bg-[#1E293B] border-r border-white/10 z-20 overflow-y-auto">
        <div className="p-4 space-y-1">
          {sidebarSections.map((section) => (
            <motion.button
              key={section.id}
              onClick={() => setActiveSection(section.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                activeSection === section.id
                  ? 'bg-blue-500/20 text-blue-400 shadow-lg shadow-blue-500/20'
                  : 'text-gray-400 hover:bg-white/5 hover:text-white'
              }`}
              whileHover={{ x: 4 }}
              whileTap={{ scale: 0.98 }}
            >
              <section.icon className="w-5 h-5" />
              <span>{section.label}</span>
            </motion.button>
          ))}
        </div>
      </div>

      {/* Main Content */}
      <div className="ml-64 mt-16 p-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeSection}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
          >
            {/* Overview Section */}
            {activeSection === 'overview' && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-3xl mb-2">Admin Overview</h1>
                  <p className="text-gray-400">Monitor system health, users, and alerts</p>
                </div>

                {/* KPI Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Users className="w-5 h-5 text-blue-400" />
                      <TrendingUp className="w-4 h-4 text-green-400" />
                    </div>
                    <div className="text-3xl mb-1">
                      {summaryLoading ? '...' : formatAdminNumber(userSummary.total_users)}
                    </div>
                    <div className="text-sm text-gray-400">Total Users</div>
                    <div className={`text-xs mt-2 ${summaryError ? 'text-red-300' : 'text-green-400'}`}>
                      {summaryError || 'Live user count'}
                    </div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Activity className="w-5 h-5 text-green-400" />
                      <TrendingUp className="w-4 h-4 text-green-400" />
                    </div>
                    <div className="text-3xl mb-1">
                      {summaryLoading
                        ? '...'
                        : formatAdminNumber(userSummary.active_users ?? userSummary.active_today)}
                    </div>
                    <div className="text-sm text-gray-400">Active Users</div>
                    <div className={`text-xs mt-2 ${summaryError ? 'text-red-300' : 'text-green-400'}`}>
                      {summaryError || `${formatAdminNumber(userSummary.active_sessions)} active session${userSummary.active_sessions === 1 ? '' : 's'} across devices`}
                    </div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                      <TrendingUp className="w-4 h-4 text-red-400" />
                    </div>
                    <div className="text-3xl mb-1">
                      {threatsLoading || threatSummaryLoading ? '...' : formatAdminNumber(openIncidentCount || threatSummary.under_investigation)}
                    </div>
                    <div className="text-sm text-gray-400">Open Incidents</div>
                    <div className={`text-xs mt-2 ${threatsError || threatSummaryError ? 'text-red-300' : 'text-red-400'}`}>
                      {threatsError || threatSummaryError || `+${formatAdminNumber(newIncidentCount)} new in 24h`}
                    </div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <XCircle className="w-5 h-5 text-orange-400" />
                      <TrendingUp className="w-4 h-4 text-orange-400" />
                    </div>
                    <div className="text-3xl mb-1">
                      {pcapSummaryLoading ? '...' : formatAdminNumber(pcapSummary.failed_jobs_24h)}
                    </div>
                    <div className="text-sm text-gray-400">Failed Jobs (24h)</div>
                    <div className={`text-xs mt-2 ${pcapSummaryError ? 'text-red-300' : 'text-orange-400'}`}>
                      {pcapSummaryError || (
                        pcapSummary.failed_jobs_24h > 0
                          ? 'Needs attention'
                          : `${formatAdminNumber(pcapSummary.running_jobs + pcapSummary.queued_jobs)} running or queued`
                      )}
                    </div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Clock className="w-5 h-5 text-purple-400" />
                      <TrendingUp className="w-4 h-4 text-green-400" />
                    </div>
                    <div className="text-3xl mb-1">
                      {threatsLoading ? '...' : formatLatency(averageAlertLatencyMs)}
                    </div>
                    <div className="text-sm text-gray-400">Avg Alert Latency</div>
                    <div className={`text-xs mt-2 ${threatsError ? 'text-red-300' : 'text-green-400'}`}>
                      {threatsError || `${formatAdminNumber(openIncidentCount)} open alert${openIncidentCount === 1 ? '' : 's'} tracked`}
                    </div>
                  </Card>
                </div>

                {/* Charts Row */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="mb-4 flex items-start justify-between gap-3">
                      <div>
                        <h3>Alerts Over Time (7 Days)</h3>
                        <p className="mt-1 text-xs text-gray-400">
                          {threatsLoading
                            ? 'Loading live alerts across all modules...'
                            : threatsError
                              ? threatsError
                              : 'Live severity trend across all modules'}
                        </p>
                      </div>
                      <Badge className="bg-slate-500/15 text-slate-200 border-slate-500/30">
                        {alertsChartData.reduce(
                          (total, day) => total + day.Critical + day.High + day.Medium + day.Low,
                          0,
                        )} alerts
                      </Badge>
                    </div>
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={alertsChartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#ffffff20" />
                        <XAxis dataKey="date" stroke="#9ca3af" />
                        <YAxis stroke="#9ca3af" />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1E293B',
                            border: '1px solid rgba(255,255,255,0.1)',
                            borderRadius: '8px',
                          }}
                        />
                        <Legend />
                        <Line type="monotone" dataKey="Critical" stroke="#ef4444" strokeWidth={2} />
                        <Line type="monotone" dataKey="High" stroke="#f97316" strokeWidth={2} />
                        <Line type="monotone" dataKey="Medium" stroke="#eab308" strokeWidth={2} />
                        <Line type="monotone" dataKey="Low" stroke="#3b82f6" strokeWidth={2} />
                      </LineChart>
                    </ResponsiveContainer>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="mb-4 flex items-start justify-between gap-3">
                      <div>
                        <h3>Alert Sources</h3>
                        <p className="mt-1 text-xs text-gray-400">
                          {threatsLoading
                            ? 'Loading live alert sources...'
                            : threatsError
                              ? threatsError
                              : 'Live source counts for the same 7-day window'}
                        </p>
                      </div>
                      <Badge className="bg-blue-500/15 text-blue-200 border-blue-500/30">
                        {alertSourceData.reduce((total, item) => total + item.count, 0)} alerts
                      </Badge>
                    </div>
                    <ResponsiveContainer width="100%" height={300}>
                      <BarChart data={alertSourceData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#ffffff20" />
                        <XAxis dataKey="source" stroke="#9ca3af" />
                        <YAxis stroke="#9ca3af" />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1E293B',
                            border: '1px solid rgba(255,255,255,0.1)',
                            borderRadius: '8px',
                          }}
                        />
                        <Bar dataKey="count" fill="#3b82f6" radius={[8, 8, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </Card>
                </div>

                {/* Recent Activity and Quick Actions */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="mb-4 flex items-start justify-between gap-3">
                      <div>
                        <h3>Recent Activity</h3>
                        <p className="mt-1 text-xs text-gray-400">Live admin audit events</p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-2"
                        onClick={() => void loadRecentActivity()}
                        disabled={recentActivityLoading}
                      >
                        <RefreshCw className={`w-4 h-4 ${recentActivityLoading ? 'animate-spin' : ''}`} />
                        Refresh
                      </Button>
                    </div>
                    <div className="space-y-3">
                      {recentActivityLoading && recentActivity.length === 0 && (
                        <div className="rounded-lg bg-white/5 p-4 text-sm text-gray-400">
                          Loading recent activity...
                        </div>
                      )}
                      {!recentActivityLoading && recentActivityError && (
                        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
                          {recentActivityError}
                        </div>
                      )}
                      {!recentActivityLoading && !recentActivityError && recentActivity.length === 0 && (
                        <div className="rounded-lg bg-white/5 p-4 text-sm text-gray-400">
                          No admin activity has been recorded yet.
                        </div>
                      )}
                      {recentActivity.map((activity, index) => (
                        <motion.div
                          key={activity.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: index * 0.1 }}
                          className="flex items-start gap-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
                        >
                          <activity.icon className={`w-5 h-5 ${activity.color} mt-0.5`} />
                          <div className="flex-1">
                            <p className="text-sm">{activity.text}</p>
                            <p className="text-xs text-gray-400 mt-1">{activity.time}</p>
                          </div>
                        </motion.div>
                      ))}
                    </div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <h3 className="mb-4">Quick Actions</h3>
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                      <Button
                        className="h-auto py-5 flex flex-col items-center gap-2 bg-blue-500/20 hover:bg-blue-500/30 border-blue-500/50"
                        onClick={() => {
                          setActiveSection('users');
                          setActiveUsersTab('users');
                          setIsCreateRoleOpen(true);
                        }}
                      >
                        <UserPlus className="w-6 h-6" />
                        <span className="text-sm">Invite User</span>
                      </Button>
                      <Button
                        className="h-auto py-5 flex flex-col items-center gap-2 bg-purple-500/20 hover:bg-purple-500/30 border-purple-500/50"
                        onClick={() => {
                          setActiveSection('users');
                          setActiveUsersTab('roles');
                          toast.info('Roles opened', {
                            description: 'Use the Roles tab to review and manage role access.',
                          });
                        }}
                      >
                        <UserCog className="w-6 h-6" />
                        <span className="text-sm">Create Role</span>
                      </Button>
                    </div>
                  </Card>
                </div>
              </div>
            )}

            {/* Users & Roles Section */}
            {activeSection === 'users' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h1 className="text-3xl mb-2">Users & Roles</h1>
                    <p className="text-gray-400">Manage users, roles, and permissions</p>
                  </div>
                  <Dialog open={isCreateRoleOpen} onOpenChange={setIsCreateRoleOpen}>
                    <DialogTrigger asChild>
                      <Button className="gap-2 bg-blue-500 hover:bg-blue-600">
                        <UserPlus className="w-4 h-4" />
                        Invite User
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="bg-[#1E293B] border-white/10 text-white max-w-2xl">
                      <DialogHeader>
                        <DialogTitle>Invite New User</DialogTitle>
                        <DialogDescription className="text-gray-400">
                          Send an invitation to a new user
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4 py-4">
                        <div className="space-y-2">
                          <Label>Name</Label>
                          <Input
                            value={inviteForm.name}
                            onChange={(event) =>
                              setInviteForm((current) => ({ ...current, name: event.target.value }))
                            }
                            placeholder="Sarah Johnson"
                            className="bg-[#0F172A] border-white/10"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>Email</Label>
                          <Input
                            type="email"
                            value={inviteForm.email}
                            onChange={(event) =>
                              setInviteForm((current) => ({ ...current, email: event.target.value }))
                            }
                            placeholder="user@company.com"
                            className="bg-[#0F172A] border-white/10"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>Role</Label>
                          <Select
                            value={inviteForm.role}
                            onValueChange={(value) =>
                              setInviteForm((current) => ({ ...current, role: value }))
                            }
                          >
                            <SelectTrigger className="bg-[#0F172A] border-white/10">
                              <SelectValue placeholder="Select a role" />
                            </SelectTrigger>
                            <SelectContent className="bg-[#1E293B] border-white/10">
                              {roleCards.map((role) => (
                                <SelectItem key={role.id} value={role.name}>
                                  {role.name}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="flex items-center justify-between">
                          <Label>Require 2FA</Label>
                          <Switch
                            checked={inviteForm.twoFA}
                            onCheckedChange={(checked) =>
                              setInviteForm((current) => ({ ...current, twoFA: checked }))
                            }
                          />
                        </div>
                      </div>
                      <DialogFooter>
                        <Button variant="outline" onClick={() => setIsCreateRoleOpen(false)}>Cancel</Button>
                        <Button className="bg-blue-500 hover:bg-blue-600" onClick={() => void handleInviteUser()}>
                          <Send className="w-4 h-4 mr-2" />
                          Send Invitation
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </div>

                <Tabs
                  value={activeUsersTab}
                  onValueChange={(value) =>
                    setActiveUsersTab(value as 'users' | 'roles' | 'permissions')
                  }
                  className="w-full"
                >
                  <TabsList className="bg-[#1E293B] border-white/10">
                    <TabsTrigger value="users">Users</TabsTrigger>
                    <TabsTrigger value="roles">Roles</TabsTrigger>
                    <TabsTrigger value="permissions">Permissions</TabsTrigger>
                  </TabsList>

                  <TabsContent value="users" className="space-y-4">
                    {/* Filters */}
                    <Card className="bg-[#1E293B] border-white/10 p-4">
                      <div className="flex items-center gap-4">
                        <div className="relative flex-1">
                          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                          <Input
                            value={userSearch}
                            onChange={(event) => setUserSearch(event.target.value)}
                            placeholder="Search users..."
                            className="pl-10 bg-[#0F172A] border-white/10"
                          />
                        </div>
                        <Select value={statusFilter} onValueChange={setStatusFilter}>
                          <SelectTrigger className="w-40 bg-[#0F172A] border-white/10">
                            <SelectValue placeholder="Status" />
                          </SelectTrigger>
                          <SelectContent className="bg-[#1E293B] border-white/10">
                            <SelectItem value="all">All Status</SelectItem>
                            <SelectItem value="Active">Active</SelectItem>
                            <SelectItem value="Suspended">Suspended</SelectItem>
                            <SelectItem value="Under Investigation">Under Investigation</SelectItem>
                            <SelectItem value="High Risk">High Risk</SelectItem>
                          </SelectContent>
                        </Select>
                        <Select value={roleFilter} onValueChange={setRoleFilter}>
                          <SelectTrigger className="w-40 bg-[#0F172A] border-white/10">
                            <SelectValue placeholder="Role" />
                          </SelectTrigger>
                          <SelectContent className="bg-[#1E293B] border-white/10">
                            <SelectItem value="all">All Roles</SelectItem>
                            {roleCards.map((role) => (
                              <SelectItem key={role.id} value={role.name}>
                                {role.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Button
                          variant="outline"
                          size="sm"
                          className="gap-2"
                          onClick={resetUserFilters}
                        >
                          <Filter className="w-4 h-4" />
                          Reset
                        </Button>
                      </div>
                    </Card>

                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      {[
                        {
                          label: 'Total Users',
                          value: userSummary.total_users,
                          icon: Users,
                          accent: 'text-sky-300 bg-sky-500/10',
                        },
                        {
                          label: 'Active Today',
                          value: userSummary.active_today,
                          icon: Activity,
                          accent: 'text-emerald-300 bg-emerald-500/10',
                        },
                        {
                          label: 'High Risk Users',
                          value: userSummary.high_risk_users,
                          icon: AlertTriangle,
                          accent: 'text-red-300 bg-red-500/10',
                        },
                        {
                          label: 'Users Without 2FA',
                          value: userSummary.without_2fa,
                          icon: Shield,
                          accent: 'text-amber-300 bg-amber-500/10',
                        },
                      ].map((card) => {
                        const Icon = card.icon;
                        return (
                          <Card key={card.label} className="bg-[#1E293B] border-white/10 px-4 py-3.5">
                            <div className="flex items-center justify-between gap-3">
                              <div className="min-w-0">
                                <p className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                                  {card.label}
                                </p>
                                <p className="mt-2 text-[1.7rem] font-semibold leading-none text-white">
                                  {summaryLoading ? '...' : card.value}
                                </p>
                                {summaryError ? (
                                  <p className="mt-1.5 line-clamp-2 text-xs text-red-300">{summaryError}</p>
                                ) : (
                                  <p className="mt-1.5 text-xs text-slate-400">
                                    Live admin security summary
                                  </p>
                                )}
                              </div>
                              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl ${card.accent}`}>
                                <Icon className="h-4.5 w-4.5" />
                              </div>
                            </div>
                          </Card>
                        );
                      })}
                    </div>

                    {/* Users Table */}
                    <Card className="overflow-x-auto bg-[#1E293B] border-white/10">
                      <Table className="min-w-[1240px]">
                        <TableHeader>
                          <TableRow className="border-white/10 hover:bg-transparent">
                            <TableHead>
                              <div className="flex items-center gap-2 cursor-pointer">
                                Name <ArrowUpDown className="w-4 h-4" />
                              </div>
                            </TableHead>
                            <TableHead>Email</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Role</TableHead>
                            <TableHead>Risk Level</TableHead>
                            <TableHead>2FA</TableHead>
                            <TableHead>Alerts</TableHead>
                            <TableHead>Last Login</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {usersLoading && (
                            <TableRow className="border-white/10 hover:bg-transparent">
                              <TableCell colSpan={9} className="py-10 text-center text-gray-400">
                                Loading users...
                              </TableCell>
                            </TableRow>
                          )}
                          {!usersLoading && usersError && (
                            <TableRow className="border-white/10 hover:bg-transparent">
                              <TableCell colSpan={9} className="py-10 text-center text-red-300">
                                {usersError}
                              </TableCell>
                            </TableRow>
                          )}
                          {!usersLoading && !usersError && users.length === 0 && (
                            <TableRow className="border-white/10 hover:bg-transparent">
                              <TableCell colSpan={9} className="py-10 text-center text-gray-400">
                                No users matched the current search and filters.
                              </TableCell>
                            </TableRow>
                          )}
                          {!usersLoading && !usersError && users.map((user) => (
                            <TableRow
                              key={user.id}
                              className={`${getUserRowClassName(user)} cursor-pointer transition-colors`}
                              onClick={() => {
                                setSelectedUser(user);
                                setIsUserDrawerOpen(true);
                              }}
                            >
                              <TableCell>
                                <div className="flex items-center gap-3">
                                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-sm">
                                    {user.name.split(' ').map((n) => n[0]).join('').slice(0, 2)}
                                  </div>
                                  {user.name}
                                </div>
                              </TableCell>
                              <TableCell className="text-gray-400">{user.email}</TableCell>
                              <TableCell>
                                <Badge className={getStatusColor(user.status)}>
                                  {user.status}
                                </Badge>
                              </TableCell>
                              <TableCell>{user.role}</TableCell>
                              <TableCell>
                                <Badge className={getRiskLevelColor(user.riskLevel)}>
                                  {user.riskLevel}
                                </Badge>
                              </TableCell>
                              <TableCell>
                                <Badge className={getTwoFactorColor(user.twoFA)}>
                                  <span className="inline-flex items-center gap-2">
                                    {user.twoFA ? (
                                      <Check className="h-3.5 w-3.5" />
                                    ) : (
                                      <X className="h-3.5 w-3.5" />
                                    )}
                                    {user.twoFA ? 'Enabled' : 'Disabled'}
                                  </span>
                                </Badge>
                              </TableCell>
                              <TableCell>
                                <Badge className={getAlertsBadgeColor(user.alertsCount)}>
                                  {user.alertsCount} alert{user.alertsCount === 1 ? '' : 's'}
                                </Badge>
                              </TableCell>
                              <TableCell className="whitespace-nowrap text-gray-400">{user.lastLogin}</TableCell>
                              <TableCell>
                                <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => void handleUserStatusToggle(user)}
                                  >
                                    {user.status === 'Active' ? (
                                      <Lock className="w-4 h-4" />
                                    ) : (
                                      <Unlock className="w-4 h-4" />
                                    )}
                                  </Button>
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => void handleUserRefresh()}
                                  >
                                    <RefreshCw className="w-4 h-4" />
                                  </Button>
                                  <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                      <Button size="sm" variant="outline">
                                        <MoreVertical className="w-4 h-4" />
                                      </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent
                                      align="end"
                                      className="bg-[#1E293B] border-white/10 text-white"
                                    >
                                      <DropdownMenuItem
                                        className="focus:bg-white/10 focus:text-white"
                                        onClick={() => {
                                          setSelectedUser(user);
                                          setIsUserDrawerOpen(true);
                                        }}
                                      >
                                        <Eye className="w-4 h-4 mr-2" />
                                        View details
                                      </DropdownMenuItem>
                                      <DropdownMenuItem
                                        className="focus:bg-white/10 focus:text-white"
                                        onClick={() => void handleUserStatusToggle(user)}
                                      >
                                        {user.status === 'Active' ? (
                                          <Lock className="w-4 h-4 mr-2" />
                                        ) : (
                                          <Unlock className="w-4 h-4 mr-2" />
                                        )}
                                        {user.status === 'Active' ? 'Lock user' : 'Unlock user'}
                                      </DropdownMenuItem>
                                      <DropdownMenuSeparator className="bg-white/10" />
                                      <DropdownMenuItem
                                        className="focus:bg-white/10 focus:text-white"
                                        onClick={() => void handleUserRefresh()}
                                      >
                                        <RefreshCw className="w-4 h-4 mr-2" />
                                        Refresh data
                                      </DropdownMenuItem>
                                      <DropdownMenuSeparator className="bg-white/10" />
                                      <DropdownMenuItem
                                        className="text-red-300 focus:bg-red-500/10 focus:text-red-200"
                                        onClick={() => void handleDeleteUser(user)}
                                      >
                                        <Trash2 className="w-4 h-4 mr-2" />
                                        Delete user
                                      </DropdownMenuItem>
                                    </DropdownMenuContent>
                                  </DropdownMenu>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </Card>
                  </TabsContent>

                  <TabsContent value="roles" className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {rolesLoading && (
                        <Card className="bg-[#1E293B] border-white/10 p-6 text-gray-400">
                          Loading roles...
                        </Card>
                      )}
                      {!rolesLoading && rolesError && (
                        <Card className="bg-[#1E293B] border-white/10 p-6 text-red-300">
                          {rolesError}
                        </Card>
                      )}
                      {!rolesLoading && !rolesError && roleCards.map((role) => (
                        <Card key={role.id} className="bg-[#1E293B] border-white/10 p-6 hover:border-blue-500/50 transition-colors cursor-pointer">
                          <div className="flex items-center justify-between mb-4">
                            <h3 className="text-xl">{role.name}</h3>
                            <Button size="sm" variant="outline">
                              <Edit className="w-4 h-4" />
                            </Button>
                          </div>
                          <p className="text-sm text-gray-400 mb-4">
                            {role.description || 'Role configuration is available from backend metadata.'}
                          </p>
                          <div className="flex items-center gap-4 text-sm">
                            <div>
                              <span className="text-gray-400">Users: </span>
                              <span className="text-white">{role.count}</span>
                            </div>
                          </div>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="permissions" className="space-y-4">
                    <Card className="bg-[#1E293B] border-white/10 p-6">
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead>
                            <tr className="border-b border-white/10">
                              <th className="text-left py-3 px-4">Permission</th>
                              <th className="text-center py-3 px-4">Admin</th>
                              <th className="text-center py-3 px-4">User</th>
                            </tr>
                          </thead>
                          <tbody>
                            {permissionsLoading && (
                              <tr className="border-b border-white/10">
                                <td colSpan={3} className="py-8 px-4 text-center text-gray-400">
                                  Loading permissions...
                                </td>
                              </tr>
                            )}
                            {!permissionsLoading && permissionsError && (
                              <tr className="border-b border-white/10">
                                <td colSpan={3} className="py-8 px-4 text-center text-red-300">
                                  {permissionsError}
                                </td>
                              </tr>
                            )}
                            {!permissionsLoading && !permissionsError && permissions.map((permission) => (
                              <tr key={permission.key} className="border-b border-white/10">
                                <td className="py-3 px-4">{permission.key}</td>
                                <td className="text-center py-3 px-4">
                                  {permission.admin ? (
                                    <CheckCircle className="w-5 h-5 text-green-400 mx-auto" />
                                  ) : (
                                    <XCircle className="w-5 h-5 text-red-400 mx-auto" />
                                  )}
                                </td>
                                <td className="text-center py-3 px-4">
                                  {permission.user ? (
                                    <CheckCircle className="w-5 h-5 text-green-400 mx-auto" />
                                  ) : (
                                    <XCircle className="w-5 h-5 text-red-400 mx-auto" />
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </Card>
                  </TabsContent>
                </Tabs>
              </div>
            )}

            {/* Alerts & Incidents Section */}
            {activeSection === 'alerts' && (
              <div className="space-y-6">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div>
                    <h1 className="text-3xl mb-2">Threat Management</h1>
                    <p className="text-gray-400">Monitor, review, and resolve security alerts across Sentinel AI modules</p>
                  </div>
                  <div className="flex flex-wrap items-center gap-3">
                    <Button variant="outline" className="gap-2" onClick={() => void handleThreatExport()}>
                      <Download className="h-4 w-4" />
                      Export Alerts
                    </Button>
                    <Button variant="outline" className="gap-2" onClick={() => { void loadThreats(); void loadThreatSummary(); }}>
                      <RefreshCw className="h-4 w-4" />
                      Refresh
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
                  {[
                    { label: 'Total Alerts', value: threatSummary.total_alerts, helper: 'Shared cross-module threat feed', icon: Bell, accent: 'text-sky-300 bg-sky-500/10' },
                    { label: 'Critical Alerts', value: threatSummary.critical_alerts, helper: 'Requires immediate review', icon: AlertTriangle, accent: 'text-red-300 bg-red-500/10' },
                    { label: 'Acknowledged', value: threatSummary.under_investigation, helper: 'Reviewed by admin monitoring', icon: Search, accent: 'text-amber-300 bg-amber-500/10' },
                    { label: 'Acknowledged Today', value: threatSummary.resolved_today, helper: 'Reviewed within the last 24h', icon: CheckCircle, accent: 'text-emerald-300 bg-emerald-500/10' },
                  ].map((card) => {
                    const Icon = card.icon;
                    return (
                      <Card key={card.label} className="bg-[#1E293B] border-white/10 px-4 py-3.5">
                        <div className="flex items-center justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-[11px] uppercase tracking-[0.16em] text-slate-500">{card.label}</p>
                            <p className="mt-2 text-[1.7rem] font-semibold leading-none text-white">
                              {threatSummaryLoading ? '...' : card.value}
                            </p>
                            <p className={`mt-1.5 text-xs ${threatSummaryError ? 'text-red-300' : 'text-slate-400'}`}>
                              {threatSummaryError || card.helper}
                            </p>
                          </div>
                          <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl ${card.accent}`}>
                            <Icon className="h-4.5 w-4.5" />
                          </div>
                        </div>
                      </Card>
                    );
                  })}
                </div>

                <Card className="bg-[#1E293B] border-white/10 p-4">
                  <div className="flex flex-col gap-4 xl:flex-row xl:items-center">
                    <div className="relative flex-1">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                      <Input
                        value={threatSearch}
                        onChange={(event) => setThreatSearch(event.target.value)}
                        placeholder="Search by alert ID, module, IP, file, or event"
                        className="pl-10 bg-[#0F172A] border-white/10"
                      />
                    </div>
                    <div className="flex flex-1 flex-wrap items-center gap-3 xl:flex-nowrap">
                      <Select value={threatSeverityFilter} onValueChange={setThreatSeverityFilter}>
                        <SelectTrigger className="w-full sm:w-40 bg-[#0F172A] border-white/10">
                          <SelectValue placeholder="Severity" />
                        </SelectTrigger>
                        <SelectContent className="bg-[#1E293B] border-white/10">
                          <SelectItem value="all">All Severities</SelectItem>
                          <SelectItem value="Critical">Critical</SelectItem>
                          <SelectItem value="High">High</SelectItem>
                          <SelectItem value="Medium">Medium</SelectItem>
                          <SelectItem value="Low">Low</SelectItem>
                        </SelectContent>
                      </Select>
                      <Select value={threatStatusFilter} onValueChange={setThreatStatusFilter}>
                        <SelectTrigger className="w-full sm:w-44 bg-[#0F172A] border-white/10">
                          <SelectValue placeholder="Status" />
                        </SelectTrigger>
                        <SelectContent className="bg-[#1E293B] border-white/10">
                          <SelectItem value="all">All Statuses</SelectItem>
                          <SelectItem value="New">New</SelectItem>
                          <SelectItem value="Acknowledged">Acknowledged</SelectItem>
                          <SelectItem value="False Positive">False Positive</SelectItem>
                        </SelectContent>
                      </Select>
                      <Select value={threatModuleFilter} onValueChange={setThreatModuleFilter}>
                        <SelectTrigger className="w-full sm:w-44 bg-[#0F172A] border-white/10">
                          <SelectValue placeholder="Module" />
                        </SelectTrigger>
                        <SelectContent className="bg-[#1E293B] border-white/10">
                          <SelectItem value="all">All Modules</SelectItem>
                          <SelectItem value="PCAP Analyzer">PCAP Analyzer</SelectItem>
                          <SelectItem value="Phishing Scanner">Phishing Scanner</SelectItem>
                          <SelectItem value="Password Checker">Password Checker</SelectItem>
                          <SelectItem value="File Vault">File Vault</SelectItem>
                          <SelectItem value="Identity Leak Monitor">Identity Leak Monitor</SelectItem>
                        </SelectContent>
                      </Select>
                      <Select value={threatTimeRangeFilter} onValueChange={setThreatTimeRangeFilter}>
                        <SelectTrigger className="w-full sm:w-36 bg-[#0F172A] border-white/10">
                          <SelectValue placeholder="Time range" />
                        </SelectTrigger>
                        <SelectContent className="bg-[#1E293B] border-white/10">
                          <SelectItem value="24h">Last 24 Hours</SelectItem>
                          <SelectItem value="7d">Last 7 Days</SelectItem>
                          <SelectItem value="30d">Last 30 Days</SelectItem>
                          <SelectItem value="all">All Time</SelectItem>
                        </SelectContent>
                      </Select>
                      <Button variant="outline" size="sm" className="gap-2" onClick={resetThreatFilters}>
                        <Filter className="h-4 w-4" />
                        Reset
                      </Button>
                    </div>
                  </div>
                </Card>

                <Card className="overflow-x-auto bg-[#1E293B] border-white/10">
                  <Table className="min-w-[1160px]">
                    <TableHeader>
                      <TableRow className="border-white/10 hover:bg-transparent">
                        <TableHead>Alert</TableHead>
                        <TableHead>Source Module</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>Time</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {threatsLoading && (
                        <TableRow className="border-white/10 hover:bg-transparent">
                          <TableCell colSpan={7} className="py-10 text-center text-gray-400">Loading alerts...</TableCell>
                        </TableRow>
                      )}
                      {!threatsLoading && threatsError && (
                        <TableRow className="border-white/10 hover:bg-transparent">
                          <TableCell colSpan={7} className="py-10 text-center text-red-300">{threatsError}</TableCell>
                        </TableRow>
                      )}
                      {!threatsLoading && !threatsError && threats.length === 0 && (
                        <TableRow className="border-white/10 hover:bg-transparent">
                          <TableCell colSpan={7} className="py-10 text-center text-gray-400">No alerts matched the current filters.</TableCell>
                        </TableRow>
                      )}
                      {!threatsLoading && !threatsError && threats.map((alert) => (
                        <TableRow
                          key={alert.id}
                          className={`${getThreatRowClassName(alert)} cursor-pointer transition-colors`}
                          onClick={() => handleAlertView(alert)}
                        >
                          <TableCell>
                            <div className="min-w-0">
                              <p className="text-sm font-medium text-white">{alert.title}</p>
                              <p className="mt-1 max-w-[320px] text-sm text-slate-400">{alert.description}</p>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge className={getModuleBadgeColor(alert.sourceModule)}>
                              {alert.sourceModule}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={getSeverityColor(alert.severity)}>{alert.severity}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={getStatusColor(alert.status)}>{alert.status}</Badge>
                          </TableCell>
                          <TableCell>
                            <div className="min-w-[148px]">
                              <div className="flex items-center gap-3">
                                <span className="w-11 text-sm font-semibold tabular-nums text-white">
                                  {alert.confidence}%
                                </span>
                                <div className="h-1.5 flex-1 rounded-full bg-white/10">
                                  <div
                                    className={`h-1.5 rounded-full transition-all ${
                                      alert.confidence >= 90
                                        ? 'bg-red-400'
                                        : alert.confidence >= 75
                                          ? 'bg-amber-400'
                                          : 'bg-emerald-400'
                                    }`}
                                    style={{ width: `${alert.confidence}%` }}
                                  />
                                </div>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell className="whitespace-nowrap text-gray-400">{alert.time}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2" onClick={(event) => event.stopPropagation()}>
                              <Button size="sm" variant="outline" onClick={() => handleAlertView(alert)}>
                                <Eye className="h-4 w-4" />
                              </Button>
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button size="sm" variant="outline">
                                    <MoreVertical className="h-4 w-4" />
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end" className="bg-[#1E293B] border-white/10 text-white">
                                  <DropdownMenuItem className="focus:bg-white/10 focus:text-white" onClick={() => handleAlertView(alert)}>
                                    <Eye className="mr-2 h-4 w-4" />
                                    {primaryAlertViewAction(alert) === 'view-report' ? 'View report' : 'View evidence'}
                                  </DropdownMenuItem>
                                </DropdownMenuContent>
                              </DropdownMenu>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>

                <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
                  <Card className="bg-[#1E293B] border-white/10 p-5 xl:col-span-1">
                    <div className="flex items-center justify-between">
                      <h3 className="text-base font-semibold text-white">Top Alert Types</h3>
                      <AlertCircle className="h-4 w-4 text-slate-400" />
                    </div>
                    <div className="mt-4 space-y-3">
                      {topAlertTypes.map((item) => (
                        <div
                          key={item.label}
                          className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-slate-950/25 px-3 py-2 text-sm"
                        >
                          <span className="min-w-0 flex-1 break-words text-slate-300">{item.label}</span>
                          <span className="shrink-0 font-semibold tabular-nums text-white">
                            {item.count}
                          </span>
                        </div>
                      ))}
                    </div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-5 xl:col-span-1">
                    <div className="flex items-center justify-between">
                      <h3 className="text-base font-semibold text-white">Alerts by Severity</h3>
                      <PieChart className="h-4 w-4 text-slate-400" />
                    </div>
                    <div className="mt-4 space-y-3">
                      {severityBreakdown.map(({ severity, count }) => (
                        <div
                          key={severity}
                          className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-slate-950/25 px-3 py-2 text-sm"
                        >
                          <Badge className={`${getSeverityColor(severity)} shrink-0`}>{severity}</Badge>
                          <span className="shrink-0 font-semibold tabular-nums text-white">{count}</span>
                        </div>
                      ))}
                    </div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-5 xl:col-span-1">
                    <div className="flex items-center justify-between">
                      <h3 className="text-base font-semibold text-white">Alert Scope</h3>
                      <Shield className="h-4 w-4 text-slate-400" />
                    </div>
                    <p className="mt-1 text-xs text-slate-500">Grouped by module without exposing user identifiers.</p>
                    <div className="mt-4 space-y-3">
                      {alertScopeBreakdown.map((item) => (
                        <div
                          key={item.label}
                          className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-slate-950/25 px-3 py-2 text-sm"
                        >
                          <span className="min-w-0 flex-1 break-all text-slate-300">{item.label}</span>
                          <span className="shrink-0 font-semibold tabular-nums text-white">
                            {item.count}
                          </span>
                        </div>
                      ))}
                    </div>
                  </Card>

                </div>
              </div>
            )}

            {/* Modules Section */}
            {activeSection === 'modules' && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-3xl mb-2">Modules</h1>
                  <p className="text-gray-400">Configure security modules and features</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {modules.map((module) => (
                    <motion.div
                      key={module.id}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      <Card className="bg-[#1E293B] border-white/10 p-6 h-full">
                        <div className="flex items-start justify-between mb-4">
                          <div className="p-3 rounded-lg bg-blue-500/20">
                            <module.icon className="w-6 h-6 text-blue-400" />
                          </div>
                          <Switch checked={module.enabled} />
                        </div>
                        <h3 className="mb-2">{module.name}</h3>
                        <p className="text-sm text-gray-400 mb-4">{module.description}</p>
                        <Dialog open={isModuleConfigOpen && selectedModule === module.id} onOpenChange={(open) => {
                          setIsModuleConfigOpen(open);
                          if (!open) setSelectedModule('');
                        }}>
                          <DialogTrigger asChild>
                            <Button
                              variant="outline"
                              className="w-full"
                              onClick={() => setSelectedModule(module.id)}
                            >
                              <Sliders className="w-4 h-4 mr-2" />
                              Configure
                            </Button>
                          </DialogTrigger>
                          <DialogContent className="bg-[#1E293B] border-white/10 text-white max-w-2xl">
                            <DialogHeader>
                              <DialogTitle>Configure {module.name}</DialogTitle>
                              <DialogDescription className="text-gray-400">
                                Adjust settings for this module
                              </DialogDescription>
                            </DialogHeader>
                            <div className="space-y-4 py-4">
                              {module.id === 'password' && (
                                <>
                                  <div className="space-y-2">
                                    <Label>HIBP API Key</Label>
                                    <Input placeholder="Enter API key" className="bg-[#0F172A] border-white/10" />
                                  </div>
                                  <div className="space-y-2">
                                    <Label>Rate Limit (requests/minute)</Label>
                                    <Input type="number" defaultValue="60" className="bg-[#0F172A] border-white/10" />
                                  </div>
                                  <div className="space-y-2">
                                    <Label>Scan Schedule</Label>
                                    <Select>
                                      <SelectTrigger className="bg-[#0F172A] border-white/10">
                                        <SelectValue placeholder="Select schedule" />
                                      </SelectTrigger>
                                      <SelectContent className="bg-[#1E293B] border-white/10">
                                        <SelectItem value="hourly">Hourly</SelectItem>
                                        <SelectItem value="daily">Daily</SelectItem>
                                        <SelectItem value="weekly">Weekly</SelectItem>
                                      </SelectContent>
                                    </Select>
                                  </div>
                                </>
                              )}
                              {module.id === 'file-vault' && (
                                <>
                                  <div className="space-y-2">
                                    <Label>Encryption Algorithm</Label>
                                    <Select defaultValue="aes256">
                                      <SelectTrigger className="bg-[#0F172A] border-white/10">
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent className="bg-[#1E293B] border-white/10">
                                        <SelectItem value="aes128">AES-128</SelectItem>
                                        <SelectItem value="aes256">AES-256</SelectItem>
                                      </SelectContent>
                                    </Select>
                                  </div>
                                  <div className="space-y-2">
                                    <Label>Max File Size (MB)</Label>
                                    <Input type="number" defaultValue="100" className="bg-[#0F172A] border-white/10" />
                                  </div>
                                  <div className="space-y-2">
                                    <Label>Storage Backend</Label>
                                    <Select defaultValue="local">
                                      <SelectTrigger className="bg-[#0F172A] border-white/10">
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent className="bg-[#1E293B] border-white/10">
                                        <SelectItem value="local">Local</SelectItem>
                                        <SelectItem value="s3">Amazon S3</SelectItem>
                                        <SelectItem value="gcs">Google Cloud Storage</SelectItem>
                                      </SelectContent>
                                    </Select>
                                  </div>
                                </>
                              )}
                              {module.id === 'ai-threat' && (
                                <>
                                  <div className="space-y-2">
                                    <Label>Model Version</Label>
                                    <Select defaultValue="v2">
                                      <SelectTrigger className="bg-[#0F172A] border-white/10">
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent className="bg-[#1E293B] border-white/10">
                                        <SelectItem value="v1">v1.0 (Legacy)</SelectItem>
                                        <SelectItem value="v2">v2.0 (Current)</SelectItem>
                                        <SelectItem value="v3">v3.0 (Beta)</SelectItem>
                                      </SelectContent>
                                    </Select>
                                  </div>
                                  <div className="space-y-3">
                                    <div className="flex items-center justify-between">
                                      <Label>Confidence Threshold</Label>
                                      <span className="text-blue-400">75%</span>
                                    </div>
                                    <Slider defaultValue={[75]} max={100} step={5} className="w-full" />
                                  </div>
                                  <div className="flex items-center justify-between">
                                    <Label>Enable Explainability</Label>
                                    <Switch defaultChecked />
                                  </div>
                                </>
                              )}
                            </div>
                            <DialogFooter>
                              <Button variant="outline" onClick={() => {
                                setIsModuleConfigOpen(false);
                                setSelectedModule('');
                              }}>Cancel</Button>
                              <Button className="bg-blue-500 hover:bg-blue-600" onClick={() => {
                                toast.success('Module configuration saved');
                                setIsModuleConfigOpen(false);
                                setSelectedModule('');
                              }}>
                                Save Changes
                              </Button>
                            </DialogFooter>
                          </DialogContent>
                        </Dialog>
                      </Card>
                    </motion.div>
                  ))}
                </div>
              </div>
            )}

            {/* Threat Intel Section */}
            {activeSection === 'threat-intel' && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-3xl mb-2">Threat Intelligence</h1>
                  <p className="text-gray-400">Monitor IOC feeds and malicious indicators</p>
                </div>

                {/* IOC Feed Status */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  {[
                    { name: 'Malicious Domains', count: '1,247', status: 'Online', lastSync: '5 min ago' },
                    { name: 'Malicious URLs', count: '3,456', status: 'Online', lastSync: '5 min ago' },
                    { name: 'File Hashes', count: '892', status: 'Online', lastSync: '10 min ago' },
                    { name: 'IP Addresses', count: '2,134', status: 'Online', lastSync: '15 min ago' },
                  ].map((feed) => (
                    <Card key={feed.name} className="bg-[#1E293B] border-white/10 p-6">
                      <div className="flex items-center justify-between mb-2">
                        <Shield className="w-5 h-5 text-blue-400" />
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                          {feed.status}
                        </Badge>
                      </div>
                      <div className="text-3xl mb-1">{feed.count}</div>
                      <div className="text-sm mb-2">{feed.name}</div>
                      <div className="text-xs text-gray-400">Last sync: {feed.lastSync}</div>
                    </Card>
                  ))}
                </div>

                {/* IOC Search and Table */}
                <Card className="bg-[#1E293B] border-white/10 p-6">
                  <div className="flex items-center gap-4 mb-6">
                    <div className="relative flex-1">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                      <Input placeholder="Search by domain, URL, hash, or IP..." className="pl-10 bg-[#0F172A] border-white/10" />
                    </div>
                    <Button variant="outline" className="gap-2">
                      <Download className="w-4 h-4" />
                      Export CSV
                    </Button>
                  </div>

                  <Table>
                    <TableHeader>
                      <TableRow className="border-white/10 hover:bg-transparent">
                        <TableHead>Indicator</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>First Seen</TableHead>
                        <TableHead>Last Seen</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {[
                        { indicator: 'malicious-site.com', type: 'Domain', confidence: 'High', firstSeen: '2024-10-15', lastSeen: '2 hours ago' },
                        { indicator: 'http://phishing-page.net/login', type: 'URL', confidence: 'Critical', firstSeen: '2024-11-01', lastSeen: '15 min ago' },
                        { indicator: 'a3b5c7d9...', type: 'File Hash', confidence: 'Medium', firstSeen: '2024-09-20', lastSeen: '3 days ago' },
                        { indicator: '192.168.1.100', type: 'IP Address', confidence: 'High', firstSeen: '2024-10-30', lastSeen: '1 hour ago' },
                      ].map((ioc, index) => (
                        <TableRow key={index} className="border-white/10 hover:bg-white/5">
                          <TableCell className="font-mono text-sm">{ioc.indicator}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{ioc.type}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={getSeverityColor(ioc.confidence)}>
                              {ioc.confidence}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-gray-400">{ioc.firstSeen}</TableCell>
                          <TableCell className="text-gray-400">{ioc.lastSeen}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Button size="sm" variant="outline">
                                <Eye className="w-4 h-4" />
                              </Button>
                              <Button size="sm" variant="outline">
                                <Download className="w-4 h-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              </div>
            )}

            {/* PCAP Analysis Admin Control Section */}
            {activeSection === 'pcap-analysis' && <PcapAnalysisAdminControl />}

            {/* Security Validation Lab Section */}
            {activeSection === 'security-lab' && <SecurityValidationLabPage />}

            {/* Jobs & Scheduling Section */}
            {activeSection === 'jobs' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h1 className="text-3xl mb-2">Jobs & Scheduling</h1>
                    <p className="text-gray-400">Manage automated tasks and schedules</p>
                  </div>
                  <Dialog open={isCreateJobOpen} onOpenChange={setIsCreateJobOpen}>
                    <DialogTrigger asChild>
                      <Button className="gap-2 bg-blue-500 hover:bg-blue-600">
                        <Plus className="w-4 h-4" />
                        Create Job
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="bg-[#1E293B] border-white/10 text-white max-w-2xl">
                      <DialogHeader>
                        <DialogTitle>Create New Job</DialogTitle>
                        <DialogDescription className="text-gray-400">
                          Schedule an automated task
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4 py-4">
                        <div className="space-y-2">
                          <Label>Job Name</Label>
                          <Input placeholder="e.g., Daily Breach Scan" className="bg-[#0F172A] border-white/10" />
                        </div>
                        <div className="space-y-2">
                          <Label>Module</Label>
                          <Select>
                            <SelectTrigger className="bg-[#0F172A] border-white/10">
                              <SelectValue placeholder="Select module" />
                            </SelectTrigger>
                            <SelectContent className="bg-[#1E293B] border-white/10">
                              <SelectItem value="password">Password Checker</SelectItem>
                              <SelectItem value="identity-leak">Identity Leak Monitor</SelectItem>
                              <SelectItem value="threat-intel">Threat Intel Sync</SelectItem>
                              <SelectItem value="reports">Monthly Report</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <Label>Schedule Type</Label>
                          <Select>
                            <SelectTrigger className="bg-[#0F172A] border-white/10">
                              <SelectValue placeholder="Select schedule" />
                            </SelectTrigger>
                            <SelectContent className="bg-[#1E293B] border-white/10">
                              <SelectItem value="hourly">Hourly</SelectItem>
                              <SelectItem value="daily">Daily</SelectItem>
                              <SelectItem value="weekly">Weekly</SelectItem>
                              <SelectItem value="monthly">Monthly</SelectItem>
                              <SelectItem value="custom">Custom (Cron)</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="flex items-center justify-between">
                          <Label>Notify on Failure</Label>
                          <Switch defaultChecked />
                        </div>
                      </div>
                      <DialogFooter>
                        <Button variant="outline" onClick={() => setIsCreateJobOpen(false)}>Cancel</Button>
                        <Button className="bg-blue-500 hover:bg-blue-600" onClick={() => {
                          toast.success('Job created successfully');
                          setIsCreateJobOpen(false);
                        }}>
                          Create Job
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </div>

                {/* Jobs Table */}
                <Card className="bg-[#1E293B] border-white/10">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-white/10 hover:bg-transparent">
                        <TableHead>Job Name</TableHead>
                        <TableHead>Module</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Next Run</TableHead>
                        <TableHead>Last Run</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Duration</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {jobs.map((job) => (
                        <TableRow key={job.id} className="border-white/10 hover:bg-white/5">
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Calendar className="w-4 h-4 text-blue-400" />
                              {job.name}
                            </div>
                          </TableCell>
                          <TableCell>{job.module}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{job.type}</Badge>
                          </TableCell>
                          <TableCell className="text-gray-400">{job.nextRun}</TableCell>
                          <TableCell className="text-gray-400">{job.lastRun}</TableCell>
                          <TableCell>
                            <Badge className={getStatusColor(job.status)}>
                              {job.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-gray-400">{job.duration}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => handleJobAction('started manually', job)}
                              >
                                <Play className="w-4 h-4" />
                              </Button>
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => handleJobAction('paused', job)}
                              >
                                <Pause className="w-4 h-4" />
                              </Button>
                              <Button size="sm" variant="outline">
                                <Edit className="w-4 h-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>

                {/* Recent Executions Timeline */}
                <Card className="bg-[#1E293B] border-white/10 p-6">
                  <h3 className="mb-4">Recent Executions</h3>
                  <div className="space-y-4">
                    {[
                      { name: 'Breach Scan Hourly', time: '45 min ago', status: 'Success', duration: '2.3s' },
                      { name: 'Threat Intel Sync', time: '3.5 hours ago', status: 'Success', duration: '12.5s' },
                      { name: 'Monthly Report', time: '2 days ago', status: 'Failed', duration: '45.2s' },
                      { name: 'Identity Leak Scan', time: '1 hour ago', status: 'Success', duration: '12.5s' },
                    ].map((execution, index) => (
                      <div key={index} className="flex items-center gap-4 p-4 rounded-lg bg-white/5">
                        {execution.status === 'Success' ? (
                          <CheckCircle className="w-5 h-5 text-green-400" />
                        ) : (
                          <XCircle className="w-5 h-5 text-red-400" />
                        )}
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <span>{execution.name}</span>
                            <span className="text-sm text-gray-400">{execution.time}</span>
                          </div>
                          <div className="text-sm text-gray-400 mt-1">Duration: {execution.duration}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            )}

            {/* System Health Section */}
            {activeSection === 'system-health' && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-3xl mb-2">System Health</h1>
                  <p className="text-gray-400">Monitor infrastructure and service status</p>
                </div>

                {/* Health Metrics */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Server className="w-5 h-5 text-green-400" />
                      <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                        Healthy
                      </Badge>
                    </div>
                    <div className="text-3xl mb-1">99.9%</div>
                    <div className="text-sm text-gray-400">API Uptime</div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Cpu className="w-5 h-5 text-blue-400" />
                      <TrendingUp className="w-4 h-4 text-green-400" />
                    </div>
                    <div className="text-3xl mb-1">45ms</div>
                    <div className="text-sm text-gray-400">Avg Response Time</div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Activity className="w-5 h-5 text-purple-400" />
                      <TrendingUp className="w-4 h-4 text-green-400" />
                    </div>
                    <div className="text-3xl mb-1">12</div>
                    <div className="text-sm text-gray-400">Queue Length</div>
                  </Card>

                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Database className="w-5 h-5 text-orange-400" />
                      <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                        Connected
                      </Badge>
                    </div>
                    <div className="text-3xl mb-1">5ms</div>
                    <div className="text-sm text-gray-400">DB Latency</div>
                  </Card>
                </div>

                {/* Resource Usage Chart */}
                <Card className="bg-[#1E293B] border-white/10 p-6">
                  <h3 className="mb-4">Resource Usage (24h)</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={[
                      { time: '00:00', cpu: 45, memory: 62, disk: 78 },
                      { time: '04:00', cpu: 38, memory: 58, disk: 78 },
                      { time: '08:00', cpu: 65, memory: 72, disk: 79 },
                      { time: '12:00', cpu: 72, memory: 78, disk: 80 },
                      { time: '16:00', cpu: 68, memory: 75, disk: 81 },
                      { time: '20:00', cpu: 55, memory: 68, disk: 82 },
                      { time: '24:00', cpu: 48, memory: 64, disk: 82 },
                    ]}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#ffffff20" />
                      <XAxis dataKey="time" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1E293B',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: '8px',
                        }}
                      />
                      <Legend />
                      <Area type="monotone" dataKey="cpu" stackId="1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.3} name="CPU %" />
                      <Area type="monotone" dataKey="memory" stackId="2" stroke="#22c55e" fill="#22c55e" fillOpacity={0.3} name="Memory %" />
                      <Area type="monotone" dataKey="disk" stackId="3" stroke="#f97316" fill="#f97316" fillOpacity={0.3} name="Disk %" />
                    </AreaChart>
                  </ResponsiveContainer>
                </Card>

                {/* Services Status */}
                <Card className="bg-[#1E293B] border-white/10 p-6">
                  <h3 className="mb-4">Services</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {[
                      { name: 'Web Server', status: 'Running', uptime: '15d 6h' },
                      { name: 'Worker Queue', status: 'Running', uptime: '15d 6h' },
                      { name: 'Scheduler', status: 'Running', uptime: '15d 6h' },
                      { name: 'Database', status: 'Running', uptime: '30d 12h' },
                      { name: 'Cache (Redis)', status: 'Running', uptime: '30d 12h' },
                      { name: 'Storage', status: 'Running', uptime: '60d 4h' },
                    ].map((service) => (
                      <div key={service.name} className="p-4 rounded-lg bg-white/5 border border-white/10">
                        <div className="flex items-center justify-between mb-2">
                          <span>{service.name}</span>
                          <div className="w-2 h-2 rounded-full bg-green-400"></div>
                        </div>
                        <div className="flex items-center justify-between text-sm">
                          <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                            {service.status}
                          </Badge>
                          <span className="text-gray-400">{service.uptime}</span>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          className="w-full mt-3"
                          onClick={() => toast.info('Service restart initiated')}
                        >
                          <RefreshCw className="w-4 h-4 mr-2" />
                          Restart
                        </Button>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            )}

            {/* Admin Audit Trail Section */}
            {activeSection === 'audit-logs' && <AdminAuditTrailPage />}

            {/* Legacy Audit Logs Section */}
            {false && activeSection === 'audit-logs' && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-3xl mb-2">Audit Logs</h1>
                  <p className="text-gray-400">Track all system and user activities</p>
                </div>

                {/* Filters */}
                <Card className="bg-[#1E293B] border-white/10 p-4">
                  <div className="flex items-center gap-4">
                    <div className="relative flex-1">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                      <Input placeholder="Search audit logs..." className="pl-10 bg-[#0F172A] border-white/10" />
                    </div>
                    <Select>
                      <SelectTrigger className="w-40 bg-[#0F172A] border-white/10">
                        <SelectValue placeholder="Actor" />
                      </SelectTrigger>
                      <SelectContent className="bg-[#1E293B] border-white/10">
                        <SelectItem value="all">All Actors</SelectItem>
                        <SelectItem value="user">Users</SelectItem>
                        <SelectItem value="system">System</SelectItem>
                      </SelectContent>
                    </Select>
                    <Select>
                      <SelectTrigger className="w-40 bg-[#0F172A] border-white/10">
                        <SelectValue placeholder="Action" />
                      </SelectTrigger>
                      <SelectContent className="bg-[#1E293B] border-white/10">
                        <SelectItem value="all">All Actions</SelectItem>
                        <SelectItem value="created">Created</SelectItem>
                        <SelectItem value="updated">Updated</SelectItem>
                        <SelectItem value="deleted">Deleted</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button variant="outline" className="gap-2">
                      <Download className="w-4 h-4" />
                      Export
                    </Button>
                  </div>
                </Card>

                {/* Audit Logs Table */}
                <Card className="bg-[#1E293B] border-white/10">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-white/10 hover:bg-transparent">
                        <TableHead>Time</TableHead>
                        <TableHead>Actor</TableHead>
                        <TableHead>Action</TableHead>
                        <TableHead>IP Address</TableHead>
                        <TableHead>Result</TableHead>
                        <TableHead>Details</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {auditLogs.map((log) => (
                        <TableRow key={log.id} className="border-white/10 hover:bg-white/5">
                          <TableCell className="text-gray-400">{log.time}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {log.actor === 'System' ? (
                                <Server className="w-4 h-4 text-purple-400" />
                              ) : (
                                <Users className="w-4 h-4 text-blue-400" />
                              )}
                              {log.actor}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline">{log.action}</Badge>
                          </TableCell>
                          <TableCell className="font-mono text-sm text-gray-400">{log.ip}</TableCell>
                          <TableCell>
                            <Badge className={getStatusColor(log.result)}>
                              {log.result}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Button size="sm" variant="outline">
                              <Eye className="w-4 h-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              </div>
            )}

            {/* Integrations Section */}
            {activeSection === 'integrations' && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-3xl mb-2">Integrations</h1>
                  <p className="text-gray-400">Connect external services and APIs</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {/* Telegram Integration */}
                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="p-3 rounded-lg bg-blue-500/20">
                        <MessageSquare className="w-6 h-6 text-blue-400" />
                      </div>
                      <div>
                        <h3>Telegram</h3>
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/50 mt-1">
                          Connected
                        </Badge>
                      </div>
                    </div>
                    <p className="text-sm text-gray-400 mb-4">
                      Receive real-time alerts via Telegram bot
                    </p>
                    <div className="space-y-2 text-sm mb-4">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Bot:</span>
                        <span>@SentinelAI_Bot</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Channel:</span>
                        <span>#security-alerts</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Last Check:</span>
                        <span>2 min ago</span>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button variant="outline" className="flex-1" onClick={() => toast.success('Test message sent')}>
                        <Send className="w-4 h-4 mr-2" />
                        Test
                      </Button>
                      <Button variant="outline" onClick={() => toast.info('Opening configuration')}>
                        <Settings className="w-4 h-4" />
                      </Button>
                    </div>
                  </Card>

                  {/* Email Integration */}
                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="p-3 rounded-lg bg-purple-500/20">
                        <Mail className="w-6 h-6 text-purple-400" />
                      </div>
                      <div>
                        <h3>Email (SMTP)</h3>
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/50 mt-1">
                          Connected
                        </Badge>
                      </div>
                    </div>
                    <p className="text-sm text-gray-400 mb-4">
                      Send email notifications for critical alerts
                    </p>
                    <div className="space-y-2 text-sm mb-4">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Server:</span>
                        <span>smtp.company.com</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Port:</span>
                        <span>587 (TLS)</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">From:</span>
                        <span>alerts@company.com</span>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button variant="outline" className="flex-1" onClick={() => toast.success('Test email sent')}>
                        <Send className="w-4 h-4 mr-2" />
                        Test
                      </Button>
                      <Button variant="outline" onClick={() => toast.info('Opening configuration')}>
                        <Settings className="w-4 h-4" />
                      </Button>
                    </div>
                  </Card>

                  {/* Cloud Storage Integration */}
                  <Card className="bg-[#1E293B] border-white/10 p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="p-3 rounded-lg bg-orange-500/20">
                        <Database className="w-6 h-6 text-orange-400" />
                      </div>
                      <div>
                        <h3>Cloud Storage</h3>
                        <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/50 mt-1">
                          Disconnected
                        </Badge>
                      </div>
                    </div>
                    <p className="text-sm text-gray-400 mb-4">
                      Backup files and logs to cloud storage
                    </p>
                    <div className="space-y-2 text-sm mb-4">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Provider:</span>
                        <span>Not configured</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Bucket:</span>
                        <span>-</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Region:</span>
                        <span>-</span>
                      </div>
                    </div>
                    <Button variant="outline" className="w-full" onClick={() => toast.info('Opening configuration')}>
                      <Plus className="w-4 h-4 mr-2" />
                      Configure
                    </Button>
                  </Card>
                </div>
              </div>
            )}

            {/* Reports Section */}
            {activeSection === 'reports' && (
              <ReportsExportCenterPage />
            )}

            {/* Notifications Section */}
            {activeSection === 'notifications' && (
              <NotificationControlCenterPage />
            )}

            {/* Settings Section */}
            {activeSection === 'settings' && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-3xl mb-2">Settings</h1>
                  <p className="text-gray-400">Configure system preferences and security</p>
                </div>

                <Tabs defaultValue="general" className="w-full">
                  <TabsList className="bg-[#1E293B] border-white/10">
                    <TabsTrigger value="general">General</TabsTrigger>
                    <TabsTrigger value="notifications">Notifications</TabsTrigger>
                    <TabsTrigger value="security">Security</TabsTrigger>
                  </TabsList>

                  <TabsContent value="general" className="space-y-4">
                    <Card className="bg-[#1E293B] border-white/10 p-6">
                      <h3 className="mb-4">General Settings</h3>
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <Label>Application Name</Label>
                          <Input defaultValue="Sentinel AI" className="bg-[#0F172A] border-white/10" />
                        </div>
                        <div className="space-y-2">
                          <Label>Base URL</Label>
                          <Input defaultValue="https://sentinel-ai.company.com" className="bg-[#0F172A] border-white/10" />
                        </div>
                        <div className="space-y-2">
                          <Label>Support Email</Label>
                          <Input defaultValue="support@company.com" className="bg-[#0F172A] border-white/10" />
                        </div>
                        <Button className="bg-blue-500 hover:bg-blue-600" onClick={() => toast.success('Settings saved')}>
                          Save Changes
                        </Button>
                      </div>
                    </Card>
                  </TabsContent>

                  <TabsContent value="notifications" className="space-y-4">
                    <Card className="bg-[#1E293B] border-white/10 p-6">
                      <h3 className="mb-4">Notification Preferences</h3>
                      <div className="space-y-6">
                        <div>
                          <h4 className="mb-3">Admin Delivery Channels</h4>
                          <div className="space-y-3">
                            <div className="flex items-center justify-between">
                              <div>
                                <Label>Email</Label>
                                <p className="text-sm text-gray-400">{adminIdentity.email || 'Admin email from the active session'}</p>
                              </div>
                              <Switch
                                checked={notificationPreferences?.emailEnabled ?? true}
                                onCheckedChange={(emailEnabled) => void updateNotificationPreferences({ emailEnabled })}
                              />
                            </div>
                            <div className="flex items-center justify-between">
                              <div>
                                <Label>Telegram</Label>
                                <p className="text-sm text-gray-400">Delivered through the configured Telegram bot.</p>
                              </div>
                              <Switch
                                checked={notificationPreferences?.telegramEnabled ?? true}
                                onCheckedChange={(telegramEnabled) => void updateNotificationPreferences({ telegramEnabled })}
                              />
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                              <div className="space-y-2">
                                <Label>Telegram Chat ID</Label>
                                <Input
                                  value={notificationPreferences?.telegramChatId || ''}
                                  onChange={(event) => void updateNotificationPreferences({ telegramChatId: event.target.value })}
                                  placeholder="Admin or security channel chat ID"
                                  className="bg-[#0F172A] border-white/10"
                                />
                                <p className="text-xs text-gray-400">Admin responder or security group/channel destination. Phone numbers are not used for Telegram delivery.</p>
                              </div>
                            </div>
                          </div>
                        </div>
                        <div>
                          <h4 className="mb-3">Routing Preferences</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                              <Label>Severity Filter</Label>
                              <Select
                                value={notificationPreferences?.severityFilter || 'medium-above'}
                                onValueChange={(severityFilter: NotificationSettings['severityFilter']) => void updateNotificationPreferences({ severityFilter })}
                              >
                                <SelectTrigger className="bg-[#0F172A] border-white/10">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent className="bg-[#1E293B] border-white/10">
                                  <SelectItem value="critical">Critical only</SelectItem>
                                  <SelectItem value="high-critical">High and Critical</SelectItem>
                                  <SelectItem value="medium-above">Medium and above</SelectItem>
                                  <SelectItem value="all">All alerts</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                            <div className="space-y-2">
                              <Label>Alert Frequency</Label>
                              <Select
                                value={notificationPreferences?.frequency || 'hourly'}
                                onValueChange={(frequency: NotificationSettings['frequency']) => void updateNotificationPreferences({ frequency })}
                              >
                                <SelectTrigger className="bg-[#0F172A] border-white/10">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent className="bg-[#1E293B] border-white/10">
                                  <SelectItem value="instant">Instant</SelectItem>
                                  <SelectItem value="15-minutes">Every 15 minutes</SelectItem>
                                  <SelectItem value="hourly">Hourly digest</SelectItem>
                                  <SelectItem value="daily">Daily summary</SelectItem>
                                  <SelectItem value="weekly">Weekly report</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                          </div>
                        </div>
                        <Button
                          className="bg-blue-500 hover:bg-blue-600"
                          disabled={notificationPreferencesLoading || !notificationPreferences}
                          onClick={saveAdminNotificationPreferences}
                        >
                          Save Changes
                        </Button>
                      </div>
                    </Card>
                  </TabsContent>

                  <TabsContent value="security" className="space-y-4">
                    <Card className="bg-[#1E293B] border-white/10 p-6">
                      <h3 className="mb-4">Security Policies</h3>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>Require 2FA for All Users</Label>
                            <p className="text-sm text-gray-400">Enforce two-factor authentication</p>
                          </div>
                          <Switch defaultChecked />
                        </div>
                        <div className="space-y-2">
                          <Label>Session Timeout (minutes)</Label>
                          <Input type="number" defaultValue="60" className="bg-[#0F172A] border-white/10" />
                        </div>
                        <div className="space-y-2">
                          <Label>Password Policy</Label>
                          <Select defaultValue="strong">
                            <SelectTrigger className="bg-[#0F172A] border-white/10">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent className="bg-[#1E293B] border-white/10">
                              <SelectItem value="basic">Basic (8+ chars)</SelectItem>
                              <SelectItem value="strong">Strong (12+ chars, mixed)</SelectItem>
                              <SelectItem value="very-strong">Very Strong (16+ chars, complex)</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <Label>Allowed File Types (File Vault)</Label>
                          <Textarea
                            defaultValue=".pdf, .doc, .docx, .txt, .zip"
                            className="bg-[#0F172A] border-white/10"
                          />
                        </div>
                        <Button className="bg-blue-500 hover:bg-blue-600" onClick={() => toast.success('Security settings saved')}>
                          Save Changes
                        </Button>
                      </div>
                    </Card>
                  </TabsContent>
                </Tabs>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      {/* User Drawer */}
      <Sheet open={isUserDrawerOpen} onOpenChange={setIsUserDrawerOpen}>
        <SheetContent className="w-full max-w-[640px] overflow-y-auto bg-[#1E293B] border-white/10 text-white sm:w-[640px]">
          <SheetHeader>
            <SheetTitle className="text-white">User Details</SheetTitle>
            <SheetDescription className="text-gray-400">
              View and manage user information
            </SheetDescription>
          </SheetHeader>
          {selectedUser && (
            <div className="mt-6 space-y-6">
              <div className="overflow-hidden rounded-3xl border border-white/10 bg-[linear-gradient(135deg,rgba(59,130,246,0.18),rgba(168,85,247,0.14)_45%,rgba(15,23,42,0.95)_100%)]">
                <div className="space-y-5 p-5">
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
                    <div className="flex h-[4.5rem] w-[4.5rem] shrink-0 items-center justify-center rounded-3xl bg-white/10 text-2xl font-semibold text-white shadow-[0_18px_60px_rgba(59,130,246,0.22)]">
                      {selectedUser.name.split(' ').map(n => n[0]).join('')}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0">
                          <h3 className="break-words text-2xl font-semibold tracking-tight text-white">
                            {selectedUser.name}
                          </h3>
                          <p className="mt-1 break-all text-sm text-slate-300">
                            {selectedUser.email}
                          </p>
                        </div>
                        <Badge className={`${getStatusColor(selectedUser.status)} shrink-0`}>
                          {selectedUser.status}
                        </Badge>
                      </div>
                      <div className="mt-4 grid gap-3 sm:grid-cols-3">
                        <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-slate-400">
                            Role
                          </p>
                          <div className="mt-2 flex items-center gap-2 text-sm font-medium text-white">
                            <UserCog className="h-4 w-4 text-sky-300" />
                            <span className="break-words">{selectedUser.role}</span>
                          </div>
                        </div>
                        <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-slate-400">
                            Risk Level
                          </p>
                          <div className="mt-2">
                            <Badge className={getRiskLevelColor(selectedUser.riskLevel)}>
                              {selectedUser.riskLevel}
                            </Badge>
                          </div>
                        </div>
                        <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-slate-400">
                            Alerts
                          </p>
                          <div className="mt-2">
                            <Badge className={getAlertsBadgeColor(selectedUser.alertsCount)}>
                              {selectedUser.alertsCount} active
                            </Badge>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
                  <div className="mb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-sky-500/10 text-sky-200">
                      <Users className="h-[18px] w-[18px]" />
                    </div>
                    <div>
                      <h4 className="text-base font-semibold text-white">Profile Snapshot</h4>
                      <p className="text-sm text-slate-400">
                        Clean overview of identity, access, and account timing.
                      </p>
                    </div>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    {[
                      {
                        label: 'Role',
                        value: selectedUser.role,
                        icon: UserCog,
                      },
                      {
                        label: '2FA Status',
                        value: selectedUser.twoFA ? 'Enabled' : 'Disabled',
                        icon: Shield,
                      },
                      {
                        label: 'Last Login',
                        value: selectedUser.lastLogin,
                        icon: Clock,
                      },
                      {
                        label: 'Linked Accounts',
                        value: selectedUser.linkedAccountsCount.toString(),
                        icon: Link2,
                      },
                    ].map(({ label, value, icon: Icon }) => (
                      <div
                        key={label}
                        className="rounded-2xl border border-white/8 bg-black/20 p-4"
                      >
                        <div className="flex items-start gap-3">
                          <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white/6 text-slate-200">
                            <Icon className="h-4 w-4" />
                          </div>
                          <div className="min-w-0">
                            <p className="text-xs uppercase tracking-[0.16em] text-slate-500">
                              {label}
                            </p>
                            <p className="mt-1 break-words text-sm font-medium leading-6 text-white">
                              {value}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
                  <div className="mb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-emerald-500/10 text-emerald-200">
                      <Activity className="h-[18px] w-[18px]" />
                    </div>
                    <div>
                      <h4 className="text-base font-semibold text-white">Recent Activity</h4>
                      <p className="text-sm text-slate-400">
                        Most relevant admin-side signals for this account.
                      </p>
                    </div>
                  </div>
                  <div className="space-y-3">
                    {selectedUser.recentSecurityEvents.length === 0 && (
                      <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                        <p className="text-sm text-slate-300">
                          No recent security events recorded for this user.
                        </p>
                      </div>
                    )}
                    {selectedUser.recentSecurityEvents.map((activity, index) => (
                      <div
                        key={`${activity.title}-${index}`}
                        className="rounded-2xl border border-white/8 bg-black/20 p-4"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex min-w-0 items-start gap-3">
                            <div
                              className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${
                                activity.severity === 'High'
                                  ? 'bg-red-400'
                                  : activity.severity === 'Medium'
                                    ? 'bg-amber-400'
                                    : 'bg-sky-400'
                              }`}
                            />
                            <div className="min-w-0">
                              <p className="text-sm font-medium leading-6 text-white">
                                {activity.title}
                              </p>
                              <p className="mt-1 text-sm text-slate-400">
                                {activity.description}
                              </p>
                              <p className="mt-2 text-xs uppercase tracking-[0.14em] text-slate-500">
                                {formatRelativeAdminTime(activity.createdAt)}
                              </p>
                            </div>
                          </div>
                          <Badge className={`${getSeverityColor(activity.severity)} shrink-0`}>
                            {activity.severity}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="grid gap-4 lg:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
                  <div className="mb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-amber-500/10 text-amber-200">
                      <ShieldAlert className="h-[18px] w-[18px]" />
                    </div>
                    <div>
                      <h4 className="text-base font-semibold text-white">Risk Summary</h4>
                      <p className="text-sm text-slate-400">
                        Short analyst-facing explanation of current exposure.
                      </p>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <p className="rounded-2xl border border-white/8 bg-black/20 p-4 text-sm leading-7 text-slate-300">
                      {selectedUser.riskSummary}
                    </p>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-[0.16em] text-slate-500">
                          Account Status
                        </p>
                        <div className="mt-2">
                          <Badge className={getStatusColor(selectedUser.status)}>
                            {selectedUser.status}
                          </Badge>
                        </div>
                      </div>
                      <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-[0.16em] text-slate-500">
                          Last Seen
                        </p>
                        <p className="mt-2 text-sm font-medium text-white">
                          {formatRelativeAdminTime(selectedUser.lastLoginAt)}
                        </p>
                      </div>
                      <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-[0.16em] text-slate-500">
                          Member Since
                        </p>
                        <p className="mt-2 text-sm font-medium text-white">
                          {formatAdminDateTime(selectedUser.createdAt)}
                        </p>
                      </div>
                      <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-[0.16em] text-slate-500">
                          Monitoring Scope
                        </p>
                        <p className="mt-2 text-sm font-medium text-white">
                          {selectedUser.alertsCount > 0 ? 'Priority watchlist' : 'Baseline monitoring'}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
                  <div className="mb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-violet-500/10 text-violet-200">
                      <FileSearch className="h-[18px] w-[18px]" />
                    </div>
                    <div>
                      <h4 className="text-base font-semibold text-white">Audit Trail Preview</h4>
                      <p className="text-sm text-slate-400">
                        Recent admin and account actions associated with this identity.
                      </p>
                    </div>
                  </div>
                  <div className="space-y-3">
                    {selectedUser.auditPreview.length === 0 && (
                      <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                        <p className="text-sm text-slate-300">
                          No recent audit items are available for preview.
                        </p>
                      </div>
                    )}
                    {selectedUser.auditPreview.map((item, index) => (
                      <div
                        key={`${item.action}-${index}`}
                        className="rounded-2xl border border-white/8 bg-black/20 p-4"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-white">{item.action}</p>
                            <p className="mt-1 text-sm text-slate-400">{item.summary}</p>
                          </div>
                          <span className="shrink-0 text-xs uppercase tracking-[0.14em] text-slate-500">
                            {formatRelativeAdminTime(item.createdAt)}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Button
                  variant="outline"
                  className="h-11 min-w-0 border-white/10 bg-white/5 text-white hover:bg-white/10"
                  onClick={() => handleEmailUser(selectedUser)}
                >
                  <Mail className="mr-2 h-4 w-4" />
                  Email User
                </Button>
                <Button
                  variant="outline"
                  className="h-11 min-w-0 border-red-500/30 bg-red-500/5 text-red-300 hover:bg-red-500/10 hover:text-red-200"
                  onClick={() => void handleDeleteUser(selectedUser)}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete User
                </Button>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* Alert Drawer */}
      <Sheet open={isAlertDrawerOpen} onOpenChange={setIsAlertDrawerOpen}>
        <SheetContent className="w-full max-w-[620px] overflow-y-auto bg-[#1E293B] border-white/10 text-white sm:w-[620px]">
          <SheetHeader>
            <SheetTitle className="text-white">Security Event Summary</SheetTitle>
            <SheetDescription className="text-gray-400">
              Admin monitoring only. Private user identifiers and profile access are hidden from this view.
            </SheetDescription>
          </SheetHeader>
          {selectedAlert && (
            <div className="mt-6 space-y-6">
              <div className="overflow-hidden rounded-3xl border border-white/10 bg-[linear-gradient(135deg,rgba(248,113,113,0.14),rgba(245,158,11,0.08)_45%,rgba(15,23,42,0.96)_100%)]">
                <div className="space-y-5 p-5">
                  <div className="flex items-start gap-4">
                    <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-red-500/15 text-red-200">
                      <AlertTriangle className="h-6 w-6" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0">
                          <h3 className="text-xl font-semibold text-white">{selectedAlert.title}</h3>
                          <p className="mt-1 text-sm text-slate-300">{selectedAlert.summary || selectedAlert.description}</p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Badge className={getSeverityColor(selectedAlert.severity)}>
                            {selectedAlert.severity}
                          </Badge>
                          <Badge className={getStatusColor(selectedAlert.status)}>
                            {selectedAlert.status}
                          </Badge>
                        </div>
                      </div>
                      <div className="mt-4 flex flex-wrap items-center gap-3 text-sm text-slate-300">
                        <span className="inline-flex items-center gap-2">
                          <Clock className="h-4 w-4 text-amber-300" />
                          {selectedAlert.time}
                        </span>
                        <span className="inline-flex items-center gap-2">
                          <Shield className="h-4 w-4 text-sky-300" />
                          {selectedAlert.sourceModule}
                        </span>
                        <span className="inline-flex items-center gap-2">
                          <span className="font-mono text-xs text-slate-400">ID:</span>
                          <span className="font-mono text-xs text-white">{selectedAlert.id}</span>
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
                <h4 className="mb-3 text-base font-semibold text-white">Limited Evidence View</h4>
                <p className="rounded-2xl border border-white/8 bg-black/20 p-4 text-sm leading-7 text-slate-300">
                  {primaryAlertViewAction(selectedAlert) === 'view-report'
                    ? selectedAlert.summary || selectedAlert.investigationSummary
                    : selectedAlert.investigationSummary}
                </p>
              </div>

              <div className="grid gap-4 lg:grid-cols-[minmax(0,0.94fr)_minmax(0,1.06fr)]">
                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
                  <h4 className="mb-4 text-base font-semibold text-white">Security Event Context</h4>
                  <div className="space-y-3 text-sm">
                    <div className="flex items-start justify-between gap-4">
                      <span className="text-slate-400">Module</span>
                      <span className="text-right text-white">{selectedAlert.sourceModule}</span>
                    </div>
                    <div className="flex items-start justify-between gap-4">
                      <span className="text-slate-400">{selectedAlert.sourceModule === 'PCAP Analyzer' ? 'Analysis ID' : 'Scan ID'}</span>
                      <span className="text-right font-mono text-xs text-white">{selectedAlert.analysisId || selectedAlert.scanId || selectedAlert.id}</span>
                    </div>
                    <div className="flex items-start justify-between gap-4">
                      <span className="text-slate-400">Risk Score</span>
                      <span className="text-right text-white">{selectedAlert.confidence}%</span>
                    </div>
                    <div className="flex items-start justify-between gap-4">
                      <span className="text-slate-400">Timestamp</span>
                      <span className="text-right text-white">{selectedAlert.time}</span>
                    </div>
                    <div className="rounded-2xl border border-blue-400/20 bg-blue-500/10 p-3 text-xs leading-5 text-blue-100">
                      User identifiers and private profile data are hidden in this admin monitoring view.
                    </div>
                  </div>
                </div>

                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
                  <h4 className="mb-4 text-base font-semibold text-white">
                    {primaryAlertViewAction(selectedAlert) === 'view-report' ? 'Report Summary' : 'Safe Evidence'}
                  </h4>
                  <div className="space-y-3">
                    <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-slate-400">Confidence Score</span>
                        <Badge className={selectedAlert.confidence >= 90 ? 'bg-red-500/20 text-red-200 border-red-500/40' : 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30'}>
                          {selectedAlert.confidence}%
                        </Badge>
                      </div>
                    </div>
                    {Object.entries(selectedAlert.evidence).length === 0 && (
                      <div className="rounded-2xl border border-white/8 bg-black/20 p-4 text-sm text-slate-300">
                        No structured evidence fields are available for this security event.
                      </div>
                    )}
                    {Object.entries(selectedAlert.evidence)
                      .filter(([key, value]) => isAdminSafeEvidenceEntry(key, value))
                      .map(([key, value]) => (
                      <div key={key} className="flex items-start justify-between gap-4 rounded-2xl border border-white/8 bg-black/20 p-4 text-sm">
                        <span className="text-slate-400">{key}</span>
                        <span className="text-right text-white">{String(value)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
                <h4 className="mb-4 text-base font-semibold text-white">Audit Trail Preview</h4>
                <div className="space-y-3">
                  {selectedAlert.auditPreview.length === 0 && (
                    <div className="rounded-2xl border border-white/8 bg-black/20 p-4 text-sm text-slate-300">
                      No audit activity is available for this alert yet.
                    </div>
                  )}
                  {selectedAlert.auditPreview.map((entry, index) => (
                    <div key={`${entry.label}-${index}`} className="rounded-2xl border border-white/8 bg-black/20 p-4">
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <p className="text-sm font-medium text-white">{entry.label}</p>
                          <p className="mt-1 text-sm text-slate-400">{entry.actor}</p>
                        </div>
                        <span className="text-xs uppercase tracking-[0.14em] text-slate-500">
                          {formatRelativeAdminTime(entry.createdAt)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
};

export default AdminConsolePage;
