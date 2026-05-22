import React, { ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'motion/react';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  AlertTriangle,
  Activity,
  Shield, 
  Key, 
  FileText, 
  Globe, 
  Eye, 
  MessageCircle, 
  Settings, 
  User,
  Menu,
  FileSearch,
  ChevronDown,
  LoaderCircle,
  LogOut,
  ShieldAlert,
  CalendarRange,
} from 'lucide-react';
import { Button } from './ui/button';
import { Avatar, AvatarFallback } from './ui/avatar';
import { NotificationCenter } from './NotificationCenter';
import { toast } from 'sonner';
import { initializeAudioContext } from '../utils/soundNotifications';
import { useLanguage } from '../contexts/LanguageContext';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from './ui/alert-dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import {
  clearRecentPcapAlertSessionCache,
  normalizeDashboardPcapAlert,
  persistRecentPcapAlertCache,
  setActiveRecentPcapAlertScopeForUser,
  RECENT_PCAP_ALERT_EVENT,
  RECENT_PCAP_ALERT_UPDATED_AT_KEY,
} from '../utils/recentPcapAlerts';
import {
  clearLocalAuthSession,
  persistEmergencyModeState,
} from '../utils/authSession';

interface LayoutProps {
  children: ReactNode;
  hideSearch?: boolean;
  hideChrome?: boolean;
}

export function Layout({ children, hideChrome = false }: LayoutProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const isChatbotPage = location.pathname.startsWith('/chatbot');
  const { t, isRtl } = useLanguage();
  const [currentUser, setCurrentUser] = useState<{ full_name?: string; email?: string } | null>(null);
  const [isEmergencyDialogOpen, setIsEmergencyDialogOpen] = useState(false);
  const [isEmergencyActivating, setIsEmergencyActivating] = useState(false);
  const [securityTiming, setSecurityTiming] = useState({
    autoLockMinutes: 15,
    sessionTimeoutMinutes: 30,
  });
  const [isSessionLocked, setIsSessionLocked] = useState(false);
  const autoLockTimerRef = useRef<number | null>(null);
  const sessionTimeoutTimerRef = useRef<number | null>(null);

  const sidebarItems = [
    { id: 'dashboard', path: '/dashboard', icon: Shield, label: t('layout.nav.dashboard'), color: 'text-blue-400' },
    { id: 'password-checker', path: '/password-checker', icon: Key, label: t('layout.nav.passwordChecker'), color: 'text-green-400' },
    { id: 'file-vault', path: '/file-vault', icon: FileText, label: t('layout.nav.fileVault'), color: 'text-purple-400' },
    { id: 'phishing-scanner', path: '/phishing-scanner', icon: Globe, label: t('layout.nav.phishingScanner'), color: 'text-yellow-400' },
    { id: 'identity-leak-monitor', path: '/identityleak-monitor', icon: Eye, label: t('layout.nav.identityLeakMonitor'), color: 'text-red-400' },
    { id: 'pcap-analyzer', path: '/pcap-analyzer', icon: FileSearch, label: t('layout.nav.pcapAnalyzer'), color: 'text-cyan-400' },

    { id: 'chatbot', path: '/chatbot', icon: MessageCircle, label: t('layout.nav.chatbot'), color: 'text-emerald-400' },
    { id: 'monthly-reports', path: '/monthly-reports', icon: CalendarRange, label: 'Monthly Reports', color: 'text-amber-400' },
    { id: 'user-activity-logs', path: '/user-activity-logs', icon: Activity, label: 'User Activity Logs', color: 'text-sky-300' },
    { id: 'settings', path: '/settings', icon: Settings, label: t('layout.nav.settings'), color: 'text-gray-400' },
  ];

  // Guard: Verify authentication via API (checks cookie token)
  useEffect(() => {
    const verifyAuth = async () => {
      const adminToken = localStorage.getItem('sentinel_admin_token');
      if (adminToken) {
        // Admin is authenticated via localStorage
        return;
      }

      // Check if we have a user token flag
      const userTokenFlag = localStorage.getItem('sentinel_auth_token');
      if (!userTokenFlag) {
        navigate('/login');
        return;
      }

      // Verify auth via API - try both cookie and Bearer token
      try {
        const API_BASE_URL = import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');
        const token = localStorage.getItem('sentinel_auth_token');
        
        console.log('Layout: Verifying auth, token exists:', !!token);
        console.log('Layout: Token value (first 20 chars):', token ? token.substring(0, 20) + '...' : 'none');
        
        // Prepare headers - use Bearer token if we have one
        const headers: HeadersInit = {
          'Content-Type': 'application/json',
        };
        
        // If token is not "cookie_based", add it as Bearer token
        if (token && token !== 'cookie_based') {
          headers['Authorization'] = `Bearer ${token}`;
          console.log('Layout: Sending Authorization header');
        } else {
          console.log('Layout: No Bearer token, relying on cookies');
        }
        
        console.log('Layout: Making request to /api/auth/me with headers:', Object.keys(headers));
        
        const response = await fetch(`${API_BASE_URL || ''}/api/auth/me`, {
          method: 'GET',
          credentials: 'include', // Send cookies if available
          headers: headers,
        });

        console.log('Layout: Response status:', response.status);
        console.log('Layout: Response ok:', response.ok);

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          console.error('Layout: Auth failed:', errorData);
          if (response.status === 423) {
            persistEmergencyModeState({
              message:
                typeof errorData?.message === 'string' && errorData.message.trim()
                  ? errorData.message
                  : 'Emergency Mode activated. All sessions were signed out and your account is temporarily protected.',
              panicModeUntil:
                typeof errorData?.panic_mode_until === 'string'
                  ? errorData.panic_mode_until
                  : null,
            });
            clearLocalAuthSession();
            setCurrentUser(null);
            navigate('/emergency-locked', { replace: true });
            return;
          }
          if (response.status === 401) {
            // Confirmed auth failure only: clear session and redirect.
            clearLocalAuthSession();
            navigate('/login', { replace: true });
          }
          return;
        }
        
        // If OK, user is authenticated
        const data = await response.json();
        console.log('Layout: Auth successful, user:', data.user?.email);
        if (data.success && data.user) {
          setActiveRecentPcapAlertScopeForUser({
            id: data.user.id,
            email: data.user.email,
          });
          setSecurityTiming({
            autoLockMinutes:
              typeof data.user.auto_lock_minutes === 'number'
                ? data.user.auto_lock_minutes
                : 15,
            sessionTimeoutMinutes:
              typeof data.user.session_timeout_minutes === 'number'
                ? data.user.session_timeout_minutes
                : 30,
          });
          if (data.user.email) {
            localStorage.setItem('userEmail', data.user.email);
          }
          setCurrentUser({
            full_name: data.user.full_name || '',
            email: data.user.email || '',
          });
          // Auth verified - user is logged in
          return;
        } else {
          // Unexpected response format
          console.error('Layout: Unexpected response format:', data);
          clearLocalAuthSession();
          setCurrentUser(null);
          navigate('/login', { replace: true });
        }
      } catch (err) {
        console.error('Layout: Auth verification error:', err);
        // Keep the current session on transient failures instead of forcing logout.
      }
    };

    verifyAuth();
  }, [navigate]);

  useEffect(() => {
    const handleProfileUpdated = (event: Event) => {
      const customEvent = event as CustomEvent<{ full_name?: string; email?: string }>;
      const detail = customEvent.detail;
      if (!detail) {
        return;
      }

      setCurrentUser((prev) => ({
        full_name:
          typeof detail.full_name === 'string'
            ? detail.full_name
            : prev?.full_name || '',
        email:
          typeof detail.email === 'string'
            ? detail.email
            : prev?.email || '',
      }));

      if (typeof detail.email === 'string' && detail.email.trim()) {
        localStorage.setItem('userEmail', detail.email);
      }
    };

    window.addEventListener('sentinel-profile-updated', handleProfileUpdated as EventListener);
    return () => {
      window.removeEventListener('sentinel-profile-updated', handleProfileUpdated as EventListener);
    };
  }, []);

  useEffect(() => {
    if (hideChrome || !currentUser?.email) {
      return;
    }

    const clearInactivityTimers = () => {
      if (autoLockTimerRef.current !== null) {
        window.clearTimeout(autoLockTimerRef.current);
      }
      if (sessionTimeoutTimerRef.current !== null) {
        window.clearTimeout(sessionTimeoutTimerRef.current);
      }
    };

    const resetInactivityTimers = () => {
      clearInactivityTimers();

      autoLockTimerRef.current = window.setTimeout(() => {
        setIsSessionLocked(true);
        toast.warning('Session locked', {
          description: 'The dashboard was hidden after inactivity. Unlock to continue.',
        });
      }, securityTiming.autoLockMinutes * 60 * 1000);

      sessionTimeoutTimerRef.current = window.setTimeout(() => {
        void handleLogout(true, 'You were signed out automatically after inactivity.');
      }, securityTiming.sessionTimeoutMinutes * 60 * 1000);
    };

    const handleActivity = () => {
      if (isSessionLocked) {
        return;
      }
      resetInactivityTimers();
    };

    const events: Array<keyof WindowEventMap> = [
      'mousemove',
      'mousedown',
      'keydown',
      'scroll',
      'touchstart',
      'click',
    ];

    events.forEach((eventName) => {
      window.addEventListener(eventName, handleActivity, { passive: true });
    });

    resetInactivityTimers();

    return () => {
      clearInactivityTimers();
      events.forEach((eventName) => {
        window.removeEventListener(eventName, handleActivity);
      });
    };
  }, [
    currentUser?.email,
    hideChrome,
    isSessionLocked,
    securityTiming.autoLockMinutes,
    securityTiming.sessionTimeoutMinutes,
  ]);

  // Initialize audio context on user interaction for autoplay policies
  useEffect(() => {
    const handleInteraction = () => {
      initializeAudioContext();
      // Remove listeners after first interaction
      document.removeEventListener('click', handleInteraction);
      document.removeEventListener('touchstart', handleInteraction);
      document.removeEventListener('keydown', handleInteraction);
    };

    document.addEventListener('click', handleInteraction);
    document.addEventListener('touchstart', handleInteraction);
    document.addEventListener('keydown', handleInteraction);

    return () => {
      document.removeEventListener('click', handleInteraction);
      document.removeEventListener('touchstart', handleInteraction);
      document.removeEventListener('keydown', handleInteraction);
    };
  }, []);

  const handleLogout = async (suppressNavigationToast = false, reason?: string) => {
    try {
      // Call backend logout to clear cookies
      const API_BASE_URL = import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');
      await fetch(`${API_BASE_URL || ''}/api/auth/logout`, {
        method: 'POST',
        credentials: 'include', // Send cookies
      });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      if (reason && !suppressNavigationToast) {
        toast.info('Signed out', {
          description: reason,
        });
      }
      clearLocalAuthSession();
      setIsSessionLocked(false);
      setCurrentUser(null);
      navigate('/login');
    }
  };

  const handleUnlockSession = () => {
    setIsSessionLocked(false);
    toast.success('Session unlocked', {
      description: 'Activity monitoring resumed for this dashboard session.',
    });
  };

  const handleEmergencyModeActivate = async () => {
    if (isEmergencyActivating) {
      return;
    }

    setIsEmergencyActivating(true);

    try {
      const API_BASE_URL = import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');
      const token = localStorage.getItem('sentinel_auth_token');
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (token && token !== 'cookie_based') {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const response = await fetch(`${API_BASE_URL || ''}/api/security/emergency-mode`, {
        method: 'POST',
        credentials: 'include',
        headers,
      });
      const responseClone = response.clone();
      const payload = await response.json().catch(() => ({} as Record<string, unknown>));

      if (!response.ok) {
        const responseText = await responseClone.text().catch(() => '');
        throw new Error(
          (typeof payload?.message === 'string' && payload.message.trim())
            ? payload.message
            : response.status === 405
              ? 'Emergency Mode endpoint is unavailable. Restart the backend and try again.'
              : response.status === 423
                ? 'Emergency Mode is already active for this account.'
                : responseText.trim() && !responseText.trim().startsWith('<!doctype')
                  ? responseText.trim()
                  : 'Emergency Mode could not be activated.'
        );
      }

      const panicModeUntil =
        typeof payload?.panic_mode_until === 'string' ? payload.panic_mode_until : null;
      const successMessage =
        typeof payload?.message === 'string' && payload.message.trim()
          ? payload.message
          : 'Emergency Mode activated. All sessions were signed out and your account is temporarily protected.';

      if (currentUser?.email) {
        const emergencyAlert = normalizeDashboardPcapAlert(
          {
            id: `emergency-mode-${Date.now()}`,
            type: 'pcap_alert',
            title: 'Emergency Mode Activated',
            message:
              'User activated Emergency Mode. All active sessions were revoked and the account was temporarily protected.',
            severity: 'high',
            risk_label: 'Account Protection',
            attack_type: 'Emergency Mode',
            protocol: 'Account',
            source_type: 'account_protection',
            created_at: new Date().toISOString(),
          },
          0
        );
        persistRecentPcapAlertCache([emergencyAlert], {
          updatedAt: new Date().toISOString(),
          user: {
            email: currentUser.email,
          },
        });
        window.dispatchEvent(new CustomEvent(RECENT_PCAP_ALERT_EVENT));
        window.localStorage.setItem(RECENT_PCAP_ALERT_UPDATED_AT_KEY, new Date().toISOString());
      }

      persistEmergencyModeState({
        message: successMessage,
        panicModeUntil,
      });

      toast.success('Emergency Mode activated', {
        description: 'All sessions were revoked and the account is now temporarily protected.',
      });

      setIsEmergencyDialogOpen(false);
      clearLocalAuthSession();
      setCurrentUser(null);
      navigate('/emergency-locked', { replace: true });
    } catch (error) {
      toast.error('Activation failed', {
        description: error instanceof Error ? error.message : 'Emergency Mode could not be activated.',
      });
    } finally {
      setIsEmergencyActivating(false);
    }
  };

  const userIdentity = useMemo(() => {
    const fullName = currentUser?.full_name?.trim() || '';
    const email = currentUser?.email?.trim() || '';

    if (fullName) {
      return {
        displayName: fullName,
        subLabel: email || t('layout.userFallbackSession'),
      };
    }

    if (email) {
      return {
        displayName: email,
        subLabel: t('layout.userFallbackSession'),
      };
    }

    return {
      displayName: t('layout.userFallbackName'),
      subLabel: t('layout.userFallbackSession'),
    };
  }, [currentUser?.email, currentUser?.full_name, t]);

  const userDisplayName = userIdentity.displayName;
  const userSubLabel = userIdentity.subLabel;
  const userInitials =
    userDisplayName
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase() || '')
      .join('') || (currentUser?.email?.trim()?.slice(0, 2).toUpperCase() || 'AC');

  return (
    <div className={`min-h-screen bg-[#0B0F19] text-white ${hideChrome ? '' : 'flex'}`} dir={isRtl ? 'rtl' : 'ltr'}>
      {!hideChrome && (
        <>
          {/* Sidebar */}
          <motion.aside 
            className="w-64 bg-[#111827] border-r border-gray-700 flex flex-col"
            initial={{ x: -100, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.5 }}
          >
            {/* Logo */}
            <div className="p-6 border-b border-gray-700">
              <motion.div 
                className={`flex items-center ${isRtl ? 'space-x-reverse space-x-3' : 'space-x-3'}`}
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                transition={{ duration: 0.3 }}
              >
                <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-cyan-400 rounded-lg flex items-center justify-center">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h1 className="font-bold text-xl">Sentinel AI</h1>
                  <p className="text-xs text-gray-400">{t('layout.brandSubtitle')}</p>
                </div>
              </motion.div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-4 space-y-2">
              {sidebarItems.map((item, index) => {
                const Icon = item.icon;
                const isActive = location.pathname.startsWith(item.path);
                
                return (
                  <motion.div
                    key={item.id}
                    initial={{ x: -50, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ duration: 0.3, delay: index * 0.1 }}
                  >
                    <Button
                      variant={isActive ? "secondary" : "ghost"}
                      className={`w-full justify-start p-3 h-auto transition-all duration-200 ${
                        isActive 
                          ? 'bg-gradient-to-r from-blue-600 to-blue-700 text-white border border-blue-500 cyber-glow' 
                          : 'text-gray-300 hover:text-white hover:bg-gray-800'
                      }`}
                      onClick={() => navigate(item.path)}
                    >
                      <Icon className={`w-5 h-5 mr-3 ${item.color}`} />
                      <span>{item.label}</span>
                    </Button>
                  </motion.div>
                );
              })}
            </nav>

            {/* User Info */}
            <div className="p-4 border-t border-gray-700">
              <div className={`flex items-center p-3 rounded-lg bg-gray-800/50 ${isRtl ? 'space-x-reverse space-x-3' : 'space-x-3'}`}>
                <Avatar className="w-8 h-8">
                  <AvatarFallback className="bg-gradient-to-r from-blue-500 to-cyan-400 text-white">
                    {userInitials}
                  </AvatarFallback>
                </Avatar>
                <div className="flex-1">
                  <p className="text-sm font-medium">{userDisplayName}</p>
                  <p className="text-xs text-gray-400 truncate">{userSubLabel}</p>
                </div>
              </div>
            </div>
          </motion.aside>

          {/* Main Content */}
          <div className="min-w-0 flex-1 flex flex-col overflow-x-hidden">
            {/* Header */}
            <motion.header 
              className="relative z-[220] overflow-visible bg-[#111827] border-b border-gray-700 p-4"
              initial={{ y: -50, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 0.5 }}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <Button variant="ghost" size="sm" className="md:hidden">
                    <Menu className="w-5 h-5" />
                  </Button>
                </div>

                <div className="relative z-[221] ml-auto flex items-center space-x-4 justify-end">
                  <NotificationCenter />
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="group h-11 rounded-2xl border border-white/5 bg-white/[0.03] px-3 text-slate-100 transition-all hover:border-white/10 hover:bg-white/[0.06]"
                      >
                        <div className="flex items-center gap-3">
                          <Avatar className="h-8 w-8">
                            <AvatarFallback className="bg-gradient-to-r from-blue-500 to-cyan-400 text-xs text-white">
                              {userInitials}
                            </AvatarFallback>
                          </Avatar>
                          <div className="hidden min-w-0 text-left md:block">
                            <p className="truncate text-sm font-medium text-white">{userDisplayName}</p>
                            <p className="truncate text-xs text-slate-400">{userSubLabel}</p>
                          </div>
                          <ChevronDown className="h-4 w-4 text-slate-400 transition-transform group-data-[state=open]:rotate-180" />
                        </div>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent
                      align="end"
                      sideOffset={10}
                      className="w-[344px] rounded-2xl border border-white/10 bg-[#0f1726]/96 p-2 text-slate-100 shadow-[0_24px_60px_rgba(2,6,23,0.45)] backdrop-blur-xl"
                    >
                      <DropdownMenuLabel className="rounded-xl px-3 py-3">
                        <div className="flex items-center gap-3">
                          <Avatar className="h-11 w-11">
                            <AvatarFallback className="bg-gradient-to-r from-blue-500 to-cyan-400 text-white">
                              {userInitials}
                            </AvatarFallback>
                          </Avatar>
                          <div className="min-w-0">
                            <p className="truncate text-sm font-semibold text-white">{userDisplayName}</p>
                            <p className="truncate text-xs font-normal text-slate-400">{userSubLabel}</p>
                          </div>
                        </div>
                      </DropdownMenuLabel>
                      <DropdownMenuSeparator className="my-2 bg-white/8" />
                      <DropdownMenuItem
                        className="group rounded-xl px-3 py-3 text-rose-100 transition-colors focus:bg-rose-500/10 focus:text-rose-50"
                        onSelect={(event) => {
                          event.preventDefault();
                          setIsEmergencyDialogOpen(true);
                        }}
                      >
                        <div className="flex w-full items-start gap-3">
                          <div className="mt-0.5 flex h-10 w-10 items-center justify-center rounded-xl border border-rose-400/20 bg-rose-500/10 shadow-[0_0_24px_rgba(244,63,94,0.08)]">
                            <ShieldAlert className="h-5 w-5 text-rose-200" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="text-sm font-semibold text-rose-100">Emergency Mode</p>
                            <p className="mt-1 text-xs leading-5 text-rose-100/70">
                              Sign out all devices and temporarily protect this account
                            </p>
                          </div>
                          <AlertTriangle className="mt-1 h-4 w-4 text-rose-300/80" />
                        </div>
                      </DropdownMenuItem>
                      <DropdownMenuSeparator className="my-2 bg-white/8" />
                      <DropdownMenuItem
                        className="rounded-xl px-3 py-2.5 text-slate-200 focus:bg-white/5 focus:text-white"
                        onSelect={(event) => {
                          event.preventDefault();
                          handleLogout();
                        }}
                      >
                        <LogOut className="h-4 w-4 text-slate-400" />
                        <span>{t('layout.logout')}</span>
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
            </motion.header>

            {/* Page Content */}
            <main
              className={`relative z-0 min-w-0 p-6 ${isChatbotPage ? '' : 'flex-1 overflow-x-hidden overflow-y-auto'}`}
              style={
                isChatbotPage
                  ? {
                      flex: "0 0 auto",
                      height: "auto",
                      minHeight: "unset",
                      maxHeight: "none",
                      overflow: "visible",
                    }
                  : undefined
              }
            >
              <motion.div
                className={`min-w-0 ${isChatbotPage ? '' : 'min-h-full'}`}
                style={
                  isChatbotPage
                    ? {
                        flex: "0 0 auto",
                        height: "auto",
                        minHeight: "unset",
                        maxHeight: "none",
                        overflow: "visible",
                      }
                    : undefined
                }
                key={location.pathname}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.3 }}
              >
                {children}
              </motion.div>
            </main>
          </div>
        </>
      )}

      {hideChrome && (
        <main className="min-h-screen w-full">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            {children}
          </motion.div>
        </main>
      )}
      {isSessionLocked && !hideChrome ? (
        <div className="fixed inset-0 z-[260] flex items-center justify-center bg-[#0b1120]/88 px-6 backdrop-blur-md">
          <div className="w-full max-w-lg rounded-[28px] border border-white/10 bg-[linear-gradient(180deg,rgba(15,23,38,0.98),rgba(10,15,26,0.98))] p-8 shadow-[0_28px_90px_rgba(2,6,23,0.58)]">
            <div className="flex items-start gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-500/10">
                <Shield className="h-7 w-7 text-cyan-200" />
              </div>
              <div>
                <h2 className="text-2xl font-semibold text-white">Session locked</h2>
                <p className="mt-2 text-sm leading-6 text-slate-300">
                  The dashboard was automatically hidden after {securityTiming.autoLockMinutes} minutes of inactivity.
                  Unlock it to continue, or sign out if you are done.
                </p>
              </div>
            </div>

            <div className="mt-6 rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-4">
              <p className="text-sm text-slate-200">{userDisplayName}</p>
              <p className="mt-1 text-xs text-slate-400">{userSubLabel}</p>
              <p className="mt-3 text-xs text-slate-500">
                Automatic sign-out remains active after {securityTiming.sessionTimeoutMinutes} minutes of inactivity.
              </p>
            </div>

            <div className="mt-6 flex flex-col gap-3 sm:flex-row">
              <Button
                className="flex-1 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-500 text-white hover:brightness-110"
                onClick={handleUnlockSession}
              >
                Unlock session
              </Button>
              <Button
                variant="outline"
                className="flex-1 rounded-xl border-white/10 bg-transparent text-slate-200 hover:bg-white/5 hover:text-white"
                onClick={() => {
                  void handleLogout(true, 'You signed out from the locked session.');
                }}
              >
                Sign out
              </Button>
            </div>
          </div>
        </div>
      ) : null}
      <AlertDialog open={isEmergencyDialogOpen} onOpenChange={setIsEmergencyDialogOpen}>
        <AlertDialogContent className="max-w-xl rounded-[28px] border border-rose-400/16 bg-[linear-gradient(180deg,rgba(15,23,38,0.98),rgba(10,15,26,0.98))] p-0 text-white shadow-[0_32px_90px_rgba(2,6,23,0.58)]">
          <div className="border-b border-white/8 px-7 py-6">
            <div className="flex items-start gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-rose-400/20 bg-rose-500/10">
                <ShieldAlert className="h-7 w-7 text-rose-100" />
              </div>
              <AlertDialogHeader className="text-left">
                <AlertDialogTitle className="text-2xl font-semibold tracking-tight text-white">
                  Activate Emergency Mode
                </AlertDialogTitle>
                <AlertDialogDescription className="text-sm leading-6 text-slate-300">
                  Use this only if you suspect the account has been compromised. This will immediately revoke all active sessions for this account and place it into a temporary protected state.
                </AlertDialogDescription>
              </AlertDialogHeader>
            </div>
          </div>

          <div className="space-y-3 px-7 py-6">
            {[
              'All active sessions for this account will be revoked server-side.',
              'All other devices will be signed out immediately.',
              'This account will be temporarily locked and protected for 15 minutes.',
              'You will need to log in again after the protection window ends.',
            ].map((item) => (
              <div
                key={item}
                className="flex items-start gap-3 rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
                <p className="text-sm leading-6 text-slate-200">{item}</p>
              </div>
            ))}
          </div>

          <AlertDialogFooter className="border-t border-white/8 px-7 py-5 sm:items-center sm:justify-between">
            <AlertDialogCancel
              disabled={isEmergencyActivating}
              className="h-11 min-w-[128px] rounded-xl border-white/10 bg-transparent text-slate-200 hover:bg-white/5 hover:text-white"
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={isEmergencyActivating}
              onClick={(event) => {
                event.preventDefault();
                handleEmergencyModeActivate();
              }}
              className="h-11 min-w-[220px] rounded-xl border border-rose-300/20 bg-[linear-gradient(135deg,#be123c,#ef4444)] px-5 text-white shadow-[0_14px_30px_rgba(190,24,93,0.28)] hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-80"
            >
              {isEmergencyActivating ? (
                <>
                  <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                  Activating...
                </>
              ) : (
                'Activate Emergency Mode'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
