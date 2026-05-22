import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Switch } from '../ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Badge } from '../ui/badge';
import { Separator } from '../ui/separator';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../ui/alert-dialog';
import { useLanguage } from '../../contexts/LanguageContext';
import { toast } from 'sonner';
import {
  Settings,
  User,
  Bell,
  Globe,
  Shield,
  Mail,
  MessageCircle,
  Key,
  Plus,
  Trash2,
  Edit,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Eye,
  EyeOff,
} from 'lucide-react';

type NotificationChannel = {
  id: string;
  type: 'Email' | 'SMS' | string;
  value: string;
  enabled: boolean;
  verified: boolean;
  status?: string;
  description?: string;
  can_test?: boolean;
  can_toggle?: boolean;
  managed_by_server?: boolean;
  icon: React.ComponentType<{ className?: string }>;
};

type BackendNotificationChannel = Omit<NotificationChannel, 'icon'>;
type ApiAttemptResult = {
  response: Response;
  payload: Record<string, any>;
  url: string;
  rawText?: string;
};

type LinkedAccountType = 'primary' | 'secondary' | 'work';
type LinkedAccountStatus = 'verified' | 'pending';

type LinkedAccount = {
  id: number;
  email: string;
  email_normalized: string;
  account_type: LinkedAccountType;
  verification_status: LinkedAccountStatus;
  is_verified: boolean;
  two_factor_enabled: boolean;
  last_access_at: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  is_primary: boolean;
  is_current_auth_email: boolean;
  can_edit_two_factor: boolean;
  can_edit_verification: boolean;
  can_resend_verification?: boolean;
  can_delete: boolean;
  delete_block_reason?: string | null;
};

type LinkedAccountFormState = {
  email: string;
  accountType: Exclude<LinkedAccountType, 'primary'> | LinkedAccountType;
  verificationStatus: LinkedAccountStatus;
  twoFactorEnabled: boolean;
};

export function SettingsPage() {
  const { language, setLanguage, t, isRtl, formatDateTime } = useLanguage();
  const API_BASE_URL = import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');
  const [profileData, setProfileData] = useState({
    fullName: '',
    email: '',
    phone: '',
    jobTitle: '',
    company: '',
  });

  const [securitySettings, setSecuritySettings] = useState({
    twoFactorEnabled: true,
    emailAlerts: true,
    pushNotifications: false,
    weeklyReports: true,
    autoLock: 15,
    sessionTimeout: 30,
  });

  const [notificationChannels, setNotificationChannels] = useState<NotificationChannel[]>([]);
  const [channelsLoading, setChannelsLoading] = useState(true);
  const [channelsError, setChannelsError] = useState('');
  const [channelTogglePendingId, setChannelTogglePendingId] = useState<string | null>(null);
  const [profileSaving, setProfileSaving] = useState(false);
  const [securitySaving, setSecuritySaving] = useState(false);
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [passwordVisibility, setPasswordVisibility] = useState({
    currentPassword: false,
    newPassword: false,
    confirmPassword: false,
  });
  const [linkedAccounts, setLinkedAccounts] = useState<LinkedAccount[]>([]);
  const [accountsLoading, setAccountsLoading] = useState(true);
  const [accountsError, setAccountsError] = useState('');
  const [accountDialogOpen, setAccountDialogOpen] = useState(false);
  const [accountDialogMode, setAccountDialogMode] = useState<'add' | 'edit'>('add');
  const [accountFormSaving, setAccountFormSaving] = useState(false);
  const [selectedAccount, setSelectedAccount] = useState<LinkedAccount | null>(null);
  const [pendingPrimaryAccountId, setPendingPrimaryAccountId] = useState<number | null>(null);
  const [accountVerificationPendingId, setAccountVerificationPendingId] = useState<number | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [accountPendingDelete, setAccountPendingDelete] = useState<LinkedAccount | null>(null);
  const [accountDeleteSaving, setAccountDeleteSaving] = useState(false);
  const [accountForm, setAccountForm] = useState<LinkedAccountFormState>({
    email: '',
    accountType: 'secondary',
    verificationStatus: 'pending',
    twoFactorEnabled: false,
  });
  const handleProfileUpdate = async () => {
    if (profileSaving) {
      return;
    }

    setProfileSaving(true);
    try {
      const result = await requestFirstSuccessful(
        '/api/settings/profile',
        {
          method: 'PATCH',
          credentials: 'include',
          headers: buildAuthedHeaders(),
          body: JSON.stringify({
            full_name: profileData.fullName,
            phone: profileData.phone,
            job_title: profileData.jobTitle,
            company: profileData.company,
          }),
        },
        [200]
      ).catch(async (patchError) => {
        try {
          return await requestFirstSuccessful(
            '/api/settings/profile',
            {
              method: 'POST',
              credentials: 'include',
              headers: buildAuthedHeaders(),
              body: JSON.stringify({
                full_name: profileData.fullName,
                phone: profileData.phone,
                job_title: profileData.jobTitle,
                company: profileData.company,
              }),
            },
            [200]
          );
        } catch {
          throw patchError;
        }
      });

      const payload = result.payload;
      if (!result.response.ok) {
        throw new Error(
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'Profile settings could not be updated.'
        );
      }

      if (payload?.user) {
        setProfileData({
          fullName: payload.user.full_name || '',
          email: payload.user.email || '',
          phone: payload.user.phone || '',
          jobTitle: payload.user.job_title || '',
          company: payload.user.company || '',
        });
        window.dispatchEvent(
          new CustomEvent('sentinel-profile-updated', {
            detail: {
              full_name: payload.user.full_name || '',
              email: payload.user.email || '',
            },
          })
        );
      }

      toast.success('Profile updated', {
        description:
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'Profile information saved successfully.',
      });
    } catch (error) {
      toast.error('Profile update failed', {
        description:
          error instanceof Error ? error.message : 'Profile settings could not be updated.',
      });
    } finally {
      setProfileSaving(false);
    }
  };

  const handleSecuritySettingChange = (setting: string, value: boolean | number) => {
    setSecuritySettings((prev) => ({
      ...prev,
      [setting]: value,
    }));
  };

  const buildAuthedHeaders = () => {
    const token = localStorage.getItem('sentinel_auth_token');
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };

    if (token && token !== 'cookie_based') {
      headers['Authorization'] = `Bearer ${token}`;
    }

    return headers;
  };

  const buildApiCandidates = (path: string) => {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    const candidates = [`${API_BASE_URL || ''}${normalizedPath}`];

    if (normalizedPath.startsWith('/api/')) {
      candidates.push(`${API_BASE_URL || ''}${normalizedPath.replace('/api/', '/')}`);
    }

    return Array.from(new Set(candidates));
  };

  const requestFirstSuccessful = async (
    path: string,
    init: RequestInit,
    successStatuses?: number[]
  ): Promise<ApiAttemptResult> => {
    const candidates = buildApiCandidates(path);
    let lastResult: ApiAttemptResult | null = null;

    for (const url of candidates) {
      try {
        const response = await fetch(url, init);
        const rawText = await response.text().catch(() => '');
        let payload: Record<string, any> = {};

        if (rawText.trim()) {
          try {
            payload = JSON.parse(rawText);
          } catch {
            payload = {};
          }
        }

        lastResult = { response, payload, url, rawText };

        if (successStatuses?.length) {
          if (successStatuses.includes(response.status)) {
            return lastResult;
          }
        } else if (response.ok) {
          return lastResult;
        }
      } catch {
        continue;
      }
    }

    if (lastResult) {
      return lastResult;
    }

    throw new Error('The notification service is currently unreachable.');
  };

  const getSettingsApiErrorMessage = (
    result: ApiAttemptResult | null | undefined,
    fallback: string,
    featureLabel = 'Settings'
  ) => {
    const payloadMessage =
      typeof result?.payload?.message === 'string' && result.payload.message.trim()
        ? result.payload.message
        : '';

    if (payloadMessage) {
      return payloadMessage;
    }

    const status = result?.response?.status;
    if (status === 404 || status === 405) {
      return `${featureLabel} endpoint is unavailable on the current backend process. Restart the backend server with the latest code and try again.`;
    }

    if (status === 401 || status === 403) {
      return 'Your session is no longer authorized. Sign in again and retry.';
    }

    if (!result?.payload || Object.keys(result.payload).length === 0) {
      const responsePreview = result?.rawText?.trim();
      if (responsePreview && status && status >= 400) {
        return `${featureLabel} request failed with HTTP ${status}. The backend returned a non-JSON response, which usually means the server is running older code or an error page intercepted the request. Restart the backend server and try again.`;
      }
    }

    return fallback;
  };

  const channelIconMap = useMemo(
    () => ({
      Email: Mail,
    }),
    []
  );

  const fetchNotificationChannels = async () => {
    setChannelsLoading(true);
    setChannelsError('');

    try {
      const [meResult, channelsResult] = await Promise.allSettled([
        requestFirstSuccessful('/api/auth/me', {
          method: 'GET',
          credentials: 'include',
          headers: buildAuthedHeaders(),
        }),
        requestFirstSuccessful('/api/integrations/channels', {
          method: 'GET',
          credentials: 'include',
          headers: buildAuthedHeaders(),
        }),
      ]);

      let mePayload: Record<string, any> = {};
      let meResponseOk = false;

      if (meResult.status === 'fulfilled') {
        mePayload = meResult.value.payload;
        meResponseOk = meResult.value.response.ok;
      }

      if (meResponseOk && mePayload?.user) {
        setProfileData({
          fullName: mePayload.user.full_name || '',
          email: mePayload.user.email || '',
          phone: mePayload.user.phone || '',
          jobTitle: mePayload.user.job_title || '',
          company: mePayload.user.company || '',
        });
        setSecuritySettings((prev) => ({
          ...prev,
          twoFactorEnabled:
            typeof mePayload.user.is_two_factor_enabled === 'boolean'
              ? mePayload.user.is_two_factor_enabled
              : prev.twoFactorEnabled,
          emailAlerts:
            typeof mePayload.user.email_notifications_enabled === 'boolean'
              ? mePayload.user.email_notifications_enabled
              : prev.emailAlerts,
          autoLock:
            typeof mePayload.user.auto_lock_minutes === 'number'
              ? mePayload.user.auto_lock_minutes
              : prev.autoLock,
          sessionTimeout:
            typeof mePayload.user.session_timeout_minutes === 'number'
              ? mePayload.user.session_timeout_minutes
              : prev.sessionTimeout,
        }));
      }

      let channelsPayload: Record<string, any> = {};
      let channelsResponseOk = false;
      let channelsStatus: number | null = null;

      if (channelsResult.status === 'fulfilled') {
        channelsPayload = channelsResult.value.payload;
        channelsResponseOk = channelsResult.value.response.ok;
        channelsStatus = channelsResult.value.response.status;
      }

      const fallbackChannels: NotificationChannel[] = [
        {
          id: 'email',
          type: 'Email',
          value:
            (typeof mePayload?.user?.email === 'string' && mePayload.user.email.trim()) ||
            'Authenticated account email',
          enabled:
            typeof mePayload?.user?.email_notifications_enabled === 'boolean'
              ? mePayload.user.email_notifications_enabled
              : Boolean(mePayload?.user?.email),
          verified: Boolean(mePayload?.user?.is_email_verified),
          status: mePayload?.user?.email ? 'active' : 'missing',
          description: 'Primary security notifications are sent to the authenticated email address.',
          can_test: false,
          can_toggle: Boolean(mePayload?.user?.email),
          managed_by_server: true,
          icon: Mail,
        },
      ];

      if (!channelsResponseOk) {
        if (meResponseOk && mePayload?.user) {
          setNotificationChannels(fallbackChannels);
          setChannelsError('');
          return;
        }

        throw new Error(
          typeof channelsPayload?.message === 'string' && channelsPayload.message.trim()
            ? channelsPayload.message
            : 'Notification channels could not be loaded.'
        );
      }

      const mappedChannels = Array.isArray(channelsPayload?.channels)
        ? (channelsPayload.channels as BackendNotificationChannel[])
            .filter((channel) => {
              const channelId = String(channel.id || '').toLowerCase();
              return channelId !== 'sms' && channelId !== 'telegram';
            })
            .map((channel) => ({
              ...channel,
              icon: channelIconMap[channel.type as keyof typeof channelIconMap] || Bell,
            }))
        : fallbackChannels;

      setNotificationChannels(mappedChannels);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Notification channels could not be loaded.';
      setChannelsError(message);
      setNotificationChannels([]);
    } finally {
      setChannelsLoading(false);
    }
  };

  const resetAccountForm = () => {
    setAccountForm({
      email: '',
      accountType: 'secondary',
      verificationStatus: 'pending',
      twoFactorEnabled: false,
    });
    setSelectedAccount(null);
    setPendingPrimaryAccountId(null);
  };

  const fetchLinkedAccounts = async () => {
    setAccountsLoading(true);
    setAccountsError('');

    try {
      const result = await requestFirstSuccessful(
        '/api/settings/linked-accounts',
        {
          method: 'GET',
          credentials: 'include',
          headers: buildAuthedHeaders(),
        },
        [200]
      );
      const payload = result.payload;

      if (!result.response.ok) {
        throw new Error(
          getSettingsApiErrorMessage(
            result,
            'Linked accounts could not be loaded.',
            'Linked account management'
          )
        );
      }

      setLinkedAccounts(Array.isArray(payload?.accounts) ? payload.accounts : []);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Linked accounts could not be loaded.';
      setAccountsError(message);
      setLinkedAccounts([]);
    } finally {
      setAccountsLoading(false);
    }
  };

  const openAddAccountDialog = () => {
    resetAccountForm();
    setAccountDialogMode('add');
    setAccountDialogOpen(true);
  };

  const openEditAccountDialog = (account: LinkedAccount) => {
    setSelectedAccount(account);
    setPendingPrimaryAccountId(null);
    setAccountForm({
      email: account.email,
      accountType: account.account_type,
      verificationStatus: account.verification_status,
      twoFactorEnabled: securitySettings.twoFactorEnabled,
    });
    setAccountDialogMode('edit');
    setAccountDialogOpen(true);
  };

  const validateAccountForm = () => {
    const normalizedEmail = accountForm.email.trim().toLowerCase();
    if (!normalizedEmail) {
      return 'Email is required.';
    }

    const emailPattern = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    if (!emailPattern.test(normalizedEmail)) {
      return 'Enter a valid email address.';
    }

    const duplicate = linkedAccounts.find(
      (account) =>
        account.email_normalized === normalizedEmail &&
        account.id !== selectedAccount?.id
    );
    if (duplicate) {
      return 'This email is already linked to your account.';
    }

    return '';
  };

  const handleSetPrimary = async (account: LinkedAccount) => {
    if (pendingPrimaryAccountId || account.is_primary) {
      if (account.is_primary) {
        toast.info('This account is already Primary.');
      }
      return;
    }

    setPendingPrimaryAccountId(account.id);
    try {
      const result = await requestFirstSuccessful(
        `/api/settings/linked-accounts/${account.id}/set-primary`,
        {
          method: 'POST',
          credentials: 'include',
          headers: buildAuthedHeaders(),
        },
        [200]
      );
      const payload = result.payload;

      if (!result.response.ok) {
        throw new Error(
          getSettingsApiErrorMessage(
            result,
            'Primary account could not be updated.',
            'Linked account management'
          )
        );
      }

      if (Array.isArray(payload?.accounts)) {
        setLinkedAccounts(payload.accounts as LinkedAccount[]);
      } else {
        await fetchLinkedAccounts();
      }

      if (selectedAccount?.id === account.id) {
        setSelectedAccount((payload?.account as LinkedAccount) || account);
        setAccountForm((prev) => ({ ...prev, accountType: 'primary' }));
      }

      toast.success('Primary account updated', {
        description:
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'The selected linked account is now Primary.',
      });
    } catch (error) {
      toast.error('Primary update failed', {
        description:
          error instanceof Error ? error.message : 'Primary account could not be updated.',
      });
    } finally {
      setPendingPrimaryAccountId(null);
    }
  };

  const handleAccountFormSubmit = async () => {
    const validationMessage = validateAccountForm();
    if (validationMessage) {
      toast.error('Account validation failed', {
        description: validationMessage,
      });
      return;
    }

    const payload: Record<string, any> = {
      email: accountForm.email.trim(),
      account_type: accountDialogMode === 'add' && accountForm.accountType === 'primary'
        ? 'Primary'
        : accountForm.accountType === 'work'
          ? 'Work'
          : accountForm.accountType === 'secondary'
            ? 'Secondary'
            : 'Primary',
    };

    setAccountFormSaving(true);
    try {
      const result = await requestFirstSuccessful(
        accountDialogMode === 'add'
          ? '/api/settings/linked-accounts'
          : `/api/settings/linked-accounts/${selectedAccount?.id}`,
        {
          method: accountDialogMode === 'add' ? 'POST' : 'PUT',
          credentials: 'include',
          headers: buildAuthedHeaders(),
          body: JSON.stringify(payload),
        },
        [200]
      );
      const responsePayload = result.payload;

      if (!result.response.ok) {
        throw new Error(
          getSettingsApiErrorMessage(
            result,
            accountDialogMode === 'add'
              ? 'Linked account could not be created.'
              : 'Linked account could not be updated.',
            'Linked account management'
          )
        );
      }

      if (Array.isArray(responsePayload?.accounts)) {
        setLinkedAccounts(responsePayload.accounts as LinkedAccount[]);
      } else {
        await fetchLinkedAccounts();
      }

      setAccountDialogOpen(false);
      resetAccountForm();

      toast.success(accountDialogMode === 'add' ? 'Account added' : 'Account updated', {
        description:
          typeof responsePayload?.message === 'string' && responsePayload.message.trim()
            ? responsePayload.message
            : accountDialogMode === 'add'
              ? 'Linked account added successfully.'
              : 'Linked account updated successfully.',
      });
    } catch (error) {
      toast.error(accountDialogMode === 'add' ? 'Add account failed' : 'Update failed', {
        description:
          error instanceof Error
            ? error.message
            : accountDialogMode === 'add'
              ? 'Linked account could not be created.'
              : 'Linked account could not be updated.',
      });
    } finally {
      setAccountFormSaving(false);
    }
  };

  const handleResendVerification = async (account: LinkedAccount) => {
    if (accountVerificationPendingId || !account.can_resend_verification) {
      return;
    }

    setAccountVerificationPendingId(account.id);
    try {
      const result = await requestFirstSuccessful(
        `/api/settings/linked-accounts/${account.id}/send-verification`,
        {
          method: 'POST',
          credentials: 'include',
          headers: buildAuthedHeaders(),
        },
        [200]
      );
      const payload = result.payload;

      if (!result.response.ok) {
        throw new Error(
          getSettingsApiErrorMessage(
            result,
            'Verification email could not be sent.',
            'Linked account management'
          )
        );
      }

      if (Array.isArray(payload?.accounts)) {
        setLinkedAccounts(payload.accounts as LinkedAccount[]);
      } else {
        await fetchLinkedAccounts();
      }

      if (selectedAccount?.id === account.id && payload?.account) {
        const refreshedAccount = payload.account as LinkedAccount;
        setSelectedAccount(refreshedAccount);
        setAccountForm((prev) => ({
          ...prev,
          email: refreshedAccount.email,
          verificationStatus: refreshedAccount.verification_status,
        }));
      }

      toast.success('Verification sent', {
        description:
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'Verification email sent successfully.',
      });
    } catch (error) {
      toast.error('Verification failed', {
        description:
          error instanceof Error ? error.message : 'Verification email could not be sent.',
      });
    } finally {
      setAccountVerificationPendingId(null);
    }
  };

  const openDeleteAccountDialog = (account: LinkedAccount) => {
    setAccountPendingDelete(account);
    setDeleteDialogOpen(true);
  };

  const handleDeleteAccount = async () => {
    if (!accountPendingDelete || accountDeleteSaving) {
      return;
    }

    if (!accountPendingDelete.can_delete) {
      toast.error('Delete blocked', {
        description:
          accountPendingDelete.delete_block_reason ||
          'This linked account cannot be deleted right now.',
      });
      return;
    }

    setAccountDeleteSaving(true);
    try {
      const result = await requestFirstSuccessful(
        `/api/settings/linked-accounts/${accountPendingDelete.id}`,
        {
          method: 'DELETE',
          credentials: 'include',
          headers: buildAuthedHeaders(),
        },
        [200]
      );
      const payload = result.payload;

      if (!result.response.ok) {
        throw new Error(
          getSettingsApiErrorMessage(
            result,
            'Linked account could not be deleted.',
            'Linked account management'
          )
        );
      }

      if (Array.isArray(payload?.accounts)) {
        setLinkedAccounts(payload.accounts as LinkedAccount[]);
      } else {
        await fetchLinkedAccounts();
      }

      setDeleteDialogOpen(false);
      setAccountPendingDelete(null);
      toast.success('Account deleted', {
        description:
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'Linked account deleted successfully.',
      });
    } catch (error) {
      toast.error('Delete failed', {
        description:
          error instanceof Error ? error.message : 'Linked account could not be deleted.',
      });
    } finally {
      setAccountDeleteSaving(false);
    }
  };



  const handleChannelToggle = async (channelId: string, enabled: boolean) => {
    if (channelId !== 'email' || channelTogglePendingId) {
      return;
    }

    const previousChannels = notificationChannels;
    setChannelTogglePendingId(channelId);
    setNotificationChannels((prev) =>
      prev.map((channel) =>
        channel.id === channelId ? { ...channel, enabled } : channel
      )
    );

    try {
      const endpoint = '/api/integrations/channels/email';
      const result = await requestFirstSuccessful(
        endpoint,
        {
          method: 'PATCH',
          credentials: 'include',
          headers: buildAuthedHeaders(),
          body: JSON.stringify({ enabled }),
        },
        [200]
      ).catch(async (patchError) => {
        try {
          return await requestFirstSuccessful(
            endpoint,
            {
              method: 'POST',
              credentials: 'include',
              headers: buildAuthedHeaders(),
              body: JSON.stringify({ enabled }),
            },
            [200]
          );
        } catch {
          throw patchError;
        }
      });
      const payload = result.payload;

      if (!result.response.ok) {
        throw new Error(
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'Email notification preference could not be updated.'
        );
      }

      if (payload?.channel) {
        const updatedChannel = {
          ...(payload.channel as BackendNotificationChannel),
          icon: Mail,
        };
        setNotificationChannels((prev) =>
          prev.map((channel) => (channel.id === channelId ? updatedChannel : channel))
        );
      }

      setSecuritySettings((prev) => ({
        ...prev,
        emailAlerts: enabled,
      }));

      toast.success(
        enabled
            ? 'Email notifications enabled'
            : 'Email notifications disabled',
        {
        description:
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : enabled
                ? 'Security emails will continue to be delivered to your account.'
                : 'Security emails are now paused for this account.',
      });
    } catch (error) {
      setNotificationChannels(previousChannels);
      toast.error('Preference update failed', {
        description:
          error instanceof Error
            ? error.message
            : 'Email notification preference could not be updated.',
      });
    } finally {
      setChannelTogglePendingId(null);
    }
  };

  useEffect(() => {
    fetchNotificationChannels();
    fetchLinkedAccounts();
  }, []);

  const saveSecuritySettings = async (nextState: typeof securitySettings) => {
    setSecuritySaving(true);
    try {
      const result = await requestFirstSuccessful(
        '/api/settings/security',
        {
          method: 'PATCH',
          credentials: 'include',
          headers: buildAuthedHeaders(),
          body: JSON.stringify({
            auto_lock_minutes: nextState.autoLock,
            session_timeout_minutes: nextState.sessionTimeout,
            two_factor_enabled: nextState.twoFactorEnabled,
          }),
        },
        [200]
      ).catch(async (patchError) => {
        try {
          return await requestFirstSuccessful(
            '/api/settings/security',
            {
              method: 'POST',
              credentials: 'include',
              headers: buildAuthedHeaders(),
              body: JSON.stringify({
                auto_lock_minutes: nextState.autoLock,
                session_timeout_minutes: nextState.sessionTimeout,
                two_factor_enabled: nextState.twoFactorEnabled,
              }),
            },
            [200]
          );
        } catch {
          throw patchError;
        }
      });

      const payload = result.payload;
      if (!result.response.ok) {
        throw new Error(
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'Security settings could not be updated.'
        );
      }

      setSecuritySettings((prev) => ({
        ...prev,
        twoFactorEnabled:
          typeof payload?.user?.is_two_factor_enabled === 'boolean'
            ? payload.user.is_two_factor_enabled
            : nextState.twoFactorEnabled,
        autoLock:
          typeof payload?.user?.auto_lock_minutes === 'number'
            ? payload.user.auto_lock_minutes
            : nextState.autoLock,
        sessionTimeout:
          typeof payload?.user?.session_timeout_minutes === 'number'
            ? payload.user.session_timeout_minutes
            : nextState.sessionTimeout,
      }));
    } finally {
      setSecuritySaving(false);
    }
  };

  const handlePasswordUpdate = async () => {
    if (passwordSaving) {
      return;
    }

    setPasswordSaving(true);
    try {
      const result = await requestFirstSuccessful(
        '/api/settings/password',
        {
          method: 'PATCH',
          credentials: 'include',
          headers: buildAuthedHeaders(),
          body: JSON.stringify({
            current_password: passwordForm.currentPassword,
            new_password: passwordForm.newPassword,
            confirm_password: passwordForm.confirmPassword,
          }),
        },
        [200]
      ).catch(async (patchError) => {
        try {
          return await requestFirstSuccessful(
            '/api/settings/password',
            {
              method: 'POST',
              credentials: 'include',
              headers: buildAuthedHeaders(),
              body: JSON.stringify({
                current_password: passwordForm.currentPassword,
                new_password: passwordForm.newPassword,
                confirm_password: passwordForm.confirmPassword,
              }),
            },
            [200]
          );
        } catch {
          throw patchError;
        }
      });

      const payload = result.payload;
      if (!result.response.ok) {
        throw new Error(
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'Password could not be updated.'
        );
      }

      setPasswordForm({
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      });

      toast.success('Password updated', {
        description:
          typeof payload?.message === 'string' && payload.message.trim()
            ? payload.message
            : 'Password changed successfully.',
      });
    } catch (error) {
      toast.error('Password update failed', {
        description:
          error instanceof Error ? error.message : 'Password could not be updated.',
      });
    } finally {
      setPasswordSaving(false);
    }
  };

  const handleSecurityControlChange = async (
    setting: 'twoFactorEnabled' | 'autoLock' | 'sessionTimeout',
    value: boolean | number
  ) => {
    const previous = securitySettings;
    const nextState = {
      ...securitySettings,
      [setting]: value,
    };
    setSecuritySettings(nextState);

    try {
      await saveSecuritySettings(nextState);
      toast.success('Security settings updated', {
        description: 'Your security preferences were saved successfully.',
      });
    } catch (error) {
      setSecuritySettings(previous);
      toast.error('Security update failed', {
        description:
          error instanceof Error ? error.message : 'Security settings could not be updated.',
      });
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'verified':
        return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">{t('settings.status.verified')}</Badge>;
      case 'pending':
        return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">{t('settings.status.pending')}</Badge>;
      default:
        return <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30">{t('settings.status.unknown')}</Badge>;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'verified':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'pending':
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getAccountTypeLabel = (type: string) => {
    switch (type) {
      case 'primary':
        return t('settings.accountType.primary');
      case 'secondary':
        return t('settings.accountType.secondary');
      case 'work':
        return t('settings.accountType.work');
      default:
        return type;
    }
  };

  const getChannelTypeLabel = (type: string) => {
    switch (type) {
      case 'Email':
        return t('settings.channel.email');
      default:
        return type;
    }
  };

  const formatTimeOption = (value: number) => {
    if (value === 60) return t('settings.time.hour', { value: 1 });
    if (value > 60) return t('settings.time.hours', { value: value / 60 });
    return t('settings.time.minutes', { value });
  };

  const stackClass = isRtl ? 'space-x-reverse space-x-3' : 'space-x-3';
  const rowClass = isRtl ? 'space-x-reverse space-x-2' : 'space-x-2';

  return (
    <div className="space-y-6" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className={`flex items-center ${stackClass}`}>
        <div className="w-10 h-10 bg-gradient-to-r from-gray-500 to-gray-600 rounded-lg flex items-center justify-center">
          <Settings className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-white">{t('settings.headerTitle')}</h1>
          <p className="text-gray-400 mt-1">{t('settings.headerDescription')}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-2 space-y-6"
        >
          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <User className="w-5 h-5 mr-2 text-blue-400" />
                {t('settings.profile.title')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="fullName" className="text-white">{t('settings.profile.fullName')}</Label>
                  <Input
                    id="fullName"
                    value={profileData.fullName}
                    onChange={(e) => setProfileData((prev) => ({ ...prev, fullName: e.target.value }))}
                    className="mt-2 bg-gray-800 border-gray-600 text-white"
                  />
                </div>
                <div>
                  <Label htmlFor="email" className="text-white">{t('settings.profile.email')}</Label>
                  <Input
                    id="email"
                    type="email"
                    value={profileData.email}
                    onChange={(e) => setProfileData((prev) => ({ ...prev, email: e.target.value }))}
                    className="mt-2 bg-gray-800 border-gray-600 text-white"
                  />
                </div>
                <div>
                  <Label htmlFor="jobTitle" className="text-white">{t('settings.profile.jobTitle')}</Label>
                  <Input
                    id="jobTitle"
                    value={profileData.jobTitle}
                    onChange={(e) => setProfileData((prev) => ({ ...prev, jobTitle: e.target.value }))}
                    className="mt-2 bg-gray-800 border-gray-600 text-white"
                  />
                </div>
                <div>
                  <Label htmlFor="company" className="text-white">{t('settings.profile.company')}</Label>
                  <Input
                    id="company"
                    value={profileData.company}
                    onChange={(e) => setProfileData((prev) => ({ ...prev, company: e.target.value }))}
                    className="mt-2 bg-gray-800 border-gray-600 text-white"
                  />
                </div>
              </div>
              <Button
                onClick={handleProfileUpdate}
                disabled={profileSaving}
                className="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800"
              >
                {profileSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                {t('settings.profile.update')}
              </Button>
            </CardContent>
          </Card>

          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Shield className="w-5 h-5 mr-2 text-green-400" />
                {t('settings.security.title')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h4 className="text-white font-medium">{t('settings.security.autoLock')}</h4>
                    <p className="text-gray-400 text-sm">{t('settings.security.autoLockDesc')}</p>
                  </div>
                  <Select
                    value={securitySettings.autoLock.toString()}
                    onValueChange={(value) => handleSecurityControlChange('autoLock', parseInt(value))}
                    disabled={securitySaving}
                  >
                    <SelectTrigger className="w-32 bg-gray-800 border-gray-600 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-gray-800 border-gray-600">
                      <SelectItem value="5" className="text-white">{formatTimeOption(5)}</SelectItem>
                      <SelectItem value="15" className="text-white">{formatTimeOption(15)}</SelectItem>
                      <SelectItem value="30" className="text-white">{formatTimeOption(30)}</SelectItem>
                      <SelectItem value="60" className="text-white">{formatTimeOption(60)}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h4 className="text-white font-medium">{t('settings.security.sessionTimeout')}</h4>
                    <p className="text-gray-400 text-sm">{t('settings.security.sessionTimeoutDesc')}</p>
                  </div>
                  <Select
                    value={securitySettings.sessionTimeout.toString()}
                    onValueChange={(value) => handleSecurityControlChange('sessionTimeout', parseInt(value))}
                    disabled={securitySaving}
                  >
                    <SelectTrigger className="w-32 bg-gray-800 border-gray-600 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-gray-800 border-gray-600">
                      <SelectItem value="15" className="text-white">{formatTimeOption(15)}</SelectItem>
                      <SelectItem value="30" className="text-white">{formatTimeOption(30)}</SelectItem>
                      <SelectItem value="60" className="text-white">{formatTimeOption(60)}</SelectItem>
                      <SelectItem value="120" className="text-white">{formatTimeOption(120)}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Key className="w-5 h-5 mr-2 text-cyan-400" />
                Password Controls
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="currentPassword" className="text-white">
                  Current password
                </Label>
                <div className="relative mt-2">
                  <Input
                    id="currentPassword"
                    type={passwordVisibility.currentPassword ? 'text' : 'password'}
                    value={passwordForm.currentPassword}
                    onChange={(event) =>
                      setPasswordForm((prev) => ({
                        ...prev,
                        currentPassword: event.target.value,
                      }))
                    }
                    className="bg-gray-800 border-gray-600 pr-12 text-white"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-2 top-1/2 h-8 w-8 -translate-y-1/2 text-gray-400 hover:bg-white/5 hover:text-white"
                    onClick={() =>
                      setPasswordVisibility((prev) => ({
                        ...prev,
                        currentPassword: !prev.currentPassword,
                      }))
                    }
                  >
                    {passwordVisibility.currentPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
              <div>
                <Label htmlFor="newPassword" className="text-white">
                  New password
                </Label>
                <div className="relative mt-2">
                  <Input
                    id="newPassword"
                    type={passwordVisibility.newPassword ? 'text' : 'password'}
                    value={passwordForm.newPassword}
                    onChange={(event) =>
                      setPasswordForm((prev) => ({
                        ...prev,
                        newPassword: event.target.value,
                      }))
                    }
                    className="bg-gray-800 border-gray-600 pr-12 text-white"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-2 top-1/2 h-8 w-8 -translate-y-1/2 text-gray-400 hover:bg-white/5 hover:text-white"
                    onClick={() =>
                      setPasswordVisibility((prev) => ({
                        ...prev,
                        newPassword: !prev.newPassword,
                      }))
                    }
                  >
                    {passwordVisibility.newPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
              <div>
                <Label htmlFor="confirmPassword" className="text-white">
                  Confirm new password
                </Label>
                <div className="relative mt-2">
                  <Input
                    id="confirmPassword"
                    type={passwordVisibility.confirmPassword ? 'text' : 'password'}
                    value={passwordForm.confirmPassword}
                    onChange={(event) =>
                      setPasswordForm((prev) => ({
                        ...prev,
                        confirmPassword: event.target.value,
                      }))
                    }
                    className="bg-gray-800 border-gray-600 pr-12 text-white"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-2 top-1/2 h-8 w-8 -translate-y-1/2 text-gray-400 hover:bg-white/5 hover:text-white"
                    onClick={() =>
                      setPasswordVisibility((prev) => ({
                        ...prev,
                        confirmPassword: !prev.confirmPassword,
                      }))
                    }
                  >
                    {passwordVisibility.confirmPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
              <Button
                onClick={handlePasswordUpdate}
                disabled={passwordSaving}
                className="bg-gradient-to-r from-cyan-600 to-blue-700 hover:from-cyan-500 hover:to-blue-600"
              >
                {passwordSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Update Password
              </Button>
            </CardContent>
          </Card>

          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Bell className="w-5 h-5 mr-2 text-yellow-400" />
                {t('settings.notifications.title')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h4 className="text-white font-medium">{t('settings.notifications.email')}</h4>
                    <p className="text-gray-400 text-sm">{t('settings.notifications.emailDesc')}</p>
                  </div>
                  <Switch
                    checked={securitySettings.emailAlerts}
                    onCheckedChange={(checked) => void handleChannelToggle('email', checked)}
                    disabled={channelTogglePendingId === 'email'}
                  />
                </div>

                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h4 className="text-white font-medium">{t('settings.notifications.weekly')}</h4>
                    <p className="text-gray-400 text-sm">{t('settings.notifications.weeklyDesc')}</p>
                  </div>
                  <Switch checked={securitySettings.weeklyReports} onCheckedChange={(checked) => handleSecuritySettingChange('weeklyReports', checked)} />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-6"
        >
          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Globe className="w-5 h-5 mr-2 text-purple-400" />
                {t('settings.language.title')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Label htmlFor="language" className="text-white">{t('settings.language.interface')}</Label>
              <Select value={language} onValueChange={(value) => setLanguage(value as 'english' | 'arabic')}>
                <SelectTrigger className="mt-2 bg-gray-800 border-gray-600 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-gray-800 border-gray-600">
                  <SelectItem value="english" className="text-white">{t('settings.language.english')}</SelectItem>
                  <SelectItem value="arabic" className="text-white">{t('settings.language.arabic')}</SelectItem>
                </SelectContent>
              </Select>
            </CardContent>
          </Card>

          <Card className="cyber-card">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <MessageCircle className="w-5 h-5 mr-2 text-blue-400" />
                {t('settings.channels.title')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {channelsLoading ? (
                <div className="flex items-center justify-center gap-3 rounded-xl border border-blue-500/20 bg-gray-900/60 px-4 py-6 text-sm text-gray-300">
                  <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
                  Loading notification channels...
                </div>
              ) : channelsError && notificationChannels.length === 0 ? (
                <div className="space-y-3">
                  <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                    {channelsError}
                  </div>
                  <Button
                    variant="outline"
                    className="w-full border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                    onClick={fetchNotificationChannels}
                  >
                    Retry
                  </Button>
                </div>
              ) : (
                <>
                  {channelsError ? (
                    <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-100">
                      {channelsError}
                    </div>
                  ) : null}

                  {notificationChannels.map((channel) => {
                    const Icon = channel.icon;
                    const statusIcon = channel.verified ? (
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-yellow-400" />
                    );

                    return (
                      <div
                        key={channel.id}
                        className="rounded-2xl border border-white/6 bg-[linear-gradient(180deg,rgba(30,41,59,0.58),rgba(15,23,42,0.78))] p-4 shadow-[0_12px_40px_rgba(2,6,23,0.2)]"
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className={`flex items-start ${stackClass}`}>
                            <div className="mt-0.5 rounded-xl border border-white/10 bg-gray-900/80 p-2">
                              <Icon className="w-4 h-4 text-gray-300" />
                            </div>
                            <div className="space-y-1">
                              <p className="text-white text-sm font-semibold">{getChannelTypeLabel(channel.type)}</p>
                              <p className="text-gray-300 text-sm">{channel.value}</p>
                              {channel.description ? (
                                <p className="max-w-xs text-[11px] leading-5 text-gray-500">{channel.description}</p>
                              ) : null}
                            </div>
                          </div>

                            <div className="flex flex-col items-end gap-3">
                              <div className={`flex items-center ${rowClass}`}>
                              {statusIcon}
                              <Switch
                                checked={channel.enabled}
                                disabled={
                                  channelTogglePendingId === channel.id ||
                                  !channel.can_toggle
                                }
                                onCheckedChange={(checked) =>
                                  handleChannelToggle(channel.id, checked)
                                }
                              />
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}

                  <Button
                    variant="outline"
                    className="w-full border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                    onClick={fetchNotificationChannels}
                  >
                    <Plus className="w-4 h-4 mr-2" />
                    Refresh Email Settings
                  </Button>
                </>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="cyber-card">
          <CardHeader>
            <CardTitle className="text-white flex items-center justify-between gap-4">
              <div className="flex items-center">
                <Key className="w-5 h-5 mr-2 text-indigo-400" />
                {t('settings.accounts.title')}
              </div>
              <Button
                size="sm"
                onClick={openAddAccountDialog}
                className="bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800"
              >
                <Plus className="w-4 h-4 mr-2" />
                {t('settings.accounts.add')}
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-gray-700">
                  <TableHead className="text-gray-300">{t('settings.accounts.email')}</TableHead>
                  <TableHead className="text-gray-300">{t('settings.accounts.type')}</TableHead>
                  <TableHead className="text-gray-300">{t('settings.accounts.status')}</TableHead>
                  <TableHead className="text-gray-300">{t('settings.accounts.twoFactor')}</TableHead>
                  <TableHead className="text-gray-300">{t('settings.accounts.lastAccess')}</TableHead>
                  <TableHead className="text-gray-300">{t('settings.accounts.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {accountsLoading ? (
                  <TableRow className="border-gray-700">
                    <TableCell colSpan={6} className="py-8 text-center text-gray-300">
                      <div className="flex items-center justify-center gap-3">
                        <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
                        Loading linked accounts...
                      </div>
                    </TableCell>
                  </TableRow>
                ) : accountsError ? (
                  <TableRow className="border-gray-700">
                    <TableCell colSpan={6} className="py-6">
                      <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                        {accountsError}
                      </div>
                      <div className="mt-3">
                        <Button
                          size="sm"
                          variant="outline"
                          className="border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                          onClick={fetchLinkedAccounts}
                        >
                          Retry
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : linkedAccounts.length === 0 ? (
                  <TableRow className="border-gray-700">
                    <TableCell colSpan={6} className="py-8 text-center text-gray-400">
                      No linked accounts yet. Add an account to get started.
                    </TableCell>
                  </TableRow>
                ) : (
                  linkedAccounts.map((account, index) => (
                    <motion.tr
                      key={account.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.4 + index * 0.05 }}
                      className="border-gray-700 hover:bg-gray-800/50"
                    >
                      <TableCell className="text-white">
                        <div className="space-y-1">
                          <div>{account.email}</div>
                          {account.is_current_auth_email ? (
                            <div className="text-[11px] text-gray-500">Authenticated sign-in email</div>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={`${
                            account.account_type === 'primary'
                              ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                              : account.account_type === 'work'
                                ? 'bg-violet-500/20 text-violet-300 border-violet-500/30'
                                : 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                          }`}
                        >
                          {getAccountTypeLabel(account.account_type)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className={`flex items-center ${rowClass}`}>
                          {getStatusIcon(account.verification_status)}
                          {getStatusBadge(account.verification_status)}
                        </div>
                      </TableCell>
                      <TableCell>
                        {securitySettings.twoFactorEnabled ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-yellow-400" />
                        )}
                      </TableCell>
                      <TableCell className="text-gray-400">
                        {account.last_access_at ? formatDateTime(account.last_access_at) : t('settings.misc.never')}
                      </TableCell>
                      <TableCell>
                        <div className={`flex items-center ${rowClass}`}>
                          {account.can_resend_verification ? (
                            <Button
                              size="sm"
                              variant="outline"
                              className="text-cyan-300 border-cyan-400/30 hover:bg-cyan-400/10"
                              onClick={() => void handleResendVerification(account)}
                              disabled={accountVerificationPendingId === account.id}
                            >
                              {accountVerificationPendingId === account.id ? (
                                <Loader2 className="w-3 h-3 animate-spin" />
                              ) : (
                                <Mail className="w-3 h-3" />
                              )}
                            </Button>
                          ) : null}
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-blue-400 border-blue-400/30 hover:bg-blue-400/10"
                            onClick={() => openEditAccountDialog(account)}
                          >
                            <Edit className="w-3 h-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-red-400 border-red-400/30 hover:bg-red-400/10 disabled:opacity-60"
                            onClick={() => openDeleteAccountDialog(account)}
                          >
                            <Trash2 className="w-3 h-3" />
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
      </motion.div>

      <Dialog
        open={accountDialogOpen}
        onOpenChange={(open) => {
          setAccountDialogOpen(open);
          if (!open) {
            resetAccountForm();
          }
        }}
      >
        <DialogContent className="max-w-xl border-blue-500/20 bg-[linear-gradient(180deg,rgba(15,23,42,0.98),rgba(10,15,28,0.98))] text-white shadow-[0_24px_80px_rgba(2,6,23,0.42)]">
          <DialogHeader>
            <DialogTitle className="text-xl font-semibold text-white">
              {accountDialogMode === 'add' ? 'Add Linked Account' : 'Edit Linked Account'}
            </DialogTitle>
            <DialogDescription className="text-gray-400">
              {accountDialogMode === 'add'
                ? 'Add another linked email while preserving the current Settings design and security rules.'
                : 'Update the selected linked account and promote it to Primary when needed.'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label htmlFor="linkedAccountEmail" className="text-white">
                {t('settings.accounts.email')}
              </Label>
              <Input
                id="linkedAccountEmail"
                type="email"
                value={accountForm.email}
                onChange={(event) =>
                  setAccountForm((prev) => ({ ...prev, email: event.target.value }))
                }
                className="mt-2 bg-gray-800 border-gray-600 text-white"
                disabled={selectedAccount?.is_current_auth_email}
              />
              {selectedAccount?.is_current_auth_email ? (
                <p className="mt-2 text-xs text-gray-500">
                  The authenticated sign-in email is managed by your account identity.
                </p>
              ) : null}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label className="text-white">{t('settings.accounts.type')}</Label>
                <Select
                  value={accountForm.accountType}
                  onValueChange={(value) =>
                    setAccountForm((prev) => ({
                      ...prev,
                      accountType: value as LinkedAccountType,
                    }))
                  }
                >
                  <SelectTrigger className="mt-2 bg-gray-800 border-gray-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-gray-800 border-gray-600">
                    {accountDialogMode === 'edit' ? (
                      <SelectItem value="primary" className="text-white">
                        {t('settings.accountType.primary')}
                      </SelectItem>
                    ) : null}
                    <SelectItem value="secondary" className="text-white">
                      {t('settings.accountType.secondary')}
                    </SelectItem>
                    <SelectItem value="work" className="text-white">
                      {t('settings.accountType.work')}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label className="text-white">{t('settings.accounts.status')}</Label>
                <div className="mt-2 rounded-xl border border-white/8 bg-gray-900/50 px-4 py-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className={`flex items-center ${rowClass}`}>
                      {getStatusIcon(accountForm.verificationStatus)}
                      {getStatusBadge(accountForm.verificationStatus)}
                    </div>
                    {accountDialogMode === 'edit' &&
                    selectedAccount?.can_resend_verification ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="border-cyan-400/30 text-cyan-300 hover:bg-cyan-400/10"
                        onClick={() => void handleResendVerification(selectedAccount)}
                        disabled={accountVerificationPendingId === selectedAccount.id}
                      >
                        {accountVerificationPendingId === selectedAccount.id ? (
                          <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Mail className="mr-2 h-3.5 w-3.5" />
                        )}
                        Resend verification
                      </Button>
                    ) : null}
                  </div>
                  <p className="mt-2 text-xs text-gray-500">
                    {accountDialogMode === 'add'
                      ? 'New linked emails start as Pending and can sign in after verification.'
                      : selectedAccount?.is_current_auth_email
                        ? 'The authenticated sign-in email follows your main account verification state.'
                        : accountForm.verificationStatus === 'verified'
                          ? 'This linked email is verified and can sign in with the same password as your main account.'
                          : 'This linked email must be verified by email before it can sign in.'}
                  </p>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-white/8 bg-gray-900/50 px-4 py-3">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-sm font-medium text-white">{t('settings.accounts.twoFactor')}</p>
                  <p className="text-xs text-gray-500">
                    2FA is shared across your primary and linked sign-in emails. Change it from
                    Security Settings.
                  </p>
                </div>
                <Switch
                  checked={securitySettings.twoFactorEnabled}
                  onCheckedChange={() => undefined}
                  disabled
                />
              </div>
            </div>

            {accountDialogMode === 'edit' && selectedAccount && !selectedAccount.is_primary ? (
              <Button
                type="button"
                variant="outline"
                className="w-full border-blue-500/30 text-blue-300 hover:bg-blue-500/10"
                onClick={() => void handleSetPrimary(selectedAccount)}
                disabled={pendingPrimaryAccountId === selectedAccount.id}
              >
                {pendingPrimaryAccountId === selectedAccount.id ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <CheckCircle className="mr-2 h-4 w-4" />
                )}
                Set as Primary
              </Button>
            ) : null}
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              className="border-white/10 text-gray-300 hover:bg-white/5"
              onClick={() => {
                setAccountDialogOpen(false);
                resetAccountForm();
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              onClick={() => void handleAccountFormSubmit()}
              disabled={accountFormSaving}
              className="bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800"
            >
              {accountFormSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              {accountDialogMode === 'add' ? 'Add Account' : 'Save Changes'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={deleteDialogOpen}
        onOpenChange={(open) => {
          setDeleteDialogOpen(open);
          if (!open) {
            setAccountPendingDelete(null);
          }
        }}
      >
        <AlertDialogContent className="border-red-500/20 bg-[linear-gradient(180deg,rgba(15,23,42,0.98),rgba(10,15,28,0.98))] text-white">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-white">Delete linked account</AlertDialogTitle>
            <AlertDialogDescription className="text-gray-400">
              {accountPendingDelete
                ? `You are about to remove ${accountPendingDelete.email}. This action updates only your linked-account list.`
                : 'Confirm linked account deletion.'}
            </AlertDialogDescription>
          </AlertDialogHeader>

          {!accountPendingDelete?.can_delete ? (
            <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-100">
              {accountPendingDelete?.delete_block_reason ||
                'This account cannot be deleted right now.'}
            </div>
          ) : (
            <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-100">
              This linked account will be removed from your settings immediately after confirmation.
            </div>
          )}

          <AlertDialogFooter>
            <AlertDialogCancel className="border-white/10 bg-transparent text-gray-300 hover:bg-white/5">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                void handleDeleteAccount();
              }}
              disabled={!accountPendingDelete?.can_delete || accountDeleteSaving}
              className="bg-red-600 text-white hover:bg-red-700"
            >
              {accountDeleteSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Delete account
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
