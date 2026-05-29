import React, { useState } from 'react';
import { motion } from 'motion/react';
import { useNavigate } from 'react-router-dom';
import { AlertCircle, ArrowLeft, Eye, EyeOff, KeyRound, Mail, Shield } from 'lucide-react';
import { Alert, AlertDescription } from '../ui/alert';
import { Button } from '../ui/button';
import { Card } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { useAppSettings } from '../../contexts/AppSettingsContext';

type AdminLoginStep = 'credentials' | '2fa';
const API_BASE_URL =
  import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');
const PENDING_2FA_STORAGE_KEY = 'sentinel_pending_2fa_token';

const AdminLoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { applicationName } = useAppSettings();
  const [step, setStep] = useState<AdminLoginStep>('credentials');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const resetToCredentials = () => {
    setStep('credentials');
    setTwoFactorCode('');
    setError('');
    setIsLoading(false);
    localStorage.removeItem(PENDING_2FA_STORAGE_KEY);
  };

  const issueAdminSession = async (): Promise<{
    token?: string;
    email?: string;
    full_name?: string;
    requires_2fa?: boolean;
    requires_2fa_setup?: boolean;
    pending_token?: string;
  }> => {
    const response = await fetch(`${API_BASE_URL || ''}/api/admin/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email.trim(),
        password,
      }),
    });

    let data: Record<string, unknown> = {};
    try {
      data = await response.json();
    } catch {
      throw new Error('Admin login server returned an invalid response.');
    }

    if (!response.ok || data.success !== true) {
      throw new Error(
        typeof data.message === 'string' && data.message.trim()
          ? data.message
          : 'Admin backend login failed.',
      );
    }
    return data as {
      token?: string;
      email?: string;
      full_name?: string;
      requires_2fa?: boolean;
      requires_2fa_setup?: boolean;
      pending_token?: string;
    };
  };

  const handleCredentialsSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setIsLoading(true);

    window.setTimeout(async () => {
      try {
        const data = await issueAdminSession();
        if (typeof data.email === 'string' && data.email) {
          setEmail(data.email);
        }
        if (data.requires_2fa_setup && typeof data.pending_token === 'string' && data.pending_token) {
          localStorage.setItem(PENDING_2FA_STORAGE_KEY, data.pending_token);
          navigate(`/setup-2fa?email=${encodeURIComponent(data.email || email.trim())}`);
          return;
        }
        if (data.requires_2fa && typeof data.pending_token === 'string' && data.pending_token) {
          localStorage.setItem(PENDING_2FA_STORAGE_KEY, data.pending_token);
          setStep('2fa');
          setIsLoading(false);
          return;
        }
        if (typeof data.token === 'string' && data.token) {
          localStorage.setItem('sentinel_admin_token', data.token);
          localStorage.setItem('sentinel_admin_email', data.email || email.trim());
          localStorage.setItem('sentinel_admin_name', data.full_name || data.email || email.trim());
          navigate('/admin/console');
          return;
        }
        setError('Admin backend login returned an incomplete response.');
        setIsLoading(false);
      } catch (sessionError) {
        setError(sessionError instanceof Error ? sessionError.message : 'Admin backend login failed.');
        setIsLoading(false);
      }
    }, 250);
  };

  const handle2FASubmit = (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    const pendingToken = localStorage.getItem(PENDING_2FA_STORAGE_KEY) || '';
    const accountLabel = email.trim().toLowerCase();
    if (!pendingToken || !accountLabel) {
      setError('Your admin 2FA session expired. Sign in again.');
      setStep('credentials');
      setIsLoading(false);
      return;
    }

    setIsLoading(true);

    window.setTimeout(async () => {
      try {
        const response = await fetch(`${API_BASE_URL || ''}/api/admin/auth/verify-2fa`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${pendingToken}`,
          },
          credentials: 'include',
          body: JSON.stringify({
            email: accountLabel,
            code: twoFactorCode.trim(),
            pending_token: pendingToken,
          }),
        });

        const data = (await response.json().catch(() => ({}))) as {
          success?: boolean;
          message?: string;
          token?: string;
          email?: string;
          full_name?: string;
        };

        if (!response.ok || data.success !== true || typeof data.token !== 'string') {
          setError(data.message || 'Invalid 2FA code.');
          setIsLoading(false);
          return;
        }

        localStorage.removeItem(PENDING_2FA_STORAGE_KEY);
        localStorage.setItem('sentinel_admin_token', data.token);
        localStorage.setItem('sentinel_admin_email', data.email || accountLabel);
        localStorage.setItem('sentinel_admin_name', data.full_name || data.email || accountLabel);
        navigate('/admin/console');
        return;
      } catch (sessionError) {
        setError(sessionError instanceof Error ? sessionError.message : 'Admin 2FA verification failed.');
        setIsLoading(false);
        return;
      }
    }, 300);
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] flex items-center justify-center p-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl" />
      </div>

      <Button
        type="button"
        variant="outline"
        className="absolute left-6 top-6 z-20 gap-2 border-white/10 bg-white/5 text-white hover:bg-white/10 hover:text-white"
        onClick={() => navigate('/')}
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Site
      </Button>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className={`w-full relative z-10 ${step === 'totp-setup' ? 'max-w-lg' : 'max-w-md'}`}
      >
        <div className="text-center mb-8">
          <motion.div
            initial={{ scale: 0.5, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-orange-500 to-red-600 mb-4 shadow-lg shadow-orange-500/50"
          >
            <Shield className="w-10 h-10 text-white" />
          </motion.div>
          <motion.h1
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-3xl mb-2 text-white"
          >
            Admin Console
          </motion.h1>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="text-gray-400"
          >
            {step === '2fa'
              ? 'Enter the authenticator code for this admin account'
              : `${applicationName} Administrative Access`}
          </motion.p>
        </div>

        <Card className="bg-[#1E293B] border-white/10 p-8 shadow-2xl">
          {error && (
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
              <Alert className="bg-red-500/10 border-red-500/50 text-red-400">
                <AlertCircle className="w-4 h-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            </motion.div>
          )}

          {step === 'credentials' && (
            <form onSubmit={handleCredentialsSubmit} className="space-y-6">
              <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 }}>
                <Label htmlFor="email" className="text-white mb-2 block">
                  Email Address
                </Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <Input
                    id="email"
                    type="email"
                    placeholder="you@your-organization.com"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    className="pl-11 bg-[#0F172A] border-white/10 text-white placeholder-gray-500 h-12 rounded-xl focus:ring-2 focus:ring-orange-500/50 focus:border-orange-500/50 transition-all"
                    required
                  />
                </div>
              </motion.div>

              <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }}>
                <Label htmlFor="password" className="text-white mb-2 block">
                  Password
                </Label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <Input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    className="pl-11 pr-11 bg-[#0F172A] border-white/10 text-white placeholder-gray-500 h-12 rounded-xl focus:ring-2 focus:ring-orange-500/50 focus:border-orange-500/50 transition-all"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((current) => !current)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </motion.div>

              <Button
                type="submit"
                className="w-full h-12 bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white rounded-xl transition-all shadow-lg shadow-orange-500/20 hover:shadow-orange-500/40"
                disabled={isLoading}
              >
                {isLoading ? (
                  <div className="flex items-center gap-2">
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Authenticating...
                  </div>
                ) : (
                  'Continue'
                )}
              </Button>

            </form>
          )}

          {step === '2fa' && (
            <form onSubmit={handle2FASubmit} className="space-y-6">
              <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="text-center mb-6">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-orange-500/20 mb-4">
                  <KeyRound className="w-8 h-8 text-orange-400" />
                </div>
                <h3 className="text-xl text-white mb-2">Two-Factor Authentication</h3>
                <p className="text-sm text-gray-400">
                  Open your authenticator app and enter the current 6-digit code
                </p>
              </motion.div>

              <div>
                <Label htmlFor="2fa" className="text-white mb-2 block">
                  Authentication Code
                </Label>
                <Input
                  id="2fa"
                  type="text"
                  placeholder="000000"
                  value={twoFactorCode}
                  onChange={(event) => setTwoFactorCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="bg-[#0F172A] border-white/10 text-white placeholder-gray-500 h-12 rounded-xl text-center text-2xl tracking-widest focus:ring-2 focus:ring-orange-500/50 focus:border-orange-500/50 transition-all"
                  maxLength={6}
                  required
                  autoComplete="one-time-code"
                />
              </div>

              <Button
                type="submit"
                className="w-full h-12 bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white rounded-xl transition-all shadow-lg shadow-orange-500/20 hover:shadow-orange-500/40"
                disabled={isLoading || twoFactorCode.length !== 6}
              >
                {isLoading ? (
                  <div className="flex items-center gap-2">
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Verifying...
                  </div>
                ) : (
                  'Verify & Login'
                )}
              </Button>

              <div className="flex flex-col gap-2">
                <Button type="button" variant="ghost" className="w-full text-gray-400 hover:text-white" onClick={resetToCredentials}>
                  Back to Login
                </Button>
              </div>
            </form>
          )}
        </Card>
      </motion.div>
    </div>
  );
};

export default AdminLoginPage;
