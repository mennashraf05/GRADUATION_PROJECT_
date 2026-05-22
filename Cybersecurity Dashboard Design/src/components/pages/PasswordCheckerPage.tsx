import React, { useState, useMemo, useEffect } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Badge } from '../ui/badge';
import { Progress } from '../ui/progress';
import { useLanguage } from '../../contexts/LanguageContext';
import {
  Key,
  Search,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Shield,
  Eye,
  EyeOff,
  Circle,
} from 'lucide-react';

const API_BASE_URL =
  (import.meta as any).env?.VITE_API_BASE_URL || '';

const FIXED_PASSWORD_MASK = '********';

type PasswordHistoryItem = {
  id: number;
  password: string;
  masked_password?: string;
  breaches: number;
  status: 'safe' | 'breached';
  checked_at: string;
};

function buildAuthedFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  const token = localStorage.getItem('sentinel_auth_token');

  if (token && token !== 'cookie_based') {
    headers.set('Authorization', `Bearer ${token}`);
  }

  return { ...init, credentials: 'omit', headers };
}

function buildCookieOnlyFetchInit(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || undefined);
  headers.delete('Authorization');
  return { ...init, credentials: 'include', headers };
}

async function fetchWithPasswordAuth(input: RequestInfo | URL, init: RequestInit = {}) {
  const cookieResponse = await fetch(input, buildCookieOnlyFetchInit(init));

  if (cookieResponse.status !== 401 && cookieResponse.status !== 403) {
    return cookieResponse;
  }

  const token = localStorage.getItem('sentinel_auth_token');
  if (token && token !== 'cookie_based') {
    return fetch(input, buildAuthedFetchInit(init));
  }

  return cookieResponse;
}

export function PasswordCheckerPage() {
  const { language, isRtl } = useLanguage();
  const isArabic = language === 'arabic';
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<'safe' | 'breached' | null>(null);

  const [breachCount, setBreachCount] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [previousChecks, setPreviousChecks] = useState<PasswordHistoryItem[]>([]);

  useEffect(() => {
    void loadPasswordHistory();
  }, []);

  const loadPasswordHistory = async () => {
    try {
      const response = await fetchWithPasswordAuth(
        `${API_BASE_URL}/api/password/history`,
      );

      if (response.status === 401 || response.status === 403) {
        setPreviousChecks([]);
        return;
      }

      const data = await response.json();
      const history = Array.isArray(data) ? data : data.history;

      if (response.ok && Array.isArray(history)) {
        setPreviousChecks(
          history.map((item: any) => ({
            id: Number(item.id),
            password: FIXED_PASSWORD_MASK,
            masked_password: FIXED_PASSWORD_MASK,
            breaches: Number(item.breaches ?? item.breach_count ?? 0),
            status: item.status === 'breached' ? 'breached' : 'safe',
            checked_at: String(item.checked_at ?? item.created_at ?? ''),
          }))
        );
      }
    } catch {
      setPreviousChecks([]);
    }
  };

  const handleClearHistory = async () => {
    try {
      const response = await fetchWithPasswordAuth(
        `${API_BASE_URL}/api/password/history`,
        { method: 'DELETE' }
      );

      if (response.ok) {
        setPreviousChecks([]);
      }
    } catch {
      setErrorMessage(isArabic ? 'تعذر مسح سجل الفحوصات.' : 'Could not clear password history.');
    }
  };

  // ===========================
  // Password strength analysis
  // ===========================
  const passwordAnalysis = useMemo(() => {
    const hasUpperFirst = /^[A-Z]/.test(password);
    const hasMin8 = password.length >= 8;
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial =
      /[!@#$%^&*()_\-+=[\]{};':"\\|,.<>/?`~]/.test(password);
    const hasMin12 = password.length >= 12;

    const checks = [hasUpperFirst, hasMin8, hasLower, hasNumber, hasSpecial];
    const score = checks.filter(Boolean).length;

    let strengthLabel = isArabic ? 'ضعيفة جدًا' : 'Very weak';
    if (score >= 4 && hasMin12) strengthLabel = isArabic ? 'قوية' : 'Strong';
    else if (score >= 3) strengthLabel = isArabic ? 'متوسطة' : 'Medium';
    else if (score >= 2) strengthLabel = isArabic ? 'ضعيفة' : 'Weak';

    const strengthPercent = (score / checks.length) * 100;
    const strengthColor =
      strengthPercent < 40
        ? 'bg-red-500'
        : strengthPercent < 80
        ? 'bg-yellow-500'
        : 'bg-green-500';

    return {
      hasUpperFirst,
      hasMin8,
      hasLower,
      hasNumber,
      hasSpecial,
      hasMin12,
      strengthLabel,
      strengthPercent,
      strengthColor,
    };
  }, [password, isArabic]);

  // ===========================
  // HIBP-backed scan handler
  // ===========================
  const handleScan = async () => {
    if (!password) return;

    setIsScanning(true);
    setScanResult(null);
    setBreachCount(null);
    setErrorMessage(null);

    try {
      const response = await fetchWithPasswordAuth(`${API_BASE_URL}/api/password/check`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ password }),
      });

      const data = await response.json().catch(() => ({}));

      if (response.ok && data.status === 'ok') {
        const pwned = !!data.pwned;
        const count =
          typeof data.count === 'number' && !isNaN(data.count)
            ? data.count
            : 0;

        setScanResult(pwned ? 'breached' : 'safe');
        setBreachCount(count);
        await loadPasswordHistory();
      } else {
        setScanResult(null);
        if (response.status === 401 || response.status === 403) {
          setErrorMessage(
            isArabic
              ? 'انتهت الجلسة، يرجى تسجيل الدخول مرة أخرى.'
              : 'Session expired, please log in again.'
          );
          return;
        }
        setErrorMessage(
          data.message || (isArabic
            ? 'خدمة فحص كلمات المرور غير متاحة مؤقتًا.'
            : 'Password check service is temporarily unavailable.')
        );
      }
    } catch {
      setScanResult(null);
      setErrorMessage(isArabic ? 'حدث خطأ غير متوقع أثناء فحص كلمة المرور.' : 'Unexpected error while checking your password.');
    } finally {
      setIsScanning(false);
    }
  };
 
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'safe':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'breached':
        return <XCircle className="w-4 h-4 text-red-400" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
    }
  };
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'safe':
        return (
          <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
            Safe
          </Badge>
        );
      case 'breached':
        return (
          <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
            Breached
          </Badge>
        );
      default:
        return (
          <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">
            Unknown
          </Badge>
        );
    }
  };

  return (
    <div className="space-y-4" dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Header */}
      <div className={`flex items-center ${isRtl ? 'space-x-reverse space-x-3' : 'space-x-3'}`}>
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-r from-green-500 to-green-600">
          <Key className="h-5 w-5 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">{isArabic ? 'فاحص تسريب كلمات المرور' : 'Password Breach Checker'}</h1>
          <p className="mt-1 text-sm text-gray-400">
            {isArabic ? 'تحقق مما إذا كانت بيانات اعتمادك قد تعرضت للاختراق في تسريبات البيانات' : 'Check if your credentials have been compromised in data breaches'}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Scan Form */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-2"
        >
          <Card className="cyber-card">
            <CardHeader className="px-4 pt-4 pb-2 sm:px-5">
              <CardTitle className="text-white flex items-center">
                <Search className={`w-5 h-5 text-blue-400 ${isRtl ? 'ml-2' : 'mr-2'}`} />
                {isArabic ? 'تحقق من بيانات اعتمادك' : 'Check Your Credentials'}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 px-4 pb-4 sm:px-5">
              <div className="space-y-3">
                <div>
                  <Label htmlFor="scan-password" className="text-white">
                    {isArabic ? 'كلمة المرور' : 'Password'}
                  </Label>
                  <div className="relative mt-2">
                    <Input
                      id="scan-password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder={isArabic ? 'أدخل كلمة المرور لفحصها' : 'Enter your password to check'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="pr-10 bg-gray-800 border-gray-600 text-white placeholder-gray-400 focus:border-blue-500"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"
                    >
                      {showPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>

                  {/* Password strength bar + requirements */}
                  <div className="mt-3 space-y-2.5">
                    <div className="flex items-center justify-between text-xs sm:text-sm">
                      <span className="text-gray-300">{isArabic ? 'قوة كلمة المرور' : 'Password strength'}</span>
                      <span className="font-medium text-gray-100">
                        {passwordAnalysis.strengthLabel}
                      </span>
                    </div>

                    <div className="h-2 w-full rounded-full bg-gray-800 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-300 ${passwordAnalysis.strengthColor}`}
                        style={{ width: `${passwordAnalysis.strengthPercent}%` }}
                      />
                    </div>

                    <div className="mt-2 rounded-md border border-gray-700 bg-gray-900/60 p-2.5 text-xs space-y-1.5 sm:text-sm">
                      <p className="font-semibold mb-1 text-gray-200">
                        {isArabic ? 'متطلبات كلمة المرور:' : 'Password requirements:'}
                      </p>
                      <RequirementRow
                        ok={passwordAnalysis.hasUpperFirst}
                        text={isArabic ? 'يجب أن يكون الحرف الأول كبيرًا' : 'First letter must be UPPERCASE'}
                      />
                      <RequirementRow
                        ok={passwordAnalysis.hasMin8}
                        text={isArabic ? '8 أحرف على الأقل' : 'At least 8 characters'}
                      />
                      <RequirementRow
                        ok={passwordAnalysis.hasLower}
                        text={isArabic ? 'تحتوي على أحرف صغيرة' : 'Contains lowercase letters'}
                      />
                      <RequirementRow
                        ok={passwordAnalysis.hasNumber}
                        text={isArabic ? 'تحتوي على رقم واحد على الأقل' : 'Contains at least one number'}
                      />
                      <RequirementRow
                        ok={passwordAnalysis.hasSpecial}
                        text={isArabic ? 'تحتوي على رمز خاص مثل ! @ # $ %' : 'Contains a special character (e.g. ! @ # $ %)'}
                      />
                      <RequirementRow
                        ok={passwordAnalysis.hasMin12}
                        text={isArabic ? 'الأفضل أن تكون 12+ حرفًا لمزيد من الأمان' : 'Better if 12+ characters (extra security)'}
                      />
                    </div>
                  </div>
                </div>

                <Button
                  onClick={handleScan}
                  disabled={!password || isScanning}
                  className="w-full bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white cyber-glow-green"
                >
                  {isScanning ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                      {isArabic ? 'جارٍ الفحص...' : 'Scanning...'}
                    </>
                  ) : (
                    <>
                      <Search className={`w-4 h-4 ${isRtl ? 'ml-2' : 'mr-2'}`} />
                      {isArabic ? 'افحص التسريبات' : 'Check for Breaches'}
                    </>
                  )}
                </Button>

                {errorMessage && (
                  <p className="text-sm text-red-400">
                    {errorMessage}
                  </p>
                )}
              </div>

              {/* Scan Progress */}
              {isScanning && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-4"
                >
                  <div className="scan-line">
                    <Progress value={66} className="h-2" />
                  </div>
                  <div className={`flex items-center text-blue-400 ${isRtl ? 'space-x-reverse space-x-2' : 'space-x-2'}`}>
                    <div className="animate-pulse w-2 h-2 bg-blue-400 rounded-full" />
                    <span className="text-sm">
                      {isArabic ? 'جارٍ المقارنة مع 14.7 مليار سجل مخترق...' : 'Checking against 14.7 billion breached records...'}
                    </span>
                  </div>
                </motion.div>
              )}

              {/* Result */}
              {scanResult && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ type: 'spring', stiffness: 300, damping: 25 }}
                  className={`rounded-lg border-2 p-4 ${
                    scanResult === 'safe'
                      ? 'bg-green-500/10 border-green-500/30 cyber-glow-green'
                      : 'bg-red-500/10 border-red-500/30 cyber-glow-red'
                  }`}
                >
                  <div className={`flex items-center ${isRtl ? 'space-x-reverse space-x-3' : 'space-x-3'}`}>
                    {scanResult === 'safe' ? (
                      <CheckCircle className="h-7 w-7 text-green-400" />
                    ) : (
                      <XCircle className="h-7 w-7 text-red-400" />
                    )}
                    <div>
                      <h3
                        className={`text-lg font-semibold ${
                          scanResult === 'safe' ? 'text-green-400' : 'text-red-400'
                        }`}
                      >
                        {scanResult === 'safe'
                          ? (isArabic ? 'تبدو كلمة المرور آمنة!' : 'Your password looks safe!')
                          : (isArabic ? 'تم العثور على كلمة المرور هذه في تسريبات!' : 'This password has been exposed in breaches!')}
                      </h3>
                      <p className="text-gray-300 text-sm">
                        {scanResult === 'safe'
                          ? (isArabic ? 'لم يتم العثور على أي تطابق لهذه الكلمة في قاعدة بيانات HIBP لكلمات المرور المسرّبة.' : 'No matches found for this password in the HIBP Pwned Passwords database.')
                          : `This password was found in ${
                              breachCount?.toLocaleString() ?? 0
                            }${isArabic ? ' تسريب بيانات. يجب تغييرها فورًا وتجنب إعادة استخدامها في مواقع أخرى.' : ' data breaches. You should change it immediately and avoid reusing it on other sites.'}`}
                      </p>
                    </div>
                  </div>
                </motion.div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* Security Tips */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card className="cyber-card">
            <CardHeader className="px-4 pt-4 pb-2 sm:px-5">
              <CardTitle className="text-white flex items-center">
                <Shield className={`w-5 h-5 text-purple-400 ${isRtl ? 'ml-2' : 'mr-2'}`} />
                {isArabic ? 'نصائح أمنية' : 'Security Tips'}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 px-4 pb-4 sm:px-5">
              <div className="space-y-2.5">
                <div className="rounded-lg border border-blue-500/20 bg-blue-500/10 p-2.5">
                  <h4 className="text-blue-400 font-medium">{isArabic ? 'استخدم كلمات مرور قوية' : 'Use Strong Passwords'}</h4>
                  <p className="text-gray-400 text-sm mt-1">
                    {isArabic ? 'أنشئ كلمات مرور فريدة من 12 حرفًا أو أكثر وتتضمن أرقامًا ورموزًا.' : 'Create unique passwords with 12+ characters, including numbers and symbols.'}
                  </p>
                </div>

                <div className="rounded-lg border border-green-500/20 bg-green-500/10 p-2.5">
                  <h4 className="text-green-400 font-medium">{isArabic ? 'فعّل المصادقة الثنائية' : 'Enable 2FA'}</h4>
                  <p className="text-gray-400 text-sm mt-1">
                    {isArabic ? 'تضيف المصادقة الثنائية طبقة أمان إضافية.' : 'Two-factor authentication adds an extra layer of security.'}
                  </p>
                </div>

                <div className="rounded-lg border border-purple-500/20 bg-purple-500/10 p-2.5">
                  <h4 className="text-purple-400 font-medium">{isArabic ? 'استخدم مدير كلمات المرور' : 'Use Password Manager'}</h4>
                  <p className="text-gray-400 text-sm mt-1">
                    {isArabic ? 'دع مدير كلمات المرور ينشئ كلمات مرور فريدة ويحفظها لك.' : 'Let a password manager generate and store unique passwords.'}
                  </p>
                </div>

                <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/10 p-2.5">
                  <h4 className="text-yellow-400 font-medium">{isArabic ? 'فحوصات منتظمة' : 'Regular Checks'}</h4>
                  <p className="text-gray-400 text-sm mt-1">
                    {isArabic ? 'افحص التسريبات شهريًا لتبقى على اطلاع بحالة أمانك.' : 'Check for breaches monthly to stay informed about your security.'}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Previous Checks Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="cyber-card">
          <CardHeader className="px-4 pt-4 pb-2 sm:px-5">
            <div className="flex items-center justify-between gap-3">
              <CardTitle className="text-white flex items-center">
                <Clock className={`w-5 h-5 text-gray-400 ${isRtl ? 'ml-2' : 'mr-2'}`} />
                {isArabic ? 'الفحوصات السابقة' : 'Previous Checks'}
              </CardTitle>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleClearHistory}
                disabled={previousChecks.length === 0}
                className="border-gray-600 text-gray-200 hover:bg-gray-800"
              >
                {isArabic ? 'مسح السجل' : 'Clear History'}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-4 sm:px-5">
            <Table>
              <TableHeader>
                <TableRow className="border-gray-700">
                  <TableHead className="text-gray-300">{isArabic ? 'كلمة المرور' : 'Password'}</TableHead>
                  <TableHead className="text-gray-300">{isArabic ? 'الحالة' : 'Status'}</TableHead>
                  <TableHead className="text-gray-300">{isArabic ? 'عدد التسريبات' : 'Breaches Found'}</TableHead>
                  <TableHead className="text-gray-300">{isArabic ? 'وقت الفحص' : 'Checked At'}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {previousChecks.map((check, index) => (
                  <motion.tr
                    key={check.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 + index * 0.05 }}
                    className="border-gray-700 hover:bg-gray-800/50"
                  >
                    <TableCell className="text-white">{FIXED_PASSWORD_MASK}</TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        {getStatusIcon(check.status)}
                        {getStatusBadge(check.status)}
                      </div>
                    </TableCell>
                    <TableCell
                      className={`font-medium ${
                        check.breaches > 0 ? 'text-red-400' : 'text-green-400'
                      }`}
                    >
                      {check.breaches}
                    </TableCell>
                    <TableCell className="text-gray-400">
                      {check.checked_at}
                    </TableCell>
                  </motion.tr>
                ))}

                {previousChecks.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={4}
                      className="text-center text-gray-500 py-6"
                    >
                      {isArabic ? 'لا توجد فحوصات سابقة بعد.' : 'No previous checks yet.'}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

    </div>
  );
}

// Small component for password requirement row
function RequirementRow({ ok, text }: { ok: boolean; text: string }) {
  return (
    <div className="flex items-center gap-2">
      {ok ? (
        <CheckCircle className="w-4 h-4 text-green-400" />
      ) : (
        <Circle className="w-4 h-4 text-gray-500" />
      )}
      <span className={ok ? 'text-green-200' : 'text-gray-300'}>{text}</span>
    </div>
  );
}


