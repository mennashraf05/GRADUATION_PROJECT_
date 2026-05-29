// src/pages/auth/TwoFactorPage.tsx

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, KeyRound, Lock, AlertCircle, CheckCircle2, ArrowLeft } from 'lucide-react';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Label } from '../../components/ui/label';
import { useNavigate } from "react-router-dom";
import { useLanguage } from '../../contexts/LanguageContext';
import { useAppSettings } from '../../contexts/AppSettingsContext';

interface TwoFactorPageProps {
  email?: string;
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000';

export const TwoFactorPage: React.FC<TwoFactorPageProps> = ({ email }) => {
  const navigate = useNavigate();
  const { language, isRtl } = useLanguage();
  const { applicationName } = useAppSettings();
  const isArabic = language === 'arabic';

  const [code, setCode] = useState('');
  const [serverError, setServerError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const resolvedEmail =
    email ||
    localStorage.getItem("loginEmail")?.trim().toLowerCase() ||
    "";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError(null);

    if (!/^\d{6}$/.test(code)) {
      setServerError(isArabic ? "يرجى إدخال الرمز المكوّن من 6 أرقام المرسل إلى بريدك الإلكتروني." : "Please enter the 6-digit code sent to your email.");
      return;
    }

    setIsLoading(true);

    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/verify-2fa`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          email: resolvedEmail,
          code: code.trim(),
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setServerError(data?.message || (isArabic ? "الرمز غير صحيح. يرجى المحاولة مرة أخرى." : "Invalid code. Please try again."));
        setIsLoading(false);
        return;
      }

      setIsSuccess(true);

      setTimeout(() => {
        navigate("/dashboard");
      }, 2000);

    } catch (err) {
      setServerError(isArabic ? "حدث خطأ في الشبكة. يرجى المحاولة مرة أخرى." : "Network error. Please try again.");
      setIsLoading(false);
    }
  };

  // ------------------ SUCCESS SCREEN ------------------
  if (isSuccess) {
    return (
      <div dir={isRtl ? 'rtl' : 'ltr'} className="min-h-screen bg-[#0F172A] flex items-center justify-center relative overflow-hidden">
        <div className="absolute inset-0">
          <div className="absolute inset-0 bg-gradient-to-br from-[#10B981]/20 via-[#0F172A] to-[#3B82F6]/20" />
        </div>

        <motion.div
          initial={{ opacity: 0, y: 30, scale: 0.9 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          className="relative z-10 w-full max-w-md mx-4"
        >
          <div className="absolute -inset-1 bg-gradient-to-r from-[#64FFDA] to-[#3B82F6] blur opacity-30 rounded-3xl" />
          <div className="relative bg-black/40 border border-white/10 rounded-3xl p-8 backdrop-blur-xl text-center">
            <motion.div
              className="w-20 h-20 mx-auto mb-5 rounded-full bg-gradient-to-br from-[#64FFDA] to-[#22C55E] flex items-center justify-center shadow-xl"
              animate={{
                scale: [1, 1.1, 1],
                boxShadow: [
                  "0 0 20px rgba(34, 197, 94, 0.5)",
                  "0 0 40px rgba(34, 197, 94, 0.2)",
                  "0 0 20px rgba(34, 197, 94, 0.5)",
                ],
              }}
              transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
            >
              <CheckCircle2 className="w-10 h-10 text-black" />
            </motion.div>

            <h2 className="text-2xl font-bold text-white mb-2">{isArabic ? 'تم التحقق من المصادقة الثنائية' : '2FA Verified'}</h2>
            <p className="text-gray-300 mb-4 text-sm">
              {isArabic ? `تم تأكيد هويتك. جارٍ تحويلك إلى ${applicationName}...` : `Your identity has been confirmed. Redirecting you to ${applicationName}...`}
            </p>
          </div>
        </motion.div>
      </div>
    );
  }

  // ------------------ MAIN SCREEN ------------------
  return (
    <div dir={isRtl ? 'rtl' : 'ltr'} className="min-h-screen bg-[#0F172A] flex items-center justify-center relative overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-br from-[#3B82F6]/15 via-[#0F172A] to-[#64FFDA]/15" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 40, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.7, type: "spring", stiffness: 80 }}
        className="relative z-10 w-full max-w-md mx-4"
      >
        <div className="absolute -inset-1 bg-gradient-to-r from-[#64FFDA] via-[#3B82F6] to-[#A855F7] rounded-3xl blur opacity-30" />
        <div className="relative bg-black/35 border border-white/10 rounded-3xl p-8 backdrop-blur-xl shadow-2xl">
          
          {/* Back */}
          <button
            onClick={() => navigate("/login")}
            className="absolute top-5 left-5 p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/10"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>

          {/* Header */}
          <div className="flex flex-col items-center mb-6">
            <motion.div
              className="w-16 h-16 rounded-2xl bg-gradient-to-br from-[#3B82F6] to-[#64FFDA] flex items-center justify-center mb-3 shadow-xl"
              animate={{ rotate: [0, 8, -8, 0] }}
              transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
            >
              <KeyRound className="w-8 h-8 text-black" />
            </motion.div>

            <h1 className="text-2xl font-bold text-white mb-1">
              {isArabic ? 'المصادقة الثنائية' : 'Two-Factor Authentication'}
            </h1>

            <p className="text-gray-300 text-sm text-center">
              {isArabic ? 'أدخل الرمز المكوّن من 6 أرقام المرسل إلى بريدك الإلكتروني.' : 'Enter the 6-digit code sent to your email.'}
            </p>
          </div>

          {/* Email */}
          <div className="flex items-center justify-center mb-5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/15 text-xs text-gray-200">
              <Shield className="w-4 h-4 text-[#64FFDA]" />
              <span className="truncate max-w-[180px]">{resolvedEmail}</span>
            </div>
          </div>

          {/* Errors */}
          <AnimatePresence>
            {serverError && (
              <motion.div
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="mb-4 rounded-lg bg-red-500/10 border border-red-500/40 px-4 py-2 text-xs text-red-300 flex items-center gap-2"
              >
                <AlertCircle className="w-4 h-4" />
                <span>{serverError}</span>
              </motion.div>
            )}
          </AnimatePresence>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <Label className="text-white mb-2 block">{isArabic ? 'رمز التحقق' : 'Verification Code'}</Label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <Input
                  type="text"
                  maxLength={6}
                  inputMode="numeric"
                  value={code}
                  onChange={(e) => {
                    const value = e.target.value.replace(/\D/g, "").slice(0, 6);
                    setCode(value);
                  }}
                  placeholder={isArabic ? 'أدخل رمزًا من 6 أرقام' : 'Enter 6-digit code'}
                  className="pl-12 h-11 bg-white/5 border-white/15 text-white rounded-xl"
                />
              </div>
              <p className="text-xs text-gray-400 mt-2">
                {isArabic ? 'تنتهي صلاحية الرمز خلال بضع دقائق.' : 'Code expires in a few minutes.'}
              </p>
            </div>

            <Button
              type="submit"
              disabled={isLoading || code.length !== 6}
              className="w-full h-11 bg-gradient-to-r from-[#3B82F6] to-[#64FFDA] text-black rounded-xl flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <motion.div
                    className="w-5 h-5 border-2 border-black border-t-transparent rounded-full"
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity }}
                  />
                  {isArabic ? 'جارٍ التحقق...' : 'Verifying...'}
                </>
              ) : (
                (isArabic ? 'تحقق وتابع' : 'Verify & Continue')
              )}
            </Button>
          </form>

          <p className="text-xs text-gray-400 mt-4 text-center">
            Didn't receive the code?{" "}
            <button
              onClick={() => navigate("/login")}
              className="text-[#64FFDA] hover:text-[#3B82F6] underline"
            >
              Back to login
            </button>
          </p>
        </div>
      </motion.div>
    </div>
  );
};
