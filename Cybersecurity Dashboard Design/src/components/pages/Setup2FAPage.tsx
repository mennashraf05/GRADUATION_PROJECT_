// src/components/pages/Setup2FAPage.tsx
import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { Shield, ArrowLeft, KeyRound, Smartphone } from "lucide-react";
import { useLanguage } from "../../contexts/LanguageContext";

const API_BASE_URL =
  import.meta.env.DEV ? "" : (import.meta.env.VITE_API_BASE_URL || "http://localhost:5000");
const PENDING_2FA_STORAGE_KEY = "sentinel_pending_2fa_token";

interface SetupResponse {
  success?: boolean;
  message?: string;
  secret?: string;
  qr_image_url?: string;
  qrImageUrl?: string;
  qr_url?: string;
}

export const Setup2FAPage: React.FC = () => {
  const navigate = useNavigate();
  const { language, isRtl } = useLanguage();
  const isArabic = language === "arabic";
  const [searchParams] = useSearchParams();
  const emailParam = searchParams.get('email');
  const [secret, setSecret] = useState<string | null>(null);
  const [qrUrl, setQrUrl] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const pendingToken = localStorage.getItem(PENDING_2FA_STORAGE_KEY) || "";

  // 🎯 مصدر الإيميل الحقيقي:
  // searchParams > localStorage > فارغ
  const resolvedEmail =
    emailParam ||
    localStorage.getItem("verifiedEmail")?.trim().toLowerCase() ||
    "";

  useEffect(() => {
    const fetchSetup = async () => {
      setIsLoading(true);
      setServerError(null);
      setSecret(null);
      setQrUrl(null);

      if (!resolvedEmail) {
        setIsLoading(false);
        setServerError(
          "Missing account email for 2FA setup. Please start again from Sign Up."
        );
        return;
      }
      if (!pendingToken) {
        setIsLoading(false);
        setServerError(
          "Your 2FA setup session has expired. Please sign in again to continue."
        );
        return;
      }

      try {
        const response = await fetch(
          `${API_BASE_URL}/api/auth/2fa/setup?email=${encodeURIComponent(
            resolvedEmail
          )}`,
          {
            headers: {
              Authorization: `Bearer ${pendingToken}`,
            },
            credentials: "include", // Send cookies if any
          }
        );

        const data = (await response.json().catch(() => null)) as SetupResponse;

        if (!response.ok || data?.success === false) {
          setServerError(
            data?.message ||
              "Could not initialize 2FA setup. Please try again later."
          );
          return;
        }

        const url =
          data.qr_image_url || data.qrImageUrl || data.qr_url || null;

        if (url) setQrUrl(url);
        if (data.secret) setSecret(data.secret);
      } catch (err) {
        setServerError("Network error during 2FA setup.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchSetup();
  }, [pendingToken, resolvedEmail]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!code.trim() || !resolvedEmail) return;
    if (!pendingToken) {
      setServerError("Your 2FA setup session has expired. Please sign in again.");
      return;
    }

    setIsSubmitting(true);
    setServerError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/2fa/verify-setup`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${pendingToken}`,
        },
        credentials: "include", // Send/receive cookies
        body: JSON.stringify({
          email: resolvedEmail,
          code: code.trim(),
          pending_token: pendingToken,
        }),
      });

      const data = (await response.json().catch(() => null)) as {
        success?: boolean;
        message?: string;
      };

      if (!response.ok || data?.success === false) {
        setServerError(
          data?.message ||
            "The code is invalid. Please try again with a new code."
        );
        return;
      }

      // 🎉 نجاح
      localStorage.removeItem(PENDING_2FA_STORAGE_KEY);
      localStorage.removeItem("verifiedEmail");
      navigate("/login");
    } catch (err) {
      setServerError("Network error. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div dir={isRtl ? "rtl" : "ltr"} className="min-h-screen bg-[#0F172A] relative overflow-hidden flex items-center justify-center text-white">
      {/* Background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-br from-[#3B82F6]/10 via-transparent to-[#64FFDA]/10" />
        <motion.div
          className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-[#64FFDA] to-transparent"
          animate={{ y: ["-10%", "110%"], opacity: [0, 1, 0] }}
          transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
        />
        <motion.div
          className="absolute w-0.5 h-full bg-gradient-to-b from-transparent via-[#3B82F6] to-[#64FFDA]/20"
          animate={{ x: ["-10%", "110%"], opacity: [0, 1, 0] }}
          transition={{ duration: 8, repeat: Infinity, delay: 3, ease: "linear" }}
        />
      </div>

      {/* Main Box */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="relative z-10 w-full max-w-2xl bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-xl"
      >
        {/* Back Button */}
        <button
          onClick={() => navigate("/login")}
          className="absolute top-6 left-6 p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/10"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>

        {/* Title */}
        <div className={`flex items-center mb-6 ${isRtl ? 'space-x-reverse space-x-3' : 'space-x-3'}`}>
          <div className="w-12 h-12 rounded-xl bg-[#3B82F6]/20 flex items-center justify-center border border-[#3B82F6]/40">
            <Shield className="w-7 h-7 text-[#64FFDA]" />
          </div>
          <div>
            <h2 className="text-2xl font-bold">{isArabic ? "إعداد المصادقة الثنائية" : "Set up 2-Factor Authentication"}</h2>
            <p className="text-gray-400 text-sm">
              {isArabic ? "احمِ حسابك بطبقة أمان إضافية." : "Protect your account with an extra layer of security."}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* Instructions */}
          <div className="text-sm space-y-4 text-gray-300">
            <p className="flex items-start gap-2">
              <Smartphone className="w-4 text-[#64FFDA]" /> {isArabic ? "ثبّت تطبيق مصادقة على هاتفك." : "Install an authenticator app on your phone."}
            </p>
            <p className="flex items-start gap-2">
              <KeyRound className="w-4 text-[#64FFDA]" /> {isArabic ? "امسح رمز QR أو أدخل المفتاح السري يدويًا." : "Scan the QR or enter the secret key manually."}
            </p>
            <p className="flex items-start gap-2">
              <KeyRound className="w-4 text-[#64FFDA]" /> {isArabic ? "أدخل الرمز المكوّن من 6 أرقام من التطبيق." : "Enter the 6-digit code from the app."}
            </p>

            {secret && (
              <div>
                <p className="text-xs text-gray-400 mb-1">{isArabic ? "المفتاح السري:" : "Secret Key:"}</p>
                <div className="text-xs font-mono bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-[#64FFDA] break-all">
                  {secret}
                </div>
              </div>
            )}
          </div>

          {/* QR + Input */}
          <div className="space-y-5">
            <div className="flex justify-center">
              {isLoading ? (
                <div className="w-32 h-32 border border-dashed border-gray-600 rounded-xl text-gray-400 flex items-center justify-center text-xs">
                  Loading QR…
                </div>
              ) : qrUrl ? (
                <div className="bg-white p-3 rounded-xl shadow-md">
                  <img
                    src={qrUrl}
                    alt="QR"
                    className="w-40 h-40 object-contain"
                  />
                </div>
              ) : (
                <div className="w-32 h-32 border border-dashed border-gray-600 rounded-xl text-gray-400 flex items-center justify-center text-xs text-center">
                  QR not available.
                </div>
              )}
            </div>

            {/* Error Message */}
            <AnimatePresence>
              {serverError && (
                <motion.div
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  className="rounded-lg bg-red-500/10 border border-red-500/30 px-4 py-2 text-xs text-red-300"
                >
                  {serverError}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              <Input
                type="text"
                maxLength={6}
                inputMode="numeric"
                placeholder="Enter 6-digit code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                className="h-11 bg-white/5 border-white/10 rounded-xl text-white"
              />

              <Button
                type="submit"
                disabled={isSubmitting || code.length < 6}
                className="w-full h-11 bg-gradient-to-r from-[#3B82F6] to-[#64FFDA] text-black font-medium rounded-xl shadow-md disabled:opacity-50"
              >
                {isSubmitting ? "Verifying…" : "Confirm & Enable 2FA"}
              </Button>
            </form>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
