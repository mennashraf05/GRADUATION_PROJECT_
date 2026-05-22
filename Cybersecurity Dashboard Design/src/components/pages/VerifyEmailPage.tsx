// src/pages/auth/VerifyEmailPage.tsx

import React, { useEffect, useState } from "react";
import { motion } from "motion/react";
import { Mail, CheckCircle, ArrowLeft, XCircle } from "lucide-react";
import { Button } from "../../components/ui/button";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useLanguage } from "../../contexts/LanguageContext";

const API =
  import.meta.env.DEV ? "" : (import.meta.env.VITE_API_BASE_URL || "http://localhost:5000");
const PENDING_2FA_STORAGE_KEY = "sentinel_pending_2fa_token";

export default function VerifyEmailPage() {
  const navigate = useNavigate();
  const { language, isRtl } = useLanguage();
  const isArabic = language === "arabic";
  const [params] = useSearchParams();

  const [status, setStatus] = useState<"verifying" | "success" | "error">(
    "verifying"
  );

  const token = params.get("token");

  useEffect(() => {
    if (!token) {
      setStatus("error");
      return;
    }

    let hasNavigated = false;

    fetch(`${API}/api/auth/verify-email-token?token=${encodeURIComponent(token)}`, {
      credentials: "include",
    })
      .then(async (res) => {
        const data = await res.json().catch(() => ({}));
        
        if (res.ok && data.success && data.email) {
          localStorage.setItem("verifiedEmail", data.email);
          if (typeof data.pending_token === "string" && data.pending_token) {
            localStorage.setItem(PENDING_2FA_STORAGE_KEY, data.pending_token);
          }

          hasNavigated = true;
          if (data.requires_2fa_setup) {
            navigate(`/setup-2fa?email=${encodeURIComponent(data.email)}`, {
              replace: true,
            });
          } else {
            navigate("/login", { replace: true });
          }
          return;
        }
        
        // If failed, show error only if we haven't navigated
        // Add small delay to prevent flash of error before navigation
        setTimeout(() => {
          if (!hasNavigated) {
            setStatus("error");
          }
        }, 200);
      })
      .catch((err) => {
        console.error("Email verification error:", err);
        // Add small delay to prevent flash of error
        setTimeout(() => {
          if (!hasNavigated) {
            setStatus("error");
          }
        }, 200);
      });
  }, [token, navigate]);

  const email =
    localStorage.getItem("verifiedEmail") ||
    (isArabic ? "تم التحقق من البريد" : "Email Verified");

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
          className="absolute w-0.5 h-full bg-gradient-to-b from-transparent via-[#3B82F6] to-transparent"
          animate={{ x: ["-10%", "110%"], opacity: [0, 1, 0] }}
          transition={{
            duration: 8,
            repeat: Infinity,
            delay: 3,
            ease: "linear",
          }}
        />
      </div>

      {/* Card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="relative z-10 w-full max-w-md bg-black/20 backdrop-blur-xl 
                   border border-white/10 rounded-2xl p-8 text-center shadow-2xl"
      >
        {/* Back Button */}
        <div className="flex justify-between mb-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate("/signup")}
            className="text-gray-400 hover:text-white hover:bg-white/5"
          >
            <ArrowLeft className="w-5 h-5" />
          </Button>
        </div>

        {/* STATUS: VERIFYING */}
        {status === "verifying" && (
          <div className="space-y-4">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 1.1, ease: "linear" }}
              className="w-14 h-14 mx-auto border-4 border-transparent border-t-[#64FFDA] rounded-full"
            />
            <h1 className="text-xl font-semibold">Verifying your email…</h1>
          </div>
        )}

        {/* STATUS: ERROR */}
        {status === "error" && (
          <div className="space-y-4">
            <div className="w-16 h-16 rounded-full bg-red-500/20 border border-red-500/40 
                            flex items-center justify-center mx-auto">
              <XCircle className="w-10 h-10 text-red-400" />
            </div>

            <h1 className="text-xl font-bold text-red-400">Verification Failed</h1>

            <p className="text-gray-400 text-sm">
              Invalid or expired verification link.
            </p>

            <Button
              onClick={() => navigate("/signup")}
              className="mt-3 w-full bg-red-500/20 hover:bg-red-500/30 
                         border border-red-500/40 text-white"
            >
              Back to Sign Up
            </Button>
          </div>
        )}

        {/* STATUS: SUCCESS */}
        {status === "success" && (
          <div className="space-y-4">
            <div className="w-16 h-16 rounded-full bg-emerald-500/20 border 
                            border-emerald-500/40 flex items-center justify-center mx-auto">
              <CheckCircle className="w-10 h-10 text-emerald-400" />
            </div>

            <h1 className="text-2xl font-bold">Email Verified Successfully!</h1>

            <div className="flex items-center justify-center space-x-2 text-sm text-gray-300">
              <Mail className="w-4 h-4 text-[#64FFDA]" />
              <span>{email}</span>
            </div>

            <p className="text-gray-400 text-sm max-w-xs mx-auto">
              Redirecting you to 2-Factor Authentication setup…
            </p>
          </div>
        )}
      </motion.div>
    </div>
  );
}
