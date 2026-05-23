import React, { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { Shield, ArrowLeft, KeyRound, Lock } from "lucide-react";
import { setActiveRecentPcapAlertScopeForUser } from "../../utils/recentPcapAlerts";
import { useLanguage } from "../../contexts/LanguageContext";

const API_BASE_URL = import.meta.env.DEV
  ? ""
  : (import.meta.env.VITE_API_BASE_URL || "http://localhost:5000");
const PENDING_2FA_STORAGE_KEY = "sentinel_pending_2fa_token";

export const Login2FAPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { t, isRtl } = useLanguage();
  const email = searchParams.get("email") || "";
  const pendingToken =
    searchParams.get("tempToken") ||
    localStorage.getItem(PENDING_2FA_STORAGE_KEY) ||
    "";
  const [code, setCode] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError(null);
    setIsSubmitting(true);

    try {
      if (!pendingToken) {
        setServerError(t("login2fa.sessionExpired"));
        setIsSubmitting(false);
        return;
      }

      const response = await fetch(
        `${API_BASE_URL || ""}/api/auth/2fa/verify-login`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${pendingToken}`,
          },
          credentials: "include",
          body: JSON.stringify({
            email: email.toLowerCase().trim(),
            code: code.trim(),
            pending_token: pendingToken,
          }),
        }
      );

      let data: {
        success?: boolean;
        message?: string;
        token?: string;
        refresh_token?: string;
      };
      try {
        data = await response.json();
      } catch {
        setServerError(t("login2fa.invalidServerResponse"));
        setIsSubmitting(false);
        return;
      }
      if (!data.success) {
        setServerError(data.message || t("login2fa.invalidCode"));
        setIsSubmitting(false);
        return;
      }

      if (data.token) {
        localStorage.setItem("sentinel_auth_token", data.token);
        if (data.refresh_token) {
          localStorage.setItem("sentinel_refresh_token", data.refresh_token);
        }
      } else {
        localStorage.setItem("sentinel_auth_token", "cookie_based");
      }

      localStorage.removeItem(PENDING_2FA_STORAGE_KEY);
      localStorage.setItem("userEmail", email);
      setActiveRecentPcapAlertScopeForUser({ email });

      await new Promise((resolve) => setTimeout(resolve, 50));
      navigate("/dashboard", { replace: true });
    } catch (err: unknown) {
      console.error("2FA error:", err);
      const isConnectionRefused =
        err instanceof TypeError &&
        (String((err as Error).message)?.includes("fetch") ||
          String((err as Error).message)?.includes("Failed to fetch"));
      setServerError(
        isConnectionRefused
          ? t("login2fa.cannotConnect")
          : t("login2fa.genericError")
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="min-h-screen bg-[#0F172A] relative overflow-hidden flex items-center justify-center"
      dir={isRtl ? "rtl" : "ltr"}
    >
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
            ease: "linear",
            delay: 3,
          }}
        />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 30, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        className="relative z-10 w-full max-w-md mx-4 bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl"
      >
        <button
          type="button"
          onClick={() => navigate("/login")}
          className="absolute top-6 left-6 p-2 text-gray-400 hover:text-white transition-colors rounded-lg hover:bg-white/5"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>

        <div className="text-center mb-6">
          <div className="mx-auto mb-4 w-14 h-14 rounded-full bg-[#3B82F6]/20 flex items-center justify-center border border-[#3B82F6]/40">
            <Shield className="w-7 h-7 text-[#64FFDA]" />
          </div>

          <h2 className="text-2xl font-bold text-white mb-1">
            {t("login2fa.title")}
          </h2>
          <p className="text-gray-400 text-sm">
            {t("login2fa.description", { email })}
          </p>
        </div>

        <AnimatePresence>
          {serverError && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="mb-4 rounded-lg bg-red-500/10 border border-red-500/40 px-4 py-2 text-sm text-red-300"
            >
              {serverError}
            </motion.div>
          )}
        </AnimatePresence>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label
              htmlFor="code"
              className="block text-sm font-medium text-white mb-2"
            >
              {t("login2fa.codeLabel")}
            </label>
            <div className="relative">
              <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <Input
                id="code"
                type="text"
                inputMode="numeric"
                maxLength={6}
                placeholder={t("login2fa.codePlaceholder")}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                className="h-12 bg-white/5 border-white/10 text-white placeholder-gray-400 rounded-xl pl-10"
                autoFocus
              />
            </div>
          </div>

          <Button
            type="submit"
            disabled={isSubmitting || code.trim().length < 6}
            className="w-full h-12 bg-gradient-to-r from-[#3B82F6] to-[#64FFDA] hover:from-[#2563EB] hover:to-[#10B981] text-black font-medium rounded-xl shadow-lg disabled:opacity-50 flex items-center justify-center space-x-2"
          >
            {isSubmitting ? (
              <>
                <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
                <span>{t("login2fa.verifying")}</span>
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" />
                <span>{t("login2fa.completeSignIn")}</span>
              </>
            )}
          </Button>
        </form>
      </motion.div>
    </div>
  );
};
