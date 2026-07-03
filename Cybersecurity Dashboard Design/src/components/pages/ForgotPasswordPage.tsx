import React, { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, CheckCircle, Loader2, Mail, Shield } from "lucide-react";

import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { useAppSettings } from "../../contexts/AppSettingsContext";
import { useLanguage } from "../../contexts/LanguageContext";

const API_BASE_URL =
  import.meta.env.DEV ? "" : (import.meta.env.VITE_API_BASE_URL || "http://localhost:5000");

const SUCCESS_MESSAGE = "If this email exists, a password reset link has been sent.";

function AuthBackground() {
  const gridPoints = Array.from({ length: 100 }, (_, i) => ({
    id: i,
    x: (i % 10) * 10,
    y: Math.floor(i / 10) * 10,
    delay: (i % 9) * 0.25,
  }));

  return (
    <div className="absolute inset-0">
      <svg className="absolute inset-0 w-full h-full opacity-20">
        <defs>
          <pattern id="forgot-grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" stroke="#3B82F6" strokeWidth="1" opacity="0.3" fill="none" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#forgot-grid)" />
      </svg>
      {gridPoints.map((point) => (
        <motion.div
          key={point.id}
          className="absolute w-1 h-1 rounded-full"
          style={{ left: `${point.x}%`, top: `${point.y}%` }}
          initial={{ opacity: 0, scale: 0 }}
          animate={{
            opacity: [0.2, 0.8, 0.2],
            scale: [0.5, 1.2, 0.5],
            backgroundColor: ["#3B82F6", "#64FFDA", "#3B82F6"],
          }}
          transition={{ duration: 4, repeat: Infinity, delay: point.delay, ease: "easeInOut" }}
        />
      ))}
    </div>
  );
}

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const { applicationName } = useAppSettings();
  const { isRtl } = useLanguage();
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const [fieldError, setFieldError] = useState("");

  const validateEmail = () => {
    const normalized = email.trim();
    if (!normalized) {
      setFieldError("Email is required");
      return false;
    }
    if (!/^\S+@\S+\.\S+$/.test(normalized)) {
      setFieldError("Please enter a valid email address");
      return false;
    }
    setFieldError("");
    return true;
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    setSuccess("");
    if (!validateEmail()) return;

    setIsLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL || ""}/api/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
      });

      if (!response.ok && response.status >= 500) {
        setError("Unable to send reset link right now. Please try again later.");
        return;
      }

      setSuccess(SUCCESS_MESSAGE);
    } catch {
      setError("Network error. Please check your connection and try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0F172A] relative overflow-hidden flex" dir={isRtl ? "rtl" : "ltr"}>
      <div className="flex-1 relative hidden lg:block">
        <AuthBackground />
        <div className="relative z-10 flex flex-col justify-center items-center h-full p-12 text-center">
          <Shield className="w-16 h-16 mx-auto text-[#64FFDA]" />
          <h1 className="text-4xl font-bold mt-6 bg-gradient-to-r from-white via-[#64FFDA] to-[#3B82F6] bg-clip-text text-transparent">
            {applicationName}
          </h1>
          <p className="text-gray-300 mt-4">Secure account recovery for your Sentinel AI workspace.</p>
        </div>
      </div>

      <div className="w-full max-w-md flex items-center justify-center p-8 mx-auto">
        <motion.div
          initial={{ opacity: 0, x: 50, scale: 0.9 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          transition={{ duration: 0.8 }}
          className="w-full max-w-sm"
        >
          <div className="relative bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl">
            <button
              onClick={() => navigate("/login")}
              className="absolute top-6 left-6 text-gray-400 hover:text-white transition-colors"
              aria-label="Back to Sign In"
            >
              <ArrowLeft />
            </button>

            <div className="text-center mb-8 pt-2">
              <h2 className="text-2xl font-bold text-white mb-2">Forgot Password?</h2>
              <p className="text-gray-400">Enter your email address and we'll send you a reset link.</p>
            </div>

            <AnimatePresence>
              {success && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  className="mb-4 border border-emerald-400/40 bg-emerald-400/10 rounded-xl px-3 py-3 text-sm text-emerald-100 flex gap-2"
                >
                  <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <span>{success}</span>
                </motion.div>
              )}
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  className="mb-4 border border-red-500/40 bg-red-500/10 rounded-xl px-3 py-2 text-sm text-red-100"
                >
                  {error}
                </motion.div>
              )}
            </AnimatePresence>

            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <Label htmlFor="reset-email" className="text-white mb-2 block">
                  Email Address
                </Label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" />
                  <Input
                    id="reset-email"
                    type="email"
                    value={email}
                    disabled={isLoading}
                    placeholder="Enter your email"
                    autoComplete="email"
                    onChange={(event) => {
                      setEmail(event.target.value);
                      if (fieldError) setFieldError("");
                      if (error) setError("");
                    }}
                    onBlur={validateEmail}
                    className={`pl-12 h-12 bg-white/5 border-white/10 text-white placeholder-gray-400 rounded-xl focus:border-[#64FFDA] focus:ring-2 focus:ring-[#64FFDA]/20 ${fieldError ? "border-red-500" : ""}`}
                  />
                </div>
                {fieldError && <p className="text-red-400 text-sm mt-1">{fieldError}</p>}
              </div>

              <Button
                type="submit"
                disabled={isLoading}
                className="w-full h-12 bg-gradient-to-r from-[#3B82F6] to-[#64FFDA] text-black font-medium rounded-xl disabled:opacity-60"
              >
                {isLoading ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Sending...
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    Send Reset Link
                    <ArrowRight className="w-4 h-4" />
                  </span>
                )}
              </Button>
            </form>

            <div className="text-center mt-4">
              <button className="text-[#64FFDA] hover:text-[#3B82F6] transition-colors" onClick={() => navigate("/login")}>
                Back to Sign In
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
