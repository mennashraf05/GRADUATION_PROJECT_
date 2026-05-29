import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { useNavigate } from "react-router-dom";

import { Button } from "../ui/button";
import { setActiveRecentPcapAlertScopeForUser } from "../../utils/recentPcapAlerts";
import {
  persistEmergencyModeState,
} from "../../utils/authSession";
import { useLanguage } from "../../contexts/LanguageContext";
import { useAppSettings } from "../../contexts/AppSettingsContext";
import {
  Eye,
  EyeOff,
  Mail,
  Lock,
  ArrowRight,
  ArrowLeft,
  Shield,
  Github,
  Sparkles,
} from "lucide-react";

const API_BASE_URL =
  import.meta.env.DEV ? "" : (import.meta.env.VITE_API_BASE_URL || "http://localhost:5000");
const PENDING_2FA_STORAGE_KEY = "sentinel_pending_2fa_token";

  
export default function LoginPage() {
  const { language, isRtl } = useLanguage();
  const { applicationName } = useAppSettings();
  const navigate = useNavigate();

  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [focusedField, setFocusedField] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setError("");
  }, []);

  const [formData, setFormData] = useState({
    email: "",
    password: "",
    rememberMe: false,
  });

  // Load saved email if Remember Me was checked
  useEffect(() => {
    const savedEmail = localStorage.getItem("sentinel_remember_email");
    if (savedEmail) {
      setFormData((prev) => ({
        ...prev,
        email: savedEmail,
        rememberMe: true,
      }));
    }
  }, []);

  const handleInputChange = (field: string, value: string | boolean) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const normalizedEmail = formData.email.trim().toLowerCase();
    const password = formData.password;

    if (!normalizedEmail || !password) {
      setError(language === "arabic" ? "من فضلك أدخل البريد الإلكتروني وكلمة المرور." : "Please enter your email and password.");
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL || ""}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          email: normalizedEmail,
          password,
          remember: formData.rememberMe,
        }),
      });

      let data: Record<string, unknown>;
      try {
        data = await response.json();
      } catch {
        setError("Invalid server response. Make sure the backend is running.");
        return;
      }

      // EMAIL NOT VERIFIED
      if (response.status === 403) {
        setError(
          data?.message ||
            (language === "arabic" ? "يرجى تأكيد بريدك الإلكتروني قبل تسجيل الدخول." : "Please verify your email address before logging in.")
        );
        return;
      }

      if (response.status === 423) {
        persistEmergencyModeState({
          message:
            typeof data?.message === "string" && data.message.trim()
              ? data.message
              : "Emergency Mode activated. All sessions were signed out and your account is temporarily protected.",
          panicModeUntil:
            typeof data?.panic_mode_until === "string"
              ? data.panic_mode_until
              : null,
        });
        navigate("/emergency-locked", { replace: true });
        return;
      }

      // ANY OTHER LOGIN ERROR
      if (!response.ok || data.success === false) {
        setError(
          data?.message ||
            "Login failed. Please check your email and password."
        );
        return;
      }

      // 💙 LOGIN SUCCESS → REQUIRE 2FA
      if (data.requires_2fa_setup) {
        const pendingToken =
          typeof data.pending_token === "string" ? data.pending_token : "";
        if (!pendingToken) {
          setError("2FA setup could not be started. Please try again.");
          return;
        }

        if (formData.rememberMe) {
          localStorage.setItem("sentinel_remember_email", normalizedEmail);
        } else {
          localStorage.removeItem("sentinel_remember_email");
        }

        localStorage.setItem(PENDING_2FA_STORAGE_KEY, pendingToken);
        localStorage.setItem("verifiedEmail", normalizedEmail);
        navigate(`/setup-2fa?email=${encodeURIComponent(normalizedEmail)}`, {
          replace: true,
        });
        return;
      }

      if (data.requires_2fa) {
        const pendingToken =
          typeof data.pending_token === "string" ? data.pending_token : "";
        if (!pendingToken) {
          setError("2FA verification could not be started. Please try again.");
          return;
        }

        if (formData.rememberMe) {
          localStorage.setItem("sentinel_remember_email", normalizedEmail);
        } else {
          localStorage.removeItem("sentinel_remember_email");
        }

        localStorage.setItem(PENDING_2FA_STORAGE_KEY, pendingToken);
        navigate(`/login-2fa?email=${encodeURIComponent(normalizedEmail)}`);
        return;
      }

      // ✅ NO 2FA: Backend sent tokens (cookies + response body)
      // Remember email
      if (formData.rememberMe) {
        localStorage.setItem("sentinel_remember_email", normalizedEmail);
      } else {
        localStorage.removeItem("sentinel_remember_email");
      }

      // Store token from response body (fallback if cookies don't work)
      localStorage.removeItem(PENDING_2FA_STORAGE_KEY);
      localStorage.removeItem("verifiedEmail");
      localStorage.setItem("userEmail", normalizedEmail);
      setActiveRecentPcapAlertScopeForUser({ email: normalizedEmail });
      if (data.token) {
        localStorage.setItem("sentinel_auth_token", data.token);
        localStorage.setItem("sentinel_refresh_token", data.refresh_token || "");
      } else {
        // If no token in body, assume cookies are set
        localStorage.setItem("sentinel_auth_token", "cookie_based");
      }
      
      // Navigate to dashboard - Layout component will verify auth on mount
      navigate("/dashboard", { replace: true });
    } catch (err: unknown) {
      console.error(err);
      const isConnectionRefused =
        err instanceof TypeError &&
        (err.message?.includes("fetch") || err.message?.includes("Failed to fetch"));
      setError(
        isConnectionRefused
          ? "Cannot connect to server. Make sure the backend is running (python app.py from Backend folder)."
          : "Network error. Please try again."
      );
    } finally {
      setIsLoading(false);
    }
  };

  // Animated points background
  const gridPoints = Array.from({ length: 100 }, (_, i) => ({
    id: i,
    x: (i % 10) * 10,
    y: Math.floor(i / 10) * 10,
    delay: Math.random() * 3,
  }));

  const particles = Array.from({ length: 15 }, (_, i) => ({
    id: i,
    x: Math.random() * 100,
    y: Math.random() * 100,
    delay: Math.random() * 5,
    duration: 3 + Math.random() * 4,
  }));

  return (
    <div className="min-h-screen bg-[#0F172A] relative overflow-hidden flex" dir={isRtl ? "rtl" : "ltr"}>
      {/* LEFT PANEL */}
      <div className="flex-1 relative">
        <div className="absolute inset-0">
          {/* Grid */}
          <svg className="absolute inset-0 w-full h-full opacity-20">
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" stroke="#3B82F6" strokeWidth="1" opacity="0.3" fill="none" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />
          </svg>

          {/* Points */}
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
              transition={{
                duration: 4,
                repeat: Infinity,
                delay: point.delay,
                ease: "easeInOut",
              }}
            />
          ))}

          {/* Floating Particles */}
          {particles.map((p) => (
            <motion.div
              key={p.id}
              className="absolute w-2 h-2 rounded-full"
              style={{ left: `${p.x}%`, top: `${p.y}%` }}
              initial={{ opacity: 0, scale: 0 }}
              animate={{
                opacity: [0, 1, 0],
                scale: [0, 1.5, 0],
                y: [-20, 20, -20],
                backgroundColor: ["#64FFDA", "#3B82F6", "#A855F7"],
                boxShadow: ["0 0 10px #64FFDA", "0 0 20px #3B82F6", "0 0 10px #A855F7"],
              }}
              transition={{
                duration: p.duration,
                repeat: Infinity,
                delay: p.delay,
                ease: "easeInOut",
              }}
            />
          ))}
        </div>

        {/* LEFT CONTENT */}
        <div className="relative z-10 flex flex-col justify-center items-center h-full p-12 text-center">
          <div>
            <Shield className="w-16 h-16 mx-auto text-[#64FFDA]" />
            <h1 className="text-4xl font-bold mt-6 bg-gradient-to-r from-white via-[#64FFDA] to-[#3B82F6] bg-clip-text text-transparent">
              {applicationName}
            </h1>
            <p className="text-gray-300 mt-4">
              {language === "arabic" ? "أمن سيبراني متقدم مدعوم بالذكاء الاصطناعي." : "Advanced cybersecurity powered by artificial intelligence."}
            </p>
          </div>
        </div>
      </div>

      {/* RIGHT PANEL */}
      <div className="w-full max-w-md flex items-center justify-center p-8">
        <motion.div
          initial={{ opacity: 0, x: 50, scale: 0.9 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          transition={{ duration: 0.8 }}
          className="w-full max-w-sm"
        >
          <div className="relative">

            {/* Card */}
            <div className="relative bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl">
              {/* HEADER */}
              <div className="text-center mb-8">
                <button
                  onClick={() => navigate("/")}
                  className={`absolute top-6 ${isRtl ? "right-6" : "left-6"} text-gray-400 hover:text-white`}
                >
                  <ArrowLeft />
                </button>

                <h2 className="text-2xl font-bold text-white mb-2">{language === "arabic" ? "مرحبًا بعودتك" : "Welcome Back"}</h2>
                <p className="text-gray-400">{language === "arabic" ? "سجّل الدخول للمتابعة" : "Sign in to continue"}</p>
              </div>

              {/* ERROR */}
              <AnimatePresence>
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

              {/* FORM */}
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* EMAIL */}
                <div>
                  <Label className="text-white mb-2 block">{language === "arabic" ? "البريد الإلكتروني" : "Email Address"}</Label>
                  <div className="relative">
                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" />
                    <Input
                      type="email"
                      value={formData.email}
                      disabled={isLoading}
                      placeholder={language === "arabic" ? "أدخل بريدك الإلكتروني" : "Enter your email"}
                      onChange={(e) => handleInputChange("email", e.target.value)}
                      onFocus={() => setFocusedField("email")}
                      onBlur={() => setFocusedField(null)}
                      className="pl-12 h-12 bg-white/5 border-white/10 text-white rounded-xl"
                    />
                  </div>
                </div>

                {/* PASSWORD */}
                <div>
                  <Label className="text-white mb-2 block">Password</Label>
                  <div className="relative">
                    <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" />
                    <Input
                      type={showPassword ? "text" : "password"}
                      value={formData.password}
                      disabled={isLoading}
                      placeholder="Enter your password"
                      onChange={(e) => handleInputChange("password", e.target.value)}
                      onFocus={() => setFocusedField("password")}
                      onBlur={() => setFocusedField(null)}
                      className="pl-12 pr-12 h-12 bg-white/5 border-white/10 text-white rounded-xl"
                    />

                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400"
                    >
                      {showPassword ? <EyeOff /> : <Eye />}
                    </button>
                  </div>
                </div>

                {/* REMEMBER ME */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <input
                      type="checkbox"
                      id="remember"
                      checked={formData.rememberMe}
                      disabled={isLoading}
                      onChange={(e) =>
                        handleInputChange("rememberMe", e.target.checked)
                      }
                    />
                    <label htmlFor="remember" className="text-sm text-gray-300">
                      {language === "arabic" ? "تذكرني" : "Remember me"}
                    </label>
                  </div>
                </div>

                {/* SUBMIT */}
                <Button
                  disabled={isLoading}
                  className="w-full h-12 bg-gradient-to-r from-[#3B82F6] to-[#64FFDA] text-black font-medium rounded-xl"
                >
                  {isLoading ? (language === "arabic" ? "جارٍ تسجيل الدخول..." : "Signing in…") : (language === "arabic" ? "تسجيل الدخول" : "Sign In")}
                  <ArrowRight className="ml-2 w-4 h-4" />
                </Button>
              </form>

              {/* SIGNUP */}
              <div className="text-center mt-4">
                <p className="text-gray-400">
                  {language === "arabic" ? "ليس لديك حساب؟ " : "Don't have an account? "}
                  <button
                    className="text-[#64FFDA]"
                    onClick={() => navigate("/signup")}
                  >
                    {language === "arabic" ? "إنشاء حساب" : "Sign Up"}
                  </button>
                </p>
              </div>
            </div>

          </div>
        </motion.div>
      </div>
    </div>
  );
}
