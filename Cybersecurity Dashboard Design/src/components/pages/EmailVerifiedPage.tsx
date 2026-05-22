import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "motion/react";
import { CheckCircle, XCircle } from "lucide-react";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

type Status = "verifying" | "success" | "error";

export default function EmailVerifiedPage() {
  const navigate = useNavigate();
  const [status, setStatus] = useState<Status>("verifying");
  const [message, setMessage] = useState("Verifying your email… Please wait.");
  const [hasResponse, setHasResponse] = useState(false); // ⭐ Prevents early error flash

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get("token");

    if (!token) {
      setHasResponse(true); // ⭐
      setStatus("error");
      setMessage("Invalid or missing verification link. Redirecting…");
      setTimeout(() => navigate("/signup"), 2000);
      return;
    }

    fetch(`${API_BASE_URL}/api/auth/verify-email-token?token=${token}`)
      .then((res) => res.json())
      .then((data) => {
        setHasResponse(true); // ⭐ reveal icon only after backend response

        if (data?.success && data?.email) {
          setStatus("success");
          setMessage("Email verified successfully! Redirecting to 2FA setup…");

          setTimeout(() => {
            navigate(
              `/setup-2fa?email=${encodeURIComponent(
                (data.email as string).toLowerCase().trim()
              )}`
            );
          }, 1300);
        } else {
          setStatus("error");
          setMessage(
            data?.message ||
              "Verification link expired or invalid. Redirecting…"
          );
          setTimeout(() => navigate("/signup"), 2200);
        }
      })
      .catch(() => {
        setHasResponse(true); // ⭐
        setStatus("error");
        setMessage(
          "Network error while verifying your email. Please try again. Redirecting…"
        );
        setTimeout(() => navigate("/signup"), 2500);
      });
  }, [navigate]);

  const title =
    status === "success"
      ? "Email Verified"
      : status === "error"
      ? "Verification Failed"
      : "Verifying Email…";

  const Icon = status === "error" ? XCircle : CheckCircle;

  return (
    <div className="min-h-screen bg-[#0F172A] relative overflow-hidden flex items-center justify-center">
      {/* Background Glow */}
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
          transition={{ duration: 8, repeat: Infinity, delay: 3, ease: "linear" }}
        />
      </div>

      {/* Card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="relative z-10 w-full max-w-md bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-10 text-center shadow-2xl"
      >
        <div className="flex flex-col items-center space-y-4">
          {/* Icon — only show AFTER backend response */}
          {hasResponse && (
            <div
              className={`w-16 h-16 rounded-full border flex items-center justify-center ${
                status === "error"
                  ? "bg-red-500/20 border-red-500/40"
                  : "bg-emerald-500/20 border-emerald-500/40"
              }`}
            >
              <Icon
                className={`w-10 h-10 ${
                  status === "error" ? "text-red-400" : "text-emerald-400"
                }`}
              />
            </div>
          )}

          {/* Title */}
          <h1 className="text-2xl font-bold text-white">{title}</h1>

          {/* Message */}
          <p className="text-gray-300 text-sm max-w-xs">{message}</p>

          {/* Spinner only while verifying */}
          {status === "verifying" && (
            <motion.div
              className="mt-4 w-8 h-8 border-4 border-[#64FFDA] border-t-transparent rounded-full"
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 1, ease: "linear" }}
            />
          )}
        </div>
      </motion.div>
    </div>
  );
}
