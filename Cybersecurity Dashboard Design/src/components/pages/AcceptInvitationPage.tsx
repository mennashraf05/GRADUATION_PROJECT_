import React, { useEffect, useState } from "react";
import { motion } from "motion/react";
import { Shield, Mail, Lock, KeyRound, ArrowLeft, CheckCircle, XCircle } from "lucide-react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { useAppSettings } from "../../contexts/AppSettingsContext";

const API_BASE_URL =
  import.meta.env.DEV ? "" : (import.meta.env.VITE_API_BASE_URL || "http://localhost:5000");
const PENDING_2FA_STORAGE_KEY = "sentinel_pending_2fa_token";

type InvitationDetails = {
  email: string;
  name: string;
  role: string;
  requireTwoFactor: boolean;
  expiresAt: string | null;
};

export default function AcceptInvitationPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { applicationName } = useAppSettings();
  const token = searchParams.get("token") || "";

  const [invitation, setInvitation] = useState<InvitationDetails | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  useEffect(() => {
    let isMounted = true;

    const loadInvitation = async () => {
      if (!token) {
        setServerError("Invitation link is missing its token.");
        setIsLoading(false);
        return;
      }

      try {
        const response = await fetch(
          `${API_BASE_URL}/api/invitations/${encodeURIComponent(token)}`,
          {
            credentials: "include",
          },
        );

        const data = (await response.json().catch(() => null)) as
          | {
              success?: boolean;
              message?: string;
              invitation?: InvitationDetails;
            }
          | null;

        if (!isMounted) return;

        if (!response.ok || data?.success === false || !data?.invitation) {
          setServerError(data?.message || "This invitation is invalid or has expired.");
          setIsLoading(false);
          return;
        }

        setInvitation(data.invitation);
        setName(data.invitation.name || "");
        setIsLoading(false);
      } catch {
        if (!isMounted) return;
        setServerError("Network error while loading your invitation.");
        setIsLoading(false);
      }
    };

    void loadInvitation();
    return () => {
      isMounted = false;
    };
  }, [token]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setServerError(null);

    if (!token) {
      setServerError("Invitation token is missing.");
      return;
    }
    if (!password || password.length < 8) {
      setServerError("Choose a password with at least 8 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setServerError("Passwords do not match.");
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/invitations/${encodeURIComponent(token)}/accept`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            name: name.trim(),
            password,
          }),
        },
      );

      const data = (await response.json().catch(() => null)) as
        | {
            success?: boolean;
            message?: string;
            email?: string;
            pending_token?: string;
            requires_2fa_setup?: boolean;
          }
        | null;

      if (!response.ok || data?.success === false) {
        setServerError(data?.message || "Could not complete your invitation.");
        setIsSubmitting(false);
        return;
      }

      if (typeof data?.email === "string" && data.email) {
        localStorage.setItem("verifiedEmail", data.email);
      }

      if (data?.requires_2fa_setup && typeof data?.pending_token === "string" && data.pending_token) {
        localStorage.setItem(PENDING_2FA_STORAGE_KEY, data.pending_token);
        navigate(`/setup-2fa?email=${encodeURIComponent(data.email || invitation?.email || "")}`, {
          replace: true,
        });
        return;
      }

      localStorage.removeItem(PENDING_2FA_STORAGE_KEY);
      navigate("/login", { replace: true });
    } catch {
      setServerError("Network error. Please try again.");
      setIsSubmitting(false);
    }
  };

  const expiresLabel = invitation?.expiresAt
    ? new Date(invitation.expiresAt).toLocaleString()
    : null;

  return (
    <div className="min-h-screen bg-[#0F172A] relative overflow-hidden flex items-center justify-center text-white px-4 py-10">
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-br from-[#3B82F6]/10 via-transparent to-[#64FFDA]/10" />
        <motion.div
          className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-[#64FFDA] to-transparent"
          animate={{ y: ["-10%", "110%"], opacity: [0, 1, 0] }}
          transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
        />
      </div>

      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 18 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="relative z-10 w-full max-w-2xl rounded-[28px] border border-white/10 bg-black/25 p-8 shadow-2xl backdrop-blur-xl"
      >
        <button
          onClick={() => navigate("/login")}
          className="mb-6 inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-300 transition hover:bg-white/10 hover:text-white"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to login
        </button>

        <div className="mb-8 flex items-start gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-sky-400/20 bg-sky-500/10">
            <Shield className="h-7 w-7 text-sky-300" />
          </div>
          <div>
            <h1 className="text-3xl font-semibold tracking-tight">Complete your invitation</h1>
            <p className="mt-2 max-w-xl text-sm leading-7 text-slate-400">
              Finish your {applicationName} account setup by choosing your password
              {invitation?.requireTwoFactor ? " and enabling 2FA" : ""}.
            </p>
          </div>
        </div>

        {isLoading ? (
          <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-8 text-center text-slate-400">
            Loading invitation details...
          </div>
        ) : serverError && !invitation ? (
          <div className="rounded-2xl border border-red-400/25 bg-red-500/10 p-8 text-center">
            <XCircle className="mx-auto h-10 w-10 text-red-300" />
            <p className="mt-4 text-base text-red-100">{serverError}</p>
          </div>
        ) : invitation ? (
          <div className="grid gap-6 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
            <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
              <div className="space-y-4">
                <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                  <div className="flex items-center gap-3">
                    <Mail className="h-4 w-4 text-sky-300" />
                    <div>
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Email</p>
                      <p className="mt-1 text-sm text-white break-all">{invitation.email}</p>
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="h-4 w-4 text-emerald-300" />
                    <div>
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Role</p>
                      <p className="mt-1 text-sm text-white">{invitation.role}</p>
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
                  <div className="flex items-center gap-3">
                    <KeyRound className="h-4 w-4 text-amber-300" />
                    <div>
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Security Setup</p>
                      <p className="mt-1 text-sm text-white">
                        {invitation.requireTwoFactor ? "Password + 2FA required" : "Password setup only"}
                      </p>
                    </div>
                  </div>
                </div>
                {expiresLabel ? (
                  <p className="text-xs leading-6 text-slate-500">
                    Invitation expires {expiresLabel}
                  </p>
                ) : null}
              </div>
            </div>

            <form onSubmit={handleSubmit} className="rounded-3xl border border-white/10 bg-white/[0.04] p-5 space-y-4">
              <div>
                <label className="mb-2 block text-sm font-medium text-white">Name</label>
                <Input
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Enter your name"
                  className="bg-[#0F172A] border-white/10 text-white"
                />
              </div>
              <div>
                <label className="mb-2 block text-sm font-medium text-white">Password</label>
                <Input
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Create a strong password"
                  className="bg-[#0F172A] border-white/10 text-white"
                />
              </div>
              <div>
                <label className="mb-2 block text-sm font-medium text-white">Confirm Password</label>
                <Input
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  placeholder="Confirm your password"
                  className="bg-[#0F172A] border-white/10 text-white"
                />
              </div>

              {serverError ? (
                <div className="rounded-xl border border-red-400/25 bg-red-500/10 px-4 py-3 text-sm text-red-100">
                  {serverError}
                </div>
              ) : null}

              <Button
                type="submit"
                disabled={isSubmitting}
                className="h-11 w-full bg-blue-500 text-white hover:bg-blue-600"
              >
                {isSubmitting ? "Completing setup..." : invitation.requireTwoFactor ? "Continue to 2FA Setup" : "Activate Account"}
              </Button>
            </form>
          </div>
        ) : null}
      </motion.div>
    </div>
  );
}
