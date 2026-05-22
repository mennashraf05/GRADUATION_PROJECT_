import React from "react";
import { motion } from "motion/react";
import { AlertTriangle, Clock3, LogIn, ShieldAlert } from "lucide-react";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";

import { Button } from "../ui/button";
import {
  clearEmergencyModeState,
  readEmergencyModeState,
} from "../../utils/authSession";

function formatUnlockTime(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) {
    return null;
  }

  return new Date(timestamp).toLocaleString();
}

export function EmergencyLockedPage() {
  const navigate = useNavigate();
  const state = readEmergencyModeState();

  const unlockTime = useMemo(
    () => formatUnlockTime(state?.panicModeUntil ?? null),
    [state?.panicModeUntil]
  );

  return (
    <div className="relative min-h-screen overflow-hidden bg-[radial-gradient(circle_at_top,rgba(190,24,93,0.18),transparent_34%),linear-gradient(180deg,#070b14_0%,#0b1220_48%,#111827_100%)] text-white">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(120deg,rgba(255,255,255,0.04),transparent_28%,transparent_72%,rgba(244,63,94,0.08))]" />
      <div className="relative mx-auto flex min-h-screen max-w-6xl items-center justify-center px-6 py-16">
        <motion.div
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="w-full max-w-2xl rounded-[28px] border border-white/10 bg-slate-950/70 p-8 shadow-[0_30px_80px_rgba(2,6,23,0.55)] backdrop-blur-xl md:p-10"
        >
          <div className="mb-8 flex items-start gap-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-rose-400/25 bg-rose-500/12 shadow-[0_0_40px_rgba(244,63,94,0.12)]">
              <ShieldAlert className="h-8 w-8 text-rose-100" />
            </div>
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 rounded-full border border-rose-400/20 bg-rose-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-rose-100/90">
                <AlertTriangle className="h-3.5 w-3.5" />
                Emergency Lock Active
              </div>
              <h1 className="text-3xl font-semibold tracking-tight text-white md:text-4xl">
                Emergency Mode activated
              </h1>
              <p className="max-w-xl text-sm leading-6 text-slate-300 md:text-base">
                {state?.message ||
                  "Emergency Mode activated. All sessions were signed out and your account is temporarily protected."}
              </p>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-5">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">
                Protection status
              </p>
              <p className="mt-3 text-lg font-medium text-white">
                All active sessions were revoked
              </p>
              <p className="mt-2 text-sm leading-6 text-slate-400">
                Other devices were signed out immediately, and new requests are blocked until the protection window ends.
              </p>
            </div>

            <div className="rounded-2xl border border-rose-400/12 bg-rose-500/[0.05] p-5">
              <div className="flex items-center gap-2 text-rose-100">
                <Clock3 className="h-4 w-4" />
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-rose-100/80">
                  Unlock time
                </p>
              </div>
              <p className="mt-3 text-lg font-medium text-white">
                {unlockTime || "Available shortly"}
              </p>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                When the temporary protection period expires, you can sign in again from the login screen.
              </p>
            </div>
          </div>

          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <Button
              className="h-11 flex-1 bg-white text-slate-950 hover:bg-slate-100"
              onClick={() => {
                clearEmergencyModeState();
                navigate("/login");
              }}
            >
              <LogIn className="mr-2 h-4 w-4" />
              Return to Login
            </Button>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
