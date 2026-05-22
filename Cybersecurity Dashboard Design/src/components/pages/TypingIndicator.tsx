import React from 'react';
import { motion } from 'motion/react';
import { Bot, LoaderCircle, Sparkles } from 'lucide-react';

export function TypingIndicator() {
  return (
    <motion.div
      key="typing-indicator"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.24 }}
      className="flex items-start gap-3"
    >
      <div className="relative z-10 flex h-11 w-11 items-center justify-center rounded-[18px] border border-emerald-400/20 bg-[linear-gradient(180deg,rgba(16,185,129,0.18),rgba(34,211,238,0.10))] shadow-[0_14px_32px_rgba(2,6,23,0.22)]">
        <Bot className="h-4.5 w-4.5 text-emerald-300" />
      </div>

      <div className="relative overflow-hidden rounded-[26px] rounded-tl-md border border-emerald-400/14 bg-[linear-gradient(180deg,rgba(5,20,31,0.96),rgba(7,14,26,0.98))] px-4 py-3 text-sm text-slate-300 shadow-[0_18px_40px_rgba(2,6,23,0.24)] backdrop-blur-xl">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(16,185,129,0.08),transparent_18%)]" />
        <div className="relative mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
          <Sparkles className="h-3.5 w-3.5 text-emerald-300" />
          AI response in progress
        </div>
        <div className="relative flex items-center gap-2">
          <LoaderCircle className="h-4 w-4 animate-spin text-emerald-300" />
          <span>Sentinel is correlating the context and drafting the next investigation step...</span>
        </div>
      </div>
    </motion.div>
  );
}
