import React from "react";
import { Activity, AlertTriangle, type LucideIcon } from "lucide-react";

import { cn } from "../ui/utils";

type ChartEmptyStateTone = "default" | "loading" | "error";

function toneClasses(tone: ChartEmptyStateTone) {
  const key = tone === "loading" ? "sky" : tone === "error" ? "rose" : "slate";
  return {
    border: `tone-${key}-border`,
    glow: `tone-${key}-glow`,
    spotlight: `tone-${key}-spotlight`,
    iconWrap: `tone-${key}-icon`,
    icon: `tone-${key}-value`,
    eyebrow: `tone-${key}-chip`,
  };
}

export function ChartEmptyState({
  title,
  description,
  icon,
  tone = "default",
  className,
}: {
  title: string;
  description: string;
  icon?: LucideIcon;
  tone?: ChartEmptyStateTone;
  className?: string;
}) {
  const Icon = icon ?? (tone === "error" ? AlertTriangle : Activity);
  const classes = toneClasses(tone);

  return (
    <div
      className={cn(
        "cyber-card cyber-glow-border relative flex flex-col items-center justify-center overflow-hidden rounded-3xl border border-dashed border-white/10 px-6 py-10 text-center shadow-lg",
        classes.border,
        className
      )}
      style={{ minHeight: 220 }}
    >
      <div
        className={cn("pointer-events-none absolute inset-0 opacity-90", classes.spotlight)}
        aria-hidden="true"
      />
      <div
        className={cn("pointer-events-none absolute inset-x-0 top-0 h-px opacity-80", classes.glow)}
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute -left-10 top-4 h-24 w-24 rounded-full bg-white/5 blur-3xl"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute -right-12 bottom-2 h-28 w-28 rounded-full bg-purple-500/10 blur-3xl"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute inset-0 bg-white/5 opacity-30"
        aria-hidden="true"
      />
      <div
        className={cn(
          "relative inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-widest",
          classes.eyebrow
        )}
      >
        Ready when data arrives
      </div>
      <div
        className={cn(
          "relative mt-5 flex h-14 w-14 items-center justify-center rounded-3xl border shadow-lg",
          classes.iconWrap
        )}
      >
        <Icon className={cn("h-5 w-5", classes.icon)} />
      </div>
      <div className="relative mt-4 text-base font-semibold text-white">{title}</div>
      <div className="relative mt-2 max-w-[30rem] text-sm leading-relaxed text-gray-300">
        {description}
      </div>
    </div>
  );
}
