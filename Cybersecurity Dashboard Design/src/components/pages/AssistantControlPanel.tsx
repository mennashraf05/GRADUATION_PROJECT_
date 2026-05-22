import React from 'react';
import { motion } from 'motion/react';
import {
  ArrowUpRight,
  BrainCircuit,
  CheckCircle2,
  Clock3,
  LockKeyhole,
  Radar,
} from 'lucide-react';

import { Card, CardContent } from '../../ui/card';
import { cn } from '../../ui/utils';
import { ASSISTANT_MODE_OPTIONS } from './chatbotCopilotConfig';
import {
  AssistantModeId,
  AssistantResponseStyle,
  ChatMessage,
  QuickActionItem,
} from './chatbotTypes';

type SessionSnapshot = {
  currentIntent: string;
  latestAttachedContext: string;
  lastReferencedAsset: string;
  memoryState: string;
};

type LatestInsight = {
  id: string;
  label: string;
  value: string;
};

type NextAction = {
  id: string;
  title: string;
  prompt: string;
};

type AssistantControlPanelProps = {
  activeMode: AssistantModeId;
  responseStyle: AssistantResponseStyle;
  messages: ChatMessage[];
  sessionSnapshot: SessionSnapshot;
  insights: LatestInsight[];
  nextActions: NextAction[];
  quickActions: QuickActionItem[];
  disabled?: boolean;
  onModeSelect: (mode: AssistantModeId) => void;
  onQuickAction: (prompt: string, mode?: AssistantModeId) => void;
};

const responseStyleLabelMap: Record<AssistantResponseStyle, string> = {
  balanced: 'Balanced',
  simple: 'Simplified',
  technical: 'Technical',
};

function PanelCard({
  eyebrow,
  title,
  description,
  icon,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <Card className="relative overflow-hidden rounded-[30px] border border-white/10 bg-[linear-gradient(180deg,rgba(7,13,25,0.96),rgba(4,8,17,0.98))] shadow-[0_22px_68px_rgba(2,6,23,0.32)]">
      <div className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(56,189,248,0.07),transparent_18%),radial-gradient(circle_at_top_left,rgba(16,185,129,0.06),transparent_16%)]" />
      <CardContent className="relative p-5">
        <div className="mb-4 flex items-start gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-[18px] border border-white/10 bg-white/[0.05] shadow-[0_12px_28px_rgba(2,6,23,0.18)]">
            {icon}
          </div>
          <div className="min-w-0">
            <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
              {eyebrow}
            </div>
            <div className="mt-1 text-lg font-semibold text-white">{title}</div>
            <div className="mt-1 text-sm leading-6 text-slate-400">{description}</div>
          </div>
        </div>
        {children}
      </CardContent>
    </Card>
  );
}

function SnapshotItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[20px] border border-white/10 bg-white/[0.04] px-4 py-3 backdrop-blur-xl">
      <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">{label}</div>
      <div className="mt-1.5 text-sm font-semibold text-white">{value}</div>
    </div>
  );
}

export function AssistantControlPanel({
  activeMode,
  responseStyle,
  messages,
  sessionSnapshot,
  insights,
  nextActions,
  quickActions,
  disabled = false,
  onModeSelect,
  onQuickAction,
}: AssistantControlPanelProps) {
  const activeModeOption =
    ASSISTANT_MODE_OPTIONS.find((mode) => mode.id === activeMode) ?? ASSISTANT_MODE_OPTIONS[0];

  return (
    <div className="space-y-4 xl:sticky xl:top-6 xl:self-start">
      <PanelCard
        eyebrow="Mission Control"
        title="Conversation command deck"
        description="A lighter right rail that keeps focus, mode state, and next moves visible during the demo."
        icon={<BrainCircuit className="h-5 w-5 text-emerald-200" />}
      >
        <div className="grid gap-3">
          <div className="rounded-[24px] border border-emerald-400/18 bg-[linear-gradient(180deg,rgba(16,185,129,0.12),rgba(5,12,22,0.9))] px-4 py-4 shadow-[0_16px_34px_rgba(16,185,129,0.08)]">
            <div className="text-[11px] uppercase tracking-[0.18em] text-emerald-200/70">Selected lane</div>
            <div className="mt-1.5 text-base font-semibold text-white">{activeModeOption.title}</div>
            <div className="mt-2 text-xs leading-6 text-slate-300">{activeModeOption.helper}</div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-2">
            <SnapshotItem label="Response profile" value={responseStyleLabelMap[responseStyle]} />
            <SnapshotItem label="Conversation size" value={`${messages.length} messages`} />
          </div>
        </div>
      </PanelCard>

      <PanelCard
        eyebrow="Active Modes"
        title="Specialized assistant lanes"
        description="Switch the copilot focus without leaving the current chat session."
        icon={<BrainCircuit className="h-5 w-5 text-cyan-200" />}
      >
        <div className="space-y-3">
          {ASSISTANT_MODE_OPTIONS.map((mode) => {
            const Icon = mode.icon;
            const isActive = mode.id === activeMode;

            return (
              <motion.button
                key={mode.id}
                type="button"
                whileHover={{ y: -3 }}
                whileTap={{ scale: 0.995 }}
                className={cn(
                  'relative w-full overflow-hidden rounded-[22px] border px-4 py-4 text-left transition',
                  isActive
                    ? 'border-cyan-400/20 bg-[linear-gradient(180deg,rgba(8,52,74,0.38),rgba(8,14,26,0.98))] shadow-[0_16px_32px_rgba(8,47,73,0.18)]'
                    : 'border-white/10 bg-white/[0.03] hover:border-cyan-400/16 hover:bg-cyan-500/[0.06]'
                )}
                onClick={() => onModeSelect(mode.id)}
              >
                <div
                  className={cn(
                    'pointer-events-none absolute inset-x-0 top-0 h-20 bg-gradient-to-r opacity-80',
                    mode.accent
                  )}
                />
                <div className="relative flex items-start gap-3">
                  <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.06]">
                    <Icon className="h-4.5 w-4.5 text-cyan-100" />
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm font-semibold text-white">{mode.title}</span>
                      {isActive ? (
                        <span className="rounded-full border border-emerald-400/20 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-100">
                          Active
                        </span>
                      ) : null}
                    </div>
                    <div className="mt-1 text-xs leading-5 text-slate-400">{mode.description}</div>
                    <div className="mt-3 text-[11px] uppercase tracking-[0.18em] text-slate-500">
                      {mode.helper}
                    </div>
                  </div>
                </div>
              </motion.button>
            );
          })}
        </div>
      </PanelCard>

      <PanelCard
        eyebrow="Quick Launches"
        title="High-value shortcuts"
        description="Kick off focused security prompts without typing a full request."
        icon={<Radar className="h-5 w-5 text-amber-200" />}
      >
        <div className="space-y-2.5">
          {quickActions.slice(0, 4).map((action) => (
            <button
              key={action.id}
              type="button"
              disabled={disabled}
              className="group flex w-full items-start justify-between gap-3 rounded-[20px] border border-white/10 bg-white/[0.04] px-4 py-3 text-left transition hover:-translate-y-0.5 hover:border-emerald-400/18 hover:bg-emerald-500/[0.06] disabled:opacity-60"
              onClick={() => onQuickAction(action.prompt, action.mode)}
            >
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-[0.18em] text-slate-500">
                  {action.category}
                </div>
                <div className="text-sm font-semibold text-white">{action.title}</div>
                <div className="mt-1 text-xs leading-5 text-slate-400">{action.description}</div>
              </div>
              <ArrowUpRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-500 transition group-hover:text-emerald-300" />
            </button>
          ))}
        </div>
      </PanelCard>

      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-1">
        <PanelCard
          eyebrow="Session Memory"
          title="Context snapshot"
          description="What the assistant is actively carrying inside the secure local session."
          icon={<LockKeyhole className="h-5 w-5 text-emerald-200" />}
        >
          <div className="grid gap-3">
            <SnapshotItem label="Selected mode" value={activeModeOption.title} />
            <SnapshotItem label="Current intent" value={sessionSnapshot.currentIntent} />
            <SnapshotItem
              label="Latest attached context"
              value={sessionSnapshot.latestAttachedContext}
            />
            <SnapshotItem label="Recent focus area" value={sessionSnapshot.lastReferencedAsset} />
            <SnapshotItem label="Memory state" value={sessionSnapshot.memoryState} />
          </div>
        </PanelCard>

        <PanelCard
          eyebrow="Latest Insights"
          title="Conversation intelligence"
          description="Compact signals derived from the most recent chat context."
          icon={<CheckCircle2 className="h-5 w-5 text-cyan-200" />}
        >
          <div className="space-y-3">
            {insights.map((insight) => (
              <SnapshotItem key={insight.id} label={insight.label} value={insight.value} />
            ))}
            <div className="rounded-[20px] border border-white/10 bg-white/[0.04] px-4 py-3 text-xs leading-6 text-slate-400">
              {messages.length <= 1
                ? 'Insights will strengthen as the conversation gains more security context.'
                : 'The copilot is adapting its guidance to the current mode, thread intent, and recent analyst prompts.'}
            </div>
          </div>
        </PanelCard>
      </div>

      <PanelCard
        eyebrow="Recommended Next Actions"
        title="Proactive follow-up"
        description="Use these prompts to keep the demo moving with clear analyst value."
        icon={<Clock3 className="h-5 w-5 text-violet-200" />}
      >
        <div className="space-y-2.5">
          {nextActions.map((action) => (
            <button
              key={action.id}
              type="button"
              className="group flex w-full items-center justify-between gap-3 rounded-[20px] border border-white/10 bg-white/[0.04] px-4 py-3 text-left transition hover:-translate-y-0.5 hover:border-cyan-400/18 hover:bg-cyan-500/[0.06]"
              onClick={() => onQuickAction(action.prompt)}
            >
              <span className="text-sm font-semibold text-white">{action.title}</span>
              <ArrowUpRight className="h-4 w-4 shrink-0 text-slate-500 transition group-hover:text-cyan-300" />
            </button>
          ))}
        </div>

        <div className="mt-4 rounded-[20px] border border-emerald-400/15 bg-emerald-500/8 px-4 py-3 text-xs leading-6 text-emerald-100/90">
          Secure local history is enabled for this session, so follow-up prompts can build on the
          current chat without leaving the page.
        </div>
      </PanelCard>
    </div>
  );
}
