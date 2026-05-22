import React from 'react';
import { motion } from 'motion/react';
import {
  Bot,
  Copy,
  CircleCheckBig,
  FileSearch,
  Lightbulb,
  RotateCcw,
  ShieldAlert,
  Sparkles,
  TerminalSquare,
  TriangleAlert,
  User,
} from 'lucide-react';

import { Badge } from '../../ui/badge';
import { Button } from '../../ui/button';
import { cn } from '../../ui/utils';
import { AssistantResponseStyle, ChatMessage, ChatMessageStatus } from './chatbotTypes';
import { SuggestionChips } from './SuggestionChips';

type MessageBubbleProps = {
  message: ChatMessage;
  onSuggestionClick: (prompt: string) => void;
  onMessageAction: (
    action: 'regenerate' | 'simple' | 'technical',
    message: ChatMessage
  ) => void;
};

const statusTone: Record<
  ChatMessageStatus,
  {
    bubble: string;
    badge: string;
    label: string;
    accentGlow: string;
  }
> = {
  normal: {
    bubble:
      'border-emerald-400/14 bg-[linear-gradient(180deg,rgba(5,20,31,0.96),rgba(6,15,27,0.98))] text-slate-100',
    badge: 'border-emerald-400/20 bg-emerald-500/10 text-emerald-100',
    label: 'Guidance',
    accentGlow: 'bg-emerald-400/40',
  },
  warning: {
    bubble:
      'border-amber-400/18 bg-[linear-gradient(180deg,rgba(43,25,6,0.82),rgba(8,15,28,0.98))] text-slate-100',
    badge: 'border-amber-400/20 bg-amber-500/10 text-amber-100',
    label: 'Warning',
    accentGlow: 'bg-amber-400/40',
  },
  critical: {
    bubble:
      'border-rose-400/18 bg-[linear-gradient(180deg,rgba(54,16,24,0.82),rgba(8,15,28,0.98))] text-slate-100',
    badge: 'border-rose-400/20 bg-rose-500/10 text-rose-100',
    label: 'Critical',
    accentGlow: 'bg-rose-400/40',
  },
  success: {
    bubble:
      'border-sky-400/18 bg-[linear-gradient(180deg,rgba(4,30,49,0.82),rgba(8,15,28,0.98))] text-slate-100',
    badge: 'border-sky-400/20 bg-sky-500/10 text-sky-100',
    label: 'Recommended',
    accentGlow: 'bg-sky-400/40',
  },
};

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });
}

async function copyMessage(content: string) {
  if (!navigator.clipboard?.writeText) {
    return;
  }

  try {
    await navigator.clipboard.writeText(content);
  } catch {
    return;
  }
}

const responseStyleLabelMap: Record<AssistantResponseStyle, string> = {
  balanced: 'Balanced',
  simple: 'Simplified',
  technical: 'Technical',
};

const sectionStyleMap = {
  summary: {
    icon: Sparkles,
    accent: 'from-cyan-400/20 via-cyan-400/5 to-transparent',
    iconClass: 'text-cyan-200',
  },
  evidence: {
    icon: FileSearch,
    accent: 'from-emerald-400/20 via-emerald-400/5 to-transparent',
    iconClass: 'text-emerald-200',
  },
  actions: {
    icon: Lightbulb,
    accent: 'from-amber-400/20 via-amber-400/5 to-transparent',
    iconClass: 'text-amber-200',
  },
  technical: {
    icon: TerminalSquare,
    accent: 'from-violet-400/20 via-violet-400/5 to-transparent',
    iconClass: 'text-violet-200',
  },
  explanation: {
    icon: CircleCheckBig,
    accent: 'from-sky-400/20 via-sky-400/5 to-transparent',
    iconClass: 'text-sky-200',
  },
} as const;

export function MessageBubble({
  message,
  onSuggestionClick,
  onMessageAction,
}: MessageBubbleProps) {
  const isUser = message.role === 'user';
  const isSystem = message.role === 'system';
  const tone = statusTone[message.status ?? 'normal'];
  const headerLabel = isUser ? 'YOU' : isSystem ? 'SYSTEM' : 'SENTINEL';
  const badgeLabel = message.tag || (!isUser ? tone.label : undefined);
  const assistantSections = !isUser && !isSystem ? message.sections ?? [] : [];
  const hasStructuredSections = assistantSections.length > 0;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 18, scale: 0.985 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.26 }}
      className={cn('flex w-full', isUser ? 'justify-end' : 'justify-start')}
    >
      <div className={cn('flex w-full gap-3', isUser ? 'flex-row-reverse justify-end' : 'justify-start')}>
        <div
          className={cn(
            'relative z-10 mt-1 flex h-11 w-11 shrink-0 items-center justify-center rounded-[18px] border shadow-[0_14px_32px_rgba(2,6,23,0.24)]',
            isUser
              ? 'border-cyan-400/20 bg-[linear-gradient(180deg,rgba(14,165,233,0.28),rgba(37,99,235,0.18))] text-cyan-50'
              : isSystem
                ? 'border-rose-400/20 bg-rose-500/12 text-rose-100'
                : 'border-emerald-400/20 bg-[linear-gradient(180deg,rgba(16,185,129,0.18),rgba(34,211,238,0.10))] text-emerald-100'
          )}
        >
          {isUser ? (
            <User className="h-4.5 w-4.5" />
          ) : isSystem ? (
            <ShieldAlert className="h-4.5 w-4.5" />
          ) : (
            <Bot className="h-4.5 w-4.5" />
          )}
        </div>

        <div
          className={cn(
            'group relative overflow-hidden border px-4 py-4 shadow-[0_20px_52px_rgba(2,6,23,0.24)] backdrop-blur-xl transition',
            isUser
              ? 'max-w-[min(720px,78%)] rounded-[28px] rounded-tr-md border-cyan-400/22 bg-[linear-gradient(180deg,rgba(6,182,212,0.92),rgba(37,99,235,0.92))] text-white'
              : 'max-w-[min(920px,86%)] rounded-[28px] rounded-tl-md',
            !isUser && tone.bubble
          )}
        >
          {!isUser ? (
            <>
              <div className={cn('pointer-events-none absolute left-0 top-5 bottom-5 w-[3px] rounded-full', tone.accentGlow)} />
              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(255,255,255,0.05),transparent_20%)]" />
            </>
          ) : null}

          <div className="relative flex items-center justify-between gap-3">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <span
                className={cn(
                  'text-[11px] font-semibold uppercase tracking-[0.18em]',
                  isUser ? 'text-cyan-50/85' : 'text-slate-400'
                )}
              >
                {headerLabel}
              </span>

              {badgeLabel ? (
                <Badge
                  className={cn(
                    'border px-2 py-0.5 text-[11px] shadow-[0_8px_18px_rgba(2,6,23,0.14)]',
                    isUser ? 'border-white/15 bg-white/12 text-white' : tone.badge
                  )}
                >
                  {!isUser && message.status === 'warning' ? (
                    <TriangleAlert className="h-3.5 w-3.5" />
                  ) : null}
                  {badgeLabel}
                </Badge>
              ) : null}

              {!isUser && !isSystem && message.mode ? (
                <Badge className="border border-white/10 bg-white/[0.08] px-2 py-0.5 text-[11px] text-slate-200">
                  {message.mode.replace(/-/g, ' ')}
                </Badge>
              ) : null}
            </div>

            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-label="Copy message"
              className={cn(
                'h-8 w-8 rounded-xl opacity-0 transition group-hover:opacity-100 focus-visible:opacity-100',
                isUser ? 'text-white hover:bg-white/12' : 'text-slate-400 hover:bg-white/8'
              )}
              onClick={() => void copyMessage(message.content)}
            >
              <Copy className="h-3.5 w-3.5" />
            </Button>
          </div>

          {!isUser && !isSystem ? (
            <div className="relative mt-3 space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className="border border-emerald-400/15 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] text-emerald-100">
                  AI response
                </Badge>
                {message.responseStyle ? (
                  <Badge className="border border-white/10 bg-white/[0.08] px-2.5 py-0.5 text-[11px] text-slate-200">
                    {responseStyleLabelMap[message.responseStyle]}
                  </Badge>
                ) : null}
                {message.metaLabel ? (
                  <Badge className="border border-cyan-400/15 bg-cyan-500/10 px-2.5 py-0.5 text-[11px] text-cyan-50">
                    {message.metaLabel}
                  </Badge>
                ) : null}
              </div>

              <div className="whitespace-pre-wrap break-words text-[15px] leading-7 text-slate-100">
                {message.content}
              </div>

              {hasStructuredSections ? (
                <div className="grid gap-3 lg:grid-cols-2">
                  {assistantSections.map((section, index) => {
                    const sectionStyle =
                      sectionStyleMap[section.kind ?? 'explanation'] || sectionStyleMap.explanation;
                    const SectionIcon = sectionStyle.icon;

                    return (
                      <motion.div
                        key={`${message.id}-${section.id}`}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.04 * index, duration: 0.24 }}
                        className="group/section relative overflow-hidden rounded-[22px] border border-white/8 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] px-4 py-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] transition hover:border-white/12 hover:bg-[linear-gradient(180deg,rgba(255,255,255,0.07),rgba(255,255,255,0.03))]"
                      >
                        <div
                          className={cn(
                            'pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-r opacity-90',
                            sectionStyle.accent
                          )}
                        />
                        <div className="relative flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                          <div className="flex h-8 w-8 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.06]">
                            <SectionIcon className={cn('h-3.5 w-3.5', sectionStyle.iconClass)} />
                          </div>
                          {section.title}
                        </div>
                        <div className="relative mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-slate-200">
                          {section.content}
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              ) : null}

              {message.evidence && message.evidence.length > 0 ? (
                <div className="space-y-2">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                    Evidence / Context
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {message.evidence.map((item) => (
                      <span
                        key={`${message.id}-${item}`}
                        className="rounded-full border border-cyan-400/14 bg-[linear-gradient(180deg,rgba(34,211,238,0.12),rgba(16,185,129,0.08))] px-3 py-1.5 text-[11px] text-cyan-50 shadow-[0_12px_24px_rgba(34,211,238,0.08)] transition hover:border-cyan-300/24 hover:bg-cyan-500/[0.16]"
                      >
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          ) : (
            <div
              className={cn(
                'mt-3 whitespace-pre-wrap break-words text-[15px] leading-7',
                isUser ? 'text-white' : 'text-slate-100'
              )}
            >
              {message.content}
            </div>
          )}

          {message.suggestions && message.suggestions.length > 0 ? (
            <SuggestionChips
              suggestions={message.suggestions}
              onSelect={onSuggestionClick}
              className="relative mt-4"
              compact={isUser}
            />
          ) : null}

          {!isUser && !isSystem ? (
            <div className="relative mt-4 flex flex-wrap gap-2">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-8 rounded-full border border-white/10 bg-white/[0.05] px-3 text-xs text-slate-200 hover:bg-white/[0.09]"
                onClick={() => onMessageAction('regenerate', message)}
              >
                <RotateCcw className="mr-1.5 h-3.5 w-3.5" />
                Regenerate
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-8 rounded-full border border-white/10 bg-white/[0.05] px-3 text-xs text-slate-200 hover:bg-white/[0.09]"
                onClick={() => onMessageAction('simple', message)}
              >
                Explain simpler
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-8 rounded-full border border-white/10 bg-white/[0.05] px-3 text-xs text-slate-200 hover:bg-white/[0.09]"
                onClick={() => onMessageAction('technical', message)}
              >
                Explain technically
              </Button>
            </div>
          ) : null}

          <div className={cn('relative mt-4 text-[11px]', isUser ? 'text-cyan-50/78' : 'text-slate-500')}>
            {formatTimestamp(message.timestamp)}
          </div>
        </div>
      </div>
    </motion.div>
  );
}
