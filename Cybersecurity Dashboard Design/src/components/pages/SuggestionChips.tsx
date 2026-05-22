import React from 'react';
import { ArrowUpRight } from 'lucide-react';

import { cn } from '../../ui/utils';
import { ChatSuggestion } from './chatbotTypes';

type SuggestionChipsProps = {
  suggestions: ChatSuggestion[];
  onSelect: (prompt: string) => void;
  className?: string;
  compact?: boolean;
};

export function SuggestionChips({
  suggestions,
  onSelect,
  className,
  compact = false,
}: SuggestionChipsProps) {
  if (suggestions.length === 0) {
    return null;
  }

  return (
    <div className={cn('flex flex-wrap gap-2', className)}>
      {suggestions.map((suggestion) => (
        <button
          key={`${suggestion.label}-${suggestion.prompt}`}
          type="button"
          className={cn(
            'group inline-flex items-center gap-2 rounded-full border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.06),rgba(255,255,255,0.03))] text-slate-100 shadow-[0_12px_28px_rgba(2,6,23,0.16)] backdrop-blur-xl transition hover:-translate-y-0.5 hover:border-cyan-400/20 hover:bg-[linear-gradient(180deg,rgba(34,211,238,0.14),rgba(16,185,129,0.10))] hover:text-cyan-50',
            compact ? 'px-3.5 py-1.5 text-[11px]' : 'px-3.5 py-2 text-xs'
          )}
          onClick={() => onSelect(suggestion.prompt)}
        >
          <span>{suggestion.label}</span>
          <ArrowUpRight className="h-3.5 w-3.5 text-slate-500 transition group-hover:text-cyan-300" />
        </button>
      ))}
    </div>
  );
}
