import * as React from "react";

import { cn } from "./utils";

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "cyber-panel-soft border-input flex h-10 w-full min-w-0 rounded-2xl border px-3 py-2 text-sm text-white shadow-sm outline-none placeholder:text-gray-400 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50",
        "selection:bg-primary selection:text-primary-foreground",
        "focus-visible:ring-[3px] focus-visible:ring-ring/40 aria-invalid:border-destructive aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40",
        "file:mr-4 file:inline-flex file:h-8 file:cursor-pointer file:rounded-xl file:border-0 file:bg-primary file:px-3 file:text-sm file:font-semibold file:text-white",
        className,
      )}
      {...props}
    />
  );
}

export { Input };
