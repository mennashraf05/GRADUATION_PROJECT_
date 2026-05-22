import * as React from "react";
import { Slot } from "@radix-ui/react-slot@1.1.2";
import { cva, type VariantProps } from "class-variance-authority@0.7.1";

import { cn } from "./utils";

const badgeVariants = cva(
  "inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden whitespace-nowrap rounded-full border px-3 py-1 text-xs font-semibold shadow-sm backdrop-blur-sm transition-colors duration-200 [&>svg]:pointer-events-none [&>svg]:size-3 focus-visible:ring-[3px] focus-visible:ring-ring/40 aria-invalid:border-destructive aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40",
  {
    variants: {
      variant: {
        default:
          "border-primary bg-primary/20 text-primary-foreground [a&]:hover:bg-primary/30",
        secondary:
          "border-white/10 bg-secondary text-secondary-foreground [a&]:hover:bg-secondary/90",
        destructive:
          "border-red-500/30 bg-red-500/10 text-white [a&]:hover:bg-red-500/20 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40",
        outline:
          "border-white/10 bg-white/5 text-foreground [a&]:hover:bg-white/10",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

function Badge({
  className,
  variant,
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "span";

  return (
    <Comp
      data-slot="badge"
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  );
}

export { Badge, badgeVariants };
