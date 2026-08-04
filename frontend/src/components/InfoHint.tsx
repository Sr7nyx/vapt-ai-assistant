"use client";
import { ReactNode, useEffect, useId, useRef, useState } from "react";

/**
 * A low-emphasis explanation, revealed on demand.
 *
 * Settings pages accumulate prose: every field acquires a sentence explaining
 * itself, and the result is a wall of grey text where nothing is emphasised
 * because everything is. Moving that text behind a ghost marker keeps it
 * available without making the reader wade through it to find the input.
 *
 * Implemented as a button rather than a title attribute or a hover-only tooltip:
 * hover does not exist on touch devices, and native tooltips cannot be styled,
 * cannot contain structure, and are invisible to keyboard users.
 */
export default function InfoHint({
  children,
  label = "More information",
  align = "left",
}: {
  children: ReactNode;
  label?: string;
  align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLSpanElement>(null);
  const id = useId();

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <span ref={wrap} className="relative inline-flex align-middle">
      <button
        type="button"
        aria-label={label}
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        onClick={() => setOpen((v) => !v)}
        onMouseEnter={() => setOpen(true)}
        className={`inline-flex h-4 w-4 items-center justify-center rounded-full border text-[9px] leading-none transition-colors ${
          open
            ? "border-accent text-accent"
            : "border-border text-muted/70 hover:border-accent/60 hover:text-accent"
        }`}
      >
        i
      </button>

      {open && (
        <span
          id={id}
          role="tooltip"
          onMouseLeave={() => setOpen(false)}
          className={`absolute top-6 z-30 w-72 rounded-lg border border-border bg-surface p-3 text-xs leading-relaxed text-muted shadow-2xl ${
            align === "right" ? "right-0" : "left-0"
          }`}
        >
          {children}
        </span>
      )}
    </span>
  );
}

/** Field label with an optional hint marker beside it. */
export function LabelWithHint({
  label,
  hint,
  children,
  ...rest
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
} & React.LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label className="grid gap-1.5" {...rest}>
      <span className="flex items-center gap-1.5 text-sm text-muted">
        {label}
        {hint && <InfoHint label={`About ${label}`}>{hint}</InfoHint>}
      </span>
      {children}
    </label>
  );
}
