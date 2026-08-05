"use client";
import { ReactNode } from "react";

/** A dense status line of label/value pairs, the way a console reports state:
 *  everything that matters at a glance, on one row, before any charts. */
export function StatStrip({ children }: { children: ReactNode }) {
  return <div className="statstrip">{children}</div>;
}

export function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: ReactNode;
  tone?: "accent" | "highlight" | "danger" | "warn" | "suspect";
}) {
  const color =
    tone === "highlight" ? "text-highlight"
    : tone === "danger" ? "text-danger"
    : tone === "warn" ? "text-warn"
    : tone === "suspect" ? "text-suspect"
    : tone === "accent" ? "text-accent"
    : "text-text";
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-muted">{label}:</span>
      <span className={color}>{value}</span>
    </span>
  );
}

export function Sep() {
  return <span className="sep">|</span>;
}

/**
 * A rule and a label. Not a box.
 *
 * Boxing every group turns a page into a stack of identical containers with no
 * hierarchy, which is the shape a generated layout takes. A rule separates, a
 * label names, and the content is left to be the content.
 */
export function Section({
  title,
  note,
  actions,
  children,
}: {
  title: string;
  note?: string;
  /** Controls that belong to this section, placed on the rule itself. */
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section>
      <div className="flex items-baseline gap-3 border-b border-border pb-1.5 mb-4">
        <h2 className="text-[11px] tracking-widest text-muted shrink-0">
          <span className="text-accent">&gt;</span> {title.toUpperCase()}
        </h2>
        {note && <p className="text-[11px] text-muted/70 truncate hidden md:block">{note}</p>}
        {actions && <div className="ml-auto flex items-center gap-2 shrink-0">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

/**
 * Label above a number, inline.
 *
 * The figure is the content. A bordered card around each one adds height and
 * nothing else, and four of them in a row is the most template-like pattern in
 * dashboard design.
 */
export function Figure({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "danger" | "warn" | "accent" | "highlight";
}) {
  const color =
    tone === "danger" ? "text-danger"
    : tone === "warn" ? "text-warn"
    : tone === "highlight" ? "text-highlight"
    : tone === "accent" ? "text-accent"
    : "text-text";
  const zero = typeof value === "number" && value === 0;
  return (
    <div>
      <div className="text-[10px] tracking-widest text-muted">{label.toUpperCase()}</div>
      <div className={`text-xl tabular-nums ${zero ? "text-muted/50" : color}`}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
    </div>
  );
}

/** `> SECTION` heading. */
export function SectionHeading({ children, note }: { children: ReactNode; note?: string }) {
  return (
    <div className="mb-3">
      <h2 className="term-h text-muted">{children}</h2>
      {note && <p className="text-xs text-muted mt-1">{note}</p>}
    </div>
  );
}
