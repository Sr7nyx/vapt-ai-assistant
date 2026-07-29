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
  tone?: "accent" | "danger" | "warn" | "suspect";
}) {
  const color =
    tone === "danger" ? "text-danger"
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

/** `> SECTION` heading. */
export function SectionHeading({ children, note }: { children: ReactNode; note?: string }) {
  return (
    <div className="mb-3">
      <h2 className="term-h text-muted">{children}</h2>
      {note && <p className="text-xs text-muted mt-1">{note}</p>}
    </div>
  );
}
