"use client";
import { ReactNode } from "react";

type Row = { label: string; count: number };

const SEVERITY_COLOR: Record<string, string> = {
  Critical: "#e06c75",
  High: "#e5a04c",
  Medium: "#5fb3ac",
  Low: "#5c6b7a",
  Informational: "#3d4854",
};
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

/** One proportional bar showing the shape of an engagement at a glance.
 *  A table gives the same numbers, but not the sense of whether a project is
 *  mostly critical work or mostly noise. */
export function SeverityBar({ rows }: { rows: Row[] }) {
  const present = SEVERITY_ORDER.map((label) => ({
    label,
    count: rows.find((r) => r.label === label)?.count ?? 0,
  })).filter((r) => r.count > 0);
  const total = present.reduce((sum, r) => sum + r.count, 0);
  if (total === 0) return null;

  return (
    <div className="grid gap-2">
      <div className="flex h-3 w-full overflow-hidden rounded-full bg-white/5">
        {present.map((r, i) => (
          <div
            key={r.label}
            style={{
              width: `${(r.count / total) * 100}%`,
              background: SEVERITY_COLOR[r.label],
              animationDelay: `${i * 60}ms`,
              animationFillMode: "backwards",
            }}
            title={`${r.label}: ${r.count}`}
            className="grow-x transition-all"
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {present.map((r) => (
          <span key={r.label} className="flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-sm" style={{ background: SEVERITY_COLOR[r.label] }} />
            <span className="text-muted">{r.label}</span>
            <span>{r.count}</span>
            <span className="text-muted">({Math.round((r.count / total) * 100)}%)</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/** Horizontal bars for comparing counts across many labelled categories, where
 *  the useful question is which are largest rather than what each value is. */
export function BarList({
  rows,
  emphasise,
  max: fixedMax,
}: {
  rows: Row[];
  emphasise?: (label: string) => boolean;
  max?: number;
}) {
  if (rows.length === 0) return <p className="text-muted text-sm">Nothing to show yet.</p>;
  const max = fixedMax ?? Math.max(...rows.map((r) => r.count), 1);

  return (
    <div className="grid gap-2">
      {rows.map((r) => {
        const muted = emphasise ? !emphasise(r.label) : false;
        return (
          <div key={r.label} className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 items-center">
            <div className="min-w-0">
              <div className={`text-xs truncate mb-1 ${muted ? "text-muted" : ""}`}>{r.label}</div>
              <div className="h-1.5 w-full rounded-full bg-white/5 overflow-hidden">
                <div
                  className={`grow-x h-full rounded-full transition-all ${muted ? "bg-muted/40" : "bg-accent"}`}
                  style={{ width: `${Math.max(2, (r.count / max) * 100)}%` }}
                />
              </div>
            </div>
            <span className="text-sm tabular-nums w-8 text-right">{r.count}</span>
          </div>
        );
      })}
    </div>
  );
}

export function Panel({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <div className="card">
      <div className="text-sm font-medium">{title}</div>
      {subtitle && <div className="text-xs text-muted mt-0.5 mb-3">{subtitle}</div>}
      <div className={subtitle ? "" : "mt-3"}>{children}</div>
    </div>
  );
}
