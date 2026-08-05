"use client";
import { useEffect, useRef, useState } from "react";
import { Job } from "@/lib/types";
import JobLog from "./JobLog";
import ScanOverlay, { phaseOf } from "./ScanOverlay";

/**
 * The running job, brought to the middle of the screen.
 *
 * Progress and the pipeline log previously sat below the form, so the moment the
 * run actually began the interesting part was off-screen and the user had to go
 * looking for it. Starting a job is a deliberate act; what happens next should
 * arrive rather than be hunted for.
 *
 * It is explicitly NOT a blocking modal. The job runs server-side and survives
 * navigation, so trapping the page would buy nothing and cost the ability to check
 * settings mid-run. Escape or the backdrop minimises it to a corner chip that
 * keeps reporting, and the chip reopens it.
 */

const PHASE_LABEL: Record<string, string> = {
  extract: "Reading evidence",
  verify: "Checking claims against the evidence",
  review: "Challenging findings",
  done: "Complete",
};

const PHASE_TONE: Record<string, string> = {
  extract: "text-highlight",
  verify: "text-accent",
  review: "text-suspect",
  done: "text-accent",
};

export default function JobConsole({
  job,
  title = "Analysis",
  evidence,
  resultCount,
  onDismiss,
}: {
  job: Job | null;
  title?: string;
  /** The material being worked through. Shown under the sweep so the panel says
   *  what is being read, not merely that something is. */
  evidence?: string;
  /** Shown once the job finishes, so the panel closes on a fact rather than a shrug. */
  resultCount?: number;
  onDismiss?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [minimised, setMinimised] = useState(false);
  const lastJobId = useRef<string | null>(null);

  // Opens when a NEW job starts. Tracked by id so returning to the page with a
  // finished job in state does not pop the panel open again.
  useEffect(() => {
    if (!job) return;
    if (job.id !== lastJobId.current) {
      lastJobId.current = job.id;
      setOpen(true);
      setMinimised(false);
    }
  }, [job]);

  useEffect(() => {
    if (!open || minimised) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMinimised(true);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, minimised]);

  if (!job || !open) return null;

  const done = job.done;
  const failed = !!job.error;
  const phase = phaseOf(job.progress ?? 0, done);
  const pct = Math.round((job.progress ?? 0) * 100);

  const close = () => {
    setOpen(false);
    onDismiss?.();
  };

  // Minimised: a chip that keeps reporting, so the run is never invisible.
  if (minimised) {
    return (
      <button
        onClick={() => setMinimised(false)}
        className="glass fixed bottom-4 right-4 z-[70] flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs hover:border-accent/60 transition-colors"
      >
        {!done && (
          <span className="pulse-ring inline-block w-1.5 h-1.5 rounded-full bg-highlight shrink-0" />
        )}
        <span className={done ? (failed ? "text-danger" : "text-accent") : PHASE_TONE[phase]}>
          {done ? (failed ? "Failed" : "Complete") : `${PHASE_LABEL[phase]}…`}
        </span>
        {!done && <span className="text-muted tabular-nums">{pct}%</span>}
        <span className="text-border">|</span>
        <span className="text-muted tracking-widest text-[10px]">OPEN</span>
      </button>
    );
  }

  return (
    <div
      className="glass-scrim fixed inset-0 z-[70] flex items-center justify-center p-4"
      
      onMouseDown={(e) => e.target === e.currentTarget && setMinimised(true)}
    >
      <div
        role="dialog"
        aria-modal="false"
        aria-label={`${title} progress`}
        className="glass w-full max-w-2xl rounded-xl overflow-hidden animate-in"
      >
        <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border/60">
          <span className="text-[10px] tracking-widest text-muted">{title.toUpperCase()}</span>
          <span className={`text-sm ${done ? (failed ? "text-danger" : "text-accent") : PHASE_TONE[phase]}`}>
            {failed ? "Failed" : PHASE_LABEL[phase]}
          </span>
          <div className="flex-1" />
          {!done && <span className="text-xs text-muted tabular-nums">{pct}%</span>}
          <button
            onClick={() => setMinimised(true)}
            className="text-[10px] tracking-widest text-muted hover:text-text transition-colors"
            title="Minimise (Esc)"
          >
            [MINIMISE]
          </button>
        </div>

        {/* Progress is a bar rather than a spinner: a run has a known shape, and
            showing where it is beats implying it is indeterminate. */}
        <div className="h-0.5 bg-white/5">
          <div
            className={`h-full transition-all duration-500 ${
              failed ? "bg-danger" : done ? "bg-accent" : "bg-highlight"
            }`}
            style={{ width: `${done ? 100 : Math.max(2, pct)}%` }}
          />
        </div>

        <div className="p-4 grid gap-4">
          {/* The evidence under the sweep. Previously this lived on the textarea,
              where the console's own backdrop covered it the moment the panel
              opened -- the most descriptive visual on the page was hidden exactly
              when it was being looked at. */}
          {!done && evidence && evidence.trim().length > 0 && (
            <div className="relative rounded-lg border border-border/60 overflow-hidden">
              <pre className="max-h-40 overflow-hidden px-3 py-2 text-[10px] leading-relaxed font-mono text-muted/70 whitespace-pre-wrap break-words select-none">
                {evidence.slice(0, 1400)}
              </pre>
              <ScanOverlay active progress={job.progress ?? 0} done={false} />
              {/* Fades the excerpt out at the bottom rather than cutting it mid-line,
                  which would read as a rendering fault. */}
              <span
                aria-hidden="true"
                className="pointer-events-none absolute inset-x-0 bottom-0 h-10"
                style={{ background: "linear-gradient(to top, #1a251e, transparent)" }}
              />
            </div>
          )}

          <JobLog job={job} />

          {failed && (
            <p className="text-sm text-danger border-l-2 border-danger/70 pl-3 py-1">
              {job.error}
            </p>
          )}

          {done && !failed && (
            <div className="flex items-center gap-3 flex-wrap">
              <p className="text-sm">
                {typeof resultCount === "number" ? (
                  <>
                    <span className="text-accent">{resultCount}</span> finding
                    {resultCount === 1 ? "" : "s"} ready to review below.
                  </>
                ) : (
                  "Finished."
                )}
              </p>
              <div className="flex-1" />
              <button className="btn" onClick={close}>
                View results
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
