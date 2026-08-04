"use client";
import { useEffect, useRef } from "react";
import { Job } from "@/lib/types";

/**
 * Live pipeline log.
 *
 * A progress bar says how long is left. This says what the tool is doing, which
 * on this project is the more interesting fact: the run is a sequence of checks,
 * and watching a claim get refuted against its own evidence is the clearest
 * demonstration of why the pipeline exists.
 *
 * The log is accumulated server-side and delivered whole on each poll, so no line
 * is lost between requests. Rendering is trivial: no virtualisation, because the
 * server caps the log at 400 lines.
 */

/** Classify a line so the eye can find the outcomes without reading everything. */
function tone(line: string): string {
  if (line.startsWith("[REFUTED]")) return "text-danger";
  if (line.startsWith("[CONFIRMED]")) return "text-accent";
  if (/->\s*Likely False Positive/i.test(line)) return "text-danger";
  if (/->\s*(Confirmed|Likely Valid)/i.test(line)) return "text-accent";
  if (/->\s*Needs More Evidence/i.test(line)) return "text-warn";
  if (line.startsWith("  ->")) return "text-muted";
  return "text-text";
}

export default function JobLog({ job }: { job: Job | null }) {
  const box = useRef<HTMLDivElement>(null);
  const lines = job?.log || [];
  const pinned = useRef(true);

  // Follow the tail, but stop following the moment the user scrolls up to read
  // something. Yanking the viewport away from what someone is reading is the
  // classic failure of an auto-scrolling log.
  const onScroll = () => {
    const el = box.current;
    if (!el) return;
    pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  };

  useEffect(() => {
    if (pinned.current && box.current) {
      box.current.scrollTop = box.current.scrollHeight;
    }
  }, [lines.length]);

  if (!job || lines.length === 0) return null;

  const running = !job.done;

  return (
    <div className="rounded-lg border border-border/60 overflow-hidden mb-4">
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border/60 bg-surface/60">
        <span className="text-[10px] tracking-widest text-muted">PIPELINE</span>
        <span className="text-[10px] tracking-widest text-muted">
          {lines.length} line{lines.length === 1 ? "" : "s"}
        </span>
        <div className="flex-1" />
        {running ? (
          <span className="flex items-center gap-1.5 text-[10px] tracking-widest text-highlight">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-highlight animate-pulse" />
            RUNNING
          </span>
        ) : (
          <span className="text-[10px] tracking-widest text-muted">
            {job.error ? "FAILED" : "DONE"}
          </span>
        )}
      </div>

      <div
        ref={box}
        onScroll={onScroll}
        role="log"
        aria-live="polite"
        className="max-h-56 overflow-y-auto px-3 py-2 text-xs leading-relaxed"
      >
        {lines.map((line, i) => (
          <div key={i} className="flex gap-2">
            <span className="text-border select-none shrink-0 tabular-nums">
              {String(i + 1).padStart(2, "0")}
            </span>
            <span className={`whitespace-pre-wrap break-words ${tone(line)}`}>{line}</span>
          </div>
        ))}
        {running && (
          <div className="flex gap-2">
            <span className="text-border select-none shrink-0 tabular-nums">
              {String(lines.length + 1).padStart(2, "0")}
            </span>
            <span className="caret text-muted" />
          </div>
        )}
      </div>
    </div>
  );
}
