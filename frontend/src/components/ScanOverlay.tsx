"use client";
import { motionReduced } from "@/lib/motion";
import { useEffect, useState } from "react";

/**
 * Activity overlay for a running analysis.
 *
 * Laid over the evidence input while the pipeline reads it, because that is
 * literally what is happening: a sweep travelling down the text the tool is
 * working through. The alternative -- an unrelated spinner somewhere else on the
 * page -- says only "wait", where this says what is being waited on.
 *
 * The sweep is decorative, but the STAGE it reports is not: the label and colour
 * track the real phase of the job, so the overlay is also the fastest read of
 * where the run has got to.
 */

type Phase = "extract" | "verify" | "review" | "done";

/** The pipeline's progress fractions, from gemini_client's _progress calls. */
export function phaseOf(progress: number, done: boolean): Phase {
  if (done) return "done";
  if (progress < 0.4) return "extract";
  if (progress < 0.5) return "verify";
  return "review";
}

const PHASE_LABEL: Record<Phase, string> = {
  extract: "READING EVIDENCE",
  verify: "CHECKING CLAIMS",
  review: "CHALLENGING FINDINGS",
  done: "COMPLETE",
};

/* RGB triplets, not CSS vars: these are interpolated into rgba() strings, and a
   var() reference cannot be used as the first three arguments. Each phase takes a
   colour that already means something in this interface -- lime for live activity,
   phosphor for a passing check, lavender for the reviewer, which is the same hue
   the held-for-review verdict uses. */
const PHASE_TONE: Record<Phase, string> = {
  extract: "198, 255, 52",
  verify: "126, 231, 135",
  review: "210, 195, 246",
  done: "126, 231, 135",
};

export default function ScanOverlay({
  active,
  progress = 0,
  done = false,
}: {
  active: boolean;
  progress?: number;
  done?: boolean;
}) {
  const [reduced, setReduced] = useState(false);
  useEffect(() => setReduced(motionReduced()), [active]);

  if (!active) return null;
  const phase = phaseOf(progress, done);
  const tone = PHASE_TONE[phase];

  return (
    <span
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 overflow-hidden rounded-lg"
      style={{ boxShadow: `inset 0 0 0 1px rgba(${tone}, 0.35)` }}
    >
      {/* A faint grid, so the sweep has something to travel over. */}
      <span
        className="absolute inset-0 opacity-[0.07]"
        style={{
          backgroundImage: `linear-gradient(rgba(${tone},1) 1px, transparent 1px), linear-gradient(90deg, rgba(${tone},1) 1px, transparent 1px)`,
          backgroundSize: "22px 22px",
        }}
      />

      {/* The sweep itself. Suppressed under reduced motion, where the border and
          the label alone still carry the state. */}
      {!reduced && (
        <span
          className="scan-sweep absolute left-0 right-0 h-24"
          style={{
            background: `linear-gradient(to bottom, transparent, rgba(${tone},0.16), transparent)`,
          }}
        />
      )}

      <span
        className="absolute right-2 top-2 text-[10px] tracking-widest px-1.5 py-0.5 rounded"
        style={{ color: `rgb(${tone})`, background: "rgba(0,0,0,0.45)" }}
      >
        {PHASE_LABEL[phase]}
      </span>
    </span>
  );
}
