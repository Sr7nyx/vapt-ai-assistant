"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { LearningSummary } from "@/lib/types";

/**
 * What the system has learned from being corrected.
 *
 * Deliberately not called "AI learning". No model is trained here: this reads
 * decisions the operator already made and reports two things -- whether the
 * verdict engine's confidence means what it claims, and which finding classes have
 * been dismissed often enough that re-reviewing them is waste.
 *
 * Saying that plainly is more defensible than implying the model improves, and it
 * happens to be the more interesting claim.
 */
export default function LearningPanel() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [data, setData] = useState<LearningSummary | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!token) return;
    let alive = true;
    api
      .learningSummary(token)
      .then((r) => alive && setData(r))
      .catch(() => alive && setFailed(true));
    return () => {
      alive = false;
    };
  }, [token]);

  if (failed) return <p className="text-sm text-muted">Could not load.</p>;
  if (!data) return <p className="text-sm text-muted">Loading…</p>;

  const cal = data.calibration;
  const reliable = cal.buckets.filter((b) => b.reliable);

  return (
    <div className="grid gap-6">
      <div>
        <div className="text-[10px] tracking-widest text-muted mb-2">CONFIDENCE CALIBRATION</div>
        <p className="measure text-sm mb-3">{cal.verdict}</p>

        {reliable.length > 0 && (
          <table className="w-full max-w-lg text-sm">
            <thead>
              <tr className="text-left text-muted border-b border-border">
                <th className="font-normal text-[10px] tracking-widest pb-1.5">CLAIMED</th>
                <th className="font-normal text-[10px] tracking-widest pb-1.5">UPHELD</th>
                <th className="font-normal text-[10px] tracking-widest pb-1.5 text-right">CASES</th>
              </tr>
            </thead>
            <tbody>
              {reliable.map((b) => (
                <tr key={b.claimed} className="border-b border-border/40 last:border-0">
                  <td className="py-1.5 tabular-nums">{b.claimed.toFixed(1)}</td>
                  <td className="py-1.5 tabular-nums">
                    <span className={Math.abs(b.gap) > 0.15 ? "text-warn" : "text-accent"}>
                      {(b.observed * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="py-1.5 text-right tabular-nums text-muted">{b.n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <p className="measure text-xs text-muted mt-3">
          Measured against {cal.corrections} correction{cal.corrections === 1 ? "" : "s"} you have
          made across {data.findings_considered} findings. A bucket with fewer than eight cases is
          left out rather than shown as a rate &mdash; a confidence figure derived from three
          findings is worse than none.
        </p>
      </div>

      <div>
        <div className="text-[10px] tracking-widest text-muted mb-2">LEARNED PRIORS</div>
        {data.priors.length === 0 ? (
          <p className="measure text-sm text-muted">
            No class has been dismissed often enough yet. After a class is marked a false positive
            three times, imports flag it and skip the review call rather than paying to be told
            again.
          </p>
        ) : (
          <>
            <ul className="grid gap-1.5 max-w-2xl">
              {data.priors.map((p) => (
                <li key={p.title} className="flex items-baseline gap-3 text-sm">
                  <span className="flex-1 min-w-0 truncate">{p.title}</span>
                  <span className="text-xs text-danger shrink-0 tabular-nums">
                    {p.dismissed} dismissed
                  </span>
                  {p.upheld > 0 && (
                    <span className="text-xs text-muted shrink-0 tabular-nums">
                      {p.upheld} upheld
                    </span>
                  )}
                </li>
              ))}
            </ul>
            <p className="measure text-xs text-muted mt-3">
              Imports flag these and skip the review call. Nothing is hidden &mdash; the finding
              still appears and still commits, it just no longer costs a reasoning call to be told
              what you have already decided three times.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
