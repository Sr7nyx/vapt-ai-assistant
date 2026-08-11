"use client";
import { ReviewSummary, VerdictResolution, Verification } from "@/lib/types";

const VERDICT_TONE: Record<string, string> = {
  "likely false positive": "border-danger/60 text-danger",
  "needs more evidence": "border-warn/60 text-warn",
  "likely true positive": "border-accent/60 text-accent",
  confirmed: "border-accent/60 text-accent",
};

function tone(verdict: string) {
  return VERDICT_TONE[verdict.trim().toLowerCase()] || "border-border text-muted";
}

/** The engine's resolved status with its confidence -- the decisive output, as
 *  opposed to the reviewer's hedged verdict. */
export function VerdictBadge({ verdict }: { verdict?: VerdictResolution }) {
  if (!verdict) return null;
  const s = verdict.resolved_status;
  const tone =
    s === "Confirmed" ? "border-accent/60 text-accent"
    : s === "False Positive" ? "border-danger/60 text-danger"
    : "border-border text-muted";
  return (
    <span className={`chip ${tone}`} title={verdict.rationale}>
      {s}
      {verdict.confidence > 0 && s !== "Need Review" && (
        <span className="opacity-70"> {Math.round(verdict.confidence * 100)}%</span>
      )}
    </span>
  );
}

/** Mechanical-verification chip. Distinct from the reviewer's chip on purpose:
 *  this one is a parsed fact, not a second opinion, and the interface should not
 *  let the two look interchangeable. */
export function VerifiedChip({ verification }: { verification?: Verification }) {
  if (!verification || verification.status === "INSUFFICIENT") return null;
  const refuted = verification.status === "REFUTED";
  return (
    <span
      className={`chip ${refuted ? "border-danger/70 text-danger" : "border-accent/70 text-accent"}`}
      title={verification.summary}
    >
      {refuted ? "CONTRADICTED BY EVIDENCE" : "VERIFIED BY CHECK"}
    </span>
  );
}

/** Compact verdict chip for list rows. */
export function VerdictChip({ review }: { review?: ReviewSummary }) {
  if (!review?.reviewed) return null;
  return (
    <span className={`chip ${tone(review.verdict)}`} title={review.reasoning || undefined}>
      {review.verdict}
    </span>
  );
}

/** Small warning marker for rows whose verification signals need attention. */
export function ReviewFlag({ review }: { review?: ReviewSummary }) {
  if (!review) return null;
  const count = review.warnings.length;
  if (count === 0) return null;
  return (
    <span
      className="chip border-danger/60 text-danger"
      title={review.warnings.join("; ")}
    >
      {count} flag{count > 1 ? "s" : ""}
    </span>
  );
}

/** The reviewer's assessment in full: what it concluded, why, and what would
 *  change its mind. Previously this reasoning existed only in exported reports,
 *  so the person doing triage in the app could see a verdict but never its basis. */
export default function ReviewPanel({
  review,
  verdict,
  verification,
}: {
  review?: ReviewSummary;
  verdict?: VerdictResolution;
  verification?: Verification;
}) {
  if (!review && !verdict && !verification) return null;

  // The "not reviewed" note only applies when there is a review object and no
  // verdict to show; with a verdict present we render the resolution instead.
  if (review && !review.reviewed && !verdict) {
    if (review.unavailable) {
      return (
        <div className="rounded-lg border border-border/60 px-3 py-2 text-xs text-muted">
          Skeptical review {review.unavailable}. The finding has not been independently audited.
        </div>
      );
    }
    if (review.warnings.length === 0 && review.cautions.length === 0) return null;
  }

  return (
    <div className="rounded-lg border border-border/60 overflow-hidden">
      {verdict && (
        <div className="px-3 py-2 border-b border-border/60">
          <div className="flex items-center gap-2 flex-wrap">
            <VerdictBadge verdict={verdict} />
            <span className="text-xs text-muted">
              {verdict.confidence_label} confidence
              {verdict.auto_set && verdict.resolved_status !== "Need Review" ? " - status set automatically" : ""}
            </span>
          </div>
          {verdict.confidence > 0 && (
            <div className="mt-2 h-1 w-full rounded-full bg-white/5 overflow-hidden">
              <div
                className={`h-full rounded-full ${verdict.resolved_status === "False Positive" ? "bg-danger" : verdict.resolved_status === "Confirmed" ? "bg-accent" : "bg-muted/50"}`}
                style={{ width: `${Math.max(4, verdict.confidence * 100)}%` }}
              />
            </div>
          )}
          <p className="text-xs text-muted mt-1.5">{verdict.rationale}</p>
        </div>
      )}
      {verification && verification.status !== "INSUFFICIENT" && (
        <div className="px-3 py-2 border-b border-border/60">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-muted uppercase tracking-wide">Deterministic check</span>
            <VerifiedChip verification={verification} />
          </div>
          <p className="text-xs text-muted mt-1.5">
            Checked by parsing the evidence, not by asking a model.
            {verification.exchange_count ? (
              <>
                {" "}
                {verification.exchange_id ? (
                  <>
                    Run against{" "}
                    <span className="text-text font-mono">{verification.exchange_id}</span> of{" "}
                    {verification.exchange_count} in this evidence.
                  </>
                ) : (
                  <>
                    The evidence holds {verification.exchange_count} exchanges and the finding does
                    not say which it refers to, so nothing was checked against a possibly unrelated
                    response.
                  </>
                )}
              </>
            ) : null}
          </p>
          <ul className="mt-2 grid gap-1">
            {verification.checks
              .filter((c) => c.status !== "INSUFFICIENT")
              .map((c, i) => (
                <li key={i} className="text-xs">
                  <span className={c.status === "REFUTED" ? "text-danger" : "text-accent"}>
                    {c.status}
                  </span>{" "}
                  <span className="text-muted">({c.verifier})</span> {c.detail}
                  {c.evidence && (
                    <span className="block font-mono text-muted mt-0.5 truncate">{c.evidence}</span>
                  )}
                </li>
              ))}
          </ul>
        </div>
      )}

      {review?.reviewed && (
      <div className="px-3 py-2 border-b border-border/60 flex items-center gap-2 flex-wrap">
        <span className="text-xs text-muted uppercase tracking-wide">Skeptical review</span>
        {review.reviewed && <span className={`chip ${tone(review.verdict)}`}>{review.verdict}</span>}
        {review.confidence && <span className="chip">confidence: {review.confidence}</span>}
        {review.false_positive_risk && <span className="chip">FP risk: {review.false_positive_risk}</span>}
      </div>
      )}

      {review && (
      <div className="px-3 py-2 grid gap-2 text-sm">
        {review.severity_disagreement && review.reviewer_severity && (
          <div className="text-warn text-xs">
            Reviewer disagrees on severity and would rate this {review.reviewer_severity}.
          </div>
        )}
        {review.exploitability && (
          <Line label="Exploitability">{review.exploitability}</Line>
        )}
        {review.reasoning && <Line label="Reasoning">{review.reasoning}</Line>}
        {review.evidence_needed && (
          <Line label="Evidence still needed">{review.evidence_needed}</Line>
        )}

        {(review.warnings.length > 0 || review.cautions.length > 0) && (
          <div className="border-t border-border/60 pt-2 grid gap-1">
            <div className="text-xs text-muted">Verification signals</div>
            {review.grounding && (
              <div className="text-xs">
                Evidence grounding:{" "}
                <span className={review.grounding === "VERIFIED" ? "text-accent" : "text-warn"}>
                  {review.grounding}
                </span>
              </div>
            )}
            {review.injection && (
              <div className="text-xs text-danger">
                Prompt-injection indicators were found in the source material.
              </div>
            )}
            {review.warnings.map((w, i) => (
              <div key={`w${i}`} className="text-xs text-danger">{w}</div>
            ))}
            {review.cautions.map((c, i) => (
              <div key={`c${i}`} className="text-xs text-warn">{c}</div>
            ))}
          </div>
        )}
      </div>
      )}
    </div>
  );
}

function Line({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs text-muted">{label}</div>
      <div className="text-sm whitespace-pre-wrap">{children}</div>
    </div>
  );
}
