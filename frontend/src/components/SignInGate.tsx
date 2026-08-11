"use client";
import { signIn } from "next-auth/react";
import ShaderField from "./ShaderField";
import ReactiveOrb from "./ReactiveOrb";
import { GithubButton, SourceFooter } from "./SourceLinks";
import InfoHint from "./InfoHint";

/**
 * Sign-in.
 *
 * The only page a visitor sees before deciding whether the rest is worth their
 * time, so it states the actual argument rather than listing features: the
 * interesting claim is not that this uses an LLM, it is what happens to the LLM's
 * output before anyone is asked to believe it.
 */

/** Each of these is something in the codebase, not a roadmap item. */
/**
 * The argument, one line each.
 *
 * These headings are the message: a visitor decides in about fifteen seconds
 * whether the rest is worth their attention, and five paragraphs of supporting
 * prose is not read in fifteen seconds -- it is skipped, taking the headings with
 * it. The detail sits behind a marker for anyone who wants it, which is the same
 * treatment the settings page gives its explanations.
 */
const GUARDRAILS: { title: string; detail: string }[] = [
  {
    title: "Claims are checked in code, not by asking again",
    detail:
      "Evidence is parsed into individual HTTP exchanges and each finding is bound to the one it is about. Headers, cookie flags, CORS policy, reflected payloads, redirects, tokens and rate limits are then settled by reading that exchange. A claim the evidence contradicts can never be auto-confirmed, and where the finding cannot be tied to a specific exchange, nothing is checked at all.",
  },
  {
    title: "CVSS is computed, never quoted",
    detail:
      "Scores come from the vector, in code. Model-assigned severity is compared against the computed band and disagreements are surfaced rather than quietly resolved.",
  },
  {
    title: "A second model argues the other side",
    detail:
      "A separate reviewer lane makes the false-positive case for every finding and returns structured signals: evidence grounding, exploitability, confidence, and any sign of prompt injection in the source material.",
  },
  {
    title: "The verdict is deterministic",
    detail:
      "Those signals are combined by a fixed rule into Confirmed, False Positive, or Need Review. Confidence is earned by signals agreeing, so ambiguous findings are held rather than forced into a decision.",
  },
  {
    title: "Nothing reaches a report unexamined",
    detail:
      "Exports run a pre-flight naming what is about to ship and should not be: contradicted claims, findings nobody has adjudicated, missing scores. Every change to a finding is recorded with its actor and rationale.",
  },
];

export default function SignInGate() {
  return (
    <div className="relative min-h-screen w-full overflow-hidden">
      <ShaderField />
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: "radial-gradient(1400px 820px at 50% 34%, transparent, rgba(10,14,12,0.92))" }}
      />

      <div className="relative z-10 min-h-screen w-full flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-7xl">
          <header className="flex items-center justify-between gap-4 mb-10 animate-in">
            <div className="text-xl tracking-wide">
              <span className="text-highlight">&gt;</span> vapt<span className="text-accent">.</span>console
            </div>
            <SourceFooter />
          </header>

          <div className="grid lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)] gap-x-16 gap-y-12 items-start">
            {/* The argument */}
            <div className="animate-in">
              <h1 className="float-in text-3xl sm:text-5xl leading-[1.1] mb-5 measure" style={{ animationDelay: "40ms" }}>
                An AI pentest workspace that assumes the AI is{" "}
                <span className="text-accent">wrong until the evidence says otherwise.</span>
              </h1>
              <p className="float-in text-muted leading-relaxed mb-8 measure" style={{ animationDelay: "120ms" }}>
                From raw evidence and scanner output, through triage, to a client-ready report.
                The models draft; deterministic checks decide.
              </p>


              <div className="float-in flex items-baseline gap-3 border-b border-border pb-1.5 mb-5" style={{ animationDelay: "180ms" }}>
                <h2 className="text-[11px] tracking-widest text-muted">
                  <span className="text-accent">&gt;</span> HOW IT KEEPS THE MODEL HONEST
                </h2>
              </div>
              <ol className="grid sm:grid-cols-2 gap-x-10 gap-y-3">
                {GUARDRAILS.map((g, i) => (
                  <li
                    key={i}
                    className="float-in flex items-baseline gap-2.5"
                    style={{ animationDelay: `${140 + i * 80}ms` }}
                  >
                    <span className="text-[10px] text-border tabular-nums shrink-0">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <span className="text-sm leading-relaxed">
                      {g.title}{" "}
                      <InfoHint label={`About: ${g.title}`}>{g.detail}</InfoHint>
                    </span>
                  </li>
                ))}
              </ol>
            </div>

            {/* The orb, and the way in */}
            <div className="animate-in lg:sticky lg:top-12">
              {/* The orb is inset so the orbit has somewhere to go. At full width
                  its sphere fills the box and leaves a band of only ~14% for the
                  rings, which is why they had nowhere to sit without either
                  crossing the body or bleeding out of the column. */}
              <div className="relative mb-10 py-4">
                {/* No container: the orb sits on the page background, and the
                    belts are free to reach past where a card's edge would have
                    been. */}
                <ReactiveOrb className="mx-auto max-w-[380px]" />
                <p className="group text-center text-[10px] tracking-[0.25em] text-muted/70 mt-2 transition-colors hover:text-accent">
                  CLICK TO DISRUPT
                  <svg
                    aria-hidden="true"
                    width="9"
                    height="12"
                    viewBox="0 0 9 12"
                    className="inline-block ml-2 -mb-0.5 opacity-60"
                  >
                    <path
                      d="M4.5 0v9M1 6l3.5 3.5L8 6"
                      stroke="currentColor"
                      strokeWidth="1.1"
                      fill="none"
                      strokeLinecap="round"
                    />
                  </svg>
                </p>
              </div>

              {/* No card. A bordered panel here read as a separate object dropped
                  onto the page -- the one heavy box on a layout built from rules and
                  whitespace. The section rule is the same device every other page
                  uses, so the sign-in belongs to the design instead of interrupting
                  it. */}
              <div className="flex items-baseline gap-3 border-b border-border pb-1.5 mb-4">
                <h2 className="text-[11px] tracking-widest text-muted">
                  <span className="text-accent">&gt;</span> GET STARTED
                </h2>
              </div>

              <button
                className="btn btn-icon w-full flex items-center justify-center gap-2 py-2.5"
                onClick={() => signIn("google")}
              >
                <svg width="16" height="16" viewBox="0 0 24 24">
                  <path
                    fill="currentColor"
                    d="M21.35 11.1h-9.17v2.98h5.27c-.23 1.4-1.6 4.1-5.27 4.1-3.17 0-5.76-2.62-5.76-5.85s2.59-5.85 5.76-5.85c1.8 0 3.01.77 3.7 1.43l2.52-2.43C16.9 3.6 14.76 2.7 12.18 2.7 6.98 2.7 2.7 6.98 2.7 12.18s4.28 9.48 9.48 9.48c5.47 0 9.1-3.85 9.1-9.27 0-.62-.07-1.1-.17-1.29z"
                  />
                </svg>
                Sign in with Google
              </button>

              <div className="mt-2.5">
                <GithubButton full label="VIEW SOURCE ON GITHUB" />
              </div>

              <p className="text-xs text-muted mt-4 leading-relaxed">
                Projects and findings are private to your account. Google is used only to sign you
                in. MIT licensed, readable without an account.
              </p>

              <p className="text-xs text-muted mt-6 leading-relaxed">
                Authorized testing only. This deployment is a demonstration &mdash; use synthetic data.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
