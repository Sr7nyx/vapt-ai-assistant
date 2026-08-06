"use client";
import { signIn } from "next-auth/react";
import ShaderField from "./ShaderField";
import ReactiveOrb from "./ReactiveOrb";
import { GithubButton, SourceFooter } from "./SourceLinks";

/**
 * Sign-in.
 *
 * The only page a visitor sees before deciding whether the rest is worth their
 * time, so it states the actual argument rather than listing features: the
 * interesting claim is not that this uses an LLM, it is what happens to the LLM's
 * output before anyone is asked to believe it.
 */

/** Each of these is something in the codebase, not a roadmap item. */
const GUARDRAILS: { title: string; body: string }[] = [
  {
    title: "Claims are checked in code, not by asking again",
    body:
      "Where a finding can be settled from its evidence -- a header present or absent, a payload reflected raw or encoded, a request answered 200 or 403 -- it is verified by parsing the response. A claim the evidence contradicts can never be auto-confirmed.",
  },
  {
    title: "CVSS is computed, never quoted",
    body:
      "Scores come from the vector in code. Model-assigned severity is compared against the computed band and disagreements are surfaced rather than silently resolved.",
  },
  {
    title: "A second model argues the other side",
    body:
      "A reviewer lane makes the false-positive case for every finding and returns structured signals: evidence grounding, exploitability, confidence.",
  },
  {
    title: "The verdict is deterministic",
    body:
      "Those signals are combined by a fixed rule into Confirmed, False Positive, or Need Review. Confidence is earned by signals agreeing -- ambiguous findings are held rather than forced.",
  },
  {
    title: "Nothing reaches a report unexamined",
    body:
      "Exports run a pre-flight that names what is about to ship and should not be: contradicted claims, unadjudicated findings, missing scores. Every change to a finding is recorded with its actor and rationale.",
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
                Takes an engagement from raw evidence and scanner output, through triage, to a
                client-ready report. The models draft; deterministic checks decide.
              </p>


              <div className="float-in flex items-baseline gap-3 border-b border-border pb-1.5 mb-5" style={{ animationDelay: "180ms" }}>
                <h2 className="text-[11px] tracking-widest text-muted">
                  <span className="text-accent">&gt;</span> HOW IT KEEPS THE MODEL HONEST
                </h2>
              </div>
              <ol className="grid sm:grid-cols-2 gap-x-8 gap-y-5">
                {GUARDRAILS.map((g, i) => (
                  <li key={i} className="float-in grid gap-1" style={{ animationDelay: `${140 + i * 90}ms` }}>
                    <div className="flex items-baseline gap-2">
                      <span className="text-[10px] text-border tabular-nums shrink-0">
                        {String(i + 1).padStart(2, "0")}
                      </span>
                      <span className="text-sm text-text">{g.title}</span>
                    </div>
                    <p className="text-xs text-muted leading-relaxed pl-6">{g.body}</p>
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
                <ReactiveOrb className="mx-auto max-w-[480px]" />
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
                in, and nothing is posted on your behalf. The source is MIT licensed and readable
                without an account.
              </p>

              <p className="text-xs text-muted mt-6 leading-relaxed">
                For authorized security testing only. This deployment is a demonstration &mdash; use
                synthetic data, not real client data.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
