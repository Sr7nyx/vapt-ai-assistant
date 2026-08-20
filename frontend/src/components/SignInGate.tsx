"use client";
import { useEffect, useState } from "react";
import { motionReduced } from "@/lib/motion";
import { signIn } from "next-auth/react";
import ShaderField from "./ShaderField";
import ReactiveOrb, { OrbFocus } from "./ReactiveOrb";
import { GithubButton, SourceFooter } from "./SourceLinks";
import { markSignInStarted } from "@/lib/handoff";

/**
 * Sign-in.
 *
 * The orb is the argument, not the ornament: the outer belts carry the
 * vulnerability classes being analysed, the inner belt carries the four stages
 * that analyse them. Hovering a capability below lights the matching stage, so
 * the copy and the visual are the same statement rather than two decorations.
 */

const PIPELINE = ["INGEST", "PARSE", "VERIFY", "CHALLENGE", "VERDICT", "REPORT"];

/** Which pipeline steps a hovered capability covers. REPORT covers two, because
 *  the verdict is what the report is built from. */
const FOCUS_STEPS: Record<string, string[]> = {
  verify: ["PARSE", "VERIFY"],
  challenge: ["CHALLENGE"],
  report: ["VERDICT", "REPORT"],
};

/** Short enough to read in the time a visitor actually gives a landing page. */
const CAPABILITIES: { key: Exclude<OrbFocus, null>; label: string; title: string; body: string }[] = [
  {
    key: "verify",
    label: "VERIFY",
    title: "Claims are checked in code",
    body:
      "Evidence is parsed into HTTP exchanges and each finding is bound to the one it concerns. Twelve deterministic checks settle it from that exchange.",
  },
  {
    key: "challenge",
    label: "CHALLENGE",
    title: "A second model argues back",
    body:
      "A reviewer makes the false-positive case for every finding. A fixed rule combines the signals, so ambiguous findings are held rather than forced.",
  },
  {
    key: "report",
    label: "REPORT",
    title: "Nothing ships unexamined",
    body:
      "Exports run a pre-flight naming what should not reach a client: contradicted claims, unadjudicated findings, missing scores.",
  },
];

/** Reports the assembly, then becomes the instruction. Timed to match the orb's
 *  own boot rather than driven by it: a prop threaded through for a caption would
 *  re-render the orb's parent on every frame. */
function BootCaption() {
  const STAGES = ["PARTICLES", "SPHERE", "RINGS", "LABELS", "READY"];
  const [stage, setStage] = useState(0);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (motionReduced()) {
      setDone(true);
      return;
    }
    const marks = [0, 780, 1300, 1870, 2450];
    const timers = marks.map((ms, i) => window.setTimeout(() => setStage(i), ms));
    const finish = window.setTimeout(() => setDone(true), 3300);
    return () => {
      timers.forEach(clearTimeout);
      clearTimeout(finish);
    };
  }, []);

  return (
    <p className="text-center text-[10px] tracking-[0.25em] mt-2 h-4">
      {done ? (
        <span className="text-muted/60">CLICK TO PROBE</span>
      ) : (
        <span className="text-accent/70">
          {STAGES[stage]}
          <span className="text-muted/40">
            {" "}
            {"·".repeat(stage + 1)}
          </span>
        </span>
      )}
    </p>
  );
}

export default function SignInGate() {
  const [focus, setFocus] = useState<OrbFocus>(null);

  return (
    <div className="relative min-h-screen w-full overflow-hidden">
      <ShaderField />
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: "radial-gradient(1500px 900px at 60% 20%, transparent, rgba(10,14,12,0.94))" }}
      />

      <div className="relative z-10 min-h-screen flex flex-col px-6 lg:px-10">
        <header className="flex items-center justify-between gap-6 h-16 shrink-0 border-b border-border/50">
          <div className="text-sm tracking-wide">
            <span className="text-highlight">&gt;</span> vapt<span className="text-accent">.</span>console
          </div>
          <SourceFooter />
        </header>

        <div className="flex-1 flex items-center py-8">
          <div className="w-full max-w-6xl mx-auto grid lg:grid-cols-[minmax(0,1fr)_auto] gap-x-12 gap-y-10 items-center">
            <div className="min-w-0">
              <p
                className="float-in text-[10px] tracking-[0.3em] text-muted mb-4"
                style={{ animationDelay: "20ms" }}
              >
                AI-ASSISTED VULNERABILITY ANALYSIS
              </p>

              <h1
                className="float-in text-4xl sm:text-5xl leading-[1.08] mb-5 measure"
                style={{ animationDelay: "70ms" }}
              >
                The model is assumed{" "}
                <span className="text-accent">wrong until the evidence says otherwise.</span>
              </h1>

              <p
                className="float-in text-muted leading-relaxed mb-5 measure"
                style={{ animationDelay: "120ms" }}
              >
                An engagement workspace that takes raw evidence and scanner output through triage to
                a client-ready report. The models draft; deterministic checks decide.
              </p>

              {/* The pipeline in one line, directly under the claim: it says what the
                  product does faster than a paragraph can. */}
              <div
                className="float-in flex flex-wrap items-center gap-x-2 gap-y-2 mb-8"
                style={{ animationDelay: "160ms" }}
              >
                {PIPELINE.map((step, i) => (
                  <span key={step} className="flex items-center gap-2">
                    <span
                      className={`text-[10px] tracking-[0.2em] transition-colors ${
                        focus && FOCUS_STEPS[focus]?.includes(step)
                          ? "text-highlight"
                          : focus
                          ? "text-muted/40"
                          : "text-muted"
                      }`}
                    >
                      {step}
                    </span>
                    {i < PIPELINE.length - 1 && <span className="text-border">&rarr;</span>}
                  </span>
                ))}
              </div>

              <div
                className="float-in flex flex-col sm:flex-row gap-2.5 max-w-lg"
                style={{ animationDelay: "200ms" }}
              >
                <button
                  className="btn btn-icon flex-1 flex items-center justify-center gap-2.5 py-3"
                  onClick={() => {
                    // Recorded before the redirect: the page is about to be
                    // destroyed, so nothing in memory survives to say this
                    // happened.
                    markSignInStarted();
                    signIn("google");
                  }}
                >
                  <svg width="17" height="17" viewBox="0 0 24 24">
                    <path
                      fill="currentColor"
                      d="M21.35 11.1h-9.17v2.98h5.27c-.23 1.4-1.6 4.1-5.27 4.1-3.17 0-5.76-2.62-5.76-5.85s2.59-5.85 5.76-5.85c1.8 0 3.01.77 3.7 1.43l2.52-2.43C16.9 3.6 14.76 2.7 12.18 2.7 6.98 2.7 2.7 6.98 2.7 12.18s4.28 9.48 9.48 9.48c5.47 0 9.1-3.85 9.1-9.27 0-.62-.07-1.1-.17-1.29z"
                    />
                  </svg>
                  Sign in with Google
                </button>
                <div className="sm:w-56">
                  <GithubButton full label="VIEW EVALUATION" />
                </div>
              </div>

              <p
                className="float-in flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] tracking-[0.18em] text-muted mt-5"
                style={{ animationDelay: "250ms" }}
              >
                <span className="text-accent">&#9679;</span>
                <span>DEMO ENVIRONMENT</span>
                <span className="text-border">&middot;</span>
                <span>SYNTHETIC DATA ONLY</span>
                <span className="text-border">&middot;</span>
                <span>MIT LICENSED</span>
              </p>
            </div>

            <div className="float-in w-full lg:w-[420px]" style={{ animationDelay: "110ms" }}>
              <ReactiveOrb focus={focus} />
              {/* The caption doubles as the boot readout: the orb reports what it is
                  assembling, then settles into the instruction. */}
              <BootCaption />
            </div>
          </div>
        </div>

        {/* Hovering a capability lights the matching stage on the inner belt, so
            the words below and the visual above are one statement. */}
        <div className="shrink-0 border-t border-border/50 py-7">
          <div className="w-full max-w-6xl mx-auto grid md:grid-cols-3 gap-x-12 gap-y-7">
            {CAPABILITIES.map((c, i) => (
              <div
                key={c.key}
                className="float-in cursor-default"
                style={{ animationDelay: `${300 + i * 70}ms` }}
                onMouseEnter={() => setFocus(c.key)}
                onMouseLeave={() => setFocus(null)}
              >
                <div className="flex items-center gap-2.5 mb-2">
                  <span
                    className={`text-[10px] tracking-[0.25em] transition-colors ${
                      focus === c.key ? "text-highlight" : "text-accent"
                    }`}
                  >
                    {c.label}
                  </span>
                  <span
                    className={`h-px flex-1 transition-colors ${
                      focus === c.key ? "bg-highlight/60" : "bg-border"
                    }`}
                  />
                </div>
                <p className="text-sm mb-1">{c.title}</p>
                <p className="text-xs text-muted leading-relaxed">{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
