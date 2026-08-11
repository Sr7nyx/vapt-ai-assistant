"use client";
import { signIn } from "next-auth/react";
import ShaderField from "./ShaderField";
import ReactiveOrb from "./ReactiveOrb";
import { GithubButton, SourceFooter } from "./SourceLinks";

/**
 * Sign-in.
 *
 * Structured around what the page is FOR. Its job is to get someone signed in;
 * the argument is what persuades them it is worth doing. The previous version had
 * that backwards -- the sign-in button sat in a side column beneath the orb and
 * five claims, competing with them for attention.
 *
 * So: one hero band carrying the claim, the visual and the action together, and a
 * capability strip beneath it. Detail is not hidden behind markers either. On a
 * settings page a marker is right, because the reader is mid-task and the
 * explanation is an interruption. Here the explanation IS the content, and a page
 * that makes a visitor click to find out what it does has answered nothing in the
 * fifteen seconds it had.
 */

/** Three columns, because three is what gets read. Each is one line. */
const CAPABILITIES: { label: string; title: string; body: string }[] = [
  {
    label: "VERIFY",
    title: "Twelve deterministic checks",
    body:
      "Evidence is parsed into individual HTTP exchanges and each finding is bound to the one it is about. Headers, cookies, CORS, reflection, redirects, tokens, session handling and rate limits are settled by reading that exchange, not by asking a model twice.",
  },
  {
    label: "CHALLENGE",
    title: "A second model argues the other side",
    body:
      "A separate reviewer makes the false-positive case for every finding. Its signals are combined by a fixed rule, so confidence is earned by agreement and ambiguous findings are held rather than forced.",
  },
  {
    label: "REPORT",
    title: "Nothing ships unexamined",
    body:
      "Exports run a pre-flight naming what is about to reach a client and should not: contradicted claims, unadjudicated findings, missing scores. Every change to a finding is recorded with its actor.",
  },
];

export default function SignInGate() {
  return (
    <div className="relative min-h-screen w-full overflow-hidden">
      <ShaderField />
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: "radial-gradient(1500px 900px at 62% 22%, transparent, rgba(10,14,12,0.94))" }}
      />

      <div className="relative z-10 min-h-screen flex flex-col px-6 lg:px-10">
        <header className="flex items-center justify-between gap-6 h-16 shrink-0 border-b border-border/50">
          <div className="text-sm tracking-wide">
            <span className="text-highlight">&gt;</span> vapt<span className="text-accent">.</span>console
          </div>
          <SourceFooter />
        </header>

        {/* Hero: the claim, the visual and the action in one band, so nothing the
            visitor needs is below the fold or off to one side. */}
        <div className="flex-1 flex items-center py-10">
          <div className="w-full max-w-6xl mx-auto grid lg:grid-cols-[minmax(0,1fr)_auto] gap-x-16 gap-y-10 items-center">
            <div>
              <p
                className="float-in text-[10px] tracking-[0.3em] text-muted mb-5"
                style={{ animationDelay: "20ms" }}
              >
                AI-ASSISTED PENETRATION TESTING
              </p>

              <h1
                className="float-in text-4xl sm:text-5xl leading-[1.08] mb-6 measure"
                style={{ animationDelay: "70ms" }}
              >
                The model is assumed{" "}
                <span className="text-accent">wrong until the evidence says otherwise.</span>
              </h1>

              <p
                className="float-in text-muted leading-relaxed mb-9 measure"
                style={{ animationDelay: "130ms" }}
              >
                An engagement workspace that takes raw evidence and scanner output through triage to
                a client-ready report. The models draft; deterministic checks decide.
              </p>

              {/* The action, at the point the reader has been persuaded. */}
              <div
                className="float-in flex flex-col sm:flex-row gap-2.5 max-w-lg"
                style={{ animationDelay: "190ms" }}
              >
                <button
                  className="btn btn-icon flex-1 flex items-center justify-center gap-2.5 py-3"
                  onClick={() => signIn("google")}
                >
                  <svg width="17" height="17" viewBox="0 0 24 24">
                    <path
                      fill="currentColor"
                      d="M21.35 11.1h-9.17v2.98h5.27c-.23 1.4-1.6 4.1-5.27 4.1-3.17 0-5.76-2.62-5.76-5.85s2.59-5.85 5.76-5.85c1.8 0 3.01.77 3.7 1.43l2.52-2.43C16.9 3.6 14.76 2.7 12.18 2.7 6.98 2.7 2.7 6.98 2.7 12.18s4.28 9.48 9.48 9.48c5.47 0 9.1-3.85 9.1-9.27 0-.62-.07-1.1-.17-1.29z"
                    />
                  </svg>
                  Sign in with Google
                </button>
                <div className="sm:w-52">
                  <GithubButton full label="VIEW SOURCE" />
                </div>
              </div>

              <p
                className="float-in text-xs text-muted mt-4 measure"
                style={{ animationDelay: "240ms" }}
              >
                Projects and findings are private to your account. MIT licensed and readable without
                one. Authorized testing only &mdash; this deployment is a demonstration, so use
                synthetic data.
              </p>
            </div>

            <div className="float-in w-full lg:w-[400px]" style={{ animationDelay: "110ms" }}>
              <ReactiveOrb />
              <p className="text-center text-[10px] tracking-[0.25em] text-muted/60 mt-3 transition-colors hover:text-accent">
                CLICK TO DISRUPT
              </p>
            </div>
          </div>
        </div>

        {/* Capability strip: three columns, visible prose, no markers. This is the
            substance, so it is on the page rather than one click away. */}
        <div className="shrink-0 border-t border-border/50 py-8">
          <div className="w-full max-w-6xl mx-auto grid md:grid-cols-3 gap-x-12 gap-y-8">
            {CAPABILITIES.map((c, i) => (
              <div
                key={c.label}
                className="float-in"
                style={{ animationDelay: `${300 + i * 80}ms` }}
              >
                <div className="flex items-center gap-2.5 mb-2.5">
                  <span className="text-[10px] tracking-[0.25em] text-accent">{c.label}</span>
                  <span className="h-px flex-1 bg-border" />
                </div>
                <p className="text-sm mb-1.5">{c.title}</p>
                <p className="text-xs text-muted leading-relaxed">{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
