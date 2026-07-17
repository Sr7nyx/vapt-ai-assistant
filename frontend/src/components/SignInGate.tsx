"use client";
import { signIn } from "next-auth/react";

const FEATURES = [
  "Extract findings from raw evidence with an AI pipeline that's checked at every step",
  "Deterministic CVSS, evidence grounding, and a skeptical reviewer keep the AI honest",
  "Import Burp, Nessus, ZAP, Nmap, and CSV, then AI-triage the noise",
  "Risk prioritization (EPSS + CISA KEV) and OWASP 2025 / PCI / CWE / ATT&CK mapping",
  "Retest tracking and one-click DOCX / PDF / XLSX / JSON reports",
];

export default function SignInGate() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6">
      <div className="w-full max-w-5xl grid lg:grid-cols-2 gap-12 items-center">
        <div className="animate-in">
          <div className="text-2xl font-semibold mb-5">
            vapt<span className="text-accent">.</span>console
          </div>
          <h1 className="text-3xl sm:text-4xl font-bold leading-tight mb-4">
            AI-assisted vulnerability assessment, <span className="text-accent">with guardrails.</span>
          </h1>
          <p className="text-muted mb-6 leading-relaxed">
            A penetration tester's workspace that takes an engagement from raw evidence and scanner output, through
            triage, to a client-ready report — without trusting the AI blindly. Every finding is scored
            deterministically, grounded against its own evidence, and challenged by a skeptical reviewer before it
            reaches a report.
          </p>
          <ul className="grid gap-3 mb-8">
            {FEATURES.map((t, i) => (
              <li key={i} className="flex gap-3 text-sm">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className="text-accent shrink-0 mt-0.5">
                  <path d="M20 6 9 17l-5-5" />
                </svg>
                <span>{t}</span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted">
            For authorized security testing only. This is a demo — use synthetic data, not real client data.
          </p>
        </div>

        <div className="card p-8 shadow-2xl animate-in">
          <h2 className="text-lg font-semibold mb-1">Get started</h2>
          <p className="text-muted text-sm mb-6">
            Sign in to create a project and start analyzing. Your projects and findings are private to your account.
          </p>
          <button className="btn w-full flex items-center justify-center gap-2" onClick={() => signIn("google")}>
            <svg width="18" height="18" viewBox="0 0 24 24">
              <path fill="currentColor" d="M21.35 11.1h-9.17v2.98h5.27c-.23 1.4-1.6 4.1-5.27 4.1-3.17 0-5.76-2.62-5.76-5.85s2.59-5.85 5.76-5.85c1.8 0 3.01.77 3.7 1.43l2.52-2.43C16.9 3.6 14.76 2.7 12.18 2.7 6.98 2.7 2.7 6.98 2.7 12.18s4.28 9.48 9.48 9.48c5.47 0 9.1-3.85 9.1-9.27 0-.62-.07-1.1-.17-1.29z" />
            </svg>
            Sign in with Google
          </button>
          <p className="text-xs text-muted mt-4">
            We only use your Google account to sign you in. Nothing is posted on your behalf.
          </p>
        </div>
      </div>
    </div>
  );
}
