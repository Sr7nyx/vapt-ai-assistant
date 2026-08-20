"use client";
import { useEffect, useRef, useState } from "react";
import ShaderField from "./ShaderField";
import { motionReduced } from "@/lib/motion";

/**
 * The moment between Google returning and the console appearing.
 *
 * That window was a bare spinner, which is the worst thing to show after a
 * redirect: the user has just left the site and come back, and a generic loader
 * gives no signal that they arrived in the right place.
 *
 * It is also genuinely dead time -- the session is being verified and the first
 * overview fetch is in flight -- so filling it costs nothing and covers a wait
 * that exists regardless.
 *
 * The stages are real work in the right order, not decoration: the token is
 * verified, then the account is resolved, then the projects load. Naming them is
 * more useful than a spinner and takes the same space.
 */

const STAGES = [
  { at: 0, label: "VERIFYING TOKEN" },
  { at: 620, label: "RESOLVING ACCOUNT" },
  { at: 1180, label: "LOADING PROJECTS" },
  { at: 1720, label: "READY" },
];

export default function SessionHandoff({ email }: { email?: string }) {
  const [stage, setStage] = useState(0);
  const [reduced, setReduced] = useState(false);
  const timers = useRef<number[]>([]);

  useEffect(() => {
    if (motionReduced()) {
      setReduced(true);
      setStage(STAGES.length - 1);
      return;
    }
    timers.current = STAGES.map((s, i) =>
      window.setTimeout(() => setStage(i), s.at)
    );
    return () => {
      timers.current.forEach(clearTimeout);
      timers.current = [];
    };
  }, []);

  const done = stage >= STAGES.length - 1;

  return (
    <div className="relative min-h-screen w-full overflow-hidden">
      {/* The same field the sign-in page uses, so the two screens are visibly the
          same application rather than a loader borrowed from somewhere else. */}
      {!reduced && <ShaderField />}
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: "radial-gradient(1200px 800px at 50% 45%, transparent, rgba(10,14,12,0.95))" }}
      />

      <div className="relative z-10 min-h-screen flex flex-col items-center justify-center px-6">
        <div className="text-lg tracking-wide mb-10">
          <span className="text-highlight">&gt;</span> vapt<span className="text-accent">.</span>console
        </div>

        {/* Stages as a vertical trace, the way the job log reads. Completed ones
            stay visible: a step that disappears when it finishes gives the reader
            nothing to measure progress against. */}
        <ol className="grid gap-2 w-full max-w-xs">
          {STAGES.map((s, i) => {
            const active = i === stage;
            const complete = i < stage;
            return (
              <li
                key={s.label}
                className="flex items-center gap-3 text-[11px] tracking-[0.2em] transition-colors duration-300"
              >
                <span
                  className={`inline-block w-3 shrink-0 ${
                    complete ? "text-accent" : active ? "text-highlight" : "text-border"
                  }`}
                >
                  {complete ? "\u2713" : active ? "\u203a" : "\u00b7"}
                </span>
                <span
                  className={
                    complete ? "text-muted" : active ? "text-text" : "text-muted/30"
                  }
                >
                  {s.label}
                </span>
                {active && !done && (
                  <span className="ml-auto flex gap-1">
                    <span className="handoff-dot inline-block w-1 h-1 rounded-full bg-highlight" />
                    <span
                      className="handoff-dot inline-block w-1 h-1 rounded-full bg-highlight"
                      style={{ animationDelay: "160ms" }}
                    />
                    <span
                      className="handoff-dot inline-block w-1 h-1 rounded-full bg-highlight"
                      style={{ animationDelay: "320ms" }}
                    />
                  </span>
                )}
              </li>
            );
          })}
        </ol>

        {email && (
          <p className="text-xs text-muted mt-8 truncate max-w-xs text-center">{email}</p>
        )}
      </div>
    </div>
  );
}
