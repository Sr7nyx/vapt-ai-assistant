"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { RetestGuide as Guide } from "@/lib/types";
import { Spinner } from "./Loading";

/** Finding-specific retest guidance.
 *
 *  Mounted only when a finding row is expanded and its Retest guide is opened, so
 *  the fetch is lazy: nothing is requested for the hundreds of rows a project may
 *  hold. The guide is derived server-side from the finding, so every finding --
 *  including ones committed before this feature existed -- has one.
 *
 *  Commands come from the finding's real target values; anything the finding did
 *  not supply arrives as a labelled placeholder the tester must replace, listed
 *  explicitly rather than silently guessed. */

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1200);
    } catch {
      // Clipboard denied (insecure context / permissions): fall back to select.
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        setDone(true);
        setTimeout(() => setDone(false), 1200);
      } catch {
        /* nothing else to do; the text is still visible to copy by hand */
      }
      document.body.removeChild(ta);
    }
  };
  return (
    <button className="btn-sm shrink-0" onClick={copy} aria-label={label}>
      {done ? "Copied" : label}
    </button>
  );
}

function Bullets({ items, tone }: { items: string[]; tone?: string }) {
  if (!items?.length) return null;
  return (
    <ul className="grid gap-1">
      {items.map((x, i) => (
        <li key={i} className="text-sm flex gap-2">
          <span className={`mt-1.5 h-1 w-1 rounded-full shrink-0 ${tone || "bg-muted/60"}`} />
          <span className="whitespace-pre-wrap break-words">{x}</span>
        </li>
      ))}
    </ul>
  );
}

function Block({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1.5">
      <div className="term-h text-muted">{label}</div>
      {children}
    </div>
  );
}

export default function RetestGuide({ findingId }: { findingId: number }) {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [guide, setGuide] = useState<Guide | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const fetchGuide = (ai = false) => {
    if (!token) return;
    setBusy(true);
    setError("");
    api
      .retestGuide(token, findingId, ai)
      .then((g) => setGuide(g))
      .catch((e) => setError((e as Error).message))
      .finally(() => setBusy(false));
  };

  useEffect(() => {
    let alive = true;
    if (!token) return;
    api
      .retestGuide(token, findingId)
      .then((g) => alive && setGuide(g))
      .catch((e) => alive && setError((e as Error).message));
    return () => {
      alive = false;
    };
  }, [token, findingId]);

  if (error) {
    return <p className="text-xs text-muted">Retest guide unavailable: {error}</p>;
  }
  if (!guide) {
    return (
      <p className="text-xs text-muted flex items-center gap-2">
        <Spinner /> Building retest guide…
      </p>
    );
  }

  const tgt = guide.target;
  const location =
    tgt.url || (tgt.host ? (tgt.port ? `${tgt.host}:${tgt.port}` : tgt.host) : "");

  return (
    <div className="grid gap-4">
      {/* Header: what this guide is, and the whole-guide actions. */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="chip">{guide.kind === "network" ? "Network" : "Web"}</span>
        <span className="chip">{guide.class}</span>
        {guide.generated === "ai-enriched" && <span className="chip text-accent">AI-refined</span>}
        <span className="ml-auto flex gap-2">
          <CopyButton text={guide.copy_all} label="Copy all" />
          <button className="btn-sm" onClick={() => fetchGuide(false)} disabled={busy}>
            {busy ? "…" : "Regenerate"}
          </button>
          <button className="btn-sm" onClick={() => fetchGuide(true)} disabled={busy}
                  title="Refine the wording with the review model. Commands and targets are never changed.">
            {busy ? "…" : "AI refine"}
          </button>
        </span>
      </div>

      {location && (
        <div className="text-xs text-muted">
          Target: <span className="font-mono text-text break-all">{location}</span>
          {tgt.method && <span className="ml-2 font-mono">{tgt.method}</span>}
          {tgt.parameter && <span className="ml-2">param <span className="font-mono">{tgt.parameter}</span></span>}
        </div>
      )}

      <Block label="Objective">
        <p className="text-sm whitespace-pre-wrap break-words">{guide.objective}</p>
      </Block>

      {guide.prerequisites?.length > 0 && (
        <Block label="Prerequisites">
          <Bullets items={guide.prerequisites} />
        </Block>
      )}

      {/* Commands: each with its own copy button and rationale. */}
      <Block label="Commands">
        <div className="grid gap-2.5">
          {guide.commands.map((c, i) => (
            <div key={i} className="rounded-lg border border-border/60 overflow-hidden">
              <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border/60">
                <span className="text-xs text-muted">{c.label}</span>
                <span className="ml-auto">
                  <CopyButton text={c.command} />
                </span>
              </div>
              <pre className="font-mono text-xs bg-bg p-3 overflow-auto whitespace-pre-wrap break-words">{c.command}</pre>
              {c.note && <p className="text-[11px] text-muted px-3 py-2 border-t border-border/60">{c.note}</p>}
            </div>
          ))}
        </div>
      </Block>

      <div className="grid gap-4 sm:grid-cols-2">
        <Block label="If still vulnerable">
          <Bullets items={guide.expected_vulnerable} tone="bg-danger" />
        </Block>
        <Block label="If remediated">
          <Bullets items={guide.expected_remediated} tone="bg-accent" />
        </Block>
      </div>

      <Block label="Pass / fail">
        <p className="text-sm whitespace-pre-wrap break-words">{guide.pass_fail}</p>
      </Block>

      <Block label="Evidence to capture">
        <Bullets items={guide.evidence_to_capture} />
      </Block>

      {guide.placeholders?.length > 0 && (
        <div className="rounded-lg border border-warn/40 bg-warn/5 p-3 grid gap-1">
          <div className="term-h text-warn">Replace before running</div>
          <ul className="grid gap-1">
            {guide.placeholders.map((p, i) => (
              <li key={i} className="text-xs">
                <span className="font-mono text-warn">{p.placeholder}</span>
                <span className="text-muted"> — {p.means}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
