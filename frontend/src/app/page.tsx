"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { Overview, UsageSummary } from "@/lib/types";
import { Skeleton } from "@/components/Loading";
import { sevClass } from "@/components/Severity";
import { SeverityBar, BarList } from "@/components/Charts";
import { swr, readCache } from "@/lib/cache";
import { Section, Figure } from "@/components/Terminal";
import ReactiveOrb from "@/components/ReactiveOrb";
import AttackStrip from "@/components/AttackStrip";
import { useProject } from "@/lib/ProjectContext";

/**
 * Overview.
 *
 * Rewritten around a rule the previous version broke: show each fact once. The
 * total finding count appeared in the persistent status line, again as a large
 * metric card, again in the severity bar, and again in the severity table --
 * four renderings of one number. Showing every possible view of the data is what
 * makes a page read as generated rather than designed, and no amount of styling
 * fixes it.
 *
 * So the metric cards are gone: the status line above already carries projects,
 * findings, critical/high, flagged and tokens, and it is on every page. What is
 * left here is what the status line cannot show -- distributions, coverage, and
 * where the risk actually sits.
 */

type Row = { label: string; count: number };

export default function Dashboard() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [data, setData] = useState<Overview | null>(() => readCache<Overview>("overview") ?? null);
  const [loading, setLoading] = useState(() => !readCache<Overview>("overview"));
  const { projectId } = useProject();
  const [usageWindow, setUsageWindow] = useState("all");
  const [usage, setUsage] = useState<UsageSummary | null>(null);

  useEffect(() => {
    if (!token) return;
    let alive = true;
    api
      .usage(token, usageWindow)
      .then((r) => alive && setUsage(r))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [token, usageWindow]);

  useEffect(() => {
    if (!token) return;
    return swr<Overview>("overview", () => api.overview(token), (value) => {
      setData(value);
      setLoading(false);
    });
  }, [token]);

  if (loading || !data) {
    return (
      <div className="animate-in grid lg:grid-cols-[minmax(0,1fr)_13rem] gap-x-10 items-start">
        <Skeleton rows={6} />
      </div>
    );
  }

  const u = usage ?? data.usage;
  const risk = data.risk_priorities || {};
  const mapped = data.owasp_coverage.filter((r) => r.label !== "Unmapped (assign manually)");
  const unmapped = data.owasp_coverage.find((r) => r.label === "Unmapped (assign manually)");

  return (
    <div className="animate-in grid lg:grid-cols-[minmax(0,1fr)_13rem] gap-x-10 items-start">
      {/* THE ORB RAIL. Its own column rather than a slot inside one section, so it
          is present the whole way down the page and does not take horizontal room
          from the figures. Sticky, because a decoration that scrolls away has
          nothing to say about the section you have scrolled to.

          Untouched otherwise: same component, same props, no styling changes. */}
      <div className="grid gap-9 min-w-0">
        {/* 1. WHERE TO START.

            Risk priority leads, with severity beside it. Severity answers "how bad";
            risk priority answers "what next", because it blends CVSS with exploit
            probability, KEV and environment. Pairing them is the point: the two
            differing is the interesting fact, and two sections apart nobody notices
            that five Criticals produced no Urgents. */}
        <Section
          title="Where to start"
          note="Risk blends CVSS with exploit probability and environment. Severity is the raw rating."
        >
          <div className="grid gap-5">
            <div className="grid md:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] gap-x-10 gap-y-6 rounded-xl border border-border bg-surface/40 p-5">
              <div>
                <div className="text-[10px] tracking-widest text-muted mb-3">RISK PRIORITY</div>
                <div className="flex flex-wrap gap-x-8 gap-y-3">
                  <Figure label="Urgent" value={risk.Urgent ?? 0} tone="danger" />
                  <Figure label="High" value={risk.High ?? 0} tone="warn" />
                  <Figure label="Moderate" value={risk.Moderate ?? 0} tone="accent" />
                  <Figure label="Low" value={risk.Low ?? 0} />
                </div>
              </div>
              <div className="md:border-l md:border-border md:pl-10">
                <div className="text-[10px] tracking-widest text-muted mb-3">SEVERITY</div>
                <SeverityBar rows={data.by_severity} />
              </div>
            </div>

            {/* Directly under the lead, not three sections down: flagged findings are
                what should stop a report going out. */}
            {data.qa_flags > 0 && (
              <p className="measure border-l-2 border-warn/70 pl-3 py-1 text-sm text-warn">
                {data.qa_flags} finding{data.qa_flags === 1 ? "" : "s"} carry verification flags
                &mdash; unverified evidence, severity disagreement, or prompt injection. Review
                before reporting.
              </p>
            )}
          </div>
        </Section>

        {/* 2. THE SAME SET, THREE WAYS. */}
        <Section title="Breakdown">
          <div className="flex flex-wrap gap-x-14 gap-y-8">
            <Table col="Status" rows={data.by_status} />
            <Table col="Severity" rows={data.by_severity} colorSeverity />
            <Table col="Category" rows={data.by_category} />
          </div>
        </Section>

        {/* 3. FRAMEWORK COVERAGE. OWASP and ATT&CK answer the same kind of question,
            so they belong in one glance rather than as two unrelated sections. */}
        <Section
          title="Framework coverage"
          note="Indicative mapping. Findings with no reliable signal stay unmapped rather than guessed."
        >
          <div className="grid xl:grid-cols-2 gap-x-14 gap-y-8 items-start">
            <div className="min-w-0">
              <div className="text-[10px] tracking-widest text-muted mb-3">OWASP TOP 10:2025</div>
              <BarList rows={mapped} />
              {unmapped && (
                <p className="measure text-xs text-muted mt-3">
                  <span className="text-text">{unmapped.count}</span> finding
                  {unmapped.count === 1 ? "" : "s"} could not be mapped from the available signal
                  and are left for manual assignment. A guessed framework category is worse than an
                  absent one, because it looks authoritative in a report.
                </p>
              )}
            </div>
            <div className="min-w-0">
              <div className="text-[10px] tracking-widest text-muted mb-3">
                MITRE ATT&amp;CK &mdash; BY TACTIC
              </div>
              <AttackStrip projectId={projectId} />
            </div>
          </div>
        </Section>

        {/* 4. OPERATIONAL, NOT POSTURE. Cost belongs last: mixing it into the same
            flow implies it is comparable to the risk figures above. */}
        <Section
          title="LLM usage"
          actions={
            <div className="flex items-center gap-1">
              {([["1h", "1H"], ["24h", "24H"], ["7d", "7D"], ["30d", "30D"], ["all", "ALL"]] as const).map(
                ([key, label]) => (
                  <button
                    key={key}
                    onClick={() => setUsageWindow(key)}
                    aria-pressed={usageWindow === key}
                    className={`rounded border px-2 py-0.5 text-[10px] tracking-widest transition-colors ${
                      usageWindow === key
                        ? "border-accent/70 text-accent"
                        : "border-border text-muted hover:border-accent/50 hover:text-text"
                    }`}
                  >
                    {label}
                  </button>
                )
              )}
            </div>
          }
        >
          <div className="flex flex-wrap gap-x-8 gap-y-2 mb-5">
            <Figure label="Calls" value={u.calls} />
            <Figure label="Total tokens" value={u.total_tokens} />
            <Figure label="Prompt" value={u.prompt_tokens} />
            <Figure label="Completion" value={u.completion_tokens} />
          </div>

        {u.by_model?.length > 0 && (
          <table className="w-full text-sm max-w-xl">
            <thead className="text-muted text-left border-b border-border">
              <tr>
                <th className="font-normal text-xs pb-1.5">Model</th>
                <th className="font-normal text-xs pb-1.5 text-right">Calls</th>
                <th className="font-normal text-xs pb-1.5 text-right">Tokens</th>
              </tr>
            </thead>
            <tbody>
              {u.by_model.map((m) => (
                <tr key={m.model} className="border-b border-border/40 last:border-0">
                  <td className="py-1.5 font-mono text-xs">{m.model}</td>
                  <td className="py-1.5 text-right tabular-nums">{m.calls}</td>
                  <td className="py-1.5 text-right tabular-nums">{m.total_tokens.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        </Section>
      </div>

      {/* The orb rail.

          Its own column rather than a slot inside one section: it is present the
          whole way down the page and takes no horizontal room from the figures.
          Sticky, because a decoration that scrolls away has nothing to say about
          the section you have scrolled to.

          The component is untouched -- same props, same styling as before. */}
      <div className="hidden lg:block sticky top-6 justify-self-center">
        <div
          className="w-52"
          style={{
            filter:
              "brightness(1.4) saturate(1.15) drop-shadow(0 0 14px rgba(126, 231, 135, 0.28))",
          }}
        >
          <ReactiveOrb showLabels={false} />
        </div>
      </div>
    </div>
  );
}

/** Rows and counts, ruled rather than boxed. */
function Table({
  col,
  rows,
  colorSeverity,
}: {
  col: string;
  rows: Row[];
  colorSeverity?: boolean;
}) {
  // Category labels are full sentences ("Web Application/API Vulnerability");
  // status and severity are single words. Sizing them identically would either
  // wrap the long one or strand the short ones.
  const width = col === "Category" ? "min-w-[22rem]" : "min-w-[15rem]";
  if (rows.length === 0) {
    return (
      <div className={width}>
        <div className="text-[10px] tracking-widest text-muted mb-2">{col.toUpperCase()}</div>
        <p className="text-xs text-muted">Nothing yet.</p>
      </div>
    );
  }
  const total = rows.reduce((sum, r) => sum + r.count, 0) || 1;
  return (
    <div>
      <div className="text-[10px] tracking-widest text-muted mb-2">{col.toUpperCase()}</div>
      <table className={`w-full max-w-sm text-sm ${width}`}>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label} className="border-b border-border/40 last:border-0">
              <td className="py-1.5 pr-2">
                {colorSeverity ? <span className={sevClass(r.label)}>{r.label}</span> : r.label}
              </td>
              <td className="py-1.5 text-right tabular-nums w-12">{r.count}</td>
              {/* A share bar in the row itself, so proportion is legible without a
                  second chart repeating the same numbers elsewhere. */}
              <td className="py-1.5 w-16 pl-3">
                <span className="block h-1 rounded-full bg-white/5 overflow-hidden">
                  <span
                    className="grow-x block h-full rounded-full bg-accent/50"
                    style={{ width: `${(r.count / total) * 100}%` }}
                  />
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
