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
      <div className="animate-in">
        <Skeleton rows={6} />
      </div>
    );
  }

  const u = usage ?? data.usage;
  const risk = data.risk_priorities || {};
  const mapped = data.owasp_coverage.filter((r) => r.label !== "Unmapped (assign manually)");
  const unmapped = data.owasp_coverage.find((r) => r.label === "Unmapped (assign manually)");

  return (
    <div className="animate-in grid gap-8">
      {data.qa_flags > 0 && (
        <p className="measure border-l-2 border-warn/70 pl-3 py-1 text-sm text-warn">
          {data.qa_flags} finding{data.qa_flags === 1 ? "" : "s"} carry verification flags &mdash;
          unverified evidence, severity disagreement, or prompt injection. Review before reporting.
        </p>
      )}

      {/* Severity: one bar, no box. A single line of information does not need a
          bordered container around it. The orb beside it is decorative and says so
          in the markup: an ornament that looks like an instrument is worse than no
          ornament, so it is aria-hidden and cannot be clicked. */}
      <div className="grid md:grid-cols-[minmax(0,1fr)_auto] gap-6 items-start">
        <Section title="Severity">
          <SeverityBar rows={data.by_severity} />
        </Section>
        <div className="hidden md:block w-40 -mt-2 opacity-70">
          <ReactiveOrb showLabels={false} />
        </div>
      </div>

      {/* Risk sits beside severity because the interesting fact is the DIFFERENCE
          between them: priority blends CVSS with exploit probability and KEV, so a
          Critical that nobody is exploiting outranks nothing. */}
      <Section
        title="Risk priority"
        note="CVSS blended with EPSS exploit probability, CISA KEV, and environment. Deliberately distinct from raw severity."
      >
        <div className="flex flex-wrap gap-x-8 gap-y-2">
          <Figure label="Urgent" value={risk.Urgent ?? 0} tone="danger" />
          <Figure label="High" value={risk.High ?? 0} tone="warn" />
          <Figure label="Moderate" value={risk.Moderate ?? 0} tone="accent" />
          <Figure label="Low" value={risk.Low ?? 0} />
        </div>
      </Section>

      <Section title="Breakdown">
        <div className="flex flex-wrap gap-x-14 gap-y-8">
          <Table col="Status" rows={data.by_status} />
          <Table col="Severity" rows={data.by_severity} colorSeverity />
          <Table col="Category" rows={data.by_category} />
        </div>
      </Section>

      <Section
        title="OWASP Top 10:2025 coverage"
        note="Indicative mapping. Findings with no reliable signal stay unmapped rather than being guessed."
      >
        {/* A row rather than halves: at 50/50 the note starts at mid-page and
            drifts away from the bars it refers to as the window widens. */}
        <div className="flex flex-wrap gap-x-14 gap-y-4 items-start">
          <div className="min-w-[24rem] max-w-2xl flex-1">
            <BarList rows={mapped} />
          </div>
          {unmapped && (
            <p className="measure text-xs text-muted self-start">
              <span className="text-text">{unmapped.count}</span> finding
              {unmapped.count === 1 ? "" : "s"} could not be mapped from the available signal and are
              left for manual assignment. That is deliberate: a guessed framework category is worse
              than an absent one, because it looks authoritative in a report.
            </p>
          )}
        </div>
      </Section>

      <Section title="LLM usage">
        <div className="flex items-center gap-1 mb-4">
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
