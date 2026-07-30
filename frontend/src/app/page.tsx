"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { Overview } from "@/lib/types";
import { Skeleton } from "@/components/Loading";
import { sevClass } from "@/components/Severity";
import { SeverityBar, BarList, Panel } from "@/components/Charts";
import ShaderField from "@/components/ShaderField";
import { StatStrip, Stat, Sep, SectionHeading } from "@/components/Terminal";
import { UsageSummary } from "@/lib/types";

function OverviewHeader() {
  return (
    <section className="relative overflow-hidden rounded-2xl border border-border/60 px-6 py-8 mb-8">
      {/* A whisper of the landing shader: static, very faint, header only. */}
      <ShaderField intensity={0.11} animate={false} seed={8} />
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-t from-bg via-bg/40 to-transparent" />
      <div className="relative z-10">
        <div className="text-xs text-muted tracking-widest mb-1">VAPT CONSOLE</div>
        <h1 className="text-2xl tracking-wide caret">OVERVIEW</h1>
        <p className="text-muted text-sm mt-1">Aggregated across all of your projects.</p>
      </div>
    </section>
  );
}

type Accent = "danger" | "warn" | "accent" | undefined;
type Row = { label: string; count: number };

export default function Dashboard() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [data, setData] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);

  // Usage is fetched separately from /overview so the window can change without
  // re-aggregating the entire dashboard.
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
    setLoading(true);
    api.overview(token).then(setData).catch(() => {}).finally(() => setLoading(false));
  }, [token]);

  if (loading || !data) {
    return (
      <div className="animate-in">
        <OverviewHeader />
        <Skeleton rows={6} />
      </div>
    );
  }

  const u = usage ?? data.usage;

  return (
    <div className="animate-in space-y-10">
      <section>
        <OverviewHeader />
        <div className="mb-4">
          <StatStrip>
            <Stat label="PROJECTS" value={data.projects} />
            <Sep />
            <Stat label="FINDINGS" value={data.findings} />
            <Sep />
            <Stat label="CRIT/HIGH" value={data.critical + data.high} tone={data.critical + data.high > 0 ? "danger" : undefined} />
            <Sep />
            <Stat label="FLAGGED" value={data.qa_flags} tone={data.qa_flags > 0 ? "warn" : undefined} />
            <Sep />
            <Stat label="LLM CALLS" value={u.calls} />
          </StatStrip>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 stagger">
          <Metric label="Active projects" value={data.projects} />
          <Metric label="Aggregated findings" value={data.findings} />
          <Metric label="Critical" value={data.critical} accent="danger" />
          <Metric label="High" value={data.high} accent="warn" />
        </div>
      </section>

      <section>
        <SectionHeading>Findings breakdown</SectionHeading>
        <div className="card mb-4">
          <div className="text-sm font-medium mb-3">Severity distribution</div>
          <SeverityBar rows={data.by_severity} />
        </div>
        <div className="grid md:grid-cols-3 gap-4">
          <MiniTable title="By severity" col="Severity" rows={data.by_severity} colorSeverity />
          <MiniTable title="By status" col="Status" rows={data.by_status} />
          <MiniTable title="By category" col="Category" rows={data.by_category} />
        </div>
        {data.qa_flags > 0 && (
          <div className="mt-4 rounded-xl border border-danger/50 bg-danger/10 text-sm px-4 py-3">
            {data.qa_flags} finding(s) carry verification flags (unverified or fabricated evidence, CVSS/severity or
            reviewer disagreement, or prompt injection) — review before reporting.
          </div>
        )}
      </section>

      <section>
        <SectionHeading>Risk priorities</SectionHeading>
        <p className="text-muted text-sm mb-4">
          Risk-based prioritization — CVSS blended with EPSS exploit probability, CISA KEV, and environment. Distinct
          from raw severity.
        </p>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4 stagger">
          <Metric label="Urgent" value={data.risk_priorities.Urgent ?? 0} accent="danger" />
          <Metric label="High" value={data.risk_priorities.High ?? 0} accent="warn" />
          <Metric label="Moderate" value={data.risk_priorities.Moderate ?? 0} accent="accent" />
          <Metric label="Low" value={data.risk_priorities.Low ?? 0} />
        </div>
        <div className="grid lg:grid-cols-2 gap-4">
          <Panel
            title="OWASP Top 10:2025 coverage"
            subtitle="Indicative mapping. Findings with no reliable signal stay unmapped rather than being guessed."
          >
            <BarList
              rows={data.owasp_coverage}
              emphasise={(label) => label !== "Unmapped (assign manually)"}
            />
          </Panel>
          <MiniTable title="Coverage detail" col="OWASP 2025 category" rows={data.owasp_coverage} countLabel="Findings" />
        </div>
      </section>

      <section>
        <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
          <h2 className="term-h text-muted">Usage</h2>
          <div className="flex items-center gap-1">
            {([["1h", "1H"], ["24h", "24H"], ["7d", "7D"], ["30d", "30D"], ["all", "ALL"]] as const).map(
              ([key, label]) => (
                <button
                  key={key}
                  onClick={() => setUsageWindow(key)}
                  aria-pressed={usageWindow === key}
                  className={`rounded-lg border px-2 py-1 text-[11px] tracking-widest transition-all ${
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
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4 stagger">
          <Metric label="Total LLM calls" value={u.calls} />
          <Metric label="Total tokens" value={u.total_tokens.toLocaleString()} />
          <Metric label="Prompt tokens" value={u.prompt_tokens.toLocaleString()} />
          <Metric label="Completion tokens" value={u.completion_tokens.toLocaleString()} />
        </div>
        {u.by_model && u.by_model.length > 0 && (
          <div className="card overflow-x-auto p-0">
            <table className="w-full text-sm">
              <thead className="text-left text-muted border-b border-border">
                <tr>
                  <th className="p-3 font-medium">Model</th>
                  <th className="font-medium">Calls</th>
                  <th className="p-3 font-medium text-right">Total tokens</th>
                </tr>
              </thead>
              <tbody>
                {u.by_model.map((m, i) => (
                  <tr key={i} className="border-b border-border/50">
                    <td className="p-3">{m.model || "-"}</td>
                    <td>{m.calls}</td>
                    <td className="p-3 text-right">{m.total_tokens.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Metric({ label, value, accent }: { label: string; value: number | string; accent?: Accent }) {
  const color =
    accent === "danger" ? "text-danger" : accent === "warn" ? "text-warn" : accent === "accent" ? "text-accent" : "";
  return (
    <div className="card card-hover">
      <div className="text-muted text-xs uppercase tracking-wide">{label}</div>
      <div className={`text-2xl font-semibold mt-1 ${color}`}>{value}</div>
    </div>
  );
}

function MiniTable({
  title,
  col,
  rows,
  colorSeverity,
  countLabel = "Count",
}: {
  title: string;
  col: string;
  rows: Row[];
  colorSeverity?: boolean;
  countLabel?: string;
}) {
  return (
    <div>
      <div className="text-sm font-medium mb-2">{title}</div>
      <div className="card overflow-x-auto p-0">
        <table className="w-full text-sm">
          <thead className="text-left text-muted border-b border-border">
            <tr>
              <th className="p-3 font-medium">{col}</th>
              <th className="p-3 font-medium text-right">{countLabel}</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td className="p-3 text-muted" colSpan={2}>None</td>
              </tr>
            ) : (
              rows.map((r, i) => (
                <tr key={i} className="border-b border-border/50">
                  <td className="p-3">{colorSeverity ? <span className={sevClass(r.label)}>{r.label}</span> : r.label}</td>
                  <td className="p-3 text-right">{r.count}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
