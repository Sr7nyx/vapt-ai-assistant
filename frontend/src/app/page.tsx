"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { Overview } from "@/lib/types";
import { Skeleton } from "@/components/Loading";
import { sevClass } from "@/components/Severity";

type Accent = "danger" | "warn" | "accent" | undefined;
type Row = { label: string; count: number };

export default function Dashboard() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [data, setData] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    api.overview(token).then(setData).catch(() => {}).finally(() => setLoading(false));
  }, [token]);

  if (loading || !data) {
    return (
      <div className="animate-in">
        <h1 className="text-2xl font-semibold mb-6">Overview</h1>
        <Skeleton rows={6} />
      </div>
    );
  }

  const u = data.usage;

  return (
    <div className="animate-in space-y-10">
      <section>
        <h1 className="text-2xl font-semibold mb-6">Overview</h1>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 stagger">
          <Metric label="Active projects" value={data.projects} />
          <Metric label="Aggregated findings" value={data.findings} />
          <Metric label="Critical" value={data.critical} accent="danger" />
          <Metric label="High" value={data.high} accent="warn" />
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold mb-4">Findings breakdown</h2>
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
        <h2 className="text-lg font-semibold mb-1">Risk priorities</h2>
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
        <MiniTable title="OWASP Top 10:2025 coverage" col="OWASP 2025 category" rows={data.owasp_coverage} countLabel="Findings" />
      </section>

      <section>
        <h2 className="text-lg font-semibold mb-4">Usage</h2>
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
