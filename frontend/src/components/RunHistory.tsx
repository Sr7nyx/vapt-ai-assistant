"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { JobHistoryRow } from "@/lib/types";

/**
 * Recent analysis runs.
 *
 * Jobs were made durable so they would survive a restart; this is the other half
 * of that work. LLM usage was already recorded but could not be attributed to a
 * particular run, so there was no way to see what an analysis actually cost.
 */

function duration(row: JobHistoryRow): string {
  if (!row.finished_at) return "";
  const start = new Date(row.created_at).getTime();
  const end = new Date(row.finished_at).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return "";
  const secs = Math.round((end - start) / 1000);
  return secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

function when(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

export default function RunHistory() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [rows, setRows] = useState<JobHistoryRow[] | null>(null);

  useEffect(() => {
    if (!token) return;
    let alive = true;
    api
      .listJobs(token)
      .then((r) => alive && setRows(r))
      .catch(() => alive && setRows([]));
    return () => {
      alive = false;
    };
  }, [token]);

  if (!rows) return <p className="text-sm text-muted">Loading…</p>;
  if (rows.length === 0) {
    return (
      <p className="measure text-sm text-muted">
        No runs recorded yet. Analyses and scan triage appear here with what each one cost.
      </p>
    );
  }

  const totalTokens = rows.reduce((sum, r) => sum + (r.total_tokens || 0), 0);

  return (
    <div className="grid gap-4">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-muted text-left border-b border-border">
            <th className="font-normal text-[10px] tracking-widest pb-1.5">WHEN</th>
            <th className="font-normal text-[10px] tracking-widest pb-1.5">KIND</th>
            <th className="font-normal text-[10px] tracking-widest pb-1.5">OUTCOME</th>
            <th className="font-normal text-[10px] tracking-widest pb-1.5 text-right">FINDINGS</th>
            <th className="font-normal text-[10px] tracking-widest pb-1.5 text-right">TOKENS</th>
            <th className="font-normal text-[10px] tracking-widest pb-1.5 text-right">TOOK</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const failed = r.status === "error";
            return (
              <tr key={r.id} className="border-b border-border/40 last:border-0">
                <td className="py-1.5 pr-3 whitespace-nowrap">{when(r.created_at)}</td>
                <td className="py-1.5 pr-3 text-muted">{r.kind}</td>
                <td className="py-1.5 pr-3">
                  {failed ? (
                    // The reason is the useful part, not the word "error".
                    <span className="text-danger" title={r.error || ""}>
                      failed
                    </span>
                  ) : r.status === "running" ? (
                    <span className="text-highlight">running</span>
                  ) : (
                    <span className="text-accent">done</span>
                  )}
                </td>
                <td className="py-1.5 text-right tabular-nums">{r.finding_count || ""}</td>
                <td className="py-1.5 text-right tabular-nums text-muted">
                  {r.total_tokens ? r.total_tokens.toLocaleString() : ""}
                </td>
                <td className="py-1.5 text-right tabular-nums text-muted">{duration(r)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <p className="text-xs text-muted">
        {rows.length} run{rows.length === 1 ? "" : "s"}, {totalTokens.toLocaleString()} tokens.
        A run marked failed after a deploy was interrupted by the restart, not by the analysis.
      </p>
    </div>
  );
}
