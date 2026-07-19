"use client";
import { useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useJob } from "@/hooks/useJob";
import { useProject } from "@/lib/ProjectContext";
import { getApiKey, getActiveJob, setActiveJob, buildLaneConfig } from "@/lib/prefs";
import { useToast } from "@/components/Toast";
import { Spinner } from "@/components/Loading";
import JobProgress from "@/components/JobProgress";
import { verdictOf } from "@/components/Severity";

type Candidate = Record<string, unknown> & {
  severity?: string;
  title?: string;
  source?: string;
  cwe?: string;
  noise?: boolean;
  affected_url?: string;
  affected_host?: string;
  _risk?: string;
  additional_remarks?: string;
};

export default function ImportPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const { notify } = useToast();
  const [files, setFiles] = useState<FileList | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [summary, setSummary] = useState<Record<string, number> | null>(null);
  const [excludeNoise, setExcludeNoise] = useState(true);
  const [hideFp, setHideFp] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [parsing, setParsing] = useState(false);
  const [committing, setCommitting] = useState(false);
  const handled = useRef<string | null>(null);
  const job = useJob(token, jobId);

  useEffect(() => {
    const id = getActiveJob("triage");
    if (id) setJobId(id);
  }, []);

  useEffect(() => {
    if (!job?.done || !jobId || handled.current === jobId) return;
    handled.current = jobId;
    if (job.status === "done") {
      const r = Array.isArray(job.result) ? (job.result as Candidate[]) : [];
      const flagged = r.filter((c) => verdictOf(c.additional_remarks).toLowerCase() === "likely false positive").length;
      notify(`Triage complete — ${flagged} likely false positive(s) flagged`, "success");
    } else {
      notify(`Triage failed: ${job.error || "unknown error"}`, "error");
    }
    setActiveJob("triage", "");
  }, [job, jobId, notify]);

  const parse = async () => {
    setJobId(null);
    handled.current = null;
    if (!files || files.length === 0) return;
    setParsing(true);
    try {
      const r = await api.scanParse(token, files);
      setCandidates(r.candidates || []);
      setSummary(r.summary || null);
      notify(`Parsed ${r.summary?.total ?? 0} candidate(s)`, "success");
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setParsing(false);
    }
  };

  const triage = async () => {
    if (candidates.length === 0) return;
    try {
      const { job_id } = await api.scanTriage(token, { candidates, api_key: getApiKey() || undefined, lane_config: buildLaneConfig() });
      handled.current = null;
      setActiveJob("triage", job_id);
      setJobId(job_id);
    } catch (e) {
      notify((e as Error).message, "error");
    }
  };

  const effective: Candidate[] =
    job?.done && job.status === "done" && Array.isArray(job.result) ? (job.result as Candidate[]) : candidates;

  const shown = effective.filter(
    (c) =>
      (!excludeNoise || !c.noise) &&
      (!hideFp || verdictOf(c.additional_remarks).toLowerCase() !== "likely false positive")
  );

  const commit = async () => {
    if (!projectId) {
      notify("Select a project first (Projects page).", "error");
      return;
    }
    setCommitting(true);
    try {
      const r = await api.commitCandidates(token, projectId, shown);
      notify(`Committed ${r.committed}, skipped ${r.skipped} already present`, "success");
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setCommitting(false);
    }
  };

  const triaging = !!job && !job.done;

  return (
    <div className="animate-in">
      <h1 className="text-2xl font-semibold mb-6">Import scan</h1>

      <div className="card grid gap-3 mb-4">
        <input type="file" multiple accept=".xml,.nessus,.json,.csv" className="text-sm" onChange={(e) => setFiles(e.target.files)} />
        <div>
          <button className="btn" onClick={parse} disabled={parsing}>
            {parsing ? (
              <span className="flex items-center gap-2">
                <Spinner /> Parsing
              </span>
            ) : (
              "Parse files"
            )}
          </button>
        </div>
      </div>

      {(summary || effective.length > 0) && (
        <>
          {summary && (
            <div className="grid grid-cols-3 gap-4 mb-4">
              <Stat label="Candidates" value={summary.total ?? 0} />
              <Stat label="Actionable" value={summary.actionable ?? 0} />
              <Stat label="Informational" value={summary.noise ?? 0} />
            </div>
          )}

          <div className="flex flex-wrap gap-4 items-center mb-3 text-sm">
            <label className="flex gap-2 items-center">
              <input type="checkbox" checked={excludeNoise} onChange={(e) => setExcludeNoise(e.target.checked)} /> Exclude noise
            </label>
            <label className="flex gap-2 items-center">
              <input type="checkbox" checked={hideFp} onChange={(e) => setHideFp(e.target.checked)} /> Hide likely FPs
            </label>
            <button className="btn-sm" onClick={triage} disabled={triaging}>
              {triaging ? "Triaging…" : "Run AI triage"}
            </button>
            <button className="btn-sm" onClick={commit} disabled={committing}>
              {committing ? "Committing…" : `Commit ${shown.length} to project`}
            </button>
          </div>

          <JobProgress job={job} />

          <div className="card overflow-x-auto p-0">
            <table className="w-full text-sm">
              <thead className="text-left text-muted border-b border-border">
                <tr>
                  <th className="p-3 font-medium">Source</th>
                  <th className="font-medium">Severity</th>
                  <th className="font-medium">Risk</th>
                  <th className="font-medium">Triage</th>
                  <th className="font-medium">Title</th>
                  <th className="font-medium">Asset</th>
                  <th className="font-medium">CWE</th>
                </tr>
              </thead>
              <tbody>
                {shown.slice(0, 300).map((c, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-white/5 transition-colors">
                    <td className="p-3">{c.source}</td>
                    <td>{c.severity}</td>
                    <td>{c._risk}</td>
                    <td className="text-muted">{verdictOf(c.additional_remarks) || "-"}</td>
                    <td className="max-w-xs truncate">{c.title}</td>
                    <td className="max-w-xs truncate">{c.affected_url || c.affected_host}</td>
                    <td>{c.cwe}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="card">
      <div className="text-muted text-sm">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
    </div>
  );
}
