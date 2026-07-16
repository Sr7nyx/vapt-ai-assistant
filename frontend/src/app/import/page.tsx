"use client";
import { useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useJob } from "@/hooks/useJob";
import { useProject } from "@/lib/ProjectContext";
import { getApiKey } from "@/lib/prefs";
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
};

export default function ImportPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const [files, setFiles] = useState<FileList | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [summary, setSummary] = useState<Record<string, number> | null>(null);
  const [excludeNoise, setExcludeNoise] = useState(true);
  const [hideFp, setHideFp] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const job = useJob(token, jobId);

  const parse = async () => {
    setMsg("");
    setJobId(null);
    if (!files || files.length === 0) return;
    const r = await api.scanParse(token, files);
    setCandidates(r.candidates || []);
    setSummary(r.summary || null);
  };

  const triage = async () => {
    if (candidates.length === 0) return;
    const { job_id } = await api.scanTriage(token, { candidates, api_key: getApiKey() || undefined });
    setJobId(job_id);
  };

  // After triage completes, use the returned (verdict-annotated) candidates.
  const effective: Candidate[] =
    job?.done && job.status === "done" && Array.isArray(job.result) ? (job.result as Candidate[]) : candidates;

  const shown = effective.filter(
    (c) =>
      (!excludeNoise || !c.noise) &&
      (!hideFp || verdictOf(c.additional_remarks).toLowerCase() !== "likely false positive")
  );

  const commit = async () => {
    if (!projectId) {
      setMsg("Select a project first (Projects page).");
      return;
    }
    const r = await api.commitCandidates(token, projectId, shown);
    setMsg(`Committed ${r.committed}, skipped ${r.skipped} already present.`);
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Import scan</h1>
      <div className="card grid gap-3 mb-4">
        <input type="file" multiple accept=".xml,.nessus,.json,.csv" className="text-sm" onChange={(e) => setFiles(e.target.files)} />
        <div>
          <button className="btn" onClick={parse}>Parse files</button>
        </div>
      </div>

      {summary && (
        <>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <Stat label="Candidates" value={summary.total ?? 0} />
            <Stat label="Actionable" value={summary.actionable ?? 0} />
            <Stat label="Informational" value={summary.noise ?? 0} />
          </div>

          <div className="flex flex-wrap gap-4 items-center mb-3 text-sm">
            <label className="flex gap-2 items-center">
              <input type="checkbox" checked={excludeNoise} onChange={(e) => setExcludeNoise(e.target.checked)} /> Exclude noise
            </label>
            <label className="flex gap-2 items-center">
              <input type="checkbox" checked={hideFp} onChange={(e) => setHideFp(e.target.checked)} /> Hide likely FPs
            </label>
            <button className="btn-sm" onClick={triage} disabled={!!job && !job.done}>Run AI triage</button>
            <button className="btn-sm" onClick={commit}>Commit {shown.length} to project</button>
          </div>

          <JobProgress job={job} />
          {msg && <p className="text-accent text-sm mb-3">{msg}</p>}

          <div className="overflow-auto card">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-muted">
                  <th className="p-2">Source</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Triage</th>
                  <th>Title</th>
                  <th>Asset</th>
                  <th>CWE</th>
                </tr>
              </thead>
              <tbody>
                {shown.slice(0, 300).map((c, i) => (
                  <tr key={i} className="border-t border-border">
                    <td className="p-2">{c.source}</td>
                    <td>{c.severity}</td>
                    <td>{c._risk}</td>
                    <td>{verdictOf(c.additional_remarks) || "-"}</td>
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
