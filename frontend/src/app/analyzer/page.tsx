"use client";
import { useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useJob } from "@/hooks/useJob";
import { useProject } from "@/lib/ProjectContext";
import { getApiKey } from "@/lib/prefs";
import JobProgress from "@/components/JobProgress";
import { sevClass } from "@/components/Severity";

const TYPES = [
  "General VAPT Analysis",
  "Burp Suite Finding",
  "Nessus Finding",
  "Nmap Result",
  "Source Code Review",
  "Cloud Misconfiguration",
];

export default function AnalyzerPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const [type, setType] = useState(TYPES[0]);
  const [input, setInput] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const job = useJob(token, jobId);

  const findings = job?.done && job.status === "done" && Array.isArray(job.result) ? (job.result as Record<string, unknown>[]) : [];

  const run = async () => {
    setMsg("");
    if (!input.trim()) return;
    try {
      const { job_id } = await api.analyze(token, { analysis_type: type, raw_input: input, api_key: getApiKey() || undefined });
      setJobId(job_id);
    } catch (e) {
      setMsg((e as Error).message);
    }
  };

  const commit = async () => {
    if (!projectId) {
      setMsg("Select a project first (Projects page).");
      return;
    }
    let n = 0;
    for (const f of findings) {
      await api.createFinding(token, projectId, f);
      n++;
    }
    setMsg(`Committed ${n} finding(s) to the selected project.`);
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Analyzer</h1>
      <div className="card grid gap-3 mb-4">
        <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
          {TYPES.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        <textarea
          className="input min-h-48 font-mono text-xs"
          placeholder="Paste HTTP requests/responses, scanner output, logs, source code…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <div>
          <button className="btn" onClick={run} disabled={!!job && !job.done}>Analyze</button>
        </div>
      </div>

      <JobProgress job={job} />
      {msg && <p className="text-accent text-sm mb-3">{msg}</p>}
      {job?.status === "error" && <p className="text-danger text-sm mb-3">Error: {job.error}</p>}

      {findings.length > 0 && (
        <div className="grid gap-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">{findings.length} finding(s)</h2>
            <button className="btn-sm" onClick={commit}>Commit to project</button>
          </div>
          {findings.map((f, i) => (
            <div key={i} className="card">
              <div className="flex items-center gap-2">
                <span className={sevClass(f.severity as string)}>{f.severity as string}</span>
                <span className="font-medium">{f.title as string}</span>
              </div>
              {typeof f.cvss === "string" && f.cvss && <div className="text-xs text-muted mt-1">{f.cvss}</div>}
              {typeof f.description === "string" && f.description && (
                <p className="text-sm text-muted mt-2 line-clamp-3">{f.description}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
