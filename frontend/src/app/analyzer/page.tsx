"use client";
import { useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useJob } from "@/hooks/useJob";
import { useProject } from "@/lib/ProjectContext";
import { getApiKey } from "@/lib/prefs";
import { useToast } from "@/components/Toast";
import { Spinner } from "@/components/Loading";
import JobProgress from "@/components/JobProgress";
import FindingEditor from "@/components/FindingEditor";
import { sevClass } from "@/components/Severity";

const TYPES = [
  "General VAPT Analysis",
  "Burp Suite Finding",
  "Nessus Finding",
  "Nmap Result",
  "Source Code Review",
  "Cloud Misconfiguration",
];

type F = Record<string, unknown>;

export default function AnalyzerPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const { notify } = useToast();
  const [type, setType] = useState(TYPES[0]);
  const [input, setInput] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [results, setResults] = useState<F[]>([]);
  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const [committing, setCommitting] = useState(false);
  const handled = useRef<string | null>(null);
  const job = useJob(token, jobId);

  // Fire a toast + capture editable results exactly once per completed job.
  useEffect(() => {
    if (!job?.done || !jobId || handled.current === jobId) return;
    handled.current = jobId;
    if (job.status === "done") {
      const r = Array.isArray(job.result) ? (job.result as F[]) : [];
      setResults(r);
      notify(`Analysis complete — ${r.length} finding(s)`, "success");
    } else {
      notify(`Analysis failed: ${job.error || "unknown error"}`, "error");
    }
  }, [job, jobId, notify]);

  const run = async () => {
    if (!input.trim()) return;
    setResults([]);
    try {
      const { job_id } = await api.analyze(token, { analysis_type: type, raw_input: input, api_key: getApiKey() || undefined });
      handled.current = null;
      setJobId(job_id);
    } catch (e) {
      notify((e as Error).message, "error");
    }
  };

  const commit = async () => {
    if (!projectId) {
      notify("Select a project first (Projects page).", "error");
      return;
    }
    setCommitting(true);
    try {
      let n = 0;
      for (const f of results) {
        await api.createFinding(token, projectId, f);
        n++;
      }
      notify(`Committed ${n} finding(s) to the project`, "success");
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setCommitting(false);
    }
  };

  const running = !!job && !job.done;

  return (
    <div className="animate-in">
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
          <button className="btn" onClick={run} disabled={running}>
            {running ? (
              <span className="flex items-center gap-2">
                <Spinner /> Analyzing
              </span>
            ) : (
              "Analyze"
            )}
          </button>
        </div>
      </div>

      <JobProgress job={job} />

      {results.length > 0 && (
        <div className="grid gap-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">{results.length} finding(s)</h2>
            <button className="btn-sm" onClick={commit} disabled={committing}>
              {committing ? "Committing…" : "Commit to project"}
            </button>
          </div>
          {results.map((f, i) => (
            <div key={i} className="card flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className={sevClass(f.severity as string)}>{f.severity as string}</span>
                  <span className="font-medium">{f.title as string}</span>
                </div>
                {typeof f.cvss === "string" && f.cvss && <div className="text-xs text-muted mt-1">{f.cvss}</div>}
                {typeof f.description === "string" && f.description && (
                  <p className="text-sm text-muted mt-2 line-clamp-3">{f.description}</p>
                )}
              </div>
              <button className="btn-sm shrink-0" onClick={() => setEditingIdx(i)}>Edit</button>
            </div>
          ))}
        </div>
      )}

      {editingIdx !== null && (
        <FindingEditor
          finding={results[editingIdx]}
          onSave={(f) => {
            setResults((prev) => prev.map((x, i) => (i === editingIdx ? f : x)));
            setEditingIdx(null);
            notify("Finding updated", "success");
          }}
          onClose={() => setEditingIdx(null)}
        />
      )}
    </div>
  );
}
