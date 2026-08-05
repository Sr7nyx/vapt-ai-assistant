"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { invalidate } from "@/lib/cache";
import { useJob } from "@/hooks/useJob";
import { useProject } from "@/lib/ProjectContext";
import { getApiKey, getActiveJob, setActiveJob, buildLaneConfig } from "@/lib/prefs";
import { Project } from "@/lib/types";
import { useToast } from "@/components/Toast";
import { Spinner } from "@/components/Loading";
import JobProgress from "@/components/JobProgress";
import JobLog from "@/components/JobLog";
import { DemoQuotaBanner, DemoLimitModal, isDemoLimit } from "@/components/DemoQuota";
import LaneStatus from "@/components/LaneStatus";
import ScanOverlay from "@/components/ScanOverlay";
import { useSelection } from "@/hooks/useSelection";
import { MasterCheckbox, RowCheckbox, SelectionBar } from "@/components/SelectionBar";
import FindingEditor from "@/components/FindingEditor";
import { sevClass } from "@/components/Severity";
import ReviewPanel, { VerdictBadge, VerdictChip, ReviewFlag, VerifiedChip } from "@/components/ReviewPanel";
import { Section } from "@/components/Terminal";
import { ReviewSummary, VerdictResolution, Verification } from "@/lib/types";

const ANALYSIS_TYPES = [
  "OWASP Top 10 Analysis",
  "API Security Analysis",
  "Security Headers Analysis",
  "Sensitive Information Disclosure Analysis",
  "Access Control Analysis",
  "Vulnerability Report Generation",
  "False Positive Check",
  "Remediation Advice",
];
const CATEGORIES = ["Web Application/API Vulnerability", "Network Security", "Mobile Application Vulnerability", "Source Code Review"];
const ENVIRONMENTS = ["STG", "PROD", "DEV", "UAT", "LOCAL", "Unknown"];
const STATUSES = ["Need Review", "Draft", "Confirmed", "False Positive", "Accepted Risk", "Fixed", "Retest Passed", "Retest Failed"];
const TEXT_EXT = ["txt", "log", "json", "har", "csv", "xml", "yaml", "yml", "md"];
const PER_FILE_CAP = 15000;

type F = Record<string, unknown>;
type Attachment = { name: string; content: string; skipped: boolean };

export default function AnalyzerPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId, setProjectId } = useProject();
  const { notify } = useToast();

  const [projects, setProjects] = useState<Project[]>([]);
  const [type, setType] = useState(ANALYSIS_TYPES[0]);
  const [category, setCategory] = useState(CATEGORIES[0]);
  const [environment, setEnvironment] = useState(ENVIRONMENTS[0]);
  const [status, setStatus] = useState(STATUSES[0]);
  const [input, setInput] = useState("");
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [results, setResults] = useState<F[]>([]);
  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const [committing, setCommitting] = useState(false);
  const [limitMsg, setLimitMsg] = useState<string | null>(null);
  const [quotaTick, setQuotaTick] = useState(0);
  // Result of the free server-side pre-check. Held as a hint only; the authoritative
  // refusal comes from /analyze, so the two can never disagree in a way that lets
  // junk through.
  const [guard, setGuard] = useState<{ ok: boolean; reason: string } | null>(null);
  const handled = useRef<string | null>(null);
  const job = useJob(token, jobId);

  useEffect(() => {
    if (token) api.listProjects(token).then(setProjects).catch(() => {});
  }, [token]);

  // Reconnect to a still-running or just-finished analysis after navigating back.
  useEffect(() => {
    const id = getActiveJob("analyze");
    if (id) setJobId(id);
  }, []);

  const applyDefaults = useCallback(
    (f: F): F => ({
      ...f,
      category: (f.category as string) || category,
      environment: (f.environment as string) || environment,
      status: (f.status as string) || status,
    }),
    [category, environment, status]
  );

  useEffect(() => {
    if (!job?.done || !jobId || handled.current === jobId) return;
    handled.current = jobId;
    if (job.status === "done") {
      const r = (Array.isArray(job.result) ? (job.result as F[]) : []).map(applyDefaults);
      setResults(r);
      notify(`Analysis complete — ${r.length} finding(s)`, "success");
    } else {
      notify(`Analysis failed: ${job.error || "unknown error"}`, "error");
    }
    setQuotaTick((n) => n + 1);
    setActiveJob("analyze", "");
  }, [job, jobId, notify, applyDefaults]);

  const addFiles = async (list: FileList | null) => {
    if (!list) return;
    const next: Attachment[] = [];
    for (const file of Array.from(list)) {
      const ext = (file.name.split(".").pop() || "").toLowerCase();
      if (TEXT_EXT.includes(ext)) {
        const text = await file.text();
        next.push({ name: file.name, content: text.slice(0, PER_FILE_CAP), skipped: false });
      } else {
        next.push({ name: file.name, content: "", skipped: true });
      }
    }
    setAttachments((prev) => [...prev, ...next]);
  };

  const removeAttachment = (i: number) => setAttachments((prev) => prev.filter((_, idx) => idx !== i));

  const combinedInput = () =>
    [input, ...attachments.filter((a) => !a.skipped).map((a) => `\n\n--- ${a.name} ---\n${a.content}`)].join("").trim();

  // Debounced so typing does not fire a request per keystroke. The endpoint is
  // pure pattern matching, so this costs no quota.
  useEffect(() => {
    const raw = [input, ...attachments.filter((a) => !a.skipped).map((a) => a.content)].join("\n").trim();
    if (!token || raw.length === 0) {
      setGuard(null);
      return;
    }
    let alive = true;
    const timer = setTimeout(() => {
      api
        .precheck(token, raw)
        .then((r) => alive && setGuard({ ok: r.ok, reason: r.reason }))
        .catch(() => alive && setGuard(null));
    }, 700);
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [token, input, attachments]);

  const run = async () => {
    const raw = combinedInput();
    if (!raw) {
      notify("Add some evidence or a text file first.", "error");
      return;
    }
    setResults([]);
    try {
      const { job_id } = await api.analyze(token, { analysis_type: type, raw_input: raw, api_key: getApiKey() || undefined, lane_config: buildLaneConfig() });
      handled.current = null;
      setActiveJob("analyze", job_id);
      setJobId(job_id);
    } catch (e) {
      const err = e as { status?: number; detail?: { error?: string } };
      if (isDemoLimit(e)) setLimitMsg((e as Error).message);
      else if (err.status === 422 && err.detail?.error === "not_security_evidence") {
        setGuard({ ok: false, reason: (e as Error).message });
      } else notify((e as Error).message, "error");
    }
  };

  // Extracted results have no server id yet, so position is the key. The hook
  // prunes on list change, so a fresh analysis clears the previous selection
  // rather than carrying indexes over to different findings.
  const sel = useSelection(
    results.map((f, i) => ({ f, i })),
    (r) => r.i
  );

  const commit = async (subset?: Record<string, unknown>[]) => {
    if (!projectId) {
      notify("Select a project first.", "error");
      return;
    }
    const batch = subset && subset.length ? subset : results;
    setCommitting(true);
    try {
      let n = 0;
      const failed: string[] = [];
      for (const f of batch) {
        try {
          await api.createFinding(token, projectId, applyDefaults(f));
      invalidate("overview");
          n++;
        } catch (e) {
          // One bad finding should not strand the rest of the batch.
          failed.push(String(f.title || "untitled"));
        }
      }
      if (failed.length) {
        notify(`Committed ${n}; ${failed.length} failed (${failed[0]}${failed.length > 1 ? ", …" : ""})`, "error");
      } else {
        notify(`Committed ${n} finding(s) to the project`, "success");
      }
      sel.clear();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setCommitting(false);
    }
  };

  const running = !!job && !job.done;
  const skippedCount = attachments.filter((a) => a.skipped).length;

  return (
    <div className="animate-in mx-auto w-full max-w-5xl">

      {/* Extraction runs below 0.5, the reviewer above it -- the same split the
          pipeline reports through progress. */}
      <LaneStatus
        activeLane={running ? ((job?.progress ?? 0) < 0.5 ? "MAIN" : "REVIEW") : null}
      />
      <DemoQuotaBanner refreshKey={quotaTick} />

      <Section title="Input">
        <div className="grid gap-4">
        <Field label="Project">
          <select className="input" value={projectId ?? ""} onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : null)}>
            <option value="">— no project selected —</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.client ? ` (${p.client})` : ""}
              </option>
            ))}
          </select>
        </Field>

        <Field label="Analysis type">
          <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
            {ANALYSIS_TYPES.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>

        <div className="grid md:grid-cols-3 gap-4">
          <Field label="Default category">
            <select className="input" value={category} onChange={(e) => setCategory(e.target.value)}>
              {CATEGORIES.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </Field>
          <Field label="Default environment">
            <select className="input" value={environment} onChange={(e) => setEnvironment(e.target.value)}>
              {ENVIRONMENTS.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </Field>
          <Field label="Default status">
            <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUSES.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </Field>
        </div>

        <Field label="Evidence files (optional)">
          <label className="border border-dashed border-border rounded-lg px-4 py-6 text-center text-sm text-muted hover:border-accent transition-colors cursor-pointer block">
            <input
              type="file"
              multiple
              accept=".txt,.log,.json,.har,.csv,.xml,.yaml,.yml,.md"
              className="hidden"
              onChange={(e) => {
                addFiles(e.target.files);
                e.target.value = "";
              }}
            />
            Click to attach text evidence — TXT, LOG, JSON, HAR, CSV, XML, YAML, MD (up to {PER_FILE_CAP.toLocaleString()} chars each)
          </label>
          {attachments.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {attachments.map((a, i) => (
                <span key={i} className={`chip flex items-center gap-2 ${a.skipped ? "text-warn" : ""}`}>
                  {a.name}
                  {a.skipped && " (not text)"}
                  <button className="hover:text-danger" onClick={() => removeAttachment(i)} aria-label="Remove">
                    &#215;
                  </button>
                </span>
              ))}
            </div>
          )}
          {skippedCount > 0 && (
            <p className="text-xs text-warn mt-1">
              {skippedCount} non-text file(s) attached but not sent — the analysis pipeline is text-only.
            </p>
          )}
        </Field>

        <Field label="Evidence / raw input">
          {/* The overlay sits on the evidence itself, because that is what the
              pipeline is reading. A spinner elsewhere would say only "wait". */}
          <div className="relative">
            <textarea
              className="input min-h-48 font-mono text-xs"
              placeholder="Paste HTTP requests/responses, scanner output, logs, source code…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              readOnly={running}
            />
            <ScanOverlay active={running} progress={job?.progress ?? 0} done={!!job?.done} />
          </div>
          {guard && !guard.ok && (
            <p className="text-xs text-warn mt-2 border border-warn/40 rounded-lg px-3 py-2">
              {guard.reason}
            </p>
          )}
          <div className="flex justify-between text-xs text-muted mt-1">
            <span>{input.length.toLocaleString()} chars typed</span>
            {input && (
              <button className="hover:text-text" onClick={() => setInput("")}>
                Clear
              </button>
            )}
          </div>
        </Field>

        <div>
          <button className="btn" onClick={run} disabled={running || (guard ? !guard.ok : false)}>
            {running ? (
              <span className="flex items-center gap-2">
                <Spinner />
                {(job?.progress ?? 0) < 0.4
                  ? "Extracting"
                  : (job?.progress ?? 0) < 0.5
                  ? "Verifying"
                  : "Reviewing"}
              </span>
            ) : (
              "Run analysis"
            )}
          </button>
        </div>
        </div>
      </Section>

      <JobProgress job={job} />
      <JobLog job={job} />

      {results.length > 0 && (
        <div className="grid gap-3">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-4">
              <MasterCheckbox
                allSelected={sel.allSelected}
                someSelected={sel.someSelected}
                onToggle={sel.toggleAll}
                label="SELECT ALL"
              />
              <h2 className="text-[11px] tracking-widest text-muted"><span className="text-accent">&gt;</span> {results.length} FINDING(S)</h2>
            </div>
            <button className="btn-sm" onClick={() => commit()} disabled={committing}>
              {committing ? "Committing…" : "Commit all"}
            </button>
          </div>

          <SelectionBar count={sel.count} noun="finding" onClear={sel.clear}>
            <button
              className="btn-sm"
              onClick={() => commit(sel.selectedItems.map((r) => r.f))}
              disabled={committing}
            >
              {committing ? "Committing…" : `Commit ${sel.count} selected`}
            </button>
          </SelectionBar>
          {results.map((f, i) => (
            <div key={i} className="card card-hover grid gap-3">
              <div className="flex items-start justify-between gap-3">
                <RowCheckbox
                  checked={sel.isSelected(i)}
                  onToggle={() => sel.toggle(i)}
                  label={`Select ${String(f.title || "finding")}`}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={sevClass(f.severity as string)}>{f.severity as string}</span>
                    <span className="font-medium">{f.title as string}</span>
                    <VerdictBadge verdict={f._verdict as VerdictResolution | undefined} />
                    <VerifiedChip verification={f._verification as Verification | undefined} />
                    <VerdictChip review={f._review as ReviewSummary | undefined} />
                    <ReviewFlag review={f._review as ReviewSummary | undefined} />
                  </div>
                  <div className="flex gap-1 mt-1 flex-wrap">
                    {typeof f.cwe === "string" && f.cwe && <span className="chip">{f.cwe}</span>}
                    {typeof f.category === "string" && f.category && <span className="chip">{f.category}</span>}
                    {typeof f.status === "string" && f.status && <span className="chip">{f.status}</span>}
                  </div>
                  {typeof f.description === "string" && f.description && (
                    <p className="text-sm text-muted mt-2 line-clamp-3">{f.description}</p>
                  )}
                </div>
                <button className="btn-sm shrink-0" onClick={() => setEditingIdx(i)}>
                  Edit
                </button>
              </div>
              <ReviewPanel review={f._review as ReviewSummary | undefined} verdict={f._verdict as VerdictResolution | undefined} verification={f._verification as Verification | undefined} />
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

      {limitMsg && <DemoLimitModal message={limitMsg} onClose={() => setLimitMsg(null)} />}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="grid gap-1.5">
      <span className="text-sm text-muted">{label}</span>
      {children}
    </label>
  );
}
