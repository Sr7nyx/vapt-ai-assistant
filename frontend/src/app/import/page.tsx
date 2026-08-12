"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { invalidate } from "@/lib/cache";
import { useJob } from "@/hooks/useJob";
import { useProject } from "@/lib/ProjectContext";
import { getApiKey, getActiveJob, setActiveJob, buildLaneConfig } from "@/lib/prefs";
import { useToast } from "@/components/Toast";
import { Spinner } from "@/components/Loading";
import JobLog from "@/components/JobLog";
import JobConsole from "@/components/JobConsole";
import { DemoQuotaBanner, DemoLimitModal, isDemoLimit } from "@/components/DemoQuota";
import LaneStatus from "@/components/LaneStatus";
import { verdictOf, sevClass } from "@/components/Severity";
import { VerdictBadge, VerdictChip, ReviewFlag } from "@/components/ReviewPanel";
import { useSelection } from "@/hooks/useSelection";
import { MasterCheckbox, RowCheckbox, SelectionBar } from "@/components/SelectionBar";
import { Section, Figure } from "@/components/Terminal";
import { Project, ReviewSummary, VerdictResolution, ScanDelta, AbsentFinding } from "@/lib/types";

// Kept in step with the analyzer: an imported finding and an extracted one land in
// the same table, so they should get the same defaults.
const CATEGORIES = ["Web Application/API Vulnerability", "Network Security", "Mobile Application Vulnerability", "Source Code Review"];
const ENVIRONMENTS = ["STG", "PROD", "DEV", "UAT", "LOCAL", "Unknown"];
const STATUSES = ["Need Review", "Draft", "Confirmed", "False Positive", "Accepted Risk", "Fixed", "Retest Passed", "Retest Failed"];

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
  category?: string;
  environment?: string;
  status?: string;
  _review?: unknown;
  _verdict?: unknown;
  _delta?: unknown;
};

export default function ImportPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId, setProjectId } = useProject();
  const { notify } = useToast();
  const [projects, setProjects] = useState<Project[]>([]);
  const [category, setCategory] = useState(CATEGORIES[0]);
  const [environment, setEnvironment] = useState(ENVIRONMENTS[0]);
  const [status, setStatus] = useState(STATUSES[0]);
  const [files, setFiles] = useState<FileList | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [summary, setSummary] = useState<Record<string, number> | null>(null);
  const [delta, setDelta] = useState<ScanDelta | null>(null);
  const [absent, setAbsent] = useState<AbsentFinding[]>([]);
  const [excludeNoise, setExcludeNoise] = useState(true);
  const [hideFp, setHideFp] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [parsing, setParsing] = useState(false);
  const [committing, setCommitting] = useState(false);
  const [limitMsg, setLimitMsg] = useState<string | null>(null);
  const [quotaTick, setQuotaTick] = useState(0);
  const handled = useRef<string | null>(null);
  const job = useJob(token, jobId);
  const running = !!job && !job.done;

  useEffect(() => {
    const id = getActiveJob("triage");
    if (id) setJobId(id);
  }, []);

  useEffect(() => {
    if (!token) return;
    api.listProjects(token).then(setProjects).catch(() => {});
  }, [token]);

  // A scanner candidate arrives with no category, environment or status. These
  // defaults fill only what is blank, so anything triage or the parser already
  // determined is preserved.
  const applyDefaults = useCallback(
    (c: Candidate): Candidate => ({
      ...c,
      category: (c.category as string) || category,
      environment: (c.environment as string) || environment,
      status: (c.status as string) || status,
    }),
    [category, environment, status]
  );

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
    setQuotaTick((n) => n + 1);
    setActiveJob("triage", "");
  }, [job, jobId, notify]);

  const parse = async () => {
    setJobId(null);
    handled.current = null;
    if (!files || files.length === 0) return;
    setParsing(true);
    try {
      const r = await api.scanParse(token, files, projectId);
      setCandidates(r.candidates || []);
      setSummary(r.summary || null);
      setDelta((r.delta as ScanDelta) || null);
      setAbsent((r.absent as AbsentFinding[]) || []);
      const d = r.delta as ScanDelta | null;
      notify(
        d
          ? `Parsed ${r.summary?.total ?? 0}: ${d.new} new, ${d.regressed} regressed`
          : `Parsed ${r.summary?.total ?? 0} candidate(s)`,
        "success"
      );
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
      if (isDemoLimit(e)) setLimitMsg((e as Error).message);
      else notify((e as Error).message, "error");
    }
  };

  const effective: Candidate[] =
    job?.done && job.status === "done" && Array.isArray(job.result) ? (job.result as Candidate[]) : candidates;

  // Rows are keyed by their index in the UNFILTERED list, so toggling a filter
  // does not reassign keys to different candidates mid-selection.
  const indexed = effective.map((c, i) => ({ c, i }));
  const shown = indexed.filter(
    ({ c }) =>
      (!excludeNoise || !c.noise) &&
      (!hideFp || verdictOf(c.additional_remarks).toLowerCase() !== "likely false positive")
  );

  const sel = useSelection(shown, (r) => r.i);

  const commit = async (subset?: Candidate[]) => {
    if (!projectId) {
      notify("Select a project above first.", "error");
      return;
    }
    const batch = (subset && subset.length ? subset : shown.map((r) => r.c)).map(applyDefaults);
    if (batch.length === 0) {
      notify("Nothing to commit.", "error");
      return;
    }
    setCommitting(true);
    try {
      const r = await api.commitCandidates(token, projectId, batch);
      invalidate("overview");
      notify(`Committed ${r.committed}, skipped ${r.skipped} already present`, "success");
      sel.clear();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setCommitting(false);
    }
  };

  const triaging = !!job && !job.done;

  return (
    <div className="animate-in">

      <LaneStatus activeLane={running ? "REVIEW" : null} />
      <DemoQuotaBanner refreshKey={quotaTick} />

      <Section title="Source">
        <div className="grid gap-4">
        {/* Same band as the analyzer: configuration compressed to one row so the
            file input and the candidate table are what the page leads with. */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-x-3 gap-y-3">
          <label className="field-inline col-span-2 lg:col-span-1">
            <span>PROJECT</span>
            <select
              className="input"
              value={projectId ?? ""}
              onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : null)}
            >
              <option value="">none selected</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                  {p.client ? ` (${p.client})` : ""}
                </option>
              ))}
            </select>
          </label>
          <label className="field-inline col-span-2">
            <span>DEFAULT CATEGORY</span>
            <select className="input" value={category} onChange={(e) => setCategory(e.target.value)}>
              {CATEGORIES.map((c) => (<option key={c} value={c}>{c}</option>))}
            </select>
          </label>
          <label className="field-inline">
            <span>ENVIRONMENT</span>
            <select className="input" value={environment} onChange={(e) => setEnvironment(e.target.value)}>
              {ENVIRONMENTS.map((c) => (<option key={c} value={c}>{c}</option>))}
            </select>
          </label>
          <label className="field-inline">
            <span>STATUS</span>
            <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUSES.map((c) => (<option key={c} value={c}>{c}</option>))}
            </select>
          </label>
        </div>

        <Field label="Scanner files">
          <input type="file" multiple accept=".xml,.nessus,.json,.csv" className="text-sm" onChange={(e) => setFiles(e.target.files)} />
        </Field>
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
      </Section>

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
            <button className="btn-sm" onClick={() => commit()} disabled={committing}>
              {committing ? "Committing…" : `Commit all ${shown.length}`}
            </button>
          </div>

          {delta && (
            <Section
              title="Since the last scan"
              note="Compared against findings already in this project."
            >
              <div className="grid gap-4">
                <div className="flex flex-wrap gap-x-10 gap-y-3">
                  <Figure label="New" value={delta.new} tone={delta.new ? "accent" : undefined} />
                  <Figure
                    label="Regressed"
                    value={delta.regressed}
                    tone={delta.regressed ? "danger" : undefined}
                  />
                  <Figure label="Re-rated" value={delta.reappraised} tone={delta.reappraised ? "warn" : undefined} />
                  <Figure label="Unchanged" value={delta.unchanged} />
                </div>

                {delta.regressed > 0 && (
                  <p className="measure border-l-2 border-danger/70 pl-3 py-0.5 text-sm text-danger">
                    {delta.regressed} finding{delta.regressed === 1 ? " was" : "s were"} previously
                    closed and {delta.regressed === 1 ? "has" : "have"} come back. Regressions matter
                    more than new findings: something that was fixed no longer is.
                  </p>
                )}

                {absent.length > 0 && (
                  <div>
                    <p className="measure text-xs text-muted mb-2">
                      {absent.length} open finding{absent.length === 1 ? "" : "s"} did not appear in
                      this scan. They are not marked fixed automatically &mdash; a scan that did not
                      cover something is not evidence it is gone.
                    </p>
                    <ul className="grid gap-1">
                      {absent.slice(0, 8).map((a) => (
                        <li key={a.id} className="flex items-center gap-2 text-xs">
                          <span className={sevClass(a.severity)}>[{a.severity}]</span>
                          <span className="truncate">{a.title}</span>
                          <span className="text-muted shrink-0">{a.status}</span>
                        </li>
                      ))}
                      {absent.length > 8 && (
                        <li className="text-xs text-muted">+{absent.length - 8} more</li>
                      )}
                    </ul>
                  </div>
                )}
              </div>
            </Section>
          )}

          <SelectionBar count={sel.count} noun="candidate" onClear={sel.clear}>
            <button
              className="btn-sm"
              onClick={() => commit(sel.selectedItems.map((r) => r.c))}
              disabled={committing}
            >
              {committing ? "Committing…" : `Commit ${sel.count} selected`}
            </button>
          </SelectionBar>

          {/* Kept below for reference once the console is dismissed. */}
          <JobLog job={job} />

          <div className="card overflow-x-auto p-0">
            <table className="w-full text-sm">
              <thead className="text-left text-muted border-b border-border">
                <tr>
                  <th className="p-3 w-8">
                    <MasterCheckbox
                      allSelected={sel.allSelected}
                      someSelected={sel.someSelected}
                      onToggle={sel.toggleAll}
                      label=""
                    />
                  </th>
                  <th className="font-medium">Source</th>
                  <th className="font-medium">Severity</th>
                  <th className="font-medium">Risk</th>
                  <th className="font-medium">Verdict</th>
                  <th className="font-medium">Title</th>
                  <th className="font-medium">Asset</th>
                  <th className="font-medium">CWE</th>
                </tr>
              </thead>
              <tbody>
                {shown.slice(0, 300).map(({ c, i }) => (
                  <tr
                    key={i}
                    className={`border-b border-border/50 transition-colors ${
                      sel.isSelected(i) ? "bg-accent/5" : "hover:bg-white/5"
                    }`}
                  >
                    <td className="p-3 align-top">
                      <RowCheckbox
                        checked={sel.isSelected(i)}
                        onToggle={() => sel.toggle(i)}
                        label={`Select ${String(c.title || "candidate")}`}
                      />
                    </td>
                    <td className="text-muted text-xs">{c.source}</td>
                    <td><span className={sevClass(String(c.severity || ""))}>{String(c.severity || "")}</span></td>
                    <td className="text-xs">{c._risk}</td>
                    <td>
                      {/* Triaged candidates carry the same assessment the findings
                          table shows, so the two views agree. */}
                      <span className="flex flex-wrap gap-1">
                        {(c._delta as { state?: string } | undefined)?.state === "regressed" && (
                          <span className="chip border-danger/70 text-danger">regressed</span>
                        )}
                        {(c._delta as { state?: string } | undefined)?.state === "new" && (
                          <span className="chip border-accent/60 text-accent">new</span>
                        )}
                        <VerdictBadge verdict={c._verdict as VerdictResolution | undefined} />
                        <VerdictChip review={c._review as ReviewSummary | undefined} />
                        <ReviewFlag review={c._review as ReviewSummary | undefined} />
                        {!c._verdict && !c._review && (
                          <span className="text-muted text-xs">{verdictOf(c.additional_remarks) || "-"}</span>
                        )}
                      </span>
                    </td>
                    <td className="max-w-xs truncate">{c.title}</td>
                    <td className="max-w-xs truncate text-accent text-xs">{c.affected_url || c.affected_host}</td>
                    <td className="text-xs">{c.cwe}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {limitMsg && <DemoLimitModal message={limitMsg} onClose={() => setLimitMsg(null)} />}

      {/* At the component root: an overlay nested in a conditional branch
          unmounts when that branch does, which would take the panel down mid-run. */}
      <JobConsole
        job={job}
        title="Triage"
        evidence={candidates.map((c) => `${c.severity ?? ""}  ${c.title ?? ""}`).join("\n")}
        resultCount={effective.length}
      />
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

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="card">
      <div className="text-muted text-sm">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
    </div>
  );
}
