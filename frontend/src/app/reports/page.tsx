"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { Finding } from "@/lib/types";
import { useProject } from "@/lib/ProjectContext";
import { useToast } from "@/components/Toast";
import MultiSelect from "@/components/MultiSelect";
import { useSelection } from "@/hooks/useSelection";
import { MasterCheckbox, RowCheckbox } from "@/components/SelectionBar";
import { sevClass } from "@/components/Severity";
import { Skeleton } from "@/components/Loading";
import { Section } from "@/components/Terminal";

export default function ReportsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const { notify } = useToast();
  const [exec, setExec] = useState("");
  const [method, setMethod] = useState("OWASP, PTES");
  const [busy, setBusy] = useState("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [sevF, setSevF] = useState<string[]>([]);
  const [statusF, setStatusF] = useState<string[]>([]);
  const [pick, setPick] = useState(false);

  const load = useCallback(() => {
    if (!token || !projectId) return;
    setLoading(true);
    api
      .listFindings(token, projectId)
      .then(setFindings)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [token, projectId]);
  useEffect(() => load(), [load]);

  const severities = useMemo(
    () => Array.from(new Set(findings.map((f) => String(f.severity || "")).filter(Boolean))),
    [findings]
  );
  const statuses = useMemo(
    () => Array.from(new Set(findings.map((f) => String(f.status || "")).filter(Boolean))),
    [findings]
  );

  // Filters narrow what the report covers; the checkboxes then refine that further.
  const matching = useMemo(
    () =>
      findings.filter(
        (f) =>
          (sevF.length === 0 || sevF.includes(String(f.severity || ""))) &&
          (statusF.length === 0 || statusF.includes(String(f.status || "")))
      ),
    [findings, sevF, statusF]
  );

  const sel = useSelection(matching, (f) => f.id);

  /** Nothing selected and no filter set means "the whole project", which is the
   *  common case and is sent without an explicit id list. */
  const included = sel.count > 0 ? sel.selectedItems : matching;
  const wholeProject = sel.count === 0 && sevF.length === 0 && statusF.length === 0;

  if (!projectId) {
    return (
      <div className="animate-in mx-auto w-full max-w-3xl">
        <div className="card text-muted text-sm">Select a project first.</div>
      </div>
    );
  }

  const download = async (fmt: string) => {
    if (!wholeProject && included.length === 0) {
      notify("No findings match the current selection.", "error");
      return;
    }
    setBusy(fmt);
    try {
      const { blob, filename } = await api.exportReport(token, projectId, {
        fmt,
        exec_summary: exec,
        methodology: method,
        ...(wholeProject ? {} : { finding_ids: included.map((f) => f.id) }),
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      notify(`${fmt.toUpperCase()} report downloaded`, "success");
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="animate-in mx-auto w-full max-w-3xl">

      <Section title="Narrative">
        <div className="grid gap-3">
        <textarea
          className="input min-h-32"
          placeholder="Executive summary (optional)"
          value={exec}
          onChange={(e) => setExec(e.target.value)}
        />
        <input className="input" placeholder="Methodology" value={method} onChange={(e) => setMethod(e.target.value)} />
        </div>
      </Section>

      <Section title="Scope">
        <div className="grid gap-3">
        {loading ? (
          <Skeleton rows={2} />
        ) : (
          <>
            <div className="flex flex-wrap gap-3">
              <MultiSelect placeholder="Severity" options={severities} selected={sevF} onChange={setSevF} />
              <MultiSelect placeholder="Status" options={statuses} selected={statusF} onChange={setStatusF} />
            </div>

            <div className="statstrip">
              <span className="flex items-center gap-1.5">
                <span className="text-muted">INCLUDED:</span>
                <span className="text-accent">{wholeProject ? findings.length : included.length}</span>
                <span className="text-muted">of {findings.length}</span>
              </span>
              <span className="sep">|</span>
              <span className="text-muted">
                {wholeProject
                  ? "the whole project"
                  : sel.count > 0
                  ? `${sel.count} explicitly selected`
                  : "filtered"}
              </span>
            </div>

            <button className="btn-sm w-fit" onClick={() => setPick((v) => !v)}>
              {pick ? "Hide finding list" : "Choose individual findings"}
            </button>

            {pick && (
              <div className="border border-border/60 rounded-lg pane-scroll max-h-72 overflow-y-auto">
                <div className="flex items-center gap-3 px-3 py-2 border-b border-border/60 sticky top-0 bg-surface">
                  <MasterCheckbox
                    allSelected={sel.allSelected}
                    someSelected={sel.someSelected}
                    onToggle={sel.toggleAll}
                    label="SELECT ALL"
                  />
                  <span className="text-xs text-muted">{matching.length} available</span>
                </div>
                {matching.length === 0 ? (
                  <p className="text-xs text-muted p-3">No findings match the filters.</p>
                ) : (
                  matching.map((f) => (
                    <label
                      key={f.id}
                      className="flex items-start gap-3 px-3 py-2 border-b border-border/40 last:border-0 hover:bg-white/5 cursor-pointer"
                    >
                      <RowCheckbox
                        checked={sel.isSelected(f.id)}
                        onToggle={() => sel.toggle(f.id)}
                        label={`Include ${String(f.title)}`}
                      />
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-2">
                          <span className={sevClass(String(f.severity || ""))}>[{String(f.severity || "")}]</span>
                          <span className="text-sm truncate">{String(f.title)}</span>
                        </span>
                        <span className="block text-xs text-muted truncate">
                          {String(f.status || "")}
                          {f.affected_url ? ` . ${String(f.affected_url)}` : ""}
                        </span>
                      </span>
                    </label>
                  ))
                )}
              </div>
            )}
          </>
        )}
        </div>
      </Section>

      <div className="flex gap-2">
        {["docx", "pdf", "xlsx", "json"].map((fmt) => (
          <button key={fmt} className="btn" disabled={!!busy} onClick={() => download(fmt)}>
            {busy === fmt ? "…" : fmt.toUpperCase()}
          </button>
        ))}
      </div>
    </div>
  );
}
