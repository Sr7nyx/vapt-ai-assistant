"use client";
import { ReactNode, useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";
import { Finding, Project } from "@/lib/types";
import { sevClass } from "@/components/Severity";
import { useToast } from "@/components/Toast";
import { Skeleton } from "@/components/Loading";
import FindingEditor from "@/components/FindingEditor";
import RetestModal from "@/components/RetestModal";
import MultiSelect from "@/components/MultiSelect";
import ReviewPanel, { VerdictBadge, VerdictChip, ReviewFlag, VerifiedChip } from "@/components/ReviewPanel";
import AuditTrail from "@/components/AuditTrail";
import { useSelection } from "@/hooks/useSelection";
import { MasterCheckbox, RowCheckbox, SelectionBar } from "@/components/SelectionBar";

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

export default function FindingsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId, setProjectId } = useProject();
  const { notify } = useToast();

  const [projects, setProjects] = useState<Project[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  // Tracked separately from row expansion so opening a finding to read it does not
  // fire a history request every time.
  const [historyFor, setHistoryFor] = useState<number | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [editing, setEditing] = useState<Record<string, unknown> | null>(null);
  const [retesting, setRetesting] = useState<Finding | null>(null);
  const [sevF, setSevF] = useState<string[]>([]);
  const [statusF, setStatusF] = useState<string[]>([]);
  const [catF, setCatF] = useState<string[]>([]);

  useEffect(() => {
    if (token) api.listProjects(token).then(setProjects).catch(() => {});
  }, [token]);

  const load = useCallback(() => {
    if (!token || !projectId) {
      setFindings([]);
      return;
    }
    setLoading(true);
    api.listFindings(token, projectId).then(setFindings).catch((e) => notify((e as Error).message, "error")).finally(() => setLoading(false));
  }, [token, projectId, notify]);
  useEffect(() => load(), [load]);

  const toggle = (id: number) =>
    setExpanded((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const save = async (f: Record<string, unknown>) => {
    try {
      if (f.id) {
        await api.updateFinding(token, f.id as number, f);
        notify("Finding updated", "success");
      } else if (projectId) {
        await api.createFinding(token, projectId, f);
        notify("Finding added", "success");
      }
      setEditing(null);
      load();
    } catch (e) {
      notify((e as Error).message, "error");
    }
  };

  const del = async (id: number) => {
    if (!confirm("Delete this finding?")) return;
    try {
      await api.deleteFinding(token, id);
      notify("Finding deleted", "success");
      load();
    } catch (e) {
      notify((e as Error).message, "error");
    }
  };

  const sevOptions = SEV_ORDER.filter((s) => findings.some((f) => f.severity === s));
  const statusOptions = Array.from(new Set(findings.map((f) => f.status).filter(Boolean))) as string[];
  const catOptions = Array.from(new Set(findings.map((f) => f.category as string).filter(Boolean)));

  const shown = findings.filter(
    (f) =>
      (sevF.length === 0 || sevF.includes(f.severity)) &&
      (statusF.length === 0 || statusF.includes(f.status || "")) &&
      (catF.length === 0 || catF.includes((f.category as string) || ""))
  );

  // Selection is over the *filtered* rows, and the hook prunes keys that leave
  // the list, so changing a filter cannot leave a bulk action holding ids the
  // user can no longer see.
  const sel = useSelection(shown, (f) => f.id);

  const deleteSelected = async () => {
    const ids = sel.selectedItems.map((f) => f.id);
    if (ids.length === 0) return;
    if (!confirm(`Delete ${ids.length} finding(s)? This cannot be undone.`)) return;
    setBulkBusy(true);
    try {
      const r = await api.bulkDeleteFindings(token, ids);
      notify(`Deleted ${r.deleted} finding(s)`, "success");
      sel.clear();
      load();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBulkBusy(false);
    }
  };

  return (
    <div className="animate-in">
      <h1 className="text-2xl tracking-wide mb-6 caret">FINDINGS</h1>

      <label className="grid gap-1.5 mb-4">
        <span className="text-sm text-muted">Project</span>
        <select className="input" value={projectId ?? ""} onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : null)}>
          <option value="">— no project selected —</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
              {p.client ? ` (${p.client})` : ""}
            </option>
          ))}
        </select>
      </label>

      {!projectId ? (
        <div className="card text-muted text-sm">Select a project to view its findings.</div>
      ) : (
        <>
          <div className="flex justify-end mb-4">
            <button
              className="btn-sm"
              onClick={() => setEditing({ title: "", severity: "Medium", status: "Need Review", category: "Web Application/API Vulnerability" })}
            >
              + Add finding
            </button>
          </div>

          <div className="grid md:grid-cols-3 gap-4 mb-4">
            <div>
              <div className="text-sm text-muted mb-1.5">Filter severity</div>
              <MultiSelect options={sevOptions} selected={sevF} onChange={setSevF} />
            </div>
            <div>
              <div className="text-sm text-muted mb-1.5">Filter status</div>
              <MultiSelect options={statusOptions} selected={statusF} onChange={setStatusF} />
            </div>
            <div>
              <div className="text-sm text-muted mb-1.5">Filter category</div>
              <MultiSelect options={catOptions} selected={catF} onChange={setCatF} />
            </div>
          </div>

          <div className="flex items-center gap-4 mb-3">
            <MasterCheckbox
              allSelected={sel.allSelected}
              someSelected={sel.someSelected}
              onToggle={sel.toggleAll}
              label="SELECT ALL"
            />
            <span className="text-sm text-muted">
              Showing {shown.length} of {findings.length} finding(s).
            </span>
          </div>

          <SelectionBar count={sel.count} noun="finding" onClear={sel.clear}>
            <button className="btn-sm-danger" onClick={deleteSelected} disabled={bulkBusy}>
              {bulkBusy ? "Deleting…" : "Delete selected"}
            </button>
          </SelectionBar>

          {loading ? (
            <Skeleton rows={6} />
          ) : shown.length === 0 ? (
            <div className="card text-muted text-sm">No findings match.</div>
          ) : (
            <div className="grid gap-2">
              {shown.map((f) => {
                const open = expanded.has(f.id);
                const fw = (f._assessment?.frameworks || {}) as Record<string, string>;
                const asset = (f.affected_url as string) || (f.affected_host as string) || "";
                return (
                  <div key={f.id} className="card p-0 overflow-hidden">
                    {/* The checkbox sits outside the expand button: nesting an
                        input inside a button makes the row un-selectable without
                        also opening it. */}
                    <div className="flex items-stretch">
                    <span className="flex items-start pl-4 pt-4">
                      <RowCheckbox
                        checked={sel.isSelected(f.id)}
                        onToggle={() => sel.toggle(f.id)}
                        label={`Select ${f.title}`}
                      />
                    </span>
                    <button
                      className="flex-1 min-w-0 flex items-center gap-3 px-3 py-3 text-left hover:bg-white/5 transition-colors"
                      onClick={() => toggle(f.id)}
                    >
                      <svg
                        width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                        strokeLinecap="round" strokeLinejoin="round"
                        className={`text-muted shrink-0 transition-transform ${open ? "rotate-90" : ""}`}
                      >
                        <path d="m9 18 6-6-6-6" />
                      </svg>
                      <span className={sevClass(f.severity)}>[{f.severity}]</span>
                      <span className="text-muted text-xs shrink-0">[{f.status || "-"}]</span>
                      <span className="font-medium truncate flex-1">{f.title}</span>
                      {asset && <span className="text-accent text-xs truncate max-w-[240px] hidden lg:inline">{asset}</span>}
                      <span className="flex gap-1 shrink-0">
                        <VerdictBadge verdict={f._verdict} />
                        <VerifiedChip verification={f._verification} />
                        <VerdictChip review={f._review} />
                        <ReviewFlag review={f._review} />
                      </span>
                    </button>
                    </div>

                    {open && (
                      <div className="px-4 pb-4 pt-1 border-t border-border/60 grid gap-3">
                        <div className="flex gap-1 flex-wrap">
                          {f._assessment?.risk?.priority && <span className="chip">Risk: {f._assessment.risk.priority}</span>}
                          {fw.owasp && <span className="chip">{fw.owasp}</span>}
                          {fw.pci && <span className="chip">{"PCI "}{fw.pci}</span>}
                          {f.cwe && <span className="chip">{f.cwe}</span>}
                          {fw.attack && <span className="chip">{"ATT&CK "}{fw.attack}</span>}
                          {f.cvss && <span className="chip">{f.cvss as string}</span>}
                        </div>

                        {asset && asset.startsWith("http") && (
                          <a href={asset} target="_blank" rel="noreferrer" className="text-accent text-sm hover:underline break-all">
                            {asset}
                          </a>
                        )}
                        <ReviewPanel review={f._review} verdict={f._verdict} verification={f._verification} />
                        {typeof f.description === "string" && f.description && <Detail label="Description">{f.description}</Detail>}
                        {typeof f.evidence === "string" && f.evidence && <Detail label="Evidence" mono>{f.evidence}</Detail>}
                        {typeof f.remediation === "string" && f.remediation && <Detail label="Remediation">{f.remediation}</Detail>}
                        {typeof f.references_data === "string" && f.references_data && <Detail label="References">{f.references_data}</Detail>}

                        <div className="rounded-lg border border-border/60">
                          <button
                            className="w-full flex items-center gap-2 px-3 py-2 text-left"
                            onClick={() => setHistoryFor(historyFor === f.id ? null : f.id)}
                            aria-expanded={historyFor === f.id}
                          >
                            <svg
                              width="12" height="12" viewBox="0 0 24 24" fill="none"
                              stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
                              className={`text-muted transition-transform ${historyFor === f.id ? "rotate-90" : ""}`}
                            >
                              <path d="m9 18 6-6-6-6" />
                            </svg>
                            <span className="term-h text-muted">History</span>
                            <span className="text-[11px] text-muted ml-auto">
                              who changed what, and why
                            </span>
                          </button>
                          {historyFor === f.id && (
                            <div className="px-3 pb-3 pt-1 border-t border-border/60">
                              <AuditTrail findingId={f.id} />
                            </div>
                          )}
                        </div>

                        <div className="flex gap-2 pt-1">
                          <button className="btn-sm" onClick={() => setEditing(f)}>Edit</button>
                          <button className="btn-sm" onClick={() => setRetesting(f)}>Retest</button>
                          <button className="btn-sm-danger" onClick={() => del(f.id)}>Delete</button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {editing && <FindingEditor finding={editing} onSave={save} onClose={() => setEditing(null)} />}
      {retesting && (
        <RetestModal
          title={retesting.title}
          onClose={() => setRetesting(null)}
          onSubmit={async (payload) => {
            await api.retestFinding(token, retesting.id, payload);
            notify(`Retest recorded (${payload.retest_status})`, "success");
            setRetesting(null);
            load();
          }}
        />
      )}
    </div>
  );
}

function Detail({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-muted mb-1">{label}</div>
      <div className={`text-sm whitespace-pre-wrap break-words ${mono ? "font-mono text-xs bg-bg rounded-lg p-3 max-h-64 overflow-auto" : ""}`}>
        {children}
      </div>
    </div>
  );
}
