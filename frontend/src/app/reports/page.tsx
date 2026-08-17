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
import { Section, Figure } from "@/components/Terminal";

/**
 * Reports.
 *
 * The rest of the pipeline treats a finding as unproven until the evidence says
 * otherwise, and then the report page exported whatever was selected without ever
 * consulting that work. The deliverable is the one artefact a client actually
 * reads, so it is the last place the guardrails should be silent.
 *
 * This page therefore inspects what is about to ship: findings a mechanical check
 * contradicted, findings the reviewer flagged, findings nobody has adjudicated.
 * Nothing is blocked -- a tester may have perfectly good reasons to include any of
 * it -- but it is stated before the download, not discovered afterwards.
 */

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

type Issue = {
  key: string;
  label: string;
  detail: string;
  findings: Finding[];
  tone: "danger" | "warn";
};

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
  const [acknowledged, setAcknowledged] = useState(false);

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
  const included = sel.count > 0 ? sel.selectedItems : matching;
  const wholeProject = sel.count === 0 && sevF.length === 0 && statusF.length === 0;

  // What is actually in the report, by severity. The composition of a deliverable
  // is the first thing a reviewer checks, and it was not shown anywhere.
  const composition = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of included) {
      const key = String(f.severity || "Unknown");
      counts[key] = (counts[key] || 0) + 1;
    }
    return SEVERITY_ORDER.filter((s) => counts[s]).map((s) => ({ label: s, count: counts[s] }));
  }, [included]);

  /** Everything about the selection worth knowing before it becomes a document. */
  const issues = useMemo<Issue[]>(() => {
    const refuted = included.filter((f) => f._verification?.status === "REFUTED");
    const flagged = included.filter((f) => (f._review?.warnings?.length ?? 0) > 0);
    const unadjudicated = included.filter((f) =>
      ["Need Review", "Draft", ""].includes(String(f.status || ""))
    );
    const noCvss = included.filter((f) => !String(f.cvss || "").trim());
    const falsePositive = included.filter((f) => String(f.status || "") === "False Positive");

    // Annotated rather than inferred: inside a bare array literal TypeScript widens
    // `tone: "danger"` to `string`, and .filter() carries the widened type through,
    // so the result no longer satisfies Issue[].
    const all: Issue[] = [
      {
        key: "refuted",
        label: "contradicted by the evidence",
        detail:
          "A deterministic check found the evidence contradicts the claim. Shipping these is how a report loses a client's trust.",
        findings: refuted,
        tone: "danger",
      },
      {
        key: "false-positive",
        label: "marked false positive",
        detail: "Already adjudicated as not real. Usually excluded from a client deliverable.",
        findings: falsePositive,
        tone: "danger",
      },
      {
        key: "flagged",
        label: "carry verification flags",
        detail:
          "Unverified or contradicted evidence, severity disagreement, or prompt-injection indicators in the source.",
        findings: flagged,
        tone: "warn",
      },
      {
        key: "unadjudicated",
        label: "not yet reviewed",
        detail: "Still at Need Review or Draft. Nobody has confirmed these are real.",
        findings: unadjudicated,
        tone: "warn",
      },
      {
        key: "no-cvss",
        label: "have no CVSS vector",
        detail: "They will appear without a computed score, which reads as an omission in a report.",
        findings: noCvss,
        tone: "warn",
      },
    ];
    return all.filter((i) => i.findings.length > 0);
  }, [included]);

  const blocking = issues.filter((i) => i.tone === "danger");
  const needsAck = blocking.length > 0;

  useEffect(() => setAcknowledged(false), [sevF, statusF, sel.count]);

  if (!projectId) {
    return (
      <div className="animate-in mx-auto w-full max-w-3xl grid gap-8">
        <div className="card text-muted text-sm">Select a project first.</div>
      </div>
    );
  }

  const applyPreset = (preset: "confirmed" | "clean" | "all") => {
    sel.clear();
    if (preset === "confirmed") {
      setStatusF(["Confirmed", "Retest Failed"].filter((s) => statuses.includes(s)));
      setSevF([]);
    } else if (preset === "clean") {
      setStatusF(statuses.filter((s) => s !== "False Positive"));
      setSevF([]);
    } else {
      setStatusF([]);
      setSevF([]);
    }
  };

  const download = async (fmt: string) => {
    if (!wholeProject && included.length === 0) {
      notify("No findings match the current selection.", "error");
      return;
    }
    if (needsAck && !acknowledged) {
      notify("Confirm the flagged findings below before exporting.", "error");
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
    <div className="animate-in mx-auto w-full max-w-4xl grid gap-8">
      <Section title="Narrative">
        <div className="grid gap-3">
          <label className="grid gap-1.5">
            <span className="text-xs text-muted">
              Executive summary &mdash; written for the reader who will not read the findings
            </span>
            <textarea
              className="input min-h-28"
              placeholder="What was assessed, what matters most, and what should happen next."
              value={exec}
              onChange={(e) => setExec(e.target.value)}
            />
          </label>
          <label className="grid gap-1.5">
            <span className="text-xs text-muted">Methodology</span>
            <input className="input" value={method} onChange={(e) => setMethod(e.target.value)} />
          </label>
        </div>
      </Section>

      <Section
        title="Scope"
        note="What the document will contain."
        actions={
          <div className="flex gap-1.5">
            {(
              [
                ["confirmed", "Confirmed only"],
                ["clean", "Exclude false positives"],
                ["all", "Everything"],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                onClick={() => applyPreset(key)}
                className="rounded border border-border px-2 py-0.5 text-[10px] tracking-widest text-muted hover:border-accent/60 hover:text-accent transition-colors"
              >
                {label}
              </button>
            ))}
          </div>
        }
      >
        {loading ? (
          <Skeleton rows={2} />
        ) : (
          <div className="grid gap-4">
            <div className="flex flex-wrap gap-3">
              <MultiSelect placeholder="Severity" options={severities} selected={sevF} onChange={setSevF} />
              <MultiSelect placeholder="Status" options={statuses} selected={statusF} onChange={setStatusF} />
              <button className="btn-sm" onClick={() => setPick((v) => !v)}>
                {pick ? "Hide list" : "Choose individually"}
              </button>
            </div>

            <div className="flex flex-wrap gap-x-8 gap-y-2">
              <Figure
                label="Included"
                value={wholeProject ? findings.length : included.length}
                tone="accent"
              />
              {composition.map((c) => (
                <Figure key={c.label} label={c.label} value={c.count} />
              ))}
              <Figure label="Of" value={findings.length} />
            </div>

            {pick && (
              <div className="pane-scroll border border-border/60 rounded-lg max-h-72 overflow-y-auto">
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
                        <span className="flex items-center gap-2 flex-wrap">
                          <span className={sevClass(String(f.severity || ""))}>
                            [{String(f.severity || "")}]
                          </span>
                          <span className="text-sm truncate">{String(f.title)}</span>
                          {f._verification?.status === "REFUTED" && (
                            <span className="chip border-danger/60 text-danger">contradicted</span>
                          )}
                          {(f._review?.warnings?.length ?? 0) > 0 && (
                            <span className="chip border-warn/60 text-warn">flagged</span>
                          )}
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
          </div>
        )}
      </Section>

      <Section
        title="Pre-flight"
        note="Checked against the selection, not the whole project."
      >
        {issues.length === 0 ? (
          <p className="text-sm text-accent">
            Nothing outstanding. Every included finding has been adjudicated, carries no verification
            flags, and has a computed score.
          </p>
        ) : (
          <div className="grid gap-3">
            {issues.map((i) => (
              <div
                key={i.key}
                className={`border-l-2 pl-3 py-0.5 ${
                  i.tone === "danger" ? "border-danger/70" : "border-warn/70"
                }`}
              >
                <p className="text-sm">
                  <span className={i.tone === "danger" ? "text-danger" : "text-warn"}>
                    {i.findings.length}
                  </span>{" "}
                  finding{i.findings.length === 1 ? "" : "s"} {i.label}
                </p>
                <p className="text-xs text-muted mt-0.5">{i.detail}</p>
                <p className="text-xs text-muted/70 mt-1 truncate">
                  {i.findings.slice(0, 3).map((f) => String(f.title)).join(" . ")}
                  {i.findings.length > 3 ? ` . +${i.findings.length - 3} more` : ""}
                </p>
              </div>
            ))}

            {/* Nothing is blocked outright: a tester may have good reason to include
                any of this. But the serious cases require a deliberate act rather
                than a click that could be muscle memory. */}
            {needsAck && (
              <label className="flex items-start gap-2 text-sm mt-1">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={acknowledged}
                  onChange={(e) => setAcknowledged(e.target.checked)}
                />
                <span>
                  I have reviewed these and intend to include them.
                  <span className="block text-xs text-muted">
                    Required because the selection contains findings the evidence contradicts or that
                    are already marked false positive.
                  </span>
                </span>
              </label>
            )}
          </div>
        )}
      </Section>

      <Section
        title="Export"
        note="HTML opens anywhere, sends as one file, and keeps evidence readable."
      >
        <div className="flex flex-wrap items-center gap-2">
          {["html", "docx", "pdf", "xlsx", "json"].map((fmt) => (
            <button
              key={fmt}
              className="btn"
              disabled={!!busy || (needsAck && !acknowledged)}
              onClick={() => download(fmt)}
            >
              {busy === fmt ? "…" : fmt.toUpperCase()}
            </button>
          ))}
          <span className="text-xs text-muted ml-2">
            {wholeProject
              ? `Whole project, ${findings.length} finding${findings.length === 1 ? "" : "s"}`
              : `${included.length} selected finding${included.length === 1 ? "" : "s"}`}
          </span>
        </div>
      </Section>
    </div>
  );
}
