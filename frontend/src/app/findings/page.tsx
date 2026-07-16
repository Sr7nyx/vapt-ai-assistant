"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";
import { Finding } from "@/lib/types";
import { sevClass, verdictOf } from "@/components/Severity";

const RETEST = ["Fixed", "Open", "Partially Fixed", "Regressed", "Accepted Risk"];

export default function FindingsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const [findings, setFindings] = useState<Finding[]>([]);

  const load = useCallback(() => {
    if (token && projectId) api.listFindings(token, projectId).then(setFindings).catch(() => {});
  }, [token, projectId]);
  useEffect(() => load(), [load]);

  if (!projectId) {
    return (
      <div>
        <h1 className="text-2xl font-semibold mb-4">Findings</h1>
        <p className="text-muted text-sm">Select a project on the Projects page first.</p>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Findings</h1>
      <div className="grid gap-3">
        {findings.map((f) => (
          <div key={f.id} className="card">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className={sevClass(f.severity)}>{f.severity}</span>
                <span className="font-medium truncate">{f.title}</span>
              </div>
              <div className="flex gap-2 shrink-0">
                <select
                  className="input py-1 text-xs w-auto"
                  defaultValue=""
                  onChange={async (e) => {
                    if (e.target.value) {
                      await api.retestFinding(token, f.id, { retest_status: e.target.value });
                      load();
                    }
                  }}
                >
                  <option value="">Retest…</option>
                  {RETEST.map((r) => (
                    <option key={r}>{r}</option>
                  ))}
                </select>
                <button
                  className="btn-sm-danger"
                  onClick={async () => {
                    await api.deleteFinding(token, f.id);
                    load();
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
            <div className="flex gap-1 mt-2 flex-wrap">
              {f._assessment?.risk?.priority && <span className="chip">Risk: {f._assessment.risk.priority}</span>}
              {f._assessment?.frameworks?.owasp && <span className="chip">{f._assessment.frameworks.owasp}</span>}
              {f.cwe && <span className="chip">{f.cwe}</span>}
              {f.status && <span className="chip">{f.status}</span>}
              {verdictOf(f.additional_remarks) && <span className="chip">Triage: {verdictOf(f.additional_remarks)}</span>}
            </div>
          </div>
        ))}
        {findings.length === 0 && <p className="text-muted text-sm">No findings in this project yet.</p>}
      </div>
    </div>
  );
}
