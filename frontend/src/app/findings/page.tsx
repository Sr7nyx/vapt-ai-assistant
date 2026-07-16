"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";
import { Finding } from "@/lib/types";
import { sevClass, verdictOf } from "@/components/Severity";
import { useToast } from "@/components/Toast";
import { Skeleton } from "@/components/Loading";
import FindingEditor from "@/components/FindingEditor";

const RETEST = ["Fixed", "Open", "Partially Fixed", "Regressed", "Accepted Risk"];

export default function FindingsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const { notify } = useToast();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState<Finding | null>(null);

  const load = useCallback(() => {
    if (!token || !projectId) return;
    setLoading(true);
    api
      .listFindings(token, projectId)
      .then(setFindings)
      .catch((e) => notify((e as Error).message, "error"))
      .finally(() => setLoading(false));
  }, [token, projectId, notify]);
  useEffect(() => load(), [load]);

  if (!projectId) {
    return (
      <div className="animate-in">
        <h1 className="text-2xl font-semibold mb-4">Findings</h1>
        <div className="card text-muted text-sm">Select a project on the Projects page first.</div>
      </div>
    );
  }

  const save = async (f: Record<string, unknown>) => {
    await api.updateFinding(token, f.id as number, f);
    setEditing(null);
    notify("Finding updated", "success");
    load();
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
  const retest = async (id: number, status: string) => {
    try {
      await api.retestFinding(token, id, { retest_status: status });
      notify(`Marked "${status}"`, "success");
      load();
    } catch (e) {
      notify((e as Error).message, "error");
    }
  };

  return (
    <div className="animate-in">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-semibold">Findings</h1>
        <span className="text-muted text-sm">{findings.length} total</span>
      </div>

      {loading ? (
        <Skeleton rows={6} />
      ) : findings.length === 0 ? (
        <div className="card text-muted text-sm">No findings in this project yet.</div>
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead className="text-left text-muted border-b border-border">
              <tr>
                <th className="p-3 font-medium">Severity</th>
                <th className="font-medium">Title</th>
                <th className="font-medium">Risk</th>
                <th className="font-medium">CWE</th>
                <th className="font-medium">Status</th>
                <th className="font-medium">Triage</th>
                <th className="p-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id} className="border-b border-border/50 hover:bg-white/5 transition-colors">
                  <td className="p-3">
                    <span className={sevClass(f.severity)}>{f.severity}</span>
                  </td>
                  <td className="max-w-md">
                    <div className="truncate font-medium">{f.title}</div>
                  </td>
                  <td>{f._assessment?.risk?.priority || "-"}</td>
                  <td className="text-muted">{f.cwe || "-"}</td>
                  <td className="text-muted">{f.status || "-"}</td>
                  <td className="text-muted">{verdictOf(f.additional_remarks) || "-"}</td>
                  <td className="p-3">
                    <div className="flex gap-1 justify-end items-center">
                      <button className="btn-sm" onClick={() => setEditing(f)}>Edit</button>
                      <select
                        className="input py-1 text-xs w-auto"
                        defaultValue=""
                        onChange={(e) => {
                          if (e.target.value) {
                            retest(f.id, e.target.value);
                            e.target.value = "";
                          }
                        }}
                      >
                        <option value="">Retest…</option>
                        {RETEST.map((r) => (
                          <option key={r}>{r}</option>
                        ))}
                      </select>
                      <button className="btn-sm-danger" onClick={() => del(f.id)}>Del</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editing && <FindingEditor finding={editing} onSave={save} onClose={() => setEditing(null)} />}
    </div>
  );
}
