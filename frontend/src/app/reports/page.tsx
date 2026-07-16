"use client";
import { useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";

export default function ReportsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const [exec, setExec] = useState("");
  const [method, setMethod] = useState("OWASP, PTES");
  const [busy, setBusy] = useState("");

  if (!projectId) {
    return (
      <div>
        <h1 className="text-2xl font-semibold mb-4">Reports</h1>
        <p className="text-muted text-sm">Select a project first.</p>
      </div>
    );
  }

  const download = async (fmt: string) => {
    setBusy(fmt);
    try {
      const { blob, filename } = await api.exportReport(token, projectId, { fmt, exec_summary: exec, methodology: method });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert((e as Error).message);
    } finally {
      setBusy("");
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Reports</h1>
      <div className="card grid gap-3 mb-4">
        <textarea className="input min-h-32" placeholder="Executive summary (optional)" value={exec} onChange={(e) => setExec(e.target.value)} />
        <input className="input" placeholder="Methodology" value={method} onChange={(e) => setMethod(e.target.value)} />
      </div>
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
