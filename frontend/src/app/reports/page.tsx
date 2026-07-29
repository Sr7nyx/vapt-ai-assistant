"use client";
import { useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";
import { useToast } from "@/components/Toast";

export default function ReportsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const { notify } = useToast();
  const [exec, setExec] = useState("");
  const [method, setMethod] = useState("OWASP, PTES");
  const [busy, setBusy] = useState("");

  if (!projectId) {
    return (
      <div className="animate-in">
        <h1 className="text-2xl tracking-wide mb-4 caret">REPORTS</h1>
        <div className="card text-muted text-sm">Select a project first.</div>
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
      notify(`${fmt.toUpperCase()} report downloaded`, "success");
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="animate-in">
      <h1 className="text-2xl tracking-wide mb-6 caret">REPORTS</h1>
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
