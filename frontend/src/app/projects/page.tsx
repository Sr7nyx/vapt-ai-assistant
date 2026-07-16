"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";
import { Project } from "@/lib/types";
import { useToast } from "@/components/Toast";
import { Skeleton } from "@/components/Loading";

export default function ProjectsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId, setProjectId } = useProject();
  const { notify } = useToast();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", client: "", scope: "" });

  const load = useCallback(() => {
    if (!token) return;
    setLoading(true);
    api.listProjects(token).then(setProjects).catch((e) => notify((e as Error).message, "error")).finally(() => setLoading(false));
  }, [token, notify]);
  useEffect(() => load(), [load]);

  const create = async () => {
    if (!form.name.trim()) return;
    setCreating(true);
    try {
      const p = await api.createProject(token, form);
      setForm({ name: "", client: "", scope: "" });
      setProjectId(p.id);
      notify(`Created "${p.name}"`, "success");
      load();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setCreating(false);
    }
  };

  const del = async (p: Project) => {
    if (!confirm(`Delete project "${p.name}" and all its findings?`)) return;
    try {
      await api.deleteProject(token, p.id);
      if (projectId === p.id) setProjectId(null);
      notify("Project deleted", "success");
      load();
    } catch (e) {
      notify((e as Error).message, "error");
    }
  };

  return (
    <div className="animate-in">
      <h1 className="text-2xl font-semibold mb-6">Projects</h1>

      <div className="card grid gap-3 mb-6">
        <input className="input" placeholder="Project name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <input className="input" placeholder="Client" value={form.client} onChange={(e) => setForm({ ...form, client: e.target.value })} />
        <input className="input" placeholder="Scope" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })} />
        <div>
          <button className="btn" onClick={create} disabled={creating}>
            {creating ? "Creating…" : "Create project"}
          </button>
        </div>
      </div>

      {loading ? (
        <Skeleton rows={3} />
      ) : (
        <div className="grid gap-2">
          {projects.map((p) => (
            <div key={p.id} className={`card flex items-center justify-between ${projectId === p.id ? "border-accent" : ""}`}>
              <div className="min-w-0">
                <div className="font-medium truncate">{p.name}</div>
                <div className="text-xs text-muted truncate">{p.client}</div>
              </div>
              <div className="flex gap-2 shrink-0">
                <button className="btn-sm" onClick={() => setProjectId(p.id)}>{projectId === p.id ? "Selected" : "Select"}</button>
                <button className="btn-sm-danger" onClick={() => del(p)}>Delete</button>
              </div>
            </div>
          ))}
          {projects.length === 0 && <p className="text-muted text-sm">No projects yet.</p>}
        </div>
      )}
    </div>
  );
}
