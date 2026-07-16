"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";
import { Project } from "@/lib/types";

export default function ProjectsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId, setProjectId } = useProject();
  const [projects, setProjects] = useState<Project[]>([]);
  const [form, setForm] = useState({ name: "", client: "", scope: "" });

  const load = useCallback(() => {
    if (token) api.listProjects(token).then(setProjects).catch(() => {});
  }, [token]);
  useEffect(() => load(), [load]);

  const create = async () => {
    if (!form.name.trim()) return;
    const p = await api.createProject(token, form);
    setForm({ name: "", client: "", scope: "" });
    setProjectId(p.id);
    load();
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Projects</h1>
      <div className="card grid gap-3 mb-6">
        <input className="input" placeholder="Project name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <input className="input" placeholder="Client" value={form.client} onChange={(e) => setForm({ ...form, client: e.target.value })} />
        <input className="input" placeholder="Scope" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })} />
        <div>
          <button className="btn" onClick={create}>Create project</button>
        </div>
      </div>
      <div className="grid gap-2">
        {projects.map((p) => (
          <div key={p.id} className={`card flex items-center justify-between ${projectId === p.id ? "border-accent" : ""}`}>
            <div>
              <div className="font-medium">{p.name}</div>
              <div className="text-xs text-muted">{p.client}</div>
            </div>
            <div className="flex gap-2">
              <button className="btn-sm" onClick={() => setProjectId(p.id)}>{projectId === p.id ? "Selected" : "Select"}</button>
              <button
                className="btn-sm-danger"
                onClick={async () => {
                  await api.deleteProject(token, p.id);
                  if (projectId === p.id) setProjectId(null);
                  load();
                }}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
        {projects.length === 0 && <p className="text-muted text-sm">No projects yet.</p>}
      </div>
    </div>
  );
}
