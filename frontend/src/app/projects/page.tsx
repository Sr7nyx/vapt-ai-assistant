"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { swr, readCache, invalidate } from "@/lib/cache";
import { useProject } from "@/lib/ProjectContext";
import { Project } from "@/lib/types";
import { useToast } from "@/components/Toast";
import { Skeleton } from "@/components/Loading";
import { Section } from "@/components/Terminal";

export default function ProjectsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId, setProjectId } = useProject();
  const { notify } = useToast();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(() => !readCache<Project[]>("projects"));
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", client: "", scope: "" });

  // Cache-then-revalidate. Every page switch used to be a cold round trip to the
  // API, which on a free-tier instance is two to four seconds of skeleton for data
  // that has almost certainly not changed. The list now paints from cache
  // immediately and refreshes behind it.
  const load = useCallback(() => {
    if (!token) return;
    invalidate("projects");
    return swr<Project[]>("projects", () => api.listProjects(token), (value) => {
      setProjects(value);
      setLoading(false);
    });
  }, [token]);

  useEffect(() => {
    if (!token) return;
    return swr<Project[]>("projects", () => api.listProjects(token), (value) => {
      setProjects(value);
      setLoading(false);
    });
  }, [token]);

  const create = async () => {
    if (!form.name.trim()) return;
    setCreating(true);
    try {
      const p = await api.createProject(token, form);
      invalidate("overview");
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
      invalidate("overview");
      if (projectId === p.id) setProjectId(null);
      notify("Project deleted", "success");
      load();
    } catch (e) {
      notify((e as Error).message, "error");
    }
  };

  return (
    <div className="animate-in mx-auto w-full max-w-5xl grid gap-10">
      {/* Labelled fields on one row, matching the analyzer and importer. Three
          unlabelled full-width inputs relying on placeholders looked like a
          different application, and a placeholder disappears the moment you type,
          which leaves no way to tell the fields apart. */}
      <Section title="New project">
        <div className="grid gap-4">
          <div className="grid sm:grid-cols-3 gap-x-3 gap-y-3">
            <label className="field-inline">
              <span>NAME</span>
              <input
                className="input"
                placeholder="acme-web-2026"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </label>
            <label className="field-inline">
              <span>CLIENT</span>
              <input
                className="input"
                placeholder="Acme Ltd"
                value={form.client}
                onChange={(e) => setForm({ ...form, client: e.target.value })}
              />
            </label>
            <label className="field-inline">
              <span>SCOPE</span>
              <input
                className="input"
                placeholder="app.acme.test"
                value={form.scope}
                onChange={(e) => setForm({ ...form, scope: e.target.value })}
              />
            </label>
          </div>
          <button className="btn w-fit" onClick={create} disabled={creating || !form.name.trim()}>
            {creating ? "Creating…" : "Create project"}
          </button>
        </div>
      </Section>

      <Section
        title="Projects"
        note={projects.length ? `${projects.length} in this account.` : undefined}
      >
        {loading ? (
          <Skeleton rows={3} />
        ) : projects.length === 0 ? (
          <p className="measure text-sm text-muted">
            No projects yet. A project holds an engagement&rsquo;s findings, and everything else in
            the console works against the one selected in the header.
          </p>
        ) : (
          /* Ruled rows, not cards. A card per project reads as five stacked
             containers; the findings and retest lists already use rules, and this
             is the same kind of list. */
          <ul className="grid gap-0">
            {projects.map((p) => {
              const active = projectId === p.id;
              return (
                <li
                  key={p.id}
                  className={`flex items-center gap-3 py-2.5 border-b border-border/40 last:border-0 ${
                    active ? "bg-accent/5" : ""
                  }`}
                >
                  <span className={`w-2 shrink-0 ${active ? "text-highlight" : "text-transparent"}`}>
                    &gt;
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className={`block truncate text-sm ${active ? "text-accent" : ""}`}>
                      {p.name}
                    </span>
                    <span className="block truncate text-xs text-muted">
                      {p.client || "no client recorded"}
                      {p.scope ? ` · ${p.scope}` : ""}
                    </span>
                  </span>
                  <button
                    className="btn-sm shrink-0"
                    onClick={() => setProjectId(p.id)}
                    disabled={active}
                  >
                    {active ? "Selected" : "Select"}
                  </button>
                  <button className="btn-sm-danger shrink-0" onClick={() => del(p)}>
                    Delete
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </Section>
    </div>
  );
}
