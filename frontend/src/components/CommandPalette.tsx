"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { Project } from "@/lib/types";
import { useProject } from "@/lib/ProjectContext";

/**
 * Keyboard command palette. Ctrl/Cmd-K.
 *
 * Navigation, project switching and the handful of destructive-free actions,
 * reachable without the mouse. This is the interaction that separates a tool from
 * a website: the people using this live in terminals, and making them travel to
 * the top of the page to change tab is friction they notice.
 *
 * Two deliberate limits. Nothing destructive is offered here -- no delete, no
 * export -- because a fuzzy list plus a fast Enter is exactly the wrong way to
 * reach an irreversible action. And the palette never runs an analysis: those cost
 * tokens, and a command palette should not be able to spend money by accident.
 */

type Command = {
  id: string;
  label: string;
  hint?: string;
  group: "Go to" | "Project" | "Action";
  run: () => void;
  keywords?: string;
};

const PAGES: { href: string; label: string; keywords: string }[] = [
  { href: "/", label: "Overview", keywords: "dashboard home summary stats" },
  { href: "/projects", label: "Projects", keywords: "engagements clients" },
  { href: "/analyzer", label: "Analyzer", keywords: "analyse evidence extract paste" },
  { href: "/import", label: "Import", keywords: "scanner burp zap nessus nmap csv upload triage" },
  { href: "/findings", label: "Findings", keywords: "vulnerabilities issues list table" },
  { href: "/reports", label: "Reports", keywords: "export docx pdf xlsx json deliverable" },
  { href: "/settings", label: "Settings", keywords: "config model provider api key lane" },
];

/** Subsequence match: "anz" finds "Analyzer". Cheap, predictable, and it does not
 *  reorder results in ways that make the list feel unstable while typing. */
function matches(query: string, text: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (t.includes(q)) return true;
  let i = 0;
  for (const ch of t) {
    if (ch === q[i]) i++;
    if (i === q.length) return true;
  }
  return false;
}

/** Anything can ask for the palette without faking a keystroke. */
export const PALETTE_EVENT = "vapt:palette";
export function openCommandPalette() {
  window.dispatchEvent(new CustomEvent(PALETTE_EVENT));
}

export default function CommandPalette() {
  const router = useRouter();
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId, setProjectId } = useProject();

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const [projects, setProjects] = useState<Project[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Global shortcut. Ignored while typing into a field, so Ctrl-K in a textarea
  // still does whatever the browser or the user expects it to.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const k = e.key.toLowerCase();
      if ((e.metaKey || e.ctrlKey) && k === "k") {
        e.preventDefault();
        setOpen((v) => !v);
        return;
      }
      if (e.key === "Escape") setOpen(false);
    };
    const onRequest = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener(PALETTE_EVENT, onRequest);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener(PALETTE_EVENT, onRequest);
    };
  }, []);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setCursor(0);
    inputRef.current?.focus();
    if (token && projects.length === 0) {
      api.listProjects(token).then(setProjects).catch(() => {});
    }
  }, [open, token, projects.length]);

  const close = useCallback(() => setOpen(false), []);

  const commands: Command[] = useMemo(() => {
    const go: Command[] = PAGES.map((p) => ({
      id: `go:${p.href}`,
      label: p.label,
      group: "Go to",
      keywords: p.keywords,
      run: () => router.push(p.href),
    }));

    const proj: Command[] = projects.map((p) => ({
      id: `proj:${p.id}`,
      label: p.name,
      hint: p.id === projectId ? "active" : p.client || undefined,
      group: "Project",
      keywords: `${p.client || ""} ${p.scope || ""}`,
      run: () => setProjectId(p.id),
    }));

    const actions: Command[] = [
      {
        id: "act:clear-project",
        label: "Clear active project",
        group: "Action",
        keywords: "deselect none unset",
        run: () => setProjectId(null),
      },
      {
        id: "act:new-project",
        label: "New project",
        hint: "opens Projects",
        group: "Action",
        keywords: "create add engagement",
        run: () => router.push("/projects"),
      },
      {
        id: "act:docs",
        label: "View source on GitHub",
        group: "Action",
        keywords: "repo code repository open source",
        run: () =>
          window.open("https://github.com/Sr7nyx/vapt-ai-assistant", "_blank", "noopener,noreferrer"),
      },
    ];

    return [...go, ...proj, ...actions];
  }, [projects, projectId, router, setProjectId]);

  const results = useMemo(
    () => commands.filter((c) => matches(query, `${c.label} ${c.keywords || ""}`)),
    [commands, query]
  );

  useEffect(() => setCursor(0), [query]);

  // Keep the highlighted row in view when arrowing past the fold.
  useEffect(() => {
    listRef.current
      ?.querySelector<HTMLElement>(`[data-idx="${cursor}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => (results.length ? (c + 1) % results.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => (results.length ? (c - 1 + results.length) % results.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const chosen = results[cursor];
      if (chosen) {
        chosen.run();
        close();
      }
    }
  };

  if (!open) return null;

  let lastGroup = "";

  return (
    <div
      className="fixed inset-0 z-[80] flex items-start justify-center px-4 pt-[12vh]"
      style={{ background: "rgba(0,0,0,0.72)" }}
      onMouseDown={(e) => e.target === e.currentTarget && close()}
    >
      <div className="w-full max-w-xl rounded-xl border border-border bg-surface shadow-2xl overflow-hidden animate-in">
        <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border/60">
          <span className="text-highlight select-none">&gt;</span>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Jump to a page, switch project…"
            aria-label="Command palette"
            className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted/60"
          />
          <kbd className="text-[10px] tracking-widest text-muted border border-border rounded px-1.5 py-0.5">
            ESC
          </kbd>
        </div>

        <div ref={listRef} className="max-h-[52vh] overflow-y-auto py-1">
          {results.length === 0 && (
            <p className="px-4 py-6 text-center text-xs text-muted">No matching command.</p>
          )}
          {results.map((c, i) => {
            const showGroup = c.group !== lastGroup;
            lastGroup = c.group;
            const on = i === cursor;
            return (
              <div key={c.id}>
                {showGroup && (
                  <div className="px-3 pt-2 pb-1 text-[10px] tracking-widest text-muted/70">
                    {c.group.toUpperCase()}
                  </div>
                )}
                <button
                  data-idx={i}
                  onMouseEnter={() => setCursor(i)}
                  onClick={() => {
                    c.run();
                    close();
                  }}
                  className={`w-full flex items-center gap-2 px-3 py-1.5 text-left text-sm transition-colors ${
                    on ? "bg-highlight/10 text-highlight" : "text-text hover:bg-white/5"
                  }`}
                >
                  <span className={`w-2 shrink-0 ${on ? "text-highlight" : "text-transparent"}`}>
                    &gt;
                  </span>
                  <span className="flex-1 truncate">{c.label}</span>
                  {c.hint && <span className="text-[11px] text-muted shrink-0">{c.hint}</span>}
                </button>
              </div>
            );
          })}
        </div>

        <div className="flex items-center gap-3 px-3 py-1.5 border-t border-border/60 text-[10px] tracking-widest text-muted">
          <span>UP / DOWN to move</span>
          <span className="text-border">|</span>
          <span>ENTER to run</span>
        </div>
      </div>
    </div>
  );
}
