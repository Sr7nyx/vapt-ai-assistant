"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { Project } from "@/lib/types";
import { useProject } from "@/lib/ProjectContext";
import { openCommandPalette } from "./CommandPalette";

/**
 * Command bar and tab strip.
 *
 * Replaces the sidebar. A left rail plus a centred content column is the shape
 * every dashboard template produces, and it wastes the horizontal space that
 * finding tables and request/response panes actually need. Security consoles put
 * navigation on one dense row at the top and give the rest of the screen to data.
 *
 * The tab strip is also where the user is, so pages no longer repeat their own
 * title in an <h1>: the active tab says it once.
 */

const TABS = [
  { href: "/", label: "OVERVIEW" },
  { href: "/projects", label: "PROJECTS" },
  { href: "/analyzer", label: "ANALYZER" },
  { href: "/import", label: "IMPORT" },
  { href: "/findings", label: "FINDINGS" },
  { href: "/reports", label: "REPORTS" },
  { href: "/settings", label: "SETTINGS" },
];

export default function TopNav({ onSignOut }: { onSignOut: () => void }) {
  const path = usePathname();
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId, setProjectId } = useProject();
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    if (!token) return;
    api.listProjects(token).then(setProjects).catch(() => {});
  }, [token]);

  const active = (href: string) => (href === "/" ? path === "/" : path.startsWith(href));

  return (
    <header className="sticky top-0 z-40 bg-bg/95 backdrop-blur border-b border-border">
      {/* Command row: identity, working context, session. */}
      <div className="flex items-center gap-4 px-4 h-11 border-b border-border/60">
        <Link href="/" className="text-sm tracking-wide shrink-0 hover:opacity-80 transition-opacity">
          <span className="text-highlight">&gt;</span> vapt<span className="text-accent">.</span>console
        </Link>

        <span className="text-border select-none hidden sm:inline">|</span>

        {/* The active project is working context, not a page. It belongs in the
            chrome, where it is visible and changeable from anywhere. */}
        <label className="flex items-center gap-2 min-w-0">
          <span className="text-[10px] tracking-widest text-muted hidden sm:inline">PROJECT</span>
          <select
            className="bg-transparent border border-border rounded-lg px-2 py-0.5 text-xs max-w-[13rem] truncate outline-none hover:border-accent/50 focus:border-accent transition-colors"
            value={projectId ?? ""}
            onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">none selected</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>

        <div className="flex-1" />

        <button
          onClick={openCommandPalette}
          aria-label="Open command palette"
          className="hidden sm:flex items-center gap-1.5 rounded-lg border border-border px-2 py-0.5 text-[10px] tracking-widest text-muted hover:border-accent/60 hover:text-accent transition-colors"
        >
          <span className="text-highlight">&gt;</span>
          <kbd className="font-mono">CTRL K</kbd>
        </button>

        <span className="text-[10px] tracking-widest text-muted truncate hidden md:inline">
          {session?.user?.email}
        </span>
        <button
          onClick={onSignOut}
          className="text-[10px] tracking-widest text-muted hover:text-danger transition-colors shrink-0"
        >
          [LOG OUT]
        </button>
      </div>

      {/* Tab strip. Scrolls horizontally rather than wrapping, so the chrome
          height never changes as the window narrows. */}
      <nav className="flex items-stretch overflow-x-auto no-scrollbar">
        {TABS.map((t) => {
          const on = active(t.href);
          return (
            <Link
              key={t.href}
              href={t.href}
              aria-current={on ? "page" : undefined}
              className={`px-3.5 py-2 text-[11px] tracking-widest whitespace-nowrap border-b-2 transition-colors ${
                on
                  ? "border-highlight text-highlight bg-highlight/5"
                  : "border-transparent text-muted hover:text-text hover:bg-white/5"
              }`}
            >
              {on ? `[${t.label}]` : t.label}
            </Link>
          );
        })}
      </nav>
    </header>
  );
}
