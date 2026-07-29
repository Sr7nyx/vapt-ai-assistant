"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { forgetSession } from "@/lib/prefs";
import { ReactNode } from "react";

const svg = (children: ReactNode) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    {children}
  </svg>
);

const items = [
  {
    href: "/",
    label: "Overview",
    icon: svg(
      <>
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
      </>
    ),
  },
  { href: "/projects", label: "Projects", icon: svg(<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />) },
  { href: "/analyzer", label: "Analyzer", icon: svg(<><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></>) },
  { href: "/import", label: "Import", icon: svg(<><path d="M12 3v12" /><path d="m8 11 4 4 4-4" /><path d="M4 21h16" /></>) },
  { href: "/findings", label: "Findings", icon: svg(<><path d="M8 6h13M8 12h13M8 18h13" /><path d="M3 6h.01M3 12h.01M3 18h.01" /></>) },
  { href: "/reports", label: "Reports", icon: svg(<><path d="M14 3v5h5" /><path d="M6 3h8l5 5v11a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" /></>) },
  {
    href: "/settings",
    label: "Settings",
    icon: svg(
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 13.5a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 1 1-4 0v-.2a1.7 1.7 0 0 0-2.9-1.1l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.1-2.9H3a2 2 0 1 1 0-4h.2a1.7 1.7 0 0 0 1.1-2.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.2a1.7 1.7 0 0 0 2.9 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.2a1.7 1.7 0 0 0-1.4.5z" />
      </>
    ),
  },
];

export default function Nav() {
  const path = usePathname();
  const { data: session } = useSession();

  return (
    <aside className="w-60 shrink-0 bg-surface border-r border-border sticky top-0 h-screen p-4 flex flex-col">
      <div className="text-base mb-8 px-2 pt-1 tracking-wide">
        <span className="text-accent">&gt;</span> vapt<span className="text-accent">.</span>console
      </div>
      <nav className="flex flex-col gap-0.5">
        {items.map((it) => {
          const active = path === it.href;
          return (
            <Link
              key={it.href}
              href={it.href}
              className={`group flex items-center gap-2.5 px-2 py-1.5 rounded-lg text-sm tracking-wide transition-all ${
                active ? "bg-accent/10 text-accent" : "text-muted hover:text-text hover:bg-white/5"
              }`}
            >
              {/* The active route is marked with a prompt caret rather than a
                  filled pill, which is how a shell shows you where you are. */}
              <span className={`w-2 shrink-0 ${active ? "text-accent" : "text-transparent"}`}>&gt;</span>
              <span className={active ? "text-accent" : "group-hover:text-text transition-colors"}>{it.icon}</span>
              <span className="uppercase text-xs">{it.label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="mt-auto pt-4 border-t border-border/60 text-xs text-muted">
        <div className="truncate mb-2 px-1">{session?.user?.email}</div>
        <button
          className="tracking-wide hover:text-danger transition-colors px-1"
          onClick={() => {
            forgetSession();
            signOut();
          }}
        >
          [LOG OUT]
        </button>
      </div>
    </aside>
  );
}
