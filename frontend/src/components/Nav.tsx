"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";

const items = [
  { href: "/", label: "Overview" },
  { href: "/projects", label: "Projects" },
  { href: "/analyzer", label: "Analyzer" },
  { href: "/import", label: "Import" },
  { href: "/findings", label: "Findings" },
  { href: "/reports", label: "Reports" },
  { href: "/settings", label: "Settings" },
];

export default function Nav() {
  const path = usePathname();
  const { data: session } = useSession();

  return (
    <aside className="w-56 shrink-0 bg-surface border-r border-border min-h-screen p-4 flex flex-col">
      <div className="font-semibold text-lg mb-6">
        vapt<span className="text-accent">.</span>console
      </div>
      <nav className="flex flex-col gap-1">
        {items.map((it) => (
          <Link
            key={it.href}
            href={it.href}
            className={`px-3 py-2 rounded-lg text-sm ${
              path === it.href ? "bg-accent/15 text-accent" : "text-muted hover:text-text hover:bg-white/5"
            }`}
          >
            {it.label}
          </Link>
        ))}
      </nav>
      <div className="mt-auto pt-4 text-xs text-muted">
        <div className="truncate mb-2">{session?.user?.email}</div>
        <button className="hover:text-danger" onClick={() => signOut()}>
          Sign out
        </button>
      </div>
    </aside>
  );
}
