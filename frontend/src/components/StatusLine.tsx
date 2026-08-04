"use client";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { Overview } from "@/lib/types";

/**
 * Persistent status line under the tabs.
 *
 * A console tells you the state of the system at all times rather than making you
 * navigate to a dashboard to find out. These are real aggregates, refetched when
 * the route changes so committing findings on one page updates the counts
 * everywhere.
 */
export default function StatusLine() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const path = usePathname();
  const [data, setData] = useState<Overview | null>(null);

  useEffect(() => {
    if (!token) return;
    let alive = true;
    api
      .overview(token)
      .then((r) => alive && setData(r))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [token, path]);

  if (!data) return null;
  const critHigh = data.critical + data.high;

  return (
    <div className="flex items-center gap-x-4 gap-y-1 flex-wrap px-4 py-1.5 text-[11px] tracking-wide border-b border-border/60 bg-surface/40">
      <Cell label="PROJECTS" value={data.projects} />
      <Sep />
      <Cell label="FINDINGS" value={data.findings} />
      <Sep />
      <Cell label="CRIT/HIGH" value={critHigh} tone={critHigh > 0 ? "danger" : undefined} />
      <Sep />
      <Cell label="FLAGGED" value={data.qa_flags} tone={data.qa_flags > 0 ? "warn" : undefined} />
      <Sep />
      <Cell label="TOKENS" value={data.usage.total_tokens.toLocaleString()} />
      <div className="flex-1" />
      <span className="flex items-center gap-1.5 text-muted">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent" />
        CONNECTED
      </span>
    </div>
  );
}

function Cell({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "danger" | "warn";
}) {
  const color = tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : "text-text";
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-muted">{label}:</span>
      <span className={color}>{value}</span>
    </span>
  );
}

function Sep() {
  return <span className="text-border select-none">|</span>;
}
