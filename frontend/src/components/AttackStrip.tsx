"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { AttackCoverage } from "@/lib/types";

/**
 * ATT&CK coverage, by tactic.
 *
 * Ordered by attack phase rather than by finding count. Sorting by frequency would
 * put Discovery above Initial Access almost always, since information-disclosure
 * findings outnumber everything -- and a kill chain out of order tells a reader
 * nothing.
 *
 * The caveat is printed rather than left implicit. Web weaknesses map imperfectly
 * onto a framework built for post-compromise endpoint behaviour, and a mapping
 * shown without that reads as more precise than it is.
 */
export default function AttackStrip({ projectId }: { projectId: number | null }) {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [data, setData] = useState<AttackCoverage | null>(null);

  useEffect(() => {
    if (!token || !projectId) {
      setData(null);
      return;
    }
    let alive = true;
    api
      .attackCoverage(token, projectId)
      .then((r) => alive && setData(r))
      .catch(() => alive && setData(null));
    return () => {
      alive = false;
    };
  }, [token, projectId]);

  if (!projectId) {
    return (
      <p className="text-sm text-muted">
        Select a project to see which phases of an attack its findings sit in.
      </p>
    );
  }
  if (!data) return <p className="text-sm text-muted">Loading coverage…</p>;
  if (data.tactics.length === 0) {
    return (
      <p className="measure text-sm text-muted">
        No finding in this project maps to a technique yet.
        {data.unmapped > 0 && (
          <>
            {" "}
            {data.unmapped} could not be mapped and are left unassigned rather than given a
            nearest match.
          </>
        )}
      </p>
    );
  }

  const max = Math.max(...data.tactics.map((t) => t.count), 1);

  return (
    <div className="grid gap-4">
      <div className="grid gap-2.5">
        {data.tactics.map((t) => (
          <div key={t.tactic} className="grid sm:grid-cols-[11rem_minmax(0,1fr)] gap-x-4 gap-y-1">
            <div className="flex items-baseline gap-2 min-w-0">
              <span className="text-sm truncate">{t.tactic_name}</span>
              <span className="text-xs text-muted tabular-nums shrink-0">{t.count}</span>
            </div>
            <div className="min-w-0">
              <span className="block h-1 rounded-full bg-white/5 overflow-hidden mb-1.5">
                <span
                  className="grow-x block h-full rounded-full bg-accent/60"
                  style={{ width: `${(t.count / max) * 100}%` }}
                />
              </span>
              <span className="flex flex-wrap gap-1.5">
                {t.techniques.map((e) => (
                  <span key={e.id} className="chip" title={e.name}>
                    {e.id}
                    {e.count > 1 && <span className="text-muted"> &times;{e.count}</span>}
                  </span>
                ))}
              </span>
            </div>
          </div>
        ))}
      </div>

      <p className="measure text-xs text-muted">
        Each finding is counted once, against the primary technique for its weakness class.
        {data.unmapped > 0 && (
          <>
            {" "}
            {data.unmapped} finding{data.unmapped === 1 ? "" : "s"} could not be mapped and{" "}
            {data.unmapped === 1 ? "is" : "are"} excluded rather than assigned a nearest match.
          </>
        )}{" "}
        ATT&amp;CK describes post-compromise behaviour on endpoints, so this is indicative
        context rather than observed adversary activity.
      </p>
    </div>
  );
}
