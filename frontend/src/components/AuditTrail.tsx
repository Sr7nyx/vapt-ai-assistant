"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { FindingEvent } from "@/lib/types";
import { Spinner } from "./Loading";

/** Who did it, in a form worth reading. Actors are stored prefixed so the source
 *  of a change is unambiguous: a person, the verdict engine, or a retester. */
function actorLabel(actor: string): { name: string; kind: "person" | "engine" | "retest" } {
  if (actor.startsWith("engine:")) return { name: "verdict engine", kind: "engine" };
  if (actor.startsWith("retester:")) return { name: actor.slice(9) || "retester", kind: "retest" };
  if (actor.startsWith("user:")) return { name: actor.slice(5), kind: "person" };
  return { name: actor || "unknown", kind: "person" };
}

const ACTION_LABEL: Record<string, string> = {
  created: "created",
  updated: "edited",
  status_changed: "status",
  retested: "retested",
  deleted: "deleted",
};

function tone(action: string): string {
  if (action === "status_changed") return "text-accent";
  if (action === "deleted") return "text-danger";
  if (action === "retested") return "text-warn";
  return "text-muted";
}

function when(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });
}

/** The recorded history of one finding.
 *
 *  Mounted only when a finding row is expanded, so the fetch is lazy by
 *  construction rather than needing a guard: nothing is requested for the
 *  hundreds of rows a project might hold. */
export default function AuditTrail({ findingId }: { findingId: number }) {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [events, setEvents] = useState<FindingEvent[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    if (!token) return;
    api
      .findingEvents(token, findingId)
      .then((rows) => alive && setEvents(rows))
      .catch((e) => alive && setError((e as Error).message));
    return () => {
      alive = false;
    };
  }, [token, findingId]);

  if (error) {
    return <p className="text-xs text-muted">History unavailable: {error}</p>;
  }
  if (!events) {
    return (
      <p className="text-xs text-muted flex items-center gap-2">
        <Spinner /> Loading history…
      </p>
    );
  }
  if (events.length === 0) {
    // Findings created before the trail existed have no rows, which is not an error.
    return <p className="text-xs text-muted">No recorded history for this finding.</p>;
  }

  return (
    <div className="grid gap-0">
      {events.map((e, i) => {
        const who = actorLabel(e.actor);
        const label = ACTION_LABEL[e.action] || e.action;
        const last = i === events.length - 1;
        return (
          <div key={e.id} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3">
            {/* Rail */}
            <div className="flex flex-col items-center">
              <span className={`mt-1.5 h-1.5 w-1.5 rounded-full shrink-0 ${
                e.action === "status_changed" ? "bg-accent"
                : e.action === "deleted" ? "bg-danger"
                : e.action === "retested" ? "bg-warn"
                : "bg-muted/60"
              }`} />
              {!last && <span className="w-px flex-1 bg-border/70" />}
            </div>

            <div className={last ? "" : "pb-3"}>
              <div className="flex flex-wrap items-baseline gap-x-2 text-xs">
                <span className={tone(e.action)}>{label}</span>
                {e.field && e.action !== "created" && (
                  <span className="text-muted">{e.field}</span>
                )}
                {e.action !== "created" && e.action !== "deleted" && (e.old_value || e.new_value) && (
                  <span className="font-mono">
                    <span className="text-muted">{e.old_value || "empty"}</span>
                    <span className="text-border"> -&gt; </span>
                    <span>{e.new_value || "empty"}</span>
                  </span>
                )}
                {e.action === "created" && e.new_value && (
                  <span className="font-mono">{e.new_value}</span>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-x-2 text-[11px] text-muted mt-0.5">
                <span className={who.kind === "engine" ? "text-suspect" : ""}>{who.name}</span>
                <span className="text-border">.</span>
                <span>{when(e.created_at)}</span>
              </div>

              {e.rationale && (
                <p className="text-[11px] text-muted mt-1 whitespace-pre-wrap border-l border-border/60 pl-2">
                  {e.rationale}
                </p>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
