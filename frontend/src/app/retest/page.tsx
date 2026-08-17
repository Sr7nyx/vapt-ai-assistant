"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { RetestCampaign, RetestCandidate } from "@/lib/types";
import { useProject } from "@/lib/ProjectContext";
import { useToast } from "@/components/Toast";
import { Section, Figure } from "@/components/Terminal";
import { sevClass } from "@/components/Severity";
import { Skeleton } from "@/components/Loading";
import RetestModal from "@/components/RetestModal";

/**
 * Retest rounds.
 *
 * Retest data existed per finding, and there was no way to run a retest as a piece
 * of work: a tester opened findings one at a time and had to remember what they had
 * covered. This is the round as an activity -- what is left, what came back, and
 * what a client can be told.
 *
 * A round is derived from the findings rather than stored, so nothing here can drift
 * out of step with the findings it describes.
 */

const OUTCOME_TONE: Record<string, string> = {
  Fixed: "text-accent",
  "Partially Fixed": "text-warn",
  Open: "text-warn",
  Regressed: "text-danger",
  "Accepted Risk": "text-muted",
};

export default function RetestPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { projectId } = useProject();
  const { notify } = useToast();

  const [data, setData] = useState<RetestCampaign | null>(null);
  const [loading, setLoading] = useState(false);
  const [round, setRound] = useState<number | undefined>(undefined);
  const [target, setTarget] = useState<RetestCandidate | null>(null);

  const load = useCallback(() => {
    if (!token || !projectId) {
      setData(null);
      return;
    }
    setLoading(true);
    api
      .retestCampaign(token, projectId, round)
      .then(setData)
      .catch((e) => notify((e as Error).message, "error"))
      .finally(() => setLoading(false));
  }, [token, projectId, round, notify]);
  useEffect(() => load(), [load]);

  if (!projectId) {
    return (
      <div className="animate-in mx-auto w-full max-w-5xl">
        <div className="card text-muted text-sm">
          Select a project to see its retest rounds.
        </div>
      </div>
    );
  }

  if (loading && !data) {
    return (
      <div className="animate-in mx-auto w-full max-w-5xl">
        <Skeleton rows={5} />
      </div>
    );
  }
  if (!data) return null;

  const d = data.delta;
  const nothingToDo = data.total === 0;

  const record = async (payload: {
    retest_status: string;
    retester: string;
    retest_date: string;
    retest_evidence: string;
    note: string;
  }) => {
    if (!target) return;
    try {
      await api.retestFinding(token, target.id, payload);
      notify(`Recorded: ${target.title} — ${payload.retest_status}`, "success");
      setTarget(null);
      load();
    } catch (e) {
      notify((e as Error).message, "error");
    }
  };

  return (
    <div className="animate-in mx-auto w-full max-w-5xl grid gap-10">
      <Section
        title={`Round ${data.round}`}
        note="Derived from each finding's retest history, so it cannot drift out of step with them."
        actions={
          data.known_rounds.length > 1 ? (
            <div className="flex items-center gap-1">
              {data.known_rounds.map((r) => (
                <button
                  key={r.round}
                  onClick={() => setRound(r.round)}
                  aria-pressed={r.round === data.round}
                  className={`rounded border px-2 py-0.5 text-[10px] tracking-widest transition-colors ${
                    r.round === data.round
                      ? "border-accent/70 text-accent"
                      : "border-border text-muted hover:border-accent/50 hover:text-text"
                  }`}
                >
                  R{r.round}
                </button>
              ))}
            </div>
          ) : undefined
        }
      >
        {nothingToDo ? (
          <p className="measure text-sm text-muted">
            Nothing to retest. Every finding in this project is closed, or none has been
            committed yet.
          </p>
        ) : (
          <div className="grid gap-5">
            <div className="flex flex-wrap gap-x-10 gap-y-3">
              <Figure label="Covered" value={`${data.covered}/${data.total}`} tone="accent" />
              <Figure label="Coverage" value={`${data.coverage_pct}%`} />
              <Figure
                label="Remediated"
                value={`${d.remediation_pct}%`}
                tone={d.remediation_pct >= 60 ? "accent" : "warn"}
              />
              <Figure
                label="Regressed"
                value={d.regressed.length}
                tone={d.regressed.length ? "danger" : undefined}
              />
            </div>

            <div>
              <span className="block h-1.5 rounded-full bg-white/5 overflow-hidden">
                <span
                  className="grow-x block h-full rounded-full bg-accent/70"
                  style={{ width: `${data.coverage_pct}%` }}
                />
              </span>
              <p className="text-xs text-muted mt-1.5 measure">
                Remediation is measured against what was retested in this round, not against every
                finding, so an incomplete round is not reported as a poor remediation rate.
              </p>
            </div>
          </div>
        )}
      </Section>

      {d.regressed.length > 0 && (
        <Section
          title="Regressed"
          note="Previously closed, and back. This matters more than a finding that was never fixed."
        >
          <ul className="grid gap-1.5">
            {d.regressed.map((r) => (
              <li key={r.id} className="flex items-baseline gap-3 text-sm">
                <span className={sevClass(r.severity)}>[{r.severity}]</span>
                <span className="flex-1 min-w-0 truncate">{r.title}</span>
                <span className="text-xs text-muted shrink-0">{r.date}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {data.outstanding.length > 0 && (
        <Section
          title="Still to retest"
          note={`${data.outstanding.length} open in this round.`}
        >
          <ul className="grid gap-0">
            {data.outstanding.map((c) => (
              <li
                key={c.id}
                className="flex items-center gap-3 py-2 border-b border-border/40 last:border-0"
              >
                <span className={`${sevClass(c.severity)} shrink-0`}>[{c.severity}]</span>
                <span className="flex-1 min-w-0">
                  <span className="block truncate text-sm">{c.title}</span>
                  {c.affected_url && (
                    <span className="block truncate text-xs text-accent/70">{c.affected_url}</span>
                  )}
                </span>
                <span className="text-xs text-muted shrink-0 hidden sm:inline">{c.status}</span>
                <button className="btn-sm shrink-0" onClick={() => setTarget(c)}>
                  Record outcome
                </button>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {data.tested.length > 0 && (
        <Section title="Recorded this round">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-muted border-b border-border">
                <th className="font-normal text-[10px] tracking-widest pb-1.5">SEVERITY</th>
                <th className="font-normal text-[10px] tracking-widest pb-1.5">FINDING</th>
                <th className="font-normal text-[10px] tracking-widest pb-1.5">OUTCOME</th>
                <th className="font-normal text-[10px] tracking-widest pb-1.5">WHEN</th>
                <th className="font-normal text-[10px] tracking-widest pb-1.5">BY</th>
              </tr>
            </thead>
            <tbody>
              {data.tested.map((t) => (
                <tr key={t.id} className="border-b border-border/40 last:border-0">
                  <td className="py-1.5 pr-3">
                    <span className={sevClass(t.severity)}>{t.severity}</span>
                  </td>
                  <td className="py-1.5 pr-3 max-w-xs truncate">{t.title}</td>
                  <td className={`py-1.5 pr-3 ${OUTCOME_TONE[t.outcome] || ""}`}>{t.outcome}</td>
                  <td className="py-1.5 pr-3 text-muted whitespace-nowrap">{t.date}</td>
                  <td className="py-1.5 text-muted">{t.retester}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      {target && (
        <RetestModal
          title={target.title}
          onSubmit={record}
          onClose={() => setTarget(null)}
        />
      )}
    </div>
  );
}
