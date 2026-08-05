"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { LaneInfo } from "@/lib/types";
import { buildLaneConfig } from "@/lib/prefs";
import { Spinner } from "./Loading";

type Health = "unknown" | "checking" | "ok" | "failed";

const LANES: { key: string; label: string; hint: string }[] = [
  { key: "MAIN", label: "Extraction", hint: "Reads the evidence and drafts findings" },
  { key: "REVIEW", label: "Reviewer", hint: "Audits each finding against its evidence" },
];

export default function LaneStatus({ activeLane }: { activeLane?: "MAIN" | "REVIEW" | null } = {}) {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [lanes, setLanes] = useState<Record<string, LaneInfo> | null>(null);
  const [health, setHealth] = useState<Record<string, Health>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [open, setOpen] = useState(false);

  const load = useCallback(() => {
    if (!token) return;
    api
      .llmLanes(token, { lane_config: buildLaneConfig() })
      .then((r) => setLanes(r.lanes))
      .catch(() => setLanes(null));
  }, [token]);
  useEffect(() => load(), [load]);

  // Liveness is checked on request, not on load: each check is a real API call,
  // and firing two of them every time this page mounts would spend quota to
  // display a green dot.
  const check = async (key: string, info: LaneInfo) => {
    setHealth((h) => ({ ...h, [key]: "checking" }));
    setErrors((e) => ({ ...e, [key]: "" }));
    try {
      // Name the lane and pass the same overrides the pipeline receives, so the
      // key is resolved for THIS lane rather than defaulting to the extraction
      // provider's credential.
      const r = await api.llmTest(token, {
        base_url: info.base_url,
        api_key: "",
        model: info.model,
        lane: key,
        lane_config: buildLaneConfig(),
      });
      setHealth((h) => ({ ...h, [key]: r.ok ? "ok" : "failed" }));
      if (!r.ok) setErrors((e) => ({ ...e, [key]: r.error || "unknown error" }));
    } catch (e) {
      setHealth((h) => ({ ...h, [key]: "failed" }));
      setErrors((err) => ({ ...err, [key]: (e as Error).message }));
    }
  };

  const checkAll = () => {
    if (!lanes) return;
    LANES.forEach(({ key }) => lanes[key] && check(key, lanes[key]));
  };

  if (!lanes) return null;

  const bothSameProvider = lanes.MAIN?.provider === lanes.REVIEW?.provider;

  return (
    <div className="border border-border rounded-xl mb-4 text-sm">
      <div className="flex items-center gap-3 px-4 py-2.5">
        <span className="text-muted text-xs uppercase tracking-wide shrink-0">Models</span>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 flex-1 min-w-0">
          {LANES.map(({ key, label }) => {
            const info = lanes[key];
            if (!info) return null;
            // Which lane is doing the work right now. Derived from the job's own
            // progress, so it is a report rather than an animation: the reviewer
            // genuinely is the expensive half, and seeing it light up explains
            // where the time is going.
            const working = activeLane === key;
            return (
              <span
                key={key}
                className={`flex items-center gap-1.5 min-w-0 rounded px-1.5 -mx-1.5 transition-colors ${
                  working ? "bg-highlight/10" : ""
                }`}
              >
                {working ? (
                  <span className="pulse-ring inline-block w-2 h-2 rounded-full bg-highlight shrink-0" />
                ) : (
                  <Dot state={health[key] || "unknown"} />
                )}
                <span className="text-muted">{label}</span>
                <span className="font-mono text-xs truncate">{info.model || "not set"}</span>
                <span className="text-muted text-xs">on {info.provider}</span>
              </span>
            );
          })}
        </div>
        <button className="text-xs text-muted hover:text-text shrink-0" onClick={() => setOpen((v) => !v)}>
          {open ? "Hide" : "Details"}
        </button>
        <button className="btn-sm text-xs shrink-0" onClick={checkAll}>
          Check
        </button>
      </div>

      {open && (
        <div className="border-t border-border/60 px-4 py-3 grid gap-3">
          {LANES.map(({ key, label, hint }) => {
            const info = lanes[key];
            if (!info) return null;
            const state = health[key] || "unknown";
            return (
              <div key={key} className="grid gap-1">
                <div className="flex items-center gap-2">
                  <Dot state={state} />
                  <span className="font-medium">{label}</span>
                  <span className="text-muted text-xs">{hint}</span>
                </div>
                <div className="text-xs text-muted pl-4 grid gap-0.5">
                  <span>
                    Provider <span className="text-text">{info.provider}</span> | model{" "}
                    <span className="text-text font-mono">{info.model || "not set"}</span>
                  </span>
                  {info.fallbacks.length > 0 && (
                    <span>Falls back to <span className="font-mono">{info.fallbacks.join(", ")}</span> if unavailable</span>
                  )}
                  <span>
                    Key: <span className="text-text">{info.key_source}</span>
                    {info.overridden ? " (configured in Settings)" : ""}
                  </span>
                  {state === "failed" && errors[key] && <span className="text-danger">{errors[key]}</span>}
                  {state === "ok" && <span className="text-accent">Responded successfully.</span>}
                </div>
              </div>
            );
          })}
          {bothSameProvider && (
            <p className="text-xs text-muted border-t border-border/60 pt-2">
              Both lanes are on {lanes.MAIN.provider}, so they share one quota. Pointing the reviewer at a
              different provider gives each lane its own allowance.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function Dot({ state }: { state: Health }) {
  if (state === "checking") return <Spinner className="text-muted" />;
  const color =
    state === "ok" ? "bg-accent" : state === "failed" ? "bg-danger" : "bg-muted/50";
  const title =
    state === "ok" ? "Responded" : state === "failed" ? "Failed" : "Not checked yet";
  return <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${color}`} title={title} />;
}
