"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Job } from "@/lib/types";

// Polls a background job until done. Reconnects to an already-running job when
// given its id. If the job can't be reached for several tries (e.g. the server
// restarted and dropped it), it resolves to an error instead of polling forever.
export function useJob(token: string | undefined, jobId: string | null): Job | null {
  const [job, setJob] = useState<Job | null>(null);

  useEffect(() => {
    if (!jobId) {
      setJob(null);
      return;
    }
    let active = true;
    let fails = 0;
    const tick = async () => {
      try {
        const j = await api.getJob(token, jobId);
        if (!active) return;
        fails = 0;
        setJob(j);
        if (j.done) return;
      } catch {
        fails += 1;
        if (fails >= 5) {
          if (active)
            setJob({ id: jobId, status: "error", progress: 0, stage: "", error: "Lost connection to the job (it may have expired).", done: true });
          return;
        }
      }
      if (active) setTimeout(tick, 1500);
    };
    tick();
    return () => {
      active = false;
    };
  }, [token, jobId]);

  return job;
}
