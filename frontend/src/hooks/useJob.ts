"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Job } from "@/lib/types";

// Polls a background job until it is done. Pass jobId=null to clear.
export function useJob(token: string | undefined, jobId: string | null): Job | null {
  const [job, setJob] = useState<Job | null>(null);

  useEffect(() => {
    if (!jobId) {
      setJob(null);
      return;
    }
    let active = true;
    const tick = async () => {
      try {
        const j = await api.getJob(token, jobId);
        if (!active) return;
        setJob(j);
        if (j.done) return;
      } catch {
        // keep polling through transient errors
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
