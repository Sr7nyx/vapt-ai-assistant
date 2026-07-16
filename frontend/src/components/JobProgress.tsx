"use client";
import { Job } from "@/lib/types";

export default function JobProgress({ job }: { job: Job | null }) {
  if (!job || job.done) return null;
  return (
    <div className="my-4">
      <div className="h-2 bg-white/10 rounded overflow-hidden">
        <div className="h-full bg-accent transition-all" style={{ width: `${Math.round((job.progress || 0) * 100)}%` }} />
      </div>
      <div className="text-xs text-muted mt-1">{job.stage}</div>
    </div>
  );
}
