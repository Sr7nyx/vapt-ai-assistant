"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { Project } from "@/lib/types";

export default function Dashboard() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const [usage, setUsage] = useState<Record<string, number> | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    if (!token) return;
    api.usage(token).then(setUsage).catch(() => {});
    api.listProjects(token).then(setProjects).catch(() => {});
  }, [token]);

  return (
    <div className="animate-in">
      <h1 className="text-2xl font-semibold mb-6">Overview</h1>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8 stagger">
        <Stat label="Projects" value={projects.length} />
        <Stat label="LLM calls" value={usage?.calls ?? "-"} />
        <Stat label="Tokens used" value={usage?.total_tokens ?? "-"} />
      </div>
      <p className="text-muted text-sm">
        Use the Analyzer to extract findings from raw evidence, or Import to bring in scanner output
        (Burp, Nessus, ZAP, Nmap, CSV) and run AI triage before committing to a project.
      </p>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="card card-hover">
      <div className="text-muted text-sm">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
    </div>
  );
}
