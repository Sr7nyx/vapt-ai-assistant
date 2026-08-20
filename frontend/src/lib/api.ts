import {
  Project,
  Finding,
  Job,
  Overview,
  LaneInfo,
  FindingEvent,
  UsageSummary,
  JobHistoryRow,
  RetestCampaign,
  AttackCoverage,
  LearningSummary,
} from "./types";

const BASE = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/+$/, "");

function jsonHeaders(token: string | undefined): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (token) h["Authorization"] = `Bearer ${token}`;
  return h;
}

/** An API error that keeps the HTTP status and any structured detail, so callers
 *  can react to specific conditions (a 429 demo limit, say) instead of matching
 *  on message strings. */
export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/** FastAPI puts errors in `detail`, which may be a string or an object. */
function readError(status: number, raw: string): ApiError {
  try {
    const parsed = JSON.parse(raw);
    const detail = parsed?.detail ?? parsed;
    const message =
      typeof detail === "string" ? detail : detail?.message || raw || `HTTP ${status}`;
    return new ApiError(status, message, detail);
  } catch {
    return new ApiError(status, raw || `HTTP ${status}`);
  }
}

async function req<T>(token: string | undefined, method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: jsonHeaders(token),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw readError(res.status, await res.text());
  const ct = res.headers.get("content-type") || "";
  return (ct.includes("application/json") ? await res.json() : ((await res.text()) as unknown)) as T;
}

export const api = {
  me: (t: string | undefined) => req<{ id: string; email: string }>(t, "GET", "/me"),
  usage: (t: string | undefined, window = "all") =>
    req<UsageSummary>(t, "GET", `/usage?window=${encodeURIComponent(window)}`),
  overview: (t: string | undefined) => req<Overview>(t, "GET", "/overview"),
  demoQuota: (t: string | undefined) =>
    req<{ limit: number; used: number; remaining: number; window_hours: number }>(t, "GET", "/demo/quota"),

  llmProviders: (t: string | undefined) => req<{ allowed_hosts: string[] }>(t, "GET", "/llm/providers"),
  precheck: (t: string | undefined, raw_input: string) =>
    req<{ ok: boolean; reason: string; signals: string[]; score: number; chars: number }>(
      t, "POST", "/llm/precheck", { raw_input }
    ),
  llmLanes: (t: string | undefined, body: { lane_config?: unknown }) =>
    req<{ lanes: Record<string, LaneInfo> }>(t, "POST", "/llm/lanes", body),
  llmModels: (t: string | undefined, body: { base_url: string; api_key: string }) =>
    req<{ models: string[] }>(t, "POST", "/llm/models", body),
  llmTest: (
    t: string | undefined,
    body: { base_url: string; api_key: string; model: string; lane?: string; lane_config?: unknown }
  ) =>
    req<{ ok: boolean; model: string; reply?: string; error?: string }>(t, "POST", "/llm/test", body),

  listProjects: (t: string | undefined) => req<Project[]>(t, "GET", "/projects"),
  createProject: (t: string | undefined, body: Partial<Project>) => req<Project>(t, "POST", "/projects", body),
  getProject: (t: string | undefined, id: number) => req<Project>(t, "GET", `/projects/${id}`),
  deleteProject: (t: string | undefined, id: number) => req<unknown>(t, "DELETE", `/projects/${id}`),

  listFindings: (t: string | undefined, pid: number) => req<Finding[]>(t, "GET", `/projects/${pid}/findings`),
  createFinding: (t: string | undefined, pid: number, data: unknown) => req<{ id: number }>(t, "POST", `/projects/${pid}/findings`, { data }),
  commitCandidates: (t: string | undefined, pid: number, candidates: unknown[]) =>
    req<{ committed: number; skipped: number }>(t, "POST", `/projects/${pid}/findings/commit`, { candidates }),
  updateFinding: (t: string | undefined, id: number, data: unknown) => req<unknown>(t, "PATCH", `/findings/${id}`, { data }),
  deleteFinding: (t: string | undefined, id: number) => req<unknown>(t, "DELETE", `/findings/${id}`),
  bulkDeleteFindings: (t: string | undefined, ids: number[]) =>
    req<{ deleted: number; missing: number }>(t, "POST", "/findings/bulk-delete", { ids }),
  findingEvents: (t: string | undefined, id: number) =>
    req<FindingEvent[]>(t, "GET", `/findings/${id}/events`),
  learningSummary: (t: string | undefined) => req<LearningSummary>(t, "GET", "/learning"),
  listJobs: (t: string | undefined) => req<JobHistoryRow[]>(t, "GET", "/jobs"),
  retestCampaign: (t: string | undefined, pid: number, round?: number) =>
    req<RetestCampaign>(t, "GET", `/projects/${pid}/retest${round ? `?round=${round}` : ""}`),
  attackCoverage: (t: string | undefined, pid: number) =>
    req<AttackCoverage>(t, "GET", `/projects/${pid}/attack`),
  retestFinding: (t: string | undefined, id: number, body: unknown) => req<unknown>(t, "POST", `/findings/${id}/retest`, body),

  analyze: (t: string | undefined, body: unknown) => req<{ job_id: string }>(t, "POST", "/analyze", body),
  scanTriage: (t: string | undefined, body: unknown) => req<{ job_id: string }>(t, "POST", "/scan/triage", body),
  getJob: (t: string | undefined, id: string) => req<Job>(t, "GET", `/jobs/${id}`),

  scanParse: async (t: string | undefined, files: FileList | File[], projectId?: number | null) => {
    const fd = new FormData();
    Array.from(files).forEach((f) => fd.append("files", f));
    // Sent so the backend can compare against what the project already holds.
    if (projectId) fd.append("project_id", String(projectId));
    const res = await fetch(`${BASE}/scan/parse`, {
      method: "POST",
      headers: t ? { Authorization: `Bearer ${t}` } : {},
      body: fd,
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  exportReport: async (t: string | undefined, pid: number, body: { fmt: string; exec_summary: string; methodology: string; finding_ids?: number[] }) => {
    const res = await fetch(`${BASE}/projects/${pid}/report`, {
      method: "POST",
      headers: jsonHeaders(t),
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(await res.text());
    const blob = await res.blob();
    const cd = res.headers.get("content-disposition") || "";
    const m = cd.match(/filename="?([^"]+)"?/);
    return { blob, filename: m ? m[1] : `report.${body.fmt}` };
  },
};
