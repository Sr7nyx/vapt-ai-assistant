export interface Project {
  id: number;
  name: string;
  client?: string;
  scope?: string;
  tester?: string;
  start_date?: string;
  end_date?: string;
  created_at?: string;
}

export interface Finding {
  id: number;
  title: string;
  severity: string;
  cwe?: string;
  cvss?: string;
  status?: string;
  affected_host?: string;
  affected_url?: string;
  description?: string;
  additional_remarks?: string;
  _assessment?: { risk?: { priority?: string; score?: number }; frameworks?: Record<string, string> };
  [k: string]: unknown;
}

export interface Job {
  id: string;
  status: string;
  progress: number;
  stage: string;
  result?: unknown;
  error?: string;
  done: boolean;
}

export interface Overview {
  projects: number;
  findings: number;
  critical: number;
  high: number;
  by_severity: { label: string; count: number }[];
  by_status: { label: string; count: number }[];
  by_category: { label: string; count: number }[];
  risk_priorities: Record<string, number>;
  owasp_coverage: { label: string; count: number }[];
  qa_flags: number;
  usage: {
    calls: number;
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
    by_model: { model: string; calls: number; total_tokens: number }[];
  };
}
