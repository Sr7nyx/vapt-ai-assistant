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
