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
  _review?: ReviewSummary;
  _verdict?: VerdictResolution;
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

export interface LaneInfo {
  provider: string;
  base_url: string;
  models: string[];
  model: string;
  fallbacks: string[];
  key_configured: boolean;
  key_source: string;
  overridden: boolean;
}

export interface ReviewSummary {
  reviewed: boolean;
  unavailable: string;
  verdict: string;
  confidence: string;
  false_positive_risk: string;
  reviewer_severity: string;
  exploitability: string;
  reasoning: string;
  evidence_needed: string;
  severity_disagreement: boolean;
  grounding: string;
  injection: boolean;
  severity_mismatch: boolean;
  warnings: string[];
  cautions: string[];
  level: string;
}

export interface VerdictResolution {
  resolved_status: string;
  confidence: number;
  confidence_label: string;
  rationale: string;
  signals: Record<string, unknown>;
  auto_set: boolean;
}
