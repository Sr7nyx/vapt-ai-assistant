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
  _verification?: Verification;
  [k: string]: unknown;
}

export interface Job {
  id: string;
  status: string;
  progress: number;
  stage: string;
  /** Every stage message in order. Accumulated server-side, because stages can
   *  pass faster than the client polls. */
  log?: string[];
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

export interface FindingEvent {
  id: number;
  actor: string;
  action: string;
  field: string;
  old_value: string;
  new_value: string;
  rationale: string;
  created_at: string;
}

export interface UsageSummary {
  calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  by_model: { model: string; calls: number; total_tokens: number }[];
  window?: string;
}

export interface VerificationCheck {
  status: string;
  verifier: string;
  detail: string;
  evidence: string;
  /** Which HTTP exchange this check ran against. */
  exchange_id?: string;
}

export interface Verification {
  status: string;
  checks: VerificationCheck[];
  summary: string;
  /** The exchange the finding was bound to, and how many were in the evidence.
   *  Empty when the finding could not be tied to one. */
  exchange_id?: string;
  exchange_count?: number;
}

export interface ScanDelta {
  new: number;
  regressed: number;
  unchanged: number;
  reappraised: number;
  absent: number;
}

export interface AbsentFinding {
  id: number;
  title: string;
  severity: string;
  status: string;
  affected_url?: string;
}

export interface JobHistoryRow {
  id: string;
  project_id?: number | null;
  kind: string;
  status: string;
  progress: number;
  stage: string;
  error?: string;
  finding_count: number;
  total_tokens: number;
  created_at: string;
  finished_at?: string | null;
}

export interface JobHistoryRow {
  id: string;
  project_id?: number | null;
  kind: string;
  status: string;
  progress: number;
  stage: string;
  error?: string;
  finding_count: number;
  total_tokens: number;
  created_at: string;
  finished_at?: string | null;
}

export interface RetestOutcome {
  id: number;
  title: string;
  severity: string;
  outcome: string;
  date: string;
  retester: string;
  note: string;
}

export interface RetestCandidate {
  id: number;
  title: string;
  severity: string;
  status: string;
  affected_url?: string;
}

export interface RetestDelta {
  round: number;
  coverage_pct: number;
  fixed: RetestOutcome[];
  still_open: RetestOutcome[];
  regressed: RetestOutcome[];
  accepted: RetestOutcome[];
  outstanding: RetestCandidate[];
  remediation_pct: number;
  tested_count: number;
}

export interface RetestCampaign {
  round: number;
  known_rounds: { round: number; count: number; first_date: string; last_date: string; testers: string[] }[];
  tested: RetestOutcome[];
  outstanding: RetestCandidate[];
  tally: Record<string, number>;
  total: number;
  covered: number;
  coverage_pct: number;
  delta: RetestDelta;
  candidates: RetestCandidate[];
  outcomes: Record<string, string>;
}

export interface AttackTactic {
  tactic: string;
  tactic_name: string;
  techniques: { id: string; name: string; count: number }[];
  count: number;
}

export interface AttackCoverage {
  tactics: AttackTactic[];
  unmapped: number;
}

export interface CalibrationBucket {
  claimed: number;
  observed: number;
  n: number;
  overturned: number;
  reliable: boolean;
  gap: number;
}

export interface LearningSummary {
  calibration: {
    buckets: CalibrationBucket[];
    samples: number;
    corrections: number;
    calibration_error: number | null;
    verdict: string;
  };
  priors: {
    title: string;
    dismissed: number;
    upheld: number;
    rate: number;
    last_seen: string;
  }[];
  findings_considered: number;
}
