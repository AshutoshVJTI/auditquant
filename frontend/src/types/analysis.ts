export type AnalysisStatus = "queued" | "pending" | "running" | "completed" | "failed";

export interface AnalysisScores {
  r_sast: number;
  r_dast: number;
  r_comp: number;
  composite: number;
}

export interface AnalysisFinding {
  id: string;
  title: string;
  impact: string;
  confidence: string;
  description: string;
  loss_percentage?: number | null;
  location?: string | null;
  source: string;
}

export interface VerificationInfo {
  status: string;
  hallucination_rate: number;
}

export interface ToolResultSummary {
  tool: string;
  finding_count: number;
  error: string | null;
  execution_time_ms: number;
}

export interface BusinessRiskInfo {
  avg_rubric_score: number;
  max_rubric_score: number;
  total_findings_assessed: number;
  consensus_rate: number;
}

export interface AnalysisPayload {
  analysis_id?: string;
  filename?: string;
  status?: AnalysisStatus;
  defi_category?: string | null;
  scores?: AnalysisScores;
  total_findings?: number;
  cross_validated_count?: number;
  findings?: AnalysisFinding[];
  verification?: VerificationInfo;
  summary?: string;
  /** Set when the LLM summary was skipped or failed (e.g. missing OPENAI_API_KEY). */
  summary_error?: string | null;
  loss_percentage?: number;
  tool_results?: ToolResultSummary[];
  total_execution_time_ms?: number;
  business_risk?: BusinessRiskInfo;
  error?: string | null;
}
