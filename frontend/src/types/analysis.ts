export type AnalysisStatus = "queued" | "running" | "completed" | "failed";

export interface AnalysisScores {
  r_sast: number;
  r_dast: number;
  r_comp: number;
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

export interface AnalysisRemediation {
  original?: string;
  patch?: string;
}

export interface AnalysisPayload {
  status?: AnalysisStatus;
  scores?: AnalysisScores;
  findings?: AnalysisFinding[];
  summary?: string;
  remediation?: AnalysisRemediation;
}
