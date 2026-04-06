import { useEffect, useRef, useState } from "react";
import { HELP } from "../content/resultsFieldHelp";
import ExecutiveSummaryMarkdown from "./ExecutiveSummaryMarkdown";
import { LabelWithInfo, SectionTitleWithInfo, ThWithInfo } from "./InfoHint";

interface ResultsProps {
  apiBase: string;
  analysisId: string | null;
  data: any;
  onData: (payload: any) => void;
}

function kv(value: unknown, digits = 3): string {
  if (typeof value !== "number" || Number.isNaN(value)) return "-";
  return value.toFixed(digits);
}

function pct(value: unknown, digits = 1): string {
  if (typeof value !== "number" || Number.isNaN(value)) return "-";
  return `${(value * 100).toFixed(digits)}%`;
}

export default function Results({ apiBase, analysisId, data, onData }: ResultsProps) {
  const [error, setError] = useState<string | null>(null);
  /** True until the analysis completes, fails, or errors — start true to avoid an empty-results flash. */
  const [loading, setLoading] = useState(true);
  const onDataRef = useRef(onData);
  onDataRef.current = onData;

  useEffect(() => {
    if (!analysisId) return;

    let cancelled = false;
    let attempts = 0;
    const POLL_INTERVAL_MS = 5000;
    const MAX_ATTEMPTS = 90;

    setLoading(true);
    setError(null);

    const poll = async () => {
      attempts++;
      if (!cancelled) setLoading(true);
      try {
        const response = await fetch(`${apiBase}/api/analysis/${analysisId}`);
        if (response.status === 202) {
          if (cancelled) return;
          onDataRef.current({ status: "pending" });
          setTimeout(poll, POLL_INTERVAL_MS);
          return;
        }

        const payload = await response.json();
        if (cancelled) return;
        onDataRef.current(payload);

        if (response.ok && payload.status === "completed") {
          setLoading(false);
          return;
        }
        if (response.ok && payload.status === "failed") {
          setError(payload.error || "Analysis failed");
          setLoading(false);
          return;
        }
        if (!response.ok) {
          setError(payload.detail || `Request failed: ${response.status}`);
          setLoading(false);
          return;
        }
        if (attempts >= MAX_ATTEMPTS) {
          setError("Analysis timed out.");
          setLoading(false);
          return;
        }
        setTimeout(poll, POLL_INTERVAL_MS);
      } catch (err: any) {
        if (!cancelled) {
          setError(err.message);
          setLoading(false);
        }
      }
    };

    poll();
    return () => {
      cancelled = true;
    };
  }, [analysisId, apiBase]);

  if (!analysisId) {
    return (
      <div className="card rounded-lg p-6">
        <p className="text-sm text-slate-700">Upload a Solidity file to start analysis.</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card rounded-lg p-6">
        <p className="text-sm text-red-700">{error}</p>
      </div>
    );
  }

  if (loading) {
    return (
      <section className="card flex min-h-[420px] flex-col items-center justify-center gap-5 rounded-xl px-8 py-16 text-center">
        <div
          className="h-14 w-14 rounded-full border-2 border-slate-200 border-t-slate-700 animate-spin"
          aria-hidden
        />
        <div className="space-y-2">
          <h2 className="text-xl font-semibold text-slate-900">Analyzing contract</h2>
          <p className="max-w-md text-sm text-slate-600">
            Running Slither, Slitherin, Semgrep, Mythril, and CodeBERT. Summarization runs when tools finish.
          </p>
          <p className="text-xs text-slate-500">This can take a few minutes. You can leave this page open.</p>
        </div>
      </section>
    );
  }

  const isCurrentPayload = data?.analysis_id === analysisId;
  const viewData = isCurrentPayload ? data : null;
  const findings = viewData?.findings || [];
  const toolResults = viewData?.tool_results || [];
  const scores = viewData?.scores;

  return (
    <section className="space-y-4 text-slate-800">
      <div className="card rounded-lg p-5">
        <h2 className="text-xl font-semibold text-slate-900">Analysis Result</h2>
        <div className="mt-3 grid gap-2 text-sm md:grid-cols-3">
          <p>
            <span className="text-slate-600">Status:</span>{" "}
            <span className="font-semibold text-slate-900">{loading ? "running" : viewData?.status ?? "pending"}</span>
          </p>
          <p>
            <span className="text-slate-600">Analysis ID:</span>{" "}
            <span className="font-mono text-slate-900">{analysisId}</span>
          </p>
          <p>
            <span className="text-slate-600">Execution Time:</span>{" "}
            <span className="font-semibold text-slate-900">{viewData?.total_execution_time_ms ? `${(viewData.total_execution_time_ms / 1000).toFixed(2)}s` : "-"}</span>
          </p>
          <p>
            <span className="text-slate-600">DeFi Category:</span>{" "}
            <span className="font-semibold text-slate-900">{viewData?.defi_category ?? "-"}</span>
          </p>
          <p>
            <span className="text-slate-600">Findings:</span>{" "}
            <span className="font-semibold text-slate-900">{viewData?.total_findings ?? findings.length}</span>
          </p>
          <p>
            <span className="text-slate-600">Cross-validated:</span>{" "}
            <span className="font-semibold text-slate-900">{viewData?.cross_validated_count ?? "-"}</span>
          </p>
        </div>
      </div>

      {scores && (
        <div className="card rounded-lg p-5">
          <SectionTitleWithInfo title="Risk Scores" info="Loosely 0–100 scores from the analyzers, how complex the code is, and CodeBERT. They’re a signal meter, not a dollar figure." />
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[640px] border-collapse text-sm">
              <thead>
                <tr className="bg-slate-100">
                  <ThWithInfo info={HELP.rSast}>R_SAST</ThWithInfo>
                  <ThWithInfo info={HELP.rDast}>R_DAST</ThWithInfo>
                  <ThWithInfo info={HELP.rComp}>R_COMP</ThWithInfo>
                  <ThWithInfo info={HELP.rModel}>R_MODEL</ThWithInfo>
                  <ThWithInfo info={HELP.composite}>Composite</ThWithInfo>
                  <ThWithInfo info={HELP.lossPct}>Loss %</ThWithInfo>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="border border-slate-200 px-3 py-2">{kv(scores.r_sast, 2)}</td>
                  <td className="border border-slate-200 px-3 py-2">{kv(scores.r_dast, 2)}</td>
                  <td className="border border-slate-200 px-3 py-2">{kv(scores.r_comp, 2)}</td>
                  <td className="border border-slate-200 px-3 py-2">{kv(scores.r_model, 4)}</td>
                  <td className="border border-slate-200 px-3 py-2 font-semibold text-slate-900">{kv(scores.composite, 4)}</td>
                  <td className="border border-slate-200 px-3 py-2">{typeof viewData?.loss_percentage === "number" ? `${viewData.loss_percentage.toFixed(2)}%` : "-"}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {toolResults.length > 0 && (
        <div className="card rounded-lg p-5">
          <h3 className="text-lg font-semibold text-slate-900">Tool Diagnostics</h3>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[740px] border-collapse text-sm">
              <thead>
                <tr className="bg-slate-100">
                  <th className="border border-slate-200 px-3 py-2 text-left align-middle font-medium text-slate-800">Tool</th>
                  <th className="border border-slate-200 px-3 py-2 text-left align-middle font-medium text-slate-800">Findings</th>
                  <th className="border border-slate-200 px-3 py-2 text-left align-middle font-medium text-slate-800">Time (s)</th>
                  <th className="border border-slate-200 px-3 py-2 text-left align-middle font-medium text-slate-800">Error</th>
                </tr>
              </thead>
              <tbody>
                {toolResults.map((tr: any) => (
                  <tr key={tr.tool}>
                    <td className="border border-slate-200 px-3 py-2 font-semibold text-slate-900">{tr.tool}</td>
                    <td className="border border-slate-200 px-3 py-2">{tr.finding_count ?? 0}</td>
                    <td className="border border-slate-200 px-3 py-2">{typeof tr.execution_time_ms === "number" ? (tr.execution_time_ms / 1000).toFixed(2) : "-"}</td>
                    <td className="border border-slate-200 px-3 py-2">{tr.error || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {viewData?.model_prediction && (
        <div className="card rounded-lg p-5">
          <SectionTitleWithInfo title="CodeBERT Prediction" info="Tags and a risk number from our fine-tuned CodeBERT on the source. Separate from the chat-style summary model below." />
          <div className="mt-2 space-y-1 text-sm">
            <p>
              <LabelWithInfo label="Available:" info={HELP.codebertAvailable} />{" "}
              <span className="font-semibold text-slate-900">{String(viewData.model_prediction.available)}</span>
            </p>
            <p>
              <LabelWithInfo label="Predicted Types:" info={HELP.codebertTypes} />{" "}
              <span className="text-slate-900">{(viewData.model_prediction.vuln_types || []).join(", ") || "-"}</span>
            </p>
            <p>
              <LabelWithInfo label="Risk Score:" info={HELP.codebertRisk} />{" "}
              <span className="font-semibold text-slate-900">{kv(viewData.model_prediction.risk_score, 4)}</span>
            </p>
            {viewData.model_prediction.error && (
              <p>
                <LabelWithInfo label="Error:" info={HELP.codebertError} />{" "}
                <span className="text-red-700">{viewData.model_prediction.error}</span>
              </p>
            )}
          </div>
        </div>
      )}

      {viewData?.business_risk && (
        <div className="card rounded-lg p-5">
          <SectionTitleWithInfo title="Business Risk" info="DeFi-flavored rubric per finding — exploitability, impact, that kind of thing. This card is just the averages and how many we scored." />
          <div className="mt-3 grid gap-2 text-sm md:grid-cols-2 lg:grid-cols-4">
            <p>
              <LabelWithInfo label="Avg Rubric:" info={HELP.avgRubric} />{" "}
              <span className="font-semibold text-slate-900">{kv(viewData.business_risk.avg_rubric_score, 2)}</span>
            </p>
            <p>
              <LabelWithInfo label="Max Rubric:" info={HELP.maxRubric} />{" "}
              <span className="font-semibold text-slate-900">{kv(viewData.business_risk.max_rubric_score, 2)}</span>
            </p>
            <p>
              <LabelWithInfo label="Findings Assessed:" info={HELP.findingsAssessed} />{" "}
              <span className="font-semibold text-slate-900">{viewData.business_risk.total_findings_assessed ?? "-"}</span>
            </p>
            <p>
              <LabelWithInfo label="Consensus:" info={HELP.consensus} />{" "}
              <span className="font-semibold text-slate-900">{pct(viewData.business_risk.consensus_rate, 1)}</span>
            </p>
          </div>
        </div>
      )}

      {viewData?.verification && (
        <div className="card rounded-lg p-5">
          <SectionTitleWithInfo title="Summary Verification" info="Did the summary’s claims match what the tools actually said? Different from CodeBERT and the “Model Verified” column on each row." />
          <div className="mt-3 grid gap-2 text-sm md:grid-cols-3">
            <p>
              <LabelWithInfo label="Status:" info={HELP.verifyStatus} />{" "}
              <span className="font-semibold text-slate-900">{viewData.verification.status ?? "-"}</span>
            </p>
            <p>
              <LabelWithInfo label="Hallucination Rate:" info={HELP.hallucinationRate} />{" "}
              <span className="font-semibold text-slate-900">{pct(viewData.verification.hallucination_rate, 1)}</span>
            </p>
            <p>
              <LabelWithInfo label="Claims:" info={HELP.verifyClaims} />{" "}
              <span className="font-semibold text-slate-900">{viewData.verification.total_claims ?? "-"}</span>
            </p>
          </div>
        </div>
      )}

      <div className="card rounded-lg p-5">
        <SectionTitleWithInfo title="Findings" info="One merged table of everything the tools reported, with agreement tiers and whether CodeBERT agrees on type." />
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[980px] border-collapse text-sm">
            <thead>
              <tr className="bg-slate-100">
                <ThWithInfo info={HELP.findingTitle}>Title</ThWithInfo>
                <ThWithInfo info={HELP.findingType}>Type</ThWithInfo>
                <ThWithInfo info={HELP.findingSource}>Source</ThWithInfo>
                <ThWithInfo info={HELP.findingImpact}>Impact</ThWithInfo>
                <ThWithInfo info={HELP.findingConfidence}>Confidence</ThWithInfo>
                <ThWithInfo info={HELP.findingTier}>Tier</ThWithInfo>
                <ThWithInfo info={HELP.findingLocation}>Location</ThWithInfo>
                <ThWithInfo info={HELP.modelVerified}>Model Verified</ThWithInfo>
              </tr>
            </thead>
            <tbody>
              {findings.length === 0 && (
                <tr>
                  <td className="border border-slate-200 px-3 py-4 text-slate-600" colSpan={8}>
                    No findings
                  </td>
                </tr>
              )}
              {findings.map((f: any) => (
                <tr key={f.id}>
                  <td className="border border-slate-200 px-3 py-2">{f.title}</td>
                  <td className="border border-slate-200 px-3 py-2">{f?.metadata?.vulnerability_type ?? "-"}</td>
                  <td className="border border-slate-200 px-3 py-2">{f.source}</td>
                  <td className="border border-slate-200 px-3 py-2">{f.impact}</td>
                  <td className="border border-slate-200 px-3 py-2">{f.confidence}</td>
                  <td className="border border-slate-200 px-3 py-2">{f?.metadata?.confidence_tier ?? "-"}</td>
                  <td className="border border-slate-200 px-3 py-2">{f.location ?? "-"}</td>
                  <td className="border border-slate-200 px-3 py-2">{String(Boolean(f?.metadata?.model_verified))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {(viewData?.summary || viewData?.summary_error) && (
        <div className="card rounded-lg p-5">
          <SectionTitleWithInfo title="Executive Summary (LLM)" info={HELP.executiveSummary} />
          {viewData.summary_error && (
            <p className="mt-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-950">
              {viewData.summary_error}
            </p>
          )}
          {viewData.summary && (
            <div className="mt-4">
              <ExecutiveSummaryMarkdown markdown={viewData.summary} />
            </div>
          )}
          {viewData?.verification?.status === "rejected" && viewData.summary && (
            <p className="mt-3 text-xs text-amber-800">
              Summary verification status is &quot;rejected&quot;; review claims against tool findings.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
