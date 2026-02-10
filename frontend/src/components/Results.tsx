import { useEffect, useRef, useState } from "react";

interface ResultsProps {
  apiBase: string;
  analysisId: string | null;
  data: any;
  onData: (payload: any) => void;
  onNext: () => void;
}

function Gauge({ value, label }: { value: number; label: string }) {
  return (
    <div className="card flex flex-col items-center rounded-3xl px-6 py-8">
      <div className="gauge relative h-28 w-28 rounded-full">
        <div className="absolute inset-3 rounded-full bg-slate-950"></div>
        <div className="absolute inset-0 flex items-center justify-center text-xl font-semibold">
          {value.toFixed(1)}
        </div>
      </div>
      <p className="mt-4 text-sm text-slate-300">{label}</p>
    </div>
  );
}

export default function Results({ apiBase, analysisId, data, onData, onNext }: ResultsProps) {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const onDataRef = useRef(onData);
  onDataRef.current = onData;

  useEffect(() => {
    if (!analysisId) return;

    let cancelled = false;
    let attempts = 0;
    const POLL_INTERVAL_MS = 5000;
    const MAX_ATTEMPTS = 90;

    const poll = async () => {
      attempts++;
      setLoading(true);
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
        if (!response.ok) {
          setError(payload.detail || `Request failed: ${response.status}`);
          setLoading(false);
          return;
        }
        if (attempts >= MAX_ATTEMPTS) {
          setError("Analysis timed out. Check backend logs and Docker.");
          setLoading(false);
          return;
        }
        setTimeout(poll, POLL_INTERVAL_MS);
      } catch (err: any) {
        if (!cancelled) setError(err.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    poll();
    return () => { cancelled = true; };
  }, [analysisId, apiBase]);

  if (!analysisId) {
    return (
      <div className="card rounded-3xl p-6">
        <p className="text-sm text-slate-300">
          Upload a contract from the Dashboard to generate results.
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card rounded-3xl p-6 text-red-200">
        Error loading analysis: {error}
      </div>
    );
  }

  const findings = data?.findings || [];
  const totalFindings = data?.total_findings ?? findings.length;
  const toolResults = data?.tool_results || [];

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold">Risk Dashboard</h2>
          <p className="text-sm text-slate-400">
            {loading
              ? "Analysis running..."
              : `Status: ${data?.status ?? "queued"}${data?.total_execution_time_ms != null ? ` · ${(data.total_execution_time_ms / 1000).toFixed(1)}s` : ""}`}
          </p>
        </div>
        <button
          className="rounded-full border border-slate-700 px-4 py-2 text-sm text-slate-200 hover:border-sky-400"
          onClick={onNext}
        >
          View Remediation
        </button>
      </div>

      {/* R_SAST, R_DAST, R_COMP radial gauges */}
      {data?.scores && (
        <div className="grid gap-4 md:grid-cols-3">
          <Gauge value={data.scores.r_sast ?? 0} label="R_SAST — Static Density" />
          <Gauge value={data.scores.r_dast ?? 0} label="R_DAST — Dynamic Certainty" />
          <Gauge value={data.scores.r_comp ?? 0} label="R_COMP — Complexity Risk" />
        </div>
      )}

      {/* Per-tool results */}
      {toolResults.length > 0 && (
        <div className="card rounded-3xl p-6">
          <h3 className="text-lg font-semibold">Tool Results</h3>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            {toolResults.map((tr: any) => (
              <div
                key={tr.tool}
                className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4"
              >
                <p className="font-medium capitalize text-white">{tr.tool}</p>
                <p className="mt-1 text-2xl font-semibold text-sky-300">{tr.finding_count}</p>
                <p className="text-xs text-slate-400">
                  {(tr.execution_time_ms / 1000).toFixed(1)}s
                  {tr.error ? ` · ${tr.error.slice(0, 30)}…` : ""}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Verification status */}
      {data?.verification && (
        <div className="card rounded-3xl p-6">
          <h3 className="text-lg font-semibold">Claim Verification</h3>
          <div className="mt-3 flex flex-wrap gap-4 text-sm">
            <span className="rounded-full border border-slate-700 px-3 py-1">
              Status: <strong className="text-white">{data.verification.status}</strong>
            </span>
            <span className="rounded-full border border-slate-700 px-3 py-1">
              Hallucination Rate:{" "}
              <strong className="text-white">
                {(data.verification.hallucination_rate * 100).toFixed(1)}%
              </strong>
            </span>
          </div>
        </div>
      )}

      {/* Vulnerability list — AI-validated conclusions */}
      <div className="card rounded-3xl p-6">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Validated Findings</h3>
          <span className="text-xs text-slate-400">
            {totalFindings} total
            {data?.cross_validated_count != null ? ` · ${data.cross_validated_count} cross-validated` : ""}
          </span>
        </div>
        <div className="mt-4 space-y-3">
          {findings.map((finding: any) => (
            <div
              key={finding.id}
              className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-sm font-semibold text-white">
                  {finding.title}
                </h4>
                <div className="flex gap-2 text-xs text-slate-300">
                  <span className="rounded-full border border-slate-700 px-2 py-1 capitalize">
                    {finding.source}
                  </span>
                  <span className="rounded-full border border-slate-700 px-2 py-1">
                    {finding.impact}
                  </span>
                  <span className="rounded-full border border-slate-700 px-2 py-1">
                    {finding.confidence} conf
                  </span>
                </div>
              </div>
              <p className="mt-2 text-xs text-slate-300">{finding.description}</p>
              <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-400">
                {finding.location != null && <span>Location: {finding.location}</span>}
                {finding.loss_percentage != null && (
                  <span>Loss: {finding.loss_percentage}%</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Executive summary */}
      <div className="card rounded-3xl p-6 text-sm text-slate-300">
        <h3 className="text-lg font-semibold text-white">Executive Summary</h3>
        <p className="mt-3 whitespace-pre-wrap">
          {data?.summary || "Summary will appear when analysis completes."}
        </p>
      </div>
    </section>
  );
}
