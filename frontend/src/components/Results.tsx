import { useEffect, useState } from "react";

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

  useEffect(() => {
    if (!analysisId) return;

    let active = true;
    const poll = async () => {
      setLoading(true);
      try {
        const response = await fetch(`${apiBase}/api/analysis/${analysisId}`);
        const payload = await response.json();
        if (!active) return;
        onData(payload);
        if (payload.status === "completed" || payload.status === "failed") {
          setLoading(false);
          return;
        }
        setTimeout(poll, 2000);
      } catch (err: any) {
        if (active) setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    poll();

    return () => {
      active = false;
    };
  }, [analysisId, apiBase, onData]);

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

  const scores = data?.scores || { r_sast: 0, r_dast: 0, r_comp: 0 };
  const findings = data?.findings || [];

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold">Risk Dashboard</h2>
          <p className="text-sm text-slate-400">
            {loading
              ? "Analysis running..."
              : `Analysis status: ${data?.status || "queued"}`}
          </p>
        </div>
        <button
          className="rounded-full border border-slate-700 px-4 py-2 text-sm text-slate-200 hover:border-sky-400"
          onClick={onNext}
        >
          View Remediation
        </button>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Gauge value={scores.r_sast} label="R_SAST" />
        <Gauge value={scores.r_dast} label="R_DAST" />
        <Gauge value={scores.r_comp} label="R_COMP" />
      </div>

      <div className="card rounded-3xl p-6">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Validated Findings</h3>
          <span className="text-xs text-slate-400">{findings.length} issues</span>
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
                  <span className="rounded-full border border-slate-700 px-2 py-1">
                    Impact: {finding.impact}
                  </span>
                  <span className="rounded-full border border-slate-700 px-2 py-1">
                    Confidence: {finding.confidence}
                  </span>
                </div>
              </div>
              <p className="mt-2 text-xs text-slate-300">{finding.description}</p>
              <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-400">
                <span>Loss: {finding.loss_percentage ?? "N/A"}%</span>
                <span>Location: {finding.location ?? "Unknown"}</span>
                <span>Source: {finding.source}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card rounded-3xl p-6 text-sm text-slate-300">
        <h3 className="text-lg font-semibold text-white">Executive Summary</h3>
        <p className="mt-3">
          {data?.summary || "Summary will appear when analysis completes."}
        </p>
      </div>
    </section>
  );
}
