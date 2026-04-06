import { useCallback, useMemo, useState } from "react";
import Dashboard from "./components/Dashboard";
import Results from "./components/Results";
import type { AnalysisPayload } from "./types/analysis";

export default function App() {
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysisData, setAnalysisData] = useState<AnalysisPayload | null>(null);

  const apiBase = useMemo(
    () => import.meta.env.VITE_API_URL || "http://localhost:8000",
    []
  );

  const onData = useCallback((payload: any) => setAnalysisData(payload), []);
  const onAnalysisQueued = useCallback((id: string) => {
    // Reset stale payload so new analysis always starts in a loading state.
    setAnalysisData(null);
    setAnalysisId(id);
  }, []);

  return (
    <div className="min-h-screen px-6 py-10">
      {!analysisId ? (
        <Dashboard apiBase={apiBase} onAnalysisQueued={onAnalysisQueued} />
      ) : (
        <div className="space-y-4">
          <button
            onClick={() => setAnalysisId(null)}
            className="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 transition hover:bg-slate-100"
          >
            Upload Another File
          </button>
          <Results
            apiBase={apiBase}
            analysisId={analysisId}
            data={analysisData}
            onData={onData}
          />
        </div>
      )}
    </div>
  );
}
