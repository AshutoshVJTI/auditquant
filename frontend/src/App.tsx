import { useMemo, useState } from "react";
import Dashboard from "./components/Dashboard";
import Results from "./components/Results";
import Remediation from "./components/Remediation";

const tabs = ["Dashboard", "Results", "Remediation"] as const;

export type TabName = (typeof tabs)[number];

export default function App() {
  const [active, setActive] = useState<TabName>("Dashboard");
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysisData, setAnalysisData] = useState<any>(null);

  const apiBase = useMemo(
    () => import.meta.env.VITE_API_URL || "http://localhost:8000",
    []
  );

  return (
    <div className="min-h-screen px-6 py-10">
      <header className="mb-8 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.35em] text-sky-300">
            Hybrid Smart Contract Auditing
          </p>
          <h1 className="text-4xl font-semibold text-white">
            AuditQuant Control Room
          </h1>
          <p className="mt-2 max-w-xl text-sm text-slate-300">
            Quantify risk, validate findings, and stage remediation with a unified
            workflow.
          </p>
        </div>
        <div className="flex items-center gap-3 rounded-full border border-slate-700 bg-slate-900/60 px-4 py-2 text-xs text-slate-300">
          <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
          Live Systems Online
        </div>
      </header>

      <nav className="mb-8 flex flex-wrap gap-3">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActive(tab)}
            className={`rounded-full px-4 py-2 text-sm transition ${
              active === tab
                ? "bg-sky-500 text-white shadow-lg shadow-sky-500/30"
                : "border border-slate-700 text-slate-300 hover:border-sky-400"
            }`}
          >
            {tab}
          </button>
        ))}
      </nav>

      {active === "Dashboard" && (
        <Dashboard
          apiBase={apiBase}
          onAnalysisQueued={(id) => {
            setAnalysisId(id);
            setActive("Results");
          }}
        />
      )}

      {active === "Results" && (
        <Results
          apiBase={apiBase}
          analysisId={analysisId}
          data={analysisData}
          onData={(payload) => setAnalysisData(payload)}
          onNext={() => setActive("Remediation")}
        />
      )}

      {active === "Remediation" && <Remediation data={analysisData} />}
    </div>
  );
}
