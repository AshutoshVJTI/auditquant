import { useRef, useState } from "react";

interface DashboardProps {
  apiBase: string;
  onAnalysisQueued: (id: string) => void;
}

export default function Dashboard({ apiBase, onAnalysisQueued }: DashboardProps) {
  const [dragging, setDragging] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleUpload = async (file: File) => {
    if (uploading) return;
    setUploading(true);
    setStatus("Uploading and queueing analysis...");
    try {
      const form = new FormData();
      form.append("file", file);
      const response = await fetch(`${apiBase}/api/analyze`, {
        method: "POST",
        body: form
      });
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.detail || "Upload failed");
      }
      const payload = await response.json();
      onAnalysisQueued(payload.analysis_id);
      setStatus("Queued. Redirecting to results...");
    } finally {
      setUploading(false);
    }
  };

  return (
    <section className="grid gap-6 lg:grid-cols-[2fr,1fr]">
      <div
        className={`card flex min-h-[320px] flex-col items-center justify-center rounded-3xl border-2 border-dashed px-10 text-center transition ${
          dragging
            ? "border-sky-400 bg-sky-500/10"
            : "border-slate-700"
        }`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          const file = event.dataTransfer.files[0];
          if (file) {
            handleUpload(file).catch((err) => setStatus(err.message));
          }
        }}
      >
        <p className="text-sm uppercase tracking-[0.3em] text-sky-300">
          Drop Solidity File
        </p>
        <h2 className="mt-3 text-2xl font-semibold">Start a New Audit Run</h2>
        <p className="mt-3 text-sm text-slate-300">
          Upload a single .sol file to run Slither, RiskQuant scoring, and AI
          validation.
        </p>
        <button
          className="mt-6 rounded-full bg-sky-500 px-6 py-2 text-sm font-semibold text-white disabled:opacity-50"
          disabled={uploading}
          onClick={() => inputRef.current?.click()}
        >
          Select File
        </button>
        <input
          ref={inputRef}
          type="file"
          accept=".sol"
          className="hidden"
          disabled={uploading}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) {
              handleUpload(file).catch((err) => setStatus(err.message));
            }
            event.target.value = "";
          }}
        />
        {status && <p className="mt-4 text-xs text-slate-400">{status}</p>}
      </div>

      <div className="card rounded-3xl p-6">
        <h3 className="text-lg font-semibold">Operational Checklist</h3>
        <ul className="mt-4 space-y-3 text-sm text-slate-300">
          <li>1. Slither static scan and JSON parsing.</li>
          <li>2. RiskQuant vectors: R_SAST, R_DAST, R_COMP.</li>
          <li>3. GPT-4o validation and financial impact buckets.</li>
          <li>4. Remediation staging (CodeT5 placeholder).</li>
        </ul>
        <div className="mt-6 rounded-2xl border border-slate-700 bg-slate-900/60 p-4 text-xs text-slate-400">
          Tip: keep the Docker Slither service built and running for the fastest
          turnarounds.
        </div>
      </div>
    </section>
  );
}
