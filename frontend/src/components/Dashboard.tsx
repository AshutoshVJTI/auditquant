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
      setStatus(`Queued (${(payload.enabled_tools || []).join(", ")}). Redirecting...`);
    } finally {
      setUploading(false);
    }
  };

  return (
    <section className="mx-auto max-w-3xl">
      <div
        className={`card relative flex min-h-[320px] flex-col items-center justify-center rounded-xl border border-dashed px-10 text-center transition ${
          dragging
            ? "border-slate-400 bg-slate-100/70"
            : "border-slate-300"
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
        <p className="text-sm text-slate-600">
          Drop Solidity File
        </p>
        <h2 className="mt-3 text-2xl font-semibold text-slate-900">Upload File</h2>
        <button
          className="mt-6 rounded-md border border-slate-300 bg-slate-100 px-6 py-2 text-sm font-semibold text-slate-900 transition hover:bg-slate-200 disabled:opacity-50"
          disabled={uploading}
          onClick={() => inputRef.current?.click()}
        >
          Start New Analysis
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
        {status && <p className="mt-4 text-xs text-slate-600">{status}</p>}
        {uploading && (
          <div
            className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-4 rounded-xl bg-white/90 backdrop-blur-[2px]"
            role="status"
            aria-live="polite"
            aria-label="Uploading"
          >
            <div
              className="h-10 w-10 rounded-full border-2 border-slate-200 border-t-slate-700 animate-spin"
              aria-hidden
            />
            <p className="text-sm font-medium text-slate-800">Uploading and queueing analysis…</p>
          </div>
        )}
      </div>
    </section>
  );
}
