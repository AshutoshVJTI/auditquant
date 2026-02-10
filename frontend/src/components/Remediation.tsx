import { useState } from "react";
import { DiffEditor } from "@monaco-editor/react";

const placeholderVuln = `function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
    balances[msg.sender] -= amount;
}`;

const placeholderPatch = `function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    balances[msg.sender] -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
}`;

interface PatchEntry {
  finding_id: string;
  vuln_type: string;
  original: string;
  patch: string;
  explanation: string;
}

export default function Remediation({ data }: { data: any }) {
  const patches: PatchEntry[] = data?.remediation ?? [];
  const [selected, setSelected] = useState(0);

  const hasPatch = patches.length > 0;
  const current = hasPatch ? patches[selected] : null;
  const vulnCode = current?.original || placeholderVuln;
  const patchCode = current?.patch || placeholderPatch;
  const explanation = current?.explanation || "";

  return (
    <section className="space-y-6">
      {hasPatch && (
        <div className="flex flex-wrap gap-2">
          {patches.map((p, i) => (
            <button
              key={p.finding_id}
              onClick={() => setSelected(i)}
              className={`rounded-full px-4 py-2 text-xs transition ${
                selected === i
                  ? "bg-sky-500 text-white shadow-lg shadow-sky-500/30"
                  : "border border-slate-700 text-slate-300 hover:border-sky-400"
              }`}
            >
              {p.finding_id}: {p.vuln_type}
            </button>
          ))}
        </div>
      )}

      {!hasPatch && (
        <div className="card rounded-3xl p-6 text-sm text-slate-400">
          No remediation patches available yet. Run an analysis from the
          Dashboard first.
        </div>
      )}

      {/* Diff Viewer — side-by-side comparison with green additions */}
      <div className="card rounded-3xl p-5">
        <h3 className="text-lg font-semibold">Diff Viewer</h3>
        <p className="text-xs text-slate-400">
          Original (left) vs AI-generated fix (right, green).
        </p>
        <div className="mt-4 h-[420px] overflow-hidden rounded-2xl border border-slate-800">
          <DiffEditor
            original={vulnCode}
            modified={patchCode}
            language="sol"
            theme="vs-dark"
            options={{
              readOnly: true,
              minimap: { enabled: false },
              fontSize: 13,
              renderSideBySide: true,
            }}
          />
        </div>

        {/* Natural language explanation */}
        {explanation && (
          <div className="mt-4 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-200">
            {explanation}
          </div>
        )}
        <div className="mt-4 rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200">
          Ensure the patch compiles before deploying. Human review remains
          required for production contracts.
        </div>
      </div>
    </section>
  );
}
