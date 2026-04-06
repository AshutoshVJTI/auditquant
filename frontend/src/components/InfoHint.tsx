import { useEffect, useId, useRef, useState, type ReactNode } from "react";

/** Small “i” control: opens on click, closes on outside click or Escape (no need to click i again). */
export function InfoHint({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const panelId = useId().replace(/:/g, "");

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown, true);
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown, true);
      document.removeEventListener("keydown", onKeyDown, true);
    };
  }, [open]);

  return (
    <div ref={rootRef} className="relative inline align-middle">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        className="inline-flex h-[1.125rem] w-[1.125rem] shrink-0 cursor-pointer select-none items-center justify-center rounded-full border border-slate-300 bg-slate-50 text-[0.65rem] font-bold leading-none text-slate-600 hover:border-slate-400 hover:bg-slate-100"
        aria-label="Explain this field"
        onClick={() => setOpen((o) => !o)}
      >
        i
      </button>
      {open ? (
        <div
          id={panelId}
          role="tooltip"
          className="absolute left-0 z-40 mt-1 w-[min(20rem,calc(100vw-2rem))] rounded-lg border border-slate-200 bg-white p-2.5 text-left text-xs font-normal normal-case leading-snug tracking-normal text-slate-700 shadow-lg"
        >
          {text}
        </div>
      ) : null}
    </div>
  );
}

export function LabelWithInfo({ label, info }: { label: string; info: string }) {
  return (
    <span className="inline-flex items-center gap-1 text-slate-600">
      {label}
      <InfoHint text={info} />
    </span>
  );
}

export function ThWithInfo({ children, info }: { children: ReactNode; info: string }) {
  return (
    <th className="border border-slate-200 px-3 py-2 text-left align-middle font-medium text-slate-800">
      <span className="inline-flex items-center gap-1.5">
        {children}
        <InfoHint text={info} />
      </span>
    </th>
  );
}

export function SectionTitleWithInfo({ title, info }: { title: string; info: string }) {
  return (
    <h3 className="flex flex-wrap items-center gap-2 text-lg font-semibold text-slate-900">
      {title}
      <InfoHint text={info} />
    </h3>
  );
}
