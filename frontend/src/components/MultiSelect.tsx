"use client";
import { useEffect, useRef, useState } from "react";

export default function MultiSelect({
  options,
  selected,
  onChange,
  placeholder = "Choose options",
}: {
  options: string[];
  selected: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const toggle = (o: string) => onChange(selected.includes(o) ? selected.filter((x) => x !== o) : [...selected, o]);

  return (
    <div className="relative" ref={ref}>
      <button type="button" className="input flex items-center justify-between" onClick={() => setOpen((v) => !v)}>
        <span className={selected.length ? "" : "text-muted"}>
          {selected.length ? `${selected.length} selected` : placeholder}
        </span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div className="absolute z-30 mt-1 w-full bg-surface border border-border rounded-lg p-1 max-h-60 overflow-auto shadow-xl">
          {options.length === 0 ? (
            <div className="px-3 py-2 text-sm text-muted">No options</div>
          ) : (
            options.map((o) => (
              <label key={o} className="flex items-center gap-2 px-3 py-1.5 text-sm hover:bg-white/5 rounded cursor-pointer">
                <input type="checkbox" checked={selected.includes(o)} onChange={() => toggle(o)} />
                {o}
              </label>
            ))
          )}
        </div>
      )}
    </div>
  );
}
