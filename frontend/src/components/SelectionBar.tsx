"use client";
import { ReactNode } from "react";

/** Tri-state master checkbox. Indeterminate matters: a plain checkbox showing
 *  unchecked when three of ten rows are picked is actively misleading. */
export function MasterCheckbox({
  allSelected,
  someSelected,
  onToggle,
  label,
}: {
  allSelected: boolean;
  someSelected: boolean;
  onToggle: () => void;
  label?: string;
}) {
  return (
    <label className="flex items-center gap-2 text-xs text-muted cursor-pointer select-none">
      <input
        type="checkbox"
        checked={allSelected}
        ref={(el) => {
          if (el) el.indeterminate = someSelected;
        }}
        onChange={onToggle}
        aria-label={label || "Select all"}
      />
      {label && <span className="tracking-wide">{label}</span>}
    </label>
  );
}

export function RowCheckbox({
  checked,
  onToggle,
  label,
}: {
  checked: boolean;
  onToggle: () => void;
  label: string;
}) {
  return (
    <input
      type="checkbox"
      checked={checked}
      onChange={onToggle}
      onClick={(e) => e.stopPropagation()}
      aria-label={label}
      className="mt-1 shrink-0 cursor-pointer"
    />
  );
}

/** Action strip that appears only when something is selected, so it never takes
 *  up space or implies an action is available when none is. */
export function SelectionBar({
  count,
  noun = "item",
  onClear,
  children,
}: {
  count: number;
  noun?: string;
  onClear: () => void;
  children: ReactNode;
}) {
  if (count === 0) return null;
  return (
    <div className="statstrip mb-3 justify-between">
      <span className="flex items-center gap-2">
        <span className="text-highlight">{count}</span>
        <span className="text-muted">
          {noun}
          {count === 1 ? "" : "s"} selected
        </span>
        <button className="text-muted hover:text-text underline ml-1" onClick={onClear}>
          clear
        </button>
      </span>
      <span className="flex items-center gap-2">{children}</span>
    </div>
  );
}
