"use client";
import { useCallback, useEffect, useMemo, useState } from "react";

export type Key = number | string;

/**
 * Multi-selection over a list, shared by the analyzer, importer, findings and
 * reports pages so the semantics are identical everywhere.
 *
 * The important behaviour is pruning: when the underlying list changes -- a new
 * analysis, a changed filter, a deletion -- keys that no longer exist are dropped.
 * Without that, "commit selected" could silently act on a stale set, or a bulk
 * delete could carry ids the user can no longer see.
 */
export function useSelection<T>(items: T[], keyOf: (item: T) => Key) {
  const [selected, setSelected] = useState<Set<Key>>(new Set());

  const presentKeys = useMemo(() => items.map(keyOf), [items, keyOf]);

  useEffect(() => {
    setSelected((prev) => {
      if (prev.size === 0) return prev;
      const present = new Set(presentKeys);
      let changed = false;
      const next = new Set<Key>();
      prev.forEach((k) => {
        if (present.has(k)) next.add(k);
        else changed = true;
      });
      return changed ? next : prev;
    });
  }, [presentKeys]);

  const isSelected = useCallback((k: Key) => selected.has(k), [selected]);

  const toggle = useCallback((k: Key) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => setSelected(new Set(presentKeys)), [presentKeys]);
  const clear = useCallback(() => setSelected(new Set()), []);

  const count = selected.size;
  const allSelected = presentKeys.length > 0 && count === presentKeys.length;
  const someSelected = count > 0 && !allSelected;

  const toggleAll = useCallback(() => {
    if (allSelected) clear();
    else selectAll();
  }, [allSelected, clear, selectAll]);

  /** Selected items in list order, which is what a caller almost always wants. */
  const selectedItems = useMemo(
    () => items.filter((i) => selected.has(keyOf(i))),
    [items, selected, keyOf]
  );

  return {
    selected, isSelected, toggle, toggleAll, selectAll, clear,
    count, allSelected, someSelected, selectedItems,
  };
}
