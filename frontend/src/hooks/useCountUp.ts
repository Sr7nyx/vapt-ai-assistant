"use client";
import { useEffect, useRef, useState } from "react";

/**
 * Animate a number up to its value.
 *
 * Used only on figures that are already known and true. It is a way of drawing
 * the eye to a real quantity, not a loading state: nothing here invents a number
 * or implies work is still happening.
 *
 * Driven by requestAnimationFrame against wall-clock time rather than a fixed
 * increment per tick, so the duration is the same on a 60Hz and a 144Hz display
 * and a throttled background tab does not leave the number stranded part-way.
 */
export function useCountUp(target: number, durationMs = 650): number {
  const [value, setValue] = useState(0);
  const from = useRef(0);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced || !Number.isFinite(target) || target === 0) {
      setValue(target);
      from.current = target;
      return;
    }

    const start = performance.now();
    const origin = from.current;
    const delta = target - origin;
    let raf = 0;

    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      // Ease out: most of the distance is covered early, so the number settles
      // rather than arriving abruptly.
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(Math.round(origin + delta * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
      else from.current = target;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);

  return value;
}
