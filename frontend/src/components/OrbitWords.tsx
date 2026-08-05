"use client";
import { useMemo } from "react";

/**
 * Vulnerability classes orbiting the orb.
 *
 * Two counter-rotating rings. Each word sits on a ring at a fixed angle, and
 * counter-rotates at exactly the ring's rate so it stays upright while travelling
 * -- otherwise the labels tumble and become unreadable, which is the usual failure
 * of orbit effects.
 *
 * Words at the top of a ring are dimmer than those at the bottom. There is no real
 * depth here, but a constant-opacity ring reads as a flat halo, and the gradient is
 * enough for the eye to accept it as an orbit.
 *
 * Entirely CSS transforms, so the browser can composite it without touching the
 * main thread while the orb next to it is doing real per-frame work.
 */

const INNER = ["SQLi", "XSS", "IDOR", "SSRF", "XXE", "CSRF"];
const OUTER = ["RCE", "LFI", "SSTI", "JWT", "BOLA", "CORS", "PROTO", "OPEN REDIRECT"];

type Ring = {
  words: string[];
  radius: number;
  duration: number;
  reverse: boolean;
  size: string;
};

export default function OrbitWords({ className = "" }: { className?: string }) {
  const rings = useMemo<Ring[]>(
    () => [
      { words: INNER, radius: 38, duration: 38, reverse: false, size: "text-[9px]" },
      { words: OUTER, radius: 52, duration: 58, reverse: true, size: "text-[8px]" },
    ],
    []
  );

  return (
    <span
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 ${className}`}
      style={{ containerType: "size" } as React.CSSProperties}
    >
      {rings.map((ring, ri) => (
        <span
          key={ri}
          className={ring.reverse ? "orbit-ring-rev" : "orbit-ring"}
          style={{ animationDuration: `${ring.duration}s` }}
        >
          {ring.words.map((word, i) => {
            const angle = (360 / ring.words.length) * i;
            // Angle 0 is the top of the ring, so dim there and brighten toward
            // the bottom, which is the half nearer the viewer.
            const depth = (1 - Math.cos((angle * Math.PI) / 180)) / 2;
            return (
              <span
                key={word}
                className="absolute left-1/2 top-1/2"
                style={{
                  // cqmin resolves against the container, not the word's own box.
                  transform: `rotate(${angle}deg) translateY(-${ring.radius}cqmin) rotate(${-angle}deg)`,
                }}
              >
                <span
                  className={ring.reverse ? "orbit-counter-rev" : "orbit-counter"}
                  style={{ animationDuration: `${ring.duration}s` }}
                >
                  <span
                    className={`block whitespace-nowrap tracking-[0.25em] text-accent ${ring.size}`}
                    style={{ opacity: 0.16 + depth * 0.4 }}
                  >
                    {word}
                  </span>
                </span>
              </span>
            );
          })}
        </span>
      ))}
    </span>
  );
}
