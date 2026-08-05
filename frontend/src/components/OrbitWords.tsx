"use client";

/**
 * Vulnerability classes in orbit around the orb.
 *
 * Genuinely three-dimensional, not a circle drawn flat. The rings live in a
 * preserve-3d context under a perspective, each tilted back on X, and the words
 * are placed with rotateY + translateZ. So they travel an ellipse, pass BEHIND the
 * orb, and the browser's own perspective divide makes the near ones larger. A flat
 * circle at any opacity reads as a halo; this reads as an orbit because the depth
 * is real.
 *
 * Three transforms have to be undone for a word to stay legible while its ring
 * turns: the ring's continuous spin, the word's own placement angle, and the ring's
 * tilt. Each gets its own nesting level, because a CSS animation on `transform`
 * replaces any static transform on the same element rather than composing with it.
 *
 * Opacity is synced to position by negative animation-delay rather than measured in
 * JavaScript: a word's phase is known from its angle, so the fade can be pinned to
 * it exactly with no per-frame work.
 */

type Ring = {
  words: string[];
  /** Radius as a share of the container's smaller dimension. */
  radius: number;
  /** Degrees of backward tilt. 0 would be edge-on, 90 flat to the screen. */
  tilt: number;
  seconds: number;
  reverse: boolean;
  size: string;
};

const RINGS: Ring[] = [
  {
    words: ["SQLi", "XSS", "IDOR", "SSRF", "XXE", "CSRF", "RCE"],
    radius: 64,
    tilt: 74,
    seconds: 26,
    reverse: false,
    size: "text-[11px]",
  },
  {
    words: ["LFI", "SSTI", "JWT", "BOLA", "CORS", "PROTOTYPE", "OPEN REDIRECT", "PATH TRAVERSAL"],
    radius: 84,
    tilt: 79,
    seconds: 40,
    reverse: true,
    size: "text-[10px]",
  },
];

export default function OrbitWords({ className = "" }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 ${className}`}
      style={{ perspective: "760px", containerType: "size" } as React.CSSProperties}
    >
      {RINGS.map((ring, ri) => (
        <span
          key={ri}
          className="absolute inset-0"
          style={{ transformStyle: "preserve-3d", transform: `rotateX(${ring.tilt}deg)` }}
        >
          <span
            className={ring.reverse ? "orbit-spin-rev" : "orbit-spin"}
            style={{ animationDuration: `${ring.seconds}s`, transformStyle: "preserve-3d" }}
          >
            {ring.words.map((word, i) => {
              const angle = (360 / ring.words.length) * i;
              // The word reaches the front of the ring at a time fixed by its
              // angle, so the fade is pinned to it with a negative delay.
              const phase = -(angle / 360) * ring.seconds;
              return (
                <span
                  key={word}
                  className="absolute left-1/2 top-1/2"
                  style={{
                    transformStyle: "preserve-3d",
                    transform: `rotateY(${angle}deg) translateZ(${ring.radius}cqmin)`,
                  }}
                >
                  {/* undo the ring's spin */}
                  <span
                    className={ring.reverse ? "orbit-spin" : "orbit-spin-rev"}
                    style={{ animationDuration: `${ring.seconds}s`, transformStyle: "preserve-3d" }}
                  >
                    {/* undo this word's placement angle and the ring's tilt */}
                    <span
                      className="block"
                      style={{ transform: `rotateY(${-angle}deg) rotateX(${-ring.tilt}deg)` }}
                    >
                      <span
                        className={`orbit-fade block whitespace-nowrap tracking-[0.22em] text-accent ${ring.size}`}
                        style={{
                          animationDuration: `${ring.seconds}s`,
                          animationDelay: `${phase}s`,
                          textShadow: "0 0 14px rgba(var(--phosphor), 0.55)",
                        }}
                      >
                        {word}
                      </span>
                    </span>
                  </span>
                </span>
              );
            })}
          </span>
        </span>
      ))}
    </span>
  );
}
