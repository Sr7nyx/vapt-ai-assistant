"use client";

/**
 * Glowing orbital rings around the orb.
 *
 * Rings only. The labelled version put vulnerability names on the orbits, which
 * turned an ornament into something that looked like it was reporting data --
 * on a page where every other figure is real, that is a bad thing for a decoration
 * to imply. The rings carry the motion; the copy beside them carries the meaning.
 *
 * Each ring is a plain circle inside a preserve-3d context. Tilted under a
 * perspective, the browser draws it as a true ellipse and handles the foreshortening
 * for free -- no path maths, no canvas. A conic gradient runs bright on one arc and
 * away to nothing on the other, so it reads as a body sweeping round rather than a
 * static hoop.
 *
 * The planes are given different Z rotations so the orbits CROSS rather than nest.
 * Concentric coplanar rings read as a target; crossed planes read as a system.
 */

type Ring = {
  /** Radius as a share of the container's smaller dimension. */
  radius: number;
  /** Backward tilt. 90 would be flat to the screen, 0 edge-on. */
  tilt: number;
  /** Roll of the orbital plane, so rings cross instead of nesting. */
  roll: number;
  seconds: number;
  reverse: boolean;
  /** Peak opacity of the bright arc. */
  trail: number;
  stroke: string;
};

const RINGS: Ring[] = [
  { radius: 60, tilt: 74, roll: -22, seconds: 22, reverse: false, trail: 0.62, stroke: "1.5px" },
  { radius: 78, tilt: 80, roll: 16, seconds: 34, reverse: true, trail: 0.38, stroke: "1.2px" },
  { radius: 92, tilt: 84, roll: 46, seconds: 52, reverse: false, trail: 0.2, stroke: "1px" },
];

export default function OrbitRings({ className = "" }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 ${className}`}
      style={{ perspective: "820px", containerType: "size" } as React.CSSProperties}
    >
      {RINGS.map((ring, i) => (
        <span
          key={i}
          className="absolute inset-0"
          style={{
            transformStyle: "preserve-3d",
            transform: `rotateZ(${ring.roll}deg) rotateX(${ring.tilt}deg)`,
          }}
        >
          <span
            className={ring.reverse ? "orbit-spin-rev" : "orbit-spin"}
            style={{ animationDuration: `${ring.seconds}s`, transformStyle: "preserve-3d" }}
          >
            <span
              className="absolute left-1/2 top-1/2 rounded-full"
              style={{
                width: `${ring.radius * 2}cqmin`,
                height: `${ring.radius * 2}cqmin`,
                transform: "translate(-50%, -50%)",
                background: `conic-gradient(from 210deg,
                  rgba(var(--phosphor), 0) 0deg,
                  rgba(var(--phosphor), 0.05) 70deg,
                  rgba(var(--phosphor), ${ring.trail}) 250deg,
                  rgba(var(--phosphor), ${Math.min(1, ring.trail + 0.35)}) 322deg,
                  rgba(var(--phosphor), 0) 360deg)`,
                // Without the mask this is a filled disc rather than a ring.
                WebkitMaskImage: `radial-gradient(closest-side, transparent calc(100% - ${ring.stroke}), #000 calc(100% - ${ring.stroke}))`,
                maskImage: `radial-gradient(closest-side, transparent calc(100% - ${ring.stroke}), #000 calc(100% - ${ring.stroke}))`,
                filter: "drop-shadow(0 0 7px rgba(var(--phosphor), 0.5))",
              }}
            />
          </span>
        </span>
      ))}
    </span>
  );
}
