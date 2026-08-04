"use client";
import React, { useCallback, useEffect, useMemo, useRef } from "react";
import { motionReduced } from "@/lib/motion";

/**
 * An ASCII orb.
 *
 * The body is a superquadric -- |x|^n + |y|^n + |z|^n = 1 -- and the solid
 * genuinely tumbles: rather than solving for z at a fixed orientation, each
 * character cell fires a perspective ray that is inverse-rotated into object
 * space and marched to the surface. That is what lets the silhouette change as
 * it turns, which is the difference between a shaded disc and something that
 * reads as a solid. Animating the exponent morphs it between a sphere (n = 2)
 * and an octahedron (n -> 1).
 *
 * Shading is diffuse plus a specular highlight plus a rim term, all taken from
 * the true surface normal (the gradient of the implicit function, rotated back
 * into view space), with distance falloff. Hue cycles, the body drifts, and
 * clicking disturbs only the region around the pointer.
 *
 * Arithmetic and a <pre>. No image, no 3D library, no dependency.
 */

const COLS = 74;
const ROWS = 34;
const FPS = 45;

const RAMP = " .,:;=+ox*OQ#%@";
const GLITCH_CHARS = "!<>-_/[]{}=+*^?#%$&@01xX";

// 5x7 glyphs. A security vocabulary needs letters, not digits.
const FONT: Record<string, string> = {
  A: "01110100011000111111100011000110001",
  B: "11110100011000111110100011000111110",
  C: "01111100001000010000100001000001111",
  D: "11100100101000110001100011001011100",
  E: "11111100001000011110100001000011111",
  F: "11111100001000011110100001000010000",
  G: "01110100011000010111100011000101111",
  H: "10001100011000111111100011000110001",
  I: "11111001000010000100001000010011111",
  J: "00111000100001000010000110010011000",
  K: "10001100101010011000101001001010001",
  L: "10000100001000010000100001000011111",
  M: "10001110111010110101100011000110001",
  N: "10001110011010110011100011000110001",
  O: "01110100011000110001100011000101110",
  P: "11110100011000111110100001000010000",
  Q: "01110100011000110001101011001001101",
  R: "11110100011000111110101001001010001",
  S: "01111100001000001110000010000111110",
  T: "11111001000010000100001000010000100",
  U: "10001100011000110001100011000101110",
  V: "10001100011000110001100010101000100",
  W: "10001100011000110101101011010101010",
  X: "10001010100010000100001000101010001",
  Y: "10001010100010000100001000010000100",
  Z: "11111000010001000100010001000011111",
};

const DEFAULT_WORDS = [
  "IDOR", "SSRF", "XSS", "SQLI", "JWT", "CVSS", "OWASP",
  "TRIAGE", "EXPLOIT", "PAYLOAD", "CONFIRMED", "VERIFIED", "ORACLE", "BOLA",
];

const BREAK_MS = 1900;
const FOCAL = 2.6;   // camera distance; smaller is a wider, more dramatic perspective

function hash2(x: number, y: number): number {
  const s = Math.sin(x * 127.1 + y * 311.7) * 43758.5453;
  return s - Math.floor(s);
}
function hash3(x: number, y: number, z: number): number {
  const s = Math.sin(x * 12.9898 + y * 78.233 + z * 37.719) * 43758.5453;
  return s - Math.floor(s);
}

/** Smooth value noise over the surface, so the skin has structure that travels
 *  with the rotation rather than reading as a flat shaded solid. */
function surfaceNoise(x: number, y: number, z: number): number {
  let sum = 0, amp = 0.5, f = 1.6;
  for (let o = 0; o < 3; o++) {
    const xi = Math.floor(x * f), yi = Math.floor(y * f), zi = Math.floor(z * f);
    const xf = x * f - xi, yf = y * f - yi, zf = z * f - zi;
    const sx = xf * xf * (3 - 2 * xf), sy = yf * yf * (3 - 2 * yf), sz = zf * zf * (3 - 2 * zf);
    let acc = 0;
    for (let dz = 0; dz < 2; dz++)
      for (let dy = 0; dy < 2; dy++)
        for (let dx = 0; dx < 2; dx++)
          acc += hash3(xi + dx, yi + dy, zi + dz) *
            (dx ? sx : 1 - sx) * (dy ? sy : 1 - sy) * (dz ? sz : 1 - sz);
    sum += acc * amp; amp *= 0.5; f *= 2.1;
  }
  return sum;
}

/** Cells lit by a word's glyphs, centred on a point rather than on the grid, so
 *  the word surfaces where the pointer landed. */
function wordMask(word: string, atCol: number, atRow: number): Set<number> {
  const on = new Set<number>();
  const letters = word.toUpperCase().split("").filter((c) => FONT[c]);
  if (!letters.length) return on;

  const scale = letters.length > 6 ? 1 : 2;
  const glyphW = 5 * scale + scale;
  const totalW = glyphW * letters.length - scale;
  const startCol = Math.max(1, Math.min(COLS - totalW - 1, Math.round(atCol - totalW / 2)));
  const startRow = Math.max(1, Math.min(ROWS - 7 * scale - 1, Math.round(atRow - (7 * scale) / 2)));

  letters.forEach((ch, i) => {
    const bits = FONT[ch];
    for (let r = 0; r < 7; r++)
      for (let c = 0; c < 5; c++) {
        if (bits[r * 5 + c] !== "1") continue;
        for (let sr = 0; sr < scale; sr++)
          for (let sc = 0; sc < scale; sc++) {
            const col = startCol + i * glyphW + c * scale + sc;
            const row = startRow + r * scale + sr;
            if (col >= 0 && col < COLS && row >= 0 && row < ROWS) on.add(row * COLS + col);
          }
      }
  });
  return on;
}

export default function AsciiOrb({
  words = DEFAULT_WORDS,
  hueCycle = true,
  baseHue = 77,
  className = "",
}: {
  words?: string[];
  /** Cycle the hue over time. Off pins the orb to baseHue. */
  hueCycle?: boolean;
  /** Starting hue; 77 is the lime highlight. 136 is the phosphor green the rest
   *  of the interface uses, if you would rather it matched the chrome. */
  baseHue?: number;
  className?: string;
}) {
  const wrapRef = useRef<HTMLSpanElement>(null);
  const baseRef = useRef<HTMLPreElement>(null);
  const aRef = useRef<HTMLPreElement>(null);
  const bRef = useRef<HTMLPreElement>(null);
  const haloRef = useRef<HTMLSpanElement>(null);
  const st = useRef({
    start: 0,
    impact: -1,
    col: COLS / 2,
    row: ROWS / 2,
    word: "",
    idx: 0,
    mask: new Set<number>(),
  });

  // Ambient terms drifting around the body. Deterministic so they do not jump
  // between renders, and purely decorative.
  const ambient = useMemo(
    () =>
      words.slice(0, 5).map((w, i) => ({
        word: w,
        top: `${12 + hash2(i, 3) * 74}%`,
        left: `${hash2(i, 9) > 0.5 ? 4 + hash2(i, 1) * 22 : 74 + hash2(i, 2) * 20}%`,
        rot: Math.round((hash2(i, 7) - 0.5) * 130),
        delay: `${(i * 1.7).toFixed(1)}s`,
        dur: `${(11 + hash2(i, 5) * 8).toFixed(1)}s`,
      })),
    [words]
  );

  const strike = useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
    const s = st.current;
    if (s.impact >= 0) return;                    // let the current wave finish
    const box = baseRef.current?.getBoundingClientRect();
    if (box && box.width > 0) {
      s.col = Math.round(((e.clientX - box.left) / box.width) * COLS);
      s.row = Math.round(((e.clientY - box.top) / box.height) * ROWS);
    } else {
      s.col = COLS / 2; s.row = ROWS / 2;
    }
    s.word = words[s.idx % words.length];
    s.idx += 1;
    s.mask = wordMask(s.word, s.col, s.row);
    s.impact = performance.now();
  }, [words]);

  useEffect(() => {
    const reduced = motionReduced();

    const s = st.current;
    s.start = performance.now();

    const radiusRows = ROWS * 0.45;
    const radiusCols = radiusRows / 0.5;   // monospace cells are ~half as wide as tall
    const cx = (COLS - 1) / 2;
    const cy = (ROWS - 1) / 2;
    const LX = -0.42, LY = -0.58, LZ = 0.70;   // fixed light, view space

    const draw = (now: number) => {
      const t = reduced ? 2.2 : (now - s.start) / 1000;

      // Shape: the exponent breathes between an octahedron and a sphere.
      const n = 1.08 + (Math.sin(t * 0.5) * 0.5 + 0.5) * 1.05;
      const nm1 = n - 1;
      const hue = hueCycle && !reduced ? (baseHue + t * 18) % 360 : baseHue;

      // Tumble. R = Rx(ax) . Ry(ay), built once per frame and applied inline.
      const ay = t * 0.55, ax = t * 0.31;
      const cA = Math.cos(ay), sA = Math.sin(ay);
      const cB = Math.cos(ax), sB = Math.sin(ax);
      const r00 = cA,      r02 = sA;
      const r10 = sA * sB, r11 = cB,  r12 = -cA * sB;
      const r20 = -sA * cB, r21 = sB, r22 = cA * cB;

      // The camera sits on +z and is the same for every cell, so rotate it once.
      const ox = r02 * FOCAL, oy = r12 * FOCAL, oz = r22 * FOCAL;
      const originSq = ox * ox + oy * oy + oz * oz;

      let p = -1;
      if (s.impact >= 0) {
        p = (now - s.impact) / BREAK_MS;
        if (p >= 1) { p = -1; s.impact = -1; s.mask = new Set(); }
      }
      const reach = p < 0 ? 0 : 7 + p * 30;
      const env = p < 0 ? 0 : p < 0.22 ? p / 0.22 : 1 - (p - 0.22) / 0.78;
      const wordAmt =
        p < 0 ? 0
        : p < 0.2 ? 0
        : p < 0.32 ? (p - 0.2) / 0.12
        : p < 0.68 ? 1
        : p < 0.8 ? 1 - (p - 0.68) / 0.12
        : 0;

      const F = (px: number, py: number, pz: number) =>
        Math.pow(Math.abs(px), n) + Math.pow(Math.abs(py), n) + Math.pow(Math.abs(pz), n);

      const out: string[] = [];
      for (let row = 0; row < ROWS; row++) {
        let line = "";
        for (let col = 0; col < COLS; col++) {
          const cell = row * COLS + col;

          let dis = 0;
          if (p >= 0) {
            const ddx = (col - s.col) * 0.5;
            const ddy = row - s.row;
            dis = Math.max(0, 1 - Math.sqrt(ddx * ddx + ddy * ddy) / reach) * env;
          }

          let scol = col, srow = row;
          if (dis > 0) {
            const a = hash2(col, row) * Math.PI * 2;
            const mag = (0.3 + hash2(row, col) * 1.5) * dis * 8;
            scol = col + Math.cos(a) * mag;
            srow = row + Math.sin(a) * mag * 0.5;
          }

          const px0 = (scol - cx) / radiusCols;
          const py0 = (srow - cy) / radiusRows;

          // Perspective ray, then inverse-rotated into the solid's frame.
          let dx = px0, dy = py0, dz = -FOCAL;
          const inv = 1 / Math.hypot(dx, dy, dz);
          dx *= inv; dy *= inv; dz *= inv;
          const rdx = r00 * dx + r02 * dz;
          const rdy = r10 * dx + r11 * dy + r12 * dz;
          const rdz = r20 * dx + r21 * dy + r22 * dz;

          let ch = " ";

          // Bounding-sphere reject: for n >= 1 the solid fits inside r = sqrt(3).
          const b = ox * rdx + oy * rdy + oz * rdz;
          const disc = b * b - (originSq - 3);
          if (disc >= 0) {
            const sq = Math.sqrt(disc);
            const tNear = Math.max(0, -b - sq);
            const tFar = -b + sq;

            // Coarse march to straddle the surface, then bisect.
            let lo = -1, hi = -1;
            const STEPS = 11, dt = (tFar - tNear) / STEPS;
            for (let i = 0; i <= STEPS; i++) {
              const tt = tNear + i * dt;
              if (F(ox + rdx * tt, oy + rdy * tt, oz + rdz * tt) <= 1) { hi = tt; lo = tt - dt; break; }
            }
            if (hi >= 0) {
              for (let i = 0; i < 5; i++) {
                const mid = (lo + hi) * 0.5;
                if (F(ox + rdx * mid, oy + rdy * mid, oz + rdz * mid) <= 1) hi = mid; else lo = mid;
              }
              const hx = ox + rdx * hi, hy = oy + rdy * hi, hz = oz + rdz * hi;

              // Normal: gradient of the implicit surface, in object space.
              const gx = Math.pow(Math.abs(hx), nm1) * Math.sign(hx);
              const gy = Math.pow(Math.abs(hy), nm1) * Math.sign(hy);
              const gz = Math.pow(Math.abs(hz), nm1) * Math.sign(hz);
              const gl = Math.hypot(gx, gy, gz) || 1;
              const ogx = gx / gl, ogy = gy / gl, ogz = gz / gl;

              // Back into view space with the transpose, so the light stays put
              // while the solid turns under it.
              const nvx = cA * ogx + sA * sB * ogy - sA * cB * ogz;
              const nvy = cB * ogy + sB * ogz;
              const nvz = sA * ogx - cA * sB * ogy + cA * cB * ogz;

              const diff = Math.max(0, nvx * LX + nvy * LY + nvz * LZ);

              // Specular: half-vector between the light and the view direction.
              const vx = -dx, vy = -dy, vz = -dz;
              let hxv = LX + vx, hyv = LY + vy, hzv = LZ + vz;
              const hl = Math.hypot(hxv, hyv, hzv) || 1;
              hxv /= hl; hyv /= hl; hzv /= hl;
              const spec = Math.pow(Math.max(0, nvx * hxv + nvy * hyv + nvz * hzv), 22) * 0.75;

              const facing = Math.abs(nvx * vx + nvy * vy + nvz * vz);
              const rim = Math.pow(1 - facing, 3) * 0.45;

              // Texture is sampled in object space, so it is painted onto the
              // solid and tumbles with it rather than sliding across the front.
              const nz = surfaceNoise(hx * 2.2, hy * 2.2, hz * 2.2);

              // Distance falloff: the far side sits lower on the ramp.
              const depth = 1 - Math.min(1, Math.max(0, (hi - (FOCAL - 1.4)) / 2.6)) * 0.3;

              let v = (diff * (0.5 + nz * 0.9) + spec + rim) * depth;
              if (wordAmt > 0) v *= 1 - wordAmt * 0.5;
              // A touch of stable per-cell dither breaks up the banding between
              // ramp steps, so the surface shades smoothly instead of stepping.
              v += (hash2(col, row) - 0.5) * 0.045;
              v = Math.max(0, Math.min(1, v));
              ch = RAMP[Math.round(v * (RAMP.length - 1))];
            }
          }

          if (ch === " " && hash2(col * 3.1 + Math.floor(t * 2), row * 1.7) > 0.988) ch = ".";

          if (dis > 0.05 && ch !== " " &&
              hash2(col + Math.floor(now / 55), row) < dis * 0.5 * (1 - wordAmt * 0.7)) {
            ch = GLITCH_CHARS[Math.floor(hash2(row, col + Math.floor(now / 55)) * GLITCH_CHARS.length)];
          }

          if (wordAmt > 0 && s.mask.has(cell)) {
            ch = wordAmt > 0.55 ? "#" : hash2(col, row) > 0.5 ? "%" : "*";
          }

          line += ch;
        }
        out.push(line);
      }

      const text = out.join("\n");
      const shove = p < 0 ? 0.6 : 0.6 + env * 4.5;
      const wob = reduced ? 0 : Math.sin(now / 95) * (p < 0 ? 0.3 : 1.5);

      if (baseRef.current) {
        baseRef.current.textContent = text;
        baseRef.current.style.color = `hsl(${hue} 70% 62%)`;
      }
      if (aRef.current) {
        aRef.current.textContent = text;
        aRef.current.style.color = `hsl(${(hue + 330) % 360} 80% 55%)`;
        aRef.current.style.transform = `translate(${-shove - wob}px, ${wob * 0.3}px)`;
      }
      if (bRef.current) {
        bRef.current.textContent = text;
        bRef.current.style.color = `hsl(${(hue + 30) % 360} 80% 55%)`;
        bRef.current.style.transform = `translate(${shove + wob}px, ${-wob * 0.3}px)`;
      }
      if (haloRef.current) {
        haloRef.current.style.background =
          `radial-gradient(circle, hsl(${hue} 70% 55% / 0.2) 0%, hsl(${hue} 70% 50% / 0.07) 45%, transparent 70%)`;
      }
    };

    if (reduced) { draw(performance.now()); return; }

    let raf = 0, last = 0;
    const loop = (now: number) => {
      raf = requestAnimationFrame(loop);
      if (now - last < 1000 / FPS) return;
      last = now;
      draw(now);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [hueCycle, baseHue]);

  const layer = "col-start-1 row-start-1 m-0 select-none whitespace-pre leading-none";
  const size = { fontSize: "clamp(5px, 1.3vw, 9px)", lineHeight: "1.02" as const };

  return (
    <button
      type="button"
      onClick={strike}
      aria-label="Decorative animation. Activate to disturb it."
      title="Click anywhere on it"
      className={`relative block w-full cursor-crosshair bg-transparent p-0 ${className}`}
    >
      {/* Ambient terms, drifting. Decorative and non-interactive. */}
      <span aria-hidden="true" className="pointer-events-none absolute inset-0">
        {ambient.map((a, i) => (
          <span
            key={i}
            className="orb-drift absolute text-[9px] tracking-[0.3em] text-accent/25"
            style={
              {
                top: a.top,
                left: a.left,
                "--rot": `${a.rot}deg`,
                animationDelay: a.delay,
                animationDuration: a.dur,
              } as React.CSSProperties
            }
          >
            {a.word}
          </span>
        ))}
      </span>

      <span ref={wrapRef} className="orb-float relative block">
        <span
          ref={haloRef}
          aria-hidden="true"
          className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full"
          style={{ width: "70%", aspectRatio: "1", filter: "blur(16px)" }}
        />
        <span className="relative grid justify-items-center">
          <pre ref={aRef} aria-hidden="true" className={`${layer} opacity-55`} style={{ ...size, mixBlendMode: "screen" }} />
          <pre ref={bRef} aria-hidden="true" className={`${layer} opacity-55`} style={{ ...size, mixBlendMode: "screen" }} />
          <pre ref={baseRef} aria-hidden="true" className={layer} style={{ ...size, mixBlendMode: "screen" }} />
        </span>
      </span>
    </button>
  );
}
