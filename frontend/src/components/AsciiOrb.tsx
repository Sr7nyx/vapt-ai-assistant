"use client";
import { useCallback, useEffect, useRef } from "react";

/**
 * An ASCII orb: a lit, rotating sphere rendered into a character grid, with
 * chromatic-aberration glitch layers. Clicking it shatters the sphere, resolves
 * the debris into a word, then lets it re-form.
 *
 * Rendered by raycasting a unit sphere per character cell and mapping the shaded
 * surface to a density ramp, so there is no image asset and no 3D library: the
 * whole thing is arithmetic and a <pre>.
 *
 * The frame is written straight to the DOM nodes through refs rather than React
 * state, because re-rendering a component ~28 times a second to swap one string
 * would cost far more than the drawing does.
 */

const COLS = 72;
const ROWS = 32;
const FPS = 28;

// Low to high density. The ramp is the whole look: too short and the sphere
// posterizes into bands, too long and it turns to mush.
const RAMP = " .,:;=+ox*OQ#%@";
const GLITCH_CHARS = "!<>-_/[]{}=+*^?#%$&@01xX";

// 5x7 glyphs, one row per five characters. Only what a security vocabulary needs.
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

/** Deterministic per-cell noise, so a given cell shatters the same way each time
 *  rather than boiling randomly between frames. */
function hash2(x: number, y: number): number {
  const s = Math.sin(x * 127.1 + y * 311.7) * 43758.5453;
  return s - Math.floor(s);
}

function hash3(x: number, y: number, z: number): number {
  const s = Math.sin(x * 12.9898 + y * 78.233 + z * 37.719) * 43758.5453;
  return s - Math.floor(s);
}

/** Smooth value noise over the sphere surface, so the skin has structure that
 *  travels with the rotation instead of a flat shaded ball. */
function surfaceNoise(x: number, y: number, z: number): number {
  let sum = 0;
  let amp = 0.5;
  let f = 1.6;
  for (let o = 0; o < 3; o++) {
    const xi = Math.floor(x * f), yi = Math.floor(y * f), zi = Math.floor(z * f);
    const xf = x * f - xi, yf = y * f - yi, zf = z * f - zi;
    const sx = xf * xf * (3 - 2 * xf), sy = yf * yf * (3 - 2 * yf), sz = zf * zf * (3 - 2 * zf);
    let acc = 0;
    for (let dz = 0; dz < 2; dz++) {
      for (let dy = 0; dy < 2; dy++) {
        for (let dx = 0; dx < 2; dx++) {
          const w =
            (dx ? sx : 1 - sx) * (dy ? sy : 1 - sy) * (dz ? sz : 1 - sz);
          acc += hash3(xi + dx, yi + dy, zi + dz) * w;
        }
      }
    }
    sum += acc * amp;
    amp *= 0.5;
    f *= 2.1;
  }
  return sum;
}

/** Cells lit by the word's glyphs, centred in the grid. */
function wordMask(word: string): Set<number> {
  const on = new Set<number>();
  const letters = word.toUpperCase().split("").filter((c) => FONT[c]);
  if (!letters.length) return on;

  const scale = letters.length > 7 ? 1 : 2;          // long words render smaller
  const glyphW = 5 * scale + scale;                   // glyph plus one-column gap
  const totalW = glyphW * letters.length - scale;
  const startCol = Math.round((COLS - totalW) / 2);
  const startRow = Math.round((ROWS - 7 * scale) / 2);

  letters.forEach((ch, i) => {
    const bits = FONT[ch];
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 5; c++) {
        if (bits[r * 5 + c] !== "1") continue;
        for (let sr = 0; sr < scale; sr++) {
          for (let sc = 0; sc < scale; sc++) {
            const col = startCol + i * glyphW + c * scale + sc;
            const row = startRow + r * scale + sr;
            if (col >= 0 && col < COLS && row >= 0 && row < ROWS) on.add(row * COLS + col);
          }
        }
      }
    }
  });
  return on;
}

export default function AsciiOrb({
  words = DEFAULT_WORDS,
  className = "",
}: {
  words?: string[];
  className?: string;
}) {
  const baseRef = useRef<HTMLPreElement>(null);
  const redRef = useRef<HTMLPreElement>(null);
  const cyanRef = useRef<HTMLPreElement>(null);
  const state = useRef({ start: 0, breakAt: -1, word: "", wordIdx: 0, mask: new Set<number>() });

  const shatter = useCallback(() => {
    const s = state.current;
    // Ignore clicks while a break is already resolving, so mashing the orb does
    // not restart the animation mid-word.
    if (s.breakAt >= 0) return;
    s.word = words[s.wordIdx % words.length];
    s.wordIdx += 1;
    s.mask = wordMask(s.word);
    s.breakAt = performance.now();
  }, [words]);

  useEffect(() => {
    const reduced =
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const s = state.current;
    s.start = performance.now();

    const radiusRows = ROWS * 0.44;
    const radiusCols = radiusRows / 0.5;   // monospace cells are about half as wide as tall
    const cx = (COLS - 1) / 2;
    const cy = (ROWS - 1) / 2;

    // Fixed light, so rotation reads as the surface moving under it.
    const LX = -0.45, LY = -0.62, LZ = 0.64;

    const draw = (now: number) => {
      const t = reduced ? 0 : (now - s.start) / 1000;

      let p = -1;                                   // break progress, 0..1
      if (s.breakAt >= 0) {
        p = (now - s.breakAt) / BREAK_MS;
        if (p >= 1) { p = -1; s.breakAt = -1; s.mask = new Set(); }
      }

      // The debris peaks first, then settles back while the word holds, so the
      // letters are not fighting maximum noise for the reader's attention. It
      // re-scatters briefly before the sphere re-forms.
      const shatterAmt =
        p < 0 ? 0
        : p < 0.26 ? p / 0.26
        : p < 0.4 ? 1 - ((p - 0.26) / 0.14) * 0.62
        : p < 0.68 ? 0.38
        : p < 0.82 ? 0.38 + ((p - 0.68) / 0.14) * 0.5
        : 1 - (p - 0.82) / 0.18;
      const wordAmt =
        p < 0 ? 0
        : p < 0.28 ? 0
        : p < 0.38 ? (p - 0.28) / 0.1
        : p < 0.68 ? 1
        : p < 0.78 ? 1 - (p - 0.68) / 0.1
        : 0;

      const ca = Math.cos(t * 0.45), sa = Math.sin(t * 0.45);
      const cb = Math.cos(t * 0.21), sb = Math.sin(t * 0.21);

      const out: string[] = [];
      for (let row = 0; row < ROWS; row++) {
        let line = "";
        for (let col = 0; col < COLS; col++) {
          const cell = row * COLS + col;

          // Debris displacement: each cell samples the sphere from an offset
          // position, so the image tears apart rather than simply fading.
          let sx = col, sy = row;
          if (shatterAmt > 0) {
            const ang = hash2(col, row) * Math.PI * 2;
            const mag = (0.4 + hash2(row, col) * 1.6) * shatterAmt * 9;
            sx = col + Math.cos(ang) * mag;
            sy = row + Math.sin(ang) * mag * 0.5;
          }

          const x = (sx - cx) / radiusCols;
          const y = (sy - cy) / radiusRows;
          const d2 = x * x + y * y;

          let ch = " ";
          if (d2 <= 1) {
            const z = Math.sqrt(1 - d2);
            const lum = Math.max(0, x * LX + y * LY + z * LZ);

            // Rotate the sample point, not the light, so the texture travels.
            const rx = x * ca - z * sa;
            const rz = x * sa + z * ca;
            const ry = y * cb - rz * sb;
            const rz2 = y * sb + rz * cb;

            const n = surfaceNoise(rx * 2.4, ry * 2.4, rz2 * 2.4);
            const rim = Math.pow(1 - z, 3) * 0.55;
            let v = lum * (0.42 + n * 0.95) + rim;
            v = Math.max(0, Math.min(1, v));

            // Pull the body down the ramp while a word is showing: the sphere
            // recedes so the letters are the brightest thing on screen.
            if (wordAmt > 0) v *= 1 - wordAmt * 0.55;
            const idx = Math.round(v * (RAMP.length - 1));
            ch = RAMP[idx];
          } else if (d2 < 2.6 && hash2(col * 3.1 + Math.floor(t * 2), row * 1.7) > 0.982) {
            // Sparse motes drifting outside the body.
            ch = ".";
          }

          // Corruption during the break.
          if (shatterAmt > 0 && ch !== " ") {
            if (hash2(col + Math.floor(now / 60), row) < shatterAmt * 0.42 * (1 - wordAmt * 0.7)) {
              ch = GLITCH_CHARS[Math.floor(hash2(row, col + Math.floor(now / 60)) * GLITCH_CHARS.length)];
            }
          }

          // The word burns through the debris.
          if (wordAmt > 0 && s.mask.has(cell)) {
            ch = wordAmt > 0.55 ? "#" : hash2(col, row) > 0.5 ? "%" : "*";
          }

          line += ch;
        }
        out.push(line);
      }

      const text = out.join("\n");
      if (baseRef.current) baseRef.current.textContent = text;

      // Chromatic split: the same frame twice more, nudged apart. It widens
      // during a break, which is what makes the shatter read as damage.
      const jitter = p < 0 ? 0.6 : 0.6 + shatterAmt * 5;
      const wobble = reduced ? 0 : Math.sin(now / 90) * (p < 0 ? 0.3 : 1.6);
      if (redRef.current) {
        redRef.current.textContent = text;
        redRef.current.style.transform = `translate(${-jitter - wobble}px, ${wobble * 0.3}px)`;
      }
      if (cyanRef.current) {
        cyanRef.current.textContent = text;
        cyanRef.current.style.transform = `translate(${jitter + wobble}px, ${-wobble * 0.3}px)`;
      }
    };

    if (reduced) {
      draw(performance.now());
      return;
    }

    let raf = 0;
    let last = 0;
    const loop = (now: number) => {
      raf = requestAnimationFrame(loop);
      if (now - last < 1000 / FPS) return;
      last = now;
      draw(now);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, []);

  const layer = "col-start-1 row-start-1 m-0 select-none whitespace-pre leading-none";
  const size = { fontSize: "clamp(5px, 1.35vw, 9.5px)", lineHeight: "1.02" as const };

  return (
    <button
      type="button"
      onClick={shatter}
      aria-label="Decorative animation. Activate to scramble it."
      title="Click to break it"
      className={`group relative block w-full cursor-pointer bg-transparent p-0 ${className}`}
    >
      {/* Glow behind the body. */}
      <span
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full"
        style={{
          width: "68%",
          aspectRatio: "1",
          background:
            "radial-gradient(circle, rgba(var(--phosphor),0.16) 0%, rgba(var(--phosphor),0.06) 45%, transparent 70%)",
          filter: "blur(14px)",
        }}
      />
      <span className="relative grid justify-items-center">
        <pre ref={redRef} aria-hidden="true" className={`${layer} text-danger opacity-60`} style={{ ...size, mixBlendMode: "screen" }} />
        <pre ref={cyanRef} aria-hidden="true" className={`${layer} text-info opacity-60`} style={{ ...size, mixBlendMode: "screen" }} />
        <pre ref={baseRef} aria-hidden="true" className={`${layer} text-accent`} style={{ ...size, mixBlendMode: "screen" }} />
      </span>
    </button>
  );
}
