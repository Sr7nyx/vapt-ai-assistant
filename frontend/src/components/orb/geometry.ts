/**
 * The 3D maths, in TypeScript.
 *
 * Deliberately duplicated from the shader's `project()` rather than shared by
 * accident: the vulnerability labels are HTML, because WebGL text at this size is
 * either blurry or a font-atlas project, and HTML gives crisp monospaced glyphs on
 * a high-DPI screen for free. But an HTML label is only convincing if it sits
 * exactly where the shader would have drawn it, so both must use the same
 * projection. Keeping them side by side, with the same names, is what makes a
 * mismatch obvious.
 */

export type Mat3 = [number, number, number, number, number, number, number, number, number];
export type Vec3 = [number, number, number];

export const CAM_DIST = 3.25;
export const FOCAL = 2.05;

export function mul(a: Mat3, b: Mat3): Mat3 {
  const o = new Array(9).fill(0) as number[];
  for (let r = 0; r < 3; r++)
    for (let c = 0; c < 3; c++)
      o[r * 3 + c] = a[r * 3] * b[c] + a[r * 3 + 1] * b[3 + c] + a[r * 3 + 2] * b[6 + c];
  return o as Mat3;
}

export function rotY(a: number): Mat3 {
  const c = Math.cos(a), s = Math.sin(a);
  return [c, 0, -s, 0, 1, 0, s, 0, c];
}

export function rotX(a: number): Mat3 {
  const c = Math.cos(a), s = Math.sin(a);
  return [1, 0, 0, 0, c, s, 0, -s, c];
}

export function apply(m: Mat3, v: Vec3): Vec3 {
  return [
    m[0] * v[0] + m[1] * v[1] + m[2] * v[2],
    m[3] * v[0] + m[4] * v[1] + m[5] * v[2],
    m[6] * v[0] + m[7] * v[1] + m[8] * v[2],
  ];
}

/** Mirrors `project()` in the shader. Returns pixel offsets from the centre. */
export function project(p: Vec3, width: number, height: number) {
  const eyeZ = Math.max(CAM_DIST - p[2], 0.05);
  const short = Math.min(width, height);
  const long = Math.max(width, height);
  const m = short / long;
  const sx = (p[0] * FOCAL) / eyeZ;
  const sy = (p[1] * FOCAL) / eyeZ;
  const ax = width > height ? m : 1;
  const ay = width > height ? 1 : m;
  return {
    // Clip space is -1..1 across the full canvas, hence the halving.
    x: sx * ax * (width / 2),
    y: -sy * ay * (height / 2),
    eyeZ,
    z: p[2],
  };
}

/**
 * Two perpendicular unit vectors spanning a ring's plane. A ring is then just
 * A*cos(t) + B*sin(t), which is the same expression the shader evaluates.
 */
export function ringBasis(tiltDeg: number, rollDeg: number): { a: Vec3; b: Vec3 } {
  const m = mul(rotY((rollDeg * Math.PI) / 180), rotX((tiltDeg * Math.PI) / 180));
  return { a: apply(m, [1, 0, 0]), b: apply(m, [0, 0, 1]) };
}

/**
 * How visible a point is, given the sphere sits at the origin with radius ~1.
 *
 * A label behind the sphere must actually go behind it. Depth alone is not enough:
 * a label at the far side of its ring but off to the edge is still in clear view,
 * so occlusion needs the projected distance from the centre as well.
 */
export function occlusion(p: Vec3, sphereRadius = 1.0) {
  const behind = p[2] < 0;
  const radial = Math.hypot(p[0], p[1]);
  if (!behind) return 1;
  // Inside the silhouette: hidden. Just outside: a soft edge rather than a pop.
  const t = (radial - sphereRadius * 0.82) / (sphereRadius * 0.5);
  return Math.min(1, Math.max(0, t));
}

/** Fibonacci sphere: even coverage without the pole clustering of lat/long. */
export function fibonacciSphere(count: number): Float32Array {
  const out = new Float32Array(count * 3);
  const phi = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / Math.max(1, count - 1)) * 2;
    const r = Math.sqrt(Math.max(0, 1 - y * y));
    const th = phi * i;
    out[i * 3] = Math.cos(th) * r;
    out[i * 3 + 1] = y;
    out[i * 3 + 2] = Math.sin(th) * r;
  }
  return out;
}
