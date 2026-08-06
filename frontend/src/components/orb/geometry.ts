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

/** Floor on how flat a label may be squashed before it stops being legible. */
export const MIN_GLYPH_HEIGHT = 0.38;

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


/**
 * The 2D transform that lays a label flat INTO its ring's plane.
 *
 * An upright label positioned at a ring point reads as a tag floating nearby, not
 * as part of the ring. To belong to the band it has to lie in the band: baseline
 * running along the ring's tangent, its own "up" pointing outward along the radius,
 * and both foreshortening as the plane tilts away from the viewer -- the way a rock
 * in Saturn's rings sits in the plane rather than standing on it.
 *
 * So instead of a rotation, we project three nearby points -- the label's position,
 * a step along the tangent, and a step along the radius -- and build the affine
 * matrix that maps text space onto the plane the projection produced. Perspective
 * then comes out for free: the far side of a ring is genuinely smaller and flatter.
 */
export function planeMatrix(
  pos: Vec3,
  tangent: Vec3,
  radial: Vec3,
  rot: Mat3,
  width: number,
  height: number
) {
  const EPS = 0.05;
  // Pixels per world unit at the origin, so the matrix comes out near unit scale.
  const K = (FOCAL / CAM_DIST) * (Math.min(width, height) / 2);

  const at = (v: Vec3) => project(apply(rot, v), width, height);
  const p0 = at(pos);
  const p1 = at([pos[0] + tangent[0] * EPS, pos[1] + tangent[1] * EPS, pos[2] + tangent[2] * EPS]);
  const p2 = at([pos[0] + radial[0] * EPS, pos[1] + radial[1] * EPS, pos[2] + radial[2] * EPS]);

  const d = EPS * K;
  let a = (p1.x - p0.x) / d;
  let b = (p1.y - p0.y) / d;
  let c = (p2.x - p0.x) / d;
  let e = (p2.y - p0.y) / d;

  // Half of every orbit runs right-to-left, where the mapping would render the
  // text mirrored. Rotating it 180 degrees in-plane keeps it reading correctly
  // without lifting it out of the band.
  const flipped = a < 0;
  if (flipped) {
    a = -a; b = -b; c = -c; e = -e;
  }

  // Where the plane turns edge-on, the true projection squashes the glyphs to a
  // line. That is physically right and visually useless -- the label simply
  // vanishes and then snaps back. So the height perpendicular to the baseline is
  // floored: still clearly foreshortened, never collapsed.
  const exLen = Math.hypot(a, b) || 1e-6;
  const nx = -b / exLen, ny = a / exLen;          // unit normal to the baseline
  const along = (c * a + e * b) / exLen;          // component of "up" along the baseline
  let perp = c * nx + e * ny;                     // and perpendicular to it
  const sign = perp < 0 ? -1 : 1;
  perp = sign * Math.max(Math.abs(perp), MIN_GLYPH_HEIGHT);
  c = (a / exLen) * along + nx * perp;
  e = (b / exLen) * along + ny * perp;

  return { a, b, c, d: e, x: p0.x, y: p0.y, z: apply(rot, pos)[2], flipped };
}

/** Unit tangent and outward radial at parameter `ang` on a ring. */
export function ringFrame(basisA: Vec3, basisB: Vec3, ang: number) {
  const ca = Math.cos(ang), sa = Math.sin(ang);
  const radial: Vec3 = [
    basisA[0] * ca + basisB[0] * sa,
    basisA[1] * ca + basisB[1] * sa,
    basisA[2] * ca + basisB[2] * sa,
  ];
  const tangent: Vec3 = [
    -basisA[0] * sa + basisB[0] * ca,
    -basisA[1] * sa + basisB[1] * ca,
    -basisA[2] * sa + basisB[2] * ca,
  ];
  return { radial, tangent };
}
