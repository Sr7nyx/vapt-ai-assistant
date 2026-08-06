/**
 * GLSL for the reactive orb.
 *
 * Kept apart from the component so the shader work is readable on its own, and so
 * the sphere and the rings can share the noise and projection code rather than
 * drifting from one another.
 */

/** Ashima/Gustavson simplex noise, the standard compact implementation. */
export const SIMPLEX = `
vec3 mod289(vec3 x){ return x - floor(x * (1.0/289.0)) * 289.0; }
vec4 mod289(vec4 x){ return x - floor(x * (1.0/289.0)) * 289.0; }
vec4 permute(vec4 x){ return mod289(((x*34.0)+1.0)*x); }
vec4 taylorInvSqrt(vec4 r){ return 1.79284291400159 - 0.85373472095314 * r; }

float snoise(vec3 v){
  const vec2 C = vec2(1.0/6.0, 1.0/3.0);
  const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
  vec3 i  = floor(v + dot(v, C.yyy));
  vec3 x0 = v - i + dot(i, C.xxx);
  vec3 g = step(x0.yzx, x0.xyz);
  vec3 l = 1.0 - g;
  vec3 i1 = min(g.xyz, l.zxy);
  vec3 i2 = max(g.xyz, l.zxy);
  vec3 x1 = x0 - i1 + C.xxx;
  vec3 x2 = x0 - i2 + C.yyy;
  vec3 x3 = x0 - D.yyy;
  i = mod289(i);
  vec4 p = permute(permute(permute(
             i.z + vec4(0.0, i1.z, i2.z, 1.0))
           + i.y + vec4(0.0, i1.y, i2.y, 1.0))
           + i.x + vec4(0.0, i1.x, i2.x, 1.0));
  float n_ = 0.142857142857;
  vec3 ns = n_ * D.wyz - D.xzx;
  vec4 j = p - 49.0 * floor(p * ns.z * ns.z);
  vec4 x_ = floor(j * ns.z);
  vec4 y_ = floor(j - 7.0 * x_);
  vec4 x = x_ * ns.x + ns.yyyy;
  vec4 y = y_ * ns.x + ns.yyyy;
  vec4 h = 1.0 - abs(x) - abs(y);
  vec4 b0 = vec4(x.xy, y.xy);
  vec4 b1 = vec4(x.zw, y.zw);
  vec4 s0 = floor(b0) * 2.0 + 1.0;
  vec4 s1 = floor(b1) * 2.0 + 1.0;
  vec4 sh = -step(h, vec4(0.0));
  vec4 a0 = b0.xzyw + s0.xzyw * sh.xxyy;
  vec4 a1 = b1.xzyw + s1.xzyw * sh.zzww;
  vec3 p0 = vec3(a0.xy, h.x);
  vec3 p1 = vec3(a0.zw, h.y);
  vec3 p2 = vec3(a1.xy, h.z);
  vec3 p3 = vec3(a1.zw, h.w);
  vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2,p2), dot(p3,p3)));
  p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
  vec4 m = max(0.6 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0);
  m = m * m;
  return 42.0 * dot(m*m, vec4(dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3)));
}
`;

/** One projection, used by both programs and mirrored in TypeScript for the text. */
export const PROJECT = `
uniform mat3  u_rot;
uniform float u_camDist;
uniform float u_focal;
uniform vec2  u_res;

// Returns clip position; writes eye-space depth so callers can shade by it.
vec4 project(vec3 objPos, out float eyeZ) {
  vec3 p = u_rot * objPos;
  eyeZ = u_camDist - p.z;
  float m = min(u_res.x, u_res.y) / max(u_res.x, u_res.y);
  vec2 s = p.xy * u_focal / max(eyeZ, 0.05);
  // Scale by the shorter axis so the orb is round at any aspect.
  vec2 aspect = u_res.x > u_res.y ? vec2(m, 1.0) : vec2(1.0, m);
  return vec4(s * aspect, 0.0, 1.0);
}
`;

export const SPHERE_VERT = `
precision highp float;
attribute vec3  a_pos;      // unit-sphere position
attribute vec2  a_seed;     // per-particle randomness
attribute vec3  a_tint;     // severity colour, when the orb is reporting one
attribute vec3  a_tint;     // this particle's colour (severity mix, or theme green)

uniform float u_time;
uniform float u_shock;      // 0..1, decays after a click
uniform vec3  u_shockDir;   // object-space direction the click landed on
uniform float u_hover;      // 0..1, eased
uniform float u_dpr;
uniform float u_pointScale;
uniform float u_calm;       // 1 normally, 0 under reduced motion

${SIMPLEX}
${PROJECT}

varying float v_depth;
varying float v_energy;
varying float v_seed;
varying vec3  v_tint;

void main() {
  v_tint = a_tint;
  vec3 dir = normalize(a_pos);

  // Layered noise: a slow swell, and a finer band that drifts the other way.
  float n1 = snoise(dir * 1.5 + vec3(0.0, 0.0, u_time * 0.12));
  float n2 = snoise(dir * 4.2 - vec3(0.0, 0.0, u_time * 0.19));
  float breathe = 0.012 * sin(u_time * 0.7);

  float disp = (n1 * 0.055 + n2 * 0.022) * u_calm + breathe;

  // Shockwave: a band expanding away from the click point, not a uniform scale.
  float ang = acos(clamp(dot(dir, u_shockDir), -1.0, 1.0));
  float front = u_shock * 3.2;
  float wave = exp(-14.0 * abs(ang - front)) * u_shock;
  disp += wave * 0.20;

  // The pointer lifts particles near it a little.
  disp += u_hover * 0.012 * n2;

  float r = 1.0 + disp;
  vec3 pos = dir * r;

  float eyeZ;
  gl_Position = project(pos, eyeZ);

  v_depth  = clamp((u_camDist + 1.0 - eyeZ) / 2.0, 0.0, 1.0);   // 1 front, 0 back
  v_energy = clamp(n2 * 0.5 + 0.5, 0.0, 1.0) + wave * 1.6;
  v_seed   = a_seed.x;
  v_tint   = a_tint;

  // Nearer particles are larger. Sizes are in device pixels, hence u_dpr.
  float size = u_pointScale * (0.55 + v_depth * 0.9) * (0.7 + a_seed.y * 0.6);
  gl_PointSize = max(1.0, size * u_dpr);
}
`;

export const SPHERE_FRAG = `
precision highp float;

uniform float u_hover;

varying float v_depth;
varying float v_energy;
varying float v_seed;
varying vec3  v_tint;

void main() {
  // Round the point and soften its edge; a square particle reads as a bug.
  vec2 d = gl_PointCoord - vec2(0.5);
  float r = length(d) * 2.0;
  float mask = smoothstep(1.0, 0.35, r);
  if (mask <= 0.003) discard;

  // Each particle carries its own colour. When the orb is showing a severity
  // mix that is the finding's band; otherwise it is the theme green, and the
  // shading below is identical either way.
  vec3 deep = v_tint * 0.28;
  vec3 col = mix(deep, v_tint, smoothstep(0.10, 0.72, v_depth));
  // The energetic front-facing particles brighten toward their own hue rather
  // than toward white, so a red particle never flares pink.
  col = mix(col, min(v_tint * 1.9, vec3(1.0)), smoothstep(0.62, 1.05, v_energy * v_depth));

  // Rear particles stay dim, which is what gives the cloud its volume -- but not
  // so dim that a small instance reads as empty.
  float a = mask * (0.14 + pow(v_depth, 1.5) * 0.86);
  a *= 0.78 + v_seed * 0.44;
  a *= 1.0 + u_hover * 0.22;

  gl_FragColor = vec4(col, clamp(a, 0.0, 1.0));
}
`;

export const RING_VERT = `
precision highp float;
attribute float a_t;        // 0..1 around the ring
attribute float a_ring;     // which ring

uniform float u_time;
uniform float u_shock;
uniform vec3  u_ringA[3];   // basis vectors, per ring
uniform vec3  u_ringB[3];
uniform float u_ringR[3];
uniform float u_ringSpeed[3];
uniform float u_dpr;
uniform float u_calm;

${PROJECT}

varying float v_depth;
varying float v_scan;

void main() {
  int idx = int(a_ring + 0.5);
  vec3 A = u_ringA[0]; vec3 B = u_ringB[0];
  float R = u_ringR[0]; float S = u_ringSpeed[0];
  if (idx == 1) { A = u_ringA[1]; B = u_ringB[1]; R = u_ringR[1]; S = u_ringSpeed[1]; }
  if (idx == 2) { A = u_ringA[2]; B = u_ringB[2]; R = u_ringR[2]; S = u_ringSpeed[2]; }

  // A click briefly speeds the belts up and nudges their radius.
  float spin = u_time * S * u_calm + u_shock * 0.5;
  float ang = a_t * 6.28318530718 + spin;
  float rr = R * (1.0 + u_shock * 0.03);
  vec3 pos = (A * cos(ang) + B * sin(ang)) * rr;

  float eyeZ;
  gl_Position = project(pos, eyeZ);
  v_depth = clamp((u_camDist + rr - eyeZ) / (2.0 * rr), 0.0, 1.0);

  // One brighter segment sweeping each belt, like a scan head.
  float head = fract(a_t - spin * 0.159);
  v_scan = pow(1.0 - min(head, 1.0 - head) * 2.0, 6.0);

  gl_PointSize = max(1.0, (0.9 + v_depth * 1.3 + v_scan * 2.2) * u_dpr);
}
`;

export const RING_FRAG = `
precision highp float;
uniform vec3  u_green;
uniform vec3  u_lime;
uniform float u_hover;
varying float v_depth;
varying float v_scan;

void main() {
  vec2 d = gl_PointCoord - vec2(0.5);
  if (length(d) > 0.5) discard;

  vec3 col = mix(u_green * 0.55, u_lime, v_scan * 0.8);
  // Belts must never outshine the sphere, so the ceiling here is deliberately low.
  float a = (0.10 + v_depth * 0.26 + v_scan * 0.38) * (1.0 + u_hover * 0.3);
  gl_FragColor = vec4(col, clamp(a, 0.0, 0.72));
}
`;
