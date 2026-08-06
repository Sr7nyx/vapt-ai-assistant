"use client";
import { useEffect, useRef } from "react";
import { motionReduced } from "@/lib/motion";

/**
 * Raymarched plasma sphere, drawn in a fragment shader.
 *
 * Replaces the ASCII orb. That one computed the same geometry in JavaScript and
 * then quantised it to a 74x34 character grid, which capped it at roughly 2,500
 * samples and made every edge a stair. Here the same surface is evaluated per
 * pixel on the GPU, so it is smooth, and the noise, rim light and glow cost
 * nothing extra.
 *
 * The palette is derived from --phosphor at runtime rather than hard-coded, so it
 * follows the theme rather than restating it.
 */

const VERT = `
attribute vec2 a;
void main() { gl_Position = vec4(a, 0.0, 1.0); }
`;

const FRAG = `
precision highp float;
uniform vec2  u_res;
uniform float u_time;
uniform vec3  u_tint;     // phosphor, linearised
uniform float u_impact;   // 0..1, decays after a click
uniform vec2  u_hit;      // where the click landed, in clip space

// --- value noise -------------------------------------------------------------
float hash(vec3 p) {
  p = fract(p * 0.3183099 + vec3(0.1, 0.2, 0.3));
  p *= 17.0;
  return fract(p.x * p.y * p.z * (p.x + p.y + p.z));
}
float noise(vec3 x) {
  vec3 i = floor(x), f = fract(x);
  f = f * f * (3.0 - 2.0 * f);
  return mix(mix(mix(hash(i + vec3(0,0,0)), hash(i + vec3(1,0,0)), f.x),
                 mix(hash(i + vec3(0,1,0)), hash(i + vec3(1,1,0)), f.x), f.y),
             mix(mix(hash(i + vec3(0,0,1)), hash(i + vec3(1,0,1)), f.x),
                 mix(hash(i + vec3(0,1,1)), hash(i + vec3(1,1,1)), f.x), f.y), f.z);
}
float fbm(vec3 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 5; i++) { v += a * noise(p); p *= 2.03; a *= 0.5; }
  return v;
}

mat3 rotY(float a){ float c=cos(a), s=sin(a); return mat3(c,0.,-s, 0.,1.,0., s,0.,c); }
mat3 rotX(float a){ float c=cos(a), s=sin(a); return mat3(1.,0.,0., 0.,c,s, 0.,-s,c); }

// A sphere that stays a sphere. The previous version displaced the surface by
// 0.16 -- a third of the radius -- which deformed the silhouette into a lump.
// The reference keeps a clean circular limb and carries ALL its character in
// surface energy and glow, so the displacement here is a sixth of that: enough to
// break up the specular, not enough to bend the outline.
float map(vec3 p, mat3 rot, float t) {
  vec3 q = rot * p;
  float d = length(p) - 1.0;
  float n = fbm(q * 3.4 + vec3(0.0, 0.0, t * 0.18)) - 0.5;
  return d - n * 0.028;
}

void main() {
  vec2 uv = (gl_FragCoord.xy * 2.0 - u_res) / min(u_res.x, u_res.y);
  vec3 ro = vec3(0.0, 0.0, 3.0);
  vec3 rd = normalize(vec3(uv, -1.9));

  float t = u_time;
  mat3 rot = rotX(sin(t * 0.17) * 0.35) * rotY(t * 0.22);

  // The click pushes a bulge outward near where it landed, then relaxes.
  float hit = 1.0 + u_impact * 0.22 * exp(-6.0 * length(uv - u_hit));

  float depth = 0.0;
  float hitDist = -1.0;
  for (int i = 0; i < 64; i++) {
    vec3 p = ro + rd * depth;
    float d = map(p / hit, rot, t) * hit;
    if (d < 0.0015) { hitDist = depth; break; }
    depth += d * 0.9;
    if (depth > 6.0) break;
  }

  vec3 col = vec3(0.0);
  float alpha = 0.0;

  if (hitDist > 0.0) {
    vec3 p = ro + rd * hitDist;
    vec2 e = vec2(0.0022, 0.0);
    vec3 n = normalize(vec3(
      map(p + e.xyy, rot, t) - map(p - e.xyy, rot, t),
      map(p + e.yxy, rot, t) - map(p - e.yxy, rot, t),
      map(p + e.yyx, rot, t) - map(p - e.yyx, rot, t)));

    vec3 lig = normalize(vec3(-0.45, 0.62, 0.65));
    float dif = max(dot(n, lig), 0.0);
    float spe = pow(max(dot(reflect(-lig, n), -rd), 0.0), 28.0);
    // Fresnel: the limb glows, which is what makes a sphere read as luminous
    // rather than as a lit ball.
    float fres = pow(1.0 - max(dot(n, -rd), 0.0), 3.4);

    // Surface energy: two scales of drifting cells, so it reads as something
    // active inside a shell rather than as a textured rock.
    vec3 q = rot * p;
    float cells = fbm(q * 7.0 + vec3(0.0, 0.0, t * 0.5));
    float fine  = fbm(q * 18.0 - vec3(0.0, 0.0, t * 0.9));
    float energy = pow(cells, 2.0) * 1.5 + pow(fine, 3.0) * 0.9;

    // Latitude banding, very faint, to give the rotation something to carry.
    float bands = 0.5 + 0.5 * sin(q.y * 22.0 + t * 0.6);

    col  = u_tint * (0.06 + dif * 0.42);          // the body stays dark
    col += u_tint * energy * 0.85;                 // the light comes from within
    col += u_tint * bands * energy * 0.35;
    col += u_tint * fres * 2.6;                    // and from the limb
    col += vec3(0.75, 1.0, 0.8) * spe * 0.55;
    alpha = 0.94;
  }

  // Two-stage bloom: a tight ring just off the limb, and a wide soft field. One
  // exponential alone either hugs the edge or washes the whole frame.
  float r = length(uv);
  float rim  = exp(-13.0 * max(r - 0.66, 0.0));
  float wide = exp(-2.4 * max(r - 0.66, 0.0));
  col   += u_tint * rim * 0.55;
  col   += u_tint * wide * 0.20;
  alpha  = max(alpha, max(rim * 0.7, wide * 0.34));

  col = col / (col + vec3(0.85));            // tonemap, keeps highlights from clipping
  col = pow(col, vec3(0.4545));              // to sRGB
  gl_FragColor = vec4(col, clamp(alpha, 0.0, 1.0));
}
`;

function compile(gl: WebGLRenderingContext, type: number, src: string) {
  const sh = gl.createShader(type);
  if (!sh) return null;
  gl.shaderSource(sh, src);
  gl.compileShader(sh);
  if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
    gl.deleteShader(sh);
    return null;
  }
  return sh;
}

/** Read --phosphor so the orb follows the theme instead of restating it. */
function phosphor(): [number, number, number] {
  if (typeof window === "undefined") return [0.49, 0.9, 0.53];
  const raw = getComputedStyle(document.documentElement).getPropertyValue("--phosphor");
  const parts = raw.split(",").map((n) => parseFloat(n.trim()));
  if (parts.length !== 3 || parts.some(Number.isNaN)) return [0.49, 0.9, 0.53];
  return parts.map((v) => Math.pow(v / 255, 2.2)) as [number, number, number];
}

export default function ShaderOrb({
  className = "",
  interactive = true,
}: {
  className?: string;
  interactive?: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const impact = useRef({ value: 0, x: 0, y: 0 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const gl = (canvas.getContext("webgl", { alpha: true, antialias: false, premultipliedAlpha: false }) ||
      canvas.getContext("experimental-webgl", { alpha: true })) as WebGLRenderingContext | null;
    if (!gl) return;

    const vs = compile(gl, gl.VERTEX_SHADER, VERT);
    const fs = compile(gl, gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return;
    const prog = gl.createProgram();
    if (!prog) return;
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
    gl.useProgram(prog);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "a");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

    const uRes = gl.getUniformLocation(prog, "u_res");
    const uTime = gl.getUniformLocation(prog, "u_time");
    const uTint = gl.getUniformLocation(prog, "u_tint");
    const uImpact = gl.getUniformLocation(prog, "u_impact");
    const uHit = gl.getUniformLocation(prog, "u_hit");

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    gl.uniform3fv(uTint, phosphor());

    // Capped device pixel ratio: this is a full-screen fragment shader, and 3x on
    // a phone costs nine times the fill for no visible gain.
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 1.75);
      const w = Math.max(1, Math.round(canvas.clientWidth * dpr));
      const h = Math.max(1, Math.round(canvas.clientHeight * dpr));
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
        gl.viewport(0, 0, w, h);
      }
      gl.uniform2f(uRes, canvas.width, canvas.height);
    };
    resize();
    window.addEventListener("resize", resize);

    const reduced = motionReduced();
    let raf = 0;
    let last = performance.now();
    const start = last;

    const frame = (now: number) => {
      const dt = Math.min((now - last) / 1000, 0.05);
      last = now;
      resize();
      impact.current.value *= Math.exp(-2.6 * dt);
      gl.uniform1f(uTime, (now - start) / 1000);
      gl.uniform1f(uImpact, impact.current.value);
      gl.uniform2f(uHit, impact.current.x, impact.current.y);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      raf = requestAnimationFrame(frame);
    };

    if (reduced) {
      // One frame, at a fixed time, so the shape is still shown but nothing moves.
      gl.uniform1f(uTime, 2.0);
      gl.uniform1f(uImpact, 0);
      gl.uniform2f(uHit, 0, 0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    } else {
      raf = requestAnimationFrame(frame);
    }

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      gl.deleteProgram(prog);
      gl.deleteShader(vs);
      gl.deleteShader(fs);
      gl.deleteBuffer(buf);
    };
  }, []);

  const strike = (e: React.MouseEvent) => {
    const el = canvasRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const m = Math.min(r.width, r.height);
    impact.current = {
      value: 1,
      x: ((e.clientX - r.left) * 2 - r.width) / m,
      y: -(((e.clientY - r.top) * 2 - r.height) / m),
    };
  };

  return (
    <canvas
      ref={canvasRef}
      onClick={interactive ? strike : undefined}
      aria-hidden="true"
      className={`block w-full aspect-square ${interactive ? "cursor-crosshair" : ""} ${className}`}
    />
  );
}
