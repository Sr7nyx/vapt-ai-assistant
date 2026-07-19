"use client";
import { useEffect, useRef } from "react";

// A slow, drifting aurora rendered by a raw WebGL fragment shader (domain-warped
// fBm noise) in the app's accent teal. No three.js and no dependencies -- just a
// full-screen triangle and one shader program.
//
// Degrades gracefully: if WebGL is unavailable or the program fails to compile,
// nothing is drawn and the layers above (particles, content) still render.
// Honors prefers-reduced-motion by drawing a single static frame.

const VERT = `
attribute vec2 a_pos;
void main() {
  gl_Position = vec4(a_pos, 0.0, 1.0);
}
`;

const FRAG = `
precision mediump float;

uniform vec2 u_resolution;
uniform float u_time;

// Theme colours (matches tailwind.config: bg #0f1216, accent #5fb3ac).
const vec3 ACCENT = vec3(0.373, 0.702, 0.675);
const vec3 DEEP   = vec3(0.180, 0.360, 0.420);

float hash(vec2 p) {
  return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
}

float noise(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(
    mix(hash(i + vec2(0.0, 0.0)), hash(i + vec2(1.0, 0.0)), u.x),
    mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x),
    u.y
  );
}

float fbm(vec2 p) {
  float v = 0.0;
  float a = 0.5;
  for (int i = 0; i < 4; i++) {
    v += a * noise(p);
    p *= 2.02;
    a *= 0.5;
  }
  return v;
}

void main() {
  vec2 uv = gl_FragCoord.xy / u_resolution.xy;
  vec2 p = uv;
  p.x *= u_resolution.x / u_resolution.y;

  float t = u_time * 0.045;

  // Domain warp: noise offsetting noise gives the slow flowing ribbons.
  vec2 q = vec2(fbm(p * 1.6 + vec2(0.0, t)), fbm(p * 1.6 + vec2(4.7, 2.1) - t * 0.8));
  vec2 r = vec2(fbm(p * 1.9 + 2.4 * q + vec2(1.7, 9.2)), fbm(p * 1.9 + 2.4 * q + vec2(8.3, 2.8)));
  float f = fbm(p * 2.1 + 2.0 * r);

  // Shape it into soft bands and keep the whole thing quiet.
  float band = smoothstep(0.42, 0.95, f);
  vec3 col = mix(DEEP, ACCENT, clamp(r.x + 0.25, 0.0, 1.0));

  // Fade toward the edges so text stays readable and corners stay dark.
  float vignette = smoothstep(1.05, 0.15, distance(uv, vec2(0.5, 0.42)));

  float alpha = band * vignette * 0.30;
  gl_FragColor = vec4(col * alpha, alpha);
}
`;

function compile(gl: WebGLRenderingContext, type: number, src: string): WebGLShader | null {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, src);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

export default function ShaderField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let gl: WebGLRenderingContext | null = null;
    try {
      gl = (canvas.getContext("webgl", { alpha: true, antialias: false, depth: false }) ||
        canvas.getContext("experimental-webgl", { alpha: true, antialias: false, depth: false })) as WebGLRenderingContext | null;
    } catch {
      gl = null;
    }
    if (!gl) return;

    const vs = compile(gl, gl.VERTEX_SHADER, VERT);
    const fs = compile(gl, gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return;

    const program = gl.createProgram();
    if (!program) return;
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      gl.deleteProgram(program);
      return;
    }
    gl.useProgram(program);

    // Full-screen triangle (cheaper than a quad, no index buffer).
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(program, "a_pos");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

    const uRes = gl.getUniformLocation(program, "u_resolution");
    const uTime = gl.getUniformLocation(program, "u_time");

    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    let raf = 0;

    const resize = () => {
      if (!gl) return;
      const w = canvas.clientWidth || window.innerWidth;
      const h = canvas.clientHeight || window.innerHeight;
      canvas.width = Math.max(1, Math.floor(w * dpr));
      canvas.height = Math.max(1, Math.floor(h * dpr));
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform2f(uRes, canvas.width, canvas.height);
    };

    const render = (seconds: number) => {
      if (!gl) return;
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.uniform1f(uTime, seconds);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    };

    const start = performance.now();
    const loop = (now: number) => {
      render((now - start) / 1000);
      raf = requestAnimationFrame(loop);
    };

    resize();
    if (reduce) render(0);
    else raf = requestAnimationFrame(loop);
    window.addEventListener("resize", resize);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      if (!gl) return;
      gl.deleteBuffer(buffer);
      gl.deleteProgram(program);
      gl.deleteShader(vs);
      gl.deleteShader(fs);
    };
  }, []);

  return <canvas ref={canvasRef} className="absolute inset-0 h-full w-full" aria-hidden />;
}
