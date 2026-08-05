"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motionReduced } from "@/lib/motion";

/**
 * A dependency-free WebGL point-cloud orb inspired by the reactive Spline scene.
 *
 * The points live on a Fibonacci sphere and are displaced in the vertex shader.
 * Pointer proximity pushes the surface away; clicking sends a second shockwave
 * through it. Depth testing keeps the dark beads solid while a small number of
 * high-energy points flare phosphor/lime.
 */

const VERTEX_SHADER = `
precision highp float;

attribute vec3 a_position;
attribute float a_seed;

uniform vec2 u_resolution;
uniform vec2 u_pointer;
uniform float u_time;
uniform float u_pulse;
uniform float u_presence;

varying float v_energy;
varying float v_seed;
varying float v_front;

mat2 rotate2d(float a) {
  float s = sin(a);
  float c = cos(a);
  return mat2(c, -s, s, c);
}

float surfaceWave(vec3 p, float t) {
  float a = sin(dot(p, vec3(3.7, 5.1, 4.3)) + t * 0.92);
  float b = sin(dot(p.yzx, vec3(7.4, 3.2, 5.8)) - t * 0.61);
  float c = sin((p.x * p.y + p.z) * 10.0 + t * 0.43);
  return (a + b * 0.62 + c * 0.38) / 2.0;
}

void main() {
  float t = u_time;
  vec3 p = a_position;

  float wave = surfaceWave(p, t + a_seed * 2.0);
  float slow = sin(t * 0.37 + a_seed * 6.2831) * 0.5 + 0.5;

  // Pointer lives in the same approximate projected space as the sphere.
  vec2 pointerOnSphere = u_pointer * vec2(0.92, 0.76);
  vec2 delta = p.xy - pointerOnSphere;
  float pointerDistance = length(delta);
  float pointerField = exp(-pointerDistance * pointerDistance * 8.0) * u_presence;

  // Click wave: expands from the click position rather than scaling the whole orb.
  float waveRadius = u_pulse * 1.75;
  float shock = exp(-pow(pointerDistance - waveRadius, 2.0) * 34.0) *
                sin((pointerDistance - waveRadius) * 28.0) *
                u_pulse;

  float radial = 1.0 + wave * 0.065 + slow * 0.018 + pointerField * 0.13 + shock * 0.17;
  p *= radial;

  vec2 pushDirection = pointerDistance > 0.001 ? delta / pointerDistance : vec2(0.0, 1.0);
  p.xy += pushDirection * pointerField * (0.10 + u_pulse * 0.14);

  // Slow autonomous tumble, with the cursor leaning the body toward the viewer.
  p.xz = rotate2d(t * 0.19 + u_pointer.x * 0.30) * p.xz;
  p.yz = rotate2d(-0.34 + sin(t * 0.14) * 0.08 - u_pointer.y * 0.22) * p.yz;
  p.xy = rotate2d(sin(t * 0.11) * 0.08) * p.xy;

  float camera = 3.25;
  float perspective = 1.0 / (camera - p.z);
  vec2 projected = p.xy * perspective * 2.36;
  projected.x *= u_resolution.y / max(u_resolution.x, 1.0);

  // Larger z is closer to the camera, so map it toward the near plane.
  gl_Position = vec4(projected, -p.z * 0.42, 1.0);

  float viewportScale = clamp(u_resolution.y / 430.0, 0.72, 1.55);
  float nearBoost = 0.82 + (p.z + 1.2) * 0.28;
  float sparkle = smoothstep(0.72, 1.0, slow + wave * 0.22);
  float energy = clamp(pointerField * 1.15 + abs(shock) * 1.35 + sparkle * 0.42, 0.0, 1.35);

  gl_PointSize = clamp(
    (2.0 + a_seed * 1.5 + energy * 4.2) * nearBoost * viewportScale,
    1.4,
    11.0
  );

  v_energy = energy;
  v_seed = a_seed;
  v_front = smoothstep(-0.86, 0.92, p.z);
}
`;

const FRAGMENT_SHADER = `
precision highp float;

varying float v_energy;
varying float v_seed;
varying float v_front;

void main() {
  vec2 point = gl_PointCoord * 2.0 - 1.0;
  float radius = dot(point, point);
  if (radius > 1.0) discard;

  float sphere = sqrt(max(0.0, 1.0 - radius));
  float edge = smoothstep(1.0, 0.62, radius);
  float highlight = pow(max(0.0, dot(normalize(vec3(point, sphere)), normalize(vec3(-0.55, -0.68, 1.0)))), 8.0);

  vec3 bead = vec3(0.018, 0.030, 0.021);
  vec3 phosphor = vec3(0.494, 0.906, 0.529);
  vec3 lime = vec3(0.776, 1.000, 0.204);
  vec3 whiteHot = vec3(0.875, 0.965, 0.890);

  // Most points remain near-black. A deterministic minority becomes live nodes.
  float liveNode = smoothstep(0.78, 0.995, v_seed + v_energy * 0.36);
  float flare = smoothstep(0.26, 1.05, v_energy);

  vec3 colour = bead;
  colour = mix(colour, phosphor, liveNode * (0.42 + v_front * 0.34));
  colour = mix(colour, lime, flare * 0.78);
  colour = mix(colour, whiteHot, highlight * (0.34 + liveNode * 0.58) + flare * 0.18);

  float alpha = edge * (0.62 + v_front * 0.24 + liveNode * 0.14);
  gl_FragColor = vec4(colour, alpha);
}
`;

type GLState = {
  gl: WebGLRenderingContext;
  program: WebGLProgram;
  positionBuffer: WebGLBuffer;
  seedBuffer: WebGLBuffer;
  vertexCount: number;
  uResolution: WebGLUniformLocation | null;
  uPointer: WebGLUniformLocation | null;
  uTime: WebGLUniformLocation | null;
  uPulse: WebGLUniformLocation | null;
  uPresence: WebGLUniformLocation | null;
};

function compileShader(
  gl: WebGLRenderingContext,
  type: number,
  source: string,
): WebGLShader | null {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    console.warn("ReactiveOrb shader compile failed:", gl.getShaderInfoLog(shader));
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

function createPointCloud(count: number): { positions: Float32Array; seeds: Float32Array } {
  const positions = new Float32Array(count * 3);
  const seeds = new Float32Array(count);
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));

  for (let i = 0; i < count; i += 1) {
    const y = 1 - (i / Math.max(1, count - 1)) * 2;
    const radius = Math.sqrt(Math.max(0, 1 - y * y));
    const theta = goldenAngle * i;

    positions[i * 3] = Math.cos(theta) * radius;
    positions[i * 3 + 1] = y;
    positions[i * 3 + 2] = Math.sin(theta) * radius;

    // Stable pseudo-random value without storing another JS object per point.
    const n = Math.sin((i + 1) * 12.9898) * 43758.5453;
    seeds[i] = n - Math.floor(n);
  }

  return { positions, seeds };
}

export default function ReactiveOrb({ className = "" }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const hostRef = useRef<HTMLButtonElement>(null);
  const stateRef = useRef<GLState | null>(null);
  const rafRef = useRef(0);
  const resizeObserverRef = useRef<ResizeObserver | null>(null);
  const reducedRef = useRef(false);
  const startRef = useRef(0);
  const pointerRef = useRef({ x: 0, y: 0, targetX: 0, targetY: 0, presence: 0, targetPresence: 0 });
  const pulseRef = useRef({ value: 0, startedAt: -1 });
  const [available, setAvailable] = useState(true);

  const renderFrame = useCallback((now: number) => {
    const state = stateRef.current;
    if (!state) return;

    const { gl } = state;
    const pointer = pointerRef.current;
    pointer.x += (pointer.targetX - pointer.x) * 0.075;
    pointer.y += (pointer.targetY - pointer.y) * 0.075;
    pointer.presence += (pointer.targetPresence - pointer.presence) * 0.09;

    let pulse = 0;
    if (pulseRef.current.startedAt >= 0) {
      const progress = Math.min(1, (now - pulseRef.current.startedAt) / 1050);
      pulse = 1 - progress;
      pulseRef.current.value = pulse;
      if (progress >= 1) pulseRef.current.startedAt = -1;
    }

    const elapsed = reducedRef.current ? 4.5 : (now - startRef.current) / 1000;

    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
    gl.uniform2f(state.uPointer, pointer.x, pointer.y);
    gl.uniform1f(state.uTime, elapsed);
    gl.uniform1f(state.uPulse, pulse);
    gl.uniform1f(state.uPresence, pointer.presence);
    gl.drawArrays(gl.POINTS, 0, state.vertexCount);
  }, []);

  const schedule = useCallback(() => {
    cancelAnimationFrame(rafRef.current);
    if (reducedRef.current) {
      rafRef.current = requestAnimationFrame(renderFrame);
      return;
    }

    const loop = (now: number) => {
      renderFrame(now);
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);
  }, [renderFrame]);

  const disrupt = useCallback(() => {
    if (!stateRef.current) return;
    pulseRef.current.startedAt = performance.now();
    if (reducedRef.current) renderFrame(performance.now());
  }, [renderFrame]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const host = hostRef.current;
    if (!canvas || !host) return;

    reducedRef.current = motionReduced();

    let gl: WebGLRenderingContext | null = null;
    try {
      gl = canvas.getContext("webgl", {
        alpha: true,
        antialias: true,
        depth: true,
        premultipliedAlpha: false,
        powerPreference: "high-performance",
      });
    } catch {
      gl = null;
    }

    if (!gl) {
      setAvailable(false);
      return;
    }

    const vertexShader = compileShader(gl, gl.VERTEX_SHADER, VERTEX_SHADER);
    const fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, FRAGMENT_SHADER);
    if (!vertexShader || !fragmentShader) {
      setAvailable(false);
      return;
    }

    const program = gl.createProgram();
    if (!program) {
      setAvailable(false);
      return;
    }
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      console.warn("ReactiveOrb program link failed:", gl.getProgramInfoLog(program));
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
      setAvailable(false);
      return;
    }

    gl.useProgram(program);
    gl.enable(gl.DEPTH_TEST);
    gl.depthFunc(gl.LEQUAL);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    const compact = window.matchMedia("(max-width: 640px)").matches;
    const vertexCount = compact ? 3600 : 6200;
    const { positions, seeds } = createPointCloud(vertexCount);

    const positionBuffer = gl.createBuffer();
    const seedBuffer = gl.createBuffer();
    if (!positionBuffer || !seedBuffer) {
      setAvailable(false);
      return;
    }

    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, positions, gl.STATIC_DRAW);
    const aPosition = gl.getAttribLocation(program, "a_position");
    gl.enableVertexAttribArray(aPosition);
    gl.vertexAttribPointer(aPosition, 3, gl.FLOAT, false, 0, 0);

    gl.bindBuffer(gl.ARRAY_BUFFER, seedBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, seeds, gl.STATIC_DRAW);
    const aSeed = gl.getAttribLocation(program, "a_seed");
    gl.enableVertexAttribArray(aSeed);
    gl.vertexAttribPointer(aSeed, 1, gl.FLOAT, false, 0, 0);

    const state: GLState = {
      gl,
      program,
      positionBuffer,
      seedBuffer,
      vertexCount,
      uResolution: gl.getUniformLocation(program, "u_resolution"),
      uPointer: gl.getUniformLocation(program, "u_pointer"),
      uTime: gl.getUniformLocation(program, "u_time"),
      uPulse: gl.getUniformLocation(program, "u_pulse"),
      uPresence: gl.getUniformLocation(program, "u_presence"),
    };
    stateRef.current = state;
    startRef.current = performance.now();

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 1.75);
      const width = Math.max(1, Math.floor(canvas.clientWidth * dpr));
      const height = Math.max(1, Math.floor(canvas.clientHeight * dpr));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }
      gl.viewport(0, 0, width, height);
      gl.uniform2f(state.uResolution, width, height);
      if (reducedRef.current) renderFrame(performance.now());
    };

    const updatePointer = (event: PointerEvent) => {
      const bounds = host.getBoundingClientRect();
      const x = ((event.clientX - bounds.left) / Math.max(bounds.width, 1)) * 2 - 1;
      const y = -(((event.clientY - bounds.top) / Math.max(bounds.height, 1)) * 2 - 1);
      pointerRef.current.targetX = Math.max(-1, Math.min(1, x));
      pointerRef.current.targetY = Math.max(-1, Math.min(1, y));
      pointerRef.current.targetPresence = 1;
      if (reducedRef.current) renderFrame(performance.now());
    };

    const leave = () => {
      pointerRef.current.targetX = 0;
      pointerRef.current.targetY = 0;
      pointerRef.current.targetPresence = 0;
      if (reducedRef.current) renderFrame(performance.now());
    };

    resize();
    schedule();
    host.addEventListener("pointermove", updatePointer);
    host.addEventListener("pointerleave", leave);

    if (typeof ResizeObserver !== "undefined") {
      resizeObserverRef.current = new ResizeObserver(resize);
      resizeObserverRef.current.observe(host);
    } else {
      window.addEventListener("resize", resize);
    }

    return () => {
      cancelAnimationFrame(rafRef.current);
      host.removeEventListener("pointermove", updatePointer);
      host.removeEventListener("pointerleave", leave);
      resizeObserverRef.current?.disconnect();
      window.removeEventListener("resize", resize);
      stateRef.current = null;
      gl.deleteBuffer(positionBuffer);
      gl.deleteBuffer(seedBuffer);
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
    };
  }, [renderFrame, schedule]);

  return (
    <button
      ref={hostRef}
      type="button"
      onClick={disrupt}
      aria-label="Disrupt the reactive evidence orb"
      className={`group relative block aspect-square w-full cursor-crosshair overflow-visible bg-transparent p-0 text-left outline-none focus-visible:ring-1 focus-visible:ring-accent/70 ${className}`}
    >
      <span
        aria-hidden="true"
        className="absolute inset-[12%] rounded-full opacity-70 blur-3xl transition-opacity duration-500 group-hover:opacity-100"
        style={{
          background:
            "radial-gradient(circle, rgba(var(--highlight),0.13) 0%, rgba(var(--phosphor),0.06) 42%, transparent 72%)",
        }}
      />

      {available ? (
        <canvas ref={canvasRef} className="absolute inset-0 h-full w-full" aria-hidden="true" />
      ) : (
        <span
          aria-hidden="true"
          className="absolute inset-[19%] rounded-full border border-accent/25"
          style={{
            background:
              "radial-gradient(circle at 34% 28%, rgba(223,255,228,0.9) 0 1%, rgba(var(--highlight),0.34) 2%, rgba(8,18,10,0.96) 34%, #020403 72%)",
            boxShadow:
              "inset -22px -28px 55px rgba(0,0,0,0.88), 0 0 55px rgba(var(--phosphor),0.12)",
          }}
        />
      )}

      <span aria-hidden="true" className="pointer-events-none absolute inset-[18%] rounded-full border border-highlight/10" />
      <span
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 h-[38%] w-[112%] -translate-x-1/2 -translate-y-1/2 rotate-[9deg] rounded-[50%] border border-accent/20 opacity-55"
        style={{ boxShadow: "0 0 18px rgba(var(--phosphor),0.08)" }}
      />
      <span
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 h-[28%] w-[96%] -translate-x-1/2 -translate-y-1/2 -rotate-[21deg] rounded-[50%] border border-highlight/10 opacity-40"
      />

      <span className="sr-only">Interactive WebGL visualization. Move the pointer over it or click to disrupt it.</span>
    </button>
  );
}
