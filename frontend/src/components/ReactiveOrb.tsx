"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { motionReduced } from "@/lib/motion";
import {
  SPHERE_VERT, SPHERE_FRAG, RING_VERT, RING_FRAG,
} from "./orb/shaders";
import {
  CAM_DIST, FOCAL, Mat3, Vec3, apply, fibonacciSphere, mul, occlusion, ringBasis, rotX, rotY,
  planeMatrix, ringFrame,
} from "./orb/geometry";

/**
 * The reactive orb: a particle sphere with orbiting analysis belts.
 *
 * Raw WebGL, no Three.js -- the project has no 3D dependency and this needs one
 * program for points and one for the belts, which is not enough to justify
 * several hundred kilobytes of scene graph.
 *
 * The sphere has no surface. It is a point cloud, dense at the centre and thinning
 * at the limb, with rear-facing particles left dark: that is what gives it volume
 * without ever looking like a plastic ball.
 *
 * The vulnerability labels are HTML, not WebGL. Text in a shader at this size is
 * either blurry or a font-atlas project of its own, and HTML gives crisp
 * monospaced glyphs on a high-DPI screen for nothing. They stay convincing because
 * they are positioned every frame from the SAME rotation matrix and the SAME
 * projection the shader uses -- they travel real 3D ellipses, and they are occluded
 * when they pass behind the cloud.
 */

/**
 * The belts carry the product's argument, not decoration.
 *
 *   OUTER  what is being analysed  -- vulnerability classes
 *   INNER  the analyser working on it -- EVIDENCE, VERIFY, CHALLENGE, VERDICT
 *
 * That split is the whole point. Rings of vulnerability names alone are a word
 * cloud; an inner belt turning inside them says the thing the tool actually does,
 * and it is the same four stages the pipeline runs.
 *
 * The inner belt turns the opposite way and faster, so the two read as separate
 * systems rather than one thick band.
 */
const RINGS = [
  {
    kind: "process" as const,
    // 52 rather than 70: at a flatter tilt this belt only spans +/-0.49 in depth,
    // so its labels never pass properly behind the sphere and the fade-behind
    // effect has nothing to act on. Measured, not guessed.
    tilt: 52,
    roll: 8,
    radius: 1.34,
    speed: -0.19,
    words: ["EVIDENCE", "VERIFY", "CHALLENGE", "VERDICT"],
  },
  {
    kind: "vuln" as const,
    tilt: 80,
    roll: -22,
    radius: 1.86,
    speed: 0.12,
    words: ["XSS", "SQLi", "IDOR", "SSRF", "XXE", "JWT"],
  },
  {
    kind: "vuln" as const,
    tilt: 66,
    roll: 48,
    radius: 2.24,
    speed: 0.068,
    words: ["CORS", "CSRF", "RCE", "SSTI", "OPEN REDIRECT", "PATH TRAVERSAL"],
  },
];

/** Which belt a capability card highlights when hovered. */
export type OrbFocus = "verify" | "challenge" | "report" | null;

const FOCUS_WORD: Record<string, string> = {
  verify: "VERIFY",
  challenge: "CHALLENGE",
  report: "VERDICT",
};

const PALETTE = {
  lime: [0.72, 1.0, 0.27] as Vec3,      // #B8FF45
  green: [0.46, 0.95, 0.54] as Vec3,    // #75F28A
  emerald: [0.11, 0.43, 0.26] as Vec3,  // #1D6E43
};

type Label = { key: string; ring: number; t: number; text: string; kind: "vuln" | "process" };

function compile(gl: WebGLRenderingContext, type: number, src: string) {
  const sh = gl.createShader(type);
  if (!sh) return null;
  gl.shaderSource(sh, src);
  gl.compileShader(sh);
  if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
    // Surfaced rather than swallowed: a shader error is otherwise silent, and the
    // page would just show an empty box with no clue why.
    console.error("[ReactiveOrb] shader:", gl.getShaderInfoLog(sh));
    gl.deleteShader(sh);
    return null;
  }
  return sh;
}

function link(gl: WebGLRenderingContext, vs: string, fs: string) {
  const v = compile(gl, gl.VERTEX_SHADER, vs);
  const f = compile(gl, gl.FRAGMENT_SHADER, fs);
  if (!v || !f) return null;
  const p = gl.createProgram();
  if (!p) return null;
  gl.attachShader(p, v);
  gl.attachShader(p, f);
  gl.linkProgram(p);
  gl.deleteShader(v);
  gl.deleteShader(f);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
    console.error("[ReactiveOrb] link:", gl.getProgramInfoLog(p));
    return null;
  }
  return p;
}

export default function ReactiveOrb({
  className = "",
  showLabels = true,
  focus = null,
}: {
  className?: string;
  /** Highlights one stage of the inner belt. Driven by the capability cards
   *  below the hero, so hovering VERIFY lights the verification stage. */
  focus?: OrbFocus;
  /** Off for small decorative instances, where the belts are legible but the
   *  words would not be. */
  showLabels?: boolean;
}) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const labelRefs = useRef<Map<string, HTMLSpanElement>>(new Map());
  const [failed, setFailed] = useState(false);

  // Read through a ref: the draw loop must see the current value without the
  // effect tearing down and rebuilding the WebGL context every time a card is
  // hovered.
  const focusRef = useRef<OrbFocus>(focus);
  focusRef.current = focus;

  const labels = useMemo<Label[]>(() => {
    const out: Label[] = [];
    RINGS.forEach((r, ri) =>
      r.words.forEach((w, wi) =>
        out.push({ key: `${ri}-${w}`, ring: ri, t: wi / r.words.length, text: w, kind: r.kind })
      )
    );
    return out;
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap) return;

    const gl = canvas.getContext("webgl", {
      alpha: true, antialias: true, premultipliedAlpha: false, depth: false,
    }) as WebGLRenderingContext | null;
    if (!gl) {
      setFailed(true);
      return;
    }

    const sphereProg = link(gl, SPHERE_VERT, SPHERE_FRAG);
    const ringProg = link(gl, RING_VERT, RING_FRAG);
    if (!sphereProg || !ringProg) {
      setFailed(true);
      return;
    }

    const reduced = motionReduced();
    const narrow = window.innerWidth < 640;

    // Density is what makes a point cloud read as a sphere, and density is a
    // function of the RENDERED size, not the viewport. At 160px, 6,200 particles
    // overlap into a solid disc; roughly one particle per 28 square pixels holds
    // the same look at any size.
    const box = Math.max(120, wrap.clientWidth || 320);
    const COUNT = Math.round(
      Math.min(narrow ? 2600 : 6400, Math.max(700, (box * box) / 28))
    );
    const smallBadge = box < 220;

    // --- buffers, built once -------------------------------------------------
    const base = fibonacciSphere(COUNT);
    const seeds = new Float32Array(COUNT * 2);
    for (let i = 0; i < COUNT; i++) {
      seeds[i * 2] = Math.random();
      seeds[i * 2 + 1] = Math.random();
    }
    const posBuf = gl.createBuffer()!;
    gl.bindBuffer(gl.ARRAY_BUFFER, posBuf);
    gl.bufferData(gl.ARRAY_BUFFER, base, gl.STATIC_DRAW);
    const seedBuf = gl.createBuffer()!;
    gl.bindBuffer(gl.ARRAY_BUFFER, seedBuf);
    gl.bufferData(gl.ARRAY_BUFFER, seeds, gl.STATIC_DRAW);

    const PER_RING = smallBadge ? 90 : narrow ? 150 : 260;
    const rt = new Float32Array(PER_RING * RINGS.length);
    const rIdx = new Float32Array(PER_RING * RINGS.length);
    for (let r = 0; r < RINGS.length; r++) {
      for (let i = 0; i < PER_RING; i++) {
        rt[r * PER_RING + i] = i / PER_RING;
        rIdx[r * PER_RING + i] = r;
      }
    }
    const rtBuf = gl.createBuffer()!;
    gl.bindBuffer(gl.ARRAY_BUFFER, rtBuf);
    gl.bufferData(gl.ARRAY_BUFFER, rt, gl.STATIC_DRAW);
    const riBuf = gl.createBuffer()!;
    gl.bindBuffer(gl.ARRAY_BUFFER, riBuf);
    gl.bufferData(gl.ARRAY_BUFFER, rIdx, gl.STATIC_DRAW);

    const bases = RINGS.map((r) => ringBasis(r.tilt, r.roll));

    // --- uniform lookups, once -----------------------------------------------
    const U = (p: WebGLProgram, n: string) => gl.getUniformLocation(p, n);
    const su = {
      rot: U(sphereProg, "u_rot"), time: U(sphereProg, "u_time"), res: U(sphereProg, "u_res"),
      cam: U(sphereProg, "u_camDist"), foc: U(sphereProg, "u_focal"), shock: U(sphereProg, "u_shock"),
      dir: U(sphereProg, "u_shockDir"), hover: U(sphereProg, "u_hover"), dpr: U(sphereProg, "u_dpr"),
      size: U(sphereProg, "u_pointScale"), calm: U(sphereProg, "u_calm"),
      lime: U(sphereProg, "u_lime"), green: U(sphereProg, "u_green"), emerald: U(sphereProg, "u_emerald"),
    };
    const ru = {
      rot: U(ringProg, "u_rot"), time: U(ringProg, "u_time"), res: U(ringProg, "u_res"),
      cam: U(ringProg, "u_camDist"), foc: U(ringProg, "u_focal"), shock: U(ringProg, "u_shock"),
      dpr: U(ringProg, "u_dpr"), calm: U(ringProg, "u_calm"), hover: U(ringProg, "u_hover"),
      green: U(ringProg, "u_green"), lime: U(ringProg, "u_lime"),
      A: U(ringProg, "u_ringA"), B: U(ringProg, "u_ringB"),
      R: U(ringProg, "u_ringR"), S: U(ringProg, "u_ringSpeed"),
    };
    const flatA = new Float32Array(bases.flatMap((b) => b.a));
    const flatB = new Float32Array(bases.flatMap((b) => b.b));
    const flatR = new Float32Array(RINGS.map((r) => r.radius));
    const flatS = new Float32Array(RINGS.map((r) => r.speed));

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    let W = 0, H = 0, dpr = 1;
    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, narrow ? 1.5 : 2);
      const w = Math.max(1, Math.round(wrap.clientWidth * dpr));
      const h = Math.max(1, Math.round(wrap.clientHeight * dpr));
      if (w !== canvas.width || h !== canvas.height) {
        canvas.width = w;
        canvas.height = h;
        gl.viewport(0, 0, w, h);
      }
      W = wrap.clientWidth;
      H = wrap.clientHeight;
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(wrap);

    // --- interaction ---------------------------------------------------------
    const st = {
      mx: 0, my: 0, tmx: 0, tmy: 0,
      hover: 0, tHover: 0,
      shock: 0, dir: [0, 0, 1] as Vec3,
      spin: 0, visible: true, onScreen: true,
    };

    const onMove = (e: PointerEvent) => {
      const r = wrap.getBoundingClientRect();
      st.tmx = ((e.clientX - r.left) / r.width) * 2 - 1;
      st.tmy = ((e.clientY - r.top) / r.height) * 2 - 1;
    };
    const onEnter = () => { st.tHover = 1; };
    const onLeave = () => { st.tHover = 0; st.tmx = 0; st.tmy = 0; };
    const onDown = (e: PointerEvent) => {
      const r = wrap.getBoundingClientRect();
      const x = ((e.clientX - r.left) / r.width) * 2 - 1;
      const y = -(((e.clientY - r.top) / r.height) * 2 - 1);
      // Unproject roughly onto the front of the sphere so the ripple starts where
      // the pointer actually landed rather than at a fixed pole.
      const d = Math.min(1, Math.hypot(x, y));
      const z = Math.sqrt(Math.max(0.02, 1 - d * d));
      const inv = rotY(-st.spin);
      st.dir = apply(inv, [x, y, z]);
      st.shock = 1;
    };
    wrap.addEventListener("pointermove", onMove);
    wrap.addEventListener("pointerenter", onEnter);
    wrap.addEventListener("pointerleave", onLeave);
    wrap.addEventListener("pointerdown", onDown);

    const onVis = () => { st.visible = !document.hidden && st.onScreen; };
    document.addEventListener("visibilitychange", onVis);

    const io = new IntersectionObserver(
      ([entry]) => {
        st.onScreen = entry.isIntersecting;
        st.visible = !document.hidden && st.onScreen;
      },
      { threshold: 0.01 }
    );
    io.observe(wrap);

    // --- frame ---------------------------------------------------------------
    let raf = 0;
    const t0 = performance.now();
    let last = t0;

    const draw = (now: number) => {
      raf = requestAnimationFrame(draw);
      // A hidden tab still fires rAF in some browsers; skipping the work there is
      // the difference between an idle background tab and a warm laptop.
      if (!st.visible) { last = now; return; }

      const dt = Math.min((now - last) / 1000, 0.05);
      last = now;
      const time = (now - t0) / 1000;

      const ease = 1 - Math.exp(-6 * dt);
      st.mx += (st.tmx - st.mx) * ease;
      st.my += (st.tmy - st.my) * ease;
      st.hover += (st.tHover - st.hover) * ease;
      // Slower than a bounce: ~1.2s to settle, which is long enough to read as a
      // pass through the data rather than a click acknowledgement.
      st.shock *= Math.exp(-2.0 * dt);

      // Idle spin plus a gentle lean toward the pointer -- a lean, never a follow.
      st.spin = reduced ? 0.4 : time * 0.11;
      const rot: Mat3 = mul(
        rotX(st.my * 0.28 + (reduced ? 0.1 : Math.sin(time * 0.13) * 0.12)),
        rotY(st.spin + st.mx * 0.35)
      );

      const res = [canvas.width, canvas.height];
      const calm = reduced ? 0.25 : 1;

      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);

      // belts first, so the cloud reads as in front of the near arcs
      gl.useProgram(ringProg);
      gl.uniformMatrix3fv(ru.rot, false, rot);
      gl.uniform1f(ru.time, time);
      gl.uniform2f(ru.res, res[0], res[1]);
      gl.uniform1f(ru.cam, CAM_DIST);
      gl.uniform1f(ru.foc, FOCAL);
      gl.uniform1f(ru.shock, st.shock);
      gl.uniform1f(ru.dpr, dpr);
      gl.uniform1f(ru.calm, calm);
      gl.uniform1f(ru.hover, st.hover);
      gl.uniform3fv(ru.green, PALETTE.green);
      gl.uniform3fv(ru.lime, PALETTE.lime);
      gl.uniform3fv(ru.A, flatA);
      gl.uniform3fv(ru.B, flatB);
      gl.uniform1fv(ru.R, flatR);
      gl.uniform1fv(ru.S, flatS);
      const at = gl.getAttribLocation(ringProg, "a_t");
      const ai = gl.getAttribLocation(ringProg, "a_ring");
      gl.bindBuffer(gl.ARRAY_BUFFER, rtBuf);
      gl.enableVertexAttribArray(at);
      gl.vertexAttribPointer(at, 1, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, riBuf);
      gl.enableVertexAttribArray(ai);
      gl.vertexAttribPointer(ai, 1, gl.FLOAT, false, 0, 0);
      gl.drawArrays(gl.POINTS, 0, PER_RING * RINGS.length);

      gl.useProgram(sphereProg);
      gl.uniformMatrix3fv(su.rot, false, rot);
      gl.uniform1f(su.time, time);
      gl.uniform2f(su.res, res[0], res[1]);
      gl.uniform1f(su.cam, CAM_DIST);
      gl.uniform1f(su.foc, FOCAL);
      gl.uniform1f(su.shock, st.shock);
      gl.uniform3fv(su.dir, st.dir);
      gl.uniform1f(su.hover, st.hover);
      gl.uniform1f(su.dpr, dpr);
      // Point size follows the box too, or a small orb becomes a coarse stipple.
      gl.uniform1f(su.size, Math.max(1.0, Math.min(2.1, box / 230)));
      gl.uniform1f(su.calm, calm);
      gl.uniform3fv(su.lime, PALETTE.lime);
      gl.uniform3fv(su.green, PALETTE.green);
      gl.uniform3fv(su.emerald, PALETTE.emerald);
      const ap = gl.getAttribLocation(sphereProg, "a_pos");
      const as = gl.getAttribLocation(sphereProg, "a_seed");
      gl.bindBuffer(gl.ARRAY_BUFFER, posBuf);
      gl.enableVertexAttribArray(ap);
      gl.vertexAttribPointer(ap, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, seedBuf);
      gl.enableVertexAttribArray(as);
      gl.vertexAttribPointer(as, 2, gl.FLOAT, false, 0, 0);
      gl.drawArrays(gl.POINTS, 0, COUNT);

      // --- labels, from the same matrix -------------------------------------
      for (const L of labels) {
        const el = labelRefs.current.get(L.key);
        if (!el) continue;
        const ring = RINGS[L.ring];
        const b = bases[L.ring];
        const spin = time * ring.speed * calm + st.shock * 0.9 * Math.sign(ring.speed);
        const ang = L.t * Math.PI * 2 + spin;
        const rr = ring.radius * (1 + st.shock * 0.05);
        const { radial, tangent } = ringFrame(b.a, b.b, ang);
        const local: Vec3 = [radial[0] * rr, radial[1] * rr, radial[2] * rr];

        // Laid INTO the ring's plane rather than stood upright at a point on it.
        const m = planeMatrix(local, tangent, radial, rot, W, H);
        const p = apply(rot, local);
        const vis = occlusion(p);
        const front = (p[2] + rr) / (2 * rr);
        let alpha = vis * (0.18 + front * 0.82);

        // Fade before the edge rather than at it. A label clipped by the viewport
        // reads as a bug; one that has already faded reads as depth.
        const half = Math.min(W, H) / 2;
        const outward = Math.hypot(m.x, m.y) / Math.max(half, 1);
        if (outward > 0.78) alpha *= Math.max(0, 1 - (outward - 0.78) / 0.22);

        const hovered = st.hover;
        const isFocus = focusRef.current && L.text === FOCUS_WORD[focusRef.current];
        if (isFocus) alpha = Math.min(1, alpha * 1.6 + 0.25);
        else if (focusRef.current && L.kind === "process") alpha *= 0.35;
        alpha *= 1 + hovered * 0.25;
        // A click pulses every label, so the shockwave is felt on the belts and
        // not only in the particle cloud.
        alpha = Math.min(1, alpha * (1 + st.shock * 0.7));

        // matrix() maps the label's own box through the plane, so perspective
        // squashes the far side exactly as it squashes the ring itself.
        el.style.transform =
          `translate(${m.x}px, ${m.y}px) matrix(${m.a.toFixed(4)}, ${m.b.toFixed(4)}, ` +
          `${m.c.toFixed(4)}, ${m.d.toFixed(4)}, 0, 0) translate(-50%, -50%)`;
        el.style.opacity = alpha.toFixed(3);

        // The two belts are coloured apart so the concept is legible without a
        // legend: the process ring is the lavender the app already uses for
        // "the reviewer is involved", the vulnerability rings are phosphor.
        if (isFocus) {
          el.style.color = "#B8FF45";
        } else if (L.kind === "process") {
          el.style.color = front > 0.6 ? "#D2C3F6" : "#8d7fb0";
        } else {
          el.style.color = front > 0.72 ? "#B8FF45" : front > 0.4 ? "#75F28A" : "#688574";
        }
        el.style.zIndex = p[2] > 0 ? "2" : "0";
      }
    };
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      wrap.removeEventListener("pointermove", onMove);
      wrap.removeEventListener("pointerenter", onEnter);
      wrap.removeEventListener("pointerleave", onLeave);
      wrap.removeEventListener("pointerdown", onDown);
      document.removeEventListener("visibilitychange", onVis);
      gl.deleteBuffer(posBuf);
      gl.deleteBuffer(seedBuf);
      gl.deleteBuffer(rtBuf);
      gl.deleteBuffer(riBuf);
      gl.deleteProgram(sphereProg);
      gl.deleteProgram(ringProg);
      gl.getExtension("WEBGL_lose_context")?.loseContext();
    };
  }, [labels]);

  return (
    <div
      ref={wrapRef}
      className={`relative w-full aspect-square select-none ${className}`}
      style={{ cursor: failed ? "default" : "crosshair" }}
    >
      <canvas ref={canvasRef} aria-hidden="true" className="absolute inset-0 w-full h-full" />

      {/* Fallback: a static CSS cloud and two rings, so a machine without WebGL
          sees the same idea rather than an empty box. */}
      {failed && (
        <div aria-hidden="true" className="absolute inset-0 grid place-items-center">
          <div
            className="w-[62%] aspect-square rounded-full"
            style={{
              background:
                "radial-gradient(circle at 42% 38%, rgba(184,255,69,0.18), rgba(117,242,138,0.10) 45%, rgba(29,110,67,0.05) 70%, transparent 76%)",
              boxShadow: "0 0 60px rgba(117,242,138,0.12)",
            }}
          />
          {[1.42, 1.72].map((r, i) => (
            <div
              key={i}
              className="absolute rounded-full border"
              style={{
                width: `${r * 44}%`,
                height: `${r * 13}%`,
                borderColor: "rgba(100,220,130,0.18)",
                transform: `rotate(${i ? 22 : -18}deg)`,
              }}
            />
          ))}
        </div>
      )}

      {!failed &&
        showLabels &&
        labels.map((L) => (
          <span
            key={L.key}
            aria-hidden="true"
            ref={(el) => {
              if (el) labelRefs.current.set(L.key, el);
              else labelRefs.current.delete(L.key);
            }}
            className={`pointer-events-none absolute left-1/2 top-1/2 whitespace-nowrap font-mono will-change-transform ${
              L.kind === "process"
                ? "text-[9px] tracking-[0.3em]"
                : "text-[11px] tracking-[0.16em]"
            }`}
            style={{ opacity: 0 }}
          >
            {L.text}
          </span>
        ))}
    </div>
  );
}
