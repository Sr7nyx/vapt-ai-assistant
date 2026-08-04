"use client";

/**
 * Motion preference.
 *
 * The operating system's prefers-reduced-motion is the honest default for most
 * applications, but it is a machine-level setting and on a managed device it is
 * frequently applied by policy rather than chosen by the person using it. The
 * result is someone receiving an accessibility accommodation they never asked
 * for, on hardware perfectly capable of the animation.
 *
 * So the default here is "on", and the choice is exposed explicitly. Anyone who
 * genuinely needs less motion can select it, and anyone whose IT department chose
 * it for them is not stuck with it. What is not acceptable is having no way back:
 * overriding the preference silently, with no control, is the pattern worth
 * avoiding.
 */

export type MotionSetting = "on" | "system" | "reduced";

const KEY = "vapt_motion";
export const DEFAULT_MOTION: MotionSetting = "on";

export function getMotion(): MotionSetting {
  if (typeof window === "undefined") return DEFAULT_MOTION;
  const raw = window.localStorage.getItem(KEY);
  return raw === "system" || raw === "reduced" || raw === "on" ? raw : DEFAULT_MOTION;
}

export function setMotion(value: MotionSetting): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(KEY, value);
  } catch {
    // private mode: the attribute below still applies for this session
  }
  applyMotion(value);
}

/** Publish the setting to the document so CSS can key off it. */
export function applyMotion(value: MotionSetting = getMotion()): void {
  if (typeof document === "undefined") return;
  document.documentElement.setAttribute("data-motion", value);
}

/** Whether motion should be suppressed right now, for the JS-driven visuals. */
export function motionReduced(): boolean {
  if (typeof window === "undefined") return false;
  const setting = getMotion();
  if (setting === "reduced") return true;
  if (setting === "on") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** Re-evaluate when the OS preference changes while "system" is selected. */
export function onMotionChange(cb: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
  const handler = () => cb();
  mq.addEventListener("change", handler);
  window.addEventListener("vapt:motion", handler);
  return () => {
    mq.removeEventListener("change", handler);
    window.removeEventListener("vapt:motion", handler);
  };
}
