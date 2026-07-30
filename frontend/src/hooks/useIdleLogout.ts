"use client";
import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Sign the user out after a period of inactivity, with a warning first.
 *
 * Three details make this reliable rather than approximate:
 *
 * It compares wall-clock timestamps on a one-second tick instead of scheduling one
 * long setTimeout. Background tabs are throttled and a sleeping machine stops
 * firing timers altogether, so a scheduled logout can arrive minutes late or not
 * at all. Comparing Date.now() against the last activity is correct in both cases
 * and expires immediately on wake.
 *
 * Activity is shared across tabs through localStorage, so working in one tab does
 * not silently expire the session in another. Only a timestamp is written.
 *
 * The expiry callback is held in a ref rather than being an effect dependency. If
 * it were a dependency, a caller passing an unmemoized function would rebuild the
 * effect on every render and reset the idle clock forever -- the timeout would
 * simply never fire.
 *
 * Deliberately NOT counted as activity: mouse movement. A cursor nudged by a
 * passing hand should not hold a security tool's session open. Presence means
 * pressing, typing, touching or scrolling.
 */

const ACTIVITY_EVENTS = ["mousedown", "keydown", "touchstart", "scroll", "wheel"] as const;
const SHARED_KEY = "vapt_last_activity";
const SHARE_THROTTLE_MS = 5000;

export function useIdleLogout({
  idleMs,
  warnMs,
  enabled,
  onExpire,
}: {
  idleMs: number;
  warnMs: number;
  enabled: boolean;
  onExpire: () => void;
}) {
  const lastActivity = useRef(Date.now());
  const lastShared = useRef(0);
  const warningActive = useRef(false);
  const expired = useRef(false);
  const onExpireRef = useRef(onExpire);
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);

  useEffect(() => {
    onExpireRef.current = onExpire;
  }, [onExpire]);

  const markActive = useCallback(() => {
    const now = Date.now();
    lastActivity.current = now;
    if (now - lastShared.current > SHARE_THROTTLE_MS) {
      lastShared.current = now;
      try {
        window.localStorage.setItem(SHARED_KEY, String(now));
      } catch {
        // storage unavailable: fall back to per-tab tracking
      }
    }
  }, []);

  /** Explicit confirmation of presence, from the warning dialog. */
  const staySignedIn = useCallback(() => {
    warningActive.current = false;
    setSecondsLeft(null);
    markActive();
  }, [markActive]);

  useEffect(() => {
    if (!enabled) {
      warningActive.current = false;
      expired.current = false;
      setSecondsLeft(null);
      return;
    }

    expired.current = false;
    warningActive.current = false;
    lastActivity.current = Date.now();

    // While the warning is up, ambient activity does not dismiss it. A stray
    // scroll should not silently extend a session that is about to end; the user
    // confirms presence deliberately, which is what makes the warning meaningful.
    const onActivity = () => {
      if (!warningActive.current) markActive();
    };
    ACTIVITY_EVENTS.forEach((e) =>
      window.addEventListener(e, onActivity, { passive: true })
    );

    const onStorage = (e: StorageEvent) => {
      if (e.key !== SHARED_KEY || !e.newValue) return;
      const shared = Number(e.newValue);
      if (Number.isFinite(shared) && shared > lastActivity.current) {
        lastActivity.current = shared;
        warningActive.current = false;
        setSecondsLeft(null);
      }
    };
    window.addEventListener("storage", onStorage);

    const tick = window.setInterval(() => {
      const idle = Date.now() - lastActivity.current;

      if (idle >= idleMs) {
        if (expired.current) return;
        expired.current = true;
        warningActive.current = false;
        setSecondsLeft(null);
        onExpireRef.current();
        return;
      }

      if (idle >= idleMs - warnMs) {
        warningActive.current = true;
        setSecondsLeft(Math.max(0, Math.ceil((idleMs - idle) / 1000)));
      } else if (warningActive.current) {
        warningActive.current = false;
        setSecondsLeft(null);
      }
    }, 1000);

    return () => {
      window.clearInterval(tick);
      window.removeEventListener("storage", onStorage);
      ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, onActivity));
    };
  }, [enabled, idleMs, warnMs, markActive]);

  return { secondsLeft, staySignedIn };
}
