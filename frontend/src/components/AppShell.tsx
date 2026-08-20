"use client";
import { useSession, signOut } from "next-auth/react";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useCallback, useEffect, useState } from "react";
import TopNav from "./TopNav";
import StatusLine from "./StatusLine";
import CommandPalette from "./CommandPalette";
import SignInGate from "./SignInGate";
import SessionHandoff from "./SessionHandoff";
import { consumeSignIn } from "@/lib/handoff";
import { bindSessionOwner, forgetSession } from "@/lib/prefs";
import Onboarding from "./Onboarding";
import IdleWarning from "./IdleWarning";
import { useIdleLogout } from "@/hooks/useIdleLogout";
import { applyMotion } from "@/lib/motion";

/** Idle timeout, matching the convention of tools like Nessus. Raising this is a
 *  security decision, not a preference, which is why it is a constant here rather
 *  than something a user can extend from the settings page. */
const IDLE_MS = 10 * 60 * 1000;
const WARN_MS = 60 * 1000;


export default function AppShell({ children }: { children: ReactNode }) {
  const { data: session, status } = useSession();
  const router = useRouter();
  const pathname = usePathname();

  // The handoff belongs to a completed sign-in.
  //
  // A React ref cannot carry that fact: signing in with Google is a full page
  // navigation away and back, so every piece of in-memory state is destroyed. The
  // component that observed "unauthenticated" no longer exists when the session
  // arrives.
  //
  // So the intent is written to sessionStorage at the moment sign-in is clicked,
  // and consumed once on return. sessionStorage rather than localStorage because
  // it dies with the tab -- a flag left behind would replay the sequence days
  // later in a tab that was never signed in through this flow.
  const [handoff, setHandoff] = useState(false);

  useEffect(() => {
    if (status !== "authenticated") return;
    if (!consumeSignIn()) return;
    setHandoff(true);
    // Long enough for the stages to read, short enough not to be in the way.
    const t = window.setTimeout(() => setHandoff(false), 2100);
    return () => clearTimeout(t);
  }, [status]);

  // Bind stored provider configuration to the signed-in account during render,
  // before any child effect can read it. If the browser holds a configuration
  // belonging to a different account, it is purged rather than inherited.
  // bindSessionOwner is idempotent, so repeated renders are harmless.
  if (typeof window !== "undefined" && status === "authenticated") {
    bindSessionOwner(session?.user?.email || "");
  }

  // Re-assert on mount: the inline bootstrap runs once, and a second tab that
  // changed the setting should be reflected here on next load.
  useEffect(() => {
    applyMotion();
  }, []);

  const endSession = useCallback(() => {
    // Clearing the browser-held provider key is the security-relevant half; the
    // callbackUrl is what stops the address bar still reading /settings once the
    // sign-in page is showing.
    forgetSession();
    signOut({ callbackUrl: "/" });
  }, []);

  const { secondsLeft, staySignedIn } = useIdleLogout({
    idleMs: IDLE_MS,
    warnMs: WARN_MS,
    enabled: status === "authenticated",
    onExpire: endSession,
  });

  // A signed-out visitor on /findings sees the sign-in page but keeps a URL that
  // implies a place they cannot reach. Send them to the root so the address
  // matches what is actually on screen.
  useEffect(() => {
    if (status === "unauthenticated" && pathname !== "/") {
      router.replace("/");
    }
  }, [status, pathname, router]);

  // Hooks above this line run on every render, before any early return.

  // The handoff belongs to a completed sign-in and nothing else.
  //
  // It used to render for status === "loading" as well, which fires on EVERY cold
  // page load -- including a first visit by someone who has never signed in. The
  // result was a "VERIFYING TOKEN" screen appearing before the sign-in page had
  // even been seen, which is the opposite of what it is for.
  if (handoff) {
    // Reached only from "authenticated", so the session is present here.
    return <SessionHandoff email={session?.user?.email || undefined} />;
  }

  if (status === "loading") {
    // A cold load with no sign-in behind it. Nothing has happened worth narrating,
    // so this stays a quiet placeholder rather than a staged sequence.
    return <div className="min-h-screen bg-bg" aria-busy="true" />;
  }
  if (status !== "authenticated") {
    return <SignInGate />;
  }
  return (
    <div className="min-h-screen flex flex-col">
      <TopNav onSignOut={endSession} />
      <StatusLine />
      {/* Full-bleed. A centred max-width column is the shape of a marketing page,
          not a console: finding tables and evidence panes need the width, and
          capping it at 1024px is what makes an application look templated. The
          cap here is generous and exists only to stop line lengths becoming
          unreadable on ultrawide displays. */}
      {/* Keyed on the route so each navigation replays the entrance. Without the
          key React reuses the node and the transition only ever runs once. */}
      <main key={pathname} className="route-in app-col flex-1 min-w-0 py-5">
        {children}
      </main>
      <Onboarding />
      <CommandPalette />
      {secondsLeft !== null && (
        <IdleWarning
          secondsLeft={secondsLeft}
          onStay={staySignedIn}
          onSignOutNow={endSession}
        />
      )}
    </div>
  );
}
