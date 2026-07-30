"use client";
import { useSession, signOut } from "next-auth/react";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useCallback, useEffect } from "react";
import Nav from "./Nav";
import SignInGate from "./SignInGate";
import { Spinner } from "./Loading";
import { bindSessionOwner, forgetSession } from "@/lib/prefs";
import Onboarding from "./Onboarding";
import IdleWarning from "./IdleWarning";
import { useIdleLogout } from "@/hooks/useIdleLogout";

/** Idle timeout, matching the convention of tools like Nessus. Raising this is a
 *  security decision, not a preference, which is why it is a constant here rather
 *  than something a user can extend from the settings page. */
const IDLE_MS = 10 * 60 * 1000;
const WARN_MS = 60 * 1000;

export default function AppShell({ children }: { children: ReactNode }) {
  const { data: session, status } = useSession();
  const router = useRouter();
  const pathname = usePathname();

  // Bind stored provider configuration to the signed-in account during render,
  // before any child effect can read it. If the browser holds a configuration
  // belonging to a different account, it is purged rather than inherited.
  // bindSessionOwner is idempotent, so repeated renders are harmless.
  if (typeof window !== "undefined" && status === "authenticated") {
    bindSessionOwner(session?.user?.email || "");
  }

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

  if (status === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center text-muted gap-2">
        <Spinner /> Loading…
      </div>
    );
  }
  if (status !== "authenticated") {
    return <SignInGate />;
  }
  return (
    <div className="flex min-h-screen">
      <Nav />
      <main className="flex-1 min-w-0 px-6 py-10">
        <div className="mx-auto w-full max-w-5xl">{children}</div>
      </main>
      <Onboarding />
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
