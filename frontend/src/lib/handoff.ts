/**
 * Marks that a sign-in was initiated, so the console knows to show the handoff
 * when the session comes back.
 *
 * Lives here rather than in AppShell because SignInGate needs to set it and
 * AppShell needs to read it — importing between those two would be circular,
 * since AppShell renders SignInGate.
 *
 * sessionStorage, not localStorage: it dies with the tab. A flag left in
 * localStorage would replay the sequence days later in a tab that never went
 * through this flow.
 */
const KEY = "vapt_handoff";

/** Called immediately before the redirect to Google. */
export function markSignInStarted(): void {
  try {
    window.sessionStorage.setItem(KEY, "1");
  } catch {
    // Private mode or storage disabled. The handoff is cosmetic, so its absence
    // is not an error worth surfacing.
  }
}

/** True once, on the first authenticated render after a sign-in. */
export function consumeSignIn(): boolean {
  try {
    const pending = window.sessionStorage.getItem(KEY) === "1";
    if (pending) window.sessionStorage.removeItem(KEY);
    return pending;
  } catch {
    return false;
  }
}
