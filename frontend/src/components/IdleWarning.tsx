"use client";

/** Shown shortly before an idle session ends.
 *
 *  Not dismissible by clicking away: the point is an explicit confirmation that
 *  someone is still at the machine. A dialog that any stray click closes proves
 *  nothing about presence. */
export default function IdleWarning({
  secondsLeft,
  onStay,
  onSignOutNow,
}: {
  secondsLeft: number;
  onStay: () => void;
  onSignOutNow: () => void;
}) {
  return (
    <div
      className="modal-backdrop"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="idle-title"
      aria-describedby="idle-body"
    >
      <div className="modal-panel max-w-md">
        <h2 id="idle-title" className="term-h text-muted mb-3">
          Session expiring
        </h2>
        <p id="idle-body" className="text-sm mb-2">
          You have been inactive. This session will end in{" "}
          <span className="text-highlight tabular-nums">{secondsLeft}s</span>.
        </p>
        <p className="text-xs text-muted mb-5">
          Signing out clears the provider key held in this browser. Any analysis already
          running continues on the server, and its results will be waiting when you sign
          back in.
        </p>
        <div className="flex justify-end gap-2">
          <button className="btn-sm" onClick={onSignOutNow}>
            Sign out now
          </button>
          <button className="btn" onClick={onStay} autoFocus>
            Stay signed in
          </button>
        </div>
      </div>
    </div>
  );
}
