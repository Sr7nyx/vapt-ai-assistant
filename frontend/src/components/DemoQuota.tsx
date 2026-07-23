"use client";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { api } from "@/lib/api";
import { getLlmConfig } from "@/lib/prefs";
import Modal from "./Modal";

type Quota = { limit: number; used: number; remaining: number; window_hours: number };

/** Shown when the backend refuses a run because the shared-key allowance is spent.
 *  The point is not to scold: it explains the limit and takes them to Settings. */
export function DemoLimitModal({ message, onClose }: { message: string; onClose: () => void }) {
  const router = useRouter();
  return (
    <Modal
      title="Demo limit reached"
      onClose={onClose}
      footer={
        <>
          <button className="btn-sm" onClick={onClose}>Not now</button>
          <button
            className="btn"
            onClick={() => {
              onClose();
              router.push("/settings");
            }}
          >
            Add my API key
          </button>
        </>
      }
    >
      <div className="grid gap-3 text-sm">
        <p>{message}</p>
        <p className="text-muted">
          The shared key exists so you can try the tool without signing up for anything. It runs on a free
          provider tier, so it is capped per person to keep it available for everyone.
        </p>
        <p className="text-muted">
          Adding your own key in Settings removes the cap entirely: your runs go to your provider account on
          your quota, and the key is kept in your browser for this session only.
        </p>
      </div>
    </Modal>
  );
}

/** A quiet line showing what is left, only while the user is on the shared key. */
export function DemoQuotaBanner({ refreshKey = 0 }: { refreshKey?: number }) {
  const { data: session } = useSession();
  const token = session?.id_token;
  const router = useRouter();
  const [quota, setQuota] = useState<Quota | null>(null);
  const [ownKey, setOwnKey] = useState(false);

  useEffect(() => setOwnKey(Boolean(getLlmConfig().apiKey.trim())), [refreshKey]);

  const load = useCallback(() => {
    if (!token || ownKey) return;
    api.demoQuota(token).then(setQuota).catch(() => {});
  }, [token, ownKey]);
  useEffect(() => load(), [load, refreshKey]);

  if (ownKey || !quota || quota.limit <= 0) return null;

  const low = quota.remaining <= 1;
  return (
    <div
      className={`text-sm rounded-lg px-3 py-2 mb-4 border ${
        low ? "border-warn/60 text-warn" : "border-border text-muted"
      }`}
    >
      {quota.remaining > 0
        ? `${quota.remaining} of ${quota.limit} demo runs left on the shared key (resets on a rolling ${quota.window_hours}h window). `
        : "You have used your demo runs on the shared key. "}
      <button className="underline hover:text-text" onClick={() => router.push("/settings")}>
        Add your own key
      </button>{" "}
      for unlimited use on your own provider quota.
    </div>
  );
}

/** Narrow a caught error to the demo-limit case. */
export function isDemoLimit(err: unknown): boolean {
  const e = err as { status?: number; detail?: { error?: string } } | undefined;
  return e?.status === 429 || e?.detail?.error === "demo_limit_reached";
}
