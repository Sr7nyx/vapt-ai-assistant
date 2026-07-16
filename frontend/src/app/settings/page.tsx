"use client";
import { useEffect, useState } from "react";
import { useSession, signOut } from "next-auth/react";
import { getApiKey, setApiKey } from "@/lib/prefs";

export default function SettingsPage() {
  const { data: session } = useSession();
  const [key, setKey] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => setKey(getApiKey()), []);

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Settings</h1>
      <div className="card grid gap-3 mb-4 max-w-lg">
        <div className="text-sm text-muted">Signed in as {session?.user?.email}</div>
        <label className="text-sm">
          Your LLM API key (optional, stored in this browser only). If unset, the server key is used.
        </label>
        <input className="input" type="password" value={key} placeholder="sk-or-…" onChange={(e) => setKey(e.target.value)} />
        <div className="flex gap-2">
          <button
            className="btn"
            onClick={() => {
              setApiKey(key.trim());
              setSaved(true);
              setTimeout(() => setSaved(false), 1500);
            }}
          >
            {saved ? "Saved" : "Save key"}
          </button>
          <button className="btn-sm" onClick={() => signOut()}>Sign out</button>
        </div>
      </div>
      <p className="text-xs text-muted">API: {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}</p>
    </div>
  );
}
