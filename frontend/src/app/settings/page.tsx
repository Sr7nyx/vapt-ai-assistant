"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession, signOut } from "next-auth/react";
import { api } from "@/lib/api";
import { getLlmConfig, setLlmConfig, clearLlmConfig, getRemember, forgetSession, LlmConfig, EMPTY_CONFIG } from "@/lib/prefs";
import { useToast } from "@/components/Toast";
import { Spinner } from "@/components/Loading";

const PRESETS = [
  { label: "Groq", url: "https://api.groq.com/openai/v1" },
  { label: "Cerebras", url: "https://api.cerebras.ai/v1" },
  { label: "Google AI Studio", url: "https://generativelanguage.googleapis.com/v1beta/openai" },
  { label: "OpenRouter", url: "https://openrouter.ai/api/v1" },
  { label: "OpenAI", url: "https://api.openai.com/v1" },
  { label: "Together", url: "https://api.together.xyz/v1" },
  { label: "Mistral", url: "https://api.mistral.ai/v1" },
];

type TestState = { lane: string; ok: boolean; message: string } | null;

export default function SettingsPage() {
  const { data: session } = useSession();
  const token = session?.id_token;
  const { notify } = useToast();

  const [cfg, setCfg] = useState<LlmConfig>(EMPTY_CONFIG);
  const [models, setModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [testing, setTesting] = useState("");
  const [result, setResult] = useState<TestState>(null);
  const [hosts, setHosts] = useState<string[]>([]);
  const [remember, setRemember] = useState(false);

  useEffect(() => {
    setCfg(getLlmConfig());
    setRemember(getRemember());
  }, []);
  useEffect(() => {
    if (token) api.llmProviders(token).then((r) => setHosts(r.allowed_hosts)).catch(() => {});
  }, [token]);

  const set = (patch: Partial<LlmConfig>) => setCfg((c) => ({ ...c, ...patch }));

  const save = () => {
    setLlmConfig(cfg, remember);
    notify(
      remember ? "Saved on this device" : "Saved for this session only",
      "success"
    );
  };

  const loadModels = useCallback(async () => {
    if (!cfg.baseUrl.trim()) {
      notify("Choose a provider first.", "error");
      return;
    }
    setLoadingModels(true);
    try {
      const r = await api.llmModels(token, { base_url: cfg.baseUrl.trim(), api_key: cfg.apiKey.trim() });
      setModels(r.models);
      notify(`Found ${r.models.length} model(s)`, "success");
    } catch (e) {
      setModels([]);
      notify((e as Error).message, "error");
    } finally {
      setLoadingModels(false);
    }
  }, [cfg.baseUrl, cfg.apiKey, token, notify]);

  const test = async (lane: "Extraction" | "Reviewer", model: string) => {
    if (!cfg.baseUrl.trim() || !model.trim()) {
      notify("Set a provider and a model for that lane first.", "error");
      return;
    }
    setTesting(lane);
    setResult(null);
    try {
      const r = await api.llmTest(token, {
        base_url: cfg.baseUrl.trim(),
        api_key: cfg.apiKey.trim(),
        model: model.trim(),
        lane: lane === "Extraction" ? "MAIN" : "REVIEW",
      });
      setResult({
        lane,
        ok: r.ok,
        message: r.ok ? `${r.model} replied: ${r.reply || "(empty)"}` : r.error || "Unknown error",
      });
      notify(r.ok ? `${lane} lane works` : `${lane} lane failed`, r.ok ? "success" : "error");
    } catch (e) {
      setResult({ lane, ok: false, message: (e as Error).message });
      notify((e as Error).message, "error");
    } finally {
      setTesting("");
    }
  };

  return (
    <div className="animate-in max-w-3xl">
      <h1 className="text-2xl tracking-wide mb-6 caret">SETTINGS</h1>

      <section className="card grid gap-4 mb-6">
        <div>
          <h2 className="font-semibold">Model configuration</h2>
          <p className="text-muted text-sm mt-1">
            The pipeline uses two model lanes. Leave anything blank to fall back to the server configuration.
          </p>
          <p className="text-muted text-sm mt-2">
            Each lane has its own provider quota, so pointing them at different providers roughly multiplies
            your free-tier headroom. A common split is a fast model for extraction and a stronger reasoning
            model on a separate provider for review.
          </p>
        </div>

        <label className="grid gap-1.5">
          <span className="text-sm text-muted">Provider</span>
          <div className="flex gap-2 flex-wrap">
            {PRESETS.map((p) => (
              <button
                key={p.url}
                className={`btn-sm ${cfg.baseUrl === p.url ? "border-accent text-accent" : ""}`}
                onClick={() => {
                  set({ baseUrl: p.url });
                  setModels([]);
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
          <input
            className="input mt-2"
            placeholder="https://api.groq.com/openai/v1"
            value={cfg.baseUrl}
            onChange={(e) => set({ baseUrl: e.target.value })}
          />
          {hosts.length > 0 && <span className="text-xs text-muted">Allowed provider hosts: {hosts.join(", ")}</span>}
        </label>

        <label className="grid gap-1.5" data-tour="api-key">
          <span className="text-sm text-muted">Your API key</span>
          <input
            className="input"
            type="password"
            placeholder="Leave blank to use the server key"
            value={cfg.apiKey}
            onChange={(e) => set({ apiKey: e.target.value })}
          />
          <span className="text-xs text-muted">
            Sent with each request and used only to call your provider. It is never written to the database
            and never leaves your browser except to your own backend.
          </span>
        </label>

        <div className="rounded-lg border border-border/60 p-3 grid gap-2">
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={remember}
              onChange={(e) => setRemember(e.target.checked)}
            />
            <span>
              Remember on this device
              <span className="block text-xs text-muted mt-0.5">
                Off by default: your key is kept only for this browser tab and is discarded when the tab
                closes. Turn this on only on a device you trust and do not share.
              </span>
            </span>
          </label>
          <p className="text-xs text-muted">
            Currently: <span className="text-text">{remember ? "stored on this device" : "this session only"}</span>.
            The configuration is tied to the signed-in account and is cleared when you sign out.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button className="btn-sm" onClick={loadModels} disabled={loadingModels}>
            {loadingModels ? (
              <span className="flex items-center gap-2">
                <Spinner /> Loading models
              </span>
            ) : (
              "Load models from provider"
            )}
          </button>
          {models.length > 0 && <span className="text-xs text-muted">{models.length} available</span>}
        </div>

        <LaneRow
          title="Extraction model"
          hint="Reads the raw evidence and drafts findings. A fast general model is fine here."
          value={cfg.mainModel}
          models={models}
          onChange={(v) => set({ mainModel: v })}
          onTest={() => test("Extraction", cfg.mainModel)}
          testing={testing === "Extraction"}
        />

        <LaneRow
          title="Reviewer model"
          hint="Audits each finding against its own evidence and drives triage verdicts. Use your strongest reasoning model here: a weak reviewer quietly defeats the point of the review pass."
          value={cfg.reviewModel}
          models={models}
          onChange={(v) => set({ reviewModel: v })}
          onTest={() => test("Reviewer", cfg.reviewModel)}
          testing={testing === "Reviewer"}
        />

        {result && (
          <div className={`text-sm rounded-lg px-3 py-2 border ${result.ok ? "border-accent text-accent" : "border-danger text-danger"}`}>
            {result.lane}: {result.message}
          </div>
        )}

        <div className="flex gap-2">
          <button className="btn" onClick={save}>Save settings</button>
          <button
            className="btn-sm-danger"
            onClick={() => {
              clearLlmConfig();
              setCfg(EMPTY_CONFIG);
              setModels([]);
              notify("Cleared. The server configuration will be used.", "success");
            }}
          >
            Clear
          </button>
        </div>
      </section>

      <section className="card grid gap-2">
        <h2 className="font-semibold">Account</h2>
        <div className="text-sm text-muted">Signed in as {session?.user?.email}</div>
        <button
          className="btn-sm w-fit"
          onClick={() => {
            try {
              const raw = localStorage.getItem("vapt_onboarded");
              const seen: string[] = raw ? JSON.parse(raw) : [];
              const owner = session?.user?.email || "";
              localStorage.setItem("vapt_onboarded", JSON.stringify(seen.filter((o) => o !== owner)));
            } catch {}
            location.reload();
          }}
        >
          Replay welcome tour
        </button>
        <div>
          <button
            className="btn-sm"
            onClick={() => {
              forgetSession();
              signOut();
            }}
          >
            Sign out
          </button>
        </div>
        <p className="text-xs text-muted mt-2">API: {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}</p>
      </section>
    </div>
  );
}

function LaneRow({
  title,
  hint,
  value,
  models,
  onChange,
  onTest,
  testing,
}: {
  title: string;
  hint: string;
  value: string;
  models: string[];
  onChange: (v: string) => void;
  onTest: () => void;
  testing: boolean;
}) {
  return (
    <div className="grid gap-1.5 border-t border-border/60 pt-4">
      <span className="text-sm">{title}</span>
      <span className="text-xs text-muted">{hint}</span>
      <div className="flex gap-2">
        {models.length > 0 ? (
          <select className="input" value={value} onChange={(e) => onChange(e.target.value)}>
            <option value="">— server default —</option>
            {models.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        ) : (
          <input
            className="input"
            placeholder="Model id (or load the list above)"
            value={value}
            onChange={(e) => onChange(e.target.value)}
          />
        )}
        <button className="btn-sm shrink-0" onClick={onTest} disabled={testing}>
          {testing ? <Spinner /> : "Test"}
        </button>
      </div>
    </div>
  );
}
