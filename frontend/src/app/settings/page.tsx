"use client";
import { useCallback, useEffect, useState } from "react";
import { useSession, signOut } from "next-auth/react";
import { api } from "@/lib/api";
import { getLlmConfig, setLlmConfig, clearLlmConfig, getRemember, forgetSession, LlmConfig, EMPTY_CONFIG } from "@/lib/prefs";
import { useToast } from "@/components/Toast";
import { Spinner } from "@/components/Loading";
import { GithubButton, SourceFooter, GithubMark, REPO_URL } from "@/components/SourceLinks";
import InfoHint, { LabelWithHint } from "@/components/InfoHint";
import { Section } from "@/components/Terminal";
import { getMotion, setMotion, MotionSetting } from "@/lib/motion";
import RunHistory from "@/components/RunHistory";

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
  const [motion, setMotionState] = useState<MotionSetting>("on");

  useEffect(() => {
    setCfg(getLlmConfig());
    setRemember(getRemember());
    setMotionState(getMotion());
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
    <div className="animate-in mx-auto w-full max-w-3xl grid gap-10">

      <Section title="Model configuration" actions={<>          <InfoHint label="About model configuration">
            The pipeline uses two model lanes. Anything left blank falls back to the server configuration.
            <span className="block mt-2">
              Each lane has its own provider quota, so pointing them at different providers roughly
              multiplies your free-tier headroom. A common split is a fast model for extraction and a
              stronger reasoning model, on a separate provider, for review.
            </span>
          </InfoHint></>}>
        <div className="grid gap-4">

        <label className="grid gap-1.5">
          <span className="flex items-center gap-1.5 text-sm text-muted">
            Provider
            {hosts.length > 0 && (
              <InfoHint label="About allowed providers">
                User-supplied endpoints are restricted to an allowlist and rejected if they resolve to
                a private or loopback address, so this field cannot be used to reach internal services.
                <span className="block mt-2 font-mono text-[11px] break-all">{hosts.join(", ")}</span>
              </InfoHint>
            )}
          </span>
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
        </label>

        <label className="grid gap-1.5" data-tour="api-key">
          <span className="flex items-center gap-1.5 text-sm text-muted">
            Your API key
            <InfoHint label="About key handling">
              Sent with each request and used only to call your provider. It is never written to the
              database and never leaves your browser except to your own backend.
              <span className="block mt-2">
                Leave it blank to use the server key, which is subject to a per-user demo quota.
              </span>
            </InfoHint>
          </span>
          <input
            className="input"
            type="password"
            placeholder="Leave blank to use the server key"
            value={cfg.apiKey}
            onChange={(e) => set({ apiKey: e.target.value })}
          />
        </label>

        <div className="rounded-lg border border-border/60 p-3 grid gap-2">
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={remember}
              onChange={(e) => setRemember(e.target.checked)}
            />
            <span className="flex items-center gap-1.5">
              Remember on this device
              <InfoHint label="About key storage">
                Off by default: the key is kept only for this browser tab and discarded when the tab
                closes. Turn this on only on a device you trust and do not share.
                <span className="block mt-2">
                  Either way the configuration is tied to the signed-in account and is cleared when you
                  sign out.
                </span>
              </InfoHint>
            </span>
          </label>
          <p className="text-xs text-muted">
            Currently:{" "}
            <span className={remember ? "text-warn" : "text-accent"}>
              {remember ? "stored on this device" : "this session only"}
            </span>
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
        </div>
      </Section>

      <Section title="Interface" actions={<>          <InfoHint label="About motion">
            Animations are on by default. Your operating system exposes a
            &quot;reduce motion&quot; preference, but on a managed device it is often
            set by policy rather than chosen, so following it silently would leave
            you with an accommodation you never asked for and no way back.
            <span className="block mt-2">
              Choose <span className="text-text">Follow system</span> to honour the
              operating system, or <span className="text-text">Reduced</span> to turn
              animation off regardless.
            </span>
          </InfoHint></>}>
        <div className="grid gap-3">

        <fieldset className="grid gap-2">
          <legend className="sr-only">Motion</legend>
          <div className="flex flex-wrap gap-2">
            {(
              [
                ["on", "Always on"],
                ["system", "Follow system"],
                ["reduced", "Reduced"],
              ] as [MotionSetting, string][]
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                aria-pressed={motion === value}
                onClick={() => {
                  setMotionState(value);
                  setMotion(value);
                  window.dispatchEvent(new Event("vapt:motion"));
                  notify(`Motion: ${label.toLowerCase()}`, "success");
                }}
                className={`rounded-lg border px-3 py-1 text-xs tracking-wide transition-all ${
                  motion === value
                    ? "border-accent/70 text-accent"
                    : "border-border text-muted hover:border-accent/50 hover:text-text"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          <p className="text-xs text-muted">
            Takes effect immediately for CSS animation; the sign-in visuals pick it up on
            next load.
          </p>
        </fieldset>
        </div>
      </Section>

      <Section
        title="Run history"
        actions={
          <InfoHint label="About run history">
            Analyses are recorded so they survive a server restart. This is the other half of
            that: LLM usage was already logged but could not be attributed to a particular run,
            so there was no way to see what one cost.
          </InfoHint>
        }
      >
        <RunHistory />
      </Section>

      <Section title="Account" actions={<>          <InfoHint label="Connection details">
            Signed in with Google. The ID token is verified server-side on every request and all data is
            scoped to this account.
            <span className="block mt-2 font-mono text-[11px] break-all">
              API: {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}
            </span>
          </InfoHint></>}>
        <div className="grid gap-3">

        <div className="text-sm">{session?.user?.email}</div>

        {/* One row: these are peers, and stacking them made the section look
            longer than it is. */}
        <div className="flex flex-wrap gap-2">
          <button
            className="btn-sm"
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
            Replay tour
          </button>
          <button
            className="btn-sm"
            onClick={() => {
              forgetSession();
              signOut({ callbackUrl: "/" });
            }}
          >
            Sign out
          </button>
        </div>
        </div>
      </Section>

      <Section title="About" actions={<>          <InfoHint label="About this tool">
            An AI-assisted workspace for penetration testing, built so the model is assumed wrong until
            proven otherwise: CVSS is computed deterministically, claims are checked against their evidence
            in code where that is possible, and a second reviewer argues the false-positive case before
            anything reaches a report.
          </InfoHint></>}>
        <div className="grid gap-3">

        <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-2 text-xs">
          <div className="flex justify-between border-b border-border/50 pb-1">
            <dt className="text-muted">License</dt>
            <dd>MIT</dd>
          </div>
          <div className="flex justify-between border-b border-border/50 pb-1">
            <dt className="text-muted">Repository</dt>
            <dd className="truncate">
              <a
                href={REPO_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 hover:text-accent transition-colors"
              >
                <GithubMark size={12} />
                Sr7nyx/vapt-ai-assistant
              </a>
            </dd>
          </div>
        </dl>

        <div className="flex flex-wrap items-center gap-3 pt-1">
          <GithubButton tone="accent" label="VIEW SOURCE" />
        </div>

        <SourceFooter className="pt-2 border-t border-border/50 mt-1" />
        </div>
      </Section>
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
