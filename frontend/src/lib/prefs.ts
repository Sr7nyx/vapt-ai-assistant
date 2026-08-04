const CONFIG_KEY = "vapt_llm_config";
const REMEMBER_KEY = "vapt_llm_remember";
const LEGACY_KEY = "vapt_api_key"; // removed on sight; never written any more

export type LlmConfig = {
  baseUrl: string;
  apiKey: string;
  mainModel: string;
  reviewModel: string;
};

export const EMPTY_CONFIG: LlmConfig = { baseUrl: "", apiKey: "", mainModel: "", reviewModel: "" };

type StoredConfig = { owner: string; config: LlmConfig };

// The account this browser's stored configuration belongs to. Set from the live
// session before any page reads the config, so a different account signing in on
// the same browser can never inherit the previous account's key or models.
let currentOwner = "";

function browserStores(): Storage[] {
  if (typeof window === "undefined") return [];
  return [window.sessionStorage, window.localStorage];
}

function readStored(): StoredConfig | null {
  for (const store of browserStores()) {
    try {
      const raw = store.getItem(CONFIG_KEY);
      if (raw) return JSON.parse(raw) as StoredConfig;
    } catch {
      // corrupt entry: treat as absent
    }
  }
  return null;
}

/** True when the user asked for the config to persist on this device. */
export function getRemember(): boolean {
  if (typeof window === "undefined") return false;
  return window.localStorage.getItem(REMEMBER_KEY) === "1";
}

/** Wipe the stored configuration from both stores. */
export function clearLlmConfig(): void {
  for (const store of browserStores()) {
    try {
      store.removeItem(CONFIG_KEY);
      store.removeItem(LEGACY_KEY);
    } catch {
      // ignore
    }
  }
}

/** Bind stored configuration to the signed-in account. Idempotent, and safe to
 *  call during render: if the stored config belongs to a different account it is
 *  purged immediately rather than being handed to the new user. */
export function bindSessionOwner(owner: string): void {
  const next = owner || "";
  if (next === currentOwner) return;
  currentOwner = next;
  const stored = readStored();
  if (stored && stored.owner && next && stored.owner !== next) {
    clearLlmConfig();
  }
}

export function getLlmConfig(): LlmConfig {
  const stored = readStored();
  if (!stored) return { ...EMPTY_CONFIG };
  // Belt and braces: never hand back another account's configuration.
  if (stored.owner && currentOwner && stored.owner !== currentOwner) return { ...EMPTY_CONFIG };
  return { ...EMPTY_CONFIG, ...stored.config };
}

/** Persist the configuration. Session-only by default: it lives in
 *  sessionStorage, which is scoped to this tab and cleared when the tab closes.
 *  `remember` opts in to localStorage on a device the user trusts. */
export function setLlmConfig(config: LlmConfig, remember: boolean = getRemember()): void {
  if (typeof window === "undefined") return;
  clearLlmConfig();
  const payload: StoredConfig = { owner: currentOwner, config };
  const target = remember ? window.localStorage : window.sessionStorage;
  try {
    target.setItem(CONFIG_KEY, JSON.stringify(payload));
    window.localStorage.setItem(REMEMBER_KEY, remember ? "1" : "0");
  } catch {
    // storage unavailable (private mode, quota): the config simply is not kept
  }
}

export function getApiKey(): string {
  return getLlmConfig().apiKey;
}

export function setApiKey(value: string): void {
  setLlmConfig({ ...getLlmConfig(), apiKey: value });
}

/** Wire format for the backend: only non-empty fields are sent, so anything the
 *  user leaves blank falls back to the server's own configuration. */
export function buildLaneConfig(): Record<string, Record<string, unknown>> | undefined {
  const c = getLlmConfig();
  const lane = (model: string) => {
    const entry: Record<string, unknown> = {};
    if (c.baseUrl.trim()) entry.base_url = c.baseUrl.trim();
    if (c.apiKey.trim()) entry.api_key = c.apiKey.trim();
    if (model.trim()) entry.models = [model.trim()];
    return entry;
  };
  const main = lane(c.mainModel);
  const review = lane(c.reviewModel);
  const out: Record<string, Record<string, unknown>> = {};
  if (Object.keys(main).length) out.MAIN = main;
  if (Object.keys(review).length) out.REVIEW = review;
  return Object.keys(out).length ? out : undefined;
}

/** Clear everything sensitive this browser holds, then hand off to sign-out. */
export function forgetSession(): void {
  clearLlmConfig();
  // Cached aggregates belong to the account that fetched them.
  try {
    void import("./cache").then((m) => m.clearCache());
  } catch {
    // ignore
  }
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(REMEMBER_KEY);
    window.sessionStorage.removeItem(CONFIG_KEY);
  } catch {
    // ignore
  }
  currentOwner = "";
}

// Active background-job ids, persisted so a page can reconnect to a running or
// finished job after the user navigates away and back (or refreshes).
export function getActiveJob(slot: string): string {
  if (typeof window === "undefined") return "";
  return window.sessionStorage.getItem(`vapt_job_${slot}`) || "";
}

export function setActiveJob(slot: string, id: string): void {
  if (typeof window === "undefined") return;
  if (id) window.sessionStorage.setItem(`vapt_job_${slot}`, id);
  else window.sessionStorage.removeItem(`vapt_job_${slot}`);
}

// First-run onboarding: shown once per account on this browser. Persistent
// (localStorage) so it does not reappear every new tab, but keyed by account so
// a different user on the same browser still gets welcomed.
export function hasSeenOnboarding(owner: string): boolean {
  if (typeof window === "undefined" || !owner) return true;
  try {
    const raw = window.localStorage.getItem("vapt_onboarded");
    const seen: string[] = raw ? JSON.parse(raw) : [];
    return seen.includes(owner);
  } catch {
    return false;
  }
}

export function markOnboarded(owner: string): void {
  if (typeof window === "undefined" || !owner) return;
  try {
    const raw = window.localStorage.getItem("vapt_onboarded");
    const seen: string[] = raw ? JSON.parse(raw) : [];
    if (!seen.includes(owner)) {
      seen.push(owner);
      window.localStorage.setItem("vapt_onboarded", JSON.stringify(seen));
    }
  } catch {
    // ignore
  }
}
