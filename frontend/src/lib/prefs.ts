const LEGACY_KEY = "vapt_api_key";
const CONFIG_KEY = "vapt_llm_config";

export type LlmConfig = {
  baseUrl: string;
  apiKey: string;
  mainModel: string;
  reviewModel: string;
};

export const EMPTY_CONFIG: LlmConfig = { baseUrl: "", apiKey: "", mainModel: "", reviewModel: "" };

export function getLlmConfig(): LlmConfig {
  if (typeof window === "undefined") return { ...EMPTY_CONFIG };
  try {
    const raw = localStorage.getItem(CONFIG_KEY);
    if (raw) return { ...EMPTY_CONFIG, ...(JSON.parse(raw) as Partial<LlmConfig>) };
  } catch {
    // fall through to the legacy single-key storage
  }
  return { ...EMPTY_CONFIG, apiKey: localStorage.getItem(LEGACY_KEY) || "" };
}

export function setLlmConfig(config: LlmConfig): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
  // keep the legacy key in sync so anything still reading it keeps working
  if (config.apiKey) localStorage.setItem(LEGACY_KEY, config.apiKey);
  else localStorage.removeItem(LEGACY_KEY);
}

export function clearLlmConfig(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(CONFIG_KEY);
  localStorage.removeItem(LEGACY_KEY);
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

// Active background-job ids, persisted so a page can reconnect to a running or
// finished job after the user navigates away and back (or refreshes).
export function getActiveJob(slot: string): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(`vapt_job_${slot}`) || "";
}

export function setActiveJob(slot: string, id: string): void {
  if (typeof window === "undefined") return;
  if (id) localStorage.setItem(`vapt_job_${slot}`, id);
  else localStorage.removeItem(`vapt_job_${slot}`);
}
