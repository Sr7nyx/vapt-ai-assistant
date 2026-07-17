const KEY = "vapt_api_key";

export function getApiKey(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(KEY) || "";
}

export function setApiKey(value: string): void {
  if (typeof window !== "undefined") localStorage.setItem(KEY, value);
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
