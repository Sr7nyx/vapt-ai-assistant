const KEY = "vapt_api_key";

export function getApiKey(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(KEY) || "";
}

export function setApiKey(value: string): void {
  if (typeof window !== "undefined") localStorage.setItem(KEY, value);
}
