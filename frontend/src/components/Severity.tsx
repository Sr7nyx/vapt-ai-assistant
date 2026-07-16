export function sevClass(s?: string): string {
  const map: Record<string, string> = {
    Critical: "text-danger",
    High: "text-warn",
    Medium: "text-accent",
    Low: "text-muted",
    Informational: "text-muted",
  };
  return `text-xs font-semibold ${map[s || ""] || "text-muted"}`;
}

export function verdictOf(remarks?: unknown): string {
  const m = String(remarks || "").match(/verdict:\s*"([^"]+)"/i);
  return m ? m[1] : "";
}
