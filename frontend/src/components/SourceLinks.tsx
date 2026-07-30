import { ReactNode } from "react";

/** Single source of truth for the repository, so the URL is not scattered
 *  across pages where one copy can drift. */
export const REPO_URL = "https://github.com/Sr7nyx/vapt-ai-assistant";
export const LICENSE_URL = `${REPO_URL}/blob/main/LICENSE`;
export const README_URL = `${REPO_URL}#readme`;
export const EVAL_URL = `${REPO_URL}/tree/main/eval`;

export function GithubMark({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" className="shrink-0">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A7.995 7.995 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

/** External links always carry noopener/noreferrer: target="_blank" without it
 *  hands the opened page a handle back to this one. */
function External({
  href,
  className,
  children,
  label,
}: {
  href: string;
  className?: string;
  children: ReactNode;
  label?: string;
}) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" aria-label={label} className={className}>
      {children}
    </a>
  );
}

/** Bordered link in the style of the rest of the terminal chrome. Secondary by
 *  default so it does not compete with a primary call to action. */
export function GithubButton({
  label = "VIEW SOURCE",
  full = false,
  tone = "muted",
}: {
  label?: string;
  full?: boolean;
  tone?: "muted" | "accent";
}) {
  const colour =
    tone === "accent"
      ? "border-accent/70 text-accent hover:bg-accent hover:text-black"
      : "border-border text-muted hover:border-accent hover:text-accent";
  return (
    <External
      href={REPO_URL}
      label="View the source code on GitHub"
      className={`inline-flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-xs tracking-widest transition-all active:scale-[0.98] ${colour} ${
        full ? "w-full" : ""
      }`}
    >
      <GithubMark />
      {label}
    </External>
  );
}

/** Bracketed row of secondary destinations. */
export function SourceFooter({ className = "" }: { className?: string }) {
  const items: [string, string][] = [
    ["source", REPO_URL],
    ["readme", README_URL],
    ["evaluation", EVAL_URL],
    ["license", LICENSE_URL],
  ];
  return (
    <div className={`flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted ${className}`}>
      {items.map(([name, href], i) => (
        <span key={name} className="flex items-center gap-3">
          {i > 0 && <span className="text-border select-none">.</span>}
          <External href={href} className="tracking-wide hover:text-accent transition-colors">
            [{name}]
          </External>
        </span>
      ))}
    </div>
  );
}
