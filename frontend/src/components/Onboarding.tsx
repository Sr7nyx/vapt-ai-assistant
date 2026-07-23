"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { usePathname, useRouter } from "next/navigation";
import { hasSeenOnboarding, markOnboarded } from "@/lib/prefs";

type Step = {
  title: string;
  body: string;
  /** CSS selector to spotlight, if this step points at something on the page. */
  target?: string;
  /** Route the user should be on for this step; the tour navigates there. */
  route?: string;
  primary: string;
};

const STEPS: Step[] = [
  {
    title: "Welcome to VAPT Console",
    body: "An AI-assisted workspace that turns raw evidence and scanner output into validated, report-ready findings. Every AI finding is scored deterministically, grounded against its evidence, and challenged by a skeptical reviewer. Here is the quick tour.",
    primary: "Show me around",
  },
  {
    title: "1. Configure your models (recommended)",
    body: "You can start right away on the shared demo key. But for private, higher-limit analysis, add your own provider key here and pick your extraction and reviewer models. This is optional — skip it any time and come back later.",
    route: "/settings",
    target: "[data-tour='api-key']",
    primary: "Got it",
  },
  {
    title: "2. Create a project",
    body: "Projects keep each engagement's findings together. Everything you analyze or import is committed into the project you have selected.",
    route: "/projects",
    primary: "Next",
  },
  {
    title: "3. Analyze or import",
    body: "Paste evidence into the Analyzer to extract findings, or bring in Burp, Nessus, ZAP, Nmap, or CSV under Import and let AI triage flag the false positives before you commit them.",
    route: "/analyzer",
    primary: "Next",
  },
  {
    title: "4. Review, retest, report",
    body: "Findings shows everything with filters and expandable detail, inline editing, and retest tracking. When you are ready, Reports exports DOCX, PDF, XLSX, or JSON. That is the whole loop.",
    route: "/findings",
    primary: "Start using it",
  },
];

export default function Onboarding() {
  const { data: session, status } = useSession();
  const owner = session?.user?.email || "";
  const router = useRouter();
  const pathname = usePathname();

  const [open, setOpen] = useState(false);
  const [i, setI] = useState(0);
  const [rect, setRect] = useState<DOMRect | null>(null);

  // Decide once, on first authenticated render for this account.
  useEffect(() => {
    if (status === "authenticated" && owner && !hasSeenOnboarding(owner)) {
      setOpen(true);
    }
  }, [status, owner]);

  const step = STEPS[i];

  // Navigate to the step's route if needed.
  useEffect(() => {
    if (open && step?.route && pathname !== step.route) {
      router.push(step.route);
    }
  }, [open, i, step, pathname, router]);

  // Track the spotlighted element (after any navigation settles).
  useEffect(() => {
    if (!open || !step?.target) {
      setRect(null);
      return;
    }
    let raf = 0;
    let tries = 0;
    const find = () => {
      const el = document.querySelector(step.target as string);
      if (el) {
        el.scrollIntoView({ block: "center", behavior: "smooth" });
        setRect(el.getBoundingClientRect());
      } else if (tries++ < 40) {
        raf = requestAnimationFrame(find);
      }
    };
    find();
    const onMove = () => {
      const el = document.querySelector(step.target as string);
      if (el) setRect(el.getBoundingClientRect());
    };
    window.addEventListener("resize", onMove);
    window.addEventListener("scroll", onMove, true);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onMove);
      window.removeEventListener("scroll", onMove, true);
    };
  }, [open, i, step, pathname]);

  if (!open || !step) return null;

  const finish = () => {
    markOnboarded(owner);
    setOpen(false);
  };
  const next = () => (i < STEPS.length - 1 ? setI(i + 1) : finish());
  const pad = 8;

  return (
    <div className="fixed inset-0 z-[70]">
      {/* Dim layer. With a spotlight, a bright ring marks the target through the dim. */}
      <div className="absolute inset-0 bg-black/70" onClick={finish} />
      {rect && (
        <div
          className="absolute rounded-lg ring-2 ring-accent pointer-events-none transition-all"
          style={{
            top: rect.top - pad,
            left: rect.left - pad,
            width: rect.width + pad * 2,
            height: rect.height + pad * 2,
            boxShadow: "0 0 0 9999px rgba(0,0,0,0.55)",
          }}
        />
      )}

      <div className="absolute inset-0 flex items-end sm:items-center justify-center p-4 pointer-events-none">
        <div className="card max-w-md w-full pointer-events-auto shadow-2xl">
          <div className="text-xs text-muted mb-2">
            Step {i + 1} of {STEPS.length}
          </div>
          <h2 className="text-lg font-semibold mb-2">{step.title}</h2>
          <p className="text-sm text-muted leading-relaxed mb-5">{step.body}</p>
          <div className="flex items-center justify-between">
            <button className="text-sm text-muted hover:text-text" onClick={finish}>
              Skip tour
            </button>
            <div className="flex gap-2">
              {i > 0 && (
                <button className="btn-sm" onClick={() => setI(i - 1)}>
                  Back
                </button>
              )}
              <button className="btn" onClick={next}>
                {step.primary}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
