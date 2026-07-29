import "./globals.css";
import { ReactNode } from "react";
import type { Metadata, Viewport } from "next";
import Providers from "@/components/Providers";
import AppShell from "@/components/AppShell";

// Absolute URLs are required for social previews. Vercel injects VERCEL_URL on
// every deployment, so preview builds advertise themselves rather than pointing
// their cards at production.
const siteUrl =
  process.env.NEXT_PUBLIC_SITE_URL ||
  (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "https://vapt-ai-assistant.vercel.app");

const title = "VAPT Console";
const description =
  "An AI-assisted workspace for penetration testing, built so the AI is assumed wrong until proven otherwise. Deterministic CVSS, evidence grounding, and a skeptical reviewer that argues the false-positive case before anything reaches a report.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: { default: title, template: "%s | VAPT Console" },
  description,
  applicationName: title,
  authors: [{ name: "VAPT Console" }],
  keywords: [
    "penetration testing", "VAPT", "vulnerability assessment", "AI security",
    "false positive triage", "OWASP", "CVSS", "security reporting",
  ],
  openGraph: {
    type: "website",
    url: siteUrl,
    siteName: title,
    title: "VAPT Console - AI-assisted VAPT, with guardrails",
    description,
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "VAPT Console" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "VAPT Console - AI-assisted VAPT, with guardrails",
    description,
    images: ["/og.png"],
  },
  // Nothing here should surface in search results: it is an authenticated tool,
  // and indexing a sign-in wall helps nobody.
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: "#0a0e0c",
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
