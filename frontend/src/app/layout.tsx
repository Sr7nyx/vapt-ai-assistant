import "./globals.css";
import { ReactNode } from "react";
import Providers from "@/components/Providers";
import AppShell from "@/components/AppShell";

export const metadata = {
  title: "VAPT Console",
  description: "AI-assisted vulnerability assessment, triage, and reporting",
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
