"use client";
import { SessionProvider } from "next-auth/react";
import { ProjectProvider } from "@/lib/ProjectContext";
import { ReactNode } from "react";

export default function Providers({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <ProjectProvider>{children}</ProjectProvider>
    </SessionProvider>
  );
}
