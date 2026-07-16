"use client";
import { SessionProvider } from "next-auth/react";
import { ProjectProvider } from "@/lib/ProjectContext";
import { ToastProvider } from "@/components/Toast";
import { ReactNode } from "react";

export default function Providers({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <ToastProvider>
        <ProjectProvider>{children}</ProjectProvider>
      </ToastProvider>
    </SessionProvider>
  );
}
