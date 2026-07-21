"use client";
import { useSession } from "next-auth/react";
import { ReactNode } from "react";
import Nav from "./Nav";
import SignInGate from "./SignInGate";
import { Spinner } from "./Loading";
import { bindSessionOwner } from "@/lib/prefs";

export default function AppShell({ children }: { children: ReactNode }) {
  const { data: session, status } = useSession();

  // Bind stored provider configuration to the signed-in account during render,
  // before any child effect can read it. If the browser holds a configuration
  // belonging to a different account, it is purged rather than inherited.
  // bindSessionOwner is idempotent, so repeated renders are harmless.
  if (typeof window !== "undefined" && status === "authenticated") {
    bindSessionOwner(session?.user?.email || "");
  }

  if (status === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center text-muted gap-2">
        <Spinner /> Loading…
      </div>
    );
  }
  if (status !== "authenticated") {
    return <SignInGate />;
  }
  return (
    <div className="flex min-h-screen">
      <Nav />
      <main className="flex-1 min-w-0 px-6 py-10">
        <div className="mx-auto w-full max-w-5xl">{children}</div>
      </main>
    </div>
  );
}
