"use client";
import { useSession } from "next-auth/react";
import { ReactNode } from "react";
import Nav from "./Nav";
import SignInGate from "./SignInGate";

export default function AppShell({ children }: { children: ReactNode }) {
  const { status } = useSession();

  if (status === "loading") {
    return <div className="min-h-screen flex items-center justify-center text-muted">Loading…</div>;
  }
  if (status !== "authenticated") {
    return <SignInGate />;
  }
  return (
    <div className="flex min-h-screen">
      <Nav />
      <main className="flex-1 p-8 max-w-6xl w-full">{children}</main>
    </div>
  );
}
