"use client";
import { signIn } from "next-auth/react";

export default function SignInGate() {
  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="card max-w-md text-center">
        <div className="text-xl font-semibold mb-1">
          vapt<span className="text-accent">.</span>console
        </div>
        <p className="text-muted mb-6 text-sm">
          AI-assisted vulnerability assessment, triage, and reporting. Sign in to continue.
        </p>
        <button className="btn" onClick={() => signIn("google")}>
          Sign in with Google
        </button>
      </div>
    </div>
  );
}
