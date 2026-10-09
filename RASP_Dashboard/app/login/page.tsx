"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiFetch, ApiError } from "@/lib/api-client";
import { saveSession, SignInResponse } from "@/lib/auth";
import { Button, Input, Label, MailIcon, LockIcon } from "@/components/ui";
import { AuthShell } from "@/components/auth-shell";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const session = await apiFetch<SignInResponse>("/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      saveSession(session);
      router.push("/dashboard");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("Incorrect email or password.");
      } else if (err instanceof ApiError && err.status === 429) {
        const body = err.body as { error?: string; retryAfterSeconds?: number } | null;
        const minutes = Math.max(1, Math.ceil((body?.retryAfterSeconds ?? 900) / 60));
        setError(
          body?.error === "ACCOUNT_TEMPORARILY_LOCKED"
            ? `Too many failed attempts for this account. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`
            : `Too many sign-in attempts from this network. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`,
        );
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell title="Welcome back" subtitle="Sign in to view your organization's protected apps and live threat telemetry.">
      <form onSubmit={onSubmit} className="space-y-4">
        <div>
          <Label>Email</Label>
          <Input
            type="email"
            required
            icon={<MailIcon size={16} />}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@yourbank.com"
            autoComplete="email"
          />
        </div>
        <div>
          <Label>Password</Label>
          <Input
            type="password"
            required
            icon={<LockIcon size={16} />}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            autoComplete="current-password"
          />
        </div>

        {error && (
          <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
        )}

        <Button type="submit" loading={loading} className="w-full" size="md">
          {loading ? "Signing in…" : "Sign in"}
        </Button>
      </form>

      <p className="mt-6 text-center text-sm text-ink-500">
        Don&apos;t have an account?{" "}
        <Link href="/register" className="font-medium text-brand-700 hover:underline">
          Register your organization
        </Link>
      </p>
    </AuthShell>
  );
}
