"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Button, Input, Label, MailIcon } from "@/components/ui";
import { AuthShell } from "@/components/auth-shell";

/**
 * Step 1 of "Forgot password": asks the backend to send a reset link
 * (POST /v1/auth/forgot-password). The answer is the same for every email,
 * so this page never says whether an account exists.
 */
export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await apiFetch("/v1/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
      setSent(true);
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Too many requests from this network. Try again in a few minutes.");
      } else if (err instanceof ApiError && err.status === 400) {
        setError("Please enter a valid email address.");
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell title="Forgot your password?" subtitle="Enter your account's email and we'll send you a link to choose a new password.">
      {sent ? (
        <div className="space-y-4" data-testid="forgot-sent">
          <p className="rounded-lg bg-brand-50 px-3 py-3 text-sm text-ink-700">
            If an account exists for <strong>{email}</strong>, a reset link is on its way. It works once and expires in 30
            minutes.
          </p>
          <p className="text-xs text-ink-500">
            No e-mail server set up (a development PC)? The link appears in the terminal where the backend runs.
          </p>
        </div>
      ) : (
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

          {error && <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

          <Button type="submit" loading={loading} className="w-full" size="md">
            {loading ? "Sending…" : "Send reset link"}
          </Button>
        </form>
      )}

      <p className="mt-6 text-center text-sm text-ink-500">
        <Link href="/login" className="font-medium text-brand-700 hover:underline">
          Back to sign in
        </Link>
      </p>
    </AuthShell>
  );
}
