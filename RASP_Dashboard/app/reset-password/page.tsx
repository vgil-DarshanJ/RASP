"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Button, Input, Label, LockIcon } from "@/components/ui";
import { AuthShell } from "@/components/auth-shell";

/**
 * Step 2 of "Forgot password": the link from the e-mail (or, on a
 * development PC, from the backend's terminal) opens this page with
 * ?token=…; the new password is sent with it to POST /v1/auth/reset-password.
 * Afterwards every session of the account is signed out and the user signs in
 * with the new password.
 */
export default function ResetPasswordPage() {
  /** undefined until read from the address; null when the link has none. */
  const [token, setToken] = useState<string | null | undefined>(undefined);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Read here rather than with useSearchParams, so the page stays a plain static page.
    setToken(new URLSearchParams(window.location.search).get("token") || null);
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) return setError("The password must be at least 8 characters.");
    if (password !== confirm) return setError("The two passwords are not the same.");
    setLoading(true);
    try {
      await apiFetch("/v1/auth/reset-password", { method: "POST", body: JSON.stringify({ token, password }) });
      setDone(true);
    } catch (err) {
      const body = err instanceof ApiError ? (err.body as { error?: string } | null) : null;
      if (body?.error === "INVALID_OR_EXPIRED_TOKEN") {
        setError("This link is expired or was already used. Ask for a new one.");
      } else if (err instanceof ApiError && err.status === 429) {
        setError("Too many attempts from this network. Try again in a few minutes.");
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell title="Choose a new password" subtitle="Your new password replaces the old one and signs this account out everywhere.">
      {done ? (
        <div className="space-y-4" data-testid="reset-done">
          <p className="rounded-lg bg-brand-50 px-3 py-3 text-sm text-ink-700">Your password was changed.</p>
          <Link href="/login" className="block text-center text-sm font-medium text-brand-700 hover:underline">
            Sign in with the new password
          </Link>
        </div>
      ) : token === null ? (
        <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
          This page needs the link from the reset e-mail.{" "}
          <Link href="/forgot-password" className="font-medium underline">
            Ask for a link
          </Link>
          .
        </p>
      ) : (
        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <Label>New password</Label>
            <Input
              type="password"
              required
              minLength={8}
              icon={<LockIcon size={16} />}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 8 characters"
              autoComplete="new-password"
            />
          </div>
          <div>
            <Label>Repeat the new password</Label>
            <Input
              type="password"
              required
              minLength={8}
              icon={<LockIcon size={16} />}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
            />
          </div>

          {error && (
            <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}{" "}
              {error.startsWith("This link") && (
                <Link href="/forgot-password" className="font-medium underline">
                  New link
                </Link>
              )}
            </p>
          )}

          <Button type="submit" loading={loading} className="w-full" size="md" disabled={!token}>
            {loading ? "Saving…" : "Set new password"}
          </Button>
        </form>
      )}
    </AuthShell>
  );
}
