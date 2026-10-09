"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiFetch, ApiError } from "@/lib/api-client";
import { saveSession, SignInResponse } from "@/lib/auth";
import { Button, Input, Label, MailIcon, LockIcon, BuildingIcon } from "@/components/ui";
import { AuthShell } from "@/components/auth-shell";

export default function RegisterPage() {
  const router = useRouter();
  const [organizationName, setOrganizationName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const session = await apiFetch<SignInResponse>("/v1/auth/register", {
        method: "POST",
        body: JSON.stringify({ organizationName, email, password }),
      });
      saveSession(session);
      router.push("/apps");
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setError("An account with that email already exists.");
      } else if (err instanceof ApiError && err.status === 400) {
        setError("Please check your details — password must be at least 8 characters.");
      } else if (err instanceof ApiError && err.status === 429) {
        setError("Too many sign-ups from this network. Please try again later.");
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell
      title="Register your organization"
      subtitle="You'll be the owner of this organization and can invite teammates later."
    >
      <form onSubmit={onSubmit} className="space-y-4">
        <div>
          <Label>Organization name</Label>
          <Input
            required
            icon={<BuildingIcon size={16} />}
            value={organizationName}
            onChange={(e) => setOrganizationName(e.target.value)}
            placeholder="Acme Bank"
          />
        </div>
        <div>
          <Label>Work email</Label>
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
            minLength={8}
            icon={<LockIcon size={16} />}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="At least 8 characters"
            autoComplete="new-password"
          />
        </div>

        {error && (
          <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
        )}

        <Button type="submit" loading={loading} className="w-full">
          {loading ? "Creating your organization…" : "Create organization"}
        </Button>
      </form>

      <p className="mt-6 text-center text-sm text-ink-500">
        Already registered?{" "}
        <Link href="/login" className="font-medium text-brand-700 hover:underline">
          Sign in
        </Link>
      </p>
    </AuthShell>
  );
}
