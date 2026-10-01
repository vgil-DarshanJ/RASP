"use client";

import { useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:4000";

export type SystemHealth = {
  status: "checking" | "healthy" | "degraded" | "unreachable";
  postgres: boolean | null;
  redis: boolean | null;
};

/**
 * Polls the backend's real `/healthz` (unauthenticated — checks an actual
 * `SELECT 1` against Postgres and a real Redis PING, see BE `app.ts`) so
 * the sidebar's "online" indicator reflects reality instead of being a
 * hardcoded always-green dot. A failed `fetch` (backend down, CORS,
 * network) is reported as "unreachable", not silently ignored.
 */
export function useHealth(intervalMs = 15_000): SystemHealth {
  const [health, setHealth] = useState<SystemHealth>({ status: "checking", postgres: null, redis: null });

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const res = await fetch(`${API_BASE}/healthz`, { cache: "no-store" });
        const body = await res.json().catch(() => null);
        if (cancelled) return;
        if (res.ok && body?.ok) {
          setHealth({ status: "healthy", postgres: !!body.postgres, redis: !!body.redis });
        } else {
          setHealth({ status: "degraded", postgres: !!body?.postgres, redis: !!body?.redis });
        }
      } catch {
        if (!cancelled) setHealth({ status: "unreachable", postgres: null, redis: null });
      }
    }

    check();
    const interval = setInterval(check, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [intervalMs]);

  return health;
}
