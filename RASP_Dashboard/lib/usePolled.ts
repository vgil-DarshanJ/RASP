"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api-client";

/**
 * GETs `path` now and every `intervalMs`, keeping the last good response.
 * `null` path = nothing to load yet (no application selected). A failed
 * poll keeps the previous data and sets `error`.
 */
export function usePolled<T>(path: string | null, intervalMs = 15_000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    setData(null);
    if (!path) return;
    let cancelled = false;
    const load = () =>
      apiFetch<T>(path)
        .then((d) => {
          if (cancelled) return;
          setData(d);
          setError(false);
        })
        .catch(() => !cancelled && setError(true));
    load();
    const id = setInterval(load, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [path, intervalMs]);

  return { data, error, loading: path !== null && data === null && !error };
}

export function timeAgo(iso: string, nowMs = Date.now()): string {
  const s = Math.max(0, Math.floor((nowMs - new Date(iso).getTime()) / 1000));
  if (s < 60) return s < 5 ? "just now" : `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return d < 7 ? `${d}d ago` : new Date(iso).toLocaleDateString();
}
