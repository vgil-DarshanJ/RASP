"use client";

import { clearSession } from "./auth";
import { recordClientProblem } from "./clientProblems";
import { API_BASE } from "./sites";

export class ApiError extends Error {
  constructor(public status: number, public body: unknown) {
    super(`API error ${status}`);
  }
}

/**
 * Thin fetch wrapper: sends the session cookie (`credentials: "include"`;
 * the token itself is httpOnly and never visible here), throws a typed
 * `ApiError` on any non-2xx response (never lets a caller silently treat
 * a failed request as success by forgetting to check `res.ok`), and on a
 * 401 clears the stored session AND sends the browser to `/login` —
 * clearing storage alone left the crashed page's own React tree still
 * rendered until something else navigated away, and most pages don't
 * catch this error themselves, so a stale/revoked token surfaced as an
 * uncaught-exception crash screen instead of the intended clean bounce
 * to the login page. Every caller still sees the thrown `ApiError`
 * (uncaught, this navigation happens anyway) — a page that wants to
 * show its own message before leaving may still catch it.
 */
export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");

  const method = (options.method || "GET").toUpperCase();
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: "include" });
  } catch (err) {
    // Never reached the backend: shown on the System Status page.
    recordClientProblem({ method, path, status: 0 });
    throw err;
  }

  if (res.status === 401) {
    clearSession();
    if (typeof window !== "undefined" && window.location.pathname !== "/login") {
      window.location.href = "/login";
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const code = (body as { error?: unknown } | null)?.error;
    recordClientProblem({
      method,
      path,
      status: res.status,
      code: typeof code === "string" ? code : undefined,
      requestId: res.headers.get("X-Request-Id") ?? undefined,
    });
    // The selected application was archived (or the list is stale): ask the
    // app picker to reload and choose a valid one. The page's own request
    // never settles, so it shows its loading state instead of an error
    // screen, then loads again for the new selection.
    if (res.status === 404 && (body as { error?: string } | null)?.error === "APPLICATION_NOT_FOUND" && typeof window !== "undefined" && !(options.method && options.method !== "GET")) {
      window.dispatchEvent(new Event(APPLICATION_GONE_EVENT));
      return new Promise<T>(() => {});
    }
    throw new ApiError(res.status, body);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

/** Fired when the backend says the selected application does not exist (any more). */
export const APPLICATION_GONE_EVENT = "rasp:application-gone";

/** Non-JSON download (the SDK zip) — returns the raw Response so the
 *  caller can trigger a browser save via a Blob URL. */
export async function apiDownload(path: string): Promise<Response> {
  const res = await fetch(`${API_BASE}${path}`, { credentials: "include" });
  if (!res.ok) throw new ApiError(res.status, await res.text().catch(() => null));
  return res;
}
