import type { Request } from "express";

/**
 * The dashboard session lives in an httpOnly cookie (F-11): page scripts,
 * including injected ones, cannot read it, unlike the token the dashboard
 * used to keep in localStorage.
 *
 * - `HttpOnly`, `Path=/v1` (sent to API routes only), `SameSite=Lax` by
 *   default (SESSION_COOKIE_SAMESITE: Lax | Strict | None).
 * - `Secure` when NODE_ENV=production or SESSION_COOKIE_SECURE=1, and always
 *   with SameSite=None (browsers require it).
 * - No `Domain`: the cookie belongs to the API host only. Serve the dashboard
 *   and the API from the same site (for example dashboard.bank.example and
 *   api.bank.example); browsers block cookies between unrelated sites.
 *
 * Requests that carry this cookie and change data must also come from an
 * allowed origin — see `requireAuth` (cross-site request forgery guard).
 */
export const SESSION_COOKIE = "rasp_session";

function sameSite(): "Lax" | "Strict" | "None" {
  const value = (process.env.SESSION_COOKIE_SAMESITE || "Lax").trim().toLowerCase();
  if (value === "strict") return "Strict";
  if (value === "none") return "None";
  return "Lax";
}

function attributes(maxAgeSeconds: number): string {
  const site = sameSite();
  const secure = site === "None" || process.env.NODE_ENV === "production" || process.env.SESSION_COOKIE_SECURE === "1";
  return [`Path=/v1`, `Max-Age=${maxAgeSeconds}`, "HttpOnly", `SameSite=${site}`, ...(secure ? ["Secure"] : [])].join("; ");
}

/** `Set-Cookie` value carrying [token] for [maxAgeSeconds]. */
export function sessionCookie(token: string, maxAgeSeconds: number): string {
  return `${SESSION_COOKIE}=${token}; ${attributes(maxAgeSeconds)}`;
}

/** `Set-Cookie` value that removes the session cookie. */
export function clearedSessionCookie(): string {
  return `${SESSION_COOKIE}=; ${attributes(0)}`;
}

/** The session token from the request's `Cookie` header, or `null`. */
export function readSessionCookie(req: Pick<Request, "headers">): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === SESSION_COOKIE) {
      const value = part.slice(eq + 1).trim();
      return value.length > 0 ? value : null;
    }
  }
  return null;
}
