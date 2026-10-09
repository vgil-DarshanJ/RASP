"use client";

const LEGACY_TOKEN_KEY = "rasp_shield_token";
const ORG_KEY = "rasp_shield_org";
const USER_KEY = "rasp_shield_user";

export interface StoredSession {
  organization: { id: string; name: string };
  user: { id: string; email: string; role: string };
}

/** What `POST /v1/auth/login` and `/register` return; `token` is for API clients and is never stored here. */
export interface SignInResponse extends StoredSession {
  token?: string;
}

/**
 * The session token lives only in the backend's httpOnly cookie, which page
 * scripts cannot read (F-11). localStorage keeps just the user and
 * organization for display, and as the hint that someone is signed in; the
 * backend decides on every request (401 → `apiFetch` signs out).
 */
export function saveSession(session: SignInResponse) {
  localStorage.removeItem(LEGACY_TOKEN_KEY);
  localStorage.setItem(ORG_KEY, JSON.stringify(session.organization));
  localStorage.setItem(USER_KEY, JSON.stringify(session.user));
}

/** `true` when this browser signed in and has not signed out since. */
export function hasSession(): boolean {
  if (typeof window === "undefined") return false;
  return localStorage.getItem(USER_KEY) !== null;
}

export function getStoredOrganization(): { id: string; name: string } | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(ORG_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function getStoredUser(): { id: string; email: string; role: string } | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function clearSession() {
  localStorage.removeItem(LEGACY_TOKEN_KEY);
  localStorage.removeItem(ORG_KEY);
  localStorage.removeItem(USER_KEY);
}
