"use client";

const TOKEN_KEY = "rasp_shield_token";
const ORG_KEY = "rasp_shield_org";
const USER_KEY = "rasp_shield_user";

export interface StoredSession {
  token: string;
  organization: { id: string; name: string };
  user: { id: string; email: string; role: string };
}

/** localStorage only — this is a local-dev admin/customer portal, not a
 *  context where XSS-hardened httpOnly-cookie session storage has been
 *  built out yet (see the platform plan's deferred items). Acceptable for
 *  now; flagged here so it isn't silently assumed production-hardened. */
export function saveSession(session: StoredSession) {
  localStorage.setItem(TOKEN_KEY, session.token);
  localStorage.setItem(ORG_KEY, JSON.stringify(session.organization));
  localStorage.setItem(USER_KEY, JSON.stringify(session.user));
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
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
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ORG_KEY);
  localStorage.removeItem(USER_KEY);
}
