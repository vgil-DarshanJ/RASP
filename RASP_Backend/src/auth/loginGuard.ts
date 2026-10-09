import crypto from "node:crypto";
import { redis } from "../redis/client";

/**
 * Brute-force limits for `POST /v1/auth/login` and `/register` (F-04).
 *
 * - Per client IP: AUTH_LOGIN_RATE_LIMIT_PER_IP login attempts (default 30)
 *   and AUTH_REGISTER_RATE_LIMIT_PER_IP registrations (default 10) per
 *   AUTH_RATE_LIMIT_WINDOW_SECONDS (default 900) → 429 RATE_LIMIT_EXCEEDED.
 * - Per account: AUTH_LOCKOUT_THRESHOLD failed logins (default 5) within the
 *   window lock that email for AUTH_LOCKOUT_SECONDS (default 900) → 429
 *   ACCOUNT_TEMPORARILY_LOCKED, even with the right password. Failures are
 *   counted for unknown emails too, so the answer never tells whether an
 *   account exists. A successful login clears the count.
 *
 * Keys hold a SHA-256 of the lower-cased email, never the email. Like the
 * other rate limits it fails open when Redis is down: the password check
 * stays the real gate.
 */
export interface AuthLimitStore {
  /** Adds one to [key] (expiring [windowSeconds] after the first hit); the new count. */
  hit(key: string, windowSeconds: number): Promise<number>;
  /** Seconds until [key] expires; 0 when it does not exist. */
  ttl(key: string): Promise<number>;
  set(key: string, ttlSeconds: number): Promise<void>;
  del(key: string): Promise<void>;
}

export const redisAuthLimitStore: AuthLimitStore = {
  async hit(key, windowSeconds) {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, windowSeconds);
    return count;
  },
  async ttl(key) {
    const seconds = await redis.ttl(key);
    return seconds > 0 ? seconds : 0;
  },
  async set(key, ttlSeconds) {
    await redis.set(key, "1", "EX", ttlSeconds);
  },
  async del(key) {
    await redis.del(key);
  },
};

/** The store in use; tests replace it. */
export const authLimits: { store: AuthLimitStore } = { store: redisAuthLimitStore };

function intEnv(name: string, fallback: number): number {
  const value = Number(process.env[name]);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function settings() {
  return {
    loginPerIp: intEnv("AUTH_LOGIN_RATE_LIMIT_PER_IP", 30),
    registerPerIp: intEnv("AUTH_REGISTER_RATE_LIMIT_PER_IP", 10),
    windowSeconds: intEnv("AUTH_RATE_LIMIT_WINDOW_SECONDS", 900),
    lockoutThreshold: intEnv("AUTH_LOCKOUT_THRESHOLD", 5),
    lockoutSeconds: intEnv("AUTH_LOCKOUT_SECONDS", 900),
  };
}

function accountKey(email: string): string {
  return crypto.createHash("sha256").update(email.trim().toLowerCase()).digest("hex");
}

async function safely<T>(fallback: T, work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (err) {
    console.error("[loginGuard] Redis unavailable, failing open:", err instanceof Error ? err.message : err);
    return fallback;
  }
}

export type Blocked = { error: "RATE_LIMIT_EXCEEDED" | "ACCOUNT_TEMPORARILY_LOCKED"; retryAfterSeconds: number };

/** Counts one attempt for this IP; a [Blocked] answer when over the limit. */
export async function checkIpLimit(kind: "login" | "register", ip: string): Promise<Blocked | null> {
  const s = settings();
  const max = kind === "login" ? s.loginPerIp : s.registerPerIp;
  const key = `auth:${kind}:ip:${ip}`;
  return safely<Blocked | null>(null, async () => {
    const count = await authLimits.store.hit(key, s.windowSeconds);
    if (count <= max) return null;
    return { error: "RATE_LIMIT_EXCEEDED", retryAfterSeconds: (await authLimits.store.ttl(key)) || s.windowSeconds };
  });
}

/** A [Blocked] answer while [email] is locked out. */
export async function checkAccountLock(email: string): Promise<Blocked | null> {
  return safely<Blocked | null>(null, async () => {
    const seconds = await authLimits.store.ttl(`auth:lock:${accountKey(email)}`);
    return seconds > 0 ? { error: "ACCOUNT_TEMPORARILY_LOCKED", retryAfterSeconds: seconds } : null;
  });
}

/** Records a failed login; locks the account when the threshold is reached. */
export async function recordLoginFailure(email: string): Promise<void> {
  const s = settings();
  const id = accountKey(email);
  await safely(undefined, async () => {
    const failures = await authLimits.store.hit(`auth:fail:${id}`, s.windowSeconds);
    if (failures >= s.lockoutThreshold) {
      await authLimits.store.set(`auth:lock:${id}`, s.lockoutSeconds);
      await authLimits.store.del(`auth:fail:${id}`);
    }
  });
}

/** Clears the failure count after a successful login. */
export async function recordLoginSuccess(email: string): Promise<void> {
  await safely(undefined, () => authLimits.store.del(`auth:fail:${accountKey(email)}`));
}
