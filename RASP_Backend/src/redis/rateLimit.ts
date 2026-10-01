import { redis } from "./client";

/**
 * Fixed-window rate limiter, per API key. Unlike `replayGuard`, this
 * fails OPEN (allows the request) if Redis is unavailable — a rate limit
 * is a damage-control control, not the primary authentication gate (the
 * HMAC signature check already happened by the time this runs); losing
 * it temporarily during a Redis outage is an acceptable trade against
 * blocking all legitimate ingestion traffic because a cache is down.
 * Postgres + the signature check remain the real security boundary
 * regardless of this control's availability.
 */
export async function checkRateLimit(
  apiKey: string,
  limitPerWindow: number,
  windowSeconds: number,
): Promise<{ allowed: boolean; remaining: number }> {
  try {
    const windowBucket = Math.floor(Date.now() / (windowSeconds * 1000));
    const key = `ratelimit:${apiKey}:${windowBucket}`;

    const count = await redis.incr(key);
    if (count === 1) {
      // Only the first increment in a new window needs to set the
      // expiry — subsequent INCRs on the same key must not keep pushing
      // it back, or a sustained attacker could keep the key alive
      // forever and the window would never actually roll over.
      await redis.expire(key, windowSeconds + 5);
    }

    return { allowed: count <= limitPerWindow, remaining: Math.max(0, limitPerWindow - count) };
  } catch (err) {
    console.error("[rateLimit] Redis unavailable, failing open:", err);
    return { allowed: true, remaining: limitPerWindow };
  }
}
