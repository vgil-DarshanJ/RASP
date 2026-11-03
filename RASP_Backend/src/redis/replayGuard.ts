import { redis } from "./client";

/**
 * Closes the residual replay window `isTimestampFresh`'s tolerance alone
 * leaves open: a valid signature is only rejected once it's stale
 * (5 minutes by default), which still lets an attacker who captured one
 * request replay it repeatedly *within* that window. This records every
 * signature seen and rejects a second use of the same one outright.
 *
 * Fails CLOSED, deliberately unlike the rate limiter and dashboard cache
 * elsewhere in this codebase: a replay check that fails open (i.e.,
 * "allow if Redis is down") stops being a real security control the
 * moment Redis has a bad day. If Redis is unavailable, every request is
 * rejected as `REPLAY_CHECK_UNAVAILABLE` rather than silently skipping
 * the check — availability is sacrificed here on purpose, because this
 * check exists specifically to stop a captured banking-app request from
 * being replayed, not to make a dashboard chart load faster.
 */
export async function checkAndRecordSignature(
  apiKey: string,
  signature: string,
  ttlSeconds: number,
): Promise<"fresh" | "replayed" | "unavailable"> {
  try {
    const key = `used_sig:${apiKey}:${signature}`;
    // NX = only set if not already present; returns null if the key
    // already existed — i.e., this exact signature was already used.
    const result = await redis.set(key, "1", "EX", ttlSeconds, "NX");
    return result === "OK" ? "fresh" : "replayed";
  } catch (err) {
    console.error("[replayGuard] Redis unavailable, failing closed:", err);
    return "unavailable";
  }
}
