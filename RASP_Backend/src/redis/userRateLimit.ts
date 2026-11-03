import { NextFunction, Response } from "express";
import type { AuthedRequest } from "../middleware/auth";
import type { RateCheck } from "./deviceRateLimit";
import { checkRateLimit } from "./rateLimit";

/** The counter dashboard (JWT) limits use; tests replace `check`. */
export const userRateLimit: { check: RateCheck } = { check: checkRateLimit };

/**
 * Rate limit for dashboard endpoints (after requireAuth): per signed-in user
 * and per client IP, in one window. A 429 names the limit hit
 * ("user" | "ip"). Like the ingestion limits it fails open if Redis is down.
 */
export function userRateLimiter(options: { scope: string; perUser: number; perIp: number; windowSeconds: number }) {
  return async function rateLimitPerUser(req: AuthedRequest, res: Response, next: NextFunction) {
    const buckets: Array<{ limit: "user" | "ip"; key: string; max: number }> = [
      { limit: "ip", key: `${options.scope}:ip:${req.ip ?? "unknown"}`, max: options.perIp },
    ];
    if (req.user) buckets.push({ limit: "user", key: `${options.scope}:user:${req.user.userId}`, max: options.perUser });
    for (const bucket of buckets) {
      const { allowed } = await userRateLimit.check(bucket.key, bucket.max, options.windowSeconds);
      if (!allowed) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED", limit: bucket.limit });
    }
    next();
  };
}
