import { NextFunction, Request, Response } from "express";
import { computeDeviceKeyId } from "../crypto/ecdsa";
import { checkRateLimit } from "./rateLimit";

export type RateCheck = (
  key: string,
  limitPerWindow: number,
  windowSeconds: number,
) => Promise<{ allowed: boolean; remaining: number }>;

const MAX_DEVICE_ID = 200;

/**
 * The device a request claims to come from, for rate limiting only. It is
 * read before authentication and is not trusted for anything else — the
 * route verifies the real identity afterwards.
 *
 * - evidence envelope: `deviceKeyId`
 * - legacy batch: the first event's `deviceId`
 * - device registration: Base64(SHA-256(publicKey)), i.e. the key id it will get
 *
 * Requests that name no device share one `unidentified` bucket per app.
 */
export function claimedDevice(body: unknown): string {
  if (typeof body !== "object" || body === null) return "unidentified";
  const b = body as Record<string, unknown>;
  const pick = (v: unknown) => (typeof v === "string" && v.length > 0 ? v.slice(0, MAX_DEVICE_ID) : null);

  const envelopeKey = pick(b.deviceKeyId);
  if (envelopeKey) return `key:${envelopeKey}`;

  if (typeof b.publicKey === "string" && b.publicKey.length > 0) {
    return `key:${computeDeviceKeyId(Buffer.from(b.publicKey, "base64"))}`;
  }

  if (Array.isArray(b.events) && b.events.length > 0) {
    const first = b.events[0] as Record<string, unknown> | null;
    const legacyId = first ? pick(first.deviceId) : null;
    if (legacyId) return `device:${legacyId}`;
  }
  return "unidentified";
}

/**
 * Three rate limits, applied before the (more expensive) credential lookup
 * and signature checks. A request must pass all of them:
 *
 * 1. per client IP (`req.ip`; set TRUST_PROXY when behind a load balancer,
 *    or every request shares the proxy's IP) — also applies to requests
 *    without an API key;
 * 2. per API key — a coarse ceiling for the whole app, so inventing a new
 *    device id per request does not buy an unlimited budget;
 * 3. per app + device — each device gets its own budget, so one busy or
 *    misbehaving device cannot use up the app's.
 *
 * The API key and device are read from the unauthenticated request; the
 * auth middleware that runs next checks them for real. A 429 names the
 * limit that was hit (`limit`: "ip" | "api_key" | "device").
 */
export function deviceRateLimiter(options: {
  scope: string;
  /** Per-device limit env var (and its default). */
  limitEnv: string;
  defaultLimit: number;
  /** Per-API-key ceiling env var (and its default). */
  apiKeyLimitEnv: string;
  defaultApiKeyLimit: number;
  /** Per-IP ceiling env var (and its default). */
  ipLimitEnv: string;
  defaultIpLimit: number;
  windowEnv: string;
  defaultWindowSeconds: number;
  check?: RateCheck;
}) {
  const check = options.check ?? checkRateLimit;
  const envNumber = (name: string, fallback: number) => Number(process.env[name]) || fallback;

  return async function rateLimitPerDevice(req: Request, res: Response, next: NextFunction) {
    const windowSeconds = envNumber(options.windowEnv, options.defaultWindowSeconds);
    const apiKey = req.header("X-Api-Key");

    const buckets: Array<{ limit: "ip" | "api_key" | "device"; key: string; max: number }> = [
      { limit: "ip", key: `${options.scope}:ip:${req.ip ?? "unknown"}`, max: envNumber(options.ipLimitEnv, options.defaultIpLimit) },
    ];
    if (apiKey) {
      buckets.push(
        { limit: "api_key", key: `${options.scope}:key:${apiKey}`, max: envNumber(options.apiKeyLimitEnv, options.defaultApiKeyLimit) },
        { limit: "device", key: `${options.scope}:${apiKey}:${claimedDevice(req.body)}`, max: envNumber(options.limitEnv, options.defaultLimit) },
      );
    }

    for (const bucket of buckets) {
      const { allowed, remaining } = await check(bucket.key, bucket.max, windowSeconds);
      if (bucket.limit === "device") {
        res.setHeader("X-RateLimit-Limit", String(bucket.max));
        res.setHeader("X-RateLimit-Remaining", String(remaining));
      }
      if (!allowed) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED", limit: bucket.limit });
    }
    next(); // no API key: the auth middleware reports MISSING_API_KEY
  };
}
