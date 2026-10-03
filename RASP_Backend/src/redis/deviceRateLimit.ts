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
 * Per app + device rate limit, applied before the (more expensive) credential
 * lookup and signature checks. One app's devices no longer share a single
 * budget: each device gets `limit` requests per window.
 *
 * The bucket is keyed by the raw `X-Api-Key` (identifies the app; checked
 * for real by the auth middleware that runs next) plus the claimed device.
 * A client that invents a new device id per request gets a new bucket each
 * time; such requests still fail authentication, but this limiter no longer
 * caps them per app.
 */
export function deviceRateLimiter(options: {
  scope: string;
  limitEnv: string;
  windowEnv: string;
  defaultLimit: number;
  defaultWindowSeconds: number;
  check?: RateCheck;
}) {
  const check = options.check ?? checkRateLimit;
  return async function rateLimitPerDevice(req: Request, res: Response, next: NextFunction) {
    const apiKey = req.header("X-Api-Key");
    if (!apiKey) return next(); // the auth middleware reports the real error

    const limit = Number(process.env[options.limitEnv]) || options.defaultLimit;
    const windowSeconds = Number(process.env[options.windowEnv]) || options.defaultWindowSeconds;
    const key = `${options.scope}:${apiKey}:${claimedDevice(req.body)}`;

    const { allowed, remaining } = await check(key, limit, windowSeconds);
    res.setHeader("X-RateLimit-Limit", String(limit));
    res.setHeader("X-RateLimit-Remaining", String(remaining));
    if (!allowed) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
    next();
  };
}
