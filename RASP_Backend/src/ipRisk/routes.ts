import { NextFunction, Request, RequestHandler, Response, Router } from "express";
import { requireApiKey } from "../middleware/apiKey";
import type { RateCheck } from "../redis/deviceRateLimit";
import { checkRateLimit } from "../redis/rateLimit";
import { redisGeoCache } from "../redis/ipRiskCache";
import {
  GeoCache,
  GeoInfo,
  GeoLookup,
  IpRiskConfig,
  IpRiskReason,
  IpRiskResponse,
  buildIpRiskResponse,
  countryFromTrustedHeader,
  httpGeoLookup,
  intFromEnv,
  isPrivateAddress,
  loadIpRiskConfig,
  normalizeIp,
} from "./ipRisk";

export interface IpRiskDeps {
  /** Default: process.env, read on every request. */
  env?: NodeJS.ProcessEnv;
  /** Default: the Redis fixed-window counter. */
  rateCheck?: RateCheck;
  /** Default: requireApiKey (X-Api-Key + HMAC X-Signature over "<X-Timestamp>." + empty body). */
  authenticate?: RequestHandler;
  /** Default: httpGeoLookup(IP_RISK_LOOKUP_URL) when IP_RISK_GEO_SOURCE=lookup. */
  geoLookup?: GeoLookup;
  /** Default: Redis (best-effort). */
  cache?: GeoCache;
}

/**
 * Per client IP and per API key (same window). GET has no body, so there is
 * no per-device bucket here. Runs before authentication, like the ingestion
 * limits. A 429 names the limit that was hit.
 */
export function ipRiskRateLimiter(check: RateCheck, env: NodeJS.ProcessEnv): RequestHandler {
  return async function rateLimitIpRisk(req: Request, res: Response, next: NextFunction) {
    const windowSeconds = intFromEnv(env.IP_RISK_RATE_LIMIT_WINDOW_SECONDS, 60, 1);
    const apiKey = req.header("X-Api-Key");
    const buckets: Array<{ limit: "ip" | "api_key"; key: string; max: number }> = [
      { limit: "ip", key: `ip_risk:ip:${req.ip ?? "unknown"}`, max: intFromEnv(env.IP_RISK_RATE_LIMIT_PER_IP, 60, 1) },
    ];
    if (apiKey) {
      buckets.push({ limit: "api_key", key: `ip_risk:key:${apiKey}`, max: intFromEnv(env.IP_RISK_RATE_LIMIT_PER_API_KEY, 6000, 1) });
    }
    for (const bucket of buckets) {
      const { allowed } = await check(bucket.key, bucket.max, windowSeconds);
      if (!allowed) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED", limit: bucket.limit });
    }
    next();
  };
}

async function assess(req: Request, config: IpRiskConfig, deps: IpRiskDeps): Promise<IpRiskResponse> {
  const respond = (geo: GeoInfo | null, privateAddress: boolean, reason: IpRiskReason | null, cached = false) =>
    buildIpRiskResponse(geo, { privateAddress, reason, cached }, config.blockedCountries);

  const ip = normalizeIp(req.ip);
  if (ip === null) return respond(null, false, "lookup_failed");

  if (isPrivateAddress(ip)) {
    // A phone on the developer's LAN reaches the backend from a private
    // address; IP_RISK_DEV_PRIVATE_IP_COUNTRY (never in production) lets
    // that setup exercise the rest of the flow.
    if (config.devPrivateIpCountry) {
      return respond({ country: config.devPrivateIpCountry, proxy: null, hosting: null, source: "dev_override" }, true, null);
    }
    return respond(null, true, "private_address");
  }

  if (config.geoSource === "header") {
    const country = countryFromTrustedHeader(req, config.countryHeader);
    return country
      ? respond({ country, proxy: null, hosting: null, source: "header" }, false, null)
      : respond(null, false, "no_geo_source");
  }

  if (config.geoSource === "lookup") {
    const cache = deps.cache ?? redisGeoCache;
    const hit = config.cacheSeconds > 0 ? await cache.get(ip) : null;
    if (hit) return respond(hit, false, null, true);

    const lookup = deps.geoLookup ?? (config.lookupUrl ? httpGeoLookup(config.lookupUrl) : null);
    if (!lookup) return respond(null, false, "no_geo_source");
    const info = await lookup.lookup(ip).catch(() => null);
    if (!info) return respond(null, false, "lookup_failed"); // failures are not cached
    if (config.cacheSeconds > 0) await cache.set(ip, info, config.cacheSeconds);
    return respond(info, false, null);
  }

  return respond(null, false, "no_geo_source");
}

/**
 * GET /v1/ip-risk — the caller's country (from its IP, honoring TRUST_PROXY
 * through req.ip) and risk flags, for the SDK's `high_risk_ip` detector:
 *
 *   { "country": "IN" | null,
 *     "flags": { "blocked_country": bool|null, "proxy": bool|null,
 *                "hosting": bool|null, "private_address": bool },
 *     "source": "lookup" | "header" | "dev_override" | "none",
 *     "reason": null | "private_address" | "no_geo_source" | "lookup_failed",
 *     "cached": bool }
 *
 * Order: rate limit (IP, API key) → requireApiKey (HMAC over "<ts>." + the
 * empty body) → lookup. `country: null` always comes with a `reason`; the
 * SDK reports that as "cannot decide", never as clean. Config: see the
 * IP_RISK_* section of .env.example.
 */
export function createIpRiskRouter(deps: IpRiskDeps = {}): Router {
  const env = deps.env ?? process.env;
  const router = Router();
  router.get(
    "/",
    ipRiskRateLimiter(deps.rateCheck ?? checkRateLimit, env),
    deps.authenticate ?? (requireApiKey as RequestHandler),
    async (req: Request, res: Response) => {
      const body = await assess(req, loadIpRiskConfig(env), deps);
      res.setHeader("Cache-Control", "no-store");
      res.json(body);
    },
  );
  return router;
}

export const ipRiskRouter = createIpRiskRouter();
