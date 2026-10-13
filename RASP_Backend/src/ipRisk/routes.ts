import { NextFunction, Request, RequestHandler, Response, Router } from "express";
import { prisma } from "../db/prisma";
import { ApiKeyedRequest, requireApiKey } from "../middleware/apiKey";
import type { RateCheck } from "../redis/deviceRateLimit";
import { checkRateLimit } from "../redis/rateLimit";
import { redisGeoCache } from "../redis/ipRiskCache";
import { activeRemoteCountries } from "../remoteConfig/routes";
import {
  GeoCache,
  GeoInfo,
  GeoLookup,
  IpRiskConfig,
  IpRiskPolicy,
  IpRiskReason,
  IpRiskResponse,
  buildIpRiskResponse,
  countryFromTrustedHeader,
  countryOnly,
  countrySet,
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
  /** The application's own country lists. Default: Prisma (`ipBlockedCountries` / `ipAllowedCountries`). */
  applicationPolicy?: (applicationId: string) => Promise<{ blocked: string[]; allowed: string[] } | null>;
  /** First-registration country of a device key within the application. Default: Prisma. */
  registrationCountry?: (applicationId: string, deviceKeyId: string) => Promise<string | null>;
}

/** The app's lists; a list set by its active remote config (Task 10.0) takes the place of the app's own. */
export const prismaApplicationPolicy = async (applicationId: string) => {
  const [app, remote] = await Promise.all([
    prisma.application.findUnique({
      where: { id: applicationId },
      select: { ipBlockedCountries: true, ipAllowedCountries: true },
    }),
    activeRemoteCountries(applicationId),
  ]);
  return app ? { blocked: remote.blocked ?? app.ipBlockedCountries, allowed: remote.allowed ?? app.ipAllowedCountries } : null;
};

export const prismaRegistrationCountry = async (applicationId: string, deviceKeyId: string) =>
  prisma.deviceRegistration.findUnique({
    where: { deviceKeyId },
    select: { applicationId: true, registrationCountry: true },
  }).then((row) => (row && row.applicationId === applicationId ? row.registrationCountry : null));

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

export interface ResolvedGeo {
  geo: GeoInfo | null;
  privateAddress: boolean;
  reason: IpRiskReason | null;
  cached: boolean;
}

/**
 * Where the request's IP is: the trusted-proxy country header or the HTTP
 * lookup (cached per IP), per IP_RISK_GEO_SOURCE. Private addresses are
 * never looked up. Also used by device registration (registration country).
 */
export async function resolveGeo(
  req: Request,
  config: IpRiskConfig,
  deps: Pick<IpRiskDeps, "geoLookup" | "cache"> = {},
): Promise<ResolvedGeo> {
  const result = (geo: GeoInfo | null, privateAddress: boolean, reason: IpRiskReason | null, cached = false) =>
    ({ geo, privateAddress, reason, cached });

  const ip = normalizeIp(req.ip);
  if (ip === null) return result(null, false, "lookup_failed");

  if (isPrivateAddress(ip)) {
    // A phone on the developer's LAN reaches the backend from a private
    // address; IP_RISK_DEV_PRIVATE_IP_COUNTRY (never in production) lets
    // that setup exercise the rest of the flow.
    if (config.devPrivateIpCountry) {
      return result(countryOnly(config.devPrivateIpCountry, "dev_override"), true, null);
    }
    return result(null, true, "private_address");
  }

  if (config.geoSource === "header") {
    const country = countryFromTrustedHeader(req, config.countryHeader);
    return country ? result(countryOnly(country, "header"), false, null) : result(null, false, "no_geo_source");
  }

  if (config.geoSource === "lookup") {
    const cache = deps.cache ?? redisGeoCache;
    const hit = config.cacheSeconds > 0 ? await cache.get(ip) : null;
    if (hit) return result(hit, false, null, true);

    const lookup = deps.geoLookup ?? (config.lookupUrl ? httpGeoLookup(config.lookupUrl) : null);
    if (!lookup) return result(null, false, "no_geo_source");
    const info = await lookup.lookup(ip).catch(() => null);
    if (!info) return result(null, false, "lookup_failed"); // failures are not cached
    if (config.cacheSeconds > 0) await cache.set(ip, info, config.cacheSeconds);
    return result(info, false, null);
  }

  return result(null, false, "no_geo_source");
}

/** The application's lists (its own blocked list, else the env default) and the device's registration country. */
async function policyFor(req: ApiKeyedRequest, config: IpRiskConfig, deps: IpRiskDeps): Promise<IpRiskPolicy> {
  const applicationId = req.applicationId;
  if (!applicationId) return { blockedCountries: config.blockedCountries };
  const lists = await (deps.applicationPolicy ?? prismaApplicationPolicy)(applicationId).catch(() => null);
  const ownBlocked = countrySet(lists?.blocked ?? []);
  const deviceKeyId = req.header("X-Device-Key-Id")?.trim().slice(0, 200);
  const registrationCountry = deviceKeyId
    ? await (deps.registrationCountry ?? prismaRegistrationCountry)(applicationId, deviceKeyId).catch(() => null)
    : null;
  return {
    blockedCountries: ownBlocked.size > 0 ? ownBlocked : config.blockedCountries,
    allowedCountries: countrySet(lists?.allowed ?? []),
    registrationCountry,
  };
}

/**
 * GET /v1/ip-risk — the caller's country (from its IP, honoring TRUST_PROXY
 * through req.ip), coarse region/city, risk flags, a risk level and the
 * rules behind it, for the SDK's `high_risk_ip` detector:
 *
 *   { "country": "IN"|null, "region": str|null, "city": str|null,
 *     "is_proxy": bool|null, "is_hosting": bool|null, "is_tor": bool|null,
 *     "risk_level": "low"|"medium"|"high"|null,
 *     "reasons": ["blocked_country"|"country_not_allowed"|"tor"|"proxy"|"hosting"|"country_changed"],
 *     "flags": { "blocked_country", "proxy", "hosting", "tor", "private_address",
 *                "country_not_allowed", "country_changed" },
 *     "source": "lookup"|"header"|"dev_override"|"none",
 *     "reason": null|"private_address"|"no_geo_source"|"lookup_failed",
 *     "cached": bool }
 *
 * Order: rate limit (IP, API key) → requireApiKey (HMAC over "<ts>." + the
 * empty body) → lookup. `X-Device-Key-Id` (optional) selects the device
 * whose first-registration country `country_changed` compares against.
 * `country: null` always comes with a `reason` and `risk_level: null`; the
 * SDK reports that as "cannot decide", never as clean. Config: see the
 * IP_RISK_* section of .env.example; per-application lists via PATCH /v1/apps/:id.
 */
export function createIpRiskRouter(deps: IpRiskDeps = {}): Router {
  const env = deps.env ?? process.env;
  const router = Router();
  router.get(
    "/",
    ipRiskRateLimiter(deps.rateCheck ?? checkRateLimit, env),
    deps.authenticate ?? (requireApiKey as RequestHandler),
    async (req: ApiKeyedRequest, res: Response) => {
      const config = loadIpRiskConfig(env);
      const [resolved, policy] = await Promise.all([resolveGeo(req, config, deps), policyFor(req, config, deps)]);
      const body: IpRiskResponse = buildIpRiskResponse(
        resolved.geo,
        { privateAddress: resolved.privateAddress, reason: resolved.reason, cached: resolved.cached },
        policy,
      );
      res.setHeader("Cache-Control", "no-store");
      res.json(body);
    },
  );
  return router;
}

export const ipRiskRouter = createIpRiskRouter();
