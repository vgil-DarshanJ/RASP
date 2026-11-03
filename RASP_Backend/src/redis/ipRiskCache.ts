import { redis } from "./client";
import { GeoCache, parseCachedGeo } from "../ipRisk/ipRisk";

const key = (ip: string) => `ip_risk:geo:${ip}`;

/**
 * Per-IP cache of geo lookups for GET /v1/ip-risk. Best-effort, like the
 * dashboard cache: a Redis error is a cache miss (or "not cached"), never a
 * failed request. Only the geo data is cached, not the blocked-country
 * decision, so a changed IP_RISK_BLOCKED_COUNTRIES applies immediately.
 */
export const redisGeoCache: GeoCache = {
  async get(ip) {
    try {
      const raw = await redis.get(key(ip));
      return raw ? parseCachedGeo(raw) : null;
    } catch (err) {
      console.error("[ipRiskCache] read failed, treating as a miss:", (err as Error).message);
      return null;
    }
  },
  async set(ip, info, ttlSeconds) {
    try {
      await redis.set(key(ip), JSON.stringify(info), "EX", ttlSeconds);
    } catch (err) {
      console.error("[ipRiskCache] write failed, result not cached:", (err as Error).message);
    }
  },
};
