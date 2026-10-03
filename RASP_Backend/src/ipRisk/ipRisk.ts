import net from "node:net";
import type { Request } from "express";

/**
 * GET /v1/ip-risk — country and risk flags for the caller's IP, for the SDK's
 * `high_risk_ip` detector (the SDK no longer calls a third-party geo service
 * itself). This file is the pure part: configuration, IP handling, the
 * trusted-header rule, the HTTP lookup and the response shape. The route and
 * the Redis cache live in routes.ts and redis/ipRiskCache.ts.
 *
 * The response never contains the IP itself.
 */

export type GeoSourceName = "lookup" | "header" | "dev_override" | "none";
export type IpRiskReason = "private_address" | "no_geo_source" | "lookup_failed";

/** What is known about one IP. Only `lookup` results are cached (per IP). */
export interface GeoInfo {
  /** ISO 3166-1 alpha-2, upper case. */
  country: string | null;
  proxy: boolean | null;
  hosting: boolean | null;
  source: GeoSourceName;
}

export interface IpRiskResponse {
  country: string | null;
  flags: {
    /** `null` when the country is unknown. */
    blocked_country: boolean | null;
    proxy: boolean | null;
    hosting: boolean | null;
    private_address: boolean;
  };
  source: GeoSourceName;
  reason: IpRiskReason | null;
  cached: boolean;
}

export interface GeoLookup {
  /** The geo data for [ip]; `null` when the lookup failed (never cached). */
  lookup(ip: string): Promise<GeoInfo | null>;
}

export interface GeoCache {
  get(ip: string): Promise<GeoInfo | null>;
  set(ip: string, info: GeoInfo, ttlSeconds: number): Promise<void>;
}

export interface IpRiskConfig {
  blockedCountries: ReadonlySet<string>;
  geoSource: "lookup" | "header" | "none";
  /** URL template with `{ip}`; `null` when unset or invalid. */
  lookupUrl: string | null;
  /** Lower-case header name. */
  countryHeader: string;
  /** 0 = no caching. */
  cacheSeconds: number;
  /** Development-only country for private addresses; always `null` in production. */
  devPrivateIpCountry: string | null;
}

export const DEFAULT_BLOCKED_COUNTRIES = "KP,IR,SY";

/** Read per request, so a changed blocked list applies without a restart in tests. */
export function loadIpRiskConfig(env: NodeJS.ProcessEnv = process.env): IpRiskConfig {
  const blockedRaw = env.IP_RISK_BLOCKED_COUNTRIES?.trim() ? env.IP_RISK_BLOCKED_COUNTRIES : DEFAULT_BLOCKED_COUNTRIES;
  const blockedCountries = new Set(
    blockedRaw.split(",").map(toCountryCode).filter((c): c is string => c !== null),
  );

  const sourceRaw = (env.IP_RISK_GEO_SOURCE ?? "").trim().toLowerCase();
  const geoSource = sourceRaw === "lookup" || sourceRaw === "header" ? sourceRaw : "none";

  const urlRaw = env.IP_RISK_LOOKUP_URL?.trim() ?? "";
  const lookupUrl = /^https?:\/\//i.test(urlRaw) && urlRaw.includes("{ip}") ? urlRaw : null;

  const devCountry = env.NODE_ENV === "production" ? null : toCountryCode(env.IP_RISK_DEV_PRIVATE_IP_COUNTRY);

  return {
    blockedCountries,
    geoSource,
    lookupUrl,
    countryHeader: (env.IP_RISK_COUNTRY_HEADER?.trim() || "cf-ipcountry").toLowerCase(),
    cacheSeconds: intFromEnv(env.IP_RISK_CACHE_SECONDS, 3600, 0),
    devPrivateIpCountry: devCountry,
  };
}

export function intFromEnv(value: string | undefined, fallback: number, min: number): number {
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number(value);
  return Number.isInteger(n) && n >= min ? n : fallback;
}

/**
 * Two upper-case letters, or `null`. "XX" (Cloudflare's "unknown") and
 * non-letter codes such as "T1" (Tor) are not countries.
 */
export function toCountryCode(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const code = value.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) && code !== "XX" ? code : null;
}

/** `::ffff:1.2.3.4` → `1.2.3.4`; zone ids dropped; `null` if not an IP address. */
export function normalizeIp(ip: string | undefined | null): string | null {
  if (!ip) return null;
  let value = ip.trim();
  const zone = value.indexOf("%");
  if (zone >= 0) value = value.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1];
  return net.isIP(value) ? value.toLowerCase() : null;
}

/**
 * Loopback, private, link-local, CGNAT, unspecified and unique-local
 * addresses — none of them can be placed in a country.
 * IPv4: 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16.
 * IPv6: ::, ::1, fc00::/7, fe80::/10.
 */
export function isPrivateAddress(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::" || lower === "::1") return true;
    const first = lower.startsWith("::") ? 0 : parseInt(lower.split(":")[0], 16);
    return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
  }
  return false;
}

/**
 * `true` only when the direct peer of this connection is a proxy Express is
 * configured to trust (TRUST_PROXY). Only then can a country header be
 * believed — without a trusted proxy in front, any client could send one.
 */
export function peerIsTrustedProxy(req: Request): boolean {
  const trust = req.app?.get("trust proxy fn") as ((addr: string, i: number) => boolean) | undefined;
  const peer = req.socket?.remoteAddress;
  if (typeof trust !== "function" || !peer) return false;
  try {
    return trust(peer, 0) === true;
  } catch {
    return false;
  }
}

/** The country header set by the trusted proxy/CDN, or `null`. */
export function countryFromTrustedHeader(req: Request, headerName: string): string | null {
  if (!peerIsTrustedProxy(req)) return null;
  return toCountryCode(req.header(headerName));
}

/**
 * Reads a provider's JSON: country from `country_code`, `countryCode` or
 * `country` (the first that is a two-letter code), `proxy` / `hosting` when
 * they are booleans. `null` without a usable country.
 */
export function parseLookupBody(data: unknown): GeoInfo | null {
  if (typeof data !== "object" || data === null) return null;
  const d = data as Record<string, unknown>;
  const country = [d.country_code, d.countryCode, d.country].map(toCountryCode).find((c) => c !== null) ?? null;
  if (!country) return null;
  return {
    country,
    proxy: typeof d.proxy === "boolean" ? d.proxy : null,
    hosting: typeof d.hosting === "boolean" ? d.hosting : null,
    source: "lookup",
  };
}

/**
 * Server-side HTTP lookup: `{ip}` in [urlTemplate] is replaced by the
 * (already validated) IP. Any failure — network, timeout, non-2xx, no usable
 * country — returns `null`.
 */
export function httpGeoLookup(
  urlTemplate: string,
  options: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): GeoLookup {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 3000;
  return {
    async lookup(ip) {
      try {
        const response = await fetchImpl(urlTemplate.split("{ip}").join(ip), {
          headers: { accept: "application/json" },
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) return null;
        return parseLookupBody(await response.json());
      } catch {
        return null;
      }
    },
  };
}

/** A cached entry, validated; `null` for anything malformed. */
export function parseCachedGeo(raw: string): GeoInfo | null {
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    const country = value.country === null ? null : toCountryCode(value.country);
    const boolOrNull = (v: unknown) => (typeof v === "boolean" ? v : null);
    if (value.source !== "lookup" || country === null) return null;
    return { country, proxy: boolOrNull(value.proxy), hosting: boolOrNull(value.hosting), source: "lookup" };
  } catch {
    return null;
  }
}

export function buildIpRiskResponse(
  geo: GeoInfo | null,
  opts: { privateAddress: boolean; reason: IpRiskReason | null; cached: boolean },
  blockedCountries: ReadonlySet<string>,
): IpRiskResponse {
  const country = geo?.country ?? null;
  return {
    country,
    flags: {
      blocked_country: country === null ? null : blockedCountries.has(country),
      proxy: geo?.proxy ?? null,
      hosting: geo?.hosting ?? null,
      private_address: opts.privateAddress,
    },
    source: geo?.source ?? "none",
    reason: opts.reason,
    cached: opts.cached,
  };
}
