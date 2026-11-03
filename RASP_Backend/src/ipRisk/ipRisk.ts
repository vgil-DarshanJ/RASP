import net from "node:net";
import type { Request } from "express";

/**
 * GET /v1/ip-risk — country, coarse region/city, risk flags and a risk
 * level for the caller's IP, for the SDK's `high_risk_ip` detector (the SDK
 * no longer calls a third-party geo service itself). This file is the pure
 * part: configuration, IP handling, the trusted-header rule, the HTTP
 * lookup, the risk rules and the response shape. The route and the Redis
 * cache live in routes.ts and redis/ipRiskCache.ts.
 *
 * The response never contains the IP itself, and never coordinates.
 */

export type GeoSourceName = "lookup" | "header" | "dev_override" | "none";
export type IpRiskReason = "private_address" | "no_geo_source" | "lookup_failed";
export type RiskLevel = "low" | "medium" | "high";
/** Rule names that can appear in `reasons`, in this order. */
export const RISK_RULES = ["blocked_country", "country_not_allowed", "tor", "proxy", "hosting", "country_changed"] as const;
export type RiskRule = (typeof RISK_RULES)[number];

/** What is known about one IP. Only `lookup` results are cached (per IP). */
export interface GeoInfo {
  /** ISO 3166-1 alpha-2, upper case. */
  country: string | null;
  /** Coarse region / city names from the provider (lookup source only). */
  region: string | null;
  city: string | null;
  proxy: boolean | null;
  hosting: boolean | null;
  tor: boolean | null;
  source: GeoSourceName;
}

export interface IpRiskResponse {
  country: string | null;
  region: string | null;
  city: string | null;
  is_proxy: boolean | null;
  is_hosting: boolean | null;
  is_tor: boolean | null;
  risk_level: RiskLevel | null;
  reasons: RiskRule[];
  flags: {
    /** `null` when the country is unknown. */
    blocked_country: boolean | null;
    proxy: boolean | null;
    hosting: boolean | null;
    tor: boolean | null;
    private_address: boolean;
    /** `null` when the country is unknown; false when the app has no allow-list. */
    country_not_allowed: boolean | null;
    /** `null` when the country or the device's registration country is unknown. */
    country_changed: boolean | null;
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

/** The per-request policy: which countries are blocked / allowed, and the device's first country. */
export interface IpRiskPolicy {
  blockedCountries: ReadonlySet<string>;
  /** Empty = no allow-list. */
  allowedCountries?: ReadonlySet<string>;
  /** Country of the device's first registration (`X-Device-Key-Id`), if known. */
  registrationCountry?: string | null;
}

export const DEFAULT_BLOCKED_COUNTRIES = "KP,IR,SY";

/** Read per request, so a changed blocked list applies without a restart in tests. */
export function loadIpRiskConfig(env: NodeJS.ProcessEnv = process.env): IpRiskConfig {
  const blockedRaw = env.IP_RISK_BLOCKED_COUNTRIES?.trim() ? env.IP_RISK_BLOCKED_COUNTRIES : DEFAULT_BLOCKED_COUNTRIES;
  const blockedCountries = countrySet(blockedRaw.split(","));

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

/** Valid ISO alpha-2 codes from a list, upper case; junk dropped. */
export function countrySet(values: Iterable<unknown>): Set<string> {
  const set = new Set<string>();
  for (const v of values) {
    const code = toCountryCode(v);
    if (code) set.add(code);
  }
  return set;
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

/** A geo record with only a country (header / dev override sources). */
export function countryOnly(country: string, source: GeoSourceName): GeoInfo {
  return { country, region: null, city: null, proxy: null, hosting: null, tor: null, source };
}

const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
/** A coarse place name: a trimmed non-empty string, at most 100 characters; else null. */
const placeName = (v: unknown): string | null =>
  typeof v === "string" && v.trim() !== "" ? v.trim().slice(0, 100) : null;

/**
 * Reads a provider's JSON: country from `country_code`, `countryCode` or
 * `country` (the first that is a two-letter code); coarse `region`
 * (`region` / `regionName`) and `city`; `proxy` / `hosting` / `tor` when they
 * are booleans (top level, or under `security`). Never coordinates.
 * `null` without a usable country.
 */
export function parseLookupBody(data: unknown): GeoInfo | null {
  if (typeof data !== "object" || data === null) return null;
  const d = data as Record<string, unknown>;
  const security = (typeof d.security === "object" && d.security !== null ? d.security : {}) as Record<string, unknown>;
  const country = [d.country_code, d.countryCode, d.country].map(toCountryCode).find((c) => c !== null) ?? null;
  if (!country) return null;
  return {
    country,
    region: placeName(d.region) ?? placeName(d.regionName),
    city: placeName(d.city),
    proxy: bool(d.proxy) ?? bool(security.proxy),
    hosting: bool(d.hosting) ?? bool(security.hosting),
    tor: bool(d.tor) ?? bool(d.is_tor) ?? bool(security.tor),
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

/** A cached entry, validated; `null` for anything malformed. Entries cached before region/city/tor existed read those as null. */
export function parseCachedGeo(raw: string): GeoInfo | null {
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    const country = value.country === null ? null : toCountryCode(value.country);
    if (value.source !== "lookup" || country === null) return null;
    return {
      country,
      region: placeName(value.region),
      city: placeName(value.city),
      proxy: bool(value.proxy),
      hosting: bool(value.hosting),
      tor: bool(value.tor),
      source: "lookup",
    };
  } catch {
    return null;
  }
}

/**
 * The risk rules. "high": blocked country, country not on the app's
 * allow-list, Tor or proxy. "medium" (soft): hosting/datacenter IP, or the
 * country differs from the device's first-registration country. "low":
 * country known and nothing fired. `null` when the country is unknown.
 */
export function assessRisk(
  geo: GeoInfo | null,
  policy: IpRiskPolicy,
): { level: RiskLevel | null; reasons: RiskRule[]; blocked: boolean | null; notAllowed: boolean | null; changed: boolean | null } {
  const country = geo?.country ?? null;
  if (country === null) return { level: null, reasons: [], blocked: null, notAllowed: null, changed: null };
  const allowed = policy.allowedCountries ?? new Set<string>();
  const registration = toCountryCode(policy.registrationCountry ?? null);

  const blocked = policy.blockedCountries.has(country);
  const notAllowed = allowed.size > 0 && !allowed.has(country);
  const changed = registration === null ? null : registration !== country;

  const fired: Record<RiskRule, boolean> = {
    blocked_country: blocked,
    country_not_allowed: notAllowed,
    tor: geo?.tor === true,
    proxy: geo?.proxy === true,
    hosting: geo?.hosting === true,
    country_changed: changed === true,
  };
  const reasons = RISK_RULES.filter((rule) => fired[rule]);
  const high = fired.blocked_country || fired.country_not_allowed || fired.tor || fired.proxy;
  const medium = fired.hosting || fired.country_changed;
  return { level: high ? "high" : medium ? "medium" : "low", reasons, blocked, notAllowed, changed };
}

export function buildIpRiskResponse(
  geo: GeoInfo | null,
  opts: { privateAddress: boolean; reason: IpRiskReason | null; cached: boolean },
  policy: IpRiskPolicy,
): IpRiskResponse {
  const country = geo?.country ?? null;
  const risk = assessRisk(geo, policy);
  return {
    country,
    region: geo?.region ?? null,
    city: geo?.city ?? null,
    is_proxy: geo?.proxy ?? null,
    is_hosting: geo?.hosting ?? null,
    is_tor: geo?.tor ?? null,
    risk_level: risk.level,
    reasons: risk.reasons,
    flags: {
      blocked_country: risk.blocked,
      proxy: geo?.proxy ?? null,
      hosting: geo?.hosting ?? null,
      tor: geo?.tor ?? null,
      private_address: opts.privateAddress,
      country_not_allowed: risk.notAllowed,
      country_changed: risk.changed,
    },
    source: geo?.source ?? "none",
    reason: opts.reason,
    cached: opts.cached,
  };
}
