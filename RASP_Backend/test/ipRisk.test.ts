// GET /v1/ip-risk (src/ipRisk): country + risk flags for the caller's IP.
// Real: the router and its rate limiter, config parsing, IP normalization and
// private ranges, the trusted-header rule, the response builder, the HTTP
// lookup (against a local HTTP server), applyTrustProxy and jsonBodyParser
// (src/middleware/requestSetup.ts), and — in "real requireApiKey" — the HMAC
// middleware itself, over real HTTP on an ephemeral port.
// Doubles: an in-memory geo cache instead of Redis, a fake geo lookup where
// the provider is not the subject, an in-memory rate counter instead of
// Redis, a pass-through auth middleware where authentication is not the
// subject, and for the requireApiKey tests Prisma's
// apiCredential.findUnique and the Redis client's set() replaced in-process
// (no Postgres or Redis is needed or contacted).
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import express, { Request, RequestHandler } from "express";
import { applyTrustProxy, jsonBodyParser } from "../src/middleware/requestSetup";
import { createIpRiskRouter, IpRiskDeps } from "../src/ipRisk/routes";
import {
  countryFromTrustedHeader,
  GeoCache,
  GeoInfo,
  GeoLookup,
  httpGeoLookup,
  isPrivateAddress,
  loadIpRiskConfig,
  normalizeIp,
  parseLookupBody,
} from "../src/ipRisk/ipRisk";
import type { RateCheck } from "../src/redis/deviceRateLimit";
import { computeSignature } from "../src/crypto/hmac";
import { encryptSecret } from "../src/crypto/secretBox";
import { prisma } from "../src/db/prisma";
import { redis } from "../src/redis/client";

class MemoryGeoCache implements GeoCache {
  entries = new Map<string, GeoInfo>();
  async get(ip: string) {
    return this.entries.get(ip) ?? null;
  }
  async set(ip: string, info: GeoInfo) {
    this.entries.set(ip, info);
  }
}

function fakeLookup(countries: Record<string, string>, extra: Partial<GeoInfo> = {}) {
  const calls: string[] = [];
  const lookup: GeoLookup = {
    async lookup(ip) {
      calls.push(ip);
      const country = countries[ip];
      return country
        ? { country, region: null, city: null, proxy: null, hosting: null, tor: null, source: "lookup", ...extra }
        : null;
    },
  };
  return { lookup, calls };
}

function memoryRate(): RateCheck {
  const counts = new Map<string, number>();
  return async (key, limit) => {
    const n = (counts.get(key) ?? 0) + 1;
    counts.set(key, n);
    return { allowed: n <= limit, remaining: Math.max(0, limit - n) };
  };
}

const passThrough: RequestHandler = (_req, _res, next) => next();

type Body = Record<string, any>;

/** The router mounted the way createApp mounts it, on 127.0.0.1:<random>. */
async function serve(env: NodeJS.ProcessEnv, deps: IpRiskDeps = {}, options: { realAuth?: boolean } = {}) {
  const app = express();
  applyTrustProxy(app, env);
  app.use(jsonBodyParser());
  app.use(
    "/v1/ip-risk",
    createIpRiskRouter({
      env,
      rateCheck: memoryRate(),
      cache: new MemoryGeoCache(),
      ...(options.realAuth ? {} : { authenticate: passThrough }),
      ...deps,
    }),
  );
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const { port } = server.address() as AddressInfo;
  return {
    async get(headers: Record<string, string> = {}) {
      const response = await fetch(`http://127.0.0.1:${port}/v1/ip-risk`, { headers });
      return { status: response.status, body: (await response.json()) as Body };
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** The full response shape for a country nobody could place (Task 6.0 contract). */
function unknownCountry(privateAddress: boolean, reason: string) {
  return {
    country: null, region: null, city: null,
    is_proxy: null, is_hosting: null, is_tor: null,
    risk_level: null, reasons: [],
    flags: {
      blocked_country: null, proxy: null, hosting: null, tor: null, private_address: privateAddress,
      country_not_allowed: null, country_changed: null,
    },
    source: "none", reason, cached: false,
  };
}

const PRIVATE_LOOPBACK = unknownCountry(true, "private_address");

describe("client IP and TRUST_PROXY", () => {
  test("TRUST_PROXY unset: X-Forwarded-For is ignored; the loopback peer is a private address", async () => {
    const geo = fakeLookup({ "203.0.113.7": "IN" });
    const s = await serve({ IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup });
    try {
      const r = await s.get({ "X-Forwarded-For": "203.0.113.7" });
      assert.equal(r.status, 200);
      assert.deepEqual(r.body, PRIVATE_LOOPBACK);
      assert.deepEqual(geo.calls, [], "a private address is never looked up");
    } finally {
      await s.close();
    }
  });

  test("TRUST_PROXY=1: the X-Forwarded-For client IP is used, and the response has no IP in it", async () => {
    const geo = fakeLookup({ "203.0.113.7": "IN" });
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup });
    try {
      const r = await s.get({ "X-Forwarded-For": "198.51.100.1, 203.0.113.7" });
      assert.deepEqual(geo.calls, ["203.0.113.7"], "the hop the trusted proxy appended");
      assert.deepEqual(r.body, {
        country: "IN", region: null, city: null,
        is_proxy: null, is_hosting: null, is_tor: null,
        risk_level: "low", reasons: [],
        flags: {
          blocked_country: false, proxy: null, hosting: null, tor: null, private_address: false,
          country_not_allowed: false, country_changed: null,
        },
        source: "lookup", reason: null, cached: false,
      });
      assert.equal(JSON.stringify(r.body).includes("203.0.113"), false);
    } finally {
      await s.close();
    }
  });

  test("IPv4-mapped IPv6 addresses are normalized before lookup", async () => {
    assert.equal(normalizeIp("::ffff:203.0.113.9"), "203.0.113.9");
    assert.equal(normalizeIp("::FFFF:127.0.0.1"), "127.0.0.1");
    assert.equal(normalizeIp("fe80::1%eth0"), "fe80::1");
    assert.equal(normalizeIp("not-an-ip"), null);
    assert.equal(normalizeIp(undefined), null);

    const geo = fakeLookup({ "203.0.113.9": "DE" });
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup });
    try {
      const r = await s.get({ "X-Forwarded-For": "::ffff:203.0.113.9" });
      assert.deepEqual(geo.calls, ["203.0.113.9"]);
      assert.equal(r.body.country, "DE");
    } finally {
      await s.close();
    }
  });

  test("private, loopback, link-local, CGNAT and unique-local ranges", () => {
    for (const ip of [
      "0.0.0.0", "10.0.0.1", "10.255.255.255", "100.64.0.1", "100.127.255.255", "127.0.0.1",
      "169.254.10.1", "172.16.0.1", "172.31.255.255", "192.168.1.20",
      "::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1",
    ]) {
      assert.equal(isPrivateAddress(ip), true, ip);
    }
    for (const ip of [
      "8.8.8.8", "100.63.255.255", "100.128.0.1", "172.15.255.255", "172.32.0.1", "192.169.0.1",
      "203.0.113.7", "2001:db8::1", "2a00:1450::1", "fec0::1",
    ]) {
      assert.equal(isPrivateAddress(ip), false, ip);
    }
  });
});

describe("blocked-country decision", () => {
  test("a blocked country sets blocked_country; an allowed one does not", async () => {
    const geo = fakeLookup({ "203.0.113.7": "KP", "203.0.113.8": "IN" });
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup });
    try {
      const blocked = await s.get({ "X-Forwarded-For": "203.0.113.7" });
      assert.equal(blocked.body.country, "KP");
      assert.equal(blocked.body.flags.blocked_country, true, "KP is in the default list");
      const allowed = await s.get({ "X-Forwarded-For": "203.0.113.8" });
      assert.equal(allowed.body.flags.blocked_country, false);
    } finally {
      await s.close();
    }
  });

  test("the blocked list: default KP,IR,SY; comma-separated, any case; junk ignored", () => {
    assert.deepEqual([...loadIpRiskConfig({}).blockedCountries].sort(), ["IR", "KP", "SY"]);
    assert.deepEqual([...loadIpRiskConfig({ IP_RISK_BLOCKED_COUNTRIES: "" }).blockedCountries].sort(), ["IR", "KP", "SY"]);
    assert.deepEqual([...loadIpRiskConfig({ IP_RISK_BLOCKED_COUNTRIES: " in, ru ,xx,T1,USA" }).blockedCountries].sort(), ["IN", "RU"]);
  });

  test("provider fields: country_code / countryCode / country; proxy and hosting only as booleans", () => {
    assert.deepEqual(parseLookupBody({ country_code: "IN", proxy: false }),
      { country: "IN", region: null, city: null, proxy: false, hosting: null, tor: null, source: "lookup" });
    assert.deepEqual(parseLookupBody({ countryCode: "de", country: "Germany", proxy: true, hosting: true }),
      { country: "DE", region: null, city: null, proxy: true, hosting: true, tor: null, source: "lookup" });
    assert.equal(parseLookupBody({ country: "India" }), null, "not a two-letter code");
    assert.equal(parseLookupBody({ error: true, reason: "RateLimited" }), null);
  });
});

describe("lookup and cache", () => {
  test("a failed lookup gives reason lookup_failed and is not cached", async () => {
    const geo = fakeLookup({});
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup });
    try {
      for (let i = 0; i < 2; i++) {
        const r = await s.get({ "X-Forwarded-For": "203.0.113.7" });
        assert.deepEqual(r.body, unknownCountry(false, "lookup_failed"));
      }
      assert.equal(geo.calls.length, 2, "looked up again: the failure was not cached");
    } finally {
      await s.close();
    }
  });

  test("a second call for the same IP is served from the cache", async () => {
    const geo = fakeLookup({ "203.0.113.7": "IN" }, { proxy: false });
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup });
    try {
      const first = await s.get({ "X-Forwarded-For": "203.0.113.7" });
      const second = await s.get({ "X-Forwarded-For": "203.0.113.7" });
      assert.equal(first.body.cached, false);
      assert.equal(second.body.cached, true);
      assert.equal(second.body.country, "IN");
      assert.equal(second.body.flags.proxy, false);
      assert.equal(geo.calls.length, 1);
    } finally {
      await s.close();
    }
  });

  test("a changed blocked list applies to a cached result (only geo data is cached)", async () => {
    const env: NodeJS.ProcessEnv = { TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup", IP_RISK_BLOCKED_COUNTRIES: "KP" };
    const geo = fakeLookup({ "203.0.113.7": "IN" });
    const s = await serve(env, { geoLookup: geo.lookup });
    try {
      assert.equal((await s.get({ "X-Forwarded-For": "203.0.113.7" })).body.flags.blocked_country, false);
      env.IP_RISK_BLOCKED_COUNTRIES = "KP,IN";
      const after = await s.get({ "X-Forwarded-For": "203.0.113.7" });
      assert.equal(after.body.cached, true);
      assert.equal(after.body.flags.blocked_country, true);
      assert.equal(geo.calls.length, 1);
    } finally {
      await s.close();
    }
  });

  test("IP_RISK_CACHE_SECONDS=0 turns caching off", async () => {
    const geo = fakeLookup({ "203.0.113.7": "IN" });
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup", IP_RISK_CACHE_SECONDS: "0" }, { geoLookup: geo.lookup });
    try {
      await s.get({ "X-Forwarded-For": "203.0.113.7" });
      assert.equal((await s.get({ "X-Forwarded-For": "203.0.113.7" })).body.cached, false);
      assert.equal(geo.calls.length, 2);
    } finally {
      await s.close();
    }
  });

  test("geo source none, or lookup without a valid URL: reason no_geo_source", async () => {
    for (const env of [
      { TRUST_PROXY: "1" },
      { TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup", IP_RISK_LOOKUP_URL: "https://geo.example/json" },
    ]) {
      const s = await serve(env);
      try {
        const r = await s.get({ "X-Forwarded-For": "203.0.113.7" });
        assert.equal(r.body.country, null);
        assert.equal(r.body.reason, "no_geo_source", JSON.stringify(env));
      } finally {
        await s.close();
      }
    }
  });

  test("httpGeoLookup against a real local HTTP server: success, provider error, timeout", async () => {
    const seen: string[] = [];
    const provider = http.createServer((req, res) => {
      seen.push(req.url ?? "");
      if (req.url === "/203.0.113.7/json/") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ country_code: "IN", proxy: false }));
      } else if (req.url === "/203.0.113.8/json/") {
        res.statusCode = 429;
        res.end("{}");
      } else {
        setTimeout(() => res.end("{}"), 1000); // slower than the lookup timeout
      }
    });
    provider.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => provider.once("listening", () => resolve()));
    const { port } = provider.address() as AddressInfo;
    try {
      const lookup = httpGeoLookup(`http://127.0.0.1:${port}/{ip}/json/`, { timeoutMs: 200 });
      assert.deepEqual(await lookup.lookup("203.0.113.7"),
        { country: "IN", region: null, city: null, proxy: false, hosting: null, tor: null, source: "lookup" });
      assert.equal(await lookup.lookup("203.0.113.8"), null, "429 from the provider");
      assert.equal(await lookup.lookup("203.0.113.9"), null, "timed out");
      assert.deepEqual(seen.slice(0, 3), ["/203.0.113.7/json/", "/203.0.113.8/json/", "/203.0.113.9/json/"]);
    } finally {
      provider.closeAllConnections();
      await new Promise<void>((resolve) => provider.close(() => resolve()));
    }
  });
});

describe("country header source", () => {
  const fakeReq = (trusted: boolean, value: string | undefined) =>
    ({
      app: { get: () => () => trusted },
      socket: { remoteAddress: "198.51.100.10" },
      header: () => value,
    }) as unknown as Request;

  test("the header counts only when the direct peer is a trusted proxy; XX and T1 are not countries", () => {
    assert.equal(countryFromTrustedHeader(fakeReq(false, "IN"), "cf-ipcountry"), null, "no trusted proxy: ignored");
    assert.equal(countryFromTrustedHeader(fakeReq(true, "in"), "cf-ipcountry"), "IN");
    assert.equal(countryFromTrustedHeader(fakeReq(true, "XX"), "cf-ipcountry"), null);
    assert.equal(countryFromTrustedHeader(fakeReq(true, "T1"), "cf-ipcountry"), null);
    assert.equal(countryFromTrustedHeader(fakeReq(true, undefined), "cf-ipcountry"), null);
  });

  test("TRUST_PROXY=1: the CDN's country header is used", async () => {
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "header", IP_RISK_BLOCKED_COUNTRIES: "IR" });
    try {
      const r = await s.get({ "X-Forwarded-For": "203.0.113.7", "CF-IPCountry": "IR" });
      assert.equal(r.body.country, "IR");
      assert.equal(r.body.source, "header");
      assert.equal(r.body.flags.blocked_country, true);
      assert.equal(r.body.cached, false);
    } finally {
      await s.close();
    }
  });

  test("TRUST_PROXY unset: a client-sent country header changes nothing", async () => {
    const s = await serve({ IP_RISK_GEO_SOURCE: "header" });
    try {
      const r = await s.get({ "X-Forwarded-For": "203.0.113.7", "CF-IPCountry": "IR" });
      assert.deepEqual(r.body, PRIVATE_LOOPBACK);
    } finally {
      await s.close();
    }
  });
});

describe("development override for private addresses", () => {
  test("development: IP_RISK_DEV_PRIVATE_IP_COUNTRY places a private address", async () => {
    const s = await serve({ NODE_ENV: "development", IP_RISK_DEV_PRIVATE_IP_COUNTRY: "in", IP_RISK_BLOCKED_COUNTRIES: "IN" });
    try {
      const r = await s.get();
      assert.deepEqual(r.body, {
        country: "IN", region: null, city: null,
        is_proxy: null, is_hosting: null, is_tor: null,
        risk_level: "high", reasons: ["blocked_country"],
        flags: {
          blocked_country: true, proxy: null, hosting: null, tor: null, private_address: true,
          country_not_allowed: false, country_changed: null,
        },
        source: "dev_override", reason: null, cached: false,
      });
    } finally {
      await s.close();
    }
  });

  test("production: the override is ignored", async () => {
    assert.equal(loadIpRiskConfig({ NODE_ENV: "production", IP_RISK_DEV_PRIVATE_IP_COUNTRY: "IN" }).devPrivateIpCountry, null);
    const s = await serve({ NODE_ENV: "production", IP_RISK_DEV_PRIVATE_IP_COUNTRY: "IN" });
    try {
      assert.deepEqual((await s.get()).body, PRIVATE_LOOPBACK);
    } finally {
      await s.close();
    }
  });
});

describe("rate limits", () => {
  test("per client IP", async () => {
    const s = await serve({ IP_RISK_RATE_LIMIT_PER_IP: "2" });
    try {
      assert.equal((await s.get()).status, 200);
      assert.equal((await s.get()).status, 200);
      const third = await s.get();
      assert.equal(third.status, 429);
      assert.deepEqual(third.body, { error: "RATE_LIMIT_EXCEEDED", limit: "ip" });
    } finally {
      await s.close();
    }
  });

  test("per API key", async () => {
    const s = await serve({ IP_RISK_RATE_LIMIT_PER_IP: "100", IP_RISK_RATE_LIMIT_PER_API_KEY: "1" });
    try {
      assert.equal((await s.get({ "X-Api-Key": "key-a" })).status, 200);
      const second = await s.get({ "X-Api-Key": "key-a" });
      assert.equal(second.status, 429);
      assert.deepEqual(second.body, { error: "RATE_LIMIT_EXCEEDED", limit: "api_key" });
      assert.equal((await s.get({ "X-Api-Key": "key-b" })).status, 200, "another app's key has its own budget");
    } finally {
      await s.close();
    }
  });
});

describe("real requireApiKey (Prisma lookup and Redis replay check replaced in-process)", () => {
  const API_KEY = "test-api-key";
  const SECRET = "test-api-secret";
  const credentials = prisma.apiCredential as unknown as { findUnique: unknown };
  const originalFindUnique = credentials.findUnique;
  const redisClient = redis as unknown as { set: unknown };
  const originalSet = redisClient.set;
  const originalKey = process.env.CREDENTIAL_ENCRYPTION_KEY;
  const usedSignatures = new Set<string>();

  before(() => {
    process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString("hex"); // throwaway test key
    const stored = encryptSecret(SECRET);
    credentials.findUnique = async (args: { where: { apiKey: string } }) =>
      args.where.apiKey === API_KEY
        ? { applicationId: "app-1", apiSecretEncrypted: stored, status: "ACTIVE", application: { archivedAt: null } }
        : null;
    redisClient.set = async (key: string) => {
      if (usedSignatures.has(key)) return null; // NX: already present
      usedSignatures.add(key);
      return "OK";
    };
  });

  after(() => {
    credentials.findUnique = originalFindUnique;
    redisClient.set = originalSet;
    if (originalKey === undefined) delete process.env.CREDENTIAL_ENCRYPTION_KEY;
    else process.env.CREDENTIAL_ENCRYPTION_KEY = originalKey;
    redis.disconnect();
  });

  const signed = (timestamp: string, signedBody: Buffer) => ({
    "X-Api-Key": API_KEY,
    "X-Timestamp": timestamp,
    "X-Signature": computeSignature(SECRET, timestamp, signedBody),
  });

  test("no credentials: 401 MISSING_API_KEY and no lookup", async () => {
    const geo = fakeLookup({ "203.0.113.7": "IN" });
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup }, { realAuth: true });
    try {
      const r = await s.get({ "X-Forwarded-For": "203.0.113.7" });
      assert.equal(r.status, 401);
      assert.deepEqual(r.body, { error: "MISSING_API_KEY" });
      assert.deepEqual(geo.calls, []);
    } finally {
      await s.close();
    }
  });

  test("bodiless GET signed over '<timestamp>.' passes; replay, a signature over a body, an unknown key and a stale timestamp are 401", async () => {
    const geo = fakeLookup({ "203.0.113.7": "IN" });
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup }, { realAuth: true });
    try {
      const xff = { "X-Forwarded-For": "203.0.113.7" };
      const ts = String(Date.now());
      const headers = { ...xff, ...signed(ts, Buffer.alloc(0)) };

      const ok = await s.get(headers);
      assert.equal(ok.status, 200);
      assert.equal(ok.body.country, "IN");

      const replay = await s.get(headers);
      assert.deepEqual([replay.status, replay.body], [401, { error: "REPLAYED_REQUEST" }]);

      const overBody = await s.get({ ...xff, ...signed(String(Date.now() + 1), Buffer.from("{}")) });
      assert.deepEqual([overBody.status, overBody.body], [401, { error: "SIGNATURE_MISMATCH" }]);

      const unknownKey = await s.get({ ...xff, ...signed(String(Date.now() + 2), Buffer.alloc(0)), "X-Api-Key": "other-key" });
      assert.deepEqual([unknownKey.status, unknownKey.body], [401, { error: "INVALID_OR_REVOKED_API_KEY" }]);

      const staleTs = String(Date.now() - 10 * 60_000);
      const stale = await s.get({ ...xff, ...signed(staleTs, Buffer.alloc(0)) });
      assert.deepEqual([stale.status, stale.body], [401, { error: "STALE_TIMESTAMP" }]);

      assert.deepEqual(geo.calls, ["203.0.113.7"], "only the authenticated request reached the lookup");
    } finally {
      await s.close();
    }
  });

  test("a captured signature re-sent upper-cased is a replay; with padding or junk it is rejected before any lookup (F-01)", async () => {
    const geo = fakeLookup({ "203.0.113.7": "IN" });
    const s = await serve({ TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" }, { geoLookup: geo.lookup }, { realAuth: true });
    try {
      const xff = { "X-Forwarded-For": "203.0.113.7" };
      const ts = String(Date.now() + 5);
      const headers = { ...xff, ...signed(ts, Buffer.alloc(0)) };
      assert.equal((await s.get(headers)).status, 200);

      const upper = await s.get({ ...headers, "X-Signature": headers["X-Signature"].toUpperCase() });
      assert.deepEqual([upper.status, upper.body], [401, { error: "REPLAYED_REQUEST" }]);

      for (const junk of ["00", "zz", "=="]) {
        const padded = await s.get({ ...headers, "X-Signature": headers["X-Signature"] + junk });
        assert.deepEqual([padded.status, padded.body], [401, { error: "INVALID_SIGNATURE_FORMAT" }], junk);
      }
      assert.deepEqual(geo.calls, ["203.0.113.7"]);
    } finally {
      await s.close();
    }
  });
});

describe("HMAC for the empty GET body", () => {
  test("a bodiless GET leaves req.rawBody undefined, so requireApiKey signs over empty bytes", async () => {
    const app = express();
    app.use(jsonBodyParser());
    let rawBody: unknown = "not set";
    app.get("/probe", (req, res) => {
      rawBody = (req as Request & { rawBody?: Buffer }).rawBody;
      res.json({});
    });
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", () => resolve()));
    try {
      const { port } = server.address() as AddressInfo;
      await fetch(`http://127.0.0.1:${port}/probe`);
      assert.equal(rawBody, undefined);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("signature for an empty body = hex HMAC-SHA256(secret, '<timestamp>.') — fixed vector for the SDK", () => {
    const ts = "1700000000000";
    const sig = computeSignature("test-secret", ts, Buffer.alloc(0));
    assert.equal(sig, crypto.createHmac("sha256", "test-secret").update(`${ts}.`).digest("hex"));
    assert.equal(sig, "27ae51cd1754dbdae532ea92ca49b7a352d4a2d8258c5e1105a6ef52a0c1e7a9");
  });
});
