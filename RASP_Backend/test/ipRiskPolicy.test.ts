// GET /v1/ip-risk risk levels, reasons and per-application policy (Task 6.0 Part 3.2).
// Real: assessRisk, buildIpRiskResponse, parseLookupBody, parseCachedGeo, and
// the router over real HTTP on an ephemeral port with TRUST_PROXY handling.
// Doubles: a fake geo lookup, an in-memory cache and rate counter, an auth
// stub that sets the application id (as requireApiKey would), and injected
// applicationPolicy / registrationCountry lookups instead of Prisma.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express, { RequestHandler } from "express";
import { applyTrustProxy, jsonBodyParser } from "../src/middleware/requestSetup";
import { createIpRiskRouter, IpRiskDeps } from "../src/ipRisk/routes";
import { assessRisk, GeoInfo, parseCachedGeo, parseLookupBody } from "../src/ipRisk/ipRisk";
import type { RateCheck } from "../src/redis/deviceRateLimit";

const geo = (over: Partial<GeoInfo> = {}): GeoInfo => ({
  country: "IN", region: null, city: null, proxy: null, hosting: null, tor: null, source: "lookup", ...over,
});
const policy = (over: Partial<{ blocked: string[]; allowed: string[]; registrationCountry: string | null }> = {}) => ({
  blockedCountries: new Set(over.blocked ?? ["KP", "IR", "SY"]),
  allowedCountries: new Set(over.allowed ?? []),
  registrationCountry: over.registrationCountry ?? null,
});

describe("risk rules", () => {
  test("each high rule alone gives high with its reason", () => {
    assert.deepEqual(pick(assessRisk(geo({ country: "KP" }), policy())), ["high", ["blocked_country"]]);
    assert.deepEqual(pick(assessRisk(geo({ country: "DE" }), policy({ allowed: ["IN"] }))), ["high", ["country_not_allowed"]]);
    assert.deepEqual(pick(assessRisk(geo({ tor: true }), policy())), ["high", ["tor"]]);
    assert.deepEqual(pick(assessRisk(geo({ proxy: true }), policy())), ["high", ["proxy"]]);
  });

  test("hosting and a changed country are soft: medium", () => {
    assert.deepEqual(pick(assessRisk(geo({ hosting: true }), policy())), ["medium", ["hosting"]]);
    assert.deepEqual(pick(assessRisk(geo(), policy({ registrationCountry: "DE" }))), ["medium", ["country_changed"]]);
  });

  test("country known and nothing fired: low; unknown country: null with no reasons", () => {
    assert.deepEqual(pick(assessRisk(geo(), policy({ allowed: ["IN"], registrationCountry: "IN" }))), ["low", []]);
    assert.deepEqual(pick(assessRisk(geo({ country: null }), policy({ registrationCountry: "DE" }))), [null, []]);
    assert.deepEqual(pick(assessRisk(null, policy())), [null, []]);
  });

  test("several rules: high wins, reasons listed in rule order", () => {
    const r = assessRisk(geo({ country: "KP", proxy: true, hosting: true }), policy({ registrationCountry: "IN" }));
    assert.deepEqual(pick(r), ["high", ["blocked_country", "proxy", "hosting", "country_changed"]]);
  });

  test("country_changed is null without a registration country; false when the same", () => {
    assert.equal(assessRisk(geo(), policy()).changed, null);
    assert.equal(assessRisk(geo(), policy({ registrationCountry: "in" })).changed, false);
  });
});

function pick(r: ReturnType<typeof assessRisk>) {
  return [r.level, r.reasons];
}

describe("provider fields", () => {
  test("coarse region/city and tor from ipapi.co and ip-api shapes; never coordinates", () => {
    const ipapi = parseLookupBody({ country_code: "IN", region: "Maharashtra", city: "Mumbai", latitude: 19.07, longitude: 72.87 });
    assert.deepEqual(ipapi, { country: "IN", region: "Maharashtra", city: "Mumbai", proxy: null, hosting: null, tor: null, source: "lookup" });
    const ipApiCom = parseLookupBody({ countryCode: "DE", regionName: "Hesse", city: "Frankfurt", proxy: false, hosting: true, lat: 50.1, lon: 8.6 });
    assert.deepEqual(ipApiCom, { country: "DE", region: "Hesse", city: "Frankfurt", proxy: false, hosting: true, tor: null, source: "lookup" });
    assert.equal(parseLookupBody({ country_code: "NL", tor: true })?.tor, true);
    assert.equal(parseLookupBody({ country_code: "NL", is_tor: true })?.tor, true);
    assert.equal(parseLookupBody({ country_code: "NL", security: { tor: true, proxy: true } })?.proxy, true);
    assert.equal(JSON.stringify(ipApiCom).includes("50.1"), false);
  });

  test("cache entries written before region/city/tor existed read them as null", () => {
    assert.deepEqual(parseCachedGeo(JSON.stringify({ country: "IN", proxy: false, hosting: null, source: "lookup" })),
      { country: "IN", region: null, city: null, proxy: false, hosting: null, tor: null, source: "lookup" });
  });
});

describe("router: per-application lists and first-registration country", () => {
  const memoryRate: RateCheck = async () => ({ allowed: true, remaining: 100 });
  const asApp: RequestHandler = (req, _res, next) => {
    (req as unknown as { applicationId: string }).applicationId = "app-1";
    next();
  };

  async function serve(deps: IpRiskDeps, countries: Record<string, Partial<GeoInfo>>) {
    const app = express();
    const env = { TRUST_PROXY: "1", IP_RISK_GEO_SOURCE: "lookup" };
    applyTrustProxy(app, env);
    app.use(jsonBodyParser());
    const cache = new Map<string, GeoInfo>();
    app.use("/v1/ip-risk", createIpRiskRouter({
      env, rateCheck: memoryRate, authenticate: asApp,
      cache: { get: async (ip) => cache.get(ip) ?? null, set: async (ip, info) => { cache.set(ip, info); } },
      geoLookup: { lookup: async (ip) => (countries[ip] ? geo(countries[ip]) : null) },
      ...deps,
    }));
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", () => r()));
    const { port } = server.address() as AddressInfo;
    return {
      async get(ip: string, headers: Record<string, string> = {}) {
        const res = await fetch(`http://127.0.0.1:${port}/v1/ip-risk`, { headers: { "X-Forwarded-For": ip, ...headers } });
        return (await res.json()) as Record<string, any>;
      },
      close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
    };
  }

  test("the application's blocked list replaces the default; its allow-list applies", async () => {
    const s = await serve({
      applicationPolicy: async () => ({ blocked: ["in"], allowed: ["IN", "US"] }),
      registrationCountry: async () => null,
    }, { "203.0.113.1": { country: "IN" }, "203.0.113.2": { country: "KP" }, "203.0.113.3": { country: "US" } });
    try {
      const india = await s.get("203.0.113.1");
      assert.deepEqual([india.risk_level, india.reasons, india.flags.blocked_country], ["high", ["blocked_country"], true]);
      const kp = await s.get("203.0.113.2");
      assert.deepEqual([kp.risk_level, kp.reasons], ["high", ["country_not_allowed"]], "KP not in the app's own blocked list, but not allowed");
      const us = await s.get("203.0.113.3");
      assert.deepEqual([us.risk_level, us.reasons, us.flags.country_not_allowed], ["low", [], false]);
    } finally {
      await s.close();
    }
  });

  test("no own lists: env default blocked list, no allow-list", async () => {
    const s = await serve({ applicationPolicy: async () => ({ blocked: [], allowed: [] }) },
      { "203.0.113.4": { country: "IR" }, "203.0.113.5": { country: "FR" } });
    try {
      assert.deepEqual((await s.get("203.0.113.4")).reasons, ["blocked_country"]);
      const fr = await s.get("203.0.113.5");
      assert.deepEqual([fr.risk_level, fr.flags.country_not_allowed], ["low", false]);
    } finally {
      await s.close();
    }
  });

  test("X-Device-Key-Id: a country different from the device's first registration is a medium, soft signal", async () => {
    const asked: string[] = [];
    const s = await serve({
      applicationPolicy: async () => ({ blocked: [], allowed: [] }),
      registrationCountry: async (applicationId, deviceKeyId) => {
        asked.push(`${applicationId}/${deviceKeyId}`);
        return deviceKeyId === "key-from-india" ? "IN" : null;
      },
    }, { "203.0.113.6": { country: "DE", region: "Hesse", city: "Frankfurt", hosting: false } });
    try {
      const moved = await s.get("203.0.113.6", { "X-Device-Key-Id": "key-from-india" });
      assert.deepEqual([moved.risk_level, moved.reasons, moved.flags.country_changed], ["medium", ["country_changed"], true]);
      assert.deepEqual([moved.region, moved.city, moved.is_hosting], ["Hesse", "Frankfurt", false]);
      const unknownDevice = await s.get("203.0.113.6", { "X-Device-Key-Id": "other" });
      assert.deepEqual([unknownDevice.risk_level, unknownDevice.flags.country_changed], ["low", null]);
      const noHeader = await s.get("203.0.113.6");
      assert.equal(noHeader.flags.country_changed, null);
      assert.deepEqual(asked, ["app-1/key-from-india", "app-1/other"], "looked up only within the authenticated application");
    } finally {
      await s.close();
    }
  });

  test("tor and proxy from the provider: high; the IP is never in the response", async () => {
    const s = await serve({ applicationPolicy: async () => null }, { "203.0.113.7": { country: "NL", tor: true, proxy: true } });
    try {
      const r = await s.get("203.0.113.7");
      assert.deepEqual([r.risk_level, r.reasons, r.is_tor, r.is_proxy], ["high", ["tor", "proxy"], true, true]);
      assert.equal(JSON.stringify(r).includes("203.0.113"), false);
    } finally {
      await s.close();
    }
  });
});
