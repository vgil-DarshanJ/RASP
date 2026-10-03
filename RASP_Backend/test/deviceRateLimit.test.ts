// Rate limiting (src/redis/deviceRateLimit.ts): per IP, per API key, per app + device.
// Real: deviceRateLimiter middleware, claimedDevice, computeDeviceKeyId.
// Doubles: an in-memory counter instead of Redis (checkRateLimit), and
// minimal Express req/res objects.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { claimedDevice, deviceRateLimiter, RateCheck } from "../src/redis/deviceRateLimit";
import { computeDeviceKeyId } from "../src/crypto/ecdsa";

function memoryCheck(): RateCheck & { keys: Map<string, number> } {
  const keys = new Map<string, number>();
  const check = (async (key: string, limit: number) => {
    const count = (keys.get(key) ?? 0) + 1;
    keys.set(key, count);
    return { allowed: count <= limit, remaining: Math.max(0, limit - count) };
  }) as RateCheck & { keys: Map<string, number> };
  check.keys = keys;
  return check;
}

async function call(mw: ReturnType<typeof deviceRateLimiter>, apiKey: string | undefined, body: unknown, ip = "10.0.0.1") {
  let status = 200;
  let json: Record<string, unknown> = {};
  let passed = false;
  const req = { header: (n: string) => (n === "X-Api-Key" ? apiKey : undefined), body, ip } as unknown as Request;
  const res = {
    setHeader: () => undefined,
    status(code: number) { status = code; return this; },
    json(b: Record<string, unknown>) { json = b; return this; },
  } as unknown as Response;
  await mw(req, res, (() => { passed = true; }) as NextFunction);
  return { status: passed ? 200 : status, limit: json.limit };
}

const limiter = (check: RateCheck, limits: { device?: number; apiKey?: number; ip?: number } = {}) =>
  deviceRateLimiter({
    scope: "ingest",
    limitEnv: "NOPE_DEVICE", defaultLimit: limits.device ?? 2,
    apiKeyLimitEnv: "NOPE_KEY", defaultApiKeyLimit: limits.apiKey ?? 1000,
    ipLimitEnv: "NOPE_IP", defaultIpLimit: limits.ip ?? 1000,
    windowEnv: "NOPE_WINDOW", defaultWindowSeconds: 60,
    check,
  });

const envelope = (device: string) => ({ envelopeVersion: 1, deviceKeyId: device });

describe("rate limits", () => {
  test("each device of the same app has its own budget", async () => {
    const mw = limiter(memoryCheck(), { device: 2 });
    assert.equal((await call(mw, "app-key", envelope("A"))).status, 200);
    assert.equal((await call(mw, "app-key", envelope("A"))).status, 200);
    const third = await call(mw, "app-key", envelope("A"));
    assert.equal(third.status, 429, "device A over its limit");
    assert.equal(third.limit, "device");
    assert.equal((await call(mw, "app-key", envelope("B"))).status, 200, "device B unaffected");
  });

  test("inventing a new device id per request runs into the per-API-key ceiling", async () => {
    const mw = limiter(memoryCheck(), { device: 2, apiKey: 5, ip: 1000 });
    const results = [];
    for (let i = 0; i < 8; i++) {
      // A different device id every time, and a different IP, so only the API-key bucket can stop it.
      results.push(await call(mw, "app-key", envelope(`fake-${i}`), `10.0.1.${i}`));
    }
    assert.deepEqual(results.map((r) => r.status), [200, 200, 200, 200, 200, 429, 429, 429]);
    assert.equal(results[5].limit, "api_key");
    // Another app's key has its own ceiling.
    assert.equal((await call(mw, "other-app-key", envelope("x"), "10.0.2.1")).status, 200);
  });

  test("the per-IP ceiling applies across API keys and device ids", async () => {
    const mw = limiter(memoryCheck(), { device: 100, apiKey: 100, ip: 3 });
    const statuses = [];
    for (let i = 0; i < 5; i++) statuses.push((await call(mw, `key-${i}`, envelope(`d-${i}`), "203.0.113.7")).status);
    assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
    assert.equal((await call(mw, "key-0", envelope("d-0"), "203.0.113.7")).limit, "ip");
    assert.equal((await call(mw, "key-0", envelope("d-0"), "198.51.100.9")).status, 200, "another IP is unaffected");
  });

  test("requests without an API key are still limited per IP", async () => {
    const check = memoryCheck();
    const mw = limiter(check, { ip: 1 });
    assert.equal((await call(mw, undefined, {}, "192.0.2.1")).status, 200); // auth then reports MISSING_API_KEY
    assert.equal((await call(mw, undefined, {}, "192.0.2.1")).status, 429);
    assert.deepEqual([...check.keys.keys()], ["ingest:ip:192.0.2.1"]);
  });

  test("the same device id under another app is a separate device bucket", async () => {
    const mw = limiter(memoryCheck(), { device: 1 });
    assert.equal((await call(mw, "app-1", envelope("A"))).status, 200);
    assert.equal((await call(mw, "app-2", envelope("A"))).status, 200);
    assert.equal((await call(mw, "app-1", envelope("A"))).status, 429);
  });

  test("device is taken from envelopes, legacy batches and registrations", () => {
    assert.equal(claimedDevice({ envelopeVersion: 1, deviceKeyId: "k1" }), "key:k1");
    assert.equal(claimedDevice({ events: [{ detectorId: "x", status: "SECURE", deviceId: "android-123" }] }), "device:android-123");
    const spki = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ type: "spki", format: "der" }) as Buffer;
    assert.equal(claimedDevice({ publicKey: spki.toString("base64"), appId: "x" }), `key:${computeDeviceKeyId(spki)}`);
    assert.equal(claimedDevice({ publicKey: spki.toString("base64") }), claimedDevice({ deviceKeyId: computeDeviceKeyId(spki) }));
    assert.equal(claimedDevice({ events: [{ detectorId: "x" }] }), "unidentified");
    assert.equal(claimedDevice(null), "unidentified");
    assert.equal(claimedDevice({ deviceKeyId: "x".repeat(500) }).length, "key:".length + 200, "bounded key length");
  });
});
