// Per app + device rate limiting (src/redis/deviceRateLimit.ts).
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

async function call(mw: ReturnType<typeof deviceRateLimiter>, apiKey: string | undefined, body: unknown) {
  let status = 200;
  let passed = false;
  const req = { header: (n: string) => (n === "X-Api-Key" ? apiKey : undefined), body } as unknown as Request;
  const res = {
    setHeader: () => undefined,
    status(code: number) { status = code; return this; },
    json() { return this; },
  } as unknown as Response;
  await mw(req, res, (() => { passed = true; }) as NextFunction);
  return passed ? 200 : status;
}

const limiter = (check: RateCheck, limit = 2) =>
  deviceRateLimiter({ scope: "ingest", limitEnv: "NOPE_LIMIT", windowEnv: "NOPE_WINDOW", defaultLimit: limit, defaultWindowSeconds: 60, check });

describe("per-device rate limit", () => {
  test("each device of the same app has its own budget", async () => {
    const check = memoryCheck();
    const mw = limiter(check, 2);
    const a = { envelopeVersion: 1, deviceKeyId: "device-A" };
    const b = { envelopeVersion: 1, deviceKeyId: "device-B" };

    assert.equal(await call(mw, "app-key", a), 200);
    assert.equal(await call(mw, "app-key", a), 200);
    assert.equal(await call(mw, "app-key", a), 429, "device A over its limit");
    // Device B of the same app is unaffected — it was one shared budget before.
    assert.equal(await call(mw, "app-key", b), 200);
    assert.equal(await call(mw, "app-key", b), 200);
    assert.deepEqual([...check.keys.keys()].sort(), ["ingest:app-key:key:device-A", "ingest:app-key:key:device-B"]);
  });

  test("the same device id under another app is a separate bucket", async () => {
    const check = memoryCheck();
    const mw = limiter(check, 1);
    const body = { envelopeVersion: 1, deviceKeyId: "device-A" };
    assert.equal(await call(mw, "app-1", body), 200);
    assert.equal(await call(mw, "app-2", body), 200);
    assert.equal(await call(mw, "app-1", body), 429);
  });

  test("device is taken from envelopes, legacy batches and registrations", () => {
    assert.equal(claimedDevice({ envelopeVersion: 1, deviceKeyId: "k1" }), "key:k1");
    assert.equal(claimedDevice({ events: [{ detectorId: "x", status: "SECURE", deviceId: "android-123" }] }), "device:android-123");
    const spki = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ type: "spki", format: "der" }) as Buffer;
    assert.equal(claimedDevice({ publicKey: spki.toString("base64"), appId: "x" }), `key:${computeDeviceKeyId(spki)}`);
    assert.equal(claimedDevice({ events: [{ detectorId: "x" }] }), "unidentified");
    assert.equal(claimedDevice(null), "unidentified");
    assert.equal(claimedDevice({ deviceKeyId: "x".repeat(500) }).length, "key:".length + 200, "bounded key length");
  });

  test("a registration and an envelope from the same key share the device bucket name", () => {
    const spki = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ type: "spki", format: "der" }) as Buffer;
    assert.equal(claimedDevice({ publicKey: spki.toString("base64") }), claimedDevice({ deviceKeyId: computeDeviceKeyId(spki) }));
  });

  test("no API key passes through (the auth middleware reports MISSING_API_KEY)", async () => {
    const check = memoryCheck();
    assert.equal(await call(limiter(check), undefined, { deviceKeyId: "d" }), 200);
    assert.equal(check.keys.size, 0);
  });
});
