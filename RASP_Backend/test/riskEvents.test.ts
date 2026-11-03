// POST /v1/risk/events (Task 8.1). Real: createRiskRouter (16 KB parser,
// deviceRateLimiter, processRiskEvent, schema, ES256 verification, replay
// rules, rules engine) over real HTTP on an ephemeral port.
// Doubles: MemoryRiskRepository instead of Postgres (test/riskSupport.ts),
// an in-memory rate counter instead of Redis, an API-key check that maps
// "key-app-1" to app-1 (the real one needs Postgres), a fixed IP country,
// and recorded alert side effects.
import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import express, { NextFunction, Response } from "express";
import { createRiskRouter } from "../src/risk/routes";
import type { RiskAlertDeps, RiskAlertSource } from "../src/risk/alerts";
import type { ApiKeyedRequest } from "../src/middleware/apiKey";
import type { RateCheck } from "../src/redis/deviceRateLimit";
import { makeDevice, TestDevice } from "./support";
import { MemoryRiskRepository, signRiskEnvelope, transactionFields } from "./riskSupport";

const NOW = Date.UTC(2026, 9, 7, 12, 0, 0);
const MIN = 60_000;

let repo: MemoryRiskRepository;
let device: TestDevice;
let otherAppDevice: TestDevice;
let rateCounts: Map<string, number>;
let deviceLimit = 1000;
let ipCountry: string | null = null;
const alerts: RiskAlertSource[] = [];
let now = NOW;
let port = 0;
let server: import("node:http").Server;

const memoryRate: RateCheck = async (key, limit) => {
  const count = (rateCounts.get(key) ?? 0) + 1;
  rateCounts.set(key, count);
  const max = key.startsWith("risk:key-app-1:") ? deviceLimit : limit;
  return { allowed: count <= max, remaining: Math.max(0, max - count) };
};

const alertDeps: RiskAlertDeps = {
  findApplicationName: async () => "Bank App",
  storeAlerts: async (source) => {
    alerts.push(source);
    return [];
  },
  recordForDashboard: async () => undefined,
  triggerWebhook: async () => undefined,
};

function fakeApiKey(req: ApiKeyedRequest, res: Response, next: NextFunction) {
  const key = req.header("X-Api-Key");
  if (!key) return res.status(401).json({ error: "MISSING_API_KEY" });
  if (key === "key-app-1") req.applicationId = "app-1";
  else if (key === "key-app-2") req.applicationId = "app-2";
  else return res.status(401).json({ error: "INVALID_OR_REVOKED_API_KEY" });
  next();
}

before(async () => {
  const app = express();
  app.use("/v1/risk", createRiskRouter({
    repo: { // delegate, so each test can swap `repo`
      findDeviceKey: (k) => repo.findDeviceKey(k),
      findRiskRules: (a) => repo.findRiskRules(a),
      findByEventId: (d, e) => repo.findByEventId(d, e),
      isNonceUsed: (d, n) => repo.isNonceUsed(d, n),
      storeRiskEvent: (i) => repo.storeRiskEvent(i),
    },
    rateCheck: memoryRate,
    authenticate: fakeApiKey as express.RequestHandler,
    ipCountry: async () => ipCountry,
    alerts: alertDeps,
    now: () => now,
  }));
  app.use(express.json({ limit: "1mb" })); // the app-wide parser comes after, as in app.ts
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  port = (server.address() as AddressInfo).port;
});

after(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

beforeEach(() => {
  repo = new MemoryRiskRepository();
  device = makeDevice("com.example.bank");
  otherAppDevice = makeDevice("com.example.bank");
  repo.addDevice(device.deviceKeyId, {
    id: "reg-1", applicationId: "app-1", appId: device.appId, deviceId: "android-1", publicKey: device.publicKeyB64,
  });
  repo.addDevice(otherAppDevice.deviceKeyId, {
    id: "reg-2", applicationId: "app-2", appId: otherAppDevice.appId, deviceId: null, publicKey: otherAppDevice.publicKeyB64,
  });
  rateCounts = new Map();
  deviceLimit = 1000;
  ipCountry = null;
  alerts.length = 0;
  now = NOW;
});

async function post(body: string, apiKey: string | null = "key-app-1", contentType = "application/json") {
  const headers: Record<string, string> = { "Content-Type": contentType };
  if (apiKey) headers["X-Api-Key"] = apiKey;
  const res = await fetch(`http://127.0.0.1:${port}/v1/risk/events`, { method: "POST", headers, body });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

const send = (overrides: Record<string, unknown> = {}, d = device) => post(signRiskEnvelope(d, now, overrides).body);
const tick = () => new Promise((r) => setImmediate(r));

describe("POST /v1/risk/events — accepted", () => {
  test("a signed session login → 202, stored with hashes only, binding created, no findings for a first device", async () => {
    const r = await send();
    assert.equal(r.status, 202);
    assert.deepEqual(r.body, { accepted: true, riskEvents: [] });
    assert.equal(repo.rows.length, 1);
    assert.equal(repo.rows[0].type, "session");
    assert.equal(repo.bindings.length, 1);
  });

  test("a transaction → 202; second transaction to a new beneficiary reports new_beneficiary with explanation; alert raised", async () => {
    assert.equal((await send({ ...transactionFields("c"), monotonicCounter: 1 })).status, 202);
    const r = await send({ ...transactionFields("e"), monotonicCounter: 2 });
    assert.equal(r.status, 202);
    const rules = r.body.riskEvents.map((f: { rule: string }) => f.rule);
    assert.ok(rules.includes("new_beneficiary"));
    const f = r.body.riskEvents.find((x: { rule: string }) => x.rule === "new_beneficiary");
    assert.equal(f.severity, "low");
    assert.equal(typeof f.explanation, "string");
    await tick();
    const raised = alerts.at(-1)!;
    assert.equal(raised.deviceId, "android-1", "registered device id, as the device page uses");
    assert.equal(raised.eventType, "transaction");
  });

  test("opted-in location is stored coarse (2 decimals); request-IP country stored", async () => {
    ipCountry = "IN";
    const r = await send({ location: { latitude: 19.076012, longitude: 72.877655, capturedAtMillis: now } });
    assert.equal(r.status, 202);
    assert.equal(repo.rows[0].latitude, 19.08);
    assert.equal(repo.rows[0].longitude, 72.88);
    assert.equal(repo.rows[0].ipCountry, "IN");
  });

  test("velocity across requests: the 6th transaction within 10 minutes reports transaction_velocity (high)", async () => {
    let last: Record<string, any> = {};
    for (let i = 1; i <= 6; i++) {
      now = NOW + i * MIN;
      last = (await send({ ...transactionFields("c"), monotonicCounter: i })).body;
    }
    assert.ok(last.riskEvents.some((f: { rule: string; severity: string }) => f.rule === "transaction_velocity" && f.severity === "high"));
  });

  test("per-app thresholds apply (maxCount 1 → the 2nd transaction fires)", async () => {
    repo.riskRules.set("app-1", { transactionVelocity: { maxCount: 1 } });
    await send({ ...transactionFields("c"), monotonicCounter: 1 });
    const r = await send({ ...transactionFields("c"), monotonicCounter: 2 });
    assert.ok(r.body.riskEvents.some((f: { rule: string }) => f.rule === "transaction_velocity"));
  });
});

describe("POST /v1/risk/events — rejected", () => {
  test("oversized body → 413 before anything is read", async () => {
    const big = JSON.stringify({ ...signRiskEnvelope(device, now).fields, padding: "x".repeat(17 * 1024) });
    const r = await post(big);
    assert.equal(r.status, 413);
    assert.equal(r.body.error, "PAYLOAD_TOO_LARGE");
    assert.equal(repo.rows.length, 0);
  });

  test("malformed JSON → 400 INVALID_JSON; non-object → 400", async () => {
    assert.equal((await post("{not json")).body.error, "INVALID_JSON");
    assert.equal((await post("[1,2]")).status, 400);
  });

  test("unknown fields (an amount, a phone number) → 400, even when signed", async () => {
    for (const extra of [{ amount: 100 }, { phoneNumber: "+910000000000" }, { smsBody: "OTP 1234" }]) {
      const r = await send(extra);
      assert.equal(r.status, 400, JSON.stringify(extra));
      assert.equal(r.body.error, "INVALID_RISK_EVENT");
    }
    assert.equal(repo.rows.length, 0);
  });

  test("bad ids and formats → 400", async () => {
    const cases: Record<string, unknown>[] = [
      { eventId: "not-a-uuid" },
      { eventId: crypto.randomUUID().toUpperCase() },
      { nonce: "abc" },
      { nonce: "G".repeat(32) },
      { accountHash: "A".repeat(64) },
      { accountHash: "a".repeat(63) },
      { sessionHash: "raw-session-id-123" },
      { riskScore: 101 },
      { riskScore: -1 },
      { riskVerdict: "SAFE" },
      { sdkVersion: "x".repeat(33) },
      { monotonicCounter: 0 },
      { monotonicCounter: 1.5 },
      { sessionEvent: "transfer" },
      { sessionEvent: undefined },
      { location: { latitude: 91, longitude: 0, capturedAtMillis: NOW } },
      { location: { latitude: 0, longitude: 0, capturedAtMillis: NOW, accuracy: 3 } },
      { riskEnvelopeVersion: 2 },
      { signatureAlgorithm: "HS256" },
      { ...transactionFields("c"), currency: "inr" },
      { ...transactionFields("c"), channel: "UPI APP" },
      { ...transactionFields("c"), beneficiaryHash: undefined },
      { ...transactionFields("c"), sessionEvent: "login" },
      { type: "session", beneficiaryHash: "c".repeat(64) },
    ];
    for (const c of cases) assert.equal((await send(c)).status, 400, JSON.stringify(c));
    assert.equal(repo.rows.length, 0);
  });

  test("missing / unknown API key → 401; unknown device key → 401; another app's device key → 401 (not 403)", async () => {
    const body = signRiskEnvelope(device, now).body;
    assert.equal((await post(body, null)).body.error, "MISSING_API_KEY");
    assert.equal((await post(body, "nope")).status, 401);
    const stranger = makeDevice();
    assert.equal((await send({}, stranger)).body.error, "UNKNOWN_DEVICE_KEY");
    assert.equal((await post(signRiskEnvelope(otherAppDevice, now).body, "key-app-1")).body.error, "UNKNOWN_DEVICE_KEY");
  });

  test("appId different from the registration → 403 APP_ID_MISMATCH", async () => {
    assert.equal((await send({ appId: "com.evil.app" })).status, 403);
  });

  test("bad signature → 401: a field changed after signing, another key's signature, garbage", async () => {
    const signed = signRiskEnvelope(device, now).fields as Record<string, unknown>;
    assert.equal((await post(JSON.stringify({ ...signed, accountHash: "f".repeat(64) }))).body.error, "SIGNATURE_INVALID");
    const foreign = signRiskEnvelope(makeDevice(), now).fields as Record<string, unknown>;
    assert.equal((await post(JSON.stringify({ ...signed, signature: foreign.signature }))).status, 401);
    assert.equal((await post(JSON.stringify({ ...signed, signature: "AAAA" }))).status, 401);
    assert.equal(repo.rows.length, 0);
  });

  test("event time: > 7 days old → 422 EVENT_TOO_OLD; > 5 min ahead → 422 EVENT_FROM_FUTURE", async () => {
    assert.equal((await send({ eventTimeMillis: NOW - 8 * 24 * 60 * MIN })).body.error, "EVENT_TOO_OLD");
    assert.equal((await send({ eventTimeMillis: NOW + 6 * MIN })).body.error, "EVENT_FROM_FUTURE");
  });

  test("replays → 409 REPLAYED: exact resend (duplicate), reused nonce, reused eventId, counter not increasing", async () => {
    const first = signRiskEnvelope(device, now, { monotonicCounter: 5 });
    assert.equal((await post(first.body)).status, 202);
    const again = await post(first.body);
    assert.equal(again.status, 409);
    assert.deepEqual(again.body, { error: "REPLAYED", duplicate: true });

    const f = first.fields as Record<string, unknown>;
    assert.equal((await send({ nonce: f.nonce, monotonicCounter: 6 })).body.error, "REPLAYED");
    const sameId = await send({ eventId: f.eventId, monotonicCounter: 7 });
    assert.equal(sameId.status, 409);
    assert.equal(sameId.body.duplicate, false);
    assert.equal((await send({ monotonicCounter: 5 })).body.error, "REPLAYED");
    assert.equal((await send({ monotonicCounter: 4 })).body.error, "REPLAYED");
    assert.equal(repo.rows.length, 1, "nothing stored again");
    assert.equal((await send({ monotonicCounter: 6 })).status, 202, "a fresh event with a higher counter is accepted");
  });

  test("rate limit per device → 429 with limit 'device'; another device of the same app is unaffected", async () => {
    deviceLimit = 2;
    assert.equal((await send({ monotonicCounter: 1 })).status, 202);
    assert.equal((await send({ monotonicCounter: 2 })).status, 202);
    const third = await send({ monotonicCounter: 3 });
    assert.equal(third.status, 429);
    assert.equal(third.body.limit, "device");
    const second = makeDevice();
    repo.addDevice(second.deviceKeyId, { id: "reg-3", applicationId: "app-1", appId: second.appId, deviceId: null, publicKey: second.publicKeyB64 });
    assert.equal((await send({ monotonicCounter: 1 }, second)).status, 202);
  });

  test("undecided input stays undecided: riskVerdict UNKNOWN with riskScore null is stored as such, never as LOW", async () => {
    assert.equal((await send({ riskVerdict: "UNKNOWN", riskScore: null })).status, 202);
    assert.equal(repo.rows[0].riskVerdict, "UNKNOWN");
    assert.equal(repo.rows[0].riskScore, null);
  });
});
