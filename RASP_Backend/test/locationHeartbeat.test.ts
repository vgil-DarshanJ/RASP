// Location heartbeats (Task 9.3): the latest shared point per device and a
// short trail, never stored as security events, coordinates only with opt-in.
// Real: heartbeatLocation / splitHeartbeats / extractLocation;
// prismaDeviceLocationRepository's queries; processEnvelope with ECDSA
// verification; createApp() over HTTP (API-key + HMAC middleware, the
// ingestion router) for the legacy and envelope paths.
// Doubles: FakeDatabase (test/fakePrisma.ts) instead of Postgres — its
// transaction is not isolated and its unique indexes are not enforced;
// MemoryEnvelopeRepository for the envelope store; Redis commands answered
// in-process.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/app";
import { computeSignature } from "../src/crypto/hmac";
import { encryptSecret } from "../src/crypto/secretBox";
import { processEnvelope } from "../src/ingestion/envelope";
import { extractLocation } from "../src/ingestion/location";
import {
  HEARTBEAT_MAX_AGE_MS,
  heartbeatLocation,
  LOCATION_HEARTBEAT_ID,
  prismaDeviceLocationRepository,
  splitHeartbeats,
  TRAIL_MAX_POINTS,
  TRAIL_RETENTION_DAYS,
} from "../src/location/deviceLocations";
import { redis } from "../src/redis/client";
import { FakeDatabase, installFakePrisma, Row } from "./fakePrisma";
import { MemoryEnvelopeRepository, makeDevice, signEnvelope } from "./support";

const NOW = Date.UTC(2026, 9, 7, 12, 0, 0);
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

/** Evidence exactly as the engine's RaspLocationHeartbeat sends it. */
const heartbeatEvidence = (lat: unknown = 21.045, lon: unknown = 79.038, isMock = false, capturedAt = NOW - 5_000) => [
  { key: "location_opt_in", value: true, note: null },
  { key: "latitude", value: lat, note: null },
  { key: "longitude", value: lon, note: null },
  { key: "location_accuracy_m", value: 14, note: null },
  { key: "location_captured_at_millis", value: capturedAt, note: null },
  { key: "location_fix_age_seconds", value: 5, note: null },
  { key: "location_is_mock", value: isMock, note: null },
];
const sharingOffEvidence = [
  { key: "location_opt_in", value: false, note: null },
  { key: "location_sharing", value: "off", note: null },
];
const heartbeat = (evidence: unknown, at = NOW) => ({
  detectorId: LOCATION_HEARTBEAT_ID, status: "UNKNOWN", evidence, reason: "Location heartbeat (not a security verdict)", observedAtMillis: at,
});

describe("heartbeat evidence", () => {
  test("opted in with valid coordinates: a point, with the mock flag", () => {
    const decision = heartbeatLocation(heartbeatEvidence(21.045, 79.038, true));
    assert.equal(decision.kind, "point");
    if (decision.kind !== "point") return;
    assert.deepEqual(decision.location, { latitude: 21.045, longitude: 79.038, accuracyM: 14, capturedAt: new Date(NOW - 5_000) });
    assert.equal(decision.isMock, true);
    assert.equal((heartbeatLocation(heartbeatEvidence()) as { isMock: boolean }).isMock, false);
  });

  test("sharing turned off, or coordinates without opt-in: clear", () => {
    assert.deepEqual(heartbeatLocation(sharingOffEvidence), { kind: "clear" });
    const withoutOptIn = heartbeatEvidence().filter((e) => e.key !== "location_opt_in");
    assert.deepEqual(heartbeatLocation(withoutOptIn), { kind: "clear" });
    assert.deepEqual(heartbeatLocation([]), { kind: "clear" });
  });

  test("opted in but unusable coordinates: invalid (ignored)", () => {
    for (const [lat, lon] of [[91, 10], [10, 181], ["21.0", 79], [null, 79]]) {
      assert.deepEqual(heartbeatLocation(heartbeatEvidence(lat, lon)), { kind: "invalid" }, `${lat},${lon}`);
    }
  });

  test("without opt-in every heartbeat location key is removed from evidence", () => {
    const withoutOptIn = heartbeatEvidence().filter((e) => e.key !== "location_opt_in");
    const x = extractLocation([...withoutOptIn, { key: "other", value: 1, note: null }]);
    assert.equal(x.location, null);
    assert.deepEqual((x.evidence as { key: string }[]).map((e) => e.key), ["other"]);
  });

  test("splitHeartbeats separates heartbeats from detector results", () => {
    const results = [{ detectorId: "root_jailbreak" }, { detectorId: LOCATION_HEARTBEAT_ID }, { detectorId: "mitm" }];
    const { heartbeats, others } = splitHeartbeats(results);
    assert.deepEqual(heartbeats.map((r) => r.detectorId), [LOCATION_HEARTBEAT_ID]);
    assert.deepEqual(others.map((r) => r.detectorId), ["root_jailbreak", "mitm"]);
  });
});

describe("prismaDeviceLocationRepository", () => {
  let db: FakeDatabase;
  let restore: () => void = () => {};
  const point = (lat: number, lon: number) => ({ latitude: lat, longitude: lon, accuracyM: 14, capturedAt: new Date(NOW) });
  const record = (overrides: Partial<Parameters<typeof prismaDeviceLocationRepository.record>[0]> = {}) =>
    prismaDeviceLocationRepository.record({
      applicationId: "app-1", deviceId: "device-1", counter: null, location: point(21.045, 79.038), isMock: false,
      receivedAt: new Date(NOW), ...overrides,
    });
  const latest = (applicationId = "app-1", deviceId = "device-1") =>
    db.rows("deviceLocation").filter((r) => r.applicationId === applicationId && r.deviceId === deviceId);
  const trail = (applicationId = "app-1", deviceId = "device-1") =>
    db.rows("deviceLocationPoint").filter((r) => r.applicationId === applicationId && r.deviceId === deviceId);

  before(() => {
    db = new FakeDatabase();
    restore = installFakePrisma(db);
  });
  after(() => restore());

  test("one row per device: the latest point is updated, not appended", async () => {
    assert.equal(await record({ counter: 5n }), "updated");
    assert.equal(await record({ counter: 6n, location: point(21.046, 79.039), isMock: true, receivedAt: new Date(NOW + MINUTE) }), "updated");
    const rows = latest();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].latitude, 21.046);
    assert.equal(rows[0].longitude, 79.039);
    assert.equal(rows[0].isMock, true);
    assert.equal(rows[0].lastCounter, 6n);
    assert.deepEqual(rows[0].receivedAt, new Date(NOW + MINUTE));
    assert.equal(trail().length, 2);
  });

  test("an envelope counter that does not increase changes nothing", async () => {
    assert.equal(await record({ counter: 6n, location: point(1, 1) }), "counter_not_increasing");
    assert.equal(await record({ counter: 2n, location: point(1, 1) }), "counter_not_increasing");
    assert.equal(latest()[0].latitude, 21.046);
    assert.equal(trail().length, 2);
  });

  test("the trail keeps the newest TRAIL_MAX_POINTS points", async () => {
    for (let i = 0; i < TRAIL_MAX_POINTS + 5; i++) {
      await record({ deviceId: "device-trail", location: point(10 + i / 1000, 20), receivedAt: new Date(NOW + i * MINUTE) });
    }
    const points = trail("app-1", "device-trail").sort((a, b) => (a.receivedAt as Date).getTime() - (b.receivedAt as Date).getTime());
    assert.equal(points.length, TRAIL_MAX_POINTS);
    assert.deepEqual(points[0].receivedAt, new Date(NOW + 5 * MINUTE));
    assert.equal(latest("app-1", "device-trail").length, 1);
  });

  test(`trail points older than ${TRAIL_RETENTION_DAYS} days are removed`, async () => {
    db.insert("deviceLocationPoint", { applicationId: "app-1", deviceId: "device-old", latitude: 1, longitude: 1, receivedAt: new Date(NOW - (TRAIL_RETENTION_DAYS + 1) * DAY) });
    db.insert("deviceLocationPoint", { applicationId: "app-1", deviceId: "device-old", latitude: 2, longitude: 2, receivedAt: new Date(NOW - DAY) });
    await record({ deviceId: "device-old" });
    assert.deepEqual(trail("app-1", "device-old").map((p) => p.latitude).sort(), [2, 21.045]);
  });

  test("sharing turned off clears the stored point and the whole trail of that device only", async () => {
    await record({ applicationId: "app-2", deviceId: "device-1" });
    assert.equal(await record({ location: null, isMock: null, counter: 7n }), "cleared");
    const [row] = latest();
    assert.equal(row.latitude, null);
    assert.equal(row.longitude, null);
    assert.equal(row.accuracyM, null);
    assert.equal(row.isMock, null);
    assert.equal(row.lastCounter, 7n);
    assert.equal(trail().length, 0);
    // Same device id in another application: untouched (applications are separate).
    assert.equal(latest("app-2", "device-1")[0].latitude, 21.045);
    assert.equal(trail("app-2", "device-1").length, 1);
  });

  test("the HMAC path has no counter: repeated heartbeats are accepted", async () => {
    assert.equal(await record({ deviceId: "legacy-1" }), "updated");
    assert.equal(await record({ deviceId: "legacy-1" }), "updated");
    assert.equal(latest("app-1", "legacy-1")[0].lastCounter, 0n);
  });
});

describe("heartbeat envelopes (processEnvelope)", () => {
  let db: FakeDatabase;
  let restore: () => void = () => {};
  before(() => {
    db = new FakeDatabase();
    restore = installFakePrisma(db);
  });
  after(() => restore());

  function setup(deviceId: string | null = "device-1") {
    const device = makeDevice();
    const repo = new MemoryEnvelopeRepository();
    repo.addDevice(device.deviceKeyId, {
      id: `reg-${device.deviceKeyId}`, applicationId: "app-1", appId: device.appId, deviceId, publicKey: device.publicKeyB64,
    });
    const send = (body: string, now = NOW) =>
      processEnvelope({ rawBody: body, applicationId: "app-1", now, repo, locations: prismaDeviceLocationRepository });
    return { device, repo, send };
  }
  const located = (deviceId: string) => db.rows("deviceLocation").find((r) => r.deviceId === deviceId);

  test("heartbeat-only envelope: 202, latest point stored, no envelope and no security event stored", async () => {
    const { device, repo, send } = setup();
    const { body } = signEnvelope(device, NOW, { monotonicCounter: 3, detectorResults: [heartbeat(heartbeatEvidence())] });
    const outcome = await send(body);
    assert.equal(outcome.status, 202);
    assert.deepEqual(outcome.body, { accepted: 0, location: "updated" });
    assert.equal(repo.envelopes.length, 0);
    assert.equal(repo.events.length, 0);
    const row = located("device-1")!;
    assert.equal(row.latitude, 21.045);
    assert.equal(row.longitude, 79.038);
    assert.equal(row.isMock, false);
    assert.equal(row.lastCounter, 3n);
  });

  test("a device registered without a device id is keyed by its key id (as its events are)", async () => {
    const { device, send } = setup(null);
    const { body } = signEnvelope(device, NOW, { detectorResults: [heartbeat(heartbeatEvidence())] });
    assert.equal((await send(body)).status, 202);
    assert.ok(located(device.deviceKeyId));
  });

  test("replayed heartbeat: 409, stale: 422, from the future: 422, bad signature: 401", async () => {
    const { device, send } = setup("device-replay");
    const first = signEnvelope(device, NOW, { monotonicCounter: 10, detectorResults: [heartbeat(heartbeatEvidence())] });
    assert.equal((await send(first.body)).status, 202);
    assert.deepEqual((await send(first.body)).body, { error: "COUNTER_NOT_INCREASING" });

    const stale = signEnvelope(device, NOW - HEARTBEAT_MAX_AGE_MS - 1, { monotonicCounter: 11, detectorResults: [heartbeat(heartbeatEvidence())] });
    assert.deepEqual(await send(stale.body), { status: 422, body: { error: "HEARTBEAT_TOO_OLD" } });
    const future = signEnvelope(device, NOW + 10 * MINUTE, { monotonicCounter: 12, detectorResults: [heartbeat(heartbeatEvidence())] });
    assert.deepEqual(await send(future.body), { status: 422, body: { error: "EVENT_FROM_FUTURE" } });

    const forged = JSON.parse(signEnvelope(device, NOW, { monotonicCounter: 13, detectorResults: [heartbeat(heartbeatEvidence())] }).body);
    forged.detectorResults[0].evidence[1].value = 1.5;
    assert.equal((await send(JSON.stringify(forged))).status, 401);
    assert.equal(located("device-replay")!.latitude, 21.045);
  });

  test("sharing turned off: 202 cleared; coordinates sent without opt-in are not stored", async () => {
    const { device, send } = setup("device-off");
    assert.equal((await send(signEnvelope(device, NOW, { monotonicCounter: 1, detectorResults: [heartbeat(heartbeatEvidence())] }).body)).status, 202);
    const off = await send(signEnvelope(device, NOW, { monotonicCounter: 2, detectorResults: [heartbeat(sharingOffEvidence)] }).body);
    assert.deepEqual(off.body, { accepted: 0, location: "cleared" });
    assert.equal(located("device-off")!.latitude, null);

    const noOptIn = heartbeatEvidence(30, 40).filter((e) => e.key !== "location_opt_in");
    assert.equal((await send(signEnvelope(device, NOW, { monotonicCounter: 3, detectorResults: [heartbeat(noOptIn)] }).body)).status, 202);
    assert.equal(located("device-off")!.latitude, null);
    assert.equal(db.rows("deviceLocationPoint").filter((p) => p.deviceId === "device-off").length, 0);
  });

  test("heartbeat together with detector results: the results are stored, the heartbeat only as location", async () => {
    const { device, repo, send } = setup("device-mixed");
    const results = [
      { detectorId: "root_jailbreak", status: "DETECTED", evidence: [{ key: "signal", value: "su_binary", note: "hard" }], observedAtMillis: NOW },
      heartbeat(heartbeatEvidence()),
    ];
    const outcome = await send(signEnvelope(device, NOW, { monotonicCounter: 4, detectorResults: results }).body);
    assert.equal(outcome.status, 201);
    assert.deepEqual(outcome.body, { accepted: 1 });
    assert.deepEqual(repo.events.map((e) => e.detectorId), ["root_jailbreak"]);
    assert.equal(located("device-mixed")!.latitude, 21.045);
  });

  test("without a location store the heartbeat is acknowledged as ignored", async () => {
    const { device, repo } = setup("device-nostore");
    const { body } = signEnvelope(device, NOW, { detectorResults: [heartbeat(heartbeatEvidence())] });
    const outcome = await processEnvelope({ rawBody: body, applicationId: "app-1", now: NOW, repo });
    assert.deepEqual(outcome, { status: 202, body: { accepted: 0, location: "ignored" } });
  });
});

describe("POST /v1/events over HTTP", () => {
  const SECRET = crypto.randomBytes(32).toString("base64url");
  const ENV = { JWT_SECRET: crypto.randomBytes(32).toString("hex"), CREDENTIAL_ENCRYPTION_KEY: crypto.randomBytes(32).toString("hex") };
  const savedEnv: Record<string, string | undefined> = {};
  const savedRedis: Record<string, unknown> = {};
  const device = makeDevice("com.example.bank");
  let db: FakeDatabase;
  let restorePrisma: () => void = () => {};
  let server: http.Server;
  let base = "";

  before(async () => {
    for (const [key, value] of Object.entries(ENV)) {
      savedEnv[key] = process.env[key];
      process.env[key] = value;
    }
    const pipeline = { lpush: () => pipeline, ltrim: () => pipeline, expire: () => pipeline, hincrby: () => pipeline, exec: async () => [] };
    const fakeRedis: Record<string, unknown> = {
      incr: async () => 1, expire: async () => 1, set: async () => "OK", get: async () => null, pipeline: () => pipeline,
    };
    const client = redis as unknown as Record<string, unknown>;
    for (const [method, impl] of Object.entries(fakeRedis)) {
      savedRedis[method] = client[method];
      client[method] = impl;
    }
    db = new FakeDatabase();
    db.insert("organization", { id: "org-1", name: "Bank Org" });
    db.insert("application", { id: "app-1", name: "Bank App", platform: "FLUTTER", organizationId: "org-1", legacyIngestionEnabled: true });
    db.insert("apiCredential", { id: "cred-1", applicationId: "app-1", apiKey: "rasp_live_cred1", apiSecretEncrypted: encryptSecret(SECRET) });
    db.insert("deviceRegistration", {
      id: "reg-1", applicationId: "app-1", appId: device.appId, deviceId: "phone-1", deviceKeyId: device.deviceKeyId,
      publicKey: device.publicKeyB64, lastCounter: 0n, signingCertSha256: null,
    });
    restorePrisma = installFakePrisma(db);
    server = createApp().listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", () => r()));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    restorePrisma();
    const client = redis as unknown as Record<string, unknown>;
    for (const [method, original] of Object.entries(savedRedis)) client[method] = original;
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  });

  async function post(rawBody: string, hmac: boolean) {
    const headers: Record<string, string> = { "Content-Type": "application/json", "X-Api-Key": "rasp_live_cred1" };
    if (hmac) {
      const timestamp = Date.now().toString();
      headers["X-Timestamp"] = timestamp;
      headers["X-Signature"] = computeSignature(SECRET, timestamp, Buffer.from(rawBody, "utf8"));
    }
    const res = await fetch(`${base}/v1/events`, { method: "POST", headers, body: rawBody });
    return { status: res.status, body: (await res.json()) as Row };
  }
  const legacy = (evidence: unknown, deviceId = "legacy-phone") => ({
    detectorId: LOCATION_HEARTBEAT_ID, status: "UNKNOWN", evidence, deviceId, osPlatform: "android",
  });

  test("legacy HMAC heartbeat: 202, latest point stored, no security event", async () => {
    const res = await post(JSON.stringify({ events: [legacy(heartbeatEvidence())] }), true);
    assert.deepEqual(res, { status: 202, body: { accepted: 0, location: "updated" } });
    assert.equal(db.rows("securityEvent").length, 0);
    const row = db.rows("deviceLocation").find((r) => r.deviceId === "legacy-phone")!;
    assert.equal(row.applicationId, "app-1");
    assert.equal(row.latitude, 21.045);
  });

  test("legacy batch with a heartbeat and a detector result: only the result is a security event", async () => {
    const batch = { events: [legacy(sharingOffEvidence), { detectorId: "root_jailbreak", status: "SECURE", deviceId: "legacy-phone" }] };
    const res = await post(JSON.stringify(batch), true);
    assert.deepEqual(res, { status: 201, body: { accepted: 1 } });
    assert.deepEqual(db.rows("securityEvent").map((e) => e.detectorId), ["root_jailbreak"]);
    assert.equal(db.rows("deviceLocation").find((r) => r.deviceId === "legacy-phone")!.latitude, null);
  });

  test("legacy heartbeat with a wrong HMAC is refused before anything is stored", async () => {
    const rawBody = JSON.stringify({ events: [legacy(heartbeatEvidence(), "forged-phone")] });
    const res = await fetch(`${base}/v1/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Api-Key": "rasp_live_cred1", "X-Timestamp": Date.now().toString(), "X-Signature": "0".repeat(64) },
      body: rawBody,
    });
    assert.equal(res.status, 401);
    assert.equal(db.rows("deviceLocation").some((r) => r.deviceId === "forged-phone"), false);
  });

  test("signed heartbeat envelope: 202 and the registered device's point is stored", async () => {
    const now = Date.now();
    const { body } = signEnvelope(device, now, {
      monotonicCounter: 1, detectorResults: [heartbeat(heartbeatEvidence(21.045, 79.038, false, now - 5_000), now)],
    });
    const res = await post(body, false);
    assert.deepEqual(res, { status: 202, body: { accepted: 0, location: "updated" } });
    const row = db.rows("deviceLocation").find((r) => r.deviceId === "phone-1")!;
    assert.equal(row.applicationId, "app-1");
    assert.equal(row.longitude, 79.038);
    assert.equal(db.rows("deviceLocationPoint").filter((p) => p.deviceId === "phone-1").length, 1);
  });

  // F-14: per-application switch for legacy batches; attestation policy on envelopes.
  test("legacy batches are refused with 403 when the application has legacy ingestion off", async () => {
    const app = db.rows("application").find((a) => a.id === "app-1")!;
    app.legacyIngestionEnabled = false;
    try {
      const res = await post(JSON.stringify({ events: [legacy({ location_opt_in: false })] }), true);
      assert.deepEqual(res, { status: 403, body: { error: "LEGACY_INGESTION_DISABLED" } });
    } finally {
      app.legacyIngestionEnabled = true;
    }
  });

  test("REQUIRE_HARDWARE: an envelope from a key without verified attestation gets 401 DEVICE_NOT_ATTESTED", async () => {
    const app = db.rows("application").find((a) => a.id === "app-1")!;
    app.attestationPolicy = "REQUIRE_HARDWARE";
    try {
      const now = Date.now();
      const { body } = signEnvelope(device, now, {
        monotonicCounter: 50, detectorResults: [heartbeat(heartbeatEvidence(21.045, 79.038, false, now - 5_000), now)],
      });
      const res = await post(body, false);
      assert.deepEqual(res, { status: 401, body: { error: "DEVICE_NOT_ATTESTED" } });
    } finally {
      app.attestationPolicy = "RECORD";
    }
  });
});
