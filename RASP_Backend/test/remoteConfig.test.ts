// Signed remote configuration (Task 10.0): validation, signing, versions,
// rollback, audit, org scoping, limits, the device endpoint, the ip-risk
// country lists and the cross-language fixture the engine verifies.
//
// Real: createApp() with every router and middleware over real HTTP,
// Ed25519 signing and verification (node:crypto), zod validation, JWT.
// Doubles: FakeDatabase (test/fakePrisma.ts) instead of Postgres; the Redis
// client's commands answered in memory.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { AddressInfo } from "node:net";
import jwt from "jsonwebtoken";
import { createApp } from "../src/app";
import { redis } from "../src/redis/client";
import { encryptSecret } from "../src/crypto/secretBox";
import { prismaApplicationPolicy } from "../src/ipRisk/routes";
import { parsePublishBody, parseRemoteSettings, REMOTE_CONFIG_BOUNDS, REMOTE_MANAGEABLE_DETECTORS, SETTING_FIELDS } from "../src/remoteConfig/settings";
import { configPayloadText, configPublicKey, resetConfigKeyCacheForTests, signConfig } from "../src/remoteConfig/signing";
import { FakeDatabase, installFakePrisma, Row } from "./fakePrisma";

const random = (bytes: number) => crypto.randomBytes(bytes).toString("hex");
const SIGNING = crypto.generateKeyPairSync("ed25519").privateKey;
const SIGNING_B64 = (SIGNING.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64");
const ENV: Record<string, string> = {
  JWT_SECRET: random(32),
  CREDENTIAL_ENCRYPTION_KEY: random(32),
  CONFIG_SIGNING_KEY: SIGNING_B64,
  CONFIG_RATE_LIMIT_PER_DEVICE: "3",
};

const db = new FakeDatabase();
const saved: Record<string, string | undefined> = {};
const savedRedis: Record<string, unknown> = {};
const counters = new Map<string, number>();
let restorePrisma = () => {};
let server: http.Server;
let base = "";

const token = (userId: string, organizationId: string, role: string) => jwt.sign({ userId, organizationId, role }, ENV.JWT_SECRET);
const owner = () => token("u-owner", "org-1", "OWNER");

async function call(method: string, url: string, options: { as?: string | null; body?: unknown; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { ...options.headers };
  const auth = options.as === undefined ? owner() : options.as;
  if (auth) headers.Authorization = `Bearer ${auth}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`${base}${url}`, { method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  const text = await res.text();
  return { status: res.status, body: text ? (JSON.parse(text) as Row) : null, headers: res.headers };
}
const device = (headers: Record<string, string> = {}) =>
  call("GET", "/v1/config", { as: null, headers: { "X-Api-Key": "rasp_live_a", ...headers } });
const publicKeyObject = () => crypto.createPublicKey({ key: Buffer.from(configPublicKey()!, "base64"), format: "der", type: "spki" });
const verifies = (signed: Row, key = publicKeyObject()) =>
  crypto.verify(null, Buffer.from(signed.payload as string, "utf8"), key, Buffer.from(signed.signature as string, "base64"));

before(async () => {
  for (const [k, v] of Object.entries(ENV)) {
    saved[k] = process.env[k];
    process.env[k] = v;
  }
  const client = redis as unknown as Record<string, unknown>;
  const fake: Record<string, unknown> = {
    incr: async (key: string) => {
      counters.set(key, (counters.get(key) ?? 0) + 1);
      return counters.get(key);
    },
    expire: async () => 1,
  };
  for (const [m, impl] of Object.entries(fake)) {
    savedRedis[m] = client[m];
    client[m] = impl;
  }
  db.insert("organization", { id: "org-1", name: "Bank" });
  db.insert("organization", { id: "org-2", name: "Other" });
  db.insert("user", { id: "u-owner", email: "owner@example.test", passwordHash: "x", role: "OWNER", organizationId: "org-1" });
  db.insert("user", { id: "u-other", email: "other@example.test", passwordHash: "x", role: "OWNER", organizationId: "org-2" });
  db.insert("user", { id: "u-m", email: "member@example.test", passwordHash: "x", role: "MEMBER", organizationId: "org-1" });
  db.insert("application", { id: "app-a", name: "A", platform: "FLUTTER", organizationId: "org-1", ipBlockedCountries: ["RU"], ipAllowedCountries: [] });
  db.insert("application", { id: "app-b", name: "B", platform: "FLUTTER", organizationId: "org-2" });
  db.insert("apiCredential", { id: "cred-a", applicationId: "app-a", apiKey: "rasp_live_a", apiSecretEncrypted: encryptSecret("s".repeat(48)) });
  db.insert("apiCredential", { id: "cred-r", applicationId: "app-a", apiKey: "rasp_live_revoked", apiSecretEncrypted: encryptSecret("r".repeat(48)), status: "REVOKED" });
  restorePrisma = installFakePrisma(db);
  server = createApp().listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  restorePrisma();
  const client = redis as unknown as Record<string, unknown>;
  for (const [m, impl] of Object.entries(savedRedis)) client[m] = impl;
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

beforeEach(() => {
  counters.clear();
  process.env.CONFIG_SIGNING_KEY = SIGNING_B64;
  resetConfigKeyCacheForTests();
});

// ── validation ───────────────────────────────────────────────────────────

test("bounds are inclusive: poll 2-60 s, heartbeat 10-300 s, location 30-600 s, thresholds 1-100", () => {
  const B = REMOTE_CONFIG_BOUNDS;
  for (const [field, { min, max }] of [
    ["pollIntervalSeconds", B.pollIntervalSeconds], ["heartbeatIntervalSeconds", B.heartbeatIntervalSeconds],
    ["locationHeartbeatIntervalSeconds", B.locationHeartbeatIntervalSeconds], ["riskHighThreshold", B.riskThreshold],
    ["reputationRefreshHours", B.reputationRefreshHours],
  ] as const) {
    assert.ok(parseRemoteSettings({ [field]: min }).ok, `${field}=${min}`);
    assert.ok(parseRemoteSettings({ [field]: max }).ok, `${field}=${max}`);
    assert.equal(parseRemoteSettings({ [field]: min - 1 }).ok, false, `${field}=${min - 1}`);
    assert.equal(parseRemoteSettings({ [field]: max + 1 }).ok, false, `${field}=${max + 1}`);
    assert.equal(parseRemoteSettings({ [field]: min + 0.5 }).ok, false, `${field} must be an integer`);
  }
  assert.deepEqual([B.pollIntervalSeconds, B.heartbeatIntervalSeconds, B.locationHeartbeatIntervalSeconds], [
    { min: 2, max: 60 }, { min: 10, max: 300 }, { min: 30, max: 600 },
  ]);
  assert.equal(parseRemoteSettings({ riskMediumThreshold: 60, riskHighThreshold: 60 }).ok, false, "medium below high");
  assert.ok(parseRemoteSettings({ stepUpThreshold: null }).ok);
});

test("unknown fields, forbidden fields and unknown detectors are rejected, not ignored", () => {
  for (const settings of [
    { ingestionUrl: "https://attacker.example" }, { apiKey: "x" }, { certificatePins: [] }, { useEvidenceEnvelope: false },
    { screenshotProtection: false }, { detectors: { not_a_detector: true } }, { detectors: { screenshot_protection: false } },
    { detectors: { remote_config_rejected: false } },
  ]) {
    assert.equal(parseRemoteSettings(settings).ok, false, JSON.stringify(settings));
  }
  assert.equal(parsePublishBody({ settings: {}, extra: 1 }).ok, false);
  assert.equal(parsePublishBody({ settings: {}, expiresInDays: 181 }).ok, false);
  assert.equal(parseRemoteSettings({ allowedCountries: ["India"] }).ok, false);
});

test("settings are normalized: fixed field order, sorted detectors, unique upper-case countries", () => {
  const r = parseRemoteSettings({ blockedCountries: ["kp", "KP", "ir"], detectors: { vpn: true, frida: false }, pollIntervalSeconds: 5 });
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(JSON.stringify(r.data), '{"detectors":{"frida":false,"vpn":true},"pollIntervalSeconds":5,"blockedCountries":["IR","KP"]}');
});

// ── signing ──────────────────────────────────────────────────────────────

test("the signature covers the exact payload: any change, or another key, fails to verify", () => {
  const row = { applicationId: "app-a", version: 3, createdAt: new Date("2026-10-13T00:00:00Z"), expiresAt: new Date("2026-11-12T00:00:00Z"), payload: { pollIntervalSeconds: 5 } };
  const signed = signConfig(row, SIGNING);
  assert.equal(signed.payload, configPayloadText(row));
  assert.equal(
    signed.payload,
    '{"schema":1,"applicationId":"app-a","version":3,"issuedAt":"2026-10-13T00:00:00.000Z","expiresAt":"2026-11-12T00:00:00.000Z","settings":{"pollIntervalSeconds":5}}',
  );
  assert.ok(verifies(signed as unknown as Row));
  assert.equal(verifies({ ...signed, payload: signed.payload.replace('"version":3', '"version":4') }), false, "tampered");
  const otherKey = crypto.createPublicKey(crypto.generateKeyPairSync("ed25519").privateKey);
  assert.equal(verifies(signed as unknown as Row, otherKey), false, "another key");
});

// ── dashboard + device endpoints ─────────────────────────────────────────

test("publish → versions only grow; the device gets the active one signed; 304 for the version it has", async () => {
  assert.equal((await device()).status, 404);
  const one = await call("PUT", "/v1/apps/app-a/remote-config", { body: { settings: { pollIntervalSeconds: 5 } } });
  assert.deepEqual([one.status, one.body], [201, { version: 1 }]);
  const two = await call("PUT", "/v1/apps/app-a/remote-config", { body: { settings: { pollIntervalSeconds: 8, detectors: { root_jailbreak: true } }, expiresInDays: 7 } });
  assert.deepEqual([two.status, two.body], [201, { version: 2 }]);
  assert.deepEqual(db.rows("remoteConfig").filter((r) => r.applicationId === "app-a").map((r) => [r.version, r.active]), [[1, false], [2, true]]);

  const got = await device({ "X-Device-Key-Id": "KEY-1" });
  assert.equal(got.status, 200);
  assert.ok(verifies(got.body!));
  const payload = JSON.parse(got.body!.payload as string);
  assert.deepEqual([payload.applicationId, payload.version, payload.settings], ["app-a", 2, { detectors: { root_jailbreak: true }, pollIntervalSeconds: 8 }]);
  assert.equal(got.headers.get("etag"), '"2"');
  assert.equal(got.headers.get("cache-control"), "no-store");
  assert.equal((await device({ "If-None-Match": '"2"' })).status, 304);
  assert.equal((await device({ "If-None-Match": '"1"' })).status, 200, "an older version gets the new one");
});

test("rollback publishes a copy of an older version as a NEW higher version, audited", async () => {
  const before = db.rows("remoteConfig").filter((r) => r.applicationId === "app-a").length;
  const rolled = await call("POST", "/v1/apps/app-a/remote-config/rollback", { body: { version: 1 } });
  assert.deepEqual([rolled.status, rolled.body], [201, { version: before + 1, copiedFromVersion: 1 }]);
  const active = db.rows("remoteConfig").find((r) => r.applicationId === "app-a" && r.active)!;
  assert.deepEqual([active.version, active.copiedFromVersion, active.payload], [before + 1, 1, { pollIntervalSeconds: 5 }]);
  assert.equal((await call("POST", "/v1/apps/app-a/remote-config/rollback", { body: { version: 99 } })).status, 404);
  assert.equal((await call("POST", "/v1/apps/app-a/remote-config/rollback", { body: { version: 1, active: true } })).status, 400);

  const audit = db.rows("remoteConfigAudit").filter((a) => a.applicationId === "app-a");
  assert.deepEqual(audit.map((a) => [a.action, a.version, a.fromVersion, a.performedByUserId]), [
    ["PUBLISHED", 1, null, "u-owner"], ["PUBLISHED", 2, null, "u-owner"], ["ROLLED_BACK", 3, 1, "u-owner"],
  ]);
  assert.deepEqual(audit[2].changes, [
    { field: "detectors", oldValue: { root_jailbreak: true }, newValue: null },
    { field: "pollIntervalSeconds", oldValue: 8, newValue: 5 },
  ]);

  const view = await call("GET", "/v1/apps/app-a/remote-config");
  assert.equal(view.status, 200);
  assert.equal((view.body!.current as Row).version, 3);
  assert.deepEqual((view.body!.history as Row[]).map((h) => h.version), [3, 2, 1]);
  assert.equal((view.body!.audit as Row[])[0].performedByEmail, "owner@example.test");
  assert.equal(view.body!.signingConfigured, true);
  assert.deepEqual((view.body!.limits as Row).detectors, [...REMOTE_MANAGEABLE_DETECTORS]);
});

test("another organization's application: 404 on every dashboard endpoint, nothing written", async () => {
  const rows = db.rows("remoteConfig").length;
  for (const [method, url, body] of [
    ["GET", "/v1/apps/app-b/remote-config", undefined], ["PUT", "/v1/apps/app-b/remote-config", { settings: {} }],
    ["POST", "/v1/apps/app-b/remote-config/rollback", { version: 1 }], ["GET", "/v1/apps/app-a/remote-config", undefined],
  ] as const) {
    const as = url.includes("app-a") ? token("u-other", "org-2", "OWNER") : owner();
    assert.deepEqual([(await call(method, url, { body, as })).status, method, url], [404, method, url]);
  }
  assert.equal(db.rows("remoteConfig").length, rows);
  assert.equal((await call("GET", "/v1/apps/app-a/remote-config", { as: token("u-m", "org-1", "MEMBER") })).status, 403);
});

test("invalid bodies are 400 and publish nothing", async () => {
  const rows = db.rows("remoteConfig").length;
  for (const body of [{ settings: { pollIntervalSeconds: 1 } }, { settings: { ingestionUrl: "https://x" } }, { settings: {}, version: 9 }, {}]) {
    assert.equal((await call("PUT", "/v1/apps/app-a/remote-config", { body })).status, 400, JSON.stringify(body));
  }
  assert.equal(db.rows("remoteConfig").length, rows);
});

test("no signing key: publishing and serving answer 503, never an unsigned config", async () => {
  delete process.env.CONFIG_SIGNING_KEY;
  resetConfigKeyCacheForTests();
  const rows = db.rows("remoteConfig").length;
  assert.deepEqual((await call("PUT", "/v1/apps/app-a/remote-config", { body: { settings: {} } })).body, { error: "REMOTE_CONFIG_SIGNING_UNAVAILABLE" });
  assert.equal(db.rows("remoteConfig").length, rows);
  const got = await device();
  assert.deepEqual([got.status, got.body], [503, { error: "REMOTE_CONFIG_SIGNING_UNAVAILABLE" }]);
  assert.equal((await call("GET", "/v1/apps/app-a/remote-config")).body!.signingConfigured, false);
});

test("an expired active version is not served; a revoked API key is refused", async () => {
  const active = db.rows("remoteConfig").find((r) => r.applicationId === "app-a" && r.active)!;
  const expiresAt = active.expiresAt;
  active.expiresAt = new Date(Date.now() - 1000);
  try {
    assert.deepEqual((await device()).body, { error: "REMOTE_CONFIG_EXPIRED" });
  } finally {
    active.expiresAt = expiresAt;
  }
  assert.equal((await device({ "X-Api-Key": "rasp_live_revoked" })).status, 401);
  assert.equal((await call("GET", "/v1/config", { as: null })).status, 401);
});

test("rate limits: per device key (CONFIG_RATE_LIMIT_PER_DEVICE), then the next device still works", async () => {
  for (let i = 0; i < 3; i++) assert.equal((await device({ "X-Device-Key-Id": "KEY-RL" })).status, 200);
  assert.deepEqual((await device({ "X-Device-Key-Id": "KEY-RL" })).body, { error: "RATE_LIMIT_EXCEEDED", limit: "device" });
  assert.equal((await device({ "X-Device-Key-Id": "KEY-OTHER" })).status, 200);
  counters.clear();
  process.env.CONFIG_RATE_LIMIT_PER_IP = "1";
  try {
    assert.equal((await device()).status, 200);
    assert.deepEqual((await device()).body, { error: "RATE_LIMIT_EXCEEDED", limit: "ip" });
  } finally {
    delete process.env.CONFIG_RATE_LIMIT_PER_IP;
  }
});

test("ip-risk uses the active config's country lists in place of the app's own; without one, the app's", async () => {
  assert.deepEqual(await prismaApplicationPolicy("app-a"), { blocked: ["RU"], allowed: [] });
  await call("PUT", "/v1/apps/app-a/remote-config", { body: { settings: { blockedCountries: ["kp"], allowedCountries: ["IN"] } } });
  assert.deepEqual(await prismaApplicationPolicy("app-a"), { blocked: ["KP"], allowed: ["IN"] });
  await call("PUT", "/v1/apps/app-a/remote-config", { body: { settings: { allowedCountries: ["IN"] } } });
  assert.deepEqual(await prismaApplicationPolicy("app-a"), { blocked: ["RU"], allowed: ["IN"] }, "a list the config does not set stays the app's");
});

// ── cross-language fixture ───────────────────────────────────────────────

test("the fixture the engine verifies: backend-signed cases verify, tampered and foreign-key cases do not, limits match", () => {
  const fixture = JSON.parse(readFileSync(path.join(__dirname, "fixtures", "remote-config", "fixture.json"), "utf8"));
  assert.ok(!JSON.stringify(fixture).includes("PRIVATE"), "public key only");
  const key = crypto.createPublicKey({ key: Buffer.from(fixture.publicKey, "base64"), format: "der", type: "spki" });
  const c = fixture.cases as Record<string, Row>;
  for (const name of ["valid_v5", "valid_v6_empty", "older_v4", "expired_v7", "other_app_v8", "out_of_bounds_v9", "unknown_field_v10", "unknown_detector_v11"]) {
    assert.ok(verifies(c[name], key), name);
  }
  assert.equal(verifies(c.tampered_v5, key), false);
  assert.equal(verifies(c.wrong_key_v12, key), false);
  assert.deepEqual(fixture.limits, { fields: [...SETTING_FIELDS], detectors: [...REMOTE_MANAGEABLE_DETECTORS], bounds: REMOTE_CONFIG_BOUNDS },
    "regenerate with scripts/remote-config-fixture.ts after changing the rules");
});
