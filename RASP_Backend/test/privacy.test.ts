// Data retention and device erasure (WP-11 privacy).
// Real: runRetention / retentionSettings, eraseDevice and the privacy router
// over HTTP with requireAuth and the role check.
// Double: the in-memory Prisma stand-in (test/fakePrisma.ts).
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import { prisma } from "../src/db/prisma";
import { retentionSettings, runRetention } from "../src/privacy/retention";
import { privacyRouter } from "../src/privacy/deviceErasure";
import { FakeDatabase, installFakePrisma } from "./fakePrisma";

const SECRET = "test-jwt-secret-not-real";
const NOW = new Date("2026-10-09T12:00:00Z");
const daysAgo = (d: number) => new Date(NOW.getTime() - d * 24 * 60 * 60 * 1000);
const ENV_KEYS = ["JWT_SECRET", "RETENTION_SECURITY_EVENT_DAYS", "RETENTION_RISK_EVENT_DAYS", "RETENTION_DEVICE_LOCATION_DAYS"];
const saved: Record<string, string | undefined> = {};
let db: FakeDatabase;
let restorePrisma: () => void = () => {};
let server: import("node:http").Server;
let base = "";

function seed() {
  db = new FakeDatabase();
  db.insert("organization", { id: "org-1", name: "Bank" });
  db.insert("organization", { id: "org-2", name: "Other" });
  db.insert("user", { id: "u-owner", email: "o@b.test", passwordHash: "x", role: "OWNER", organizationId: "org-1" });
  db.insert("user", { id: "u-member", email: "m@b.test", passwordHash: "x", role: "MEMBER", organizationId: "org-1" });
  db.insert("application", { id: "app-1", name: "Bank App", platform: "FLUTTER", organizationId: "org-1" });
  db.insert("application", { id: "app-2", name: "Other App", platform: "FLUTTER", organizationId: "org-2" });
  db.insert("deviceRegistration", { id: "reg-1", applicationId: "app-1", appId: "com.bank", deviceId: "phone-hash", deviceKeyId: "key-1", publicKey: "p", attestationChain: [], attestationStatus: "PARSED", attestationDetails: {}, sdkVersion: "1" });
  db.insert("deviceRegistration", { id: "reg-2", applicationId: "app-1", appId: "com.bank", deviceId: null, deviceKeyId: "key-2", publicKey: "p", attestationChain: [], attestationStatus: "PARSED", attestationDetails: {}, sdkVersion: "1" });
  db.insert("evidenceEnvelope", { id: "env-old", eventId: "e-old", deviceRegistrationId: "reg-1", applicationId: "app-1", monotonicCounter: 1n, nonce: "n1", eventTime: daysAgo(200), receivedAt: daysAgo(200), signedPayload: "{}", signature: "s" });
  db.insert("evidenceEnvelope", { id: "env-new", eventId: "e-new", deviceRegistrationId: "reg-1", applicationId: "app-1", monotonicCounter: 2n, nonce: "n2", eventTime: daysAgo(1), receivedAt: daysAgo(1), signedPayload: "{}", signature: "s" });
  db.insert("securityEvent", { id: "se-old", applicationId: "app-1", detectorId: "vpn", status: "SECURE", deviceId: "phone-hash", envelopeId: "env-old", receivedAt: daysAgo(200) });
  db.insert("securityEvent", { id: "se-new", applicationId: "app-1", detectorId: "vpn", status: "SECURE", deviceId: "phone-hash", envelopeId: "env-new", receivedAt: daysAgo(1) });
  db.insert("securityEvent", { id: "se-other", applicationId: "app-1", detectorId: "vpn", status: "SECURE", deviceId: "key-2", receivedAt: daysAgo(1) });
  db.insert("securityEvent", { id: "se-app2", applicationId: "app-2", detectorId: "vpn", status: "SECURE", deviceId: "phone-hash", receivedAt: daysAgo(1) });
  db.insert("sessionEvent", { id: "ss-1", applicationId: "app-1", deviceRegistrationId: "reg-1", deviceKeyId: "key-1", eventId: "s1", nonce: "x", monotonicCounter: 1n, accountHash: "a", sessionHash: "b", sessionEvent: "login", eventTime: daysAgo(200), receivedAt: daysAgo(200), signature: "s", riskScore: 0, riskVerdict: "LOW" });
  db.insert("accountDeviceBinding", { id: "b-1", applicationId: "app-1", accountHash: "a", deviceKeyId: "key-1", deviceRegistrationId: "reg-1", firstSeenAt: daysAgo(300), lastSeenAt: daysAgo(200) });
  db.insert("deviceLocation", { id: "loc-1", applicationId: "app-1", deviceId: "phone-hash", latitude: 1, longitude: 2, receivedAt: daysAgo(40) });
  db.insert("deviceLocationPoint", { id: "pt-1", applicationId: "app-1", deviceId: "phone-hash", latitude: 1, longitude: 2, receivedAt: daysAgo(2) });
  restorePrisma = installFakePrisma(db);
}

before(async () => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  process.env.JWT_SECRET = SECRET;
  const app = express();
  app.use(express.json());
  app.use("/v1/privacy", privacyRouter);
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
beforeEach(() => {
  restorePrisma();
  seed();
});
after(async () => {
  restorePrisma();
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

const ids = (model: string) => db.rows(model).map((r) => r.id).sort();

test("retention: unset keeps everything; event periods are at least 8 days", async () => {
  for (const k of ENV_KEYS.slice(1)) delete process.env[k];
  assert.deepEqual(retentionSettings(), { securityEventDays: 0, riskEventDays: 0, deviceLocationDays: 0 });
  const r = await runRetention(NOW);
  assert.equal(Object.values(r).reduce((a, b) => a + b, 0), 0);
  process.env.RETENTION_SECURITY_EVENT_DAYS = "3";
  process.env.RETENTION_DEVICE_LOCATION_DAYS = "3";
  assert.deepEqual(retentionSettings(), { securityEventDays: 8, riskEventDays: 0, deviceLocationDays: 3 });
});

test("retention: only rows older than each period are deleted, events before their envelopes", async () => {
  const report = await runRetention(NOW, { securityEventDays: 180, riskEventDays: 180, deviceLocationDays: 30 }, prisma);
  assert.deepEqual(report, { securityEvents: 1, envelopes: 1, sessionEvents: 1, transactionEvents: 0, accountDeviceBindings: 1, deviceLocations: 1 });
  assert.deepEqual(ids("securityEvent"), ["se-app2", "se-new", "se-other"]);
  assert.deepEqual(ids("evidenceEnvelope"), ["env-new"]);
  assert.deepEqual(ids("deviceLocationPoint"), ["pt-1"], "the 7-day trail has its own limit");
});

const token = (user: string, role: string) => jwt.sign({ userId: user, organizationId: "org-1", role }, SECRET);
const erase = (device: string, user = "u-owner", role = "OWNER", app = "app-1") =>
  fetch(`${base}/v1/privacy/applications/${app}/devices/${encodeURIComponent(device)}`, {
    method: "DELETE", headers: { Authorization: `Bearer ${token(user, role)}` },
  }).then(async (r) => ({ status: r.status, body: (await r.json()) as Record<string, unknown> }));

test("erasure: everything about the device in this application goes, nothing else; the audit log says who", async () => {
  const r = await erase("phone-hash");
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.erased, {
    securityEvents: 2, envelopes: 2, sessionEvents: 1, transactionEvents: 0, accountDeviceBindings: 1,
    deviceRegistrations: 1, deviceLocations: 1, deviceLocationPoints: 1,
  });
  assert.deepEqual(ids("securityEvent"), ["se-app2", "se-other"], "other devices and other applications untouched");
  assert.deepEqual(ids("deviceRegistration"), ["reg-2"]);
  const audit = db.rows("applicationSettingsAuditLog");
  assert.equal(audit.length, 1);
  assert.equal(audit[0].action, "DEVICE_DATA_ERASED");
  assert.equal(audit[0].performedByUserId, "u-owner");
});

test("erasure: by key id too; unknown device 404; MEMBER 403; another organization's app 404", async () => {
  assert.equal((await erase("key-2")).status, 200);
  assert.deepEqual(ids("deviceRegistration"), ["reg-1"]);
  assert.deepEqual([(await erase("nobody")).status, db.rows("applicationSettingsAuditLog").length], [404, 1]);
  assert.deepEqual((await erase("phone-hash", "u-member", "MEMBER")).body, { error: "FORBIDDEN_ROLE" });
  assert.equal((await erase("phone-hash", "u-owner", "OWNER", "app-2")).status, 404);
});
