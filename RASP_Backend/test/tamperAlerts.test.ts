// Signing-certificate tamper alerts (Task 6.0 Part 2.3).
// Real: normalizeCertHash, tamperAlertsFor, raiseTamperAlerts, registerDevice
// (signingCertSha256 + registration country), severityOf, and the real webhook
// dispatcher (maybeTriggerWebhook → deliver) posting to a local HTTP server.
// Doubles: injected store/dashboard deps for raiseTamperAlerts; for the
// webhook test, Prisma's webhookConfig.findUnique/update replaced in-process
// (no Postgres); MemoryRegistrationRepository.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { AddressInfo } from "node:net";
import {
  IngestedEvent,
  StoredAlert,
  TAMPER_ALERT_DETECTOR,
  TamperAlertDeps,
  normalizeCertHash,
  raiseTamperAlerts,
  tamperAlertsFor,
} from "../src/ingestion/tamperAlerts";
import { severityOf } from "../src/detectors/severity";
import { maybeTriggerWebhook } from "../src/webhooks/dispatch";
import { encryptSecret } from "../src/crypto/secretBox";
import { prisma } from "../src/db/prisma";
import { registerDevice } from "../src/devices/registration";
import { MemoryRegistrationRepository } from "./support";

const A = "AB".repeat(32);
const B = "CD".repeat(32);
const withColons = A.match(/../g)!.join(":").toLowerCase();

const event = (id: string, hash: string | null, deviceId = "device-1"): IngestedEvent => ({
  id, deviceId, deviceModel: "Pixel", osPlatform: "android",
  evidence: hash === null ? [{ key: "install_directory_missing", value: false, note: null }]
    : [{ key: "signing_cert_sha256", value: hash, note: null }],
});

describe("hash normalization", () => {
  test("64 hex, any case, ':' separators → uppercase without separators; anything else → null", () => {
    assert.equal(normalizeCertHash(withColons), A);
    assert.equal(normalizeCertHash(A.toLowerCase()), A);
    for (const bad of ["", "AB", A + "0", "ZZ".repeat(32), null, 42]) assert.equal(normalizeCertHash(bad), null, String(bad));
  });
});

describe("tamperAlertsFor", () => {
  test("a different hash than the application's expected one raises an alert", () => {
    const alerts = tamperAlertsFor([event("e1", B)], A, null);
    assert.equal(alerts.length, 1);
    assert.deepEqual([alerts[0].observed, alerts[0].expected, alerts[0].expectedSource], [B, A, "application"]);
  });

  test("the same hash (any formatting) raises nothing", () => {
    assert.deepEqual(tamperAlertsFor([event("e1", withColons)], A, null), []);
  });

  test("without an application hash, the device's registered hash is the expectation", () => {
    const alerts = tamperAlertsFor([event("e1", B)], null, A);
    assert.equal(alerts[0].expectedSource, "device_registration");
    // The application's hash takes precedence: the device registered B, but the app expects A.
    assert.deepEqual(tamperAlertsFor([event("e1", B)], A, B).map((a) => a.expectedSource), ["application"]);
  });

  test("nothing expected, no hash in the evidence, or malformed hash → no alert; one alert per device and hash", () => {
    assert.deepEqual(tamperAlertsFor([event("e1", B)], null, null), []);
    assert.deepEqual(tamperAlertsFor([event("e1", null)], A, null), []);
    assert.deepEqual(tamperAlertsFor([event("e1", "nonsense")], A, null), []);
    const many = tamperAlertsFor([event("e1", B), event("e2", B), event("e3", B, "device-2")], A, null);
    assert.deepEqual(many.map((a) => a.sourceEventId), ["e1", "e3"]);
  });
});

describe("raiseTamperAlerts", () => {
  function deps(expected: string | null) {
    const stored: StoredAlert[] = [];
    const webhooks: { detectorId: string; status: string }[] = [];
    const dashboard: string[] = [];
    const d: TamperAlertDeps = {
      async findApplication() { return { name: "Bank App", expectedSigningCertSha256: expected }; },
      async storeAlerts(_app, alerts, receivedAt) {
        const rows = alerts.map((a, i) => ({
          id: `alert-${i}`, detectorId: TAMPER_ALERT_DETECTOR, status: "DETECTED",
          deviceId: a.deviceId, deviceModel: a.deviceModel, osPlatform: a.osPlatform, receivedAt,
          evidence: [{ key: "observed_signing_cert_sha256", value: a.observed, note: null }],
        }));
        stored.push(...rows);
        return rows;
      },
      async recordForDashboard(_app, e) { dashboard.push(e.detectorId); },
      async triggerWebhook(_app, _name, e) { webhooks.push({ detectorId: e.detectorId, status: e.status }); },
    };
    return { d, stored, webhooks, dashboard };
  }

  test("stores a DETECTED tamper_signing_mismatch event, caches it, sends it to the webhook path; severity high", async () => {
    const { d, stored, webhooks, dashboard } = deps(A);
    const out = await raiseTamperAlerts({ applicationId: "app-1", events: [event("e1", B)], now: new Date(), deps: d });
    assert.equal(out.length, 1);
    assert.equal(stored[0].detectorId, "tamper_signing_mismatch");
    assert.deepEqual(webhooks, [{ detectorId: "tamper_signing_mismatch", status: "DETECTED" }]);
    assert.deepEqual(dashboard, ["tamper_signing_mismatch"]);
    assert.equal(severityOf(TAMPER_ALERT_DETECTOR), "high");
  });

  test("matching hash or no expectation: nothing stored or sent", async () => {
    for (const [expected, hash] of [[A, A], [null, B]] as const) {
      const { d, stored, webhooks } = deps(expected);
      await raiseTamperAlerts({ applicationId: "app-1", events: [event("e1", hash)], now: new Date(), deps: d });
      assert.deepEqual([stored.length, webhooks.length], [0, 0]);
    }
  });

  test("the real webhook dispatcher delivers the alert with severity high to a HIGH-threshold webhook", async () => {
    const received: Record<string, unknown>[] = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => { received.push(JSON.parse(body)); res.end("ok"); });
    });
    server.listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", () => r()));
    const { port } = server.address() as AddressInfo;

    const originalKey = process.env.CREDENTIAL_ENCRYPTION_KEY;
    process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString("hex"); // throwaway test key
    const webhookConfig = prisma.webhookConfig as unknown as Record<string, unknown>;
    const originalFind = webhookConfig.findUnique;
    const originalUpdate = webhookConfig.update;
    webhookConfig.findUnique = async () => ({
      id: "wh-1", url: `http://127.0.0.1:${port}/hook`, secretEncrypted: encryptSecret("hook-secret"),
      minSeverity: "HIGH", enabled: true,
    });
    webhookConfig.update = async () => ({});
    try {
      await maybeTriggerWebhook("app-1", "Bank App", {
        detectorId: TAMPER_ALERT_DETECTOR, status: "DETECTED", deviceId: "device-1", deviceModel: "Pixel",
        osPlatform: "android", receivedAt: new Date(), evidence: [],
      });
      assert.equal(received.length, 1);
      assert.equal(received[0].detectorId, "tamper_signing_mismatch");
      assert.equal(received[0].severity, "high");
    } finally {
      webhookConfig.findUnique = originalFind;
      webhookConfig.update = originalUpdate;
      if (originalKey === undefined) delete process.env.CREDENTIAL_ENCRYPTION_KEY;
      else process.env.CREDENTIAL_ENCRYPTION_KEY = originalKey;
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});

describe("device registration stores the signing certificate and registration country", () => {
  const certs = JSON.parse(readFileSync(path.join(__dirname, "fixtures/attestation-certs.json"), "utf8"));
  const body = (extra: Record<string, unknown> = {}) => ({
    appId: "com.example.bank", deviceId: "device-1", publicKey: certs.publicKey,
    attestationChain: certs.attested, sdkVersion: "1.1.0-local", ...extra,
  });
  const NOW = new Date(Date.UTC(2026, 9, 5, 12, 0, 0));

  test("hash normalized and stored with the registration country", async () => {
    const repo = new MemoryRegistrationRepository();
    const out = await registerDevice({
      body: body({ signingCertSha256: withColons }), applicationId: "app-1", now: NOW, repo, registrationCountry: "IN",
    });
    assert.equal(out.status, 201);
    assert.equal(repo.rows[0].input.signingCertSha256, A);
    assert.equal(repo.rows[0].input.registrationCountry, "IN");
  });

  test("no hash sent → stored as null; malformed hash → 400 INVALID_SIGNING_CERT and nothing stored", async () => {
    const repo = new MemoryRegistrationRepository();
    assert.equal((await registerDevice({ body: body(), applicationId: "app-1", now: NOW, repo })).status, 201);
    assert.equal(repo.rows[0].input.signingCertSha256, null);
    assert.equal(repo.rows[0].input.registrationCountry, null);

    const repo2 = new MemoryRegistrationRepository();
    const bad = await registerDevice({ body: body({ signingCertSha256: "abc" }), applicationId: "app-1", now: NOW, repo: repo2 });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error, "INVALID_SIGNING_CERT");
    assert.equal(repo2.rows.length, 0);
  });
});
