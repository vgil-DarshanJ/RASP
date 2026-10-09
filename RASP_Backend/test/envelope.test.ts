// POST /v1/events — evidence envelope rules (processEnvelope).
// Real: processEnvelope, envelopeSchema, canonicalization, ECDSA verification
// (node:crypto), and an envelope signed by the Kotlin engine (fixture).
// Double: MemoryEnvelopeRepository instead of Postgres (see test/support.ts).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  deviceColumns,
  ENVELOPE_MAX_AGE_MS,
  ENVELOPE_MAX_FUTURE_MS,
  isEnvelopeBody,
  processEnvelope,
} from "../src/ingestion/envelope";
import { computeDeviceKeyId } from "../src/crypto/ecdsa";
import { MemoryEnvelopeRepository, makeDevice, signEnvelope, TestDevice } from "./support";

const APP = "app-1";
const NOW = Date.UTC(2026, 9, 1, 12, 0, 0);

function setup(device: TestDevice = makeDevice(), applicationId = APP) {
  const repo = new MemoryEnvelopeRepository();
  repo.addDevice(device.deviceKeyId, {
    id: `reg-${device.deviceKeyId.slice(0, 6)}`,
    applicationId,
    appId: device.appId,
    deviceId: "device-1",
    publicKey: device.publicKeyB64,
  });
  return { repo, device };
}

const run = (repo: MemoryEnvelopeRepository, rawBody: string, now = NOW, applicationId = APP) =>
  processEnvelope({ rawBody, applicationId, now, repo });

describe("evidence envelope", () => {
  test("valid signature is accepted and its events stored", async () => {
    const { repo, device } = setup();
    const { body } = signEnvelope(device, NOW);

    const out = await run(repo, body);

    assert.equal(out.status, 201);
    assert.deepEqual(out.body, { accepted: 2 });
    assert.equal(repo.envelopes.length, 1);
    assert.equal(repo.events.length, 2);
    assert.equal(repo.devices.get(device.deviceKeyId)!.lastCounter, 1n);
    assert.equal(repo.events[0].deviceId, "device-1");
  });

  test("an envelope signed by the Kotlin engine (RaspEvidenceEnvelope) is accepted", async () => {
    const fixture = JSON.parse(readFileSync(path.join(__dirname, "fixtures/kotlin-envelope.json"), "utf8"));
    const body = JSON.parse(fixture.body);
    const spki = Buffer.from(fixture.publicKeySpkiBase64, "base64");
    const repo = new MemoryEnvelopeRepository();
    repo.addDevice(computeDeviceKeyId(spki), {
      id: "reg-kotlin", applicationId: APP, appId: body.appId, deviceId: null, publicKey: fixture.publicKeySpkiBase64,
    });

    const out = await run(repo, fixture.body, body.eventTimeMillis + 60_000);
    assert.equal(out.status, 201, JSON.stringify(out.body));
    assert.deepEqual(out.body, { accepted: 2 });

    const tampered = await run(repo, fixture.tamperedBody, body.eventTimeMillis + 60_000);
    assert.equal(tampered.status, 401);
    assert.equal(tampered.body.error, "ENVELOPE_SIGNATURE_INVALID");
  });

  test("tampered field is rejected and nothing is stored", async () => {
    const { repo, device } = setup();
    const { fields } = signEnvelope(device, NOW);

    // Flip the detection to SECURE without re-signing.
    const flipped = structuredClone(fields) as any;
    flipped.detectorResults[0].status = "SECURE";
    let out = await run(repo, JSON.stringify(flipped));
    assert.equal(out.status, 401);
    assert.equal(out.body.error, "ENVELOPE_SIGNATURE_INVALID");

    // Every other signed field the schema still accepts after the change.
    const changes: Record<string, unknown> = {
      eventId: crypto.randomUUID(),
      eventTimeMillis: NOW - 1,
      monotonicCounter: 2,
      nonce: "f".repeat(32),
      sdkVersion: "other",
    };
    for (const [key, value] of Object.entries(changes)) {
      out = await run(repo, JSON.stringify({ ...fields, [key]: value }));
      assert.equal(out.status, 401, key);
      assert.equal(out.body.error, "ENVELOPE_SIGNATURE_INVALID", key);
    }
    // Adding a field the device did not sign.
    out = await run(repo, JSON.stringify({ ...fields, injected: true }));
    assert.equal(out.body.error, "ENVELOPE_SIGNATURE_INVALID");

    assert.equal(repo.envelopes.length, 0);
    assert.equal(repo.events.length, 0);
  });

  test("unknown device key is rejected", async () => {
    const { repo } = setup();
    const stranger = makeDevice();
    const out = await run(repo, signEnvelope(stranger, NOW).body);
    assert.equal(out.status, 401);
    assert.equal(out.body.error, "UNKNOWN_DEVICE_KEY");
  });

  test("a key registered to another application or package is rejected", async () => {
    const { repo, device } = setup(makeDevice(), "other-app");
    let out = await run(repo, signEnvelope(device, NOW).body);
    assert.equal(out.status, 403);
    assert.equal(out.body.error, "DEVICE_KEY_MISMATCH");

    const same = setup();
    out = await run(same.repo, signEnvelope(same.device, NOW, { appId: "com.attacker.app" }).body);
    assert.equal(out.status, 403);
    assert.equal(out.body.error, "APP_ID_MISMATCH");
  });

  test("replayed nonce is rejected; an exact resend is acknowledged once, not stored again", async () => {
    const { repo, device } = setup();
    const first = signEnvelope(device, NOW, { monotonicCounter: 1 });
    assert.equal((await run(repo, first.body)).status, 201);

    // Exact resend (e.g. the SDK never saw the first 201): 200, nothing new stored.
    const resend = await run(repo, first.body);
    assert.equal(resend.status, 200);
    assert.deepEqual(resend.body, { accepted: 0, duplicate: true });
    assert.equal(repo.envelopes.length, 1);
    assert.equal(repo.events.length, 2);

    // A different envelope reusing the accepted nonce.
    const reuse = signEnvelope(device, NOW, { monotonicCounter: 2, nonce: (first.fields as any).nonce });
    const out = await run(repo, reuse.body);
    assert.equal(out.status, 409);
    assert.equal(out.body.error, "REPLAYED_NONCE");
    assert.equal(repo.envelopes.length, 1);
  });

  test("lower or equal counter is rejected", async () => {
    const { repo, device } = setup();
    assert.equal((await run(repo, signEnvelope(device, NOW, { monotonicCounter: 5 }).body)).status, 201);

    let out = await run(repo, signEnvelope(device, NOW, { monotonicCounter: 4 }).body);
    assert.equal(out.status, 409);
    assert.equal(out.body.error, "COUNTER_NOT_INCREASING");

    out = await run(repo, signEnvelope(device, NOW, { monotonicCounter: 5 }).body);
    assert.equal(out.status, 409);
    assert.equal(out.body.error, "COUNTER_NOT_INCREASING");

    assert.equal((await run(repo, signEnvelope(device, NOW, { monotonicCounter: 6 }).body)).status, 201);
    assert.equal(repo.devices.get(device.deviceKeyId)!.lastCounter, 6n);
  });

  test("late offline event up to 7 days old is accepted, older is rejected", async () => {
    const { repo, device } = setup();
    const almostSevenDays = NOW - ENVELOPE_MAX_AGE_MS + 60 * 60 * 1000;
    let out = await run(repo, signEnvelope(device, almostSevenDays, { monotonicCounter: 1 }).body);
    assert.equal(out.status, 201);

    out = await run(repo, signEnvelope(device, NOW - ENVELOPE_MAX_AGE_MS - 60_000, { monotonicCounter: 2 }).body);
    assert.equal(out.status, 422);
    assert.equal(out.body.error, "EVENT_TOO_OLD");
  });

  test("future event more than 5 minutes ahead is rejected", async () => {
    const { repo, device } = setup();
    let out = await run(repo, signEnvelope(device, NOW + ENVELOPE_MAX_FUTURE_MS + 1_000, { monotonicCounter: 1 }).body);
    assert.equal(out.status, 422);
    assert.equal(out.body.error, "EVENT_FROM_FUTURE");

    out = await run(repo, signEnvelope(device, NOW + 4 * 60_000, { monotonicCounter: 2 }).body);
    assert.equal(out.status, 201);
  });

  test("same event id with different content is rejected", async () => {
    const { repo, device } = setup();
    const first = signEnvelope(device, NOW, { monotonicCounter: 1 });
    await run(repo, first.body);
    const clash = signEnvelope(device, NOW, { monotonicCounter: 2, eventId: (first.fields as any).eventId });
    const out = await run(repo, clash.body);
    assert.equal(out.status, 409);
    assert.equal(out.body.error, "EVENT_ID_REUSED");
  });

  test("a field the device signed but this backend does not know still verifies", async () => {
    const { repo, device } = setup();
    const out = await run(repo, signEnvelope(device, NOW, { futureField: { a: 1 } }).body);
    assert.equal(out.status, 201);
  });

  test("the signed device object (model, OS) is accepted and mapped to the event columns", async () => {
    const { repo, device } = setup();
    const phone = { manufacturer: "OnePlus", model: "CPH2581", osPlatform: "android", osVersion: "15", appVersion: "1.0.0" };
    const out = await run(repo, signEnvelope(device, NOW, { device: phone }).body);
    assert.equal(out.status, 201, JSON.stringify(out.body));
    assert.equal(repo.events[0].deviceModel, "CPH2581");
    assert.equal(repo.events[0].osPlatform, "android");
    assert.deepEqual(deviceColumns({ device: phone }), {
      deviceModel: "CPH2581", manufacturer: "OnePlus", osPlatform: "android", osVersion: "15", appVersion: "1.0.0",
    });
    assert.deepEqual(deviceColumns({}), {
      deviceModel: undefined, manufacturer: undefined, osPlatform: undefined, osVersion: undefined, appVersion: undefined,
    });

    const { repo: repo2, device: device2 } = setup();
    const tooLong = await run(repo2, signEnvelope(device2, NOW, { device: { model: "x".repeat(201) } }).body);
    assert.equal(tooLong.status, 400);
  });

  test("malformed bodies are rejected with 400", async () => {
    const { repo, device } = setup();
    assert.equal((await run(repo, "{not json")).body.error, "INVALID_JSON");
    const { fields } = signEnvelope(device, NOW);
    const { nonce: _n, ...missing } = fields as Record<string, unknown>;
    const out = await run(repo, JSON.stringify(missing));
    assert.equal(out.status, 400);
    assert.equal(out.body.error, "INVALID_ENVELOPE");
  });

  test("routing: only bodies with envelopeVersion take the envelope path", () => {
    assert.equal(isEnvelopeBody({ events: [{ detectorId: "x", status: "SECURE" }] }), false);
    assert.equal(isEnvelopeBody({ envelopeVersion: 1 }), true);
    // Fails the envelope schema; can never be processed as a legacy batch without HMAC.
    assert.equal(isEnvelopeBody({ envelopeVersion: 2, events: [] }), true);
    assert.equal(isEnvelopeBody(null), false);
    assert.equal(isEnvelopeBody([{ envelopeVersion: 1 }]), false);
  });
});
