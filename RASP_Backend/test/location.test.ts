// Location on events (Task 6.0 Part 4.1): stored only with location_opt_in.
// Real: extractLocation, locationColumns, redactEnvelopePayload,
// processEnvelope with ECDSA verification and canonicalization.
// Double: MemoryEnvelopeRepository instead of Postgres (test/support.ts).
// Not exercised: the Prisma create calls themselves (need Postgres).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { extractLocation, locationColumns, redactEnvelopePayload } from "../src/ingestion/location";
import { processEnvelope } from "../src/ingestion/envelope";
import { canonicalStringify, verifyEnvelopeSignature } from "../src/crypto/ecdsa";
import { MemoryEnvelopeRepository, makeDevice, signEnvelope } from "./support";

const NOW = Date.UTC(2026, 9, 5, 12, 0, 0);
const loc = (lat: unknown, lon: unknown, optIn?: boolean) => [
  { key: "is_mock", value: false, note: null },
  ...(optIn === undefined ? [] : [{ key: "location_opt_in", value: optIn, note: null }]),
  { key: "latitude", value: lat, note: null },
  { key: "longitude", value: lon, note: null },
  { key: "location_accuracy_m", value: 12.5, note: null },
  { key: "location_captured_at_millis", value: NOW - 1000, note: null },
];
const keys = (evidence: unknown) => (evidence as { key: string }[]).map((e) => e.key);

describe("extractLocation", () => {
  test("opt-in with valid coordinates: stored in the columns rounded to 3 decimals (F-16), evidence unchanged", () => {
    const ev = loc(19.076, 72.8777, true);
    const x = extractLocation(ev);
    assert.equal(x.optIn, true);
    assert.equal(x.stripped, false);
    assert.deepEqual(x.evidence, ev);
    assert.deepEqual(locationColumns(x.location), {
      latitude: 19.076, longitude: 72.878, locationAccuracyM: 12.5,
      locationCapturedAt: new Date(NOW - 1000), locationOptIn: true,
    });
  });

  test("coordinates without opt-in (older SDK): removed from the evidence, nothing stored", () => {
    for (const ev of [loc(19.076, 72.8777), loc(19.076, 72.8777, false)]) {
      const x = extractLocation(ev);
      assert.equal(x.location, null);
      assert.equal(x.stripped, true);
      assert.deepEqual(keys(x.evidence), ["is_mock"]);
      assert.deepEqual(locationColumns(x.location), {
        latitude: null, longitude: null, locationAccuracyM: null, locationCapturedAt: null, locationOptIn: false,
      });
    }
  });

  test("opt-in but out-of-range or non-numeric coordinates: nothing stored, keys removed", () => {
    for (const [lat, lon] of [[91, 10], [10, -181], ["19.0", 72], [Number.NaN, 1]]) {
      const x = extractLocation(loc(lat, lon, true));
      assert.equal(x.location, null, `${lat},${lon}`);
      assert.deepEqual(keys(x.evidence), ["is_mock"]);
    }
  });

  test("plain-object evidence is handled the same way; no location keys = untouched", () => {
    const x = extractLocation({ latitude: 1, longitude: 2, other: "x" });
    assert.deepEqual(x.evidence, { other: "x" });
    const plain = [{ key: "signal", value: "su_binary", note: "hard" }];
    assert.deepEqual(extractLocation(plain), { evidence: plain, location: null, optIn: false, stripped: false });
  });
});

describe("evidence envelopes", () => {
  function setup() {
    const device = makeDevice();
    const repo = new MemoryEnvelopeRepository();
    repo.addDevice(device.deviceKeyId, {
      id: "reg-1", applicationId: "app-1", appId: device.appId, deviceId: "device-1", publicKey: device.publicKeyB64,
    });
    return { device, repo };
  }
  const results = (evidence: unknown) => ({
    detectorResults: [{ detectorId: "mock_location", status: "SECURE", evidence, observedAtMillis: NOW }],
  });

  test("opted-in location is stored with the event; the signed payload stays verifiable", async () => {
    const { device, repo } = setup();
    const { body } = signEnvelope(device, NOW, results(loc(19.076, 72.8777, true)));
    const out = await processEnvelope({ rawBody: body, applicationId: "app-1", now: NOW, repo });
    assert.equal(out.status, 201);
    assert.equal(repo.events[0].location?.latitude, 19.076);
    assert.equal(repo.envelopes[0].payloadRedacted, false);
    const signature = JSON.parse(body).signature;
    assert.equal(verifyEnvelopeSignature(device.publicKeyB64, repo.envelopes[0].signedPayload, signature), true);
  });

  test("location without opt-in: not in the stored evidence, not in the stored payload, marked redacted", async () => {
    const { device, repo } = setup();
    const { body } = signEnvelope(device, NOW, results(loc(19.076, 72.8777)));
    const out = await processEnvelope({ rawBody: body, applicationId: "app-1", now: NOW, repo });
    assert.equal(out.status, 201, "the envelope itself is still accepted (signature verified before redaction)");
    assert.equal(repo.events[0].location, null);
    assert.deepEqual(keys(repo.events[0].evidence), ["is_mock"]);
    assert.equal(repo.envelopes[0].payloadRedacted, true);
    assert.equal(repo.envelopes[0].signedPayload.includes("19.076"), false);
    assert.equal(repo.envelopes[0].signedPayload.includes("latitude"), false);
  });

  test("redactEnvelopePayload leaves a payload without location byte-for-byte unchanged", () => {
    const payload = canonicalStringify({ detectorResults: [{ detectorId: "vpn", evidence: [{ key: "x", value: 1, note: null }] }] });
    assert.deepEqual(redactEnvelopePayload(payload, canonicalStringify), { payload, redacted: false });
  });
});
