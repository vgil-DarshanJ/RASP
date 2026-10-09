// Legacy HMAC ingestion still applies to non-envelope bodies.
// Real: the HMAC helpers requireApiKey uses (computeSignature,
// signaturesMatch, isTimestampFresh) and the path selector.
// Not exercised: the Express middleware itself, which needs Postgres and Redis.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { canonicalSignature, computeSignature, isTimestampFresh, signaturesMatch } from "../src/crypto/hmac";
import { isEnvelopeBody } from "../src/ingestion/envelope";

describe("legacy HMAC batch path", () => {
  const secret = "test-secret";
  const body = Buffer.from(JSON.stringify({ events: [{ detectorId: "root_jailbreak", status: "DETECTED" }] }));
  const ts = String(Date.now());

  test("a legacy batch is routed to the HMAC-authenticated path", () => {
    assert.equal(isEnvelopeBody(JSON.parse(body.toString())), false);
  });

  test("correct signature matches; changed body, timestamp or secret does not", () => {
    const sig = computeSignature(secret, ts, body);
    assert.equal(signaturesMatch(sig, computeSignature(secret, ts, body)), true);
    assert.equal(signaturesMatch(sig, computeSignature(secret, ts, Buffer.from(body.toString().replace("DETECTED", "SECURE")))), false);
    assert.equal(signaturesMatch(sig, computeSignature(secret, String(Number(ts) + 1), body)), false);
    assert.equal(signaturesMatch(sig, computeSignature("other-secret", ts, body)), false);
  });

  test("only the exact 64-hex form matches: upper case is canonicalised, padding and trailing junk never match (F-01)", () => {
    const sig = computeSignature(secret, ts, body);
    assert.equal(canonicalSignature(sig), sig);
    assert.equal(canonicalSignature(sig.toUpperCase()), sig);
    for (const variant of [sig + "zz", sig + "00", sig + " ", " " + sig, sig.slice(0, 63), sig.slice(0, 63) + "g", ""]) {
      assert.equal(canonicalSignature(variant), null, JSON.stringify(variant));
      assert.equal(signaturesMatch(variant, sig), false, JSON.stringify(variant));
    }
    assert.equal(signaturesMatch(sig.toUpperCase(), sig), true);
  });

  test("timestamp window is ±5 minutes by default", () => {
    assert.equal(isTimestampFresh(Date.now() - 4 * 60_000), true);
    assert.equal(isTimestampFresh(Date.now() - 6 * 60_000), false);
    assert.equal(isTimestampFresh(Date.now() + 6 * 60_000), false);
  });
});
