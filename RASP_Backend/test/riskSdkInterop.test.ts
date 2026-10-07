// Cross-language check (Task 8.1): risk events built and signed by the
// Kotlin engine (rashield-sdk-publish RaspTask81Test writes
// test/fixtures/sdk-risk-events.json) pass the backend's real path.
// Real: the engine's bytes, processRiskEvent (strict schema, canonical JSON,
// ES256 verification, replay checks, rules), Node crypto for the binding.
// Double: MemoryRiskRepository instead of Postgres.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { computeDeviceKeyId } from "../src/crypto/ecdsa";
import { processRiskEvent } from "../src/risk/riskEvents";
import { MemoryRiskRepository } from "./riskSupport";

interface Fixture {
  publicKeySpkiBase64: string;
  appId: string;
  eventTimeMillis: number;
  sessionEvent: string;
  transactionEvent: string;
  binding: { canonical: string; signature: string; bindingSha256: string };
}

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures", "sdk-risk-events.json"), "utf8"),
) as Fixture;
const deviceKeyId = computeDeviceKeyId(Buffer.from(fixture.publicKeySpkiBase64, "base64"));

function repoWithDevice() {
  const repo = new MemoryRiskRepository();
  repo.addDevice(deviceKeyId, {
    id: "reg-1",
    applicationId: "app-1",
    appId: fixture.appId,
    deviceId: "device-1",
    publicKey: fixture.publicKeySpkiBase64,
  });
  return repo;
}

const run = (repo: MemoryRiskRepository, body: string) =>
  processRiskEvent({
    body: JSON.parse(body),
    applicationId: "app-1",
    resolveIpCountry: async () => null,
    now: fixture.eventTimeMillis + 60_000,
    repo,
  });

test("the engine's session and transaction events are accepted as signed", async () => {
  const repo = repoWithDevice();
  const session = await run(repo, fixture.sessionEvent);
  assert.equal(session.status, 202, JSON.stringify(session.body));
  const transaction = await run(repo, fixture.transactionEvent);
  assert.equal(transaction.status, 202, JSON.stringify(transaction.body));
  assert.equal(repo.rows.length, 2);
  assert.equal(repo.rows[0].sessionEvent, "login");
  assert.equal(repo.rows[0].latitude, 12.97, "opted-in location is stored rounded to 2 decimals");
  assert.equal(repo.rows[1].type, "transaction");
});

test("the engine's events carry no amount and no raw ids", () => {
  for (const body of [fixture.sessionEvent, fixture.transactionEvent]) {
    const fields = JSON.parse(body) as Record<string, unknown>;
    assert.ok(!("amount" in fields), "no amount field");
    for (const value of Object.values(fields)) {
      assert.ok(![1500, "1500", "1500.00"].includes(value as never), "no amount value");
    }
    assert.ok(!body.includes("acct-42") && !body.includes("session-1") && !body.includes("benef-1"), "no raw ids");
  }
});

test("a changed engine event is rejected, a resend is a replay", async () => {
  const repo = repoWithDevice();
  const tampered = JSON.parse(fixture.sessionEvent);
  tampered.riskVerdict = "LOW";
  assert.equal((await run(repo, JSON.stringify(tampered))).status, 401);
  assert.equal((await run(repo, fixture.sessionEvent)).status, 202);
  const again = await run(repo, fixture.sessionEvent);
  assert.equal(again.status, 409);
  assert.equal(again.body.duplicate, true);
});

test("the transaction binding verifies with the device key and matches its digest", () => {
  const { canonical, signature, bindingSha256 } = fixture.binding;
  const key = crypto.createPublicKey({ key: Buffer.from(fixture.publicKeySpkiBase64, "base64"), format: "der", type: "spki" });
  assert.ok(crypto.verify("sha256", Buffer.from(canonical, "utf8"), key, Buffer.from(signature, "base64")));
  assert.equal(crypto.createHash("sha256").update(canonical, "utf8").digest("hex"), bindingSha256);
  assert.equal(JSON.parse(fixture.transactionEvent).bindingSha256, bindingSha256);
  assert.match(canonical, /^rasp-txn-v1\|1500\|INR\|[0-9a-f]{64}\|[0-9a-f]{32}\|\d+\|\d+$/);
});
