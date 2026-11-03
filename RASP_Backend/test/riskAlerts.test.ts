// Risk findings → alerts and dashboard rows (Task 8.1).
// Real: raiseRiskAlerts, riskAlertEvidence (src/risk/alerts.ts) and
// toDashboardRiskEvent (src/dashboard/riskEvents.ts).
// Doubles: the alert store, dashboard cache and webhook sender are recorders.
import { test } from "node:test";
import assert from "node:assert/strict";
import { raiseRiskAlerts, riskAlertEvidence, RiskAlertDeps, RiskAlertSource } from "../src/risk/alerts";
import { toDashboardRiskEvent } from "../src/dashboard/riskEvents";
import type { StoredAlert } from "../src/ingestion/tamperAlerts";

const source: RiskAlertSource = {
  applicationId: "app-1",
  deviceId: "android-1",
  sdkVersion: "1.2.0",
  eventType: "transaction",
  eventId: "8f0c7f8e-1c2a-4b5d-9e6f-0a1b2c3d4e5f",
  receivedAt: new Date("2026-10-07T12:00:00Z"),
  findings: [
    { rule: "transaction_velocity", severity: "high", explanation: "6 transactions in 10 minutes", evidence: { account_hash: "a1a1a1a1a1a1", transactions_in_window: 6 } },
    { rule: "new_beneficiary", severity: "low", explanation: "new beneficiary", evidence: { account_hash: "a1a1a1a1a1a1", beneficiary_hash: "bebebebebebe" } },
  ],
};

test("each finding becomes a stored DETECTED alert, then dashboard cache, then webhook — in that order", async () => {
  const calls: string[] = [];
  const deps: RiskAlertDeps = {
    findApplicationName: async () => "Bank App",
    storeAlerts: async (s) => {
      calls.push(`store:${s.findings.map((f) => f.rule).join(",")}`);
      return s.findings.map((f, i): StoredAlert => ({
        id: `se-${i}`, detectorId: f.rule, status: "DETECTED", deviceId: s.deviceId, deviceModel: null, osPlatform: null,
        receivedAt: s.receivedAt, evidence: riskAlertEvidence(s, f),
      }));
    },
    recordForDashboard: async (_app, e) => { calls.push(`cache:${e.detectorId}`); },
    triggerWebhook: async (_app, name, e) => { calls.push(`webhook:${name}:${e.detectorId}`); },
  };
  const stored = await raiseRiskAlerts(source, deps);
  assert.equal(stored.length, 2);
  assert.deepEqual(calls, [
    "store:transaction_velocity,new_beneficiary",
    "cache:transaction_velocity",
    "cache:new_beneficiary",
    "webhook:Bank App:transaction_velocity",
    "webhook:Bank App:new_beneficiary",
  ]);
});

test("no findings → nothing stored or sent", async () => {
  let touched = false;
  const deps = {
    findApplicationName: async () => { touched = true; return "x"; },
    storeAlerts: async () => { touched = true; return []; },
    recordForDashboard: async () => { touched = true; },
    triggerWebhook: async () => { touched = true; },
  } as RiskAlertDeps;
  assert.deepEqual(await raiseRiskAlerts({ ...source, findings: [] }, deps), []);
  assert.equal(touched, false);
});

test("alert evidence: the finding's numbers and shortened hashes, the event type and id — no full hash", () => {
  const evidence = riskAlertEvidence(source, source.findings[0]);
  assert.deepEqual(evidence.map((e) => e.key), ["account_hash", "transactions_in_window", "event_type", "risk_event_id"]);
  assert.ok(evidence.every((e) => typeof e.value !== "string" || !/^[0-9a-f]{64}$/.test(e.value)));
});

test("dashboard row: hashes cut to 12 characters, coordinates never sent (only 'locationShared'), rules listed", () => {
  const row = toDashboardRiskEvent({
    id: "r1", type: "transaction", deviceKeyId: "K".repeat(44), accountHash: "a".repeat(64), sessionHash: "b".repeat(64),
    beneficiaryHash: "c".repeat(64), currency: "INR", channel: "upi", riskScore: null, riskVerdict: "UNKNOWN",
    ipCountry: "IN", latitude: 19.08, eventTime: new Date(0), receivedAt: new Date(0),
    riskEvents: [{ rule: "new_beneficiary", severity: "low", explanation: "x", evidence: {} }, "junk", null],
  });
  assert.equal(row.accountHash, "a".repeat(12));
  assert.equal(row.beneficiaryHash, "c".repeat(12));
  assert.equal(row.deviceKeyId.length, 12);
  assert.equal(row.locationShared, true);
  assert.ok(!("latitude" in row));
  assert.equal(row.riskVerdict, "UNKNOWN", "undecided stays undecided");
  assert.deepEqual(row.rules, [{ rule: "new_beneficiary", severity: "low", explanation: "x" }]);
});
