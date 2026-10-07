// Account-hash salt (Task 8.1). Real: src/risk/accountHashSalt.ts helpers
// and the severity table entries for the Task 8.1 detectors and rules.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { accountHash, generateAccountHashSalt, isAccountHashSalt, withoutAccountHashSalt } from "../src/risk/accountHashSalt";
import { DETECTOR_SEVERITY } from "../src/detectors/severity";
import { RISK_RULE_IDS, RULE_SEVERITY } from "../src/risk/rules";

test("salt: 64 lowercase hex from 32 random bytes, different every time", () => {
  const a = generateAccountHashSalt();
  const b = generateAccountHashSalt();
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, b);
  assert.ok(isAccountHashSalt(a));
  assert.ok(!isAccountHashSalt(a.toUpperCase()));
  assert.ok(!isAccountHashSalt(a.slice(1)));
  assert.ok(!isAccountHashSalt(null));
});

test("hash = hex(HMAC-SHA256(key = salt bytes from hex, msg = UTF-8 id)) — the SDK contract", () => {
  const salt = "00".repeat(31) + "01";
  const expected = crypto.createHmac("sha256", Buffer.from(salt, "hex")).update("customer-42", "utf8").digest("hex");
  assert.equal(accountHash(salt, "customer-42"), expected);
  assert.match(accountHash(salt, "customer-42"), /^[0-9a-f]{64}$/);
  // Keyed by the salt BYTES, not the hex text.
  const wrongKey = crypto.createHmac("sha256", salt).update("customer-42", "utf8").digest("hex");
  assert.notEqual(accountHash(salt, "customer-42"), wrongKey);
  // Same id, another application's salt → unrelated hash.
  assert.notEqual(accountHash(generateAccountHashSalt(), "customer-42"), expected);
  // Non-ASCII ids hash their UTF-8 bytes.
  assert.equal(accountHash(salt, "ग्राहक"), crypto.createHmac("sha256", Buffer.from(salt, "hex")).update(Buffer.from("ग्राहक", "utf8")).digest("hex"));
});

test("withoutAccountHashSalt removes only the salt", () => {
  const row = { id: "app-1", name: "Bank", accountHashSalt: "f".repeat(64), riskRules: null };
  assert.deepEqual(withoutAccountHashSalt(row), { id: "app-1", name: "Bank", riskRules: null });
  assert.ok(!JSON.stringify(withoutAccountHashSalt(row)).includes("f".repeat(64)));
});

test("severity table: Task 8.1 detectors and every rule have an explicit severity matching the rules engine", () => {
  const detectors: Record<string, string> = {
    otp_interception_risk: "high",
    sms_reader_abuse: "high",
    otp_forwarding_risk: "medium",
    remote_control_app: "high",
    screen_sharing_risk: "high",
  };
  for (const [id, severity] of Object.entries(detectors)) assert.equal(DETECTOR_SEVERITY[id], severity, id);
  for (const rule of RISK_RULE_IDS) assert.equal(DETECTOR_SEVERITY[rule], RULE_SEVERITY[rule], rule);
});
