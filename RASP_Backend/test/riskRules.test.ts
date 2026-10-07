// Fraud-risk rules (src/risk/rules.ts): each rule — normal case, edge of
// the threshold, abuse case — plus threshold parsing.
// Real: evaluateRiskRules, effectiveRiskRules, mergeRiskRules, riskRulesPatchSchema (pure, no I/O).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  AccountHistory,
  DEFAULT_RISK_RULES,
  RiskEventFacts,
  distanceKm,
  effectiveRiskRules,
  evaluateRiskRules,
  mergeRiskRules,
  riskRulesPatchSchema,
} from "../src/risk/rules";

const MIN = 60_000;
const NOW = Date.UTC(2026, 9, 7, 12, 0, 0);
const ACCOUNT = "a1".repeat(32);

const facts = (over: Partial<RiskEventFacts> = {}): RiskEventFacts => ({
  type: "session",
  deviceKeyId: "dev-new",
  accountHash: ACCOUNT,
  sessionHash: "5e".repeat(32),
  sessionEvent: "login",
  eventTime: new Date(NOW),
  receivedAt: new Date(NOW),
  location: null,
  ipCountry: null,
  ...over,
});

const history = (over: Partial<AccountHistory> = {}): AccountHistory => ({
  bindings: [],
  recentSessions: [],
  lastLocated: null,
  lastIpCountry: null,
  recentTransactionCount: 0,
  beneficiarySeenBefore: true,
  ...over,
});

const rulesFired = (f: RiskEventFacts, h: AccountHistory, rules = DEFAULT_RISK_RULES) =>
  evaluateRiskRules(f, h, rules).map((x) => x.rule);

const bound = (deviceKeyId: string, minutesAgo: number) => ({ deviceKeyId, firstSeenAt: new Date(NOW - minutesAgo * MIN) });

describe("new_device_for_account", () => {
  test("normal: a second device for an account fires (medium) with an explanation", () => {
    const [f] = evaluateRiskRules(facts(), history({ bindings: [bound("dev-old", 60 * 24 * 30)] }), DEFAULT_RISK_RULES);
    assert.equal(f.rule, "new_device_for_account");
    assert.equal(f.severity, "medium");
    assert.match(f.explanation, /has not used before/);
    assert.equal(f.evidence.known_devices, 1);
    assert.equal(f.evidence.account_hash, ACCOUNT.slice(0, 12), "only a shortened hash in the evidence");
  });
  test("edge: the account's first device is enrolment, and a known device never fires", () => {
    assert.deepEqual(rulesFired(facts(), history()), []);
    assert.deepEqual(rulesFired(facts({ deviceKeyId: "dev-old" }), history({ bindings: [bound("dev-old", 5)] })), []);
  });
  test("abuse: a hash shared across apps does not leak bindings — only this history counts", () => {
    // The repository scopes bindings by application; the rule sees only what it is given.
    assert.ok(rulesFired(facts(), history({ bindings: [bound("other", 1)] })).includes("new_device_for_account"));
  });
});

describe("device_change_velocity", () => {
  test("normal: a 4th new device within 24 h fires (high)", () => {
    const h = history({ bindings: [bound("d1", 600), bound("d2", 300), bound("d3", 10)] });
    const f = evaluateRiskRules(facts(), h, DEFAULT_RISK_RULES).find((x) => x.rule === "device_change_velocity")!;
    assert.equal(f.severity, "high");
    assert.equal(f.evidence.devices_in_window, 4);
  });
  test("edge: exactly maxDevices in the window does not fire; devices first seen before the window do not count", () => {
    assert.ok(!rulesFired(facts(), history({ bindings: [bound("d1", 600), bound("d2", 300)] })).includes("device_change_velocity"));
    const old = history({ bindings: [bound("d1", 1441), bound("d2", 2000), bound("d3", 10)] });
    assert.ok(!rulesFired(facts(), old).includes("device_change_velocity"));
  });
  test("abuse: rotating through many fresh device keys fires, and a tighter per-app threshold applies", () => {
    const many = history({ bindings: Array.from({ length: 20 }, (_, i) => bound(`k${i}`, i)) });
    assert.ok(rulesFired(facts(), many).includes("device_change_velocity"));
    const strict = mergeRiskRules(DEFAULT_RISK_RULES, { deviceChangeVelocity: { maxDevices: 1 } });
    assert.ok(rulesFired(facts(), history({ bindings: [bound("d1", 5)] }), strict).includes("device_change_velocity"));
  });
  test("a device already bound to the account never re-fires it", () => {
    const h = history({ bindings: [bound("d1", 1), bound("d2", 1), bound("d3", 1), bound("dev-new", 1)] });
    assert.deepEqual(rulesFired(facts(), h), []);
  });
});

describe("concurrent_sessions", () => {
  const session = (deviceKeyId: string, sessionEvent: string, minutesAgo: number, sessionHash = deviceKeyId.padEnd(64, "0")) =>
    ({ deviceKeyId, sessionHash, sessionEvent, eventTime: new Date(NOW - minutesAgo * MIN) });
  const known = { bindings: [bound("d1", 9999), bound("d2", 9999), bound("dev-new", 9999)] };

  test("normal: a login while two other devices have active sessions fires (medium)", () => {
    const h = history({ ...known, recentSessions: [session("d1", "login", 10), session("d2", "resume", 5)] });
    const f = evaluateRiskRules(facts(), h, DEFAULT_RISK_RULES).find((x) => x.rule === "concurrent_sessions")!;
    assert.equal(f.severity, "medium");
    assert.equal(f.evidence.active_devices, 3);
  });
  test("edge: a session that logged out, or is outside the window, is not active; two devices = limit, no fire", () => {
    const h = history({
      ...known,
      recentSessions: [session("d1", "login", 20), session("d1", "logout", 15), session("d2", "login", 31)],
    });
    assert.deepEqual(rulesFired(facts(), h), []);
    const atLimit = history({ ...known, recentSessions: [session("d1", "login", 1)] });
    assert.deepEqual(rulesFired(facts(), atLimit), []);
  });
  test("abuse: a logout event never fires it, and many sessions on ONE device count as one device", () => {
    const h = history({ ...known, recentSessions: [session("d1", "login", 1), session("d2", "login", 1)] });
    assert.deepEqual(rulesFired(facts({ sessionEvent: "logout" }), h), []);
    const oneDevice = history({
      ...known,
      recentSessions: Array.from({ length: 50 }, (_, i) => session("d1", "login", 1, i.toString(16).padStart(64, "0"))),
    });
    assert.deepEqual(rulesFired(facts(), oneDevice), []);
  });
});

describe("impossible_travel", () => {
  const MUMBAI = { latitude: 19.08, longitude: 72.88 };
  const LONDON = { latitude: 51.51, longitude: -0.13 };
  const DELHI = { latitude: 28.61, longitude: 77.21 };
  const at = (place: { latitude: number; longitude: number }, minutesAgo: number) =>
    ({ ...place, capturedAt: new Date(NOW - minutesAgo * MIN) });
  const known = { bindings: [bound("dev-new", 9999)] };

  test("normal: Mumbai then London 60 minutes later (~7,200 km/h) fires (high), basis location", () => {
    const h = history({ ...known, lastLocated: { deviceKeyId: "d1", location: at(MUMBAI, 60) } });
    const f = evaluateRiskRules(facts({ location: at(LONDON, 0) }), h, DEFAULT_RISK_RULES).find((x) => x.rule === "impossible_travel")!;
    assert.equal(f.severity, "high");
    assert.equal(f.evidence.basis, "location");
    assert.ok(Number(f.evidence.speed_kmh) > 7000);
  });
  test("edge: Mumbai to Delhi in 3 hours (~380 km/h) is plausible; gaps under minMinutes or distances under minDistanceKm are not judged", () => {
    const plausible = history({ ...known, lastLocated: { deviceKeyId: "d1", location: at(MUMBAI, 180) } });
    assert.deepEqual(rulesFired(facts({ location: at(DELHI, 0) }), plausible), []);
    const tooSoon = history({ ...known, lastLocated: { deviceKeyId: "d1", location: at(MUMBAI, 4) } });
    assert.deepEqual(rulesFired(facts({ location: at(LONDON, 0) }), tooSoon), []);
    const near = history({ ...known, lastLocated: { deviceKeyId: "d1", location: at({ latitude: 19.5, longitude: 72.88 }, 5) } });
    assert.ok(distanceKm(MUMBAI, { latitude: 19.5, longitude: 72.88 }) < 100);
    assert.deepEqual(rulesFired(facts({ location: at(MUMBAI, 0) }), near), []);
  });
  test("no location and no IP country: not evaluated (no finding, never 'safe')", () => {
    assert.deepEqual(rulesFired(facts(), history(known)), []);
  });
  test("IP country: IN then GB 20 minutes later fires with a VPN/roaming caveat; same country or > window does not", () => {
    const prev = (country: string, minutesAgo: number) => ({ country, receivedAt: new Date(NOW - minutesAgo * MIN), deviceKeyId: "d1" });
    const [f] = evaluateRiskRules(facts({ ipCountry: "GB" }), history({ ...known, lastIpCountry: prev("IN", 20) }), DEFAULT_RISK_RULES);
    assert.equal(f.rule, "impossible_travel");
    assert.equal(f.evidence.basis, "ip_country");
    assert.match(f.explanation, /VPN or mobile roaming/);
    assert.deepEqual(rulesFired(facts({ ipCountry: "IN" }), history({ ...known, lastIpCountry: prev("IN", 20) })), []);
    assert.deepEqual(rulesFired(facts({ ipCountry: "GB" }), history({ ...known, lastIpCountry: prev("IN", 61) })), []);
    assert.deepEqual(rulesFired(facts({ ipCountry: "GB" }), history({ ...known, lastIpCountry: prev("IN", 2) })), [], "under minMinutes");
    const off = mergeRiskRules(DEFAULT_RISK_RULES, { impossibleTravel: { ipCountryChangeMinutes: 0 } });
    assert.deepEqual(rulesFired(facts({ ipCountry: "GB" }), history({ ...known, lastIpCountry: prev("IN", 20) }), off), []);
  });
  test("abuse: a location pair decides on its own — a forged IP-country change cannot add a second finding", () => {
    const h = history({
      ...known,
      lastLocated: { deviceKeyId: "d1", location: at(MUMBAI, 180) },
      lastIpCountry: { country: "US", receivedAt: new Date(NOW - 20 * MIN), deviceKeyId: "d1" },
    });
    assert.deepEqual(rulesFired(facts({ location: at(DELHI, 0), ipCountry: "IN" }), h), []);
  });
});

describe("transaction_velocity and new_beneficiary", () => {
  const tx = (over: Partial<RiskEventFacts> = {}) =>
    facts({ type: "transaction", sessionEvent: undefined, beneficiaryHash: "be".repeat(32), deviceKeyId: "dev-old", ...over });
  const known = { bindings: [bound("dev-old", 9999)] };

  test("normal: the 6th transaction in 10 minutes fires (high)", () => {
    const f = evaluateRiskRules(tx(), history({ ...known, recentTransactionCount: 5 }), DEFAULT_RISK_RULES)
      .find((x) => x.rule === "transaction_velocity")!;
    assert.equal(f.severity, "high");
    assert.equal(f.evidence.transactions_in_window, 6);
  });
  test("edge: the 5th transaction (= limit) does not fire", () => {
    assert.deepEqual(rulesFired(tx(), history({ ...known, recentTransactionCount: 4 })), []);
  });
  test("abuse: a burst of 100 keeps firing; session events never count as transactions", () => {
    assert.ok(rulesFired(tx(), history({ ...known, recentTransactionCount: 99 })).includes("transaction_velocity"));
    assert.ok(!rulesFired(facts({ deviceKeyId: "dev-old" }), history({ ...known, recentTransactionCount: 99 })).includes("transaction_velocity"));
  });
  test("new_beneficiary: normal fires (low) with a shortened hash; a known beneficiary does not; sessions never", () => {
    const f = evaluateRiskRules(tx(), history({ ...known, beneficiarySeenBefore: false }), DEFAULT_RISK_RULES)[0];
    assert.equal(f.rule, "new_beneficiary");
    assert.equal(f.severity, "low");
    assert.equal(f.evidence.beneficiary_hash, "be".repeat(6));
    assert.deepEqual(rulesFired(tx(), history({ ...known, beneficiarySeenBefore: true })), []);
    assert.deepEqual(rulesFired(facts({ deviceKeyId: "dev-old" }), history({ ...known, beneficiarySeenBefore: false })), []);
  });
});

describe("thresholds", () => {
  test("defaults; stored values merged per field; out-of-range or junk falls back to the default", () => {
    assert.deepEqual(effectiveRiskRules(null), DEFAULT_RISK_RULES);
    const r = effectiveRiskRules({ transactionVelocity: { maxCount: 3 }, concurrentSessions: { maxDevices: 0 }, junk: 1 });
    assert.equal(r.transactionVelocity.maxCount, 3);
    assert.equal(r.transactionVelocity.windowMinutes, 10);
    assert.equal(r.concurrentSessions.maxDevices, 2, "0 is below the allowed range");
    assert.deepEqual(effectiveRiskRules("x"), DEFAULT_RISK_RULES);
    assert.deepEqual(effectiveRiskRules([1, 2]), DEFAULT_RISK_RULES);
  });
  test("patch schema: partial ok; out of range, non-integer, unknown rule or field rejected", () => {
    assert.ok(riskRulesPatchSchema.safeParse({ transactionVelocity: { maxCount: 10 } }).success);
    assert.ok(!riskRulesPatchSchema.safeParse({ transactionVelocity: { maxCount: 0 } }).success);
    assert.ok(!riskRulesPatchSchema.safeParse({ transactionVelocity: { maxCount: 2.5 } }).success);
    assert.ok(!riskRulesPatchSchema.safeParse({ impossibleTravel: { maxSpeedKmh: 1_000_000 } }).success);
    assert.ok(!riskRulesPatchSchema.safeParse({ mlModel: {} }).success);
    assert.ok(!riskRulesPatchSchema.safeParse({ transactionVelocity: { amountLimit: 5 } }).success);
    assert.ok(!riskRulesPatchSchema.safeParse({ transactionVelocity: { maxCount: "5" } }).success);
  });
  test("merge leaves other rules and fields untouched and does not mutate the input", () => {
    const merged = mergeRiskRules(DEFAULT_RISK_RULES, { impossibleTravel: { maxSpeedKmh: 500 } });
    assert.equal(merged.impossibleTravel.maxSpeedKmh, 500);
    assert.equal(merged.impossibleTravel.minMinutes, 5);
    assert.equal(DEFAULT_RISK_RULES.impossibleTravel.maxSpeedKmh, 900);
  });
});
