// Server-side key attestation (F-13 / F-14).
// Real: inspectAttestationChain against the embedded Google roots and a real
// StrongBox chain from a development phone (test/fixtures/real-attestation-
// chain.json); KeyDescription parsing; the policy rules; challenge
// signatures; registerDevice under RECORD and REQUIRE_HARDWARE; the
// envelope and risk-event checks.
// Built in the test (test/attestationBuilder.ts): a test root and attested
// leaf certificates for keys the test holds, so possession can be proven.
// Doubles: in-memory registration repository and challenge store.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { computeDeviceKeyId, inspectAttestationChain } from "../src/crypto/ecdsa";
import { attestationTrust, normalizeSerial } from "../src/crypto/attestationTrust";
import { attestationShortfalls, PolicyInput, rowMeetsPolicy } from "../src/devices/attestationPolicy";
import { ChallengeStore, issueChallenge, possessionMessage, registrationChallenges, verifyPossession } from "../src/devices/registrationChallenge";
import { ApplicationPolicy, registerDevice } from "../src/devices/registration";
import { attestedLeaf, spkiBase64, testRoot } from "./attestationBuilder";
import { MemoryRegistrationRepository } from "./support";

const real = JSON.parse(readFileSync(path.join(__dirname, "fixtures/real-attestation-chain.json"), "utf8"));
const REAL_AT = new Date(real.registeredAt);
const REAL_DIGEST = "B7415079117872FC2AFE47E672F1B703F7757F9F99ECD4EF9DD58B27A092DEEE";
const synthetic = JSON.parse(readFileSync(path.join(__dirname, "fixtures/attestation-certs.json"), "utf8"));
const spki = (b64: string) => Buffer.from(b64, "base64");

describe("inspectAttestationChain with the Google roots", () => {
  test("the real StrongBox chain verifies and its attested fields are read", () => {
    const r = inspectAttestationChain(spki(real.publicKey), real.attestationChain, { now: REAL_AT, revoked: new Map() });
    assert.equal(r.verdict, "verified");
    assert.equal(r.rootVerified, true);
    assert.equal(r.validityOk, true);
    assert.equal(r.revocationChecked, true);
    assert.equal(r.attestationSecurityLevel, 2);
    assert.deepEqual(r.attestedPackages, ["com.example.rasp_trial"]);
    assert.deepEqual(r.attestedSigningCertSha256, [REAL_DIGEST]);
    assert.equal(r.deviceLocked, true);
    assert.equal(r.verifiedBootState, "VERIFIED");
    assert.equal(r.osPatchLevel, 202608);
  });

  test("without a revocation list it still verifies, recorded as not checked", () => {
    const r = inspectAttestationChain(spki(real.publicKey), real.attestationChain, { now: REAL_AT, revoked: null });
    assert.equal(r.verdict, "verified");
    assert.equal(r.revocationChecked, false);
  });

  test("a revoked certificate in the chain makes it unverified", () => {
    const serial = new crypto.X509Certificate(Buffer.from(real.attestationChain[2], "base64")).serialNumber;
    const r = inspectAttestationChain(spki(real.publicKey), real.attestationChain, { now: REAL_AT, revoked: new Map([[normalizeSerial(serial), "REVOKED"]]) });
    assert.equal(r.verdict, "unverified");
    assert.deepEqual(r.revokedSerials, [normalizeSerial(serial)]);
  });

  test("expired intermediates, an untrusted root, a missing root or another key make it unverified", () => {
    const later = inspectAttestationChain(spki(real.publicKey), real.attestationChain, { now: new Date("2027-01-01T00:00:00Z") });
    assert.deepEqual([later.verdict, later.validityOk], ["unverified", false]);
    const noRoots = inspectAttestationChain(spki(real.publicKey), real.attestationChain, { now: REAL_AT, roots: [] });
    assert.deepEqual([noRoots.verdict, noRoots.rootVerified], ["unverified", false]);
    const truncated = inspectAttestationChain(spki(real.publicKey), real.attestationChain.slice(0, -1), { now: REAL_AT });
    assert.deepEqual([truncated.verdict, truncated.rootVerified], ["unverified", false]);
    const otherKey = inspectAttestationChain(spki(synthetic.otherPublicKey), real.attestationChain, { now: REAL_AT });
    assert.deepEqual([otherKey.verdict, otherKey.status], ["unverified", "KEY_MISMATCH"]);
  });

  test("a chain to a self-made root claiming TEE is unverified (this used to read as verified)", () => {
    const r = inspectAttestationChain(spki(synthetic.publicKey), synthetic.attested, { now: new Date("2026-10-05T00:00:00Z") });
    assert.equal(r.attestationSecurityLevel, 1);
    assert.equal(r.rootVerified, false);
    assert.equal(r.verdict, "unverified");
  });

  test("serials are compared in the revocation list's form", () => {
    assert.equal(normalizeSerial("00AB:CD"), "abcd");
    assert.equal(normalizeSerial("84A9D0297B0EB58AE7FF0E80DE760605"), "84a9d0297b0eb58ae7ff0e80de760605");
    assert.equal(normalizeSerial("00"), "0");
  });
});

describe("attestation policy", () => {
  const ok: PolicyInput = {
    policy: "REQUIRE_HARDWARE", appId: "com.bank", expectedSigningCertSha256: "AA".repeat(32),
    verdict: "verified", possessionVerified: true, revocationChecked: true, revocationRequired: true,
    attestedPackages: ["com.bank"], attestedSigningCertSha256: ["AA".repeat(32)],
  };
  test("each requirement has its own reason", () => {
    assert.deepEqual(attestationShortfalls(ok), []);
    assert.deepEqual(attestationShortfalls({ ...ok, verdict: "software-only" }), ["attestation_not_verified"]);
    assert.deepEqual(attestationShortfalls({ ...ok, revocationChecked: false }), ["revocation_not_checked"]);
    assert.deepEqual(attestationShortfalls({ ...ok, revocationChecked: false, revocationRequired: false }), []);
    assert.deepEqual(attestationShortfalls({ ...ok, possessionVerified: false }), ["possession_not_proven"]);
    assert.deepEqual(attestationShortfalls({ ...ok, attestedPackages: ["com.bank.repack"] }), ["package_mismatch"]);
    assert.deepEqual(attestationShortfalls({ ...ok, attestedSigningCertSha256: ["BB".repeat(32)] }), ["signing_certificate_mismatch"]);
    assert.deepEqual(attestationShortfalls({ ...ok, expectedSigningCertSha256: null, attestedSigningCertSha256: [] }), []);
  });
  test("RECORD accepts every key; REQUIRE_HARDWARE only compliant ones (row form used by ingestion)", () => {
    const row = (policy: "RECORD" | "REQUIRE_HARDWARE", verdict: string) => ({
      appId: "com.bank", attestationVerdict: verdict, possessionVerified: true,
      attestationDetails: { revocationChecked: true, attestedPackages: ["com.bank"], attestedSigningCertSha256: [] },
      application: { attestationPolicy: policy, expectedSigningCertSha256: null },
    });
    assert.equal(rowMeetsPolicy(row("RECORD", "unverified"), true), true);
    assert.equal(rowMeetsPolicy(row("REQUIRE_HARDWARE", "unverified"), true), false);
    assert.equal(rowMeetsPolicy(row("REQUIRE_HARDWARE", "verified"), true), true);
  });
});

class MemoryChallenges implements ChallengeStore {
  live = new Set<string>();
  async save(applicationId: string, challenge: string) {
    this.live.add(`${applicationId}:${challenge}`);
  }
  async consume(applicationId: string, challenge: string) {
    return this.live.delete(`${applicationId}:${challenge}`);
  }
}

describe("registration with possession proof and policy", () => {
  const savedStore = registrationChallenges.store;
  const savedRoots = attestationTrust.roots;
  let challenges: MemoryChallenges;
  const root = testRoot();
  const NOW = new Date("2026-10-09T10:00:00Z");
  const APP_DIGEST = "CD".repeat(32);

  before(() => {
    challenges = new MemoryChallenges();
    registrationChallenges.store = challenges;
    attestationTrust.roots = [root.cert];
  });
  after(() => {
    registrationChallenges.store = savedStore;
    attestationTrust.roots = savedRoots;
  });

  class PolicyRepo extends MemoryRegistrationRepository {
    constructor(public policy: ApplicationPolicy) {
      super();
    }
    async policyFor() {
      return this.policy;
    }
    updated: string[] = [];
    deviceIds: Array<string | undefined> = [];
    async updateAttestation(id: string, _a: unknown, _p: boolean, _n: Date, deviceId?: string) {
      this.updated.push(id);
      this.deviceIds.push(deviceId);
    }
  }

  function device(spec: Parameters<typeof attestedLeaf>[1] = { securityLevel: 2, packages: ["com.bank"], signingDigestsHex: [APP_DIGEST] }) {
    const leaf = attestedLeaf(root, spec);
    const publicKey = spkiBase64(leaf.publicKey);
    const deviceKeyId = computeDeviceKeyId(spki(publicKey));
    return {
      publicKey,
      deviceKeyId,
      chain: [leaf.base64, root.base64],
      prove: async (applicationId = "app-1") => {
        const challenge = await issueChallenge(applicationId);
        const sig = crypto.sign("sha256", possessionMessage(challenge, deviceKeyId), { key: leaf.key, dsaEncoding: "der" });
        return { challenge, challengeSignature: sig.toString("base64") };
      },
    };
  }
  const body = (d: ReturnType<typeof device>, extra: Record<string, unknown> = {}) => ({
    appId: "com.bank", publicKey: d.publicKey, attestationChain: d.chain, sdkVersion: "1.2.0", ...extra,
  });

  test("a signed challenge proves possession once; reuse, another app or another key does not", async () => {
    const d = device();
    const proof = await d.prove();
    assert.equal(verifyPossession(spki(d.publicKey), proof.challenge, d.deviceKeyId, proof.challengeSignature), true);
    assert.equal(verifyPossession(spki(d.publicKey), proof.challenge, "other-key-id", proof.challengeSignature), false);
    assert.equal(verifyPossession(spki(synthetic.publicKey), proof.challenge, d.deviceKeyId, proof.challengeSignature), false);
    const repo = new PolicyRepo({ policy: "RECORD", expectedSigningCertSha256: null });
    const first = await registerDevice({ body: body(d, proof), applicationId: "app-1", now: NOW, repo, revoked: new Map() });
    assert.deepEqual([first.status, first.body.possessionVerified, first.body.attestationVerdict], [201, true, "verified"]);
    const second = await registerDevice({ body: body(d, proof), applicationId: "app-1", now: NOW, repo, revoked: new Map() });
    assert.equal(second.body.possessionVerified, true, "stored value");
    assert.deepEqual(repo.updated, [], "a used challenge does not replace the stored attestation");
    const otherApp = device();
    const proofForApp1 = await otherApp.prove("app-1");
    const wrongApp = await registerDevice({ body: body(otherApp, proofForApp1), applicationId: "app-2", now: NOW, repo: new PolicyRepo({ policy: "RECORD", expectedSigningCertSha256: null }), revoked: new Map() });
    assert.equal(wrongApp.body.possessionVerified, false);
  });

  test("REQUIRE_HARDWARE: a compliant, possession-proven key registers", async () => {
    const d = device();
    const repo = new PolicyRepo({ policy: "REQUIRE_HARDWARE", expectedSigningCertSha256: APP_DIGEST });
    const out = await registerDevice({ body: body(d, await d.prove()), applicationId: "app-1", now: NOW, repo, revoked: new Map() });
    assert.equal(out.status, 201, JSON.stringify(out.body));
    assert.equal(repo.rows.length, 1);
    assert.equal(repo.rows[0].input.possessionVerified, true);
  });

  test("REQUIRE_HARDWARE: each shortfall is refused with 403 and nothing is stored", async () => {
    const cases: Array<[string, ReturnType<typeof device>, boolean, string[]]> = [
      ["no possession proof", device(), false, ["possession_not_proven"]],
      ["software-level key", device({ securityLevel: 0, packages: ["com.bank"], signingDigestsHex: [APP_DIGEST] }), true, ["attestation_not_verified"]],
      ["repackaged app (other signing certificate)", device({ securityLevel: 1, packages: ["com.bank"], signingDigestsHex: ["EE".repeat(32)] }), true, ["signing_certificate_mismatch"]],
      ["another package", device({ securityLevel: 1, packages: ["com.bank.clone"], signingDigestsHex: [APP_DIGEST] }), true, ["package_mismatch"]],
    ];
    for (const [name, d, prove, reasons] of cases) {
      const repo = new PolicyRepo({ policy: "REQUIRE_HARDWARE", expectedSigningCertSha256: APP_DIGEST });
      const out = await registerDevice({ body: body(d, prove ? await d.prove() : {}), applicationId: "app-1", now: NOW, repo, revoked: new Map() });
      assert.deepEqual([out.status, out.body.error, out.body.reasons], [403, "ATTESTATION_REQUIRED", reasons], name);
      assert.equal(repo.rows.length, 0, `${name}: not stored`);
    }
  });

  test("REQUIRE_HARDWARE without a revocation list: 503, try again later (unless the check is switched off)", async () => {
    const d = device();
    const repo = new PolicyRepo({ policy: "REQUIRE_HARDWARE", expectedSigningCertSha256: null });
    const out = await registerDevice({ body: body(d, await d.prove()), applicationId: "app-1", now: NOW, repo, revoked: null });
    assert.deepEqual([out.status, out.body.error], [503, "ATTESTATION_STATUS_UNAVAILABLE"]);
    const off = await registerDevice({ body: body(d, await d.prove()), applicationId: "app-1", now: NOW, repo, revoked: undefined, revocationRequired: false });
    assert.equal(off.status, 201, JSON.stringify(off.body));
  });

  test("a key registered under RECORD is upgraded by a later possession-proven registration", async () => {
    const d = device();
    const repo = new PolicyRepo({ policy: "RECORD", expectedSigningCertSha256: null });
    await registerDevice({ body: body(d), applicationId: "app-1", now: NOW, repo, revoked: new Map() });
    repo.policy = { policy: "REQUIRE_HARDWARE", expectedSigningCertSha256: null };
    const without = await registerDevice({ body: body(d), applicationId: "app-1", now: NOW, repo, revoked: new Map() });
    assert.deepEqual([without.status, without.body.reasons], [403, ["possession_not_proven"]]);
    const withProof = await registerDevice({ body: body(d, { ...(await d.prove()), deviceId: "e".repeat(64) }), applicationId: "app-1", now: NOW, repo, revoked: new Map() });
    assert.equal(withProof.status, 200, JSON.stringify(withProof.body));
    assert.equal(repo.updated.length, 1);
    assert.deepEqual(repo.deviceIds, ["e".repeat(64)], "the stable device id is added to a row that had none (F-15)");
  });

  test("the real phone chain under REQUIRE_HARDWARE fails only on possession (no private key in the fixture)", async () => {
    attestationTrust.roots = savedRoots; // the Google roots
    try {
      const repo = new PolicyRepo({ policy: "REQUIRE_HARDWARE", expectedSigningCertSha256: REAL_DIGEST });
      const out = await registerDevice({
        body: { appId: "com.example.rasp_trial", publicKey: real.publicKey, attestationChain: real.attestationChain, sdkVersion: "1.1.0-local" },
        applicationId: "app-1", now: REAL_AT, repo, revoked: new Map(),
      });
      assert.deepEqual([out.status, out.body.reasons, out.body.attestationVerdict], [403, ["possession_not_proven"], "verified"]);
    } finally {
      attestationTrust.roots = [root.cert];
    }
  });
});
