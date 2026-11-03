// POST /v1/devices/register — registerDevice rules and attestation-chain parsing.
// Real: registerDevice, parseEcP256PublicKey, inspectAttestationChain
// (node:crypto X509Certificate) on openssl-generated certificates
// (test/fixtures/make-attestation-certs.sh).
// Double: MemoryRegistrationRepository instead of Postgres (see test/support.ts).
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { registerDevice } from "../src/devices/registration";
import { computeDeviceKeyId, inspectAttestationChain } from "../src/crypto/ecdsa";
import { MemoryRegistrationRepository } from "./support";
import { attestationTrust } from "../src/crypto/attestationTrust";

const certs = JSON.parse(readFileSync(path.join(__dirname, "fixtures/attestation-certs.json"), "utf8"));
// Inside the validity of the test CA (created 2026-10-03).
const NOW = new Date(Date.UTC(2026, 9, 5, 12, 0, 0));

const body = (overrides: Record<string, unknown> = {}) => ({
  appId: "com.example.bank",
  deviceId: "device-1",
  publicKey: certs.publicKey,
  attestationChain: certs.attested,
  sdkVersion: "1.1.0-local",
  ...overrides,
});

const register = (repo: MemoryRegistrationRepository, b: unknown, applicationId = "app-1") =>
  registerDevice({ body: b, applicationId, now: NOW, repo });

describe("device registration", () => {
  test("new key with an attested chain is registered and the parse result recorded", async () => {
    const repo = new MemoryRegistrationRepository();
    const out = await register(repo, body());

    assert.equal(out.status, 201);
    assert.equal(out.body.deviceKeyId, computeDeviceKeyId(Buffer.from(certs.publicKey, "base64")));
    const att = out.body.attestation as any;
    assert.equal(att.status, "PARSED");
    assert.equal(att.leafMatchesKey, true);
    assert.equal(att.chainLinked, true);
    assert.equal(att.hasKeyAttestationExtension, true);
    assert.equal(att.selfSignedOnly, false);
    assert.equal(att.rootVerified, false);
    assert.equal(repo.rows.length, 1);
    assert.equal(repo.rows[0].input.attestation.status, "PARSED");
    assert.equal(repo.rows[0].appId, "com.example.bank");
  });

  test("self-signed-only chain is recorded as such", async () => {
    const out = await register(new MemoryRegistrationRepository(), body({ attestationChain: certs.selfSigned }));
    assert.equal(out.status, 201);
    const att = out.body.attestation as any;
    assert.equal(att.status, "PARSED");
    assert.equal(att.selfSignedOnly, true);
    assert.equal(att.hasKeyAttestationExtension, false);
  });

  test("chain for a different key is recorded as KEY_MISMATCH", async () => {
    const out = await register(new MemoryRegistrationRepository(), body({ attestationChain: certs.otherSelfSigned }));
    assert.equal(out.status, 201);
    assert.equal((out.body.attestation as any).status, "KEY_MISMATCH");
  });

  test("unparseable chain is recorded as UNPARSEABLE", async () => {
    const out = await register(new MemoryRegistrationRepository(), body({ attestationChain: ["bm90IGEgY2VydA=="] }));
    assert.equal(out.status, 201);
    assert.equal((out.body.attestation as any).status, "UNPARSEABLE");
  });

  test("public key must be a canonical Base64 SPKI of an EC P-256 key", async () => {
    const repo = new MemoryRegistrationRepository();
    const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey
      .export({ type: "spki", format: "der" }).toString("base64");
    const p384 = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey
      .export({ type: "spki", format: "der" }).toString("base64");
    for (const publicKey of [rsa, p384, "bm90IGEga2V5", ` ${certs.publicKey}`]) {
      const out = await register(repo, body({ publicKey }));
      assert.equal(out.status, 400, publicKey.slice(0, 20));
      assert.equal(out.body.error, "INVALID_PUBLIC_KEY");
    }
    assert.equal(repo.rows.length, 0);
  });

  test("registering the same key again is idempotent", async () => {
    const repo = new MemoryRegistrationRepository();
    await register(repo, body());
    const again = await register(repo, body());
    assert.equal(again.status, 200);
    assert.equal(again.body.existing, true);
    assert.equal(repo.rows.length, 1);
  });

  test("the same key cannot be registered to another application or package", async () => {
    const repo = new MemoryRegistrationRepository();
    await register(repo, body());
    let out = await register(repo, body(), "app-2");
    assert.equal(out.status, 409);
    assert.equal(out.body.error, "DEVICE_KEY_REGISTERED_TO_OTHER_APPLICATION");
    out = await register(repo, body({ appId: "com.other.app" }));
    assert.equal(out.status, 409);
    assert.equal(out.body.error, "DEVICE_KEY_REGISTERED_FOR_OTHER_APP_ID");
  });

  test("a new key for a known deviceId does not replace the existing key", async () => {
    const repo = new MemoryRegistrationRepository();
    await register(repo, body());
    const out = await register(repo, body({ publicKey: certs.otherPublicKey, attestationChain: certs.otherSelfSigned }));
    assert.equal(out.status, 201);
    assert.equal(repo.rows.length, 2);
    assert.equal(repo.rows[0].input.publicKey, certs.publicKey, "original key untouched");
  });

  test("invalid body is rejected", async () => {
    const out = await register(new MemoryRegistrationRepository(), { publicKey: certs.publicKey });
    assert.equal(out.status, 400);
    assert.equal(out.body.error, "INVALID_REGISTER_BODY");
  });

  test("attestation verdict is recorded on the row and shown in the response (test CA trusted as a root)", async () => {
    const googleRoots = attestationTrust.roots;
    attestationTrust.roots = [new crypto.X509Certificate(Buffer.from(certs.attested[1], "base64"))];
    after(() => {
      attestationTrust.roots = googleRoots;
    });
    const cases: Array<[string, unknown, string]> = [
      ["TEE attestation chain", certs.attested, "verified"],
      ["Software-level attestation", certs.attestedSoftware, "software-only"],
      ["single self-signed certificate", certs.selfSigned, "software-only"],
      ["extension that is not a KeyDescription", certs.attestedBadExtension, "unverified"],
      ["certificates in the wrong order", certs.attestedWrongOrder, "unverified"],
      ["chain for another key", certs.otherSelfSigned, "unverified"],
      ["unparseable chain", ["bm90IGEgY2VydA=="], "unverified"],
    ];
    for (const [name, chain, verdict] of cases) {
      const repo = new MemoryRegistrationRepository();
      const out = await register(repo, body({ attestationChain: chain }));
      assert.equal(out.status, 201, `${name}: registration is not rejected`);
      assert.equal(out.body.attestationVerdict, verdict, name);
      assert.equal(repo.rows[0].attestationVerdict, verdict, `${name}: stored on the row`);
    }
  });

  test("re-registering an existing key returns its stored verdict", async () => {
    const repo = new MemoryRegistrationRepository();
    await register(repo, body({ attestationChain: certs.attestedSoftware }));
    const again = await register(repo, body({ attestationChain: certs.attestedSoftware }));
    assert.equal(again.status, 200);
    assert.equal(again.body.attestationVerdict, "software-only");
  });

  test("inspectAttestationChain: empty chain is UNPARSEABLE", () => {
    const r = inspectAttestationChain(Buffer.from(certs.publicKey, "base64"), []);
    assert.equal(r.status, "UNPARSEABLE");
  });
});
