// Play Integrity server-side verification (src/integrity/playIntegrity.ts).
// Real: the verdict rules, the digest conversion, the service-account JWT
// (signed with node:crypto and checked here with the public key), the
// decode request. Fake: Google's two endpoints (a fetch stub). The routes'
// auth and "not configured" answers are in test/secretExposure.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  createGoogleDecoder,
  digestToHex,
  evaluateIntegrity,
  IntegrityDecodeError,
  IntegrityPayload,
  loadIntegrityConfig,
} from "../src/integrity/playIntegrity";

const NOW = new Date("2026-10-24T10:00:00Z");
const PKG = "com.example.bank";
const NONCE = "n".repeat(43);
const CERT_HEX = "AB".repeat(32);
const CERT_B64URL = Buffer.from(CERT_HEX, "hex").toString("base64url");
const config = loadIntegrityConfig({ PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE: "x.json", PLAY_INTEGRITY_ALLOWED_PACKAGES: PKG });

function payload(over: Partial<{ nonce: string; pkg: string; ts: number; app: string; certs: string[]; device: string[]; licensing: string }> = {}): IntegrityPayload {
  return {
    requestDetails: { requestPackageName: over.pkg ?? PKG, nonce: over.nonce ?? NONCE, timestampMillis: String(over.ts ?? NOW.getTime() - 5_000) },
    appIntegrity: { appRecognitionVerdict: over.app ?? "PLAY_RECOGNIZED", packageName: PKG, certificateSha256Digest: over.certs ?? [CERT_B64URL], versionCode: "7" },
    deviceIntegrity: { deviceRecognitionVerdict: over.device ?? ["MEETS_DEVICE_INTEGRITY"] },
    accountDetails: { appLicensingVerdict: over.licensing ?? "LICENSED" },
  };
}
const verdict = (p: IntegrityPayload, c = config, cert: string | null = CERT_HEX) =>
  evaluateIntegrity({ payload: p, packageName: PKG, nonce: NONCE, expectedCertSha256: cert, config: c, now: NOW });

test("a genuine Play-installed app on a genuine device passes", () => {
  const v = verdict(payload());
  assert.equal(v.verdict, "PASS");
  assert.deepEqual(v.reasons, []);
  assert.equal(v.versionCode, "7");
});

test("digests: Google's base64url is compared with the dashboard's hex", () => {
  assert.equal(digestToHex(CERT_B64URL), CERT_HEX);
  assert.deepEqual(verdict(payload({ certs: [Buffer.from("CD".repeat(32), "hex").toString("base64url")] })).reasons, ["SIGNING_CERT_MISMATCH"]);
  assert.equal(verdict(payload(), config, null).verdict, "PASS", "no expected certificate configured: not compared");
});

test("replayed or foreign tokens fail: nonce, package, age", () => {
  assert.deepEqual(verdict(payload({ nonce: "other".repeat(5) })).reasons, ["NONCE_MISMATCH"]);
  assert.ok(verdict(payload({ pkg: "com.evil" })).reasons.includes("PACKAGE_MISMATCH"));
  assert.deepEqual(verdict(payload({ ts: NOW.getTime() - 301_000 })).reasons, ["TOKEN_TOO_OLD"]);
});

test("device and app verdicts", () => {
  assert.deepEqual(verdict(payload({ device: [] })).reasons, ["DEVICE_INTEGRITY_FAILED"]);
  assert.deepEqual(verdict(payload({ device: ["MEETS_BASIC_INTEGRITY"] })).reasons, ["DEVICE_INTEGRITY_FAILED"]);
  assert.deepEqual(verdict(payload({ app: "UNRECOGNIZED_VERSION" })).reasons, ["APP_NOT_RECOGNIZED"]);
  assert.deepEqual(verdict(payload({ app: "UNEVALUATED" })).reasons, ["APP_NOT_PLAY_RECOGNIZED"]);
  const lax = loadIntegrityConfig({ PLAY_INTEGRITY_REQUIRE: "" });
  assert.equal(verdict(payload({ app: "UNEVALUATED" }), lax).verdict, "PASS", "sideloaded test builds when PLAY_RECOGNIZED is not required");
});

test("optional requirements: STRONG and LICENSED", () => {
  const strict = loadIntegrityConfig({ PLAY_INTEGRITY_REQUIRE: "PLAY_RECOGNIZED,STRONG,LICENSED" });
  assert.deepEqual(verdict(payload(), strict).reasons, ["STRONG_INTEGRITY_REQUIRED"]);
  assert.equal(verdict(payload({ device: ["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"] }), strict).verdict, "PASS");
  assert.deepEqual(verdict(payload({ device: ["MEETS_STRONG_INTEGRITY"], licensing: "UNLICENSED" }), strict).reasons, ["NOT_LICENSED"]);
});

// ── Google client ────────────────────────────────────────────────────────

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const account = {
  client_email: "rasp-integrity@example.iam.gserviceaccount.com",
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  token_uri: "https://oauth2.googleapis.com/token",
};

function fakeGoogle(decodeStatus = 200) {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    if (url === account.token_uri) return new Response(JSON.stringify({ access_token: "ya29.test", expires_in: 3600 }), { status: 200 });
    if (decodeStatus !== 200) return new Response("{}", { status: decodeStatus });
    return new Response(JSON.stringify({ tokenPayloadExternal: payload() }), { status: 200 });
  }) as unknown as typeof fetch;
  return { calls, impl };
}

test("decoder: signed service-account JWT, bearer token reused, decode request shape", async () => {
  const google = fakeGoogle();
  const decoder = createGoogleDecoder(account, google.impl);
  const first = await decoder.decode(PKG, "TOKEN-1");
  await decoder.decode(PKG, "TOKEN-2");
  assert.equal(first.requestDetails?.nonce, NONCE);
  assert.equal(google.calls.filter((c) => c.url === account.token_uri).length, 1, "access token cached");

  const assertion = new URLSearchParams(String(google.calls[0].init.body)).get("assertion")!;
  const [h, p, s] = assertion.split(".");
  assert.ok(crypto.verify("RSA-SHA256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url")));
  const claims = JSON.parse(Buffer.from(p, "base64url").toString());
  assert.equal(claims.iss, account.client_email);
  assert.equal(claims.scope, "https://www.googleapis.com/auth/playintegrity");

  const decode = google.calls[1];
  assert.equal(decode.url, `https://playintegrity.googleapis.com/v1/${PKG}:decodeIntegrityToken`);
  assert.equal((decode.init.headers as Record<string, string>).Authorization, "Bearer ya29.test");
  assert.deepEqual(JSON.parse(String(decode.init.body)), { integrity_token: "TOKEN-1" });
});

test("decoder: Google refusing the token vs Google being down", async () => {
  for (const [status, code] of [[400, "TOKEN_REJECTED_BY_GOOGLE"], [403, "TOKEN_REJECTED_BY_GOOGLE"], [500, "GOOGLE_UNAVAILABLE"]] as const) {
    await assert.rejects(createGoogleDecoder(account, fakeGoogle(status).impl).decode(PKG, "T"),
      (e: unknown) => e instanceof IntegrityDecodeError && e.code === code);
  }
});
