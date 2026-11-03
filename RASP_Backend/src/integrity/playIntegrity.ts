import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { redis } from "../redis/client";

/**
 * Google Play Integrity, server side.
 *
 * Flow: the SDK asks `POST /v1/integrity/challenge` for a one-time nonce,
 * calls Play Integrity on the phone with it, and sends the token to
 * `POST /v1/integrity/verify`. This module decodes the token with Google
 * (`playintegrity.googleapis.com/v1/<package>:decodeIntegrityToken`, a
 * service account with the Play Integrity API enabled) and turns the verdict
 * into PASS / FAIL with the reasons. The phone never decides.
 *
 * Config (all server-side; see docs/PLAY_INTEGRITY_SETUP.md):
 * - PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE: path to the service account JSON key
 *   (never committed, never sent anywhere but Google's token endpoint);
 * - PLAY_INTEGRITY_ALLOWED_PACKAGES: comma-separated package names this
 *   backend accepts tokens for;
 * - PLAY_INTEGRITY_REQUIRE: comma-separated extra requirements, any of
 *   `PLAY_RECOGNIZED` (app installed from Play, default on), `LICENSED`,
 *   `STRONG` (hardware-backed device integrity);
 * - PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS: default 300.
 */

export const INTEGRITY_NONCE_TTL_SECONDS = 300;

// ── Nonces ─────────────────────────────────────────────────────────────

export interface NonceStore {
  save(applicationId: string, nonce: string, ttlSeconds: number): Promise<void>;
  /** `true` once for a saved, unexpired nonce; it is gone afterwards. */
  consume(applicationId: string, nonce: string): Promise<boolean>;
}

const nonceKey = (applicationId: string, nonce: string) => `pi_nonce:${applicationId}:${nonce}`;

export const redisNonceStore: NonceStore = {
  async save(applicationId, nonce, ttlSeconds) {
    await redis.set(nonceKey(applicationId, nonce), "1", "EX", ttlSeconds);
  },
  async consume(applicationId, nonce) {
    return (await redis.del(nonceKey(applicationId, nonce))) === 1;
  },
};

/** The stores in use; tests replace them. */
export const integrityDeps: { nonces: NonceStore; decode: TokenDecoder } = {
  nonces: redisNonceStore,
  decode: (packageName, token) => googleDecoder().decode(packageName, token),
};

/** 32 random bytes, base64url without padding (Play Integrity needs URL-safe base64, 16–500 chars). */
export async function issueIntegrityNonce(applicationId: string): Promise<string> {
  const nonce = crypto.randomBytes(32).toString("base64url");
  await integrityDeps.nonces.save(applicationId, nonce, INTEGRITY_NONCE_TTL_SECONDS);
  return nonce;
}

// ── Configuration ──────────────────────────────────────────────────────

export interface IntegrityConfig {
  serviceAccountFile: string | null;
  allowedPackages: Set<string>;
  requirePlayRecognized: boolean;
  requireLicensed: boolean;
  requireStrong: boolean;
  maxTokenAgeSeconds: number;
}

export function loadIntegrityConfig(env: NodeJS.ProcessEnv = process.env): IntegrityConfig {
  const list = (v: string | undefined) => new Set((v ?? "").split(",").map((s) => s.trim()).filter(Boolean));
  const require = list(env.PLAY_INTEGRITY_REQUIRE ?? "PLAY_RECOGNIZED");
  return {
    serviceAccountFile: env.PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE?.trim() || null,
    allowedPackages: list(env.PLAY_INTEGRITY_ALLOWED_PACKAGES),
    requirePlayRecognized: require.has("PLAY_RECOGNIZED"),
    requireLicensed: require.has("LICENSED"),
    requireStrong: require.has("STRONG"),
    maxTokenAgeSeconds: Number(env.PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS) || 300,
  };
}

export const integrityConfigured = (c: IntegrityConfig) => c.serviceAccountFile !== null && c.allowedPackages.size > 0;

// ── Verdict ────────────────────────────────────────────────────────────

/** The `tokenPayloadExternal` object Google returns (fields this backend reads). */
export interface IntegrityPayload {
  requestDetails?: { requestPackageName?: string; nonce?: string; timestampMillis?: string | number };
  appIntegrity?: { appRecognitionVerdict?: string; packageName?: string; certificateSha256Digest?: string[]; versionCode?: string };
  deviceIntegrity?: { deviceRecognitionVerdict?: string[] };
  accountDetails?: { appLicensingVerdict?: string };
}

export interface IntegrityVerdict {
  verdict: "PASS" | "FAIL";
  /** Stable reason codes; empty on PASS. */
  reasons: string[];
  appRecognition: string | null;
  deviceRecognition: string[];
  licensing: string | null;
  versionCode: string | null;
}

/** Google sends certificate digests as unpadded base64url; the dashboard stores uppercase hex. */
export function digestToHex(base64url: string): string {
  return Buffer.from(base64url, "base64url").toString("hex").toUpperCase();
}

export function evaluateIntegrity(input: {
  payload: IntegrityPayload;
  packageName: string;
  nonce: string;
  expectedCertSha256: string | null;
  config: IntegrityConfig;
  now: Date;
}): IntegrityVerdict {
  const { payload, config } = input;
  const reasons: string[] = [];
  const req = payload.requestDetails ?? {};
  const app = payload.appIntegrity ?? {};
  const device = payload.deviceIntegrity?.deviceRecognitionVerdict ?? [];
  const licensing = payload.accountDetails?.appLicensingVerdict ?? null;

  if (req.nonce !== input.nonce) reasons.push("NONCE_MISMATCH");
  if (req.requestPackageName !== input.packageName) reasons.push("PACKAGE_MISMATCH");
  const issued = Number(req.timestampMillis);
  if (!Number.isFinite(issued)) reasons.push("NO_TIMESTAMP");
  else if (Math.abs(input.now.getTime() - issued) > config.maxTokenAgeSeconds * 1000) reasons.push("TOKEN_TOO_OLD");

  const recognized = app.appRecognitionVerdict ?? null;
  if (recognized === "UNRECOGNIZED_VERSION") reasons.push("APP_NOT_RECOGNIZED");
  else if (config.requirePlayRecognized && recognized !== "PLAY_RECOGNIZED") reasons.push("APP_NOT_PLAY_RECOGNIZED");
  if (app.packageName !== undefined && app.packageName !== input.packageName) reasons.push("APP_PACKAGE_MISMATCH");
  if (input.expectedCertSha256) {
    const certs = (app.certificateSha256Digest ?? []).map(digestToHex);
    if (certs.length > 0 && !certs.includes(input.expectedCertSha256.toUpperCase())) reasons.push("SIGNING_CERT_MISMATCH");
  }

  if (!device.includes("MEETS_DEVICE_INTEGRITY") && !device.includes("MEETS_STRONG_INTEGRITY")) reasons.push("DEVICE_INTEGRITY_FAILED");
  else if (config.requireStrong && !device.includes("MEETS_STRONG_INTEGRITY")) reasons.push("STRONG_INTEGRITY_REQUIRED");
  if (config.requireLicensed && licensing !== "LICENSED") reasons.push("NOT_LICENSED");

  return {
    verdict: reasons.length === 0 ? "PASS" : "FAIL",
    reasons,
    appRecognition: recognized,
    deviceRecognition: device,
    licensing,
    versionCode: app.versionCode ?? null,
  };
}

// ── Google API ─────────────────────────────────────────────────────────

export type TokenDecoder = (packageName: string, token: string) => Promise<IntegrityPayload>;

export class IntegrityDecodeError extends Error {
  constructor(readonly code: string, readonly status?: number) {
    super(code);
  }
}

interface ServiceAccount {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

const SCOPE = "https://www.googleapis.com/auth/playintegrity";

/** Decodes tokens with a service account (OAuth 2 JWT bearer grant, RS256 via node:crypto). */
export function createGoogleDecoder(account: ServiceAccount, fetchImpl: typeof fetch = fetch) {
  let cached: { token: string; expiresAt: number } | null = null;
  const tokenUri = account.token_uri ?? "https://oauth2.googleapis.com/token";

  async function accessToken(): Promise<string> {
    if (cached && cached.expiresAt - 60_000 > Date.now()) return cached.token;
    const now = Math.floor(Date.now() / 1000);
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const unsigned = `${b64({ alg: "RS256", typ: "JWT" })}.${b64({ iss: account.client_email, scope: SCOPE, aud: tokenUri, iat: now, exp: now + 3600 })}`;
    const signature = crypto.sign("RSA-SHA256", Buffer.from(unsigned), account.private_key).toString("base64url");
    const res = await fetchImpl(tokenUri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: `${unsigned}.${signature}` }),
    });
    if (!res.ok) throw new IntegrityDecodeError("GOOGLE_AUTH_FAILED", res.status);
    const body = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!body.access_token) throw new IntegrityDecodeError("GOOGLE_AUTH_FAILED");
    cached = { token: body.access_token, expiresAt: Date.now() + (body.expires_in ?? 3600) * 1000 };
    return cached.token;
  }

  return {
    async decode(packageName: string, integrityToken: string): Promise<IntegrityPayload> {
      const url = `https://playintegrity.googleapis.com/v1/${encodeURIComponent(packageName)}:decodeIntegrityToken`;
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" },
        body: JSON.stringify({ integrity_token: integrityToken }),
      });
      // 400 = malformed/foreign token, 403 = this project may not decode it.
      if (!res.ok) throw new IntegrityDecodeError(res.status === 400 || res.status === 403 ? "TOKEN_REJECTED_BY_GOOGLE" : "GOOGLE_UNAVAILABLE", res.status);
      const body = (await res.json()) as { tokenPayloadExternal?: IntegrityPayload };
      if (!body.tokenPayloadExternal) throw new IntegrityDecodeError("GOOGLE_EMPTY_RESPONSE");
      return body.tokenPayloadExternal;
    },
  };
}

let decoder: ReturnType<typeof createGoogleDecoder> | null = null;

function googleDecoder() {
  if (decoder) return decoder;
  const file = loadIntegrityConfig().serviceAccountFile;
  if (!file) throw new IntegrityDecodeError("NOT_CONFIGURED");
  let account: ServiceAccount;
  try {
    account = JSON.parse(readFileSync(file, "utf8")) as ServiceAccount;
  } catch {
    throw new IntegrityDecodeError("SERVICE_ACCOUNT_UNREADABLE");
  }
  if (!account.client_email || !account.private_key) throw new IntegrityDecodeError("SERVICE_ACCOUNT_UNREADABLE");
  decoder = createGoogleDecoder(account);
  return decoder;
}
