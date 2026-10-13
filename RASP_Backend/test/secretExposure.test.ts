// No response may contain a secret (Task 8.2): the API secret (plaintext or
// encrypted), the account-hash salt, the webhook signing secret, password
// hashes or passwords. The only exceptions are the responses that create or
// rotate one: POST /v1/credentials/applications/:id/credentials and its
// administrator-only, audited .../:credentialId/reveal (api_secret,
// account_hash_salt) and the webhook create / rotate-secret responses
// (secret). Elsewhere only masked prefixes ("abcd…"). The server's signing
// keys (CONFIG_SIGNING_KEY, in every encoding) appear in no response at all.
//
// Every route of every router is called (the last test fails if a route is
// added without a case here) and each response is scanned by
// findSecretLeaks: secret field names, and every secret value known to the
// database at that moment (so a leak under an innocent name, in an error
// message or in a CSV is caught too). Unhandled errors must also keep
// secrets out of the logs.
//
// Real: createApp() — every router, the auth and API-key middleware, the
// JSON/raw-body parsers, the error handler — over real HTTP on an ephemeral
// port; AES-GCM secret encryption; bcrypt; HMAC; JWT.
// Doubles: FakeDatabase (test/fakePrisma.ts) instead of Postgres — it
// returns every column when a query has no `select`, like Prisma; the Redis
// client's commands replaced in-process (no Redis); a local HTTP server as
// the webhook receiver.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { createApp } from "../src/app";
import { appsRouter } from "../src/apps/routes";
import { authRouter } from "../src/auth/routes";
import { credentialsRouter } from "../src/credentials/routes";
import { dashboardRouter } from "../src/dashboard/routes";
import { devicesRouter } from "../src/devices/routes";
import { ingestionRouter } from "../src/ingestion/routes";
import { ipRiskRouter } from "../src/ipRisk/routes";
import { riskRouter } from "../src/risk/routes";
import { reputationRouter } from "../src/reputation/routes";
import { deviceConfigRouter, remoteConfigAdminRouter } from "../src/remoteConfig/routes";
import { configKeyId, configPublicKey } from "../src/remoteConfig/signing";
import { privacyRouter } from "../src/privacy/deviceErasure";
import { sdkDistributionRouter } from "../src/sdk-distribution/routes";
import { webhooksRouter } from "../src/webhooks/routes";
import { redis } from "../src/redis/client";
import { decryptSecret, encryptSecret } from "../src/crypto/secretBox";
import { computeSignature } from "../src/crypto/hmac";
import { isSecretFieldName, maskSecret, redactSecrets } from "../src/security/secretFields";
import { FakeDatabase, installFakePrisma, Row } from "./fakePrisma";
import { findSecretLeaks, KnownSecret } from "./secretLeaks";
import { makeDevice } from "./support";
import { signRiskEnvelope } from "./riskSupport";

// Random per run: test values only, never printed (failure messages name a secret by label).
const random = (bytes: number, encoding: BufferEncoding = "hex") => crypto.randomBytes(bytes).toString(encoding);
const CONFIG_KEY = crypto.generateKeyPairSync("ed25519").privateKey;
const CONFIG_KEY_PKCS8 = (CONFIG_KEY.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64");
const CONFIG_KEY_SEED = CONFIG_KEY.export({ format: "jwk" }).d as string; // base64url of the 32-byte private seed
const ENV = {
  CONFIG_SIGNING_KEY: CONFIG_KEY_PKCS8,
  JWT_SECRET: random(32),
  CREDENTIAL_ENCRYPTION_KEY: random(32),
  PUBLIC_INGESTION_URL: "https://ingest.example.test/v1/events",
  // The webhook receiver runs on 127.0.0.1 over http (development override, see webhooks/destination.ts).
  WEBHOOK_ALLOW_PRIVATE_DESTINATIONS: "1",
};
const OWNER_PASSWORD = random(18, "base64url");
const MEMBER_PASSWORD = random(18, "base64url");
const NEW_USER_PASSWORD = random(18, "base64url");
const SECRET1 = random(36, "base64url");
const SECRET2 = random(36, "base64url");
const SECRET_OTHER = random(36, "base64url");
const SALT1 = random(32);
const SALT_OTHER = random(32);
const WEBHOOK_SECRET = random(32);

const db = new FakeDatabase();
const covered = new Set<string>();
const remembered = new Map<string, string>(); // value → label
const logged: string[] = [];
const savedEnv: Record<string, string | undefined> = {};
const savedRedis: Record<string, unknown> = {};
const savedConsoleError = console.error;
let restorePrisma: () => void = () => {};
let server: http.Server;
let receiver: http.Server;
let base = "";
let newAppId = "";

function remember(label: string, value: unknown) {
  if (typeof value === "string" && value.length > 0 && !remembered.has(value)) remembered.set(value, label);
}

/** Every secret the database holds now, plus every one it ever held (old webhook secrets, …). */
function knownSecrets(): KnownSecret[] {
  for (const c of db.rows("apiCredential")) {
    remember(`encrypted API secret of ${c.id}`, c.apiSecretEncrypted);
    remember(`API secret of ${c.id}`, decryptSecret(c.apiSecretEncrypted as string));
  }
  for (const a of db.rows("application")) remember(`account-hash salt of ${a.id}`, a.accountHashSalt);
  for (const w of db.rows("webhookConfig")) {
    remember(`encrypted webhook secret of ${w.id}`, w.secretEncrypted);
    remember(`webhook secret of ${w.id}`, decryptSecret(w.secretEncrypted as string));
  }
  for (const u of db.rows("user")) remember(`password hash of ${u.id}`, u.passwordHash);
  remember("owner password", OWNER_PASSWORD);
  remember("member password", MEMBER_PASSWORD);
  remember("new user's password", NEW_USER_PASSWORD);
  remember("JWT signing key", ENV.JWT_SECRET);
  remember("credential encryption key", ENV.CREDENTIAL_ENCRYPTION_KEY);
  remember("config signing key (PKCS#8)", CONFIG_KEY_PKCS8);
  remember("config signing key (seed, base64url)", CONFIG_KEY_SEED);
  remember("config signing key (seed, base64)", Buffer.from(CONFIG_KEY_SEED, "base64url").toString("base64"));
  remember("config signing key (seed, hex)", Buffer.from(CONFIG_KEY_SEED, "base64url").toString("hex"));
  return [...remembered].map(([value, label]) => ({ label, value }));
}

const tokens = {
  owner: () => jwt.sign({ userId: "u-owner", organizationId: "org-1", role: "OWNER" }, ENV.JWT_SECRET),
  member: () => jwt.sign({ userId: "u-member", organizationId: "org-1", role: "MEMBER" }, ENV.JWT_SECRET),
};

interface CallOptions {
  as?: keyof typeof tokens | "none";
  body?: unknown;
  rawBody?: string;
  headers?: Record<string, string>;
  /** Fields this endpoint is allowed to return in full (create / rotate only). */
  allowedFields?: string[];
}

/**
 * Calls [path] (an instance of route pattern [route]), checks the status,
 * and fails on any secret in the response — except [allowedFields], whose
 * values are taken out of the value scan too.
 */
async function call(route: string, path: string, expectedStatus: number, options: CallOptions = {}) {
  covered.add(route);
  const [method] = route.split(" ");
  const as = options.as ?? "owner";
  const headers: Record<string, string> = { ...options.headers };
  if (as !== "none") headers.Authorization = `Bearer ${tokens[as]()}`;
  let payload: string | undefined = options.rawBody;
  if (payload === undefined && options.body !== undefined) payload = JSON.stringify(options.body);
  if (payload !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`${base}${path}`, { method, headers, body: payload });
  const text = await res.text();
  assert.equal(res.status, expectedStatus, `${route}: status ${res.status}, body ${text.slice(0, 200)}`);

  const allowedValues = new Set<string>();
  let body: Row = {};
  try {
    body = JSON.parse(text) as Row;
  } catch {
    // not JSON
  }
  for (const field of options.allowedFields ?? []) {
    assert.equal(typeof body[field], "string", `${route} should return ${field}`);
    allowedValues.add(body[field] as string);
  }
  const known = knownSecrets().filter((s) => !allowedValues.has(s.value));
  const leaks = findSecretLeaks(text, known, { allowedFields: options.allowedFields });
  assert.deepEqual(leaks, [], `${route} leaks: ${leaks.join("; ")}`);
  return { status: res.status, body, text, headers: res.headers };
}

const hmacHeaders = (apiKey: string, secret: string | null, rawBody: string) => {
  const timestamp = Date.now().toString();
  return {
    "X-Api-Key": apiKey,
    "X-Timestamp": timestamp,
    "X-Signature": secret ? computeSignature(secret, timestamp, Buffer.from(rawBody, "utf8")) : "0".repeat(64),
  };
};

const prefix = (value: string) => `${value.slice(0, 4)}…`;

before(async () => {
  for (const [key, value] of Object.entries(ENV)) {
    savedEnv[key] = process.env[key];
    process.env[key] = value;
  }
  // No Redis: the client's commands answer from memory.
  const counters = new Map<string, number>();
  const pipeline = { lpush: () => pipeline, ltrim: () => pipeline, expire: () => pipeline, hincrby: () => pipeline, exec: async () => [] };
  const fakeRedis: Record<string, unknown> = {
    connect: async () => undefined,
    ping: async () => "PONG",
    incr: async (key: string) => {
      counters.set(key, (counters.get(key) ?? 0) + 1);
      return counters.get(key);
    },
    expire: async () => 1,
    set: async () => "OK",
    get: async () => null,
    lrange: async () => [],
    hgetall: async () => ({}),
    pipeline: () => pipeline,
  };
  const client = redis as unknown as Record<string, unknown>;
  for (const [method, impl] of Object.entries(fakeRedis)) {
    savedRedis[method] = client[method];
    client[method] = impl;
  }

  receiver = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => res.end("ok"));
  });
  receiver.listen(0, "127.0.0.1");
  await new Promise<void>((r) => receiver.once("listening", () => r()));
  const webhookUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/hook`;

  db.insert("organization", { id: "org-1", name: "Bank Org" });
  db.insert("organization", { id: "org-2", name: "Other Org" });
  db.insert("user", { id: "u-owner", email: "owner@example.test", passwordHash: bcrypt.hashSync(OWNER_PASSWORD, 4), role: "OWNER", organizationId: "org-1" });
  db.insert("user", { id: "u-member", email: "member@example.test", passwordHash: bcrypt.hashSync(MEMBER_PASSWORD, 4), role: "MEMBER", organizationId: "org-1" });
  db.insert("application", { id: "app-1", name: "Bank App", platform: "FLUTTER", organizationId: "org-1", accountHashSalt: SALT1, legacyIngestionEnabled: true });
  db.insert("application", { id: "app-legacy", name: "Legacy App", platform: "ANDROID_NATIVE", organizationId: "org-1" });
  db.insert("application", { id: "app-legacy-2", name: "Legacy App 2", platform: "ANDROID_NATIVE", organizationId: "org-1" });
  db.insert("application", { id: "app-other", name: "Other Bank", platform: "FLUTTER", organizationId: "org-2", accountHashSalt: SALT_OTHER });
  db.insert("apiCredential", { id: "cred-1", applicationId: "app-1", apiKey: "rasp_live_cred1", apiSecretEncrypted: encryptSecret(SECRET1) });
  db.insert("apiCredential", {
    id: "cred-2", applicationId: "app-1", apiKey: "rasp_live_cred2", apiSecretEncrypted: encryptSecret(SECRET2), status: "REVOKED", revokedAt: new Date(),
  });
  db.insert("apiCredential", { id: "cred-other", applicationId: "app-other", apiKey: "rasp_live_other", apiSecretEncrypted: encryptSecret(SECRET_OTHER) });
  db.insert("credentialAuditLog", { credentialId: "cred-1", action: "ISSUED", performedByUserId: "u-owner" });
  db.insert("credentialAuditLog", { credentialId: "cred-2", action: "REVOKED", performedByUserId: "u-owner" });
  db.insert("applicationSettingsAuditLog", { applicationId: "app-1", action: "ACCOUNT_HASH_SALT_GENERATED", field: "accountHashSalt", performedByUserId: "u-owner" });
  // A row in which an older writer stored the salt itself: it must never be returned.
  db.insert("applicationSettingsAuditLog", { applicationId: "app-1", action: "SETTINGS_UPDATED", field: "accountHashSalt", newValue: SALT1, performedByUserId: "u-owner" });
  db.insert("webhookConfig", { id: "wh-1", applicationId: "app-1", url: webhookUrl, secretEncrypted: encryptSecret(WEBHOOK_SECRET) });
  db.insert("securityEvent", {
    id: "evt-1", applicationId: "app-1", detectorId: "root_jailbreak", status: "DETECTED", reason: null, deviceId: "dev-1",
    deviceModel: "Pixel 8", manufacturer: "Google", osPlatform: "android", osVersion: "14", appVersion: "1.0.0", sdkVersion: "1.1.0",
    ipAddress: null, evidence: [{ key: "su_binary", value: true }], clientObservedAt: new Date(),
  });
  db.insert("deviceRegistration", { id: "reg-1", applicationId: "app-1", appId: "com.example.bank", deviceId: "dev-1", deviceKeyId: "KEYID-1", publicKey: "PUBLIC-KEY", registrationCountry: null });
  db.insert("sessionEvent", {
    id: "se-1", applicationId: "app-1", deviceKeyId: "KEYID-1", accountHash: "a".repeat(64), sessionHash: "b".repeat(64), sessionEvent: "login",
    riskScore: 40, riskVerdict: "MEDIUM", ipCountry: "IN", latitude: null, eventTime: new Date(), riskEvents: [],
  });
  db.insert("accountDeviceBinding", { applicationId: "app-1", accountHash: "a".repeat(64), deviceKeyId: "KEYID-1" });

  restorePrisma = installFakePrisma(db);
  server = createApp().listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  console.error = savedConsoleError;
  restorePrisma();
  const client = redis as unknown as Record<string, unknown>;
  for (const [method, original] of Object.entries(savedRedis)) client[method] = original;
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  for (const s of [server, receiver]) {
    s.closeAllConnections();
    await new Promise<void>((r) => s.close(() => r()));
  }
});

// ── helpers ───────────────────────────────────────────────────────────────

test("maskSecret keeps 4 characters; short or missing values keep none", () => {
  assert.equal(maskSecret("0123456789abcdef0123"), "0123…");
  assert.equal(maskSecret("short"), "…");
  assert.equal(maskSecret(""), null);
  assert.equal(maskSecret(null), null);
});

test("redactSecrets hides the value after every secret field name, in Prisma, JSON, inspect and key=value text", () => {
  const salt = "f".repeat(64);
  const samples = [
    `Invalid \`prisma.application.updateMany()\` invocation:\n{\n  data: {\n    accountHashSalt: "${salt}",\n  }\n}`,
    JSON.stringify({ api_secret: "s3cr3t-value-123456", account_hash_salt: salt, apiKey: "rasp_live_x" }),
    `{ apiSecretEncrypted: 'aa:bb:cc', passwordHash: '$2a$12$abcdefghijklmnopqrstuv' }`,
    `secretEncrypted=aa:bb:cc password=hunter2-hunter2`,
  ];
  for (const sample of samples) {
    const out = redactSecrets(sample);
    for (const value of [salt, "s3cr3t-value-123456", "aa:bb:cc", "$2a$12$abcdefghijklmnopqrstuv", "hunter2-hunter2"]) {
      assert.ok(!out.includes(value), `${out} still contains a secret`);
    }
    assert.ok(out.includes("[REDACTED]"));
  }
  assert.ok(redactSecrets('{"apiKey":"rasp_live_x"}').includes("rasp_live_x"), "the API key is an identifier, not redacted");
  assert.equal(redactSecrets("accountHashSalt: null"), "accountHashSalt: null");
  assert.ok(isSecretFieldName("accountHashSalt") && isSecretFieldName("API_SECRET") && !isSecretFieldName("apiKey"));
});

test("findSecretLeaks: names and values are caught; masked prefixes and zod field errors are not", () => {
  const known = [{ label: "test salt", value: SALT1 }];
  assert.deepEqual(findSecretLeaks(JSON.stringify({ application: { accountHashSalt: SALT1 } }), known), [
    "contains the test salt", "$.application.accountHashSalt is a secret field",
  ]);
  assert.deepEqual(findSecretLeaks(JSON.stringify({ note: `salt=${SALT1}` }), known), ["contains the test salt"]);
  assert.deepEqual(findSecretLeaks(JSON.stringify({ apiSecretEncrypted: "aa:bb" }), []), ["$.apiSecretEncrypted is a secret field"]);
  assert.deepEqual(findSecretLeaks(JSON.stringify({ accountHashSaltMasked: SALT1 }), []), ["$.accountHashSaltMasked is not a masked prefix"]);
  assert.deepEqual(findSecretLeaks(JSON.stringify({ accountHashSaltMasked: prefix(SALT1), secret: null }), known), []);
  assert.deepEqual(findSecretLeaks(JSON.stringify({ details: { fieldErrors: { password: ["too short"] } } }), []), []);
});

// ── auth ──────────────────────────────────────────────────────────────────

test("auth: register and login return a token and the user, never a password or hash", async () => {
  const created = await call("POST /v1/auth/register", "/v1/auth/register", 201, {
    as: "none", body: { email: "new@example.test", password: NEW_USER_PASSWORD, organizationName: "New Org" },
  });
  assert.equal(created.body.user && (created.body.user as Row).email, "new@example.test");
  await call("POST /v1/auth/register", "/v1/auth/register", 409, {
    as: "none", body: { email: "new@example.test", password: NEW_USER_PASSWORD, organizationName: "New Org" },
  });
  await call("POST /v1/auth/register", "/v1/auth/register", 400, { as: "none", body: { email: "x@example.test", password: "short", organizationName: "X" } });
  const login = await call("POST /v1/auth/login", "/v1/auth/login", 200, { as: "none", body: { email: "owner@example.test", password: OWNER_PASSWORD } });
  assert.equal(typeof login.body.token, "string");
  await call("POST /v1/auth/login", "/v1/auth/login", 401, { as: "none", body: { email: "owner@example.test", password: MEMBER_PASSWORD } });

  // Forgot password: the same answer for any email; a bad link is refused without detail.
  await call("POST /v1/auth/forgot-password", "/v1/auth/forgot-password", 202, { as: "none", body: { email: "nobody@example.test" } });
  await call("POST /v1/auth/reset-password", "/v1/auth/reset-password", 400, { as: "none", body: { token: "x".repeat(43), password: "long enough password" } });

  // The new user's own session: profile, then sign-out (raises only that user's tokenVersion).
  const newUser = { Authorization: `Bearer ${created.body.token as string}` };
  const me = await call("GET /v1/auth/me", "/v1/auth/me", 200, { as: "none", headers: newUser });
  assert.equal((me.body.user as Row).email, "new@example.test");
  await call("POST /v1/auth/logout", "/v1/auth/logout", 204, { as: "none", headers: newUser });
  await call("GET /v1/auth/me", "/v1/auth/me", 401, { as: "none", headers: newUser });
});

// ── applications ──────────────────────────────────────────────────────────

test("apps: create and list show no salt; the new app carries only the masked salt", async () => {
  const created = await call("POST /v1/apps", "/v1/apps", 201, { body: { name: "New App", platform: "FLUTTER" } });
  const app = created.body.application as Row;
  newAppId = app.id as string;
  const stored = db.rows("application").find((a) => a.id === newAppId)!;
  assert.match(stored.accountHashSalt as string, /^[0-9a-f]{64}$/, "the salt is created with the app");
  assert.equal(app.accountHashSaltMasked, prefix(stored.accountHashSalt as string));
  await call("POST /v1/apps", "/v1/apps", 400, { body: { name: "" } });
  const list = await call("GET /v1/apps", "/v1/apps", 200);
  assert.ok((list.body.applications as Row[]).some((a) => a.id === "app-1"));
});

test("apps: GET /v1/apps/:id shows the API secret and the salt as masked prefixes only", async () => {
  const res = await call("GET /v1/apps/:id", "/v1/apps/app-1", 200);
  const app = res.body.application as Row;
  assert.equal(app.accountHashSaltMasked, prefix(SALT1));
  const credentials = app.credentials as Row[];
  assert.deepEqual(credentials.map((c) => [c.id, c.apiSecretMasked]), [["cred-1", prefix(SECRET1)], ["cred-2", prefix(SECRET2)]]);
  await call("GET /v1/apps/:id", "/v1/apps/app-other", 404);
});

test("apps: security settings, settings audit (no stored salt value), PATCH errors, archive", async () => {
  await call("GET /v1/apps/:id/security-settings", "/v1/apps/app-1/security-settings", 200);
  const audit = await call("GET /v1/apps/:id/settings-audit", "/v1/apps/app-1/settings-audit", 200);
  const saltRows = (audit.body.logs as Row[]).filter((l) => l.field === "accountHashSalt");
  assert.equal(saltRows.length, 2);
  assert.ok(saltRows.every((l) => l.oldValue === null && l.newValue === null));
  await call("PATCH /v1/apps/:id", "/v1/apps/app-1", 200, { body: { riskRules: { transactionVelocity: { maxCount: 3 } } } });
  await call("PATCH /v1/apps/:id", "/v1/apps/app-1", 400, { body: { accountHashSalt: SALT1 } });
  await call("PATCH /v1/apps/:id", "/v1/apps/app-1", 403, { as: "member", body: { ipAllowedCountries: ["IN"] } });
  await call("DELETE /v1/apps/:id", `/v1/apps/${newAppId}`, 204);
});

// ── credentials ───────────────────────────────────────────────────────────

test("credentials: the list and the audit logs carry masked prefixes only", async () => {
  const list = await call("GET /v1/credentials", "/v1/credentials", 200);
  const byId = new Map((list.body.credentials as Row[]).map((c) => [c.id, c]));
  assert.equal(byId.get("cred-1")!.apiSecretMasked, prefix(SECRET1));
  assert.equal((byId.get("cred-1")!.application as Row).accountHashSaltMasked, prefix(SALT1));
  assert.ok(!byId.has("cred-other"), "another organization's credential is not listed");
  await call("GET /v1/credentials/audit-log", "/v1/credentials/audit-log", 200);
  await call(
    "GET /v1/credentials/applications/:applicationId/credentials/audit-log",
    "/v1/credentials/applications/app-1/credentials/audit-log",
    200,
  );
});

test("credentials: issuing is the one response with api_secret and account_hash_salt", async () => {
  const issued = await call(
    "POST /v1/credentials/applications/:applicationId/credentials",
    "/v1/credentials/applications/app-1/credentials",
    201,
    { allowedFields: ["api_secret", "account_hash_salt"] },
  );
  const stored = db.rows("apiCredential").find((c) => c.apiKey === issued.body.api_key)!;
  assert.equal(decryptSecret(stored.apiSecretEncrypted as string), issued.body.api_secret);
  assert.equal(issued.body.account_hash_salt, SALT1);
  assert.equal(issued.body.config_public_key, configPublicKey(), "the public half only");

  // An application created before salts existed gets one now, audited without the value.
  const legacy = await call(
    "POST /v1/credentials/applications/:applicationId/credentials",
    "/v1/credentials/applications/app-legacy/credentials",
    201,
    { allowedFields: ["api_secret", "account_hash_salt"] },
  );
  const legacyApp = db.rows("application").find((a) => a.id === "app-legacy")!;
  assert.equal(legacy.body.account_hash_salt, legacyApp.accountHashSalt);
  const generated = db.rows("applicationSettingsAuditLog").filter((l) => l.applicationId === "app-legacy");
  assert.deepEqual(generated.map((l) => [l.action, l.newValue]), [["ACCOUNT_HASH_SALT_GENERATED", null]]);

  await call("POST /v1/credentials/applications/:applicationId/credentials", "/v1/credentials/applications/app-other/credentials", 404);
});

test("credentials: reveal shows an ACTIVE credential again (audited), never a revoked or foreign one", async () => {
  const at = (app: string, id: string) => `/v1/credentials/applications/${app}/credentials/${id}/reveal`;
  const route = "POST /v1/credentials/applications/:applicationId/credentials/:credentialId/reveal";
  const shown = await call(route, at("app-1", "cred-1"), 200, { allowedFields: ["api_secret", "account_hash_salt"] });
  assert.deepEqual(
    [shown.body.api_key, shown.body.api_secret, shown.body.account_hash_salt, shown.body.ingestion_url],
    ["rasp_live_cred1", SECRET1, SALT1, ENV.PUBLIC_INGESTION_URL],
  );
  assert.equal(shown.headers.get("cache-control"), "no-store");
  const audit = db.rows("credentialAuditLog").filter((l) => l.credentialId === "cred-1" && l.action === "REVEALED");
  assert.deepEqual(audit.map((l) => l.performedByUserId), ["u-owner"]);

  await call(route, at("app-1", "cred-2"), 400); // revoked
  await call(route, at("app-1", "cred-missing"), 404);
  await call(route, at("app-other", "cred-1"), 404); // another organization's application
  await call(route, at("app-1", "cred-1"), 403, { as: "member" });
});

test("credentials: there is no endpoint that returns the salt of an existing application", async () => {
  const res = await fetch(`${base}/v1/credentials/applications/app-1/account-hash-salt`, {
    headers: { Authorization: `Bearer ${tokens.owner()}` },
  });
  const text = await res.text();
  assert.equal(res.status, 404);
  assert.deepEqual(findSecretLeaks(text, knownSecrets()), []);
});

test("credentials: revoke, un-revoke and delete answer without secrets", async () => {
  const at = (id: string, action = "") => `/v1/credentials/applications/app-1/credentials/${id}${action}`;
  await call("POST /v1/credentials/applications/:applicationId/credentials/:credentialId/revoke", at("cred-1", "/revoke"), 200);
  await call("POST /v1/credentials/applications/:applicationId/credentials/:credentialId/unrevoke", at("cred-1", "/unrevoke"), 200);
  await call("POST /v1/credentials/applications/:applicationId/credentials/:credentialId/unrevoke", at("cred-1", "/unrevoke"), 400);
  await call("DELETE /v1/credentials/applications/:applicationId/credentials/:credentialId", at("cred-1"), 400);
  await call("DELETE /v1/credentials/applications/:applicationId/credentials/:credentialId", at("cred-2"), 204);
});

// ── webhooks ──────────────────────────────────────────────────────────────

test("webhooks: only create and rotate-secret return the signing secret", async () => {
  const route = "/v1/webhooks/applications/app-1";
  await call("GET /v1/webhooks/applications/:applicationId", route, 200);
  const updated = await call("PUT /v1/webhooks/applications/:applicationId", route, 200, {
    body: { url: (db.rows("webhookConfig")[0].url as string), minSeverity: "HIGH", enabled: true },
  });
  assert.equal(updated.body.secret, null, "an update keeps the secret and does not return it");
  const rotated = await call("POST /v1/webhooks/applications/:applicationId/rotate-secret", `${route}/rotate-secret`, 200, { allowedFields: ["secret"] });
  assert.equal(decryptSecret(db.rows("webhookConfig")[0].secretEncrypted as string), rotated.body.secret);
  await call("POST /v1/webhooks/applications/:applicationId/test", `${route}/test`, 200);
  await call("DELETE /v1/webhooks/applications/:applicationId", route, 204);
  const created = await call("PUT /v1/webhooks/applications/:applicationId", route, 201, {
    body: { url: "https://hooks.example.test/rasp", minSeverity: "HIGH", enabled: true }, allowedFields: ["secret"],
  });
  assert.equal(decryptSecret(db.rows("webhookConfig")[0].secretEncrypted as string), created.body.secret);
});

// ── dashboard ─────────────────────────────────────────────────────────────

test("dashboard: every view, the search and the CSV export carry no secret", async () => {
  const app = "/v1/dashboard/applications/app-1";
  await call("GET /v1/dashboard/map-points", "/v1/dashboard/map-points", 200);
  await call("GET /v1/dashboard/applications/:applicationId/risk-events", `${app}/risk-events`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/device-risk", `${app}/device-risk?deviceId=dev-1`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/detector-counts", `${app}/detector-counts`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/volume", `${app}/volume`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/events", `${app}/events`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/recent", `${app}/recent`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/devices", `${app}/devices`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/risk-summary", `${app}/risk-summary`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/geography", `${app}/geography`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/events/export", `${app}/events/export`, 200);
  await call("GET /v1/dashboard/applications/:applicationId/events/:eventId", `${app}/events/evt-1`, 200);
  const search = await call("GET /v1/dashboard/search", "/v1/dashboard/search?q=bank", 200);
  assert.deepEqual((search.body.applications as Row[]).map((a) => a.id), ["app-1"]);
});

// ── privacy ───────────────────────────────────────────────────────────────

test("privacy: erasing an unknown device answers 404 and carries no secret", async () => {
  await call("DELETE /v1/privacy/applications/:applicationId/devices/:deviceId", "/v1/privacy/applications/app-1/devices/no-such-device", 404);
  await call("DELETE /v1/privacy/applications/:applicationId/devices/:deviceId", "/v1/privacy/applications/app-1/devices/no-such-device", 403, { as: "member" });
});

// ── SDK-facing endpoints: error responses ────────────────────────────────

test("remote config: dashboard and device responses carry no private key", async () => {
  const admin = "/v1/apps/app-1/remote-config";
  await call("GET /v1/config", "/v1/config", 401, { as: "none" });
  await call("GET /v1/config", "/v1/config", 404, { as: "none", headers: { "X-Api-Key": "rasp_live_cred1" } });
  await call("PUT /v1/apps/:id/remote-config", admin, 400, { body: { settings: { ingestionUrl: "https://evil.example" } } });
  await call("PUT /v1/apps/:id/remote-config", admin, 403, { as: "member", body: { settings: {} } });
  await call("PUT /v1/apps/:id/remote-config", admin, 201, { body: { settings: { detectors: { root_jailbreak: true }, pollIntervalSeconds: 5 } } });
  await call("POST /v1/apps/:id/remote-config/rollback", `${admin}/rollback`, 201, { body: { version: 1 } });
  const view = await call("GET /v1/apps/:id/remote-config", admin, 200);
  assert.equal(view.body.keyId, configKeyId());
  await call("GET /v1/apps/:id/remote-config", "/v1/apps/app-other/remote-config", 404);
  const signed = await call("GET /v1/config", "/v1/config", 200, { as: "none", headers: { "X-Api-Key": "rasp_live_cred1", "X-Device-Key-Id": "KEYID-1" } });
  const publicKey = crypto.createPublicKey({ key: Buffer.from(configPublicKey()!, "base64"), format: "der", type: "spki" });
  assert.ok(crypto.verify(null, Buffer.from(signed.body.payload as string, "utf8"), publicKey, Buffer.from(signed.body.signature as string, "base64")));
  await call("GET /v1/config", "/v1/config", 304, { as: "none", headers: { "X-Api-Key": "rasp_live_cred1", "If-None-Match": '"2"' } });
});

test("SDK endpoints: signature and validation errors carry no secret", async () => {
  const batch = JSON.stringify({ events: "not-a-list" });
  await call("POST /v1/events", "/v1/events", 401, { as: "none", rawBody: batch, headers: hmacHeaders("rasp_live_cred1", null, batch) });
  await call("POST /v1/events", "/v1/events", 400, { as: "none", rawBody: batch, headers: hmacHeaders("rasp_live_cred1", SECRET1, batch) });
  const registration = JSON.stringify({ appId: "com.example.bank" });
  await call("POST /v1/devices/register", "/v1/devices/register", 401, {
    as: "none", rawBody: registration, headers: hmacHeaders("rasp_live_cred1", null, registration),
  });
  await call("POST /v1/devices/challenge", "/v1/devices/challenge", 401, { as: "none", rawBody: "{}", headers: hmacHeaders("rasp_live_cred1", null, "{}") });
  const challenge = await call("POST /v1/devices/challenge", "/v1/devices/challenge", 200, { as: "none", rawBody: "{}", headers: hmacHeaders("rasp_live_cred1", SECRET1, "{}") });
  assert.equal(typeof challenge.body.challenge, "string");
  await call("GET /v1/ip-risk", "/v1/ip-risk", 401, { as: "none", headers: hmacHeaders("rasp_live_cred1", null, "") });
  await call("GET /v1/reputation/list", "/v1/reputation/list", 401, { as: "none" });
  await call("GET /v1/reputation/list", "/v1/reputation/list", 404, { as: "none", headers: { "X-Api-Key": "rasp_live_cred1" } });
  await call("POST /v1/risk/events", "/v1/risk/events", 400, { as: "none", body: { riskEnvelopeVersion: 1 }, headers: { "X-Api-Key": "rasp_live_cred1" } });
  const unknownDevice = signRiskEnvelope(makeDevice("com.example.bank"), Date.now());
  await call("POST /v1/risk/events", "/v1/risk/events", 401, { as: "none", rawBody: unknownDevice.body, headers: { "X-Api-Key": "rasp_live_cred1" } });
  await call("GET /v1/sdk/catalog", "/v1/sdk/catalog", 200, { as: "none" });
  await call("GET /v1/sdk/download/:platform", "/v1/sdk/download/not-a-platform", 404, { as: "none" });
  await call("GET /healthz", "/healthz", 200, { as: "none" });
});

// ── unhandled errors ──────────────────────────────────────────────────────

test("an unhandled error answers a bare 500 and its log has every secret value redacted", async () => {
  // Prisma validation errors print the arguments they were given.
  const prismaLikeError = (method: string) => (args: Row) =>
    new Error(`Invalid \`prisma.${method}()\` invocation:\n${JSON.stringify(args, null, 2)}`);
  console.error = (...parts: unknown[]) => { logged.push(parts.map(String).join(" ")); };
  try {
    db.failures["apiCredential.create"] = (args) => {
      remember("API secret passed to a failing create", (args.data as Row).apiSecretEncrypted);
      return prismaLikeError("apiCredential.create")(args);
    };
    const failedCreate = await call(
      "POST /v1/credentials/applications/:applicationId/credentials",
      "/v1/credentials/applications/app-1/credentials",
      500,
    );
    assert.deepEqual(failedCreate.body, { error: "INTERNAL_SERVER_ERROR" });
    delete db.failures["apiCredential.create"];

    // A salt being generated for an older application, then the write fails.
    db.failures["application.updateMany"] = (args) => {
      remember("salt passed to a failing update", (args.data as Row).accountHashSalt);
      return prismaLikeError("application.updateMany")(args);
    };
    await call(
      "POST /v1/credentials/applications/:applicationId/credentials",
      "/v1/credentials/applications/app-legacy-2/credentials",
      500,
    );
    delete db.failures["application.updateMany"];
  } finally {
    console.error = savedConsoleError;
  }
  const log = logged.join("\n");
  assert.ok(log.includes("[unhandled]") && log.includes("[REDACTED]"), "the error was logged, redacted");
  assert.deepEqual(findSecretLeaks(log, knownSecrets()), [], "no secret value in the log");
});

// ── coverage ──────────────────────────────────────────────────────────────

test("every route of every router was scanned above", () => {
  const mounted: [string, Router][] = [
    ["/v1/auth", authRouter], ["/v1/apps", appsRouter], ["/v1/credentials", credentialsRouter],
    ["/v1/sdk", sdkDistributionRouter], ["/v1/events", ingestionRouter], ["/v1/devices", devicesRouter],
    ["/v1/dashboard", dashboardRouter], ["/v1/webhooks", webhooksRouter], ["/v1/ip-risk", ipRiskRouter],
    ["/v1/risk", riskRouter], ["/v1/reputation", reputationRouter], ["/v1/privacy", privacyRouter],
    ["/v1/config", deviceConfigRouter], ["/v1/apps/:id/remote-config", remoteConfigAdminRouter],
  ];
  const routes = new Set<string>(["GET /healthz"]);
  for (const [prefixPath, router] of mounted) {
    for (const layer of (router as unknown as { stack: { route?: { path: string; methods: Record<string, boolean> } }[] }).stack) {
      if (!layer.route) continue;
      for (const method of Object.keys(layer.route.methods)) {
        const path = `${prefixPath}${layer.route.path === "/" ? "" : layer.route.path}`;
        routes.add(`${method.toUpperCase()} ${path}`);
      }
    }
  }
  const missing = [...routes].filter((r) => !covered.has(r)).sort();
  assert.deepEqual(missing, [], `routes without a secret scan: ${missing.join(", ")}`);
  const unknown = [...covered].filter((r) => !routes.has(r)).sort();
  assert.deepEqual(unknown, [], `scanned routes that do not exist: ${unknown.join(", ")}`);
});
