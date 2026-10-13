// Role checks on actions that cut an app off or reveal secrets (F-10).
// Real: requireAuth, requireAdminRole and the apps, credentials and webhooks
// routers over real HTTP. Doubles: the in-memory Prisma stand-in.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import { appsRouter } from "../src/apps/routes";
import { credentialsRouter } from "../src/credentials/routes";
import { webhooksRouter } from "../src/webhooks/routes";
import { remoteConfigAdminRouter } from "../src/remoteConfig/routes";
import { encryptSecret } from "../src/crypto/secretBox";
import { isAdminRole } from "../src/auth/roles";
import { FakeDatabase, installFakePrisma } from "./fakePrisma";

const SECRET = "test-jwt-secret-not-real";
const ENV_KEYS = ["JWT_SECRET", "CREDENTIAL_ENCRYPTION_KEY", "WEBHOOK_ALLOW_PRIVATE_DESTINATIONS"];
const saved: Record<string, string | undefined> = {};
const db = new FakeDatabase();
let restorePrisma: () => void = () => {};
let server: import("node:http").Server;
let base = "";

before(async () => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  process.env.JWT_SECRET = SECRET;
  process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString("hex"); // throwaway test key
  process.env.WEBHOOK_ALLOW_PRIVATE_DESTINATIONS = "1"; // no DNS lookups for the test URL
  db.insert("organization", { id: "org-1", name: "Bank Org" });
  for (const role of ["OWNER", "ADMIN", "MEMBER"]) {
    db.insert("user", { id: `u-${role.toLowerCase()}`, email: `${role.toLowerCase()}@bank.test`, passwordHash: "x", role, organizationId: "org-1" });
  }
  db.insert("application", { id: "app-1", name: "Bank App", platform: "FLUTTER", organizationId: "org-1", accountHashSalt: "a".repeat(64) });
  db.insert("apiCredential", { id: "cred-1", applicationId: "app-1", apiKey: "rasp_live_x", apiSecretEncrypted: encryptSecret("s") });
  db.insert("webhookConfig", { id: "wh-1", applicationId: "app-1", url: "https://hooks.bank.example/rasp", secretEncrypted: encryptSecret("w") });
  restorePrisma = installFakePrisma(db);
  const app = express();
  app.use(express.json());
  app.use("/v1/apps/:id/remote-config", remoteConfigAdminRouter);
  app.use("/v1/apps", appsRouter);
  app.use("/v1/credentials", credentialsRouter);
  app.use("/v1/webhooks", webhooksRouter);
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  restorePrisma();
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

const token = (role: string) => jwt.sign({ userId: `u-${role.toLowerCase()}`, organizationId: "org-1", role }, SECRET);
async function call(role: string, method: string, path: string, body?: unknown) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token(role)}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const DESTRUCTIVE: Array<[string, string, unknown?]> = [
  ["POST", "/v1/credentials/applications/app-1/credentials"],
  ["POST", "/v1/credentials/applications/app-1/credentials/cred-1/revoke"],
  ["POST", "/v1/credentials/applications/app-1/credentials/cred-1/unrevoke"],
  ["POST", "/v1/credentials/applications/app-1/credentials/cred-1/reveal"],
  ["DELETE", "/v1/credentials/applications/app-1/credentials/cred-1"],
  ["PUT", "/v1/webhooks/applications/app-1", { url: "https://hooks.bank.example/other", minSeverity: "HIGH", enabled: true }],
  ["POST", "/v1/webhooks/applications/app-1/rotate-secret"],
  ["POST", "/v1/webhooks/applications/app-1/test"],
  ["DELETE", "/v1/webhooks/applications/app-1"],
  ["GET", "/v1/apps/app-1/remote-config"],
  ["PUT", "/v1/apps/app-1/remote-config", { settings: {} }],
  ["POST", "/v1/apps/app-1/remote-config/rollback", { version: 1 }],
  ["DELETE", "/v1/apps/app-1"],
];

test("only OWNER and ADMIN count as administrators", () => {
  assert.deepEqual(["OWNER", "ADMIN", "MEMBER", undefined].map(isAdminRole), [true, true, false, false]);
});

test("MEMBER: 403 FORBIDDEN_ROLE on every destructive or secret-revealing action, and nothing changes", async () => {
  const snapshot = JSON.stringify([db.rows("apiCredential"), db.rows("webhookConfig"), db.rows("application"), db.rows("remoteConfig")]);
  for (const [method, path, body] of DESTRUCTIVE) {
    const r = await call("MEMBER", method, path, body);
    assert.deepEqual([r.status, r.body], [403, { error: "FORBIDDEN_ROLE" }], `${method} ${path}`);
  }
  assert.equal(JSON.stringify([db.rows("apiCredential"), db.rows("webhookConfig"), db.rows("application"), db.rows("remoteConfig")]), snapshot);
});

test("MEMBER can still read", async () => {
  assert.equal((await call("MEMBER", "GET", "/v1/apps")).status, 200);
  assert.equal((await call("MEMBER", "GET", "/v1/credentials")).status, 200);
  assert.equal((await call("MEMBER", "GET", "/v1/webhooks/applications/app-1")).status, 200);
});

test("ADMIN passes the role check (issue a credential, change the webhook)", async () => {
  const issued = await call("ADMIN", "POST", "/v1/credentials/applications/app-1/credentials");
  assert.equal(issued.status, 201, JSON.stringify(issued.body));
  const updated = await call("ADMIN", "PUT", "/v1/webhooks/applications/app-1", { url: "https://hooks.bank.example/new", minSeverity: "LOW", enabled: true });
  assert.equal(updated.status, 200, JSON.stringify(updated.body));
});
