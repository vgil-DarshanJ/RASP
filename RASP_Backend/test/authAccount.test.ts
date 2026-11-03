// requireAuth checks that a validly signed token's account still exists
// (a reset database or a token from another backend with the same JWT
// secret used to pass, and then POST /v1/apps failed with a foreign-key
// error → 500 "Could not create the application"). Now: 401
// ACCOUNT_NOT_FOUND, which the dashboard answers by signing out.
// Real: requireAuth, JWT signing/verification, the apps router over real
// HTTP. Doubles: the account lookup (authAccounts.find) and, for the apps
// route, the in-memory Prisma stand-in (test/fakePrisma.ts).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import { authAccounts, AuthedRequest, requireAuth } from "../src/middleware/auth";
import { appsRouter } from "../src/apps/routes";
import { FakeDatabase, installFakePrisma } from "./fakePrisma";

const SECRET = "test-jwt-secret-not-real";
const originalSecret = process.env.JWT_SECRET;
const originalFind = authAccounts.find;
let base = "";
let server: import("node:http").Server;
let restorePrisma: () => void = () => {};
const db = new FakeDatabase();

before(async () => {
  process.env.JWT_SECRET = SECRET;
  db.insert("organization", { id: "org-1", name: "Bank Org" });
  db.insert("user", { id: "u-owner", email: "owner@example.test", passwordHash: "x", role: "ADMIN", organizationId: "org-1" });
  restorePrisma = installFakePrisma(db);
  const app = express();
  app.use(express.json());
  app.get("/whoami", requireAuth, (req: AuthedRequest, res) => res.json(req.user));
  app.use("/v1/apps", appsRouter);
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  restorePrisma();
  authAccounts.find = originalFind;
  if (originalSecret === undefined) delete process.env.JWT_SECRET;
  else process.env.JWT_SECRET = originalSecret;
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

const call = async (path: string, token: string, init: RequestInit = {}) => {
  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
};
const sign = (claims: Record<string, unknown>) => jwt.sign(claims, SECRET);

test("an existing account passes, with its role from the database", async () => {
  authAccounts.find = originalFind; // the default lookup, against the stand-in database
  const r = await call("/whoami", sign({ userId: "u-owner", organizationId: "org-1", role: "OWNER" }));
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { userId: "u-owner", organizationId: "org-1", role: "ADMIN" });
});

test("a signed token for an account this database does not have → 401 ACCOUNT_NOT_FOUND, nothing created", async () => {
  authAccounts.find = originalFind;
  const stale = sign({ userId: "cm-from-another-backend", organizationId: "org-gone", role: "OWNER" });
  assert.deepEqual(await call("/whoami", stale), { status: 401, body: { error: "ACCOUNT_NOT_FOUND" } });
  const before = db.rows("application").length;
  const created = await call("/v1/apps", stale, { method: "POST", body: JSON.stringify({ name: "test2", platform: "FLUTTER" }) });
  assert.deepEqual(created, { status: 401, body: { error: "ACCOUNT_NOT_FOUND" } });
  assert.equal(db.rows("application").length, before, "no application written");
});

test("a user moved to another organization → 401; a broken token → 401 INVALID_TOKEN", async () => {
  authAccounts.find = originalFind;
  const r = await call("/whoami", sign({ userId: "u-owner", organizationId: "org-other", role: "OWNER" }));
  assert.deepEqual(r, { status: 401, body: { error: "ACCOUNT_NOT_FOUND" } });
  assert.equal((await call("/whoami", "not-a-jwt")).status, 401);
  assert.equal((await call("/whoami", sign({ organizationId: "org-1" }))).body.error, "INVALID_TOKEN");
});

test("the account database unavailable → 503, never let through", async () => {
  authAccounts.find = async () => {
    throw new Error("connection refused");
  };
  const r = await call("/whoami", sign({ userId: "u-owner", organizationId: "org-1", role: "OWNER" }));
  assert.deepEqual(r, { status: 503, body: { error: "AUTH_BACKEND_UNAVAILABLE" } });
});
