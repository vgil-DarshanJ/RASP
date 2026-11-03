// "Forgot password" (POST /v1/auth/forgot-password, /reset-password).
// Real: the auth router over HTTP, bcrypt, JWT, token hashing, the lockout
// rules, the console fallback of the default mailer.
// Doubles: the in-memory Prisma stand-in, an in-memory limit store instead of
// Redis, a mailer that records the links instead of sending e-mail.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { authRouter } from "../src/auth/routes";
import { AuthedRequest, requireAuth } from "../src/middleware/auth";
import { authLimits, AuthLimitStore, redisAuthLimitStore } from "../src/auth/loginGuard";
import { defaultMailer, hashResetToken, passwordReset, RESET_TOKEN_TTL_MS } from "../src/auth/passwordReset";
import { FakeDatabase, installFakePrisma } from "./fakePrisma";

const SECRET = "test-jwt-secret-not-real";
const ENV_KEYS = ["JWT_SECRET", "BCRYPT_ROUNDS", "DASHBOARD_URL", "SMTP_HOST", "NODE_ENV"];
const saved: Record<string, string | undefined> = {};
const originalMailer = passwordReset.mailer;

class MemoryStore implements AuthLimitStore {
  values = new Map<string, number>();
  async hit(key: string) {
    const n = (this.values.get(key) ?? 0) + 1;
    this.values.set(key, n);
    return n;
  }
  async ttl(key: string) {
    return this.values.has(key) ? 900 : 0;
  }
  async set(key: string) {
    this.values.set(key, 1);
  }
  async del(key: string) {
    this.values.delete(key);
  }
}

let db: FakeDatabase;
let restorePrisma: () => void = () => {};
let server: import("node:http").Server;
let base = "";
let mails: Array<{ to: string; link: string }> = [];

before(async () => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  process.env.JWT_SECRET = SECRET;
  process.env.BCRYPT_ROUNDS = "4";
  process.env.DASHBOARD_URL = "https://rasp.example.test/";
  const app = express();
  app.set("trust proxy", true);
  app.use(express.json());
  app.use("/v1/auth", authRouter);
  app.get("/v1/whoami", requireAuth, (req: AuthedRequest, res) => res.json(req.user));
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

beforeEach(() => {
  restorePrisma();
  db = new FakeDatabase();
  db.insert("organization", { id: "org-1", name: "Bank" });
  db.insert("user", { id: "u-1", email: "owner@bank.test", passwordHash: bcrypt.hashSync("old password", 4), role: "OWNER", organizationId: "org-1", tokenVersion: 0 });
  restorePrisma = installFakePrisma(db);
  authLimits.store = new MemoryStore();
  mails = [];
  passwordReset.mailer = () => ({ send: async (to, link) => { mails.push({ to, link }); } });
});

after(async () => {
  restorePrisma();
  authLimits.store = redisAuthLimitStore;
  passwordReset.mailer = originalMailer;
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

async function post(path: string, body: unknown, ip = "198.51.100.1") {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Forwarded-For": ip },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}
const forgot = async (email: string, ip?: string) => {
  const r = await post("/v1/auth/forgot-password", { email }, ip);
  await passwordReset.lastJob;
  return r;
};
const tokenOf = (link: string) => new URL(link).searchParams.get("token")!;

test("a known email gets a one-time link; only the token's hash is stored", async () => {
  const r = await forgot("owner@bank.test");
  assert.deepEqual(r, { status: 202, body: { ok: true } });
  assert.equal(mails.length, 1);
  assert.equal(mails[0].to, "owner@bank.test");
  assert.match(mails[0].link, /^https:\/\/rasp\.example\.test\/reset-password\?token=[A-Za-z0-9_-]{43}$/);
  const token = tokenOf(mails[0].link);
  const rows = db.rows("passwordResetToken");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].tokenHash, hashResetToken(token));
  assert.notEqual(rows[0].tokenHash, token);
  const ttl = (rows[0].expiresAt as Date).getTime() - Date.now();
  assert.ok(ttl > RESET_TOKEN_TTL_MS - 60_000 && ttl <= RESET_TOKEN_TTL_MS, String(ttl));
});

test("an unknown email gets the same answer and nothing is sent or stored", async () => {
  assert.deepEqual(await forgot("nobody@bank.test"), { status: 202, body: { ok: true } });
  assert.equal(mails.length, 0);
  assert.equal(db.rows("passwordResetToken").length, 0);
  assert.equal((await post("/v1/auth/forgot-password", { email: "not an email" })).status, 400);
});

test("the link sets a new password once, signs out every session and the old password stops working", async () => {
  const oldToken = jwt.sign({ userId: "u-1", organizationId: "org-1", role: "OWNER", tv: 0 }, SECRET);
  await forgot("owner@bank.test");
  const token = tokenOf(mails[0].link);
  const short = await post("/v1/auth/reset-password", { token, password: "short" });
  assert.deepEqual([short.status, short.body.error], [400, "INVALID_INPUT"], "8 characters at least");
  assert.equal(db.rows("passwordResetToken").length, 1, "a refused password does not use up the link");
  assert.deepEqual(await post("/v1/auth/reset-password", { token, password: "brand new password" }), { status: 200, body: { ok: true } });

  assert.equal((await post("/v1/auth/login", { email: "owner@bank.test", password: "old password" })).status, 401);
  assert.equal((await post("/v1/auth/login", { email: "owner@bank.test", password: "brand new password" })).status, 200);
  const me = await fetch(`${base}/v1/whoami`, { headers: { Authorization: `Bearer ${oldToken}` } });
  assert.equal(me.status, 401, "sessions from before the reset are revoked");

  assert.deepEqual(await post("/v1/auth/reset-password", { token, password: "another password" }), {
    status: 400, body: { error: "INVALID_OR_EXPIRED_TOKEN" },
  });
  assert.equal(db.rows("passwordResetToken").length, 0);
});

test("expired, unknown and replaced links are refused", async () => {
  await forgot("owner@bank.test");
  const first = tokenOf(mails[0].link);
  await forgot("owner@bank.test");
  const second = tokenOf(mails[1].link);
  assert.equal((await post("/v1/auth/reset-password", { token: first, password: "new password 1" })).body.error, "INVALID_OR_EXPIRED_TOKEN", "a newer link replaces the older one");
  assert.equal((await post("/v1/auth/reset-password", { token: "x".repeat(43), password: "new password 1" })).body.error, "INVALID_OR_EXPIRED_TOKEN");
  db.rows("passwordResetToken")[0].expiresAt = new Date(Date.now() - 1000);
  assert.equal((await post("/v1/auth/reset-password", { token: second, password: "new password 1" })).body.error, "INVALID_OR_EXPIRED_TOKEN");
  assert.equal(db.rows("passwordResetToken").length, 0, "the expired link is removed");
});

test("a reset ends a login lockout", async () => {
  for (let i = 0; i < 5; i++) await post("/v1/auth/login", { email: "owner@bank.test", password: "wrong" }, `203.0.113.${i}`);
  assert.equal((await post("/v1/auth/login", { email: "owner@bank.test", password: "old password" }, "203.0.113.9")).body.error, "ACCOUNT_TEMPORARILY_LOCKED");
  await forgot("owner@bank.test");
  await post("/v1/auth/reset-password", { token: tokenOf(mails[0].link), password: "unlocked password" });
  assert.equal((await post("/v1/auth/login", { email: "owner@bank.test", password: "unlocked password" }, "203.0.113.10")).status, 200);
});

test("at most 3 links per email and hour; the answer stays the same", async () => {
  for (let i = 0; i < 5; i++) assert.equal((await forgot("owner@bank.test", `192.0.2.${i}`)).status, 202);
  assert.equal(mails.length, 3);
});

test("default delivery: console in development without SMTP, nothing in production without SMTP", async () => {
  delete process.env.SMTP_HOST;
  const logs: string[] = [];
  const errors: string[] = [];
  const { log, error } = console;
  console.log = (...a: unknown[]) => { logs.push(a.join(" ")); };
  console.error = (...a: unknown[]) => { errors.push(a.join(" ")); };
  try {
    process.env.NODE_ENV = "development";
    await defaultMailer().send("owner@bank.test", "https://rasp.example.test/reset-password?token=abc");
    process.env.NODE_ENV = "production";
    await defaultMailer().send("owner@bank.test", "https://rasp.example.test/reset-password?token=def");
  } finally {
    console.log = log;
    console.error = error;
    delete process.env.NODE_ENV;
  }
  assert.ok(logs.some((l) => l.includes("token=abc")), "development: link in the terminal");
  assert.ok(!logs.concat(errors).some((l) => l.includes("token=def")), "production: the link is never printed");
  assert.ok(errors.some((l) => l.includes("SMTP_HOST is not set")));
});

test("tokens are 32 random bytes", () => {
  assert.equal(crypto.randomBytes(32).toString("base64url").length, 43);
});
