// Dashboard sign-in hardening (F-04, F-11).
// Real: the auth router (register, login, me, logout) and requireAuth over
// real HTTP, JWT signing/verification, bcrypt, the session cookie, the
// origin check and the lockout rules in loginGuard.ts.
// Doubles: the in-memory Prisma stand-in (test/fakePrisma.ts) and an
// in-memory AuthLimitStore in place of Redis.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { authRouter } from "../src/auth/routes";
import { AuthedRequest, requireAuth } from "../src/middleware/auth";
import { authLimits, AuthLimitStore, redisAuthLimitStore } from "../src/auth/loginGuard";
import { readSessionCookie, SESSION_COOKIE } from "../src/auth/sessionCookie";
import { DEFAULT_JWT_EXPIRES_IN, secondsUntilExpiry } from "../src/auth/jwt";
import { FakeDatabase, installFakePrisma } from "./fakePrisma";

const SECRET = "test-jwt-secret-not-real";
const DASHBOARD = "http://localhost:3000";
const ENV_KEYS = ["JWT_SECRET", "JWT_EXPIRES_IN", "CORS_ORIGINS", "BCRYPT_ROUNDS", "AUTH_LOGIN_RATE_LIMIT_PER_IP", "AUTH_LOCKOUT_THRESHOLD", "NODE_ENV"];
const savedEnv: Record<string, string | undefined> = {};

class MemoryStore implements AuthLimitStore {
  values = new Map<string, { count: number; expiresAt: number }>();
  now = () => Date.now();
  private live(key: string) {
    const v = this.values.get(key);
    if (v && v.expiresAt <= this.now()) this.values.delete(key);
    return this.values.get(key);
  }
  async hit(key: string, windowSeconds: number) {
    const v = this.live(key) ?? { count: 0, expiresAt: this.now() + windowSeconds * 1000 };
    v.count += 1;
    this.values.set(key, v);
    return v.count;
  }
  async ttl(key: string) {
    const v = this.live(key);
    return v ? Math.ceil((v.expiresAt - this.now()) / 1000) : 0;
  }
  async set(key: string, ttlSeconds: number) {
    this.values.set(key, { count: 1, expiresAt: this.now() + ttlSeconds * 1000 });
  }
  async del(key: string) {
    this.values.delete(key);
  }
}

let base = "";
let server: import("node:http").Server;
let restorePrisma: () => void = () => {};
let db: FakeDatabase;
let store: MemoryStore;

before(async () => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  process.env.JWT_SECRET = SECRET;
  process.env.CORS_ORIGINS = ` ${DASHBOARD} , http://127.0.0.1:3000`;
  process.env.BCRYPT_ROUNDS = "4";
  delete process.env.JWT_EXPIRES_IN;
  delete process.env.NODE_ENV;
  const app = express();
  app.set("trust proxy", true);
  app.use(express.json());
  app.use("/v1/auth", authRouter);
  app.get("/v1/whoami", requireAuth, (req: AuthedRequest, res) => res.json(req.user));
  app.post("/v1/change", requireAuth, (_req, res) => res.json({ changed: true }));
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

beforeEach(() => {
  restorePrisma();
  db = new FakeDatabase();
  db.insert("organization", { id: "org-1", name: "Bank Org" });
  db.insert("user", { id: "u-1", email: "owner@bank.test", passwordHash: bcrypt.hashSync("correct horse", 4), role: "OWNER", organizationId: "org-1", tokenVersion: 0 });
  restorePrisma = installFakePrisma(db);
  store = new MemoryStore();
  authLimits.store = store;
  delete process.env.AUTH_LOGIN_RATE_LIMIT_PER_IP;
  delete process.env.AUTH_LOCKOUT_THRESHOLD;
});

after(async () => {
  restorePrisma();
  authLimits.store = redisAuthLimitStore;
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

async function call(path: string, init: { method?: string; body?: unknown; headers?: Record<string, string> } = {}) {
  const res = await fetch(`${base}${path}`, {
    method: init.method ?? "GET",
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
}

const login = (password: string, ip = "198.51.100.1", email = "owner@bank.test") =>
  call("/v1/auth/login", { method: "POST", body: { email, password }, headers: { "X-Forwarded-For": ip } });

function cookieFrom(headers: Headers): { value: string | null; raw: string } {
  const raw = headers.get("set-cookie") ?? "";
  return { value: readSessionCookie({ headers: { cookie: raw.split(";")[0] } }), raw };
}

test("login sets an httpOnly session cookie that authenticates, with HS256 and an 8 h default lifetime", async () => {
  const r = await login("correct horse");
  assert.equal(r.status, 200);
  const cookie = cookieFrom(r.headers);
  assert.ok(cookie.value, "session cookie set");
  for (const attr of ["HttpOnly", "Path=/v1", "SameSite=Lax"]) assert.ok(cookie.raw.includes(attr), attr);
  assert.ok(!cookie.raw.includes("Secure"), "not Secure outside production unless configured");
  assert.equal(cookie.value, r.body.token, "the same token is returned for API clients");
  assert.equal((jwt.decode(cookie.value!, { complete: true }) as jwt.Jwt).header.alg, "HS256");
  assert.equal(DEFAULT_JWT_EXPIRES_IN, "8h");
  const lifetime = secondsUntilExpiry(cookie.value!);
  assert.ok(lifetime > 8 * 3600 - 60 && lifetime <= 8 * 3600, String(lifetime));

  const me = await call("/v1/whoami", { headers: { Cookie: `${SESSION_COOKIE}=${cookie.value}` } });
  assert.deepEqual([me.status, me.body], [200, { userId: "u-1", organizationId: "org-1", role: "OWNER" }]);
  const profile = await call("/v1/auth/me", { headers: { Cookie: `${SESSION_COOKIE}=${cookie.value}` } });
  assert.deepEqual(profile.body, { user: { id: "u-1", email: "owner@bank.test", role: "OWNER" }, organization: { id: "org-1", name: "Bank Org" } });
});

test("production cookies are Secure", async () => {
  process.env.NODE_ENV = "production";
  try {
    const r = await login("correct horse", "198.51.100.9");
    assert.ok(cookieFrom(r.headers).raw.includes("Secure"));
  } finally {
    delete process.env.NODE_ENV;
  }
});

test("a cookie-authenticated change needs an allowed Origin; Bearer requests and reads do not", async () => {
  const token = (await login("correct horse")).body.token as string;
  const cookie = { Cookie: `${SESSION_COOKIE}=${token}` };
  assert.equal((await call("/v1/change", { method: "POST", body: {}, headers: { ...cookie, Origin: DASHBOARD } })).status, 200);
  assert.equal((await call("/v1/change", { method: "POST", body: {}, headers: { ...cookie, Origin: "http://127.0.0.1:3000" } })).status, 200, "trimmed CORS_ORIGINS entry");
  const forged = await call("/v1/change", { method: "POST", body: {}, headers: { ...cookie, Origin: "https://evil.example" } });
  assert.deepEqual([forged.status, forged.body], [403, { error: "ORIGIN_NOT_ALLOWED" }]);
  assert.equal((await call("/v1/change", { method: "POST", body: {}, headers: cookie })).status, 403, "no Origin");
  assert.equal((await call("/v1/whoami", { headers: { ...cookie, Origin: "https://evil.example" } })).status, 200, "GET is read-only");
  assert.equal((await call("/v1/change", { method: "POST", body: {}, headers: { Authorization: `Bearer ${token}` } })).status, 200);
});

test("logout revokes every token issued so far and clears the cookie", async () => {
  const first = (await login("correct horse")).body.token as string;
  const second = (await login("correct horse", "198.51.100.2")).body.token as string;
  const out = await call("/v1/auth/logout", { method: "POST", headers: { Cookie: `${SESSION_COOKIE}=${first}`, Origin: DASHBOARD } });
  assert.equal(out.status, 204);
  assert.ok((out.headers.get("set-cookie") ?? "").includes("Max-Age=0"));
  for (const token of [first, second]) {
    const r = await call("/v1/whoami", { headers: { Authorization: `Bearer ${token}` } });
    assert.deepEqual([r.status, r.body], [401, { error: "TOKEN_REVOKED" }]);
  }
  const again = (await login("correct horse")).body.token as string;
  assert.equal((await call("/v1/whoami", { headers: { Authorization: `Bearer ${again}` } })).status, 200, "a new sign-in works");
});

test("tokens with another algorithm, or none, are rejected; tokens from before revocation existed still work", async () => {
  const claims = { userId: "u-1", organizationId: "org-1", role: "OWNER" };
  const hs512 = jwt.sign(claims, SECRET, { algorithm: "HS512" });
  const unsigned = jwt.sign(claims, "", { algorithm: "none" } as jwt.SignOptions);
  for (const token of [hs512, unsigned]) {
    const r = await call("/v1/whoami", { headers: { Authorization: `Bearer ${token}` } });
    assert.deepEqual([r.status, r.body], [401, { error: "INVALID_TOKEN" }]);
  }
  const legacy = jwt.sign(claims, SECRET, { expiresIn: "1h" }); // no `tv` claim
  assert.equal((await call("/v1/whoami", { headers: { Authorization: `Bearer ${legacy}` } })).status, 200);
});

test("five failed logins lock the email for 15 minutes, right password included; unknown emails are counted the same way", async () => {
  for (let i = 0; i < 5; i++) assert.equal((await login("wrong", `198.51.100.${10 + i}`)).status, 401);
  const locked = await login("correct horse", "198.51.100.20");
  assert.equal(locked.status, 429);
  assert.equal(locked.body.error, "ACCOUNT_TEMPORARILY_LOCKED");
  assert.equal(locked.headers.get("retry-after"), "900");

  for (let i = 0; i < 5; i++) await login("wrong", "198.51.100.30", "nobody@bank.test");
  assert.equal((await login("wrong", "198.51.100.31", "nobody@bank.test")).body.error, "ACCOUNT_TEMPORARILY_LOCKED", "same answer for an unknown email");

  store.now = () => Date.now() + 901_000;
  assert.equal((await login("correct horse", "198.51.100.21")).status, 200, "unlocked after the lock period");
});

test("a successful login clears earlier failures", async () => {
  for (let i = 0; i < 4; i++) await login("wrong");
  assert.equal((await login("correct horse")).status, 200);
  for (let i = 0; i < 4; i++) assert.equal((await login("wrong")).status, 401);
  assert.equal((await login("correct horse")).status, 200, "4 + 4 failures with a success between never lock");
});

test("per-IP limits: login and register answer 429 RATE_LIMIT_EXCEEDED with Retry-After", async () => {
  process.env.AUTH_LOGIN_RATE_LIMIT_PER_IP = "3";
  for (let i = 0; i < 3; i++) assert.notEqual((await login("correct horse", "203.0.113.5")).status, 429);
  const blocked = await login("correct horse", "203.0.113.5");
  assert.deepEqual([blocked.status, blocked.body.error], [429, "RATE_LIMIT_EXCEEDED"]);
  assert.ok(Number(blocked.headers.get("retry-after")) > 0);
  assert.equal((await login("correct horse", "203.0.113.6")).status, 200, "another IP is not affected");

  for (let i = 0; i < 10; i++) {
    await call("/v1/auth/register", { method: "POST", body: { email: `n${i}@bank.test`, password: "longenough", organizationName: `Org ${i}` }, headers: { "X-Forwarded-For": "203.0.113.7" } });
  }
  const tooMany = await call("/v1/auth/register", { method: "POST", body: { email: "x@bank.test", password: "longenough", organizationName: "Org X" }, headers: { "X-Forwarded-For": "203.0.113.7" } });
  assert.deepEqual([tooMany.status, tooMany.body.error], [429, "RATE_LIMIT_EXCEEDED"]);
});

test("register signs the new owner in with the session cookie", async () => {
  const r = await call("/v1/auth/register", { method: "POST", body: { email: "new@bank.test", password: "longenough", organizationName: "New Org" }, headers: { "X-Forwarded-For": "203.0.113.8" } });
  assert.equal(r.status, 201);
  const cookie = cookieFrom(r.headers).value!;
  const me = await call("/v1/whoami", { headers: { Cookie: `${SESSION_COOKIE}=${cookie}` } });
  assert.equal(me.status, 200);
  assert.equal(me.body.role, "OWNER");
});

test("when the limit store fails, sign-in still works (fails open; the password stays the gate)", async () => {
  authLimits.store = {
    hit: async () => { throw new Error("redis down"); },
    ttl: async () => { throw new Error("redis down"); },
    set: async () => { throw new Error("redis down"); },
    del: async () => { throw new Error("redis down"); },
  };
  assert.equal((await login("correct horse")).status, 200);
  assert.equal((await login("wrong")).status, 401);
});
