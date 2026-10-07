// PATCH /v1/apps/:id security settings (Task 6.0 Parts 2.3 and 3.2; Task 8.1
// risk-rule thresholds and the settings audit log).
// Real: parseAppSecurityPatch, applySecurityPatch, canEditAppSecurity, the
// apps router with requireAuth (JWT) over real HTTP on an ephemeral port.
// Doubles: Prisma's application.findFirst / update, $transaction and
// applicationSettingsAuditLog.createMany replaced in-process (no Postgres);
// an in-memory rate counter instead of Redis.
import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import { appsRouter, applySecurityPatch, canEditAppSecurity, parseAppSecurityPatch } from "../src/apps/routes";
import { prisma } from "../src/db/prisma";
import { userRateLimit } from "../src/redis/userRateLimit";
import { authAccounts } from "../src/middleware/auth";
import { DEFAULT_RISK_RULES } from "../src/risk/rules";

const A = "AB".repeat(32);

describe("parseAppSecurityPatch", () => {
  test("hash normalized; null or empty clears it; malformed rejected", () => {
    assert.deepEqual(parseAppSecurityPatch({ expectedSigningCertSha256: A.toLowerCase().match(/../g)!.join(":") }),
      { ok: true, data: { expectedSigningCertSha256: A } });
    assert.deepEqual(parseAppSecurityPatch({ expectedSigningCertSha256: null }), { ok: true, data: { expectedSigningCertSha256: null } });
    assert.deepEqual(parseAppSecurityPatch({ expectedSigningCertSha256: "" }), { ok: true, data: { expectedSigningCertSha256: null } });
    assert.equal((parseAppSecurityPatch({ expectedSigningCertSha256: "abc" }) as { error: string }).error, "INVALID_SIGNING_CERT");
  });

  test("country lists: uppercase, unique; invalid codes rejected; unknown fields and empty body rejected", () => {
    assert.deepEqual(parseAppSecurityPatch({ ipBlockedCountries: ["kp", "IR", "kp"], ipAllowedCountries: [] }),
      { ok: true, data: { ipBlockedCountries: ["KP", "IR"], ipAllowedCountries: [] } });
    const bad = parseAppSecurityPatch({ ipAllowedCountries: ["IN", "India", "XX"] }) as { error: string; details: unknown };
    assert.equal(bad.error, "INVALID_COUNTRY_CODE");
    assert.deepEqual(bad.details, { field: "ipAllowedCountries", invalid: ["India", "XX"] });
    assert.equal((parseAppSecurityPatch({ name: "x" }) as { error: string }).error, "INVALID_INPUT");
    assert.equal((parseAppSecurityPatch({}) as { error: string }).error, "NOTHING_TO_UPDATE");
  });

  test("risk rules: a valid subset passes; out-of-range, unknown and the salt are rejected", () => {
    assert.deepEqual(parseAppSecurityPatch({ riskRules: { transactionVelocity: { maxCount: 3 } } }),
      { ok: true, data: { riskRules: { transactionVelocity: { maxCount: 3 } } } });
    assert.deepEqual(parseAppSecurityPatch({ riskRules: null }), { ok: true, data: { riskRules: null } });
    assert.equal((parseAppSecurityPatch({ riskRules: { transactionVelocity: { maxCount: 5000 } } }) as { error: string }).error, "INVALID_INPUT");
    assert.equal((parseAppSecurityPatch({ riskRules: { blockEverything: true } }) as { error: string }).error, "INVALID_INPUT");
    assert.equal((parseAppSecurityPatch({ accountHashSalt: "0".repeat(64) }) as { error: string }).error, "INVALID_INPUT");
  });

  test("only OWNER and ADMIN may change security settings", () => {
    assert.equal(canEditAppSecurity("OWNER"), true);
    assert.equal(canEditAppSecurity("ADMIN"), true);
    assert.equal(canEditAppSecurity("MEMBER"), false);
    assert.equal(canEditAppSecurity(undefined), false);
  });
});

describe("applySecurityPatch", () => {
  const current = { expectedSigningCertSha256: null, ipBlockedCountries: [], ipAllowedCountries: ["IN"], riskRules: structuredClone(DEFAULT_RISK_RULES) };

  test("one change per field that actually changed, with old and new values", () => {
    const { next, changes } = applySecurityPatch(current, { ipAllowedCountries: ["IN"], riskRules: { transactionVelocity: { maxCount: 3 } } });
    assert.equal(next.riskRules.transactionVelocity.maxCount, 3);
    assert.equal(next.riskRules.transactionVelocity.windowMinutes, 10, "other fields kept");
    assert.deepEqual(changes.map((c) => c.field), ["riskRules"], "unchanged country list is not audited");
    assert.equal((changes[0].oldValue as typeof DEFAULT_RISK_RULES).transactionVelocity.maxCount, 5);
  });

  test("null resets the rules to the defaults", () => {
    const custom = { ...current, riskRules: { ...structuredClone(DEFAULT_RISK_RULES), transactionVelocity: { maxCount: 1, windowMinutes: 5 } } };
    const { next, changes } = applySecurityPatch(custom, { riskRules: null });
    assert.deepEqual(next.riskRules, DEFAULT_RISK_RULES);
    assert.equal(changes.length, 1);
  });
});

describe("PATCH /v1/apps/:id and GET .../security-settings", () => {
  const SECRET = "test-jwt-secret-not-real";
  const application = prisma.application as unknown as Record<string, unknown>;
  const audit = prisma.applicationSettingsAuditLog as unknown as Record<string, unknown>;
  const client = prisma as unknown as Record<string, unknown>;
  const original = {
    findFirst: application.findFirst, update: application.update, createMany: audit.createMany,
    transaction: client.$transaction, check: userRateLimit.check, secret: process.env.JWT_SECRET,
    find: authAccounts.find,
  };
  const updates: unknown[] = [];
  const auditRows: Record<string, unknown>[] = [];
  let stored: Record<string, unknown> = {};
  let rateCount = 0;
  let rateLimit = 1000;
  let port = 0;
  let server: import("node:http").Server;

  before(async () => {
    process.env.JWT_SECRET = SECRET;
    application.findFirst = async (args: { where: { id: string; organizationId: string } }) =>
      args.where.id === "app-1" && args.where.organizationId === "org-1" ? { id: "app-1", ...stored } : null;
    application.update = async (args: { data: Record<string, unknown> }) => {
      updates.push(args.data);
      stored = { ...stored, ...args.data };
      return { id: "app-1", name: "Bank App", platform: "FLUTTER", expectedSigningCertSha256: A, ipBlockedCountries: [], ipAllowedCountries: ["IN"], riskRules: null, ...args.data };
    };
    audit.createMany = async (args: { data: Record<string, unknown>[] }) => {
      auditRows.push(...args.data);
      return { count: args.data.length };
    };
    client.$transaction = async (ops: Promise<unknown>[]) => Promise.all(ops);
    // The token's account exists, in the token's organization, with the token's role.
    authAccounts.find = async (claims) => ({ organizationId: claims.organizationId, role: claims.role });
    userRateLimit.check = async (_key, limit) => {
      rateCount++;
      return { allowed: rateCount <= Math.min(limit, rateLimit), remaining: 0 };
    };
    const app = express();
    app.use(express.json());
    app.use("/v1/apps", appsRouter);
    server = app.listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", () => r()));
    port = (server.address() as AddressInfo).port;
  });
  after(async () => {
    application.findFirst = original.findFirst;
    application.update = original.update;
    audit.createMany = original.createMany;
    client.$transaction = original.transaction;
    userRateLimit.check = original.check;
    authAccounts.find = original.find;
    if (original.secret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = original.secret;
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  });
  beforeEach(() => {
    stored = { expectedSigningCertSha256: null, ipBlockedCountries: [], ipAllowedCountries: [], riskRules: null, accountHashSalt: "9".repeat(64) };
    rateCount = 0;
    rateLimit = 1000;
  });

  const call = async (method: string, path: string, body?: unknown, role = "ADMIN", organizationId = "org-1") => {
    const token = jwt.sign({ userId: "u1", organizationId, role }, SECRET);
    const res = await fetch(`http://127.0.0.1:${port}/v1/apps/${path}`, {
      method,
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, body: JSON.parse(text) as Record<string, any>, text };
  };
  const patch = (id: string, body: unknown, role = "ADMIN", organizationId = "org-1") => call("PATCH", id, body, role, organizationId);

  test("ADMIN sets the expected hash and the allow-list; the stored data is normalized", async () => {
    const r = await patch("app-1", { expectedSigningCertSha256: A.toLowerCase(), ipAllowedCountries: ["in"] });
    assert.equal(r.status, 200);
    assert.equal(r.body.application.expectedSigningCertSha256, A);
    assert.deepEqual(updates.at(-1), { expectedSigningCertSha256: A, ipAllowedCountries: ["IN"] });
  });

  test("risk thresholds: merged, stored, audited with who / old / new; response has the effective rules", async () => {
    const before = auditRows.length;
    const r = await patch("app-1", { riskRules: { transactionVelocity: { maxCount: 3 } } }, "OWNER");
    assert.equal(r.status, 200);
    assert.equal(r.body.application.riskRules.transactionVelocity.maxCount, 3);
    assert.deepEqual(r.body.changed, ["riskRules"]);
    const row = auditRows[before];
    assert.equal(row.action, "SETTINGS_UPDATED");
    assert.equal(row.field, "riskRules");
    assert.equal(row.performedByUserId, "u1");
    assert.equal((row.oldValue as typeof DEFAULT_RISK_RULES).transactionVelocity.maxCount, 5);
    assert.equal((row.newValue as typeof DEFAULT_RISK_RULES).transactionVelocity.maxCount, 3);
  });

  test("MEMBER → 403; another organization's application → 404; invalid body → 400; nothing written", async () => {
    const before = updates.length;
    const auditBefore = auditRows.length;
    assert.equal((await patch("app-1", { ipAllowedCountries: ["IN"] }, "MEMBER")).status, 403);
    assert.equal((await patch("app-1", { riskRules: { transactionVelocity: { maxCount: 3 } } }, "MEMBER")).status, 403);
    assert.equal((await patch("app-1", { ipAllowedCountries: ["IN"] }, "OWNER", "org-2")).status, 404);
    assert.equal((await patch("app-1", { ipAllowedCountries: ["India"] })).status, 400);
    assert.equal((await patch("app-1", { riskRules: { concurrentSessions: { maxDevices: 0 } } })).status, 400);
    assert.equal((await patch("app-1", { riskRules: { concurrentSessions: { maxDevices: "2; DROP TABLE" } } })).status, 400);
    assert.equal(updates.length, before, "nothing written");
    assert.equal(auditRows.length, auditBefore, "nothing audited");
  });

  test("GET security-settings: values, defaults, limits, canEdit by role — never the salt", async () => {
    const admin = await call("GET", "app-1/security-settings");
    assert.equal(admin.status, 200);
    assert.equal(admin.body.canEdit, true);
    assert.deepEqual(admin.body.settings.riskRules, DEFAULT_RISK_RULES);
    assert.deepEqual(admin.body.riskRuleDefaults, DEFAULT_RISK_RULES);
    assert.ok(!admin.text.includes("9".repeat(64)) && !admin.text.includes("accountHashSalt"));
    assert.equal((await call("GET", "app-1/security-settings", undefined, "MEMBER")).body.canEdit, false);
    assert.equal((await call("GET", "app-1/security-settings", undefined, "OWNER", "org-2")).status, 404);
  });

  test("rate limited per user / IP → 429", async () => {
    rateLimit = 1;
    assert.equal((await call("GET", "app-1/security-settings")).status, 429);
  });
});
