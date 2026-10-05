// PATCH /v1/apps/:id security settings (Task 6.0 Parts 2.3 and 3.2).
// Real: parseAppSecurityPatch, canEditAppSecurity, the apps router with
// requireAuth (JWT) over real HTTP on an ephemeral port.
// Double: Prisma's application.findFirst / update replaced in-process (no Postgres).
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import { appsRouter, canEditAppSecurity, parseAppSecurityPatch } from "../src/apps/routes";
import { prisma } from "../src/db/prisma";

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

  test("only OWNER and ADMIN may change security settings", () => {
    assert.equal(canEditAppSecurity("OWNER"), true);
    assert.equal(canEditAppSecurity("ADMIN"), true);
    assert.equal(canEditAppSecurity("MEMBER"), false);
    assert.equal(canEditAppSecurity(undefined), false);
  });
});

describe("PATCH /v1/apps/:id", () => {
  const SECRET = "test-jwt-secret-not-real";
  const application = prisma.application as unknown as Record<string, unknown>;
  const original = { findFirst: application.findFirst, update: application.update, secret: process.env.JWT_SECRET };
  const updates: unknown[] = [];
  let port = 0;
  let server: import("node:http").Server;

  before(async () => {
    process.env.JWT_SECRET = SECRET;
    application.findFirst = async (args: { where: { id: string; organizationId: string } }) =>
      args.where.id === "app-1" && args.where.organizationId === "org-1" ? { id: "app-1" } : null;
    application.update = async (args: { data: unknown }) => {
      updates.push(args.data);
      return { id: "app-1", name: "Bank App", platform: "FLUTTER", expectedSigningCertSha256: A, ipBlockedCountries: [], ipAllowedCountries: ["IN"] };
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
    if (original.secret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = original.secret;
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  });

  const patch = async (id: string, body: unknown, role = "ADMIN", organizationId = "org-1") => {
    const token = jwt.sign({ userId: "u1", organizationId, role }, SECRET);
    const res = await fetch(`http://127.0.0.1:${port}/v1/apps/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };

  test("ADMIN sets the expected hash and the allow-list; the stored data is normalized", async () => {
    const r = await patch("app-1", { expectedSigningCertSha256: A.toLowerCase(), ipAllowedCountries: ["in"] });
    assert.equal(r.status, 200);
    assert.equal(r.body.application.expectedSigningCertSha256, A);
    assert.deepEqual(updates.at(-1), { expectedSigningCertSha256: A, ipAllowedCountries: ["IN"] });
  });

  test("MEMBER → 403; another organization's application → 404; invalid body → 400", async () => {
    const before = updates.length;
    assert.equal((await patch("app-1", { ipAllowedCountries: ["IN"] }, "MEMBER")).status, 403);
    assert.equal((await patch("app-1", { ipAllowedCountries: ["IN"] }, "OWNER", "org-2")).status, 404);
    assert.equal((await patch("app-1", { ipAllowedCountries: ["India"] })).status, 400);
    assert.equal(updates.length, before, "nothing written");
  });
});
