// The raw SQL queries against a real PostgreSQL (F-28): every dashboard view
// built with $queryRaw, the map points, the credential device counts, and
// /healthz. Runs only when TEST_DATABASE_URL points at a throwaway database
// with the migrations applied (CI: the postgres service; locally: see
// docs in .github/workflows/ci.yml). Never point it at real data: it writes
// rows and deletes everything of its own organization afterwards.
// Real: the whole app (createApp) over HTTP, Prisma, PostgreSQL, the JWT.
// Redis: whatever REDIS_URL points at (the limits fail open without it).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

const DB_URL = process.env.TEST_DATABASE_URL;
const skip = DB_URL ? false : "TEST_DATABASE_URL not set";

let server: Server;
let base = "";
let token = "";
let prisma: import("@prisma/client").PrismaClient;
const ORG = `org-it-${crypto.randomBytes(4).toString("hex")}`;
const APP = `app-it-${crypto.randomBytes(4).toString("hex")}`;
const USER = `user-it-${crypto.randomBytes(4).toString("hex")}`;

before(async () => {
  if (!DB_URL) return;
  process.env.DATABASE_URL = DB_URL;
  process.env.JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
  process.env.CREDENTIAL_ENCRYPTION_KEY = process.env.CREDENTIAL_ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex");
  ({ prisma } = await import("../src/db/prisma"));
  const { createApp } = await import("../src/app");
  const { signJwt } = await import("../src/auth/jwt");
  const { encryptSecret } = await import("../src/crypto/secretBox");

  await prisma.organization.create({ data: { id: ORG, name: "Integration Org" } });
  await prisma.user.create({ data: { id: USER, email: `${USER}@it.test`, passwordHash: "x", role: "OWNER", organizationId: ORG } });
  await prisma.application.create({ data: { id: APP, name: "Integration App", platform: "FLUTTER", organizationId: ORG } });
  await prisma.apiCredential.create({ data: { applicationId: APP, apiKey: `rasp_it_${crypto.randomBytes(6).toString("hex")}`, apiSecretEncrypted: encryptSecret("s") } });
  const now = Date.now();
  const events = [
    { deviceId: "dev-a", detectorId: "root_jailbreak", status: "DETECTED", minutesAgo: 5, located: true },
    { deviceId: "dev-a", detectorId: "vpn", status: "SECURE", minutesAgo: 4, located: false },
    { deviceId: "dev-b", detectorId: "mitm", status: "DETECTED", minutesAgo: 3, located: true },
    { deviceId: "dev-b", detectorId: "mitm", status: "SECURE", minutesAgo: 1, located: false },
    { deviceId: "dev-c", detectorId: "emulator", status: "UNKNOWN", minutesAgo: 2, located: false },
  ];
  for (const e of events) {
    await prisma.securityEvent.create({
      data: {
        applicationId: APP, deviceId: e.deviceId, detectorId: e.detectorId, status: e.status, deviceModel: "Pixel", osPlatform: "android",
        receivedAt: new Date(now - e.minutesAgo * 60_000),
        ...(e.located ? { latitude: 19.076, longitude: 72.878, locationOptIn: true, locationCapturedAt: new Date(now - e.minutesAgo * 60_000) } : {}),
      },
    });
  }
  await prisma.deviceLocation.create({ data: { applicationId: APP, deviceId: "dev-a", latitude: 19.076, longitude: 72.878, receivedAt: new Date(now - 60_000), capturedAt: new Date(now - 60_000) } });

  token = signJwt({ userId: USER, organizationId: ORG, role: "OWNER", tokenVersion: 0 });
  server = createApp().listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (!DB_URL) return;
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
  await prisma.securityEvent.deleteMany({ where: { applicationId: APP } });
  await prisma.deviceLocation.deleteMany({ where: { applicationId: APP } });
  await prisma.apiCredential.deleteMany({ where: { applicationId: APP } });
  await prisma.application.deleteMany({ where: { id: APP } });
  await prisma.user.deleteMany({ where: { id: USER } });
  await prisma.organization.deleteMany({ where: { id: ORG } });
  await prisma.$disconnect();
  (await import("../src/redis/client")).redis.disconnect();
});

const get = async (path: string) => {
  const res = await fetch(`${base}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
};

test("healthz runs SELECT 1 against the database", { skip }, async () => {
  const res = await fetch(`${base}/healthz`);
  assert.equal(((await res.json()) as { postgres: boolean }).postgres, true);
});

test("devices view: per-device counts and latest status from the raw queries", { skip }, async () => {
  const r = await get(`/v1/dashboard/applications/${APP}/devices`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const devices = r.body.devices as Array<Record<string, unknown>>;
  const ids = devices.map((d) => d.deviceId).sort();
  assert.deepEqual(ids, ["dev-a", "dev-b", "dev-c"]);
});

test("volume and risk summary queries run and count the seeded events", { skip }, async () => {
  const volume = await get(`/v1/dashboard/applications/${APP}/volume?hours=24`);
  assert.equal(volume.status, 200, JSON.stringify(volume.body));
  const summary = await get(`/v1/dashboard/applications/${APP}/risk-summary`);
  assert.equal(summary.status, 200, JSON.stringify(summary.body));
  // Latest per detector: root_jailbreak DETECTED on dev-a; mitm's latest on dev-b is SECURE.
  assert.ok(JSON.stringify(summary.body).includes("root_jailbreak"));
});

test("map points: located devices from the raw queries, in the 24 h default window", { skip }, async () => {
  const r = await get(`/v1/dashboard/map-points?applicationId=${APP}`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const points = r.body.points as Array<Record<string, unknown>>;
  assert.ok(points.some((p) => p.deviceId === "dev-a"), JSON.stringify(points));
});

test("credential list: device count per application from the raw query", { skip }, async () => {
  const r = await get(`/v1/credentials`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const ours = (r.body.credentials as Array<{ application?: { id?: string; deviceCount?: number }; deviceCount?: number }>)
    .find((c) => c.application?.id === APP);
  assert.ok(ours, "credential listed");
  assert.equal(ours!.application?.deviceCount ?? ours!.deviceCount, 3);
});
