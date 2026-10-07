// GET /v1/dashboard/map-points (Task 6.0 Part 4.4).
// Real: buildMapPoints, mapPointsHandler, the query schema, severity mapping,
// and requireAuth (JWT verification) over real HTTP on an ephemeral port.
// Double: an in-memory MapPointsRepository that applies the same scoping the
// SQL does (organization, non-archived app, opted-in located rows, range).
// Not exercised: the SQL itself (needs Postgres).
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import { authAccounts, requireAuth } from "../src/middleware/auth";
import {
  buildMapPoints,
  DetectedEventRow,
  LocatedEventRow,
  MAP_POINTS_LIMIT,
  MapPointsRepository,
  MapPointsScope,
  mapPointsHandler,
  mapSeverity,
} from "../src/dashboard/mapPoints";

const NOW = Date.UTC(2026, 9, 5, 12, 0, 0);
const minutesAgo = (m: number) => new Date(NOW - m * 60_000);

interface Row {
  organizationId: string;
  applicationId: string;
  applicationName: string;
  archived?: boolean;
  deviceId: string;
  detectorId: string;
  status: string;
  locationOptIn: boolean;
  latitude: number | null;
  longitude: number | null;
  receivedAt: Date;
}

class MemoryMapRepo implements MapPointsRepository {
  constructor(public rows: Row[]) {}
  private inScope(r: Row, s: MapPointsScope) {
    return r.organizationId === s.organizationId && !r.archived && r.receivedAt >= s.since &&
      (!s.applicationId || r.applicationId === s.applicationId);
  }
  async findOwnedApplication(applicationId: string, organizationId: string) {
    const row = this.rows.find((r) => r.applicationId === applicationId && r.organizationId === organizationId && !r.archived);
    return row ? { id: row.applicationId } : null;
  }
  async latestLocatedPerDevice(s: MapPointsScope): Promise<LocatedEventRow[]> {
    const newest = new Map<string, Row>();
    for (const r of this.rows) {
      if (!this.inScope(r, s) || !r.locationOptIn || r.latitude === null || r.longitude === null) continue;
      const k = `${r.applicationId}/${r.deviceId}`;
      const cur = newest.get(k);
      if (!cur || r.receivedAt > cur.receivedAt) newest.set(k, r);
    }
    return [...newest.values()].map((r) => ({
      applicationId: r.applicationId, applicationName: r.applicationName, deviceId: r.deviceId,
      latitude: r.latitude!, longitude: r.longitude!, receivedAt: r.receivedAt,
    }));
  }
  async detectedEvents(s: MapPointsScope): Promise<DetectedEventRow[]> {
    return this.rows.filter((r) => this.inScope(r, s) && r.status === "DETECTED")
      .map((r) => ({ applicationId: r.applicationId, deviceId: r.deviceId, detectorId: r.detectorId, receivedAt: r.receivedAt }));
  }
}

const base = { organizationId: "org-1", applicationId: "app-1", applicationName: "Bank App" };
const row = (over: Partial<Row>): Row => ({
  ...base, deviceId: "device-aaaaaaaa-1", detectorId: "vpn", status: "SECURE",
  locationOptIn: true, latitude: 19.076, longitude: 72.877, receivedAt: minutesAgo(5), ...over,
});

describe("buildMapPoints", () => {
  test("severity: critical counts as high; the highest DETECTED severity per device; low without threats", () => {
    assert.equal(mapSeverity("root_jailbreak"), "high"); // critical
    assert.equal(mapSeverity("overlay"), "medium");
    assert.equal(mapSeverity("vpn"), "low");
    const located: LocatedEventRow[] = [
      { applicationId: "app-1", applicationName: "A", deviceId: "d1", latitude: 1, longitude: 2, receivedAt: minutesAgo(1) },
      { applicationId: "app-1", applicationName: "A", deviceId: "d2", latitude: 3, longitude: 4, receivedAt: minutesAgo(2) },
    ];
    const detected: DetectedEventRow[] = [
      { applicationId: "app-1", deviceId: "d1", detectorId: "vpn", receivedAt: minutesAgo(1) },
      { applicationId: "app-1", deviceId: "d1", detectorId: "overlay", receivedAt: minutesAgo(30) },
    ];
    const points = buildMapPoints(located, detected);
    assert.deepEqual(points.map((p) => [p.deviceId, p.severity, p.lastThreat?.detectorId ?? null]),
      [["d1", "medium", "vpn"], ["d2", "low", null]]);
  });

  test("newest first, device id shortened to 8 characters, limit 1000", () => {
    const located = Array.from({ length: MAP_POINTS_LIMIT + 5 }, (_, i): LocatedEventRow => ({
      applicationId: "app-1", applicationName: "A", deviceId: `device-${String(i).padStart(6, "0")}`,
      latitude: 10, longitude: 10, receivedAt: minutesAgo(i),
    }));
    const points = buildMapPoints(located.slice().reverse(), []);
    assert.equal(points.length, MAP_POINTS_LIMIT);
    assert.equal(points[0].deviceId, "device-0");
    assert.equal(points[0].at, minutesAgo(0).toISOString());
    assert.ok(points.every((p, i) => i === 0 || points[i - 1].at >= p.at));
  });
});

describe("GET /v1/dashboard/map-points", () => {
  const SECRET = "test-jwt-secret-not-real";
  let originalSecret: string | undefined;
  const originalFind = authAccounts.find;
  // The token's account exists, in the token's organization.
  before(() => {
    originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;
    authAccounts.find = async (claims) => ({ organizationId: claims.organizationId, role: claims.role });
  });
  after(() => {
    authAccounts.find = originalFind;
    if (originalSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalSecret;
  });
  const token = (organizationId = "org-1") => jwt.sign({ userId: "u1", organizationId, role: "MEMBER" }, SECRET);

  async function serve(repo: MapPointsRepository) {
    const app = express();
    app.get("/v1/dashboard/map-points", requireAuth, mapPointsHandler(repo, () => NOW));
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", () => r()));
    const { port } = server.address() as AddressInfo;
    return {
      async get(query = "", auth: string | null = token()) {
        const res = await fetch(`http://127.0.0.1:${port}/v1/dashboard/map-points${query}`,
          { headers: auth ? { Authorization: `Bearer ${auth}` } : {} });
        return { status: res.status, body: (await res.json()) as Record<string, any> };
      },
      close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
    };
  }

  const rows: Row[] = [
    row({ deviceId: "phone-high-1", detectorId: "root_jailbreak", status: "DETECTED", receivedAt: minutesAgo(10) }),
    row({ deviceId: "phone-high-1", detectorId: "vpn", status: "SECURE", receivedAt: minutesAgo(2), latitude: 19.1, longitude: 72.9 }),
    row({ deviceId: "phone-low-22", status: "SECURE", receivedAt: minutesAgo(20) }),
    // Not opted in: never on the map, even with coordinates.
    row({ deviceId: "phone-nooptin", status: "DETECTED", detectorId: "frida", locationOptIn: false, receivedAt: minutesAgo(1) }),
    // Another organization's device.
    row({ organizationId: "org-2", applicationId: "app-9", applicationName: "Other", deviceId: "phone-other-org", receivedAt: minutesAgo(1) }),
    // Archived application.
    row({ applicationId: "app-old", applicationName: "Old", archived: true, deviceId: "phone-archived", receivedAt: minutesAgo(1) }),
    // Second app of the same org, medium threat, 3 days ago.
    row({ applicationId: "app-2", applicationName: "Wallet", deviceId: "phone-medium", detectorId: "overlay", status: "DETECTED", receivedAt: minutesAgo(3 * 24 * 60) }),
  ];

  test("only the caller's organization, only opted-in located devices, newest first, one point per device", async () => {
    const s = await serve(new MemoryMapRepo(rows));
    try {
      const r = await s.get();
      assert.equal(r.status, 200);
      assert.deepEqual(r.body.points.map((p: any) => [p.deviceId, p.applicationName, p.severity]),
        [["phone-hi", "Bank App", "high"], ["phone-lo", "Bank App", "low"], ["phone-me", "Wallet", "medium"]]);
      const first = r.body.points[0];
      assert.deepEqual([first.latitude, first.longitude], [19.1, 72.9], "the device's newest located event");
      assert.equal(first.lastThreat.detectorId, "root_jailbreak");
    } finally {
      await s.close();
    }
  });

  test("filters: range, severity, application; another org's application is 404", async () => {
    const s = await serve(new MemoryMapRepo(rows));
    try {
      assert.deepEqual((await s.get("?range=24h")).body.points.map((p: any) => p.deviceId), ["phone-hi", "phone-lo"]);
      assert.deepEqual((await s.get("?severity=high")).body.points.map((p: any) => p.deviceId), ["phone-hi"]);
      assert.deepEqual((await s.get("?applicationId=app-2")).body.points.map((p: any) => p.deviceId), ["phone-me"]);
      assert.equal((await s.get("?applicationId=app-9")).status, 404);
      assert.equal((await s.get("?range=1y")).status, 400);
      assert.equal((await s.get("?severity=critical")).status, 400);
    } finally {
      await s.close();
    }
  });

  test("authentication required; another organization's token sees only its own devices", async () => {
    const s = await serve(new MemoryMapRepo(rows));
    try {
      assert.equal((await s.get("", null)).status, 401);
      assert.deepEqual((await s.get("", token("org-2"))).body.points.map((p: any) => p.deviceId), ["phone-ot"]);
    } finally {
      await s.close();
    }
  });
});
