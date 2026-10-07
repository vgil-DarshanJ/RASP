// GET /v1/dashboard/map-points (Task 6.0 Part 4.4; heartbeats, last seen,
// stale, summary and trail: Task 9.3).
// Real: buildMapPoints, chooseLocations, mapPointsHandler, the query schema,
// severity mapping, and requireAuth (JWT verification) over real HTTP on an
// ephemeral port; prismaMapPointsRepository's Prisma-client queries
// (heartbeat rows, trail) over the fake Prisma client.
// Doubles: an in-memory MapPointsRepository that applies the same scoping the
// SQL does (organization, non-archived app, opted-in located rows, range);
// FakeDatabase (test/fakePrisma.ts) instead of Postgres.
// Not exercised here: the raw SQL (DISTINCT ON, the reporting-device count)
// and groupBy — they need Postgres.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import { authAccounts, requireAuth } from "../src/middleware/auth";
import {
  buildMapPoints,
  chooseLocations,
  DetectedEventRow,
  DeviceKey,
  HeartbeatLocationRow,
  LastEventRow,
  LocatedEventRow,
  MAP_POINTS_LIMIT,
  MapPointsInput,
  MapPointsRepository,
  MapPointsScope,
  mapPointsHandler,
  mapSeverity,
  prismaMapPointsRepository,
  TrailPointRow,
} from "../src/dashboard/mapPoints";
import { FakeDatabase, installFakePrisma } from "./fakePrisma";

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

type Scoped<T> = T & { organizationId: string; archived?: boolean };

class MemoryMapRepo implements MapPointsRepository {
  constructor(
    public rows: Row[],
    public heartbeats: Scoped<HeartbeatLocationRow>[] = [],
    public points: Scoped<TrailPointRow>[] = [],
  ) {}
  private inScope(r: { organizationId: string; archived?: boolean; applicationId: string; receivedAt: Date }, s: MapPointsScope) {
    return r.organizationId === s.organizationId && !r.archived && r.receivedAt >= s.since &&
      (!s.applicationId || r.applicationId === s.applicationId);
  }
  private listed(r: DeviceKey, devices: DeviceKey[]) {
    return devices.some((d) => d.applicationId === r.applicationId && d.deviceId === r.deviceId);
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
  async heartbeatLocations(s: MapPointsScope): Promise<HeartbeatLocationRow[]> {
    return this.heartbeats.filter((h) => this.inScope(h, s)).map(({ organizationId: _o, archived: _a, ...h }) => h);
  }
  async detectedEvents(s: MapPointsScope): Promise<DetectedEventRow[]> {
    return this.rows.filter((r) => this.inScope(r, s) && r.status === "DETECTED")
      .map((r) => ({ applicationId: r.applicationId, deviceId: r.deviceId, detectorId: r.detectorId, receivedAt: r.receivedAt }));
  }
  async lastEventAt(s: MapPointsScope, devices: DeviceKey[]): Promise<LastEventRow[]> {
    const newest = new Map<string, LastEventRow>();
    for (const r of this.rows) {
      if (!this.inScope(r, s) || !this.listed(r, devices)) continue;
      const k = `${r.applicationId}/${r.deviceId}`;
      const cur = newest.get(k);
      if (!cur || r.receivedAt > cur.receivedAt) newest.set(k, { applicationId: r.applicationId, deviceId: r.deviceId, receivedAt: r.receivedAt });
    }
    return [...newest.values()];
  }
  async trailPoints(s: MapPointsScope, devices: DeviceKey[]): Promise<TrailPointRow[]> {
    return this.points.filter((p) => this.inScope(p, s) && this.listed(p, devices)).map(({ organizationId: _o, archived: _a, ...p }) => p);
  }
  async countReportingDevices(s: MapPointsScope) {
    const keys = new Set([...this.rows, ...this.heartbeats].filter((r) => this.inScope(r, s)).map((r) => `${r.applicationId}/${r.deviceId}`));
    return keys.size;
  }
}

const base = { organizationId: "org-1", applicationId: "app-1", applicationName: "Bank App" };
const row = (over: Partial<Row>): Row => ({
  ...base, deviceId: "device-aaaaaaaa-1", detectorId: "vpn", status: "SECURE",
  locationOptIn: true, latitude: 19.076, longitude: 72.877, receivedAt: minutesAgo(5), ...over,
});
const heartbeatRow = (over: Partial<Scoped<HeartbeatLocationRow>>): Scoped<HeartbeatLocationRow> => ({
  ...base, deviceId: "phone-hb-1", latitude: 21.045, longitude: 79.038, accuracyM: 14, isMock: false, receivedAt: minutesAgo(1), ...over,
});
const input = (over: Partial<MapPointsInput>): MapPointsInput => ({
  located: [], heartbeats: [], detected: [], lastEvents: [], trail: [], now: NOW, ...over,
});
const located = (deviceId: string, receivedAt: Date, lat = 1, lon = 2): LocatedEventRow =>
  ({ applicationId: "app-1", applicationName: "A", deviceId, latitude: lat, longitude: lon, receivedAt });

describe("buildMapPoints", () => {
  test("severity: critical counts as high; the highest DETECTED severity per device; none without threats", () => {
    assert.equal(mapSeverity("root_jailbreak"), "high"); // critical
    assert.equal(mapSeverity("overlay"), "medium");
    assert.equal(mapSeverity("vpn"), "low");
    const detected: DetectedEventRow[] = [
      { applicationId: "app-1", deviceId: "d1", detectorId: "vpn", receivedAt: minutesAgo(1) },
      { applicationId: "app-1", deviceId: "d1", detectorId: "overlay", receivedAt: minutesAgo(30) },
    ];
    const { points } = buildMapPoints(input({ located: [located("d1", minutesAgo(1)), located("d2", minutesAgo(2))], detected }));
    assert.deepEqual(points.map((p) => [p.deviceId, p.severity, p.lastThreat?.detectorId ?? null]),
      [["d1", "medium", "vpn"], ["d2", "none", null]]);
    const onlyClean = buildMapPoints(input({ located: [located("d1", minutesAgo(1)), located("d2", minutesAgo(2))], detected }), { severity: "none" });
    assert.deepEqual(onlyClean.points.map((p) => p.deviceId), ["d2"]);
    assert.equal(onlyClean.devicesWithLocation, 2, "the summary ignores the severity filter");
  });

  test("newest first, device id shortened to 8 characters, limit 1000", () => {
    const rows = Array.from({ length: MAP_POINTS_LIMIT + 5 }, (_, i) => located(`device-${String(i).padStart(6, "0")}`, minutesAgo(i), 10, 10));
    const { points } = buildMapPoints(input({ located: rows.slice().reverse() }));
    assert.equal(points.length, MAP_POINTS_LIMIT);
    assert.equal(points[0].deviceId, "device-0");
    assert.equal(points[0].at, minutesAgo(0).toISOString());
    assert.ok(points.every((p, i) => i === 0 || points[i - 1].at >= p.at));
  });

  test("location: the newer of heartbeat and located event; a newer sharing-off heartbeat hides the device", () => {
    const heartbeats: HeartbeatLocationRow[] = [
      { applicationId: "app-1", applicationName: "A", deviceId: "hb-newer", latitude: 21.045, longitude: 79.038, accuracyM: 14, isMock: true, receivedAt: minutesAgo(1) },
      { applicationId: "app-1", applicationName: "A", deviceId: "event-newer", latitude: 5, longitude: 5, accuracyM: 30, isMock: false, receivedAt: minutesAgo(50) },
      { applicationId: "app-1", applicationName: "A", deviceId: "sharing-off", latitude: null, longitude: null, accuracyM: null, isMock: null, receivedAt: minutesAgo(2) },
    ];
    const events = [located("hb-newer", minutesAgo(30), 9, 9), located("event-newer", minutesAgo(3), 7, 7), located("sharing-off", minutesAgo(20), 8, 8)];
    const chosen = chooseLocations(events, heartbeats);
    assert.deepEqual(chosen.map((c) => [c.deviceId, c.source, c.latitude]).sort(), [["event-newer", "event", 7], ["hb-newer", "heartbeat", 21.045]]);
    const { points, devicesWithLocation } = buildMapPoints(input({ located: events, heartbeats }));
    assert.equal(devicesWithLocation, 2);
    const hb = points.find((p) => p.deviceId === "hb-newer")!;
    assert.deepEqual([hb.accuracyM, hb.isMock, hb.source], [14, true, "heartbeat"]);
    const ev = points.find((p) => p.deviceId === "event-ne")!;
    assert.deepEqual([ev.source, ev.latitude, ev.accuracyM, ev.isMock, ev.lastSeenAt], ["event", 7, null, null, minutesAgo(3).toISOString()]);
  });

  test("stale after 10 minutes; last seen = the newest heartbeat, event or threat", () => {
    const lastEvents: LastEventRow[] = [{ applicationId: "app-1", deviceId: "old-fix", receivedAt: minutesAgo(1) }];
    const { points } = buildMapPoints(input({
      located: [located("fresh-fix", minutesAgo(9)), located("old-fix", minutesAgo(11))],
      lastEvents,
    }));
    const byId = Object.fromEntries(points.map((p) => [p.deviceId, p]));
    assert.equal(byId["fresh-fi"].stale, false);
    assert.equal(byId["fresh-fi"].lastSeenAt, minutesAgo(9).toISOString());
    assert.equal(byId["old-fix"].stale, true, "the location is 11 minutes old");
    assert.equal(byId["old-fix"].lastSeenAt, minutesAgo(1).toISOString(), "but the device sent an event a minute ago");
  });

  test("trail: only with includeTrail, oldest first, only the device's own points", () => {
    const trail: TrailPointRow[] = [
      { applicationId: "app-1", deviceId: "d1", latitude: 1.002, longitude: 2, receivedAt: minutesAgo(1) },
      { applicationId: "app-1", deviceId: "d1", latitude: 1.001, longitude: 2, receivedAt: minutesAgo(2) },
      { applicationId: "app-1", deviceId: "d2", latitude: 50, longitude: 50, receivedAt: minutesAgo(1) },
    ];
    const without = buildMapPoints(input({ located: [located("d1", minutesAgo(1))], trail }));
    assert.equal(without.points[0].trail, undefined);
    const withTrail = buildMapPoints(input({ located: [located("d1", minutesAgo(1))], trail }), { includeTrail: true });
    assert.deepEqual(withTrail.points[0].trail, [
      { latitude: 1.001, longitude: 2, at: minutesAgo(2).toISOString() },
      { latitude: 1.002, longitude: 2, at: minutesAgo(1).toISOString() },
    ]);
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
  async function withServer(repo: MapPointsRepository, run: (s: Awaited<ReturnType<typeof serve>>) => Promise<void>) {
    const s = await serve(repo);
    try {
      await run(s);
    } finally {
      await s.close();
    }
  }
  const ids = (body: Record<string, any>) => body.points.map((p: any) => p.deviceId);

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
  const heartbeats = [
    // The trial phone: no threats, location heartbeat a minute ago.
    heartbeatRow({ deviceId: "trial-phone-1", receivedAt: minutesAgo(1) }),
    heartbeatRow({ organizationId: "org-2", applicationId: "app-9", applicationName: "Other", deviceId: "hb-other-org" }),
    heartbeatRow({ applicationId: "app-old", applicationName: "Old", archived: true, deviceId: "hb-archived" }),
  ];

  test("defaults: last 24 hours, all severities; devices without threats are 'none'", async () => {
    await withServer(new MemoryMapRepo(rows, heartbeats), async (s) => {
      const r = await s.get();
      assert.equal(r.status, 200);
      assert.deepEqual(r.body.points.map((p: any) => [p.deviceId, p.applicationName, p.severity, p.source]), [
        ["trial-ph", "Bank App", "none", "heartbeat"],
        ["phone-hi", "Bank App", "high", "event"],
        ["phone-lo", "Bank App", "none", "event"],
      ]);
      const trial = r.body.points[0];
      assert.deepEqual([trial.latitude, trial.longitude, trial.stale, trial.lastSeenAt], [21.045, 79.038, false, minutesAgo(1).toISOString()]);
      const first = r.body.points[1];
      assert.deepEqual([first.latitude, first.longitude], [19.1, 72.9], "the device's newest located event");
      assert.equal(first.lastThreat.detectorId, "root_jailbreak");
      assert.equal(r.body.points[2].stale, true, "phone-low-22's location is 20 minutes old");
      assert.equal(r.body.staleAfterMinutes, 10);
      // Reporting in range: trial-phone-1, phone-high-1, phone-low-22, phone-nooptin (no location).
      assert.deepEqual(r.body.summary, { devicesReporting: 4, devicesWithLocation: 3 });
    });
  });

  test("filters: range, severity (none included), application; another org's application is 404", async () => {
    await withServer(new MemoryMapRepo(rows, heartbeats), async (s) => {
      assert.deepEqual(ids((await s.get("?range=7d")).body), ["trial-ph", "phone-hi", "phone-lo", "phone-me"]);
      assert.deepEqual(ids((await s.get("?severity=high")).body), ["phone-hi"]);
      assert.deepEqual(ids((await s.get("?severity=none")).body), ["trial-ph", "phone-lo"]);
      assert.deepEqual(ids((await s.get("?applicationId=app-2&range=30d")).body), ["phone-me"]);
      assert.equal((await s.get("?applicationId=app-9")).status, 404);
      assert.equal((await s.get("?range=1y")).status, 400);
      assert.equal((await s.get("?severity=critical")).status, 400);
      assert.equal((await s.get("?trail=yes")).status, 400);
    });
  });

  test("empty map: the summary says whether devices report without a shared location", async () => {
    const noLocation = [row({ deviceId: "phone-a", locationOptIn: false }), row({ deviceId: "phone-b", locationOptIn: false, latitude: null, longitude: null })];
    const sharingOff = [heartbeatRow({ deviceId: "phone-c", latitude: null, longitude: null, accuracyM: null, isMock: null })];
    await withServer(new MemoryMapRepo(noLocation, sharingOff), async (s) => {
      const r = await s.get();
      assert.deepEqual(r.body.points, []);
      assert.deepEqual(r.body.summary, { devicesReporting: 3, devicesWithLocation: 0 });
    });
    await withServer(new MemoryMapRepo([]), async (s) => {
      assert.deepEqual((await s.get()).body.summary, { devicesReporting: 0, devicesWithLocation: 0 });
    });
  });

  test("trail=true adds each device's trail in range", async () => {
    const points = [
      { ...base, deviceId: "trial-phone-1", latitude: 21.044, longitude: 79.037, receivedAt: minutesAgo(3) },
      { ...base, deviceId: "trial-phone-1", latitude: 21.045, longitude: 79.038, receivedAt: minutesAgo(1) },
      { ...base, deviceId: "trial-phone-1", latitude: 20, longitude: 70, receivedAt: minutesAgo(3 * 24 * 60) }, // out of range
      { ...base, organizationId: "org-2", applicationId: "app-9", deviceId: "hb-other-org", latitude: 1, longitude: 1, receivedAt: minutesAgo(1) },
    ];
    await withServer(new MemoryMapRepo(rows, heartbeats, points), async (s) => {
      const r = await s.get("?trail=true");
      const trial = r.body.points.find((p: any) => p.deviceId === "trial-ph");
      assert.deepEqual(trial.trail.map((t: any) => [t.latitude, t.longitude]), [[21.044, 79.037], [21.045, 79.038]]);
      assert.deepEqual(r.body.points.find((p: any) => p.deviceId === "phone-hi").trail, []);
      assert.equal((await s.get()).body.points[0].trail, undefined);
    });
  });

  test("authentication required; another organization's token sees only its own devices", async () => {
    await withServer(new MemoryMapRepo(rows, heartbeats), async (s) => {
      assert.equal((await s.get("", null)).status, 401);
      assert.deepEqual(ids((await s.get("", token("org-2"))).body), ["hb-other", "phone-ot"]);
    });
  });
});

describe("prismaMapPointsRepository location queries (fake Prisma)", () => {
  const db = new FakeDatabase();
  let restore: () => void = () => {};
  const scope = (over: Partial<MapPointsScope> = {}): MapPointsScope => ({ organizationId: "org-1", since: minutesAgo(24 * 60), ...over });
  before(() => {
    db.insert("organization", { id: "org-1", name: "Bank Org" });
    db.insert("organization", { id: "org-2", name: "Other Org" });
    db.insert("application", { id: "app-1", name: "Bank App", platform: "FLUTTER", organizationId: "org-1" });
    db.insert("application", { id: "app-2", name: "Wallet", platform: "FLUTTER", organizationId: "org-1" });
    db.insert("application", { id: "app-old", name: "Old", platform: "FLUTTER", organizationId: "org-1", archivedAt: minutesAgo(60) });
    db.insert("application", { id: "app-9", name: "Other", platform: "FLUTTER", organizationId: "org-2" });
    const location = (applicationId: string, deviceId: string, receivedAt: Date) =>
      db.insert("deviceLocation", { applicationId, deviceId, latitude: 21.045, longitude: 79.038, accuracyM: 14, isMock: false, receivedAt });
    location("app-1", "phone-1", minutesAgo(1));
    location("app-2", "phone-2", minutesAgo(2));
    location("app-1", "phone-old", minutesAgo(3 * 24 * 60));
    location("app-old", "phone-archived", minutesAgo(1));
    location("app-9", "phone-other", minutesAgo(1));
    for (const [deviceId, m] of [["phone-1", 3], ["phone-1", 1], ["phone-2", 1], ["phone-other", 1]] as const) {
      db.insert("deviceLocationPoint", { applicationId: deviceId === "phone-other" ? "app-9" : deviceId === "phone-2" ? "app-2" : "app-1", deviceId, latitude: m, longitude: m, receivedAt: minutesAgo(m) });
    }
    restore = installFakePrisma(db);
  });
  after(() => restore());

  test("heartbeat rows: organization, non-archived application, range and application filter", async () => {
    const rows = await prismaMapPointsRepository.heartbeatLocations(scope());
    assert.deepEqual(rows.map((r) => [r.deviceId, r.applicationName]).sort(), [["phone-1", "Bank App"], ["phone-2", "Wallet"]]);
    assert.deepEqual((await prismaMapPointsRepository.heartbeatLocations(scope({ applicationId: "app-2" }))).map((r) => r.deviceId), ["phone-2"]);
    assert.deepEqual((await prismaMapPointsRepository.heartbeatLocations(scope({ organizationId: "org-2" }))).map((r) => r.deviceId), ["phone-other"]);
  });

  test("trail points: only the listed devices of the organization, oldest first", async () => {
    const devices = [{ applicationId: "app-1", deviceId: "phone-1" }, { applicationId: "app-9", deviceId: "phone-other" }];
    const rows = await prismaMapPointsRepository.trailPoints(scope(), devices);
    assert.deepEqual(rows.map((r) => [r.deviceId, r.latitude]), [["phone-1", 3], ["phone-1", 1]]);
    assert.deepEqual(await prismaMapPointsRepository.trailPoints(scope(), []), []);
  });
});
