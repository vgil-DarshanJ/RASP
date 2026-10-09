import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { getDetectorCountsFromCache, getRecentEventsFromCache } from "../redis/dashboardCache";
import { contributingDetectors, riskLevelForScore, scoreForLatestStatuses } from "../detectors/severity";
import { mapPointsHandler } from "./mapPoints";
import { deviceRiskHandler, riskEventsHandler } from "./riskEvents";
import { userRateLimiter } from "../redis/userRateLimit";
import { PUBLIC_APPLICATION_SELECT } from "../security/secretFields";
import { csvField } from "./csv";

export const dashboardRouter = Router();
dashboardRouter.use(requireAuth);

/** Map of devices that shared their location — see mapPoints.ts. */
dashboardRouter.get("/map-points", mapPointsHandler());

/** `archivedAt: null` hides every dashboard view (devices, events, risk
 *  scores, geography, exports…) for an archived application without
 *  touching a single `SecurityEvent` row — see `apps/routes.ts`'s
 *  archive endpoint. */
async function assertOwnedApplication(applicationId: string, organizationId: string) {
  return prisma.application.findFirst({ where: { id: applicationId, organizationId, archivedAt: null } });
}

/** Session/transaction risk events (hashes shortened) — see riskEvents.ts. */
const riskViewsRateLimit = userRateLimiter({ scope: "risk_views", perUser: 240, perIp: 600, windowSeconds: 60 });
dashboardRouter.get("/applications/:applicationId/risk-events", riskViewsRateLimit, riskEventsHandler(assertOwnedApplication));
dashboardRouter.get("/applications/:applicationId/device-risk", riskViewsRateLimit, deviceRiskHandler(assertOwnedApplication));

/** "Most common alert type" chart data — tries the Redis rolling-counter
 *  cache first (cheap, recent-hours only), falls back to a real Postgres
 *  GROUP BY covering the full requested window when Redis is unavailable
 *  or the window exceeds what's cached. Redis is never the only source of
 *  truth for this — see redis/dashboardCache.ts's doc. */
dashboardRouter.get("/applications/:applicationId/detector-counts", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const hours = Math.min(Number(req.query.hours) || 24, 24 * 7);

  if (hours <= 24) {
    const cached = await getDetectorCountsFromCache(app.id, hours);
    if (cached) return res.json({ source: "cache", counts: cached });
  }

  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  const rows = await prisma.securityEvent.groupBy({
    by: ["detectorId"],
    where: { applicationId: app.id, receivedAt: { gte: since } },
    _count: { detectorId: true },
  });
  const counts = Object.fromEntries(rows.map((r) => [r.detectorId, r._count.detectorId]));
  res.json({ source: "postgres", counts });
});

/** Volume-over-time chart — hourly buckets, real Postgres aggregation
 *  (this one always queries fresh; the granularity/window here is small
 *  enough that a Redis fast-path isn't worth the extra cache-invalidation
 *  complexity). */
dashboardRouter.get("/applications/:applicationId/volume", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const hours = Math.min(Number(req.query.hours) || 24, 24 * 30);
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  const rows = await prisma.$queryRaw<{ bucket: Date; status: string; count: bigint }[]>`
    SELECT date_trunc('hour', "receivedAt") AS bucket, status, COUNT(*)::bigint AS count
    FROM security_events
    WHERE "applicationId" = ${app.id} AND "receivedAt" >= ${since}
    GROUP BY bucket, status
    ORDER BY bucket ASC
  `;

  res.json({
    buckets: rows.map((r) => ({ bucket: r.bucket.toISOString(), status: r.status, count: Number(r.count) })),
  });
});

const listQuerySchema = z.object({
  status: z.enum(["SECURE", "DETECTED", "UNAVAILABLE", "UNKNOWN", "ERROR"]).optional(),
  detectorId: z.string().optional(),
  deviceId: z.string().optional(),
  limit: z.coerce.number().min(1).max(200).default(50),
  cursor: z.string().optional(), // event id — keyset pagination, stable under high insert volume
});

/** The filterable event log table's data source — cursor-paginated
 *  (keyset, not OFFSET) so it stays fast as the table grows into millions
 *  of rows, which a security-event audit table genuinely will. */
dashboardRouter.get("/applications/:applicationId/events", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const parsed = listQuerySchema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_QUERY" });
  const { status, detectorId, deviceId, limit, cursor } = parsed.data;

  const events = await prisma.securityEvent.findMany({
    where: {
      applicationId: app.id,
      ...(status && { status }),
      ...(detectorId && { detectorId }),
      ...(deviceId && { deviceId }),
    },
    orderBy: { receivedAt: "desc" },
    take: limit + 1,
    ...(cursor && { cursor: { id: cursor }, skip: 1 }),
  });

  const hasMore = events.length > limit;
  const page = hasMore ? events.slice(0, limit) : events;

  res.json({
    events: page,
    nextCursor: hasMore ? page[page.length - 1]?.id ?? null : null,
  });
});

/** Live-ish "recent events" strip — reads the Redis cache first for
 *  snappy polling, falls back to Postgres if the cache is cold/unavailable. */
dashboardRouter.get("/applications/:applicationId/recent", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const cached = await getRecentEventsFromCache(app.id);
  if (cached) return res.json({ source: "cache", events: cached });

  const events = await prisma.securityEvent.findMany({
    where: { applicationId: app.id },
    orderBy: { receivedAt: "desc" },
    take: 50,
  });
  res.json({ source: "postgres", events });
});

/**
 * Real device inventory for one application — every distinct `deviceId`
 * that has ever reported an event, with its latest known identity
 * (model/OS/app version — taken from its most recent event, since a
 * device's own attributes can drift between reports) and lifetime
 * counters. Two real Postgres queries, no mocked/placeholder rows:
 * `DISTINCT ON` for "latest identity per device" (Postgres-specific,
 * cheaper than a window function here) and a plain GROUP BY for the
 * counters, merged by deviceId in JS.
 */
dashboardRouter.get("/applications/:applicationId/devices", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const [latest, counters, latestPerDetector, sharedLocation] = await Promise.all([
    prisma.$queryRaw<
      {
        deviceId: string;
        deviceModel: string | null;
        manufacturer: string | null;
        osPlatform: string | null;
        osVersion: string | null;
        appVersion: string | null;
        sdkVersion: string | null;
        lastStatus: string;
        lastSeen: Date;
      }[]
    >`
      SELECT DISTINCT ON ("deviceId")
        "deviceId", "deviceModel", "manufacturer", "osPlatform", "osVersion",
        "appVersion", "sdkVersion", status AS "lastStatus", "receivedAt" AS "lastSeen"
      FROM security_events
      WHERE "applicationId" = ${app.id} AND "deviceId" IS NOT NULL
      ORDER BY "deviceId", "receivedAt" DESC
    `,
    prisma.$queryRaw<{ deviceId: string; eventCount: bigint; threatCount: bigint; firstSeen: Date }[]>`
      SELECT
        "deviceId",
        COUNT(*)::bigint AS "eventCount",
        COUNT(*) FILTER (WHERE status = 'DETECTED')::bigint AS "threatCount",
        MIN("receivedAt") AS "firstSeen"
      FROM security_events
      WHERE "applicationId" = ${app.id} AND "deviceId" IS NOT NULL
      GROUP BY "deviceId"
    `,
    // Risk scoring needs each device's LATEST status PER DETECTOR (not
    // just "any threat ever") — a detector that was DETECTED once and is
    // now SECURE must not keep contributing to the score forever.
    prisma.$queryRaw<{ deviceId: string; detectorId: string; status: string }[]>`
      SELECT DISTINCT ON ("deviceId", "detectorId")
        "deviceId", "detectorId", status
      FROM security_events
      WHERE "applicationId" = ${app.id} AND "deviceId" IS NOT NULL
      ORDER BY "deviceId", "detectorId", "receivedAt" DESC
    `,
    // Devices that have shared their location at least once (opted in).
    prisma.$queryRaw<{ deviceId: string }[]>`
      SELECT DISTINCT "deviceId"
      FROM security_events
      WHERE "applicationId" = ${app.id} AND "deviceId" IS NOT NULL AND "locationOptIn" = true
    `,
  ]);

  const counterByDevice = new Map(counters.map((c) => [c.deviceId, c]));
  const locationSharedBy = new Set(sharedLocation.map((r) => r.deviceId));
  const statusesByDevice = new Map<string, Record<string, string>>();
  for (const row of latestPerDetector) {
    const bucket = statusesByDevice.get(row.deviceId) ?? {};
    bucket[row.detectorId] = row.status;
    statusesByDevice.set(row.deviceId, bucket);
  }

  const devices = latest
    .map((row) => {
      const counter = counterByDevice.get(row.deviceId);
      const latestStatuses = statusesByDevice.get(row.deviceId) ?? {};
      const riskScore = scoreForLatestStatuses(latestStatuses);
      return {
        deviceId: row.deviceId,
        deviceModel: row.deviceModel,
        manufacturer: row.manufacturer,
        osPlatform: row.osPlatform,
        osVersion: row.osVersion,
        appVersion: row.appVersion,
        sdkVersion: row.sdkVersion,
        lastStatus: row.lastStatus,
        lastSeen: row.lastSeen.toISOString(),
        firstSeen: (counter?.firstSeen ?? row.lastSeen).toISOString(),
        eventCount: Number(counter?.eventCount ?? 0),
        threatCount: Number(counter?.threatCount ?? 0),
        riskScore,
        riskLevel: riskLevelForScore(riskScore),
        riskDetectors: contributingDetectors(latestStatuses).map((d) => d.detectorId),
        /** false → the UI shows "location not shared"; the device is never on the map. */
        locationShared: locationSharedBy.has(row.deviceId),
      };
    })
    .sort((a, b) => b.riskScore - a.riskScore || b.lastSeen.localeCompare(a.lastSeen));

  res.json({ devices });
});

/**
 * App-level risk rollup, built from the same per-device/per-detector
 * "latest status" data as `/devices` above (recomputed here rather than
 * shared in-process — this route can be called independently and the
 * query is cheap: one indexed DISTINCT ON scan). Gives the Dashboard a
 * single headline number plus the "why" behind it: an aggregate risk
 * figure first, then the individual devices.
 */
dashboardRouter.get("/applications/:applicationId/risk-summary", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const latestPerDetector = await prisma.$queryRaw<
    { deviceId: string; detectorId: string; status: string }[]
  >`
    SELECT DISTINCT ON ("deviceId", "detectorId")
      "deviceId", "detectorId", status
    FROM security_events
    WHERE "applicationId" = ${app.id} AND "deviceId" IS NOT NULL
    ORDER BY "deviceId", "detectorId", "receivedAt" DESC
  `;

  const statusesByDevice = new Map<string, Record<string, string>>();
  for (const row of latestPerDetector) {
    const bucket = statusesByDevice.get(row.deviceId) ?? {};
    bucket[row.detectorId] = row.status;
    statusesByDevice.set(row.deviceId, bucket);
  }

  const detectorWeightTotals = new Map<string, number>();
  const distribution: Record<"low" | "medium" | "high" | "critical", number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  const deviceScores: Array<{ deviceId: string; riskScore: number }> = [];
  for (const [deviceId, statuses] of statusesByDevice.entries()) {
    const score = scoreForLatestStatuses(statuses);
    deviceScores.push({ deviceId, riskScore: score });
    distribution[riskLevelForScore(score)]++;
    for (const d of contributingDetectors(statuses)) {
      detectorWeightTotals.set(d.detectorId, (detectorWeightTotals.get(d.detectorId) ?? 0) + 1);
    }
  }

  const totalDevices = deviceScores.length;
  const avgScore = totalDevices > 0 ? deviceScores.reduce((s, d) => s + d.riskScore, 0) / totalDevices : 0;
  const maxScore = totalDevices > 0 ? Math.max(...deviceScores.map((d) => d.riskScore)) : 0;

  const topRiskyDevices = deviceScores
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 10);

  const topContributingDetectors = Array.from(detectorWeightTotals.entries())
    .map(([detectorId, deviceCount]) => ({ detectorId, deviceCount }))
    .sort((a, b) => b.deviceCount - a.deviceCount)
    .slice(0, 10);

  res.json({
    totalDevices,
    averageRiskScore: Math.round(avgScore * 10) / 10,
    averageRiskLevel: riskLevelForScore(avgScore),
    maxRiskScore: maxScore,
    maxRiskLevel: riskLevelForScore(maxScore),
    distribution,
    topRiskyDevices,
    topContributingDetectors,
  });
});

/**
 * Threat geolocation feed for a map/list view — DETECTED events whose
 * location was shared with opt-in (`locationOptIn`, stored columns; see
 * ingestion/location.ts). Coordinates that older SDKs put into the evidence
 * without opt-in are deliberately NOT read here, so a device that did not
 * opt in never appears on a map.
 */
dashboardRouter.get("/applications/:applicationId/geography", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const hours = Math.min(Number(req.query.hours) || 24, 24 * 30);
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  const events = await prisma.securityEvent.findMany({
    where: {
      applicationId: app.id,
      status: "DETECTED",
      receivedAt: { gte: since },
      locationOptIn: true,
      latitude: { not: null },
      longitude: { not: null },
    },
    select: { id: true, detectorId: true, deviceId: true, receivedAt: true, latitude: true, longitude: true },
    orderBy: { receivedAt: "desc" },
    take: 2000,
  });

  const points = events.map((event) => ({
    eventId: event.id,
    detectorId: event.detectorId,
    deviceId: event.deviceId,
    receivedAt: event.receivedAt.toISOString(),
    latitude: event.latitude as number,
    longitude: event.longitude as number,
  }));

  res.json({ points });
});

const exportQuerySchema = z.object({
  status: z.enum(["SECURE", "DETECTED", "UNAVAILABLE", "UNKNOWN", "ERROR"]).optional(),
  detectorId: z.string().optional(),
  hours: z.coerce.number().min(1).max(24 * 90).default(24 * 7),
});


/**
 * CSV export of the audit trail, for compliance reporting. Builds
 * the file in memory (capped at 20,000 rows — generous for a single
 * export; a customer needing more should page by date range) rather than
 * streaming, since this dataset size makes that complexity unnecessary.
 */
dashboardRouter.get("/applications/:applicationId/events/export", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const parsed = exportQuerySchema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_QUERY" });
  const { status, detectorId, hours } = parsed.data;
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  const events = await prisma.securityEvent.findMany({
    where: {
      applicationId: app.id,
      receivedAt: { gte: since },
      ...(status && { status }),
      ...(detectorId && { detectorId }),
    },
    orderBy: { receivedAt: "desc" },
    take: 20_000,
  });

  const columns = [
    "receivedAt",
    "detectorId",
    "status",
    "reason",
    "deviceId",
    "deviceModel",
    "manufacturer",
    "osPlatform",
    "osVersion",
    "appVersion",
    "sdkVersion",
    "ipAddress",
    "evidence",
  ] as const;

  const lines = [columns.join(",")];
  for (const e of events) {
    lines.push(
      columns
        .map((col) => {
          if (col === "receivedAt") return csvField(e.receivedAt.toISOString());
          return csvField((e as any)[col]);
        })
        .join(","),
    );
  }

  const filename = `${app.name.replace(/[^a-z0-9]+/gi, "_")}_events_${new Date().toISOString().slice(0, 10)}.csv`;
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.send(lines.join("\n"));
});

/**
 * Org-wide search across applications and the devices/events they've
 * reported — real Postgres `ILIKE`-style matching (Prisma `contains` +
 * `insensitive` mode), scoped to the caller's own organization via the
 * `application.organizationId` relation filter. No fuzzy/vector search,
 * no external index — this dataset is small enough that a couple of
 * indexed `WHERE` queries stay fast, and it never returns another org's
 * data since every branch filters through that relation.
 */
dashboardRouter.get("/search", async (req: AuthedRequest, res) => {
  const q = String(req.query.q ?? "").trim();
  if (q.length < 2) return res.json({ applications: [], events: [] });

  const organizationId = req.user!.organizationId;

  const [applications, events] = await Promise.all([
    prisma.application.findMany({
      where: { organizationId, archivedAt: null, name: { contains: q, mode: "insensitive" } },
      orderBy: { createdAt: "desc" },
      take: 10,
      select: PUBLIC_APPLICATION_SELECT,
    }),
    prisma.securityEvent.findMany({
      where: {
        application: { organizationId, archivedAt: null },
        OR: [
          { deviceId: { contains: q, mode: "insensitive" } },
          { deviceModel: { contains: q, mode: "insensitive" } },
          { manufacturer: { contains: q, mode: "insensitive" } },
          { detectorId: { contains: q, mode: "insensitive" } },
        ],
      },
      orderBy: { receivedAt: "desc" },
      take: 25,
      include: { application: { select: { id: true, name: true, platform: true } } },
    }),
  ]);

  res.json({ applications, events });
});

dashboardRouter.get("/applications/:applicationId/events/:eventId", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const event = await prisma.securityEvent.findFirst({
    where: { id: req.params.eventId, applicationId: app.id },
  });
  if (!event) return res.status(404).json({ error: "EVENT_NOT_FOUND" });
  res.json({ event });
});
