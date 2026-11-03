import { Prisma } from "@prisma/client";
import type { RequestHandler, Response } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import type { AuthedRequest } from "../middleware/auth";
import { severityOf } from "../detectors/severity";

/**
 * GET /v1/dashboard/map-points — one point per device that SHARED its
 * location, for the dashboard map. Only the caller's organization's
 * non-archived applications. Coordinates are stored only for devices whose
 * user opted in (see ingestion/location.ts); other devices never appear.
 *
 * A device's location is the newer of:
 * - its latest location heartbeat (device_locations, Task 9.3), sent every
 *   minute while sharing is on; a heartbeat sent when sharing was turned off
 *   hides the device until it shares again;
 * - its newest opted-in located security event (SDKs without heartbeats).
 *
 * Query: `applicationId?`, `severity?` (none|low|medium|high; default all),
 * `range?` (24h|7d|30d, default 24h), `trail?` (true|false, default false).
 * Response:
 *   { "points": [ { "deviceId": first 8 chars, "applicationId", "applicationName",
 *                   "latitude", "longitude", "accuracyM", "isMock",
 *                   "source": "heartbeat" | "event",
 *                   "severity": "none" | "low" | "medium" | "high",
 *                   "lastThreat": { "detectorId", "at" } | null,
 *                   "at": when this location was received,
 *                   "lastSeenAt": the device's newest heartbeat or event,
 *                   "stale": the location is older than 10 minutes,
 *                   "trail"?: [ { "latitude", "longitude", "at" } ] } ],  // oldest first, with trail=true
 *     "summary": { "devicesReporting", "devicesWithLocation" },
 *     "staleAfterMinutes": 10 }
 * severity = the highest severity among the device's DETECTED events in
 * range (critical counts as high), "none" without any; newest location
 * first; at most 1000 points. `summary` ignores the severity filter: the
 * devices heard from in range and how many of them shared a location — so
 * the map can say why it is empty.
 */
export const MAP_POINTS_LIMIT = 1000;
export const STALE_AFTER_MINUTES = 10;
const STALE_AFTER_MS = STALE_AFTER_MINUTES * 60 * 1000;

export type ThreatSeverity = "low" | "medium" | "high";
export type MapSeverity = "none" | ThreatSeverity;

export const RANGE_HOURS = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 } as const;

export const mapPointsQuerySchema = z.object({
  applicationId: z.string().min(1).max(100).optional(),
  severity: z.enum(["none", "low", "medium", "high"]).optional(),
  range: z.enum(["24h", "7d", "30d"]).default("24h"),
  trail: z.enum(["true", "false"]).default("false"),
});

export interface DeviceKey {
  applicationId: string;
  deviceId: string;
}

export interface LocatedEventRow extends DeviceKey {
  applicationName: string;
  latitude: number;
  longitude: number;
  accuracyM?: number | null;
  receivedAt: Date;
}

/** A device's device_locations row; coordinates null after sharing was turned off. */
export interface HeartbeatLocationRow extends DeviceKey {
  applicationName: string;
  latitude: number | null;
  longitude: number | null;
  accuracyM: number | null;
  isMock: boolean | null;
  receivedAt: Date;
}

export interface DetectedEventRow extends DeviceKey {
  detectorId: string;
  receivedAt: Date;
}

/** Newest event (any status) of a device. */
export interface LastEventRow extends DeviceKey {
  receivedAt: Date;
}

export interface TrailPointRow extends DeviceKey {
  latitude: number;
  longitude: number;
  receivedAt: Date;
}

export interface MapPoint {
  deviceId: string;
  applicationId: string;
  applicationName: string;
  latitude: number;
  longitude: number;
  accuracyM: number | null;
  isMock: boolean | null;
  source: "heartbeat" | "event";
  severity: MapSeverity;
  lastThreat: { detectorId: string; at: string } | null;
  at: string;
  lastSeenAt: string;
  stale: boolean;
  trail?: { latitude: number; longitude: number; at: string }[];
}

export interface MapPointsScope {
  organizationId: string;
  applicationId?: string;
  since: Date;
}

/** Data access for the map. Production: [prismaMapPointsRepository]. */
export interface MapPointsRepository {
  /** The application when it belongs to the organization and is not archived. */
  findOwnedApplication(applicationId: string, organizationId: string): Promise<{ id: string } | null>;
  /** Newest opted-in, located event per (application, device) in scope. */
  latestLocatedPerDevice(scope: MapPointsScope): Promise<LocatedEventRow[]>;
  /** device_locations rows in scope (one per device), cleared ones included. */
  heartbeatLocations(scope: MapPointsScope): Promise<HeartbeatLocationRow[]>;
  /** DETECTED events in scope (at least the newest per device and detector). */
  detectedEvents(scope: MapPointsScope): Promise<DetectedEventRow[]>;
  /** Newest event time in scope for each of [devices] that has one. */
  lastEventAt(scope: MapPointsScope, devices: DeviceKey[]): Promise<LastEventRow[]>;
  /** Trail points in scope for [devices]. */
  trailPoints(scope: MapPointsScope, devices: DeviceKey[]): Promise<TrailPointRow[]>;
  /** Devices in scope the backend heard from: events or heartbeats. */
  countReportingDevices(scope: MapPointsScope): Promise<number>;
}

const SEVERITY_RANK: Record<MapSeverity, number> = { none: -1, low: 0, medium: 1, high: 2 };

/** Detector severity on the map's three-level scale: critical counts as high. */
export function mapSeverity(detectorId: string): ThreatSeverity {
  const severity = severityOf(detectorId);
  return severity === "critical" ? "high" : severity;
}

const keyOf = (row: DeviceKey) => `${row.applicationId}\u0000${row.deviceId}`;
const later = (a: Date, b: Date | undefined) => (b && b > a ? b : a);

interface ChosenLocation extends DeviceKey {
  applicationName: string;
  latitude: number;
  longitude: number;
  accuracyM: number | null;
  isMock: boolean | null;
  source: "heartbeat" | "event";
  at: Date;
}

const usable = (lat: number | null, lon: number | null): boolean =>
  lat !== null && lon !== null && Number.isFinite(lat) && Number.isFinite(lon);

/**
 * Each device's location: the newer of its heartbeat row and its newest
 * located event. A newer heartbeat with no coordinates (sharing turned off)
 * means no location. Pure.
 */
export function chooseLocations(located: LocatedEventRow[], heartbeats: HeartbeatLocationRow[]): ChosenLocation[] {
  const chosen = new Map<string, ChosenLocation | null>();
  const at = new Map<string, Date>();
  const offer = (key: string, receivedAt: Date, location: ChosenLocation | null) => {
    const current = at.get(key);
    if (current && current >= receivedAt) return;
    at.set(key, receivedAt);
    chosen.set(key, location);
  };
  for (const h of heartbeats) {
    offer(keyOf(h), h.receivedAt, usable(h.latitude, h.longitude)
      ? {
        applicationId: h.applicationId, applicationName: h.applicationName, deviceId: h.deviceId,
        latitude: h.latitude!, longitude: h.longitude!, accuracyM: h.accuracyM, isMock: h.isMock,
        source: "heartbeat", at: h.receivedAt,
      }
      : null);
  }
  for (const e of located) {
    if (!usable(e.latitude, e.longitude)) continue;
    offer(keyOf(e), e.receivedAt, {
      applicationId: e.applicationId, applicationName: e.applicationName, deviceId: e.deviceId,
      latitude: e.latitude, longitude: e.longitude, accuracyM: e.accuracyM ?? null, isMock: null,
      source: "event", at: e.receivedAt,
    });
  }
  return [...chosen.values()].filter((c): c is ChosenLocation => c !== null);
}

export interface MapPointsInput {
  located: LocatedEventRow[];
  heartbeats: HeartbeatLocationRow[];
  detected: DetectedEventRow[];
  lastEvents: LastEventRow[];
  trail: TrailPointRow[];
  now: number;
}

/** Builds the points. Pure. */
export function buildMapPoints(
  input: MapPointsInput,
  options: { severity?: MapSeverity; includeTrail?: boolean; limit?: number } = {},
): { points: MapPoint[]; devicesWithLocation: number } {
  const { severity: severityFilter, includeTrail = false, limit = MAP_POINTS_LIMIT } = options;

  const threats = new Map<string, { severity: ThreatSeverity; last: DetectedEventRow }>();
  for (const row of input.detected) {
    const k = keyOf(row);
    const severity = mapSeverity(row.detectorId);
    const current = threats.get(k);
    if (!current) {
      threats.set(k, { severity, last: row });
      continue;
    }
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[current.severity]) current.severity = severity;
    if (row.receivedAt > current.last.receivedAt) current.last = row;
  }
  const heartbeatAt = new Map(input.heartbeats.map((h) => [keyOf(h), h.receivedAt]));
  const lastEventAt = new Map(input.lastEvents.map((e) => [keyOf(e), e.receivedAt]));
  const trails = new Map<string, TrailPointRow[]>();
  for (const p of input.trail) {
    const k = keyOf(p);
    trails.set(k, [...(trails.get(k) ?? []), p]);
  }

  const locations = chooseLocations(input.located, input.heartbeats);
  const points = locations
    .map((location): MapPoint => {
      const k = keyOf(location);
      const threat = threats.get(k);
      const lastSeen = [heartbeatAt.get(k), lastEventAt.get(k), threat?.last.receivedAt]
        .reduce<Date>((max, value) => later(max, value), location.at);
      const point: MapPoint = {
        deviceId: location.deviceId.slice(0, 8),
        applicationId: location.applicationId,
        applicationName: location.applicationName,
        latitude: location.latitude,
        longitude: location.longitude,
        accuracyM: location.accuracyM,
        isMock: location.isMock,
        source: location.source,
        severity: threat?.severity ?? "none",
        lastThreat: threat ? { detectorId: threat.last.detectorId, at: threat.last.receivedAt.toISOString() } : null,
        at: location.at.toISOString(),
        lastSeenAt: lastSeen.toISOString(),
        stale: input.now - location.at.getTime() > STALE_AFTER_MS,
      };
      if (includeTrail) {
        point.trail = (trails.get(k) ?? [])
          .slice()
          .sort((a, b) => a.receivedAt.getTime() - b.receivedAt.getTime())
          .map((p) => ({ latitude: p.latitude, longitude: p.longitude, at: p.receivedAt.toISOString() }));
      }
      return point;
    })
    .filter((point) => !severityFilter || point.severity === severityFilter)
    .sort((a, b) => b.at.localeCompare(a.at))
    .slice(0, limit);
  return { points, devicesWithLocation: locations.length };
}

/** `AND <alias>."applicationId" = …` when one application is selected. */
function appFilter(alias: "e" | "l", applicationId: string | undefined) {
  return applicationId ? Prisma.sql`AND ${Prisma.raw(alias)}."applicationId" = ${applicationId}` : Prisma.empty;
}

/** Prisma `where` for the location tables: same organization / archive / range / application scoping as the SQL. */
function locationWhere({ organizationId, applicationId, since }: MapPointsScope) {
  return {
    application: { organizationId, archivedAt: null },
    receivedAt: { gte: since },
    ...(applicationId ? { applicationId } : {}),
  };
}

const devicesWhere = (devices: DeviceKey[]) =>
  devices.map(({ applicationId, deviceId }) => ({ applicationId, deviceId }));

export const prismaMapPointsRepository: MapPointsRepository = {
  async findOwnedApplication(applicationId, organizationId) {
    return prisma.application.findFirst({
      where: { id: applicationId, organizationId, archivedAt: null },
      select: { id: true },
    });
  },

  async latestLocatedPerDevice({ organizationId, applicationId, since }) {
    return prisma.$queryRaw<LocatedEventRow[]>`
      SELECT DISTINCT ON (e."applicationId", e."deviceId")
        e."applicationId", a.name AS "applicationName", e."deviceId",
        e.latitude, e.longitude, e."locationAccuracyM" AS "accuracyM", e."receivedAt"
      FROM security_events e
      JOIN applications a ON a.id = e."applicationId"
      WHERE a."organizationId" = ${organizationId}
        AND a."archivedAt" IS NULL
        AND e."locationOptIn" = true
        AND e.latitude IS NOT NULL AND e.longitude IS NOT NULL
        AND e."deviceId" IS NOT NULL
        AND e."receivedAt" >= ${since}
        ${appFilter("e", applicationId)}
      ORDER BY e."applicationId", e."deviceId", e."receivedAt" DESC
    `;
  },

  async heartbeatLocations(scope) {
    const rows = await prisma.deviceLocation.findMany({
      where: locationWhere(scope),
      select: {
        applicationId: true, deviceId: true, latitude: true, longitude: true, accuracyM: true, isMock: true, receivedAt: true,
        application: { select: { name: true } },
      },
    });
    return rows.map(({ application, ...row }) => ({ ...row, applicationName: application.name }));
  },

  async detectedEvents({ organizationId, applicationId, since }) {
    return prisma.$queryRaw<DetectedEventRow[]>`
      SELECT DISTINCT ON (e."applicationId", e."deviceId", e."detectorId")
        e."applicationId", e."deviceId", e."detectorId", e."receivedAt"
      FROM security_events e
      JOIN applications a ON a.id = e."applicationId"
      WHERE a."organizationId" = ${organizationId}
        AND a."archivedAt" IS NULL
        AND e.status = 'DETECTED'
        AND e."deviceId" IS NOT NULL
        AND e."receivedAt" >= ${since}
        ${appFilter("e", applicationId)}
      ORDER BY e."applicationId", e."deviceId", e."detectorId", e."receivedAt" DESC
    `;
  },

  async lastEventAt(scope, devices) {
    if (devices.length === 0) return [];
    const groups = await prisma.securityEvent.groupBy({
      by: ["applicationId", "deviceId"],
      where: { ...locationWhere(scope), OR: devicesWhere(devices) },
      _max: { receivedAt: true },
    });
    return groups.flatMap((g) =>
      g.deviceId && g._max.receivedAt ? [{ applicationId: g.applicationId, deviceId: g.deviceId, receivedAt: g._max.receivedAt }] : []);
  },

  async trailPoints(scope, devices) {
    if (devices.length === 0) return [];
    return prisma.deviceLocationPoint.findMany({
      where: { ...locationWhere(scope), OR: devicesWhere(devices) },
      orderBy: { receivedAt: "asc" },
      select: { applicationId: true, deviceId: true, latitude: true, longitude: true, receivedAt: true },
    });
  },

  async countReportingDevices({ organizationId, applicationId, since }) {
    const rows = await prisma.$queryRaw<{ count: number }[]>`
      SELECT COUNT(*)::int AS count FROM (
        SELECT e."applicationId", e."deviceId"
        FROM security_events e
        JOIN applications a ON a.id = e."applicationId"
        WHERE a."organizationId" = ${organizationId}
          AND a."archivedAt" IS NULL
          AND e."deviceId" IS NOT NULL
          AND e."receivedAt" >= ${since}
          ${appFilter("e", applicationId)}
        UNION
        SELECT l."applicationId", l."deviceId"
        FROM device_locations l
        JOIN applications a ON a.id = l."applicationId"
        WHERE a."organizationId" = ${organizationId}
          AND a."archivedAt" IS NULL
          AND l."receivedAt" >= ${since}
          ${appFilter("l", applicationId)}
      ) AS reporting
    `;
    return Number(rows[0]?.count ?? 0);
  },
};

/** The route handler; mounted on the (authenticated) dashboard router. */
export function mapPointsHandler(
  repo: MapPointsRepository = prismaMapPointsRepository,
  now: () => number = Date.now,
): RequestHandler {
  return async (req: AuthedRequest, res: Response) => {
    const parsed = mapPointsQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ error: "INVALID_QUERY", details: parsed.error.flatten() });
    const { applicationId, severity, range } = parsed.data;
    const includeTrail = parsed.data.trail === "true";
    const organizationId = req.user!.organizationId;

    if (applicationId && !(await repo.findOwnedApplication(applicationId, organizationId))) {
      return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
    }
    const at = now();
    const scope: MapPointsScope = { organizationId, applicationId, since: new Date(at - RANGE_HOURS[range] * 60 * 60 * 1000) };
    const [located, heartbeats, detected, devicesReporting] = await Promise.all([
      repo.latestLocatedPerDevice(scope),
      repo.heartbeatLocations(scope),
      repo.detectedEvents(scope),
      repo.countReportingDevices(scope),
    ]);
    const devices = chooseLocations(located, heartbeats).map(({ applicationId, deviceId }) => ({ applicationId, deviceId }));
    const [lastEvents, trail] = await Promise.all([
      repo.lastEventAt(scope, devices),
      includeTrail ? repo.trailPoints(scope, devices) : Promise.resolve([]),
    ]);
    const { points, devicesWithLocation } = buildMapPoints(
      { located, heartbeats, detected, lastEvents, trail, now: at },
      { severity, includeTrail },
    );
    res.json({
      points,
      summary: { devicesReporting: Math.max(devicesReporting, devicesWithLocation), devicesWithLocation },
      staleAfterMinutes: STALE_AFTER_MINUTES,
    });
  };
}
