import { Prisma } from "@prisma/client";
import type { RequestHandler, Response } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import type { AuthedRequest } from "../middleware/auth";
import { severityOf } from "../detectors/severity";

/**
 * GET /v1/dashboard/map-points — one point per device that SHARED its
 * location (events stored with `locationOptIn`, see ingestion/location.ts),
 * for the dashboard map. Only the caller's organization's non-archived
 * applications. Devices that never opted in have no coordinates stored and
 * never appear here.
 *
 * Query: `applicationId?`, `severity?` (low|medium|high), `range?`
 * (24h|7d|30d, default 7d). Response:
 *   { "points": [ { "deviceId": first 8 chars, "applicationId", "applicationName",
 *                   "latitude", "longitude", "severity": "low"|"medium"|"high",
 *                   "lastThreat": { "detectorId", "at" } | null, "at" } ] }
 * One point per device = its newest opted-in located event in range;
 * severity = the highest severity among the device's DETECTED events in
 * range (critical counts as high), "low" if none; newest first; at most 1000.
 */
export const MAP_POINTS_LIMIT = 1000;

export type MapSeverity = "low" | "medium" | "high";

export const RANGE_HOURS = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 } as const;

export const mapPointsQuerySchema = z.object({
  applicationId: z.string().min(1).max(100).optional(),
  severity: z.enum(["low", "medium", "high"]).optional(),
  range: z.enum(["24h", "7d", "30d"]).default("7d"),
});

export interface LocatedEventRow {
  applicationId: string;
  applicationName: string;
  deviceId: string;
  latitude: number;
  longitude: number;
  receivedAt: Date;
}

export interface DetectedEventRow {
  applicationId: string;
  deviceId: string;
  detectorId: string;
  receivedAt: Date;
}

export interface MapPoint {
  deviceId: string;
  applicationId: string;
  applicationName: string;
  latitude: number;
  longitude: number;
  severity: MapSeverity;
  lastThreat: { detectorId: string; at: string } | null;
  at: string;
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
  /** DETECTED events in scope (at least the newest per device and detector). */
  detectedEvents(scope: MapPointsScope): Promise<DetectedEventRow[]>;
}

const SEVERITY_RANK: Record<MapSeverity, number> = { low: 0, medium: 1, high: 2 };

/** Detector severity on the map's three-level scale: critical counts as high. */
export function mapSeverity(detectorId: string): MapSeverity {
  const severity = severityOf(detectorId);
  return severity === "critical" ? "high" : severity;
}

/** Builds the points. Pure. */
export function buildMapPoints(
  located: LocatedEventRow[],
  detected: DetectedEventRow[],
  severityFilter?: MapSeverity,
  limit = MAP_POINTS_LIMIT,
): MapPoint[] {
  const key = (applicationId: string, deviceId: string) => `${applicationId}\u0000${deviceId}`;
  const threats = new Map<string, { severity: MapSeverity; last: DetectedEventRow }>();
  for (const row of detected) {
    const k = key(row.applicationId, row.deviceId);
    const severity = mapSeverity(row.detectorId);
    const current = threats.get(k);
    if (!current) {
      threats.set(k, { severity, last: row });
      continue;
    }
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[current.severity]) current.severity = severity;
    if (row.receivedAt > current.last.receivedAt) current.last = row;
  }

  return located
    .filter((row) => Number.isFinite(row.latitude) && Number.isFinite(row.longitude))
    .map((row): MapPoint => {
      const threat = threats.get(key(row.applicationId, row.deviceId));
      return {
        deviceId: row.deviceId.slice(0, 8),
        applicationId: row.applicationId,
        applicationName: row.applicationName,
        latitude: row.latitude,
        longitude: row.longitude,
        severity: threat?.severity ?? "low",
        lastThreat: threat ? { detectorId: threat.last.detectorId, at: threat.last.receivedAt.toISOString() } : null,
        at: row.receivedAt.toISOString(),
      };
    })
    .filter((point) => !severityFilter || point.severity === severityFilter)
    .sort((a, b) => b.at.localeCompare(a.at))
    .slice(0, limit);
}

function appFilter(applicationId: string | undefined) {
  return applicationId ? Prisma.sql`AND e."applicationId" = ${applicationId}` : Prisma.empty;
}

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
        e.latitude, e.longitude, e."receivedAt"
      FROM security_events e
      JOIN applications a ON a.id = e."applicationId"
      WHERE a."organizationId" = ${organizationId}
        AND a."archivedAt" IS NULL
        AND e."locationOptIn" = true
        AND e.latitude IS NOT NULL AND e.longitude IS NOT NULL
        AND e."deviceId" IS NOT NULL
        AND e."receivedAt" >= ${since}
        ${appFilter(applicationId)}
      ORDER BY e."applicationId", e."deviceId", e."receivedAt" DESC
    `;
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
        ${appFilter(applicationId)}
      ORDER BY e."applicationId", e."deviceId", e."detectorId", e."receivedAt" DESC
    `;
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
    const organizationId = req.user!.organizationId;

    if (applicationId && !(await repo.findOwnedApplication(applicationId, organizationId))) {
      return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
    }
    const scope: MapPointsScope = {
      organizationId,
      applicationId,
      since: new Date(now() - RANGE_HOURS[range] * 60 * 60 * 1000),
    };
    const [located, detected] = await Promise.all([repo.latestLocatedPerDevice(scope), repo.detectedEvents(scope)]);
    res.json({ points: buildMapPoints(located, detected, severity) });
  };
}
