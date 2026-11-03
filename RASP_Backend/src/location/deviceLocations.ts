import { prisma } from "../db/prisma";
import { extractLocation, StoredLocation } from "../ingestion/location";

/**
 * Location heartbeats (Task 9.3). While the user shares location, the SDK
 * sends a `location_heartbeat` result every minute and on the first fix;
 * when sharing is turned off it sends one with `location_opt_in: false`.
 * They are not security events: they update the device's latest point
 * (DeviceLocation, one row per device) and a short trail
 * (DeviceLocationPoint: at most TRAIL_MAX_POINTS per device, none older than
 * TRAIL_RETENTION_DAYS). Coordinates are stored only with opt-in.
 */
export const LOCATION_HEARTBEAT_ID = "location_heartbeat";
export const TRAIL_MAX_POINTS = 20;
export const TRAIL_RETENTION_DAYS = 7;
/** A heartbeat (envelope time) older than this is rejected: a location is only useful fresh. */
export const HEARTBEAT_MAX_AGE_MS = 5 * 60 * 1000;

export interface LocationHeartbeatInput {
  applicationId: string;
  deviceId: string;
  /** Envelope counter (must exceed the device's last accepted one); null on the HMAC path (replay guard). */
  counter: bigint | null;
  /** null = sharing turned off (or no usable coordinates): clear the stored point and trail. */
  location: StoredLocation | null;
  isMock: boolean | null;
  receivedAt: Date;
}

export type LocationRecordOutcome = "updated" | "cleared" | "counter_not_increasing";

export interface DeviceLocationRepository {
  record(input: LocationHeartbeatInput): Promise<LocationRecordOutcome>;
}

/**
 * What a heartbeat result's evidence asks for. Pure.
 * - `point`: opted in with valid coordinates → store them;
 * - `clear`: no opt-in (sharing off, or coordinates without opt-in) → delete the stored point and trail;
 * - `invalid`: opted in but unusable coordinates → ignore.
 */
export function heartbeatLocation(evidence: unknown):
  | { kind: "point"; location: StoredLocation; isMock: boolean | null }
  | { kind: "clear" }
  | { kind: "invalid" } {
  const extraction = extractLocation(evidence);
  if (!extraction.optIn) return { kind: "clear" };
  if (!extraction.location) return { kind: "invalid" };
  let isMock: boolean | null = null;
  if (Array.isArray(evidence)) {
    const entry = evidence.find((e) => e && typeof e === "object" && (e as { key?: unknown }).key === "location_is_mock");
    const value = (entry as { value?: unknown } | undefined)?.value;
    if (typeof value === "boolean") isMock = value;
  }
  return { kind: "point", location: extraction.location, isMock };
}

/** Splits heartbeat results from detector results (heartbeats are never stored as security events). */
export function splitHeartbeats<T extends { detectorId: string }>(results: T[]): { heartbeats: T[]; others: T[] } {
  return {
    heartbeats: results.filter((r) => r.detectorId === LOCATION_HEARTBEAT_ID),
    others: results.filter((r) => r.detectorId !== LOCATION_HEARTBEAT_ID),
  };
}

export const prismaDeviceLocationRepository: DeviceLocationRepository = {
  async record(input) {
    const { applicationId, deviceId, counter, location, isMock, receivedAt } = input;
    return prisma.$transaction(async (tx) => {
      const key = { applicationId_deviceId: { applicationId, deviceId } };
      const existing = await tx.deviceLocation.findUnique({ where: key, select: { lastCounter: true } });
      if (counter !== null && existing && existing.lastCounter >= counter) return "counter_not_increasing" as const;
      const counterUpdate = counter !== null ? { lastCounter: counter } : {};

      if (!location) {
        await tx.deviceLocation.upsert({
          where: key,
          create: { applicationId, deviceId, receivedAt, ...counterUpdate },
          update: { latitude: null, longitude: null, accuracyM: null, isMock: null, capturedAt: null, receivedAt, ...counterUpdate },
        });
        await tx.deviceLocationPoint.deleteMany({ where: { applicationId, deviceId } });
        return "cleared" as const;
      }

      const point = { latitude: location.latitude, longitude: location.longitude, accuracyM: location.accuracyM };
      await tx.deviceLocation.upsert({
        where: key,
        create: { applicationId, deviceId, ...point, isMock, capturedAt: location.capturedAt, receivedAt, ...counterUpdate },
        update: { ...point, isMock, capturedAt: location.capturedAt, receivedAt, ...counterUpdate },
      });
      await tx.deviceLocationPoint.create({ data: { applicationId, deviceId, ...point, receivedAt } });
      // Retention: nothing older than TRAIL_RETENTION_DAYS, at most TRAIL_MAX_POINTS.
      const cutoff = new Date(receivedAt.getTime() - TRAIL_RETENTION_DAYS * 24 * 60 * 60 * 1000);
      await tx.deviceLocationPoint.deleteMany({ where: { applicationId, deviceId, receivedAt: { lt: cutoff } } });
      const surplus = await tx.deviceLocationPoint.findMany({
        where: { applicationId, deviceId },
        orderBy: { receivedAt: "desc" },
        skip: TRAIL_MAX_POINTS,
        select: { id: true },
      });
      if (surplus.length > 0) await tx.deviceLocationPoint.deleteMany({ where: { id: { in: surplus.map((p) => p.id) } } });
      return "updated" as const;
    });
  },
};
