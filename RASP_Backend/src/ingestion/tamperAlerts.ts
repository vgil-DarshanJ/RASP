import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma";
import { recordEventForDashboard } from "../redis/dashboardCache";
import { maybeTriggerWebhook } from "../webhooks/dispatch";

/**
 * Signing-certificate tamper alerts.
 *
 * The SDK's `tamper` result carries the app's observed signing certificate
 * as evidence `signing_cert_sha256`. If the application has an expected
 * hash (set by an admin), or — for evidence envelopes — the device reported
 * one when it registered, and the observed hash differs, the backend raises
 * its own alert: a stored `SecurityEvent` with detectorId
 * "tamper_signing_mismatch", status DETECTED, which goes through the same
 * dashboard cache and webhook path as every DETECTED event (severity "high"
 * in detectors/severity.ts).
 */
export const TAMPER_ALERT_DETECTOR = "tamper_signing_mismatch";
export const TAMPER_ALERT_REASON = "signing certificate differs from the expected hash";

/** 64 hex characters, case-insensitive, ':' (and spaces) allowed → uppercase without separators; else null. */
export function normalizeCertHash(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const compact = value.replace(/[:\s]/g, "");
  return /^[0-9a-fA-F]{64}$/.test(compact) ? compact.toUpperCase() : null;
}

/** The `signing_cert_sha256` evidence value of one result, normalized; null when absent or malformed. */
export function observedCertHash(evidence: unknown): string | null {
  if (Array.isArray(evidence)) {
    for (const item of evidence) {
      if (item && typeof item === "object" && (item as { key?: unknown }).key === "signing_cert_sha256") {
        return normalizeCertHash((item as { value?: unknown }).value);
      }
    }
    return null;
  }
  if (evidence && typeof evidence === "object") {
    return normalizeCertHash((evidence as Record<string, unknown>).signing_cert_sha256);
  }
  return null;
}

export interface IngestedEvent {
  id: string;
  deviceId: string | null;
  deviceModel: string | null;
  osPlatform: string | null;
  evidence: unknown;
}

export interface TamperAlert {
  sourceEventId: string;
  deviceId: string | null;
  deviceModel: string | null;
  osPlatform: string | null;
  observed: string;
  expected: string;
  expectedSource: "application" | "device_registration";
}

/**
 * One alert per device and observed hash in a batch, for every event whose
 * `signing_cert_sha256` differs from the expected hash: the application's
 * when set, else the registering device's. No expected hash → no alerts.
 */
export function tamperAlertsFor(
  events: IngestedEvent[],
  expectedForApplication: string | null | undefined,
  expectedFromDevice: string | null | undefined,
): TamperAlert[] {
  const appHash = normalizeCertHash(expectedForApplication);
  const deviceHash = normalizeCertHash(expectedFromDevice);
  const expected = appHash ?? deviceHash;
  if (!expected) return [];
  const expectedSource = appHash ? "application" : "device_registration";

  const alerts: TamperAlert[] = [];
  const seen = new Set<string>();
  for (const event of events) {
    const observed = observedCertHash(event.evidence);
    if (!observed || observed === expected) continue;
    const key = `${event.deviceId ?? ""}|${observed}`;
    if (seen.has(key)) continue;
    seen.add(key);
    alerts.push({
      sourceEventId: event.id,
      deviceId: event.deviceId,
      deviceModel: event.deviceModel,
      osPlatform: event.osPlatform,
      observed,
      expected,
      expectedSource,
    });
  }
  return alerts;
}

export function alertEvidence(alert: TamperAlert) {
  return [
    { key: "observed_signing_cert_sha256", value: alert.observed, note: null },
    { key: "expected_signing_cert_sha256", value: alert.expected, note: alert.expectedSource },
    { key: "source_event_id", value: alert.sourceEventId, note: null },
  ];
}

export interface StoredAlert {
  id: string;
  detectorId: string;
  status: string;
  deviceId: string | null;
  deviceModel: string | null;
  osPlatform: string | null;
  receivedAt: Date;
  evidence: unknown;
}

export interface TamperAlertDeps {
  /** The application's name and expected hash; null when not found. */
  findApplication(applicationId: string): Promise<{ name: string; expectedSigningCertSha256: string | null } | null>;
  storeAlerts(applicationId: string, alerts: TamperAlert[], receivedAt: Date, ipAddress?: string): Promise<StoredAlert[]>;
  recordForDashboard: typeof recordEventForDashboard;
  triggerWebhook: typeof maybeTriggerWebhook;
}

export const prismaTamperAlertDeps: TamperAlertDeps = {
  async findApplication(applicationId) {
    return prisma.application.findUnique({
      where: { id: applicationId },
      select: { name: true, expectedSigningCertSha256: true },
    });
  },
  async storeAlerts(applicationId, alerts, receivedAt, ipAddress) {
    return prisma.securityEvent.createManyAndReturn({
      data: alerts.map((alert) => ({
        applicationId,
        detectorId: TAMPER_ALERT_DETECTOR,
        status: "DETECTED",
        reason: TAMPER_ALERT_REASON,
        evidence: alertEvidence(alert) as unknown as Prisma.InputJsonValue,
        deviceId: alert.deviceId,
        deviceModel: alert.deviceModel,
        osPlatform: alert.osPlatform,
        receivedAt,
        ipAddress,
      })),
      select: {
        id: true, detectorId: true, status: true, deviceId: true,
        deviceModel: true, osPlatform: true, receivedAt: true, evidence: true,
      },
    });
  },
  recordForDashboard: recordEventForDashboard,
  triggerWebhook: maybeTriggerWebhook,
};

/**
 * Raises the alerts for one ingested batch: stores them, adds them to the
 * dashboard cache and sends them through the webhook path. Returns the
 * stored alert rows (empty when nothing differed or nothing is expected).
 */
export async function raiseTamperAlerts(args: {
  applicationId: string;
  events: IngestedEvent[];
  deviceSigningCertSha256?: string | null;
  ipAddress?: string;
  now: Date;
  deps?: TamperAlertDeps;
}): Promise<StoredAlert[]> {
  const deps = args.deps ?? prismaTamperAlertDeps;
  if (!args.events.some((e) => observedCertHash(e.evidence))) return [];
  const app = await deps.findApplication(args.applicationId);
  if (!app) return [];
  const alerts = tamperAlertsFor(args.events, app.expectedSigningCertSha256, args.deviceSigningCertSha256);
  if (alerts.length === 0) return [];

  const stored = await deps.storeAlerts(args.applicationId, alerts, args.now, args.ipAddress);
  await Promise.all(stored.map((row) => deps.recordForDashboard(args.applicationId, {
    id: row.id, detectorId: row.detectorId, status: row.status, receivedAt: row.receivedAt.toISOString(),
  })));
  for (const row of stored) {
    await deps.triggerWebhook(args.applicationId, app.name, row);
  }
  return stored;
}
