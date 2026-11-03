import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma";
import { recordEventForDashboard } from "../redis/dashboardCache";
import { maybeTriggerWebhook } from "../webhooks/dispatch";
import type { StoredAlert } from "../ingestion/tamperAlerts";
import type { RiskFinding } from "./rules";

/**
 * Every rule that fires becomes a stored `SecurityEvent` (detectorId = the
 * rule id, status DETECTED, reason = the explanation), so it shows up on
 * Live Threats, the device trail, analytics and exports, and goes through
 * the same dashboard cache and webhook path as SDK detections. Severity:
 * detectors/severity.ts. Evidence holds shortened hashes only.
 */
export interface RiskAlertSource {
  applicationId: string;
  /** The SecurityEvent deviceId: the registered device id, else the key id (as envelopes use). */
  deviceId: string;
  sdkVersion: string;
  eventType: "session" | "transaction";
  eventId: string;
  receivedAt: Date;
  findings: RiskFinding[];
}

export function riskAlertEvidence(source: RiskAlertSource, finding: RiskFinding) {
  return [
    ...Object.entries(finding.evidence).map(([key, value]) => ({ key, value, note: null })),
    { key: "event_type", value: source.eventType, note: null },
    { key: "risk_event_id", value: source.eventId, note: "eventId of the risk envelope" },
  ];
}

export interface RiskAlertDeps {
  findApplicationName(applicationId: string): Promise<string | null>;
  storeAlerts(source: RiskAlertSource): Promise<StoredAlert[]>;
  recordForDashboard: typeof recordEventForDashboard;
  triggerWebhook: typeof maybeTriggerWebhook;
}

export const prismaRiskAlertDeps: RiskAlertDeps = {
  async findApplicationName(applicationId) {
    const app = await prisma.application.findUnique({ where: { id: applicationId }, select: { name: true } });
    return app?.name ?? null;
  },
  async storeAlerts(source) {
    return prisma.securityEvent.createManyAndReturn({
      data: source.findings.map((finding) => ({
        applicationId: source.applicationId,
        detectorId: finding.rule,
        status: "DETECTED",
        reason: finding.explanation,
        evidence: riskAlertEvidence(source, finding) as unknown as Prisma.InputJsonValue,
        deviceId: source.deviceId,
        sdkVersion: source.sdkVersion,
        receivedAt: source.receivedAt,
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

/** Stores the findings as alerts, adds them to the dashboard cache, sends webhooks. */
export async function raiseRiskAlerts(source: RiskAlertSource, deps: RiskAlertDeps = prismaRiskAlertDeps): Promise<StoredAlert[]> {
  if (source.findings.length === 0) return [];
  const stored = await deps.storeAlerts(source);
  await Promise.all(stored.map((row) => deps.recordForDashboard(source.applicationId, {
    id: row.id, detectorId: row.detectorId, status: row.status, receivedAt: row.receivedAt.toISOString(),
  })));
  const name = await deps.findApplicationName(source.applicationId);
  if (name !== null) {
    for (const row of stored) await deps.triggerWebhook(source.applicationId, name, row);
  }
  return stored;
}
