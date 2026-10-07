import { Response } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import type { AuthedRequest } from "../middleware/auth";
import { shortHash } from "../risk/rules";

/**
 * Dashboard views of session / transaction risk events. Hashes leave the
 * backend shortened (first 12 hex characters) and coordinates not at all —
 * the dashboard shows that a location was shared, not where.
 */

export interface RiskEventRow {
  id: string;
  type: "session" | "transaction";
  deviceKeyId: string;
  accountHash: string;
  sessionHash: string;
  sessionEvent?: string;
  beneficiaryHash?: string;
  currency?: string;
  channel?: string;
  riskScore: number | null;
  riskVerdict: string;
  ipCountry: string | null;
  latitude: number | null;
  eventTime: Date;
  receivedAt: Date;
  riskEvents: unknown;
}

/** One row as the dashboard receives it. Pure. */
export function toDashboardRiskEvent(row: RiskEventRow) {
  const rules = Array.isArray(row.riskEvents)
    ? row.riskEvents
        .filter((f): f is { rule: string; severity: string; explanation: string } =>
          !!f && typeof f === "object" && typeof (f as { rule?: unknown }).rule === "string")
        .map((f) => ({ rule: f.rule, severity: String(f.severity), explanation: String(f.explanation) }))
    : [];
  return {
    id: row.id,
    type: row.type,
    deviceKeyId: shortHash(row.deviceKeyId),
    accountHash: shortHash(row.accountHash),
    sessionHash: shortHash(row.sessionHash),
    ...(row.sessionEvent !== undefined && { sessionEvent: row.sessionEvent }),
    ...(row.beneficiaryHash !== undefined && { beneficiaryHash: shortHash(row.beneficiaryHash) }),
    ...(row.currency !== undefined && { currency: row.currency }),
    ...(row.channel !== undefined && { channel: row.channel }),
    riskScore: row.riskScore,
    riskVerdict: row.riskVerdict,
    ipCountry: row.ipCountry,
    locationShared: row.latitude !== null,
    eventTime: row.eventTime.toISOString(),
    receivedAt: row.receivedAt.toISOString(),
    rules,
  };
}

const commonSelect = {
  id: true, deviceKeyId: true, accountHash: true, sessionHash: true, riskScore: true, riskVerdict: true,
  ipCountry: true, latitude: true, eventTime: true, receivedAt: true, riskEvents: true,
} as const;

async function recentRiskEvents(where: { applicationId: string; deviceKeyId?: { in: string[] } }, limit: number) {
  const [sessions, transactions] = await Promise.all([
    prisma.sessionEvent.findMany({
      where, orderBy: { receivedAt: "desc" }, take: limit, select: { ...commonSelect, sessionEvent: true },
    }),
    prisma.transactionEvent.findMany({
      where, orderBy: { receivedAt: "desc" }, take: limit,
      select: { ...commonSelect, beneficiaryHash: true, currency: true, channel: true },
    }),
  ]);
  return [
    ...sessions.map((s) => ({ ...s, type: "session" as const })),
    ...transactions.map((t) => ({ ...t, type: "transaction" as const })),
  ]
    .sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime())
    .slice(0, limit)
    .map(toDashboardRiskEvent);
}

const listQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  onlyFlagged: z.enum(["true", "false"]).optional(),
}).strict();

type OwnedApp = (applicationId: string, organizationId: string) => Promise<{ id: string } | null>;

/** GET .../risk-events — recent session and transaction risk events of the application. */
export function riskEventsHandler(assertOwnedApplication: OwnedApp) {
  return async (req: AuthedRequest, res: Response) => {
    const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
    if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
    const parsed = listQuery.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ error: "INVALID_QUERY" });
    const events = await recentRiskEvents({ applicationId: app.id }, parsed.data.limit);
    res.json({ events: parsed.data.onlyFlagged === "true" ? events.filter((e) => e.rules.length > 0) : events });
  };
}

const deviceQuery = z.object({
  deviceId: z.string().min(1).max(200),
  limit: z.coerce.number().int().min(1).max(100).default(20),
}).strict();

/**
 * GET .../device-risk?deviceId= — for the device drawer: how many accounts
 * (hashes) this device is bound to, and its recent risk events. `deviceId`
 * is the dashboard's device id: the registered device id, or the key id.
 * A query parameter, not a path segment: key ids are Base64 and may contain "/".
 */
export function deviceRiskHandler(assertOwnedApplication: OwnedApp) {
  return async (req: AuthedRequest, res: Response) => {
    const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
    if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
    const parsed = deviceQuery.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ error: "INVALID_QUERY" });
    const { deviceId, limit } = parsed.data;

    const keys = await prisma.deviceRegistration.findMany({
      where: { applicationId: app.id, OR: [{ deviceId }, { deviceKeyId: deviceId }] },
      select: { deviceKeyId: true },
      take: 20,
    });
    const keyIds = keys.map((k) => k.deviceKeyId);
    if (keyIds.length === 0) return res.json({ accountBindingCount: 0, events: [] });

    const [bindings, events] = await Promise.all([
      prisma.accountDeviceBinding.findMany({
        where: { applicationId: app.id, deviceKeyId: { in: keyIds } },
        select: { accountHash: true },
        distinct: ["accountHash"],
      }),
      recentRiskEvents({ applicationId: app.id, deviceKeyId: { in: keyIds } }, limit),
    ]);
    res.json({ accountBindingCount: bindings.length, events });
  };
}
