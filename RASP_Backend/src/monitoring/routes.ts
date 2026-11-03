import os from "node:os";
import { Router } from "express";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { isAdminRole, requireAdminRole } from "../auth/roles";
import { allowedOrigins } from "../security/origins";
import { publicIngestionUrl } from "../credentials/ingestionUrl";
import { configurationWarnings } from "../startupChecks";
import { CHECK_INTERVAL_MS, checkHistory, latestRun, runChecks } from "./healthMonitor";
import { deviceRouteStats, minuteBuckets, recentProblems } from "./problemLog";
import { prisma } from "../db/prisma";

/** A device counts as active when it reached the backend within this window. */
const ACTIVE_DEVICE_WINDOW_MS = 10 * 60_000;

const startedAt = new Date();
// eslint-disable-next-line @typescript-eslint/no-var-requires
const version: string = require("../../package.json").version;

/** Recently failing again within this many ms of a manual run is not re-run. */
const MANUAL_RUN_MIN_GAP_MS = 10_000;

/**
 * GET  /v1/system/status — everything the System Status page shows: the
 *      latest dependency checks and their last hour, per-minute traffic and
 *      error counts, recent problems, and configuration warnings. Any
 *      signed-in user; client IPs only for OWNER/ADMIN.
 * POST /v1/system/checks — run the checks now (OWNER/ADMIN).
 *
 * No secret is ever part of the answer: configuration is reported as
 * warnings and public URLs only.
 */
export const systemRouter = Router();
systemRouter.use(requireAuth);

systemRouter.get("/status", async (req: AuthedRequest, res) => {
  const run = latestRun() ?? (await runChecks());
  const admin = isAdminRole(req.user?.role);
  const traffic = minuteBuckets();
  const lastMinutes = (n: number) => traffic.slice(-n).reduce(
    (acc, b) => ({
      requests: acc.requests + b.requests,
      clientErrors: acc.clientErrors + b.clientErrors,
      serverErrors: acc.serverErrors + b.serverErrors,
      slow: acc.slow + b.slow,
    }),
    { requests: 0, clientErrors: 0, serverErrors: 0, slow: 0 },
  );

  res.json({
    generatedAt: new Date().toISOString(),
    checkIntervalSeconds: CHECK_INTERVAL_MS / 1000,
    server: {
      version,
      node: process.version,
      environment: process.env.NODE_ENV || "development",
      host: os.hostname(),
      startedAt: startedAt.toISOString(),
      uptimeSeconds: Math.round(process.uptime()),
      memoryMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
    },
    checks: run.results,
    checkedAt: run.at,
    checkHistory: checkHistory().map((r) => ({ at: r.at, failed: r.results.filter((c) => !c.ok).map((c) => c.id) })),
    configuration: {
      warnings: configurationWarnings(),
      corsOrigins: allowedOrigins(),
      dashboardUrl: process.env.DASHBOARD_URL?.trim() || null,
      visitorSiteUrl: process.env.VISITOR_SITE_URL?.trim() || null,
      ingestionUrl: publicIngestionUrl(),
    },
    traffic,
    summary: { last5Minutes: lastMinutes(5), last60Minutes: lastMinutes(60) },
    problems: recentProblems(200).map((p) => (admin ? p : { ...p, clientIp: undefined })),
    devices: {
      routes: deviceRouteStats(),
      organization: await organizationDeviceFacts(req.user!.organizationId),
    },
  });
});

/** When this organization's phones last reached the backend; null when the database cannot answer. */
async function organizationDeviceFacts(organizationId: string) {
  const app = { application: { organizationId } };
  const activeSince = new Date(Date.now() - ACTIVE_DEVICE_WINDOW_MS);
  try {
    const [lastEvent, lastHeartbeat, lastRegistration, activeDevices, registeredDevices] = await Promise.all([
      prisma.securityEvent.findFirst({ where: app, orderBy: { receivedAt: "desc" }, select: { receivedAt: true } }),
      prisma.deviceLocation.findFirst({ where: app, orderBy: { receivedAt: "desc" }, select: { receivedAt: true } }),
      prisma.deviceRegistration.findFirst({ where: app, orderBy: { lastSeenAt: "desc" }, select: { lastSeenAt: true } }),
      prisma.deviceRegistration.count({ where: { ...app, lastSeenAt: { gte: activeSince } } }),
      prisma.deviceRegistration.count({ where: app }),
    ]);
    return {
      lastEventAt: lastEvent?.receivedAt.toISOString() ?? null,
      lastHeartbeatAt: lastHeartbeat?.receivedAt.toISOString() ?? null,
      lastDeviceSeenAt: lastRegistration?.lastSeenAt.toISOString() ?? null,
      activeDevices,
      activeWindowMinutes: ACTIVE_DEVICE_WINDOW_MS / 60_000,
      registeredDevices,
    };
  } catch {
    return null;
  }
}

let lastManualRun = 0;
systemRouter.post("/checks", requireAdminRole, async (_req, res) => {
  const now = Date.now();
  const recent = now - lastManualRun < MANUAL_RUN_MIN_GAP_MS ? latestRun() : undefined;
  if (!recent) lastManualRun = now;
  const run = recent ?? (await runChecks());
  res.json({ checks: run.results, checkedAt: run.at });
});
