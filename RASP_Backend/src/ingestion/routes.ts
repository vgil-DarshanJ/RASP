import { NextFunction, Response, Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { ApiKeyedRequest, requireApiKey, requireApiKeyIdentity } from "../middleware/apiKey";
import { recordEventForDashboard } from "../redis/dashboardCache";
import { deviceRateLimiter } from "../redis/deviceRateLimit";
import { maybeTriggerWebhook } from "../webhooks/dispatch";
import { isEnvelopeBody, processEnvelope } from "./envelope";
import { prismaEnvelopeRepository } from "./envelopeRepository";
import { extractLocation, locationColumns } from "./location";
import { raiseTamperAlerts } from "./tamperAlerts";
import { heartbeatLocation, prismaDeviceLocationRepository, splitHeartbeats } from "../location/deviceLocations";

/** Runs after the response: never affects the stored events or the status sent. */
function raiseTamperAlertsInBackground(args: Parameters<typeof raiseTamperAlerts>[0]) {
  void raiseTamperAlerts(args).catch((err) => console.error("[tamperAlerts] failed (non-fatal):", err));
}

export const ingestionRouter = Router();

/**
 * Per app + device rate limit, BEFORE the (more expensive) DB lookup and
 * signature checks — see `deviceRateLimiter`. Each device of an app gets
 * INGESTION_RATE_LIMIT_PER_WINDOW requests per window (it was one budget
 * shared by every device of the app).
 */
const rateLimitIngestion = deviceRateLimiter({
  scope: "ingest",
  limitEnv: "INGESTION_RATE_LIMIT_PER_WINDOW",
  windowEnv: "INGESTION_RATE_LIMIT_WINDOW_SECONDS",
  defaultLimit: 60,
  apiKeyLimitEnv: "INGESTION_RATE_LIMIT_PER_API_KEY",
  defaultApiKeyLimit: 6000,
  ipLimitEnv: "INGESTION_RATE_LIMIT_PER_IP",
  defaultIpLimit: 1200,
  defaultWindowSeconds: 60,
});

/**
 * Evidence envelopes authenticate with a registered device key's signature
 * (checked in `processEnvelope`), so they need only the API key to identify
 * the application. Every other body keeps the full HMAC check.
 */
function authenticateIngestion(req: ApiKeyedRequest, res: Response, next: NextFunction) {
  return isEnvelopeBody(req.body)
    ? requireApiKeyIdentity(req, res, next)
    : requireApiKey(req, res, next);
}

ingestionRouter.use(rateLimitIngestion);
ingestionRouter.use(authenticateIngestion);

/**
 * Legacy event schema (HMAC-signed batches) — mirrors `RaspCheckResult`/`RaspCheckStatus`
 * from `android_core`.
 */
/** `applications.legacyIngestionEnabled`; tests replace `allowed`. */
export const legacyIngestion: { allowed: (applicationId: string) => Promise<boolean> } = {
  allowed: async (applicationId) =>
    (await prisma.application.findUnique({ where: { id: applicationId }, select: { legacyIngestionEnabled: true } }))
      ?.legacyIngestionEnabled ?? false,
};

function legacyIngestionAllowed(applicationId: string): Promise<boolean> {
  return legacyIngestion.allowed(applicationId);
}

const legacyEventSchema = z.object({
  detectorId: z.string().min(1).max(100),
  status: z.enum(["SECURE", "DETECTED", "UNAVAILABLE", "UNKNOWN", "ERROR"]),
  evidence: z.unknown().optional(),
  reason: z.string().max(2000).optional(),

  // Device/app identity — the audit trail's "who and what."
  deviceId: z.string().max(200).optional(),
  deviceModel: z.string().max(200).optional(),
  manufacturer: z.string().max(200).optional(),
  osPlatform: z.enum(["android", "ios"]).optional(),
  osVersion: z.string().max(50).optional(),
  appVersion: z.string().max(50).optional(),
  sdkVersion: z.string().max(50).optional(),

  /** Advisory only — the device's own clock. `receivedAt` (server time) is
   *  what every query/chart actually orders by; see the schema's own doc. */
  observedAt: z.string().datetime().optional(),
});

const legacyBatchSchema = z.object({
  events: z.array(legacyEventSchema).min(1).max(200),
});

/**
 * `POST /v1/events` — handles both legacy HMAC batches and Evidence Envelopes.
 *
 * Envelope path: see `processEnvelope` in `./envelope.ts` for the
 * verification and replay rules. Legacy path: unchanged.
 */
ingestionRouter.post("/", async (req: ApiKeyedRequest, res) => {
  const applicationId = req.applicationId!;
  const ipAddress = req.ip;
  const rawBody = req.rawBody ?? Buffer.alloc(0);
  const rawBodyStr = rawBody.toString("utf8");

  // Evidence Envelope path
  if (isEnvelopeBody(req.body)) {
    const outcome = await processEnvelope({
      rawBody: rawBodyStr,
      applicationId,
      ipAddress,
      now: Date.now(),
      repo: prismaEnvelopeRepository,
      locations: prismaDeviceLocationRepository,
    });
    const created = outcome.created ?? [];

    // Same order as the legacy path: dashboard cache, then respond, then webhooks.
    await Promise.all(
      created.map((row) =>
        recordEventForDashboard(applicationId, {
          id: row.id,
          detectorId: row.detectorId,
          status: row.status,
          receivedAt: row.receivedAt.toISOString(),
        })
      )
    );

    res.status(outcome.status).json(outcome.body);

    raiseTamperAlertsInBackground({
      applicationId,
      events: created,
      deviceSigningCertSha256: outcome.deviceSigningCertSha256,
      ipAddress,
      now: new Date(),
    });

    const detected = created.filter((row) => row.status === "DETECTED");
    if (detected.length > 0) {
      const app = await prisma.application.findUnique({
        where: { id: applicationId },
        select: { name: true },
      });
      if (app) {
        for (const row of detected) {
          void maybeTriggerWebhook(applicationId, app.name, {
            detectorId: row.detectorId,
            status: row.status,
            deviceId: row.deviceId,
            deviceModel: row.deviceModel,
            osPlatform: row.osPlatform,
            receivedAt: row.receivedAt,
            evidence: row.evidence,
          });
        }
      }
    }
    return;
  }

  // Legacy HMAC batches carry no device key: anyone holding the app's API
  // secret could send them (F-14). Applications created since 2026-10-09
  // accept signed envelopes only, unless an OWNER/ADMIN turns this back on.
  if (!(await legacyIngestionAllowed(applicationId))) {
    return res.status(403).json({ error: "LEGACY_INGESTION_DISABLED" });
  }

  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(rawBodyStr);
  } catch {
    return res.status(400).json({ error: "INVALID_JSON" });
  }

  // Legacy HMAC batch path
  const parsed = legacyBatchSchema.safeParse(parsedBody);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_EVENT_BATCH", details: parsed.error.flatten() });
  }

  // Location heartbeats (Task 9.3) update the device's latest location; they
  // are not security events. Replay protection on this path: the HMAC
  // signature replay guard (requireApiKey).
  const { heartbeats, others } = splitHeartbeats(parsed.data.events);
  let locationOutcome: string | undefined;
  for (const heartbeat of heartbeats) {
    if (!heartbeat.deviceId) continue;
    const decision = heartbeatLocation(heartbeat.evidence);
    if (decision.kind === "invalid") continue;
    locationOutcome = await prismaDeviceLocationRepository.record({
      applicationId,
      deviceId: heartbeat.deviceId,
      counter: null,
      location: decision.kind === "point" ? decision.location : null,
      isMock: decision.kind === "point" ? decision.isMock : null,
      receivedAt: new Date(),
    });
  }
  if (others.length === 0) {
    return res.status(202).json({ accepted: 0, ...(locationOutcome ? { location: locationOutcome } : {}) });
  }

  const created = await prisma.$transaction(
    others.map((event) => {
      // Location only with location_opt_in === true; otherwise stripped from the evidence.
      const location = extractLocation(event.evidence);
      return prisma.securityEvent.create({
        data: {
          applicationId,
          detectorId: event.detectorId,
          status: event.status,
          evidence: location.evidence as any,
          ...locationColumns(location.location),
          reason: event.reason,
          deviceId: event.deviceId,
          deviceModel: event.deviceModel,
          manufacturer: event.manufacturer,
          osPlatform: event.osPlatform,
          osVersion: event.osVersion,
          appVersion: event.appVersion,
          sdkVersion: event.sdkVersion,
          clientObservedAt: event.observedAt ? new Date(event.observedAt) : undefined,
          ipAddress,
        },
      });
    }),
  );

  await Promise.all(
    created.map((row) =>
      recordEventForDashboard(applicationId, {
        id: row.id,
        detectorId: row.detectorId,
        status: row.status,
        receivedAt: row.receivedAt.toISOString(),
      })
    )
  );

  res.status(201).json({ accepted: created.length });

  raiseTamperAlertsInBackground({ applicationId, events: created, ipAddress, now: new Date() });

  const detected = created.filter((row) => row.status === "DETECTED");
  if (detected.length > 0) {
    const app = await prisma.application.findUnique({
      where: { id: applicationId },
      select: { name: true },
    });
    if (app) {
      for (const row of detected) {
        void maybeTriggerWebhook(applicationId, app.name, {
          detectorId: row.detectorId,
          status: row.status,
          deviceId: row.deviceId,
          deviceModel: row.deviceModel,
          osPlatform: row.osPlatform,
          receivedAt: row.receivedAt,
          evidence: row.evidence,
        });
      }
    }
  }
});
