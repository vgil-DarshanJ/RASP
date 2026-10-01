import { NextFunction, Response, Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { ApiKeyedRequest, requireApiKey } from "../middleware/apiKey";
import { recordEventForDashboard } from "../redis/dashboardCache";
import { checkRateLimit } from "../redis/rateLimit";
import { maybeTriggerWebhook } from "../webhooks/dispatch";
import { verifyEnvelopeSignature } from "../crypto/ecdsa";

export const ingestionRouter = Router();

/**
 * Rate-limits by the raw `X-Api-Key` header value, BEFORE the (more
 * expensive) DB lookup + HMAC verification in `requireApiKey` — a flood
 * of requests against one key gets rejected cheaply rather than paying
 * for a Postgres round-trip and a decrypt+HMAC computation per request
 * first. Keying on the unvalidated header is safe: an attacker spraying
 * made-up key strings only grows Redis counters for keys that will fail
 * `requireApiKey` anyway, and never grants them anything.
 */
async function rateLimitIngestion(req: ApiKeyedRequest, res: Response, next: NextFunction) {
  const apiKey = req.header("X-Api-Key");
  if (!apiKey) return next(); // requireApiKey below reports the real error

  const limit = Number(process.env.INGESTION_RATE_LIMIT_PER_WINDOW) || 60;
  const windowSeconds = Number(process.env.INGESTION_RATE_LIMIT_WINDOW_SECONDS) || 60;

  const { allowed, remaining } = await checkRateLimit(apiKey, limit, windowSeconds);
  res.setHeader("X-RateLimit-Limit", String(limit));
  res.setHeader("X-RateLimit-Remaining", String(remaining));
  if (!allowed) {
    return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
  }
  next();
}

ingestionRouter.use(rateLimitIngestion);
ingestionRouter.use(requireApiKey);

/**
 * Legacy event schema (HMAC-signed batches) — mirrors `RaspCheckResult`/`RaspCheckStatus`
 * from `android_core`.
 */
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

/**
 * Evidence Envelope schema (ECDSA-signed, per-device key).
 * The envelope is the entire request body — we verify its ECDSA signature
 * before processing any events inside.
 */
const envelopeSchema = z.object({
  envelopeVersion: z.literal(1),
  eventId: z.string().uuid(),
  eventTimeMillis: z.number().int().positive(),
  monotonicCounter: z.number().int().nonnegative(),
  nonce: z.string().min(1),
  sdkVersion: z.string().min(1).max(50),
  appId: z.string().min(1).max(200),
  deviceKeyId: z.string().min(1),
  detectorResults: z.array(z.object({
    detectorId: z.string().min(1).max(100),
    status: z.enum(["SECURE", "DETECTED", "UNAVAILABLE", "UNKNOWN", "ERROR"]),
    evidence: z.unknown().optional(),
    reason: z.string().max(2000).optional(),
    observedAtMillis: z.number().int().positive(),
  })).min(1).max(200),
  signature: z.string().min(1), // Base64-encoded DER ECDSA signature
  signatureAlgorithm: z.literal("ES256"),
});

const legacyBatchSchema = z.object({
  events: z.array(legacyEventSchema).min(1).max(200),
});

/**
 * Detects whether the request body is an evidence envelope (new path)
 * or a legacy HMAC batch (legacy path).
 */
function isEnvelope(body: unknown): body is z.infer<typeof envelopeSchema> {
  const obj = body as Record<string, unknown>;
  return obj?.envelopeVersion === 1 && typeof obj.eventId === "string" && typeof obj.signature === "string";
}

/**
 * Canonicalizes JSON for ECDSA verification — must match SDK exactly.
 * Sorts object keys recursively, no whitespace.
 */
function canonicalizeJson(json: string): string {
  const obj = JSON.parse(json);
  return JSON.stringify(canonicalizeValue(obj));
}

function canonicalizeValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(canonicalizeValue);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = canonicalizeValue((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * `POST /v1/events` — handles both legacy HMAC batches and new Evidence Envelopes.
 *
 * Evidence Envelope path:
 * 1. Detect envelope by `envelopeVersion: 1` + `signature` field
 * 2. Look up device registration by `deviceKeyId` (SHA-256 of SPKI)
 * 3. Verify ECDSA P-256 signature over canonical JSON body
 * 4. Check replay: nonce never reused, counter strictly increasing
 * 5. Check time: eventTime within 7 days past, not >5 min future
 * 6. Store events, update device's lastCounter/lastNonce
 * 7. Legacy HMAC path continues to work unchanged
 */
ingestionRouter.post("/", async (req: ApiKeyedRequest, res) => {
  const applicationId = req.applicationId!;
  const ipAddress = req.ip;
  const rawBody = req.rawBody ?? Buffer.alloc(0);
  const rawBodyStr = rawBody.toString("utf8");

  // Determine path by inspecting raw body
  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(rawBodyStr);
  } catch {
    return res.status(400).json({ error: "INVALID_JSON" });
  }

  // Evidence Envelope path (new)
  if (isEnvelope(parsedBody)) {
    const envelope = parsedBody as z.infer<typeof envelopeSchema>;

    // Verify envelope structure
    const envelopeParse = envelopeSchema.safeParse(parsedBody);
    if (!envelopeParse.success) {
      return res.status(400).json({ error: "INVALID_ENVELOPE", details: envelopeParse.error.flatten() });
    }
    const envelopeData = envelopeParse.data;

    // Verify device registration exists
    const deviceReg = await prisma.deviceRegistration.findUnique({
      where: { deviceKeyId: envelopeData.deviceKeyId },
    });
    if (!deviceReg) {
      return res.status(401).json({ error: "UNKNOWN_DEVICE_KEY" });
    }
    if (deviceReg.applicationId !== req.applicationId) {
      return res.status(403).json({ error: "DEVICE_KEY_MISMATCH" });
    }

    // Verify ECDSA signature over canonical JSON (envelope without signature field)
    const { signature, ...envelopeWithoutSig } = envelopeData;
    const canonicalBody = canonicalizeJson(JSON.stringify(envelopeWithoutSig));
    const signatureValid = verifyEnvelopeSignature(deviceReg.publicKey, canonicalBody, envelopeData.signature);
    if (!signatureValid) {
      return res.status(401).json({ error: "ENVELOPE_SIGNATURE_INVALID" });
    }

    // Replay protection: nonce uniqueness
    if (deviceReg.lastNonce === envelopeData.nonce) {
      return res.status(401).json({ error: "REPLAYED_NONCE" });
    }

    // Counter monotonicity
    if (BigInt(envelopeData.monotonicCounter) <= deviceReg.lastCounter) {
      return res.status(401).json({ error: "COUNTER_NOT_INCREASING" });
    }

    // Time window: eventTime within 7 days past, not >5 min future
    const now = Date.now();
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
    const fiveMinMs = 5 * 60 * 1000;
    if (envelopeData.eventTimeMillis < now - sevenDaysMs) {
      return res.status(401).json({ error: "EVENT_TOO_OLD" });
    }
    if (envelopeData.eventTimeMillis > now + fiveMinMs) {
      return res.status(401).json({ error: "EVENT_FROM_FUTURE" });
    }

    // All checks passed — store events and update device state
    const created = await prisma.$transaction(async (tx) => {
      // Store events
      const created = await Promise.all(
        envelopeData.detectorResults.map((event) =>
          tx.securityEvent.create({
            data: {
              applicationId: req.applicationId!,
              detectorId: event.detectorId,
              status: event.status,
              evidence: event.evidence as any,
              reason: event.reason,
              deviceId: envelopeData.appId, // Use appId as deviceId for envelope path
              deviceModel: undefined,
              manufacturer: undefined,
              osPlatform: undefined,
              osVersion: undefined,
              appVersion: undefined,
              sdkVersion: envelopeData.sdkVersion,
              clientObservedAt: new Date(event.observedAtMillis),
              ipAddress: req.ip,
            },
          })
        )
      );

      // Update device registration state
      await tx.deviceRegistration.update({
        where: { deviceKeyId: envelopeData.deviceKeyId },
        data: {
          lastCounter: BigInt(envelopeData.monotonicCounter),
          lastNonce: envelopeData.nonce,
          lastSeenAt: new Date(),
        },
      });

      return created;
    });

    // Fire-and-forget dashboard cache update
    await Promise.all(
      created.map((row) =>
        recordEventForDashboard(req.applicationId!, {
          id: row.id,
          detectorId: row.detectorId,
          status: row.status,
          receivedAt: row.receivedAt.toISOString(),
        })
      )
    );

    res.status(201).json({ accepted: created.length });

    // Webhook alerting
    const detected = created.filter((row) => row.status === "DETECTED");
    if (detected.length > 0) {
      const app = await prisma.application.findUnique({
        where: { id: req.applicationId! },
        select: { name: true },
      });
      if (app) {
        for (const row of detected) {
          void maybeTriggerWebhook(req.applicationId!, app.name, {
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

  // Legacy HMAC batch path (unchanged)
  const parsed = legacyBatchSchema.safeParse(parsedBody);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_EVENT_BATCH", details: parsed.error.flatten() });
  }

  const created = await prisma.$transaction(
    parsed.data.events.map((event) =>
      prisma.securityEvent.create({
        data: {
          applicationId,
          detectorId: event.detectorId,
          status: event.status,
          evidence: event.evidence as any,
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
      })
    ),
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