import crypto from "node:crypto";
import { prisma } from "../db/prisma";
import { decryptSecret } from "../crypto/secretBox";
import { meetsSeverityThreshold, severityOf } from "../detectors/severity";

const DELIVERY_TIMEOUT_MS = 5000;

export interface WebhookEventPayload {
  applicationId: string;
  applicationName: string;
  detectorId: string;
  severity: ReturnType<typeof severityOf>;
  status: string;
  deviceId: string | null;
  deviceModel: string | null;
  osPlatform: string | null;
  receivedAt: string;
  evidence: unknown;
}

/**
 * Fire-and-forget outbound alert — called from the ingestion route
 * AFTER the event is already durably written to Postgres, never in a
 * position to affect that write's success. Every failure mode (no
 * config, disabled, below threshold, network error, non-2xx response)
 * resolves silently here; the config's `lastStatusCode`/`lastError`
 * fields are the only record, read by the FE settings page, never
 * thrown back to a caller. This mirrors `RaspEventShipper`'s own
 * "telemetry must never affect the primary operation" rule, just on the
 * other end of the pipe.
 */
export async function maybeTriggerWebhook(
  applicationId: string,
  applicationName: string,
  event: { detectorId: string; status: string; deviceId: string | null; deviceModel: string | null; osPlatform: string | null; receivedAt: Date; evidence: unknown },
): Promise<void> {
  if (event.status !== "DETECTED") return;

  let config;
  try {
    config = await prisma.webhookConfig.findUnique({ where: { applicationId } });
  } catch {
    return;
  }
  if (!config || !config.enabled) return;

  const severity = severityOf(event.detectorId);
  const threshold = config.minSeverity.toLowerCase() as ReturnType<typeof severityOf>;
  if (!meetsSeverityThreshold(severity, threshold)) return;

  const payload: WebhookEventPayload = {
    applicationId,
    applicationName,
    detectorId: event.detectorId,
    severity,
    status: event.status,
    deviceId: event.deviceId,
    deviceModel: event.deviceModel,
    osPlatform: event.osPlatform,
    receivedAt: event.receivedAt.toISOString(),
    evidence: event.evidence,
  };

  await deliver(config.id, config.url, config.secretEncrypted, payload);
}

export async function deliver(
  configId: string,
  url: string,
  secretEncrypted: string,
  payload: WebhookEventPayload,
): Promise<void> {
  const bodyBytes = Buffer.from(JSON.stringify(payload), "utf8");

  let statusCode: number | null = null;
  let error: string | null = null;
  try {
    const secret = decryptSecret(secretEncrypted);
    const signature = crypto.createHmac("sha256", secret).update(bodyBytes).digest("hex");

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Webhook-Signature": signature },
        body: bodyBytes,
        signal: controller.signal,
      });
      statusCode = res.status;
      if (!res.ok) error = `Non-2xx response: ${res.status}`;
    } finally {
      clearTimeout(timer);
    }
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown delivery failure";
  }

  try {
    await prisma.webhookConfig.update({
      where: { id: configId },
      data: { lastTriggeredAt: new Date(), lastStatusCode: statusCode, lastError: error },
    });
  } catch {
    // Best-effort status bookkeeping only — never let this throw upward.
  }
}
