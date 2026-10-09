import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { prisma } from "../db/prisma";
import { decryptSecret } from "../crypto/secretBox";
import { meetsSeverityThreshold, severityOf } from "../detectors/severity";
import { guardedLookup, isBlockedAddress, privateDestinationsAllowed } from "./destination";

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

/**
 * Signature headers of one delivery (F-08):
 *   X-Webhook-Id         one id per alert, the same on every retry (deduplicate on it)
 *   X-Webhook-Timestamp  Unix seconds when this attempt was signed
 *   X-Webhook-Signature  v1=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>
 * A receiver recomputes the HMAC over the timestamp and the exact body bytes,
 * compares in constant time, and rejects timestamps more than 5 minutes old,
 * so a captured delivery cannot be replayed later.
 */
export function signDelivery(secret: string, body: Buffer, timestampSeconds: number): string {
  const mac = crypto.createHmac("sha256", secret).update(`${timestampSeconds}.`).update(body).digest("hex");
  return `v1=${mac}`;
}

/** Waits before retry n (1-based): 1 s, then 4 s. Tests replace it. */
export const webhookRetry: { attempts: number; delayMs: (retry: number) => number; sleep: (ms: number) => Promise<void> } = {
  attempts: 3,
  delayMs: (retry) => (retry === 1 ? 1000 : 4000),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

type AttemptResult = { statusCode: number | null; error: string | null; retryable: boolean };

function attempt(url: URL, headers: Record<string, string>, body: Buffer): Promise<AttemptResult> {
  return new Promise((resolve) => {
    const host = url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
    if (net.isIP(host) && isBlockedAddress(host) && !privateDestinationsAllowed()) {
      resolve({ statusCode: null, error: "Destination is a private or reserved address", retryable: false });
      return;
    }
    const transport = url.protocol === "https:" ? https : http;
    const req = transport.request(
      url,
      {
        method: "POST",
        headers: { ...headers, "Content-Length": String(body.length) },
        lookup: guardedLookup as unknown as net.LookupFunction,
        timeout: DELIVERY_TIMEOUT_MS,
      },
      (res) => {
        res.resume(); // the receiver's body is not needed
        const status = res.statusCode ?? 0;
        const ok = status >= 200 && status < 300;
        resolve({
          statusCode: status,
          error: ok ? null : `Non-2xx response: ${status}`,
          retryable: status >= 500 || status === 429,
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error(`No response within ${DELIVERY_TIMEOUT_MS} ms`)));
    req.on("error", (e: NodeJS.ErrnoException) => {
      const blocked = e.code === "WEBHOOK_URL_PRIVATE_ADDRESS";
      resolve({ statusCode: null, error: e.message || "Unknown delivery failure", retryable: !blocked });
    });
    req.end(body);
  });
}

/**
 * Delivers one alert: HTTPS only (see destination.ts), up to
 * [webhookRetry.attempts] tries on network errors, 5xx and 429 (not on other
 * 4xx), each attempt freshly timestamped and signed. Records the last
 * attempt's status on the config; never throws.
 */
export async function deliver(
  configId: string,
  url: string,
  secretEncrypted: string,
  payload: WebhookEventPayload,
): Promise<void> {
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  const deliveryId = crypto.randomUUID();

  let result: AttemptResult = { statusCode: null, error: "Not attempted", retryable: false };
  let tries = 0;
  try {
    const secret = decryptSecret(secretEncrypted);
    const target = new URL(url);
    if (target.protocol !== "https:" && !(target.protocol === "http:" && privateDestinationsAllowed())) {
      result = { statusCode: null, error: "Webhook URL must use https://", retryable: false };
    } else {
      for (tries = 1; tries <= webhookRetry.attempts; tries++) {
        const timestamp = Math.floor(Date.now() / 1000);
        result = await attempt(
          target,
          {
            "Content-Type": "application/json",
            "User-Agent": "RASP-Shield-Webhooks/1",
            "X-Webhook-Id": deliveryId,
            "X-Webhook-Timestamp": String(timestamp),
            "X-Webhook-Signature": signDelivery(secret, body, timestamp),
          },
          body,
        );
        if (result.error === null || !result.retryable || tries === webhookRetry.attempts) break;
        await webhookRetry.sleep(webhookRetry.delayMs(tries));
      }
    }
  } catch (e) {
    result = { statusCode: null, error: e instanceof Error ? e.message : "Unknown delivery failure", retryable: false };
  }

  const error = result.error === null ? null : tries > 1 ? `${result.error} (after ${tries} attempts)` : result.error;
  try {
    await prisma.webhookConfig.update({
      where: { id: configId },
      data: { lastTriggeredAt: new Date(), lastStatusCode: result.statusCode, lastError: error },
    });
  } catch {
    // Best-effort status bookkeeping only — never let this throw upward.
  }
}
