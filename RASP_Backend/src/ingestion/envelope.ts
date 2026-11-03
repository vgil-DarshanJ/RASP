import { z } from "zod";
import { canonicalStringify, verifyEnvelopeSignature } from "../crypto/ecdsa";
import { extractLocation, redactEnvelopePayload, StoredLocation } from "./location";
import {
  DeviceLocationRepository,
  HEARTBEAT_MAX_AGE_MS,
  heartbeatLocation,
  LocationRecordOutcome,
  splitHeartbeats,
} from "../location/deviceLocations";

/** Oldest accepted event time: envelopes may sit in the SDK's offline queue. */
export const ENVELOPE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
/** Device clocks may run ahead; beyond this an event time is rejected. */
export const ENVELOPE_MAX_FUTURE_MS = 5 * 60 * 1000;

/**
 * Fields this backend reads from an envelope. Validation only — the
 * signature is checked over the body exactly as received (every field
 * except `signature`), not over this schema's output, so a field the SDK
 * adds later does not break verification.
 */
export const envelopeSchema = z.object({
  envelopeVersion: z.literal(1),
  eventId: z.string().uuid(),
  eventTimeMillis: z.number().int().positive(),
  monotonicCounter: z.number().int().positive(),
  nonce: z.string().min(1).max(200),
  sdkVersion: z.string().min(1).max(50),
  appId: z.string().min(1).max(200),
  deviceKeyId: z.string().min(1).max(100),
  detectorResults: z.array(z.object({
    detectorId: z.string().min(1).max(100),
    status: z.enum(["SECURE", "DETECTED", "UNAVAILABLE", "UNKNOWN", "ERROR"]),
    evidence: z.unknown().optional(),
    reason: z.string().max(2000).optional(),
    observedAtMillis: z.number().int().positive(),
  })).min(1).max(200),
  signature: z.string().min(1).max(200),
  signatureAlgorithm: z.literal("ES256"),
  /** The phone, for the dashboard (signed like every other field); older SDKs omit it. */
  device: z.object({
    manufacturer: z.string().max(200).optional(),
    model: z.string().max(200).optional(),
    osPlatform: z.string().max(50).optional(),
    osVersion: z.string().max(100).optional(),
    appVersion: z.string().max(100).optional(),
  }).optional(),
});

export type Envelope = z.infer<typeof envelopeSchema>;

/** `security_events` identity columns from the envelope's `device` object; all undefined without it. */
export function deviceColumns(envelope: Pick<Envelope, "device">) {
  const d = envelope.device;
  return {
    deviceModel: d?.model,
    manufacturer: d?.manufacturer,
    osPlatform: d?.osPlatform,
    osVersion: d?.osVersion,
    appVersion: d?.appVersion,
  };
}

/**
 * Which ingestion path a parsed body takes. Anything carrying
 * `envelopeVersion` is an envelope, whatever else it contains, so a body can
 * never get the envelope path's authentication (API key + device signature)
 * and then be processed as a legacy HMAC batch.
 */
export function isEnvelopeBody(body: unknown): boolean {
  return typeof body === "object" && body !== null && !Array.isArray(body) && "envelopeVersion" in body;
}

/** The registered key an envelope claims to be signed by. */
export interface DeviceKeyRecord {
  id: string;
  applicationId: string;
  appId: string;
  deviceId: string | null;
  publicKey: string;
  lastCounter: bigint;
  /** Signing certificate SHA-256 reported at registration (uppercase hex), if any. */
  signingCertSha256?: string | null;
  /** `false` when the application requires hardware attestation and this key falls short (devices/attestationPolicy.ts). */
  meetsAttestationPolicy?: boolean;
}

export interface NewEnvelopeEvent {
  detectorId: string;
  status: string;
  evidence: unknown;
  reason?: string;
  clientObservedAt: Date;
  /** Opted-in location for the event columns; null when none or not opted in. */
  location: StoredLocation | null;
}

export interface StoreEnvelopeInput {
  device: DeviceKeyRecord;
  envelope: Envelope;
  /** The verified canonical payload, with non-opted-in location removed (see [payloadRedacted]). */
  signedPayload: string;
  /** true when location fields were removed from [signedPayload]; it then no longer re-verifies. */
  payloadRedacted: boolean;
  ipAddress?: string;
  receivedAt: Date;
  events: NewEnvelopeEvent[];
}

/** A stored `SecurityEvent`, as the route needs it for the dashboard cache and webhooks. */
export interface CreatedEvent {
  id: string;
  detectorId: string;
  status: string;
  deviceId: string | null;
  deviceModel: string | null;
  osPlatform: string | null;
  receivedAt: Date;
  evidence: unknown;
}

export type StoreResult =
  | { outcome: "stored"; events: CreatedEvent[] }
  | { outcome: "counter_not_increasing" | "nonce_reused" | "event_id_reused" };

/** Persistence the envelope rules need. Production: `prismaEnvelopeRepository`. */
export interface EnvelopeRepository {
  findDeviceKey(deviceKeyId: string): Promise<DeviceKeyRecord | null>;
  findEnvelopeByEventId(eventId: string): Promise<{ deviceRegistrationId: string; signature: string } | null>;
  isNonceUsed(deviceRegistrationId: string, nonce: string): Promise<boolean>;
  /**
   * Atomically: raise the device's `lastCounter` to the envelope counter only
   * if it is currently lower, store the envelope, store its events. Nothing
   * is stored unless all three succeed.
   */
  storeEnvelope(input: StoreEnvelopeInput): Promise<StoreResult>;
}

export interface EnvelopeOutcome {
  status: number;
  body: Record<string, unknown>;
  created?: CreatedEvent[];
  /** The signing device's registered signing certificate hash, for tamper alerts. */
  deviceSigningCertSha256?: string | null;
}

const reject = (status: number, error: string, extra: Record<string, unknown> = {}): EnvelopeOutcome =>
  ({ status, body: { error, ...extra } });

/**
 * Records the last location heartbeat of an envelope (Task 9.3) for the
 * signing device; `ignored` without a location store or for unusable
 * coordinates.
 */
async function recordHeartbeat(
  locations: DeviceLocationRepository | undefined,
  device: DeviceKeyRecord,
  envelope: Envelope,
  heartbeat: { evidence?: unknown },
  now: number,
): Promise<LocationRecordOutcome | "ignored"> {
  if (!locations) return "ignored";
  const decision = heartbeatLocation(heartbeat.evidence);
  if (decision.kind === "invalid") return "ignored";
  return locations.record({
    applicationId: device.applicationId,
    // Same device id as this device's stored events (see envelopeRepository).
    deviceId: device.deviceId ?? envelope.deviceKeyId,
    counter: BigInt(envelope.monotonicCounter),
    location: decision.kind === "point" ? decision.location : null,
    isMock: decision.kind === "point" ? decision.isMock : null,
    receivedAt: new Date(now),
  });
}

/**
 * Verifies and stores one evidence envelope. Rules, in order:
 *
 * 1. Body parses and has the envelope fields → else 400.
 * 2. `deviceKeyId` is a registered key → else 401 UNKNOWN_DEVICE_KEY;
 *    registered to the calling application → else 403; same `appId` it was
 *    registered for → else 403; meets the application's attestation policy
 *    → else 401 DEVICE_NOT_ATTESTED (the SDK registers again, proving
 *    possession, and retries once).
 * 3. ECDSA P-256 signature over the canonical JSON of every field except
 *    `signature` verifies with that key → else 401.
 * 3a. Only `location_heartbeat` results (Task 9.3) → the device's latest
 *    location is updated and nothing else is stored: event time at most
 *    5 minutes old → else 422 HEARTBEAT_TOO_OLD; counter above the last
 *    heartbeat's → else 409 COUNTER_NOT_INCREASING; then 202
 *    `{ accepted: 0, location: "updated" | "cleared" | "ignored" }`.
 * 4. Exact resend of an envelope already accepted (same `eventId`, same
 *    signature) → 200 `{ accepted: 0, duplicate: true }`, nothing stored
 *    again. The SDK removes an envelope only on 2xx, so a resend after a
 *    lost response must not be refused forever. Same `eventId` with
 *    different content → 409.
 * 5. Event time within the last 7 days (offline queue) and at most 5 minutes
 *    ahead → else 422 EVENT_TOO_OLD / EVENT_FROM_FUTURE (the SDK drops these).
 * 6. Nonce never accepted before for this key → else 409 REPLAYED_NONCE.
 * 7. Counter greater than the last accepted one for this key → else 409
 *    COUNTER_NOT_INCREASING. Enforced again atomically at store time.
 */
export async function processEnvelope(args: {
  rawBody: string;
  applicationId: string;
  ipAddress?: string;
  now: number;
  repo: EnvelopeRepository;
  /** Where location heartbeats go (Task 9.3); without it they are ignored. */
  locations?: DeviceLocationRepository;
}): Promise<EnvelopeOutcome> {
  const { rawBody, applicationId, ipAddress, now, repo, locations } = args;

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return reject(400, "INVALID_JSON");
  }
  const check = envelopeSchema.safeParse(parsed);
  if (!check.success) {
    return reject(400, "INVALID_ENVELOPE", { details: check.error.flatten() });
  }
  const envelope = check.data;

  const device = await repo.findDeviceKey(envelope.deviceKeyId);
  if (!device) return reject(401, "UNKNOWN_DEVICE_KEY");
  if (device.applicationId !== applicationId) return reject(403, "DEVICE_KEY_MISMATCH");
  if (device.appId !== envelope.appId) return reject(403, "APP_ID_MISMATCH");
  if (device.meetsAttestationPolicy === false) return reject(401, "DEVICE_NOT_ATTESTED");

  // Verified over the body as received, minus `signature` — not over the
  // schema output — so it covers every field the device signed.
  const { signature: _signature, ...unsigned } = parsed as Record<string, unknown>;
  const signedPayload = canonicalStringify(unsigned);
  if (!verifyEnvelopeSignature(device.publicKey, signedPayload, envelope.signature)) {
    return reject(401, "ENVELOPE_SIGNATURE_INVALID");
  }

  // Location heartbeats are not security events. A heartbeat-only envelope
  // updates the device's latest location and is not stored itself (one per
  // minute would grow without limit); its replay protection is the
  // per-device location counter and a short freshness window.
  const { heartbeats, others } = splitHeartbeats(envelope.detectorResults);
  if (heartbeats.length > 0 && others.length === 0) {
    if (envelope.eventTimeMillis < now - HEARTBEAT_MAX_AGE_MS) return reject(422, "HEARTBEAT_TOO_OLD");
    if (envelope.eventTimeMillis > now + ENVELOPE_MAX_FUTURE_MS) return reject(422, "EVENT_FROM_FUTURE");
    const outcome = await recordHeartbeat(locations, device, envelope, heartbeats[heartbeats.length - 1], now);
    if (outcome === "counter_not_increasing") return reject(409, "COUNTER_NOT_INCREASING");
    return { status: 202, body: { accepted: 0, location: outcome } };
  }

  const previous = await repo.findEnvelopeByEventId(envelope.eventId);
  if (previous) {
    if (previous.deviceRegistrationId === device.id && previous.signature === envelope.signature) {
      return { status: 200, body: { accepted: 0, duplicate: true } };
    }
    return reject(409, "EVENT_ID_REUSED");
  }

  if (envelope.eventTimeMillis < now - ENVELOPE_MAX_AGE_MS) return reject(422, "EVENT_TOO_OLD");
  if (envelope.eventTimeMillis > now + ENVELOPE_MAX_FUTURE_MS) return reject(422, "EVENT_FROM_FUTURE");

  if (await repo.isNonceUsed(device.id, envelope.nonce)) return reject(409, "REPLAYED_NONCE");
  if (BigInt(envelope.monotonicCounter) <= device.lastCounter) return reject(409, "COUNTER_NOT_INCREASING");

  // Location is kept only with location_opt_in === true; otherwise it is
  // removed from the stored evidence and from the stored signed payload.
  const stored = redactEnvelopePayload(signedPayload, canonicalStringify);
  const result = await repo.storeEnvelope({
    device,
    envelope,
    signedPayload: stored.payload,
    payloadRedacted: stored.redacted,
    ipAddress,
    receivedAt: new Date(now),
    events: others.map((r) => {
      const location = extractLocation(r.evidence);
      return {
        detectorId: r.detectorId,
        status: r.status,
        evidence: location.evidence,
        reason: r.reason,
        clientObservedAt: new Date(r.observedAtMillis),
        location: location.location,
      };
    }),
  });

  switch (result.outcome) {
    case "stored":
      // A heartbeat sent together with detector results (not what the SDK
      // does, but accepted): recorded after the envelope was stored.
      if (heartbeats.length > 0) await recordHeartbeat(locations, device, envelope, heartbeats[heartbeats.length - 1], now);
      return {
        status: 201,
        body: { accepted: result.events.length },
        created: result.events,
        deviceSigningCertSha256: device.signingCertSha256 ?? null,
      };
    case "counter_not_increasing":
      return reject(409, "COUNTER_NOT_INCREASING");
    case "nonce_reused":
      return reject(409, "REPLAYED_NONCE");
    case "event_id_reused":
      return reject(409, "EVENT_ID_REUSED");
  }
}
