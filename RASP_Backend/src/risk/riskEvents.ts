import { z } from "zod";
import { canonicalStringify, verifyEnvelopeSignature } from "../crypto/ecdsa";
import { ENVELOPE_MAX_AGE_MS, ENVELOPE_MAX_FUTURE_MS } from "../ingestion/envelope";
import {
  AccountHistory,
  RiskEventFacts,
  RiskFinding,
  RiskLocation,
  RiskRulesConfig,
  effectiveRiskRules,
  evaluateRiskRules,
} from "./rules";

/** Largest accepted body; larger → 413 before parsing (see riskJsonBodyParser). */
export const RISK_EVENT_MAX_BODY_BYTES = 16 * 1024;

const hex64 = z.string().regex(/^[0-9a-f]{64}$/, "64 lowercase hex");
const uuidV4 = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, "lowercase uuid v4");

const commonFields = {
  riskEnvelopeVersion: z.literal(1),
  eventId: uuidV4,
  eventTimeMillis: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  monotonicCounter: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  nonce: z.string().regex(/^[0-9a-f]{32}$/, "32 lowercase hex"),
  appId: z.string().min(1).max(200),
  deviceKeyId: z.string().min(1).max(100),
  sdkVersion: z.string().min(1).max(32),
  accountHash: hex64,
  sessionHash: hex64,
  riskScore: z.number().int().min(0).max(100).nullable(),
  riskVerdict: z.enum(["LOW", "MEDIUM", "HIGH", "UNKNOWN"]),
  /** Present only when the user opted in to location; otherwise null. */
  location: z
    .object({
      latitude: z.number().min(-90).max(90),
      longitude: z.number().min(-180).max(180),
      capturedAtMillis: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    })
    .strict()
    .nullable(),
  signatureAlgorithm: z.literal("ES256"),
  signature: z.string().min(1).max(200).regex(/^[A-Za-z0-9+/]+={0,2}$/, "Base64"),
};

/**
 * The signed risk envelope. Strict: an unknown field (an `amount`, a phone
 * number, anything) is rejected, so nothing the backend did not ask for is
 * ever stored. Session events carry `sessionEvent`; transaction events carry
 * beneficiary, currency, channel and binding hash — and never an amount.
 */
export const riskEnvelopeSchema = z.discriminatedUnion("type", [
  z.object({ ...commonFields, type: z.literal("session"), sessionEvent: z.enum(["login", "resume", "logout"]) }).strict(),
  z.object({
    ...commonFields,
    type: z.literal("transaction"),
    beneficiaryHash: hex64,
    currency: z.string().regex(/^[A-Z]{3}$/, "3 uppercase letters"),
    channel: z.string().regex(/^[a-z0-9_-]{1,32}$/, "[a-z0-9_-]{1,32}"),
    bindingSha256: hex64,
  }).strict(),
]);

export type RiskEnvelope = z.infer<typeof riskEnvelopeSchema>;

export interface RiskDeviceKey {
  id: string;
  applicationId: string;
  appId: string;
  deviceId: string | null;
  publicKey: string;
  lastRiskCounter: bigint;
  /** `false` when the application requires hardware attestation and this key falls short. */
  meetsAttestationPolicy?: boolean;
}

/** Stored location: rounded to 2 decimals (~1 km). */
export function coarseLocation(location: RiskEnvelope["location"]): RiskLocation | null {
  if (!location) return null;
  const round = (v: number) => Math.round(v * 100) / 100;
  return { latitude: round(location.latitude), longitude: round(location.longitude), capturedAt: new Date(location.capturedAtMillis) };
}

export interface StoreRiskEventInput {
  device: RiskDeviceKey;
  envelope: RiskEnvelope;
  facts: RiskEventFacts;
  rules: RiskRulesConfig;
  /** Called inside the store's transaction with the account's history; its findings are stored with the event. */
  evaluate: (history: AccountHistory) => RiskFinding[];
}

export type StoreRiskResult =
  | { outcome: "stored"; eventRowId: string; findings: RiskFinding[] }
  | { outcome: "replayed"; duplicate: boolean };

/** Persistence for risk events. Production: `prismaRiskEventRepository`. */
export interface RiskEventRepository {
  findDeviceKey(deviceKeyId: string): Promise<RiskDeviceKey | null>;
  /** The application's stored `riskRules` JSON (null = defaults). */
  findRiskRules(applicationId: string): Promise<unknown>;
  /** A risk event of this device with this eventId (either type): its signature. */
  findByEventId(deviceRegistrationId: string, eventId: string): Promise<{ signature: string } | null>;
  isNonceUsed(deviceRegistrationId: string, nonce: string): Promise<boolean>;
  /**
   * Atomically: raise the device's `lastRiskCounter` only if lower, re-check
   * nonce and eventId, load the account history, evaluate, store the event
   * and upsert the account/device binding. Nothing is stored on a replay.
   */
  storeRiskEvent(input: StoreRiskEventInput): Promise<StoreRiskResult>;
}

export interface RiskEventOutcome {
  status: number;
  body: Record<string, unknown>;
  /** Present on 202: what the alert path needs. */
  stored?: { device: RiskDeviceKey; envelope: RiskEnvelope; findings: RiskFinding[] };
}

const reject = (status: number, error: string, extra: Record<string, unknown> = {}): RiskEventOutcome =>
  ({ status, body: { error, ...extra } });

/**
 * Verifies, stores and evaluates one risk envelope. In order:
 * 1. strict schema → 400 INVALID_RISK_EVENT (unknown fields included);
 * 2. registered device key of THIS application → else 401 UNKNOWN_DEVICE_KEY;
 *    same appId it was registered for → else 403 APP_ID_MISMATCH;
 * 3. ES256 signature over canonicalStringify(all fields except signature)
 *    → else 401 SIGNATURE_INVALID;
 * 4. event time ≤ 7 days old and ≤ 5 minutes ahead → else 422
 *    EVENT_TOO_OLD / EVENT_FROM_FUTURE;
 * 5. eventId or nonce already used by this key, or counter not above the
 *    last accepted one on this endpoint → 409 REPLAYED (`duplicate: true`
 *    for an exact resend of an accepted event);
 * 6. store + rules → 202 { accepted: true, riskEvents: [...] }.
 */
export async function processRiskEvent(args: {
  body: unknown;
  applicationId: string;
  /** Country of the request IP, or null; called only for an event that will be stored. */
  resolveIpCountry: () => Promise<string | null>;
  now: number;
  repo: RiskEventRepository;
}): Promise<RiskEventOutcome> {
  const { body, applicationId, resolveIpCountry, now, repo } = args;

  if (typeof body !== "object" || body === null || Array.isArray(body)) return reject(400, "INVALID_RISK_EVENT");
  const check = riskEnvelopeSchema.safeParse(body);
  if (!check.success) return reject(400, "INVALID_RISK_EVENT", { details: check.error.flatten() });
  const envelope = check.data;

  const device = await repo.findDeviceKey(envelope.deviceKeyId);
  // Another application's key is reported as unknown: no hint that it exists.
  if (!device || device.applicationId !== applicationId) return reject(401, "UNKNOWN_DEVICE_KEY");
  if (device.appId !== envelope.appId) return reject(403, "APP_ID_MISMATCH");
  if (device.meetsAttestationPolicy === false) return reject(401, "DEVICE_NOT_ATTESTED");

  const { signature: _signature, ...unsigned } = body as Record<string, unknown>;
  if (!verifyEnvelopeSignature(device.publicKey, canonicalStringify(unsigned), envelope.signature)) {
    return reject(401, "SIGNATURE_INVALID");
  }

  if (envelope.eventTimeMillis < now - ENVELOPE_MAX_AGE_MS) return reject(422, "EVENT_TOO_OLD");
  if (envelope.eventTimeMillis > now + ENVELOPE_MAX_FUTURE_MS) return reject(422, "EVENT_FROM_FUTURE");

  const previous = await repo.findByEventId(device.id, envelope.eventId);
  if (previous) return reject(409, "REPLAYED", { duplicate: previous.signature === envelope.signature });
  if (await repo.isNonceUsed(device.id, envelope.nonce)) return reject(409, "REPLAYED");
  if (BigInt(envelope.monotonicCounter) <= device.lastRiskCounter) return reject(409, "REPLAYED");

  const rules = effectiveRiskRules(await repo.findRiskRules(applicationId));
  const ipCountry = await resolveIpCountry().catch(() => null);
  const facts: RiskEventFacts = {
    type: envelope.type,
    deviceKeyId: envelope.deviceKeyId,
    accountHash: envelope.accountHash,
    sessionHash: envelope.sessionHash,
    sessionEvent: envelope.type === "session" ? envelope.sessionEvent : undefined,
    beneficiaryHash: envelope.type === "transaction" ? envelope.beneficiaryHash : undefined,
    eventTime: new Date(envelope.eventTimeMillis),
    receivedAt: new Date(now),
    location: coarseLocation(envelope.location),
    ipCountry,
  };

  const result = await repo.storeRiskEvent({
    device,
    envelope,
    facts,
    rules,
    evaluate: (history) => evaluateRiskRules(facts, history, rules),
  });
  if (result.outcome === "replayed") return reject(409, "REPLAYED", result.duplicate ? { duplicate: true } : {});

  return {
    status: 202,
    body: { accepted: true, riskEvents: result.findings },
    stored: { device, envelope, findings: result.findings },
  };
}
