// Test doubles for risk events (POST /v1/risk/events). The repository
// below stands in for Postgres: it enforces the same rules as
// src/risk/repository.ts (counter compare-and-set, nonce / eventId once per
// key, the same history windows) but is NOT the Prisma code — that code
// needs a database and is not exercised by these tests.
import crypto from "node:crypto";
import { canonicalStringify } from "../src/crypto/ecdsa";
import type {
  RiskDeviceKey,
  RiskEventRepository,
  StoreRiskEventInput,
  StoreRiskResult,
} from "../src/risk/riskEvents";
import type { AccountHistory, RiskFinding } from "../src/risk/rules";
import type { TestDevice } from "./support";

export interface MemoryRiskRow {
  id: string;
  type: "session" | "transaction";
  applicationId: string;
  deviceRegistrationId: string;
  deviceKeyId: string;
  eventId: string;
  nonce: string;
  signature: string;
  accountHash: string;
  sessionHash: string;
  sessionEvent?: string;
  beneficiaryHash?: string;
  riskScore: number | null;
  riskVerdict: string;
  latitude: number | null;
  longitude: number | null;
  locationCapturedAt: Date | null;
  ipCountry: string | null;
  eventTime: Date;
  receivedAt: Date;
  findings: RiskFinding[];
}

export class MemoryRiskRepository implements RiskEventRepository {
  devices = new Map<string, RiskDeviceKey>(); // by deviceKeyId
  riskRules = new Map<string, unknown>();
  rows: MemoryRiskRow[] = [];
  bindings: { applicationId: string; accountHash: string; deviceKeyId: string; firstSeenAt: Date; lastSeenAt: Date }[] = [];

  addDevice(deviceKeyId: string, record: Omit<RiskDeviceKey, "lastRiskCounter"> & { lastRiskCounter?: bigint }) {
    this.devices.set(deviceKeyId, { lastRiskCounter: 0n, ...record });
  }

  async findDeviceKey(deviceKeyId: string) {
    const d = this.devices.get(deviceKeyId);
    return d ? { ...d } : null;
  }

  async findRiskRules(applicationId: string) {
    return this.riskRules.get(applicationId) ?? null;
  }

  async findByEventId(deviceRegistrationId: string, eventId: string) {
    const r = this.rows.find((x) => x.deviceRegistrationId === deviceRegistrationId && x.eventId === eventId);
    return r ? { signature: r.signature } : null;
  }

  async isNonceUsed(deviceRegistrationId: string, nonce: string) {
    return this.rows.some((x) => x.deviceRegistrationId === deviceRegistrationId && x.nonce === nonce);
  }

  history(input: StoreRiskEventInput): AccountHistory {
    const { facts, rules } = input;
    const appId = input.device.applicationId;
    const mine = this.rows.filter((r) => r.applicationId === appId && r.accountHash === facts.accountHash);
    const sessionSince = facts.eventTime.getTime() - rules.concurrentSessions.windowMinutes * 60_000;
    const txSince = facts.eventTime.getTime() - rules.transactionVelocity.windowMinutes * 60_000;
    const located = facts.location
      ? mine
          .filter((r) => r.locationCapturedAt && r.locationCapturedAt < facts.location!.capturedAt)
          .sort((a, b) => b.locationCapturedAt!.getTime() - a.locationCapturedAt!.getTime())[0]
      : undefined;
    const withCountry = facts.ipCountry
      ? mine.filter((r) => r.ipCountry).sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime())[0]
      : undefined;
    return {
      bindings: this.bindings
        .filter((b) => b.applicationId === appId && b.accountHash === facts.accountHash)
        .map((b) => ({ deviceKeyId: b.deviceKeyId, firstSeenAt: b.firstSeenAt })),
      recentSessions: mine
        .filter((r) => r.type === "session" && r.eventTime.getTime() >= sessionSince && r.eventTime <= facts.eventTime)
        .map((r) => ({ deviceKeyId: r.deviceKeyId, sessionHash: r.sessionHash, sessionEvent: r.sessionEvent!, eventTime: r.eventTime })),
      lastLocated: located
        ? { deviceKeyId: located.deviceKeyId, location: { latitude: located.latitude!, longitude: located.longitude!, capturedAt: located.locationCapturedAt! } }
        : null,
      lastIpCountry: withCountry ? { country: withCountry.ipCountry!, receivedAt: withCountry.receivedAt, deviceKeyId: withCountry.deviceKeyId } : null,
      recentTransactionCount: facts.type === "transaction"
        ? mine.filter((r) => r.type === "transaction" && r.eventTime.getTime() > txSince && r.eventTime <= facts.eventTime).length
        : 0,
      beneficiarySeenBefore: facts.type === "transaction" && mine.some((r) => r.beneficiaryHash === facts.beneficiaryHash),
    };
  }

  async storeRiskEvent(input: StoreRiskEventInput): Promise<StoreRiskResult> {
    const { device, envelope, facts } = input;
    const stored = [...this.devices.values()].find((d) => d.id === device.id)!;
    const counter = BigInt(envelope.monotonicCounter);
    if (!(stored.lastRiskCounter < counter)) return { outcome: "replayed", duplicate: false };
    const earlier = this.rows.find((r) => r.deviceRegistrationId === device.id && (r.nonce === envelope.nonce || r.eventId === envelope.eventId));
    if (earlier) return { outcome: "replayed", duplicate: earlier.eventId === envelope.eventId && earlier.signature === envelope.signature };

    const findings = input.evaluate(this.history(input));
    stored.lastRiskCounter = counter;
    const row: MemoryRiskRow = {
      id: `risk-${this.rows.length + 1}`,
      type: envelope.type,
      applicationId: device.applicationId,
      deviceRegistrationId: device.id,
      deviceKeyId: envelope.deviceKeyId,
      eventId: envelope.eventId,
      nonce: envelope.nonce,
      signature: envelope.signature,
      accountHash: envelope.accountHash,
      sessionHash: envelope.sessionHash,
      sessionEvent: envelope.type === "session" ? envelope.sessionEvent : undefined,
      beneficiaryHash: envelope.type === "transaction" ? envelope.beneficiaryHash : undefined,
      riskScore: envelope.riskScore,
      riskVerdict: envelope.riskVerdict,
      latitude: facts.location?.latitude ?? null,
      longitude: facts.location?.longitude ?? null,
      locationCapturedAt: facts.location?.capturedAt ?? null,
      ipCountry: facts.ipCountry,
      eventTime: facts.eventTime,
      receivedAt: facts.receivedAt,
      findings,
    };
    this.rows.push(row);
    const binding = this.bindings.find((b) =>
      b.applicationId === device.applicationId && b.accountHash === envelope.accountHash && b.deviceKeyId === envelope.deviceKeyId);
    if (binding) binding.lastSeenAt = facts.receivedAt;
    else this.bindings.push({
      applicationId: device.applicationId, accountHash: envelope.accountHash, deviceKeyId: envelope.deviceKeyId,
      firstSeenAt: facts.receivedAt, lastSeenAt: facts.receivedAt,
    });
    return { outcome: "stored", eventRowId: row.id, findings };
  }
}

/**
 * Builds and signs a risk envelope the way the SDK does: ES256 over the
 * canonical JSON of every field except the signature. Overrides with the
 * value undefined remove that field.
 */
export function signRiskEnvelope(device: TestDevice, now: number, overrides: Record<string, unknown> = {}) {
  const fields: Record<string, unknown> = {
    riskEnvelopeVersion: 1,
    type: "session",
    eventId: crypto.randomUUID(),
    eventTimeMillis: now,
    monotonicCounter: 1,
    nonce: crypto.randomBytes(16).toString("hex"),
    appId: device.appId,
    deviceKeyId: device.deviceKeyId,
    sdkVersion: "test",
    accountHash: "a".repeat(64),
    sessionHash: "b".repeat(64),
    sessionEvent: "login",
    riskScore: null,
    riskVerdict: "UNKNOWN",
    location: null,
    signatureAlgorithm: "ES256",
    ...overrides,
  };
  for (const [k, v] of Object.entries(fields)) if (v === undefined) delete fields[k];
  const signature = crypto.sign("sha256", Buffer.from(canonicalStringify(fields), "utf8"), device.privateKey).toString("base64");
  const signed = { ...fields, signature };
  return { fields: signed, body: JSON.stringify(signed) };
}

/** Transaction-type overrides for [signRiskEnvelope]. */
export const transactionFields = (beneficiary = "c") => ({
  type: "transaction",
  sessionEvent: undefined,
  beneficiaryHash: beneficiary.repeat(64).slice(0, 64),
  currency: "INR",
  channel: "upi",
  bindingSha256: "d".repeat(64),
});
