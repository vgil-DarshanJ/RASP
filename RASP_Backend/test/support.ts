// Test doubles and helpers. The repositories below stand in for Postgres:
// they enforce the same rules as the Prisma implementations (counter
// compare-and-set, unique nonce / counter / eventId per key, unique
// deviceKeyId) but are NOT the Prisma code — that code needs a database
// and is not exercised by these tests.
import crypto from "node:crypto";
import { canonicalStringify, computeDeviceKeyId } from "../src/crypto/ecdsa";
import {
  CreatedEvent,
  DeviceKeyRecord,
  EnvelopeRepository,
  StoreEnvelopeInput,
  StoreResult,
} from "../src/ingestion/envelope";
import { NewRegistration, RegisteredKey, RegistrationRepository } from "../src/devices/registration";
import type { StoredLocation } from "../src/ingestion/location";

export class MemoryEnvelopeRepository implements EnvelopeRepository {
  devices = new Map<string, DeviceKeyRecord>(); // by deviceKeyId
  envelopes: { id: string; eventId: string; deviceRegistrationId: string; nonce: string; counter: bigint; signature: string; signedPayload: string; payloadRedacted: boolean }[] = [];
  events: (CreatedEvent & { envelopeId: string; applicationId: string; location: StoredLocation | null })[] = [];

  addDevice(deviceKeyId: string, record: Omit<DeviceKeyRecord, "lastCounter"> & { lastCounter?: bigint }) {
    this.devices.set(deviceKeyId, { lastCounter: 0n, ...record });
  }

  async findDeviceKey(deviceKeyId: string) {
    const d = this.devices.get(deviceKeyId);
    return d ? { ...d } : null;
  }

  async findEnvelopeByEventId(eventId: string) {
    const e = this.envelopes.find((x) => x.eventId === eventId);
    return e ? { deviceRegistrationId: e.deviceRegistrationId, signature: e.signature } : null;
  }

  async isNonceUsed(deviceRegistrationId: string, nonce: string) {
    return this.envelopes.some((x) => x.deviceRegistrationId === deviceRegistrationId && x.nonce === nonce);
  }

  async storeEnvelope(input: StoreEnvelopeInput): Promise<StoreResult> {
    const device = [...this.devices.values()].find((d) => d.id === input.device.id)!;
    const counter = BigInt(input.envelope.monotonicCounter);
    if (!(device.lastCounter < counter)) return { outcome: "counter_not_increasing" };
    if (this.envelopes.some((x) => x.deviceRegistrationId === device.id && x.nonce === input.envelope.nonce)) {
      return { outcome: "nonce_reused" };
    }
    if (this.envelopes.some((x) => x.eventId === input.envelope.eventId)) return { outcome: "event_id_reused" };

    device.lastCounter = counter;
    const envelopeId = `env-${this.envelopes.length + 1}`;
    this.envelopes.push({
      id: envelopeId,
      eventId: input.envelope.eventId,
      deviceRegistrationId: device.id,
      nonce: input.envelope.nonce,
      counter,
      signature: input.envelope.signature,
      signedPayload: input.signedPayload,
      payloadRedacted: input.payloadRedacted,
    });
    const created = input.events.map((e, i) => ({
      id: `${envelopeId}-ev-${i}`,
      detectorId: e.detectorId,
      status: e.status,
      deviceId: device.deviceId ?? input.envelope.deviceKeyId,
      deviceModel: null,
      osPlatform: null,
      receivedAt: input.receivedAt,
      evidence: e.evidence,
      envelopeId,
      applicationId: device.applicationId,
      location: e.location,
    }));
    this.events.push(...created);
    return { outcome: "stored", events: created };
  }
}

export class MemoryRegistrationRepository implements RegistrationRepository {
  rows: (RegisteredKey & { input: NewRegistration; lastSeenAt: Date })[] = [];

  async findByKeyId(deviceKeyId: string) {
    const r = this.rows.find((x) => x.deviceKeyId === deviceKeyId);
    return r ? { id: r.id, applicationId: r.applicationId, appId: r.appId, deviceKeyId: r.deviceKeyId, attestationStatus: r.attestationStatus, attestationVerdict: r.attestationVerdict } : null;
  }

  async create(input: NewRegistration) {
    if (this.rows.some((x) => x.deviceKeyId === input.deviceKeyId)) return "exists" as const;
    const row = {
      id: `reg-${this.rows.length + 1}`,
      applicationId: input.applicationId,
      appId: input.appId,
      deviceKeyId: input.deviceKeyId,
      attestationStatus: input.attestation.status,
      attestationVerdict: input.attestation.verdict,
      input,
      lastSeenAt: input.now,
    };
    this.rows.push(row);
    return { id: row.id, applicationId: row.applicationId, appId: row.appId, deviceKeyId: row.deviceKeyId, attestationStatus: row.attestationStatus, attestationVerdict: row.attestationVerdict };
  }

  async touch(id: string, now: Date) {
    const r = this.rows.find((x) => x.id === id);
    if (r) r.lastSeenAt = now;
  }
}

export interface TestDevice {
  privateKey: crypto.KeyObject;
  publicKeyB64: string;
  deviceKeyId: string;
  appId: string;
}

/** A software EC P-256 key standing in for the device's Keystore key. */
export function makeDevice(appId = "com.example.bank"): TestDevice {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return { privateKey, publicKeyB64: spki.toString("base64"), deviceKeyId: computeDeviceKeyId(spki), appId };
}

/**
 * Builds and signs an envelope the way the SDK does: ECDSA P-256 / SHA-256
 * (DER) over the canonical JSON of every field except `signature`. The body
 * is serialized with ordinary JSON.stringify (unsorted), so the server's own
 * canonicalization is what makes it verify.
 */
export function signEnvelope(device: TestDevice, now: number, overrides: Record<string, unknown> = {}) {
  const fields: Record<string, unknown> = {
    envelopeVersion: 1,
    eventId: crypto.randomUUID(),
    eventTimeMillis: now,
    monotonicCounter: 1,
    nonce: crypto.randomBytes(16).toString("hex"),
    sdkVersion: "test",
    appId: device.appId,
    deviceKeyId: device.deviceKeyId,
    detectorResults: [
      { detectorId: "root_jailbreak", status: "DETECTED", evidence: [{ key: "signal", value: "su_binary", note: "hard" }], observedAtMillis: now },
      { detectorId: "mitm", status: "UNKNOWN", evidence: [], reason: "pin probe not attempted", observedAtMillis: now },
    ],
    signatureAlgorithm: "ES256",
    ...overrides,
  };
  const signature = crypto.sign("sha256", Buffer.from(canonicalStringify(fields), "utf8"), device.privateKey).toString("base64");
  const signed = { ...fields, signature };
  return { fields: signed, body: JSON.stringify(signed) };
}
