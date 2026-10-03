import { z } from "zod";
import {
  AttestationInspection,
  computeDeviceKeyId,
  inspectAttestationChain,
  parseEcP256PublicKey,
} from "../crypto/ecdsa";

/**
 * `POST /v1/devices/register` body.
 * - appId: the host app's package name; envelopes signed by this key must carry it
 * - deviceId: optional advisory label (the SDK's device id)
 * - publicKey: Base64 X.509 SPKI of the EC P-256 device key (`RaspDeviceKey.exportPublicKeyBase64()`)
 * - attestationChain: Base64 DER certificates, leaf first (`RaspDeviceKey.exportAttestationChainBase64()`)
 * - sdkVersion
 */
export const registerSchema = z.object({
  appId: z.string().min(1).max(200),
  deviceId: z.string().min(1).max(200).optional(),
  publicKey: z.string().min(1).max(1000),
  attestationChain: z.array(z.string().min(1).max(20_000)).min(1).max(10),
  sdkVersion: z.string().min(1).max(50),
});

export interface RegisteredKey {
  id: string;
  applicationId: string;
  appId: string;
  deviceKeyId: string;
  attestationStatus: string;
  attestationVerdict: string;
}

export interface NewRegistration {
  applicationId: string;
  appId: string;
  deviceId?: string;
  deviceKeyId: string;
  publicKey: string;
  attestationChain: string[];
  attestation: AttestationInspection;
  sdkVersion: string;
  now: Date;
}

/** Persistence for registrations. Production: `prismaRegistrationRepository`. */
export interface RegistrationRepository {
  findByKeyId(deviceKeyId: string): Promise<RegisteredKey | null>;
  /** `"exists"` when another request registered the same key first. */
  create(input: NewRegistration): Promise<RegisteredKey | "exists">;
  touch(id: string, now: Date): Promise<void>;
}

export interface RegistrationOutcome {
  status: number;
  body: Record<string, unknown>;
}

/**
 * Registers one device key for the calling application.
 *
 * - The key must be a canonical Base64 SPKI of an EC P-256 key → else 400.
 * - The attestation chain is parsed and the result recorded with the key
 *   (PARSED / KEY_MISMATCH / UNPARSEABLE, plus details). It is not a
 *   reason to refuse: the result is evidence for policy and dashboards,
 *   and checking against the Google attestation roots comes later.
 * - A key is registered once and never overwritten. Registering the same
 *   key again for the same application and package is idempotent (200);
 *   for another application or package it is refused (409). A new key for
 *   an existing `deviceId` becomes a new registration — the old key is kept,
 *   so knowing a device's id is not enough to take over its identity.
 */
export async function registerDevice(args: {
  body: unknown;
  applicationId: string;
  now: Date;
  repo: RegistrationRepository;
}): Promise<RegistrationOutcome> {
  const parsed = registerSchema.safeParse(args.body);
  if (!parsed.success) {
    return { status: 400, body: { error: "INVALID_REGISTER_BODY", details: parsed.error.flatten() } };
  }
  const { appId, deviceId, publicKey, attestationChain, sdkVersion } = parsed.data;

  const key = parseEcP256PublicKey(publicKey);
  if (!key.ok) return { status: 400, body: { error: "INVALID_PUBLIC_KEY", reason: key.reason } };
  const deviceKeyId = computeDeviceKeyId(key.spkiDer);

  const existing = await args.repo.findByKeyId(deviceKeyId);
  if (existing) return existingKey(existing, args.applicationId, appId, args.now, args.repo);

  const attestation = inspectAttestationChain(key.spkiDer, attestationChain);
  const created = await args.repo.create({
    applicationId: args.applicationId,
    appId,
    deviceId,
    deviceKeyId,
    publicKey,
    attestationChain,
    attestation,
    sdkVersion,
    now: args.now,
  });
  if (created === "exists") {
    const winner = await args.repo.findByKeyId(deviceKeyId);
    if (!winner) return { status: 500, body: { error: "REGISTRATION_FAILED" } };
    return existingKey(winner, args.applicationId, appId, args.now, args.repo);
  }
  return { status: 201, body: { registered: true, deviceKeyId, attestationVerdict: attestation.verdict, attestation } };
}

async function existingKey(
  existing: RegisteredKey,
  applicationId: string,
  appId: string,
  now: Date,
  repo: RegistrationRepository,
): Promise<RegistrationOutcome> {
  if (existing.applicationId !== applicationId) {
    return { status: 409, body: { error: "DEVICE_KEY_REGISTERED_TO_OTHER_APPLICATION" } };
  }
  if (existing.appId !== appId) {
    return { status: 409, body: { error: "DEVICE_KEY_REGISTERED_FOR_OTHER_APP_ID" } };
  }
  await repo.touch(existing.id, now);
  return {
    status: 200,
    body: {
      registered: true,
      existing: true,
      deviceKeyId: existing.deviceKeyId,
      attestationStatus: existing.attestationStatus,
      attestationVerdict: existing.attestationVerdict,
    },
  };
}
