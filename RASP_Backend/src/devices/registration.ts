import { z } from "zod";
import {
  AttestationInspection,
  computeDeviceKeyId,
  inspectAttestationChain,
  parseEcP256PublicKey,
} from "../crypto/ecdsa";
import { normalizeCertHash } from "../ingestion/tamperAlerts";
import { AttestationPolicyName, attestationShortfalls, PolicyReason, storedAttestation } from "./attestationPolicy";
import { registrationChallenges, verifyPossession } from "./registrationChallenge";

/**
 * `POST /v1/devices/register` body.
 * - appId: the host app's package name; envelopes signed by this key must carry it
 * - deviceId: optional advisory label (the SDK's device id)
 * - publicKey: Base64 X.509 SPKI of the EC P-256 device key (`RaspDeviceKey.exportPublicKeyBase64()`)
 * - attestationChain: Base64 DER certificates, leaf first (`RaspDeviceKey.exportAttestationChainBase64()`)
 * - sdkVersion
 * - signingCertSha256: optional, the app's signing certificate SHA-256 (64 hex
 *   characters; upper/lower case and ':' separators accepted; stored
 *   uppercase without separators). Malformed → 400 INVALID_SIGNING_CERT.
 * - challenge + challengeSignature: optional proof of possession — a
 *   challenge from `POST /v1/devices/challenge` and the device key's ECDSA
 *   signature (Base64 DER) over `rasp-register-v1:<challenge>:<deviceKeyId>`.
 */
export const registerSchema = z.object({
  appId: z.string().min(1).max(200),
  deviceId: z.string().min(1).max(200).optional(),
  publicKey: z.string().min(1).max(1000),
  attestationChain: z.array(z.string().min(1).max(20_000)).min(1).max(10),
  sdkVersion: z.string().min(1).max(50),
  signingCertSha256: z.string().min(1).max(200).optional(),
  challenge: z.string().min(16).max(200).optional(),
  challengeSignature: z.string().min(1).max(200).optional(),
});

export interface RegisteredKey {
  id: string;
  applicationId: string;
  appId: string;
  deviceKeyId: string;
  attestationStatus: string;
  attestationVerdict: string;
  possessionVerified?: boolean;
  attestationDetails?: unknown;
  deviceId?: string | null;
}

export interface NewRegistration {
  applicationId: string;
  appId: string;
  deviceId?: string;
  deviceKeyId: string;
  publicKey: string;
  attestationChain: string[];
  attestation: AttestationInspection;
  possessionVerified: boolean;
  sdkVersion: string;
  /** Normalized (uppercase hex), or null when the SDK did not send one. */
  signingCertSha256: string | null;
  /** Country of the registration request IP (ISO alpha-2), or null. */
  registrationCountry: string | null;
  now: Date;
}

export interface ApplicationPolicy {
  policy: AttestationPolicyName;
  expectedSigningCertSha256: string | null;
}

const DEFAULT_POLICY: ApplicationPolicy = { policy: "RECORD", expectedSigningCertSha256: null };

/** Persistence for registrations. Production: `prismaRegistrationRepository`. */
export interface RegistrationRepository {
  findByKeyId(deviceKeyId: string): Promise<RegisteredKey | null>;
  /** `"exists"` when another request registered the same key first. */
  create(input: NewRegistration): Promise<RegisteredKey | "exists">;
  touch(id: string, now: Date): Promise<void>;
  /** The application's attestation policy; RECORD when not implemented. */
  policyFor?(applicationId: string): Promise<ApplicationPolicy | null>;
  /**
   * Replaces the stored attestation of a key after a new, possession-proven
   * registration, and sets `deviceId` when the row has none yet (keys
   * registered by SDKs that did not send one, F-15).
   */
  updateAttestation?(id: string, attestation: AttestationInspection, possessionVerified: boolean, now: Date, deviceId?: string): Promise<void>;
}

export interface RegistrationOutcome {
  status: number;
  body: Record<string, unknown>;
}

/**
 * Registers one device key for the calling application.
 *
 * - The key must be a canonical Base64 SPKI of an EC P-256 key → else 400.
 * - The attestation chain is verified (Google roots, validity, revocation
 *   list when available, hardware level; see inspectAttestationChain) and
 *   the result recorded with the key.
 * - Possession: a valid challenge signature sets `possessionVerified`.
 * - Policy (see attestationPolicy.ts): under REQUIRE_HARDWARE a key that
 *   falls short is refused with 403 ATTESTATION_REQUIRED and the reasons,
 *   and nothing is stored; without a revocation list the answer is 503
 *   ATTESTATION_STATUS_UNAVAILABLE (try again later). RECORD registers
 *   every key.
 * - A key is registered once. Registering the same key again for the same
 *   application and package is idempotent (200); for another application or
 *   package it is refused (409). The stored attestation is replaced only by
 *   a registration that proves possession of the key, so nobody without the
 *   private key can change it. A new key for an existing `deviceId` becomes
 *   a new registration — the old key is kept, so knowing a device's id is
 *   not enough to take over its identity.
 */
export async function registerDevice(args: {
  body: unknown;
  applicationId: string;
  now: Date;
  repo: RegistrationRepository;
  /** Country of the request IP (resolved by the route); stored with a new registration. */
  registrationCountry?: string | null;
  /** Revocation list entries (null: not available). Undefined: not checked. */
  revoked?: Map<string, string> | null;
  /** Whether REQUIRE_HARDWARE needs a checked revocation list (ATTESTATION_REVOCATION_CHECK). Default true. */
  revocationRequired?: boolean;
}): Promise<RegistrationOutcome> {
  const parsed = registerSchema.safeParse(args.body);
  if (!parsed.success) {
    return { status: 400, body: { error: "INVALID_REGISTER_BODY", details: parsed.error.flatten() } };
  }
  const { appId, deviceId, publicKey, attestationChain, sdkVersion, challenge, challengeSignature } = parsed.data;
  let signingCertSha256: string | null = null;
  if (parsed.data.signingCertSha256 !== undefined) {
    signingCertSha256 = normalizeCertHash(parsed.data.signingCertSha256);
    if (!signingCertSha256) {
      return { status: 400, body: { error: "INVALID_SIGNING_CERT", reason: "expected 64 hex characters (':' separators allowed)" } };
    }
  }

  const key = parseEcP256PublicKey(publicKey);
  if (!key.ok) return { status: 400, body: { error: "INVALID_PUBLIC_KEY", reason: key.reason } };
  const deviceKeyId = computeDeviceKeyId(key.spkiDer);

  let possessionVerified = false;
  if (challenge && challengeSignature) {
    const fresh = await registrationChallenges.store.consume(args.applicationId, challenge);
    possessionVerified = fresh && verifyPossession(key.spkiDer, challenge, deviceKeyId, challengeSignature);
  }

  const policy = (await args.repo.policyFor?.(args.applicationId)) ?? DEFAULT_POLICY;
  const revocationRequired = args.revocationRequired ?? true;
  if (policy.policy === "REQUIRE_HARDWARE" && revocationRequired && args.revoked === null) {
    return { status: 503, body: { error: "ATTESTATION_STATUS_UNAVAILABLE" } };
  }
  const attestation = inspectAttestationChain(key.spkiDer, attestationChain, { revoked: args.revoked ?? null, now: args.now });
  const shortfalls = (a: AttestationInspection, possession: boolean): PolicyReason[] =>
    attestationShortfalls({
      policy: policy.policy,
      appId,
      expectedSigningCertSha256: policy.expectedSigningCertSha256,
      verdict: a.verdict,
      possessionVerified: possession,
      revocationChecked: a.revocationChecked,
      revocationRequired,
      attestedPackages: a.attestedPackages,
      attestedSigningCertSha256: a.attestedSigningCertSha256,
    });

  const existing = await args.repo.findByKeyId(deviceKeyId);
  if (existing) {
    return existingKey({ existing, applicationId: args.applicationId, appId, deviceId, now: args.now, repo: args.repo, policy, attestation, possessionVerified, revocationRequired, shortfalls });
  }

  if (policy.policy === "REQUIRE_HARDWARE") {
    const reasons = shortfalls(attestation, possessionVerified);
    if (reasons.length > 0) {
      return { status: 403, body: { error: "ATTESTATION_REQUIRED", reasons, attestationVerdict: attestation.verdict } };
    }
  }

  const created = await args.repo.create({
    applicationId: args.applicationId,
    appId,
    deviceId,
    deviceKeyId,
    publicKey,
    attestationChain,
    attestation,
    possessionVerified,
    sdkVersion,
    signingCertSha256,
    registrationCountry: args.registrationCountry ?? null,
    now: args.now,
  });
  if (created === "exists") {
    const winner = await args.repo.findByKeyId(deviceKeyId);
    if (!winner) return { status: 500, body: { error: "REGISTRATION_FAILED" } };
    return existingKey({ existing: winner, applicationId: args.applicationId, appId, deviceId, now: args.now, repo: args.repo, policy, attestation, possessionVerified, revocationRequired, shortfalls });
  }
  return {
    status: 201,
    body: { registered: true, deviceKeyId, attestationVerdict: attestation.verdict, possessionVerified, attestation },
  };
}

async function existingKey(a: {
  existing: RegisteredKey;
  applicationId: string;
  appId: string;
  deviceId?: string;
  now: Date;
  repo: RegistrationRepository;
  policy: ApplicationPolicy;
  attestation: AttestationInspection;
  possessionVerified: boolean;
  revocationRequired: boolean;
  shortfalls: (attestation: AttestationInspection, possession: boolean) => PolicyReason[];
}): Promise<RegistrationOutcome> {
  const { existing } = a;
  if (existing.applicationId !== a.applicationId) {
    return { status: 409, body: { error: "DEVICE_KEY_REGISTERED_TO_OTHER_APPLICATION" } };
  }
  if (existing.appId !== a.appId) {
    return { status: 409, body: { error: "DEVICE_KEY_REGISTERED_FOR_OTHER_APP_ID" } };
  }

  // Only the holder of the private key may replace what is on record.
  let verdict = existing.attestationVerdict;
  let possession = existing.possessionVerified ?? false;
  let reasons: PolicyReason[];
  if (a.possessionVerified && a.repo.updateAttestation) {
    await a.repo.updateAttestation(existing.id, a.attestation, true, a.now, existing.deviceId ? undefined : a.deviceId);
    verdict = a.attestation.verdict;
    possession = true;
    reasons = a.shortfalls(a.attestation, true);
  } else {
    await a.repo.touch(existing.id, a.now);
    const stored = storedAttestation(existing.attestationDetails);
    reasons = attestationShortfalls({
      policy: a.policy.policy,
      appId: a.appId,
      expectedSigningCertSha256: a.policy.expectedSigningCertSha256,
      verdict,
      possessionVerified: possession,
      revocationChecked: stored.revocationChecked,
      revocationRequired: a.revocationRequired,
      attestedPackages: stored.attestedPackages,
      attestedSigningCertSha256: stored.attestedSigningCertSha256,
    });
  }
  if (a.policy.policy === "REQUIRE_HARDWARE" && reasons.length > 0) {
    return { status: 403, body: { error: "ATTESTATION_REQUIRED", reasons, attestationVerdict: verdict } };
  }
  return {
    status: 200,
    body: {
      registered: true,
      existing: true,
      deviceKeyId: existing.deviceKeyId,
      attestationStatus: existing.attestationStatus,
      attestationVerdict: verdict,
      possessionVerified: possession,
    },
  };
}
