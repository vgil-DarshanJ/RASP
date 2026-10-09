import crypto from "node:crypto";
import { redis } from "../redis/client";

/**
 * One-time registration challenges (F-13): `POST /v1/devices/challenge`
 * issues 32 random bytes (base64url), valid for 5 minutes and for one
 * registration of one application. The device signs
 * `rasp-register-v1:<challenge>:<deviceKeyId>` with its device key and sends
 * challenge + signature with the registration, which proves it holds the
 * attested private key now (a copied attestation chain alone does not).
 */
export const CHALLENGE_TTL_SECONDS = 300;

export interface ChallengeStore {
  save(applicationId: string, challenge: string, ttlSeconds: number): Promise<void>;
  /** `true` once for a saved, unexpired challenge; it is gone afterwards. */
  consume(applicationId: string, challenge: string): Promise<boolean>;
}

const key = (applicationId: string, challenge: string) => `reg_chal:${applicationId}:${challenge}`;

export const redisChallengeStore: ChallengeStore = {
  async save(applicationId, challenge, ttlSeconds) {
    await redis.set(key(applicationId, challenge), "1", "EX", ttlSeconds);
  },
  async consume(applicationId, challenge) {
    return (await redis.del(key(applicationId, challenge))) === 1;
  },
};

/** The store in use; tests replace it. */
export const registrationChallenges: { store: ChallengeStore } = { store: redisChallengeStore };

export async function issueChallenge(applicationId: string): Promise<string> {
  const challenge = crypto.randomBytes(32).toString("base64url");
  await registrationChallenges.store.save(applicationId, challenge, CHALLENGE_TTL_SECONDS);
  return challenge;
}

/** The exact bytes the device signs. */
export function possessionMessage(challenge: string, deviceKeyId: string): Buffer {
  return Buffer.from(`rasp-register-v1:${challenge}:${deviceKeyId}`, "utf8");
}

/** ECDSA P-256 / SHA-256 (DER signature) over [possessionMessage] with the key [spkiDer]. */
export function verifyPossession(spkiDer: Buffer, challenge: string, deviceKeyId: string, signatureBase64: string): boolean {
  try {
    const publicKey = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    return crypto.verify("sha256", possessionMessage(challenge, deviceKeyId), { key: publicKey, dsaEncoding: "der" }, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}
