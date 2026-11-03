import crypto from "node:crypto";

/**
 * Reversible encryption for the `ApiCredential.apiSecret` — deliberately
 * NOT bcrypt/argon2. Those are one-way password hashes: they can only
 * ever answer "does this plaintext match," never recover the plaintext.
 * HMAC request verification (see `middleware/apiKey.ts`) needs the
 * server to actually POSSESS the raw secret to recompute a signature —
 * a one-way hash cannot do that job. AES-256-GCM here is the standard
 * primitive for "store a secret encrypted at rest, decrypt it when a
 * real operation needs the raw value" (the same pattern AWS/Stripe-style
 * platforms use for API secrets that back HMAC signing).
 *
 * `CREDENTIAL_ENCRYPTION_KEY` (.env) is the server-side master key — a
 * 32-byte value, hex-encoded (64 hex chars). Generate one with:
 *   openssl rand -hex 32
 * Losing/rotating this key invalidates every already-issued credential's
 * ability to be decrypted — treat it with the same care as a database
 * root password, and back it up outside of source control.
 */

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH_BYTES = 12; // 96-bit nonce, the recommended size for GCM

function loadMasterKey(): Buffer {
  const hex = process.env.CREDENTIAL_ENCRYPTION_KEY;
  if (!hex) {
    throw new Error(
      "CREDENTIAL_ENCRYPTION_KEY is not set — generate one with `openssl rand -hex 32` and add it to .env",
    );
  }
  const key = Buffer.from(hex, "hex");
  if (key.length !== 32) {
    throw new Error(
      `CREDENTIAL_ENCRYPTION_KEY must decode to exactly 32 bytes (64 hex chars); got ${key.length} bytes`,
    );
  }
  return key;
}

/**
 * Encrypts `plaintext`, returning a single self-contained string:
 * `<iv-hex>:<authTag-hex>:<ciphertext-hex>`. Each field is fixed-format
 * hex so the stored value is safely printable/storable as a plain
 * Postgres `String` column with no binary-encoding concerns.
 */
export function encryptSecret(plaintext: string): string {
  const key = loadMasterKey();
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${authTag.toString("hex")}:${ciphertext.toString("hex")}`;
}

/**
 * Inverse of [encryptSecret]. Throws on any malformed input or a failed
 * GCM authentication check (tampered ciphertext, wrong key) — a caller
 * must treat any thrown error as "this credential cannot be verified,"
 * never silently proceed.
 */
export function decryptSecret(stored: string): string {
  const key = loadMasterKey();
  const parts = stored.split(":");
  if (parts.length !== 3) {
    throw new Error("Malformed encrypted secret — expected iv:authTag:ciphertext");
  }
  const [ivHex, authTagHex, ciphertextHex] = parts;
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const ciphertext = Buffer.from(ciphertextHex, "hex");

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}
