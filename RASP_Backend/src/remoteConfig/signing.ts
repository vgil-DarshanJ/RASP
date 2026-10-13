import crypto from "node:crypto";
import { normalizeSettings, RemoteSettings } from "./settings";

/**
 * Signs remote configurations (Task 10.0) with Ed25519, in the format the
 * engine verifies (RaspRemoteConfig.kt, same envelope as the malware list):
 *
 *   { "payload": "<JSON text>", "signature": "<Base64 Ed25519 over the UTF-8 payload bytes>", "keyId": "<16 hex>" }
 *
 * payload:
 *   { "schema": 1, "applicationId": "...", "version": 7,
 *     "issuedAt": "<ISO>", "expiresAt": "<ISO>", "settings": { ... } }
 *
 * `applicationId` binds a config to one application, so a valid config of
 * another application (same signing key) is refused by the phone. `version`
 * and `expiresAt` make an old config useless for a replay.
 *
 * CONFIG_SIGNING_KEY: the private key, Base64 of PKCS#8 DER, from
 * `npm run config:keygen`. Only in the server's environment; never in the
 * repository, a log, a response or the dashboard. Its public half goes into
 * newly issued credentials as `config_public_key`.
 */
export const REMOTE_CONFIG_SCHEMA = 1;

export interface RemoteConfigRow {
  applicationId: string;
  version: number;
  createdAt: Date;
  expiresAt: Date;
  payload: unknown;
}

export interface SignedConfig {
  payload: string;
  signature: string;
  keyId: string;
}

let cached: { raw: string; key: crypto.KeyObject | null } | null = null;

/** The configured signing key, or null when CONFIG_SIGNING_KEY is missing or not an Ed25519 PKCS#8 key. */
export function configSigningKey(env: NodeJS.ProcessEnv = process.env): crypto.KeyObject | null {
  const raw = env.CONFIG_SIGNING_KEY?.trim() ?? "";
  if (cached && cached.raw === raw) return cached.key;
  let key: crypto.KeyObject | null = null;
  if (raw) {
    try {
      const k = crypto.createPrivateKey({ key: Buffer.from(raw, "base64"), format: "der", type: "pkcs8" });
      key = k.asymmetricKeyType === "ed25519" ? k : null;
    } catch {
      key = null;
    }
  }
  cached = { raw, key };
  return key;
}

function spki(key: crypto.KeyObject): Buffer {
  return crypto.createPublicKey(key).export({ type: "spki", format: "der" }) as Buffer;
}

/** Base64 X.509 SPKI of the public half, or null when not configured. Public, safe to show. */
export function configPublicKey(env: NodeJS.ProcessEnv = process.env): string | null {
  const key = configSigningKey(env);
  return key ? spki(key).toString("base64") : null;
}

/** First 16 hex of SHA-256 over the public SPKI: names the key without revealing anything. */
export function configKeyId(env: NodeJS.ProcessEnv = process.env): string | null {
  const key = configSigningKey(env);
  return key ? crypto.createHash("sha256").update(spki(key)).digest("hex").slice(0, 16) : null;
}

/** The exact text that is signed; fields always in this order. */
export function configPayloadText(row: RemoteConfigRow): string {
  return JSON.stringify({
    schema: REMOTE_CONFIG_SCHEMA,
    applicationId: row.applicationId,
    version: row.version,
    issuedAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    settings: normalizeSettings((row.payload ?? {}) as RemoteSettings),
  });
}

export function signConfig(row: RemoteConfigRow, key: crypto.KeyObject): SignedConfig {
  const payload = configPayloadText(row);
  const keyId = crypto.createHash("sha256").update(spki(key)).digest("hex").slice(0, 16);
  return { payload, signature: crypto.sign(null, Buffer.from(payload, "utf8"), key).toString("base64"), keyId };
}

/** For tests. */
export function resetConfigKeyCacheForTests() {
  cached = null;
}
