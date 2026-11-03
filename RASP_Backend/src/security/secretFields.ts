import util from "node:util";
import { decryptSecret } from "../crypto/secretBox";

/**
 * Secret values this API holds, and the one rule for them: a secret is
 * returned in full only by the response that creates or rotates it —
 * `POST /v1/credentials/applications/:id/credentials` (`api_secret`,
 * `account_hash_salt`) and the webhook create / rotate-secret responses
 * (`secret`). Every other response either leaves it out or shows a masked
 * prefix (`*Masked` fields, see [maskSecret]); logs get [redactSecrets].
 *
 * Field names, in database rows and in credential JSON:
 * - `apiSecretEncrypted` / `api_secret` — the credential's HMAC secret;
 * - `accountHashSalt` / `account_hash_salt` — the SDK's id-hash salt;
 * - `secretEncrypted` / `secret` — the webhook signing secret;
 * - `passwordHash` / `password` — user passwords;
 * - `CONFIG_SIGNING_KEY` / `REPUTATION_SIGNING_KEY` / `privateKey` — the
 *   server's Ed25519 signing keys, which no response returns at all (only
 *   their public halves, `config_public_key` / `reputation_public_key`).
 */
export const SECRET_FIELD_NAMES = [
  "apiSecret",
  "api_secret",
  "apiSecretEncrypted",
  "accountHashSalt",
  "account_hash_salt",
  "secret",
  "secretEncrypted",
  "passwordHash",
  "password",
  // Server signing keys (remote config, reputation list): environment only, never in a response.
  "CONFIG_SIGNING_KEY",
  "REPUTATION_SIGNING_KEY",
  "privateKey",
  "private_key",
  "signingKey",
] as const;

const SECRET_FIELD_SET = new Set<string>(SECRET_FIELD_NAMES.map((name) => name.toLowerCase()));

export function isSecretFieldName(name: string | null | undefined): boolean {
  return typeof name === "string" && SECRET_FIELD_SET.has(name.toLowerCase());
}

/** How many leading characters a masked value keeps. */
export const MASK_VISIBLE_CHARS = 4;

/**
 * `"9f3a…"` — the first [MASK_VISIBLE_CHARS] characters and an ellipsis, so
 * someone can tell which secret they hold without the API returning it.
 * Values shorter than 16 characters keep no prefix (`"…"`); `null` stays null.
 */
export function maskSecret(value: string | null | undefined): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  return value.length < 16 ? "…" : `${value.slice(0, MASK_VISIBLE_CHARS)}…`;
}

/** [maskSecret] of a value stored with `encryptSecret`; `null` if it cannot be decrypted. */
export function maskEncryptedSecret(stored: string | null | undefined): string | null {
  if (typeof stored !== "string" || stored.length === 0) return null;
  try {
    return maskSecret(decryptSecret(stored));
  } catch {
    return null;
  }
}

/**
 * The application fields any response may carry: everything except the
 * account-hash salt. An allow-list (Prisma `select`), so a column added
 * later is not returned until it is listed here.
 */
export const PUBLIC_APPLICATION_SELECT = {
  id: true,
  name: true,
  platform: true,
  organizationId: true,
  createdAt: true,
  archivedAt: true,
  expectedSigningCertSha256: true,
  ipBlockedCountries: true,
  ipAllowedCountries: true,
  riskRules: true,
} as const;

const KEY_PATTERN = SECRET_FIELD_NAMES.join("|");
// key: "value" / key: 'value' / "key":"value" / key=value — the value is replaced.
const QUOTED_VALUE = new RegExp(`\\b(${KEY_PATTERN})\\b(["']?\\s*[:=]\\s*)(["'\`])(?:\\\\.|(?!\\3)[^\\\\])*\\3`, "gi");
const BARE_VALUE = new RegExp(`\\b(${KEY_PATTERN})\\b(["']?\\s*[:=]\\s*)(?!["'\`\\[{]|\\[REDACTED\\]|null\\b|undefined\\b)([^\\s,;}\\])]+)`, "gi");

/**
 * Replaces the value after any secret field name in [text] with
 * `[REDACTED]` — for error messages that echo arguments (Prisma validation
 * errors print the `data` they were given) before they reach a log.
 */
export function redactSecrets(text: string): string {
  return text.replace(QUOTED_VALUE, "$1$2\"[REDACTED]\"").replace(BARE_VALUE, "$1$2[REDACTED]");
}

/** `console.error(prefix, err)` with secret values redacted from the message, stack and properties. */
export function logError(prefix: string, err: unknown): void {
  const text = err instanceof Error
    ? `${err.stack ?? `${err.name}: ${err.message}`}${Object.keys(err).length > 0 ? ` ${util.inspect({ ...err }, { depth: 4 })}` : ""}`
    : util.inspect(err, { depth: 4 });
  console.error(prefix, redactSecrets(text));
}
