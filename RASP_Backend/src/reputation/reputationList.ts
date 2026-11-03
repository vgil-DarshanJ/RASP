import crypto from "node:crypto";
import { readFileSync, statSync } from "node:fs";

/**
 * The malware reputation list the SDK's `malware_reputation` detector
 * downloads (GET /v1/reputation/list), signed with Ed25519 in the format
 * the engine verifies (RaspMalwareReputationProbes):
 *   { "payload": "<JSON text>", "signature": "<Base64 Ed25519 over the payload bytes>" }
 * payload: { "version": <integer>, "entries": [ { "package", "category", "severity" } ] }
 *
 * Configuration (both needed, otherwise the endpoint answers 404):
 * - REPUTATION_LIST_PATH: a JSON file with the payload above, maintained by
 *   the operator from a threat-intelligence source. Raise `version` on
 *   every change: devices ignore lists older than the one they have.
 * - REPUTATION_SIGNING_KEY: the Ed25519 private key, Base64 of PKCS#8 DER
 *   (`npm run reputation:keygen` prints a new pair). Its public key is put
 *   into newly issued credentials as `reputation_public_key`; apps that pin
 *   their own key in RaspLeanConfig.malwareReputationPublicKey need it too.
 *
 * The file is re-read and re-signed only when it changes (mtime).
 */
export interface ReputationEntry {
  package: string;
  category?: string;
  severity?: string;
}

export type SignedList = { payload: string; signature: string };

export type ListResult =
  | { ok: true; list: SignedList; version: number; entries: number }
  | { ok: false; error: "REPUTATION_LIST_NOT_CONFIGURED" | "REPUTATION_LIST_INVALID" };

let cache: { path: string; mtimeMs: number; keyFingerprint: string; result: ListResult } | null = null;

function signingKey(): crypto.KeyObject | null {
  const raw = process.env.REPUTATION_SIGNING_KEY?.trim();
  if (!raw) return null;
  try {
    const key = crypto.createPrivateKey({ key: Buffer.from(raw, "base64"), format: "der", type: "pkcs8" });
    return key.asymmetricKeyType === "ed25519" ? key : null;
  } catch {
    return null;
  }
}

/** Base64 X.509 SPKI of the signing key's public half, or null when not configured. */
export function reputationPublicKey(): string | null {
  const key = signingKey();
  if (!key) return null;
  return (crypto.createPublicKey(key).export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

/** Validates a payload object; the canonical text that gets signed. */
export function payloadText(value: unknown): string | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as { version?: unknown; entries?: unknown };
  if (!Number.isInteger(v.version) || (v.version as number) < 0 || !Array.isArray(v.entries)) return null;
  const entries: ReputationEntry[] = [];
  for (const e of v.entries) {
    if (typeof e !== "object" || e === null) return null;
    const pkg = (e as { package?: unknown }).package;
    if (typeof pkg !== "string" || !/^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(pkg) || pkg.length > 255) return null;
    const category = (e as { category?: unknown }).category;
    const severity = (e as { severity?: unknown }).severity;
    entries.push({
      package: pkg,
      ...(typeof category === "string" ? { category: category.slice(0, 64) } : {}),
      ...(typeof severity === "string" ? { severity: severity.slice(0, 16) } : {}),
    });
  }
  return JSON.stringify({ version: v.version, entries });
}

export function signList(payload: string, key: crypto.KeyObject): SignedList {
  return { payload, signature: crypto.sign(null, Buffer.from(payload, "utf8"), key).toString("base64") };
}

/** The current signed list. */
export function currentList(): ListResult {
  const path = process.env.REPUTATION_LIST_PATH?.trim();
  const key = signingKey();
  if (!path || !key) return { ok: false, error: "REPUTATION_LIST_NOT_CONFIGURED" };
  let mtimeMs: number;
  try {
    mtimeMs = statSync(path).mtimeMs;
  } catch {
    return { ok: false, error: "REPUTATION_LIST_NOT_CONFIGURED" };
  }
  const keyFingerprint = reputationPublicKey() ?? "";
  if (cache && cache.path === path && cache.mtimeMs === mtimeMs && cache.keyFingerprint === keyFingerprint) return cache.result;

  let result: ListResult;
  try {
    const text = payloadText(JSON.parse(readFileSync(path, "utf8")));
    if (text === null) {
      result = { ok: false, error: "REPUTATION_LIST_INVALID" };
    } else {
      const parsed = JSON.parse(text) as { version: number; entries: unknown[] };
      result = { ok: true, list: signList(text, key), version: parsed.version, entries: parsed.entries.length };
    }
  } catch {
    result = { ok: false, error: "REPUTATION_LIST_INVALID" };
  }
  cache = { path, mtimeMs, keyFingerprint, result };
  return result;
}

/** For tests. */
export function resetReputationCacheForTests() {
  cache = null;
}
