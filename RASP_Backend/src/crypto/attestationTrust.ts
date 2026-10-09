import crypto from "node:crypto";
import { GOOGLE_ATTESTATION_ROOTS_PEM } from "./googleAttestationRoots";

/**
 * What an attestation chain is checked against (F-13): the Google hardware
 * attestation roots and Google's attestation revocation list.
 *
 * The revocation list (https://android.googleapis.com/attestation/status,
 * override with ATTESTATION_STATUS_URL) lists revoked or suspended
 * attestation certificates by serial number, for example keys leaked from a
 * device model. It is fetched by this server, kept for 24 hours, and a stale
 * copy is used for up to 7 days when Google cannot be reached. Never
 * contacted from the device. ATTESTATION_REVOCATION_CHECK=off skips it
 * (air-gapped test setups only).
 *
 * Tests replace `attestationTrust.roots` and `attestationTrust.statusSource`.
 */

const LIST_TTL_MS = 24 * 60 * 60 * 1000;
const LIST_MAX_STALE_MS = 7 * LIST_TTL_MS;
const FETCH_TIMEOUT_MS = 5000;

export interface RevocationList {
  /** Serial numbers (lower-case hex, no leading zeros) → status (REVOKED, SUSPENDED). */
  entries: Map<string, string>;
  fetchedAt: number;
}

export type StatusSource = () => Promise<RevocationList | null>;

let cached: RevocationList | null = null;
let inflight: Promise<RevocationList | null> | null = null;

/** Lower-case hex without leading zeros, the form the revocation list uses. */
export function normalizeSerial(serial: string): string {
  const hex = serial.toLowerCase().replace(/[^0-9a-f]/g, "").replace(/^0+/, "");
  return hex === "" ? "0" : hex;
}

async function fetchStatusList(): Promise<RevocationList | null> {
  const url = process.env.ATTESTATION_STATUS_URL || "https://android.googleapis.com/attestation/status";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { "Cache-Control": "no-cache" } });
    if (!res.ok) return null;
    const body = (await res.json()) as { entries?: Record<string, { status?: string }> };
    const entries = new Map<string, string>();
    for (const [serial, entry] of Object.entries(body.entries ?? {})) {
      entries.set(normalizeSerial(serial), String(entry?.status ?? "REVOKED"));
    }
    return { entries, fetchedAt: Date.now() };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** The revocation list (cached), or null when none is available. */
async function defaultStatusSource(): Promise<RevocationList | null> {
  const now = Date.now();
  if (cached && now - cached.fetchedAt < LIST_TTL_MS) return cached;
  if (!inflight) {
    inflight = fetchStatusList().finally(() => {
      inflight = null;
    });
  }
  const fresh = await inflight;
  if (fresh) cached = fresh;
  if (cached && now - cached.fetchedAt < LIST_MAX_STALE_MS) return cached;
  return null;
}

function loadRoots(): crypto.X509Certificate[] {
  return GOOGLE_ATTESTATION_ROOTS_PEM.map((pem) => new crypto.X509Certificate(pem));
}

export const attestationTrust: {
  roots: crypto.X509Certificate[];
  statusSource: StatusSource;
} = {
  roots: loadRoots(),
  statusSource: defaultStatusSource,
};

export function revocationCheckEnabled(): boolean {
  return (process.env.ATTESTATION_REVOCATION_CHECK || "on").trim().toLowerCase() !== "off";
}

/** `true` when [cert]'s public key is one of the trusted roots' keys. */
export function isTrustedRoot(cert: crypto.X509Certificate, roots = attestationTrust.roots): boolean {
  const spki = cert.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return roots.some((root) => (root.publicKey.export({ type: "spki", format: "der" }) as Buffer).equals(spki));
}

/** For tests: forget the cached list. */
export function resetRevocationCacheForTests() {
  cached = null;
  inflight = null;
}
