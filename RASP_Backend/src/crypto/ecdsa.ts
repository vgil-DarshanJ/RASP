import crypto from "node:crypto";
import { attestationExtension, KeyDescriptionInfo, parseKeyDescription } from "./keyAttestation";
import { attestationTrust, isTrustedRoot, normalizeSerial } from "./attestationTrust";

/**
 * ECDSA P-256 (ES256) signature verification for evidence envelopes.
 *
 * The SDK signs the canonical JSON of the envelope (every field except
 * `signature`) with the device's hardware-backed EC P-256 private key (see
 * `android_core`'s `RaspDeviceKey`). The public key is registered via
 * `POST /v1/devices/register` and stored as a Base64-encoded X.509 SPKI.
 *
 * The signature is Base64-encoded DER (ASN.1 SEQUENCE of r,s).
 */
export function verifyEnvelopeSignature(
  publicKeyBase64: string,
  body: string,
  signatureBase64: string,
): boolean {
  try {
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(publicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });
    const signature = Buffer.from(signatureBase64, "base64");
    const verifier = crypto.createVerify("SHA256");
    verifier.update(body, "utf8");
    return verifier.verify(publicKey, signature);
  } catch {
    // Any error (malformed key, malformed signature, wrong curve) = verification failure
    return false;
  }
}

/**
 * Canonicalizes a JSON string by sorting object keys recursively.
 * This must match the SDK's canonicalization exactly
 * (`android_core`'s `RaspCanonicalJson`).
 */
export function canonicalizeJson(json: string): string {
  return canonicalStringify(JSON.parse(json));
}

/** `JSON.stringify` of [value] with object keys sorted recursively. */
export function canonicalStringify(value: unknown): string {
  return JSON.stringify(canonicalizeValue(value));
}

function canonicalizeValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalizeValue);
  }
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = canonicalizeValue((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

/** Base64(SHA-256(SPKI DER)) — the device key id envelopes are looked up by. */
export function computeDeviceKeyId(spkiDer: Buffer): string {
  return crypto.createHash("sha256").update(spkiDer).digest("base64");
}

export type PublicKeyCheck =
  | { ok: true; spkiDer: Buffer }
  | { ok: false; reason: string };

/**
 * Accepts only a canonical Base64 X.509 SPKI of an EC P-256 key — the form
 * Android's `PublicKey.getEncoded()` produces and the SDK hashes for its key id.
 */
export function parseEcP256PublicKey(publicKeyBase64: string): PublicKeyCheck {
  const der = Buffer.from(publicKeyBase64, "base64");
  if (der.length === 0 || der.toString("base64") !== publicKeyBase64) {
    return { ok: false, reason: "not canonical Base64" };
  }
  try {
    const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      return { ok: false, reason: "not an EC P-256 key" };
    }
    return { ok: true, spkiDer: der };
  } catch {
    return { ok: false, reason: "not an X.509 SubjectPublicKeyInfo" };
  }
}

/** DER of OID 1.3.6.1.4.1.11129.2.1.17 — the Android key attestation extension. */
const KEY_ATTESTATION_OID_DER = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11]);

export type AttestationStatus = "PARSED" | "KEY_MISMATCH" | "UNPARSEABLE";

/**
 * Recorded on the device row; the application's attestation policy decides
 * whether a registration needs `verified` (see devices/registration.ts).
 * - `verified`: the chain parses, its leaf is the registered key, each
 *   certificate is signed by the next and ends at a Google hardware
 *   attestation root, the intermediate and root certificates are within
 *   their validity at registration time, none is on the revocation list
 *   (when the list could be checked), and the leaf's attestation extension
 *   reports a hardware security level (TEE or StrongBox).
 * - `software-only`: the chain parses and the leaf is the registered key,
 *   but there is no hardware attestation (no extension, Software level, or
 *   a single self-signed certificate).
 * - `unverified`: anything else (unparseable, different key, broken chain,
 *   a root other than Google's, an expired or revoked certificate,
 *   unreadable extension).
 */
export type AttestationVerdict = "verified" | "unverified" | "software-only";

export interface AttestationInspection {
  verdict: AttestationVerdict;
  status: AttestationStatus;
  /** From the leaf's KeyDescription: 0 Software, 1 TEE, 2 StrongBox; `null` when absent/unreadable. */
  attestationSecurityLevel: number | null;
  chainLength: number;
  /** Leaf certificate's public key equals the registered key. */
  leafMatchesKey: boolean;
  /** Every certificate is signed by the next one (a single cert: signed by itself). */
  chainLinked: boolean;
  /** One self-signed certificate: the key exists but nothing attests where it lives. */
  selfSignedOnly: boolean;
  /** Leaf carries the Android key attestation extension (1.3.6.1.4.1.11129.2.1.17). */
  hasKeyAttestationExtension: boolean;
  /** The linked chain ends at a Google hardware attestation root (by public key). */
  rootVerified: boolean;
  /** Every certificate but the leaf is valid at registration time (leaf validity is not meaningful on Android). */
  validityOk: boolean;
  /** The revocation list was available and checked. */
  revocationChecked: boolean;
  /** Serial numbers in the chain that the revocation list names. */
  revokedSerials: string[];
  /** Read from the leaf's KeyDescription; trustworthy only when `rootVerified`. */
  attestedPackages: string[];
  attestedSigningCertSha256: string[];
  attestationChallengeHex: string | null;
  deviceLocked: boolean | null;
  verifiedBootState: string | null;
  osPatchLevel: number | null;
  error?: string;
}

export interface InspectOptions {
  /** Trusted roots (default: Google's). */
  roots?: crypto.X509Certificate[];
  /** Revocation list entries; `null` when the list is not available. */
  revoked?: Map<string, string> | null;
  /** Time of the check (validity). Default: now. */
  now?: Date;
}

/**
 * Parses and verifies an attestation chain (Base64 DER, leaf first) for
 * [spkiDer]. Pure: the revocation list is passed in (see
 * crypto/attestationTrust.ts for fetching it).
 */
export function inspectAttestationChain(spkiDer: Buffer, chainBase64: string[], options: InspectOptions = {}): AttestationInspection {
  const roots = options.roots ?? attestationTrust.roots;
  const now = options.now ?? new Date();
  const base: AttestationInspection = {
    verdict: "unverified",
    status: "UNPARSEABLE",
    attestationSecurityLevel: null,
    chainLength: chainBase64.length,
    leafMatchesKey: false,
    chainLinked: false,
    selfSignedOnly: false,
    hasKeyAttestationExtension: false,
    rootVerified: false,
    validityOk: false,
    revocationChecked: false,
    revokedSerials: [],
    attestedPackages: [],
    attestedSigningCertSha256: [],
    attestationChallengeHex: null,
    deviceLocked: null,
    verifiedBootState: null,
    osPatchLevel: null,
  };
  if (chainBase64.length === 0) return { ...base, error: "empty chain" };

  let certs: crypto.X509Certificate[];
  try {
    certs = chainBase64.map((b64) => new crypto.X509Certificate(Buffer.from(b64, "base64")));
  } catch (err) {
    return { ...base, error: err instanceof Error ? err.message : "certificate parse failed" };
  }

  const leaf = certs[0];
  const leafSpki = leaf.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const leafMatchesKey = leafSpki.equals(spkiDer);

  let chainLinked: boolean;
  try {
    chainLinked = certs.length === 1
      ? leaf.verify(leaf.publicKey)
      : certs.slice(0, -1).every((cert, i) => cert.verify(certs[i + 1].publicKey));
  } catch {
    chainLinked = false;
  }
  const last = certs[certs.length - 1];
  let rootSelfSigned = false;
  try {
    rootSelfSigned = last.verify(last.publicKey);
  } catch {
    rootSelfSigned = false;
  }
  const rootVerified = chainLinked && certs.length > 1 && rootSelfSigned && isTrustedRoot(last, roots);

  const nowMs = now.getTime();
  const validityOk = certs.slice(1).every((c) => Date.parse(c.validFrom) <= nowMs && nowMs <= Date.parse(c.validTo));

  const revoked = options.revoked ?? null;
  const revokedSerials = revoked ? certs.map((c) => normalizeSerial(c.serialNumber)).filter((s) => revoked.has(s)) : [];

  let extension: Buffer | null = null;
  let description: KeyDescriptionInfo | null = null;
  let extensionError: string | undefined;
  try {
    extension = attestationExtension(leaf.raw);
    if (extension) description = parseKeyDescription(extension);
  } catch (err) {
    extensionError = err instanceof Error ? err.message : "attestation extension unreadable";
  }
  const securityLevel = description?.attestationSecurityLevel ?? null;
  const selfSignedOnly = certs.length === 1 && chainLinked;

  let verdict: AttestationVerdict;
  if (!leafMatchesKey || !chainLinked || extensionError) verdict = "unverified";
  else if (selfSignedOnly || extension === null || securityLevel === 0) verdict = "software-only";
  else if ((securityLevel === 1 || securityLevel === 2) && rootVerified && validityOk && revokedSerials.length === 0) verdict = "verified";
  else verdict = "unverified";

  return {
    ...base,
    verdict,
    status: leafMatchesKey ? "PARSED" : "KEY_MISMATCH",
    attestationSecurityLevel: securityLevel,
    leafMatchesKey,
    chainLinked,
    selfSignedOnly,
    hasKeyAttestationExtension: extension !== null || leaf.raw.includes(KEY_ATTESTATION_OID_DER),
    rootVerified,
    validityOk,
    revocationChecked: revoked !== null,
    revokedSerials,
    attestedPackages: description?.attestedPackages ?? [],
    attestedSigningCertSha256: description?.attestedSigningCertSha256 ?? [],
    attestationChallengeHex: description?.attestationChallengeHex ?? null,
    deviceLocked: description?.deviceLocked ?? null,
    verifiedBootState: description?.verifiedBootState ?? null,
    osPatchLevel: description?.osPatchLevel ?? null,
    ...(extensionError ? { error: extensionError } : {}),
  };
}
