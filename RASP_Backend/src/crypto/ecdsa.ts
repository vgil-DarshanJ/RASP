import crypto from "node:crypto";

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

export interface AttestationInspection {
  status: AttestationStatus;
  chainLength: number;
  /** Leaf certificate's public key equals the registered key. */
  leafMatchesKey: boolean;
  /** Every certificate is signed by the next one (a single cert: signed by itself). */
  chainLinked: boolean;
  /** One self-signed certificate: the key exists but nothing attests where it lives. */
  selfSignedOnly: boolean;
  /** Leaf carries the Android key attestation extension (1.3.6.1.4.1.11129.2.1.17). */
  hasKeyAttestationExtension: boolean;
  /** Always false for now: the chain is not yet checked against the Google attestation roots. */
  rootVerified: false;
  error?: string;
}

/**
 * Parses an attestation chain (Base64 DER, leaf first) and reports what it
 * shows about [spkiDer]. Recording only — this does not decide whether the
 * key is trusted; verification against the Google attestation roots and the
 * extension's boot-state fields is a later, separate check.
 */
export function inspectAttestationChain(spkiDer: Buffer, chainBase64: string[]): AttestationInspection {
  const base: AttestationInspection = {
    status: "UNPARSEABLE",
    chainLength: chainBase64.length,
    leafMatchesKey: false,
    chainLinked: false,
    selfSignedOnly: false,
    hasKeyAttestationExtension: false,
    rootVerified: false,
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

  return {
    ...base,
    status: leafMatchesKey ? "PARSED" : "KEY_MISMATCH",
    leafMatchesKey,
    chainLinked,
    selfSignedOnly: certs.length === 1 && chainLinked,
    hasKeyAttestationExtension: leaf.raw.includes(KEY_ATTESTATION_OID_DER),
  };
}
