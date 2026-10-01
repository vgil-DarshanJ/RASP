import crypto from "node:crypto";

/**
 * ECDSA P-256 (ES256) signature verification for evidence envelopes.
 *
 * The SDK signs the canonical JSON of the envelope body with the
 * device's hardware-backed EC P-256 private key (see `android_core`'s
 * `RaspDeviceKey`). The public key is registered via `POST /v1/devices/register`
 * and stored as a Base64-encoded X.509 SPKI.
 *
 * This module handles:
 * - Importing the Base64-encoded X.509 SPKI public key
 * - Verifying ECDSA signatures over canonical JSON bodies
 * - The signature is Base64-encoded DER (ASN.1 SEQUENCE of r,s)
 */
export function verifyEnvelopeSignature(
  publicKeyBase64: string,
  body: string,
  signatureBase64: string,
): boolean {
  try {
    // Import the public key from Base64-encoded X.509 SPKI
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(publicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });

    // The signature is Base64-encoded DER (ASN.1 SEQUENCE of r,s)
    const signature = Buffer.from(signatureBase64, "base64");

    // Verify the signature over the UTF-8 body
    const verifier = crypto.createVerify("SHA256");
    verifier.update(body, "utf8");
    return verifier.verify(publicKey, signature);
  } catch (err) {
    // Any error (malformed key, malformed signature, wrong curve) = verification failure
    return false;
  }
}

/**
 * Canonicalizes a JSON string by sorting object keys recursively.
 * This must match the SDK's canonicalization exactly.
 */
export function canonicalizeJson(json: string): string {
  const obj = JSON.parse(json);
  return JSON.stringify(canonicalizeValue(obj));
}

function canonicalizeValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalizeValue);
  }
  // Object: sort keys
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = canonicalizeValue((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * Parses the attestation certificate chain (Base64-encoded DER certificates)
 * and verifies the leaf certificate's public key matches the registered SPKI.
 * This is a best-effort check — the Android Keystore attestation is complex
 * and we only do a basic sanity check here.
 */
export function verifyAttestationChain(
  spkiBase64: string,
  attestationChainBase64: string[],
): boolean {
  if (attestationChainBase64.length === 0) return false;

  try {
    // Parse the leaf certificate (first in chain)
    const leafDer = Buffer.from(attestationChainBase64[0], "base64");
    const cert = new crypto.X509Certificate(leafDer);

    // Get the public key from the certificate
    const certPublicKey = cert.publicKey;

    // Export as SPKI and compare
    const certSpki = certPublicKey.export({ type: "spki", format: "der" });
    const registeredSpki = Buffer.from(spkiBase64, "base64");

    return certSpki.equals(registeredSpki);
  } catch {
    return false;
  }
}