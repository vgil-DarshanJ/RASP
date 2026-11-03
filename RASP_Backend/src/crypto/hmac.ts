import crypto from "node:crypto";

/**
 * The exact wire contract every SDK (Kotlin's `RaspEventShipper`, Dart's
 * `RaspSecurityEventShipper`) must reproduce byte-for-byte:
 *
 *   signingString = "<X-Timestamp>.<raw request body bytes>"
 *   X-Signature   = hex(HMAC-SHA256(apiSecret, signingString))
 *
 * `rawBody` MUST be the exact bytes sent on the wire — not a
 * re-serialization of the parsed JSON, which could differ in whitespace
 * or key order from what the client actually signed. See `app.ts`'s
 * `express.json({ verify })` for how those exact bytes are captured
 * before Express's JSON parser normalizes them into an object.
 */
export function computeSignature(apiSecret: string, timestamp: string, rawBody: Buffer): string {
  const signingString = Buffer.concat([
    Buffer.from(`${timestamp}.`, "utf8"),
    rawBody,
  ]);
  return crypto.createHmac("sha256", apiSecret).update(signingString).digest("hex");
}

const SIGNATURE_HEX = /^[0-9a-fA-F]{64}$/;

/**
 * The one accepted spelling of an `X-Signature`: exactly 64 hex characters,
 * returned lower-cased; `null` for anything else (padding, junk after the
 * digest, odd length, other encodings).
 *
 * `Buffer.from(x, "hex")` ignores case and silently drops everything from the
 * first non-hex character on, so without this check one captured signature
 * could be re-sent as many different header strings (upper-cased, with
 * trailing junk) that all decode to the same digest, and each would pass a
 * replay cache keyed by the raw header (F-01). The replay cache is keyed by
 * this canonical form instead.
 */
export function canonicalSignature(header: string): string | null {
  return SIGNATURE_HEX.test(header) ? header.toLowerCase() : null;
}

/** Constant-time comparison — a plain `===`/string-equality check on a
 *  MAC leaks timing information proportional to how many leading bytes
 *  match, which a patient attacker can exploit to forge a valid signature
 *  byte-by-byte. `crypto.timingSafeEqual` closes that side channel. Both
 *  values must be well-formed 64-hex-character digests (see
 *  [canonicalSignature]); anything else never matches. */
export function signaturesMatch(a: string, b: string): boolean {
  const canonicalA = canonicalSignature(a);
  const canonicalB = canonicalSignature(b);
  if (canonicalA === null || canonicalB === null) return false;
  return crypto.timingSafeEqual(Buffer.from(canonicalA, "hex"), Buffer.from(canonicalB, "hex"));
}

/** Rejects a timestamp more than [toleranceMs] away from the server's own
 *  clock, in either direction — bounds how long a captured
 *  request+signature pair remains even theoretically replayable, before
 *  the Redis-backed nonce cache (see `redis/replayGuard.ts`) closes the
 *  rest of that window. */
export function isTimestampFresh(timestampMs: number, toleranceMs = 5 * 60 * 1000): boolean {
  const drift = Math.abs(Date.now() - timestampMs);
  return drift <= toleranceMs;
}
