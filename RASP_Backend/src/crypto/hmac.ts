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

/** Constant-time comparison — a plain `===`/string-equality check on a
 *  MAC leaks timing information proportional to how many leading bytes
 *  match, which a patient attacker can exploit to forge a valid signature
 *  byte-by-byte. `crypto.timingSafeEqual` closes that side channel. Both
 *  buffers must be equal length first (checked here) since the function
 *  itself throws on a length mismatch rather than returning false. */
export function signaturesMatch(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
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
