import { NextFunction, Request, Response } from "express";
import { prisma } from "../db/prisma";
import { decryptSecret } from "../crypto/secretBox";
import { computeSignature, isTimestampFresh, signaturesMatch } from "../crypto/hmac";
import { checkAndRecordSignature } from "../redis/replayGuard";

export interface ApiKeyedRequest extends Request {
  applicationId?: string;
  /** Raw request body bytes, captured by `express.json({ verify })` in
   *  `app.ts` — required here because the HMAC was computed by the SDK
   *  over the exact bytes it sent, which can differ from a
   *  re-serialization of the parsed JSON (whitespace, key order). */
  rawBody?: Buffer;
}

/**
 * Authenticates the SDK's own ingestion calls with three checks, in
 * order, each a real gate (not defense-in-depth theater):
 *
 * 1. `X-Api-Key` identifies which credential/application this is —
 *    looked up fresh on every request, so a revoked key stops working
 *    immediately.
 * 2. `X-Signature` (HMAC-SHA256 over `X-Timestamp + rawBody`, keyed by
 *    the credential's secret) proves the caller actually possesses the
 *    secret, not just the key — this is the fix for the finding that a
 *    leaked `api_key` alone used to be sufficient. See `crypto/hmac.ts`.
 * 3. Timestamp freshness + a Redis-backed replay cache reject a captured
 *    request+signature pair being resent — even within the freshness
 *    window, the exact same signature can only ever be used once.
 *
 * Any single failure is a 401 — there is no partial-credit path.
 */
export async function requireApiKey(
  req: ApiKeyedRequest,
  res: Response,
  next: NextFunction,
) {
  const apiKey = req.header("X-Api-Key");
  const signature = req.header("X-Signature");
  const timestampHeader = req.header("X-Timestamp");

  if (!apiKey) return res.status(401).json({ error: "MISSING_API_KEY" });
  if (!signature) return res.status(401).json({ error: "MISSING_SIGNATURE" });
  if (!timestampHeader) return res.status(401).json({ error: "MISSING_TIMESTAMP" });

  const timestampMs = Number(timestampHeader);
  if (!Number.isFinite(timestampMs)) {
    return res.status(401).json({ error: "INVALID_TIMESTAMP" });
  }

  const toleranceMs =
    (Number(process.env.INGESTION_SIGNATURE_TOLERANCE_SECONDS) || 300) * 1000;
  if (!isTimestampFresh(timestampMs, toleranceMs)) {
    return res.status(401).json({ error: "STALE_TIMESTAMP" });
  }

  let credential;
  try {
    credential = await prisma.apiCredential.findUnique({
      where: { apiKey },
      include: { application: { select: { archivedAt: true } } },
    });
  } catch (err) {
    console.error("[apiKey] lookup failed:", err);
    return res.status(503).json({ error: "AUTH_BACKEND_UNAVAILABLE" });
  }

  if (!credential || credential.status !== "ACTIVE") {
    return res.status(401).json({ error: "INVALID_OR_REVOKED_API_KEY" });
  }
  // An archived application is a decommissioned integration — its SDK
  // should stop being able to ship new events the same way a revoked
  // credential does, even though the credential row itself is untouched.
  if (credential.application.archivedAt) {
    return res.status(401).json({ error: "APPLICATION_ARCHIVED" });
  }

  let apiSecret: string;
  try {
    apiSecret = decryptSecret(credential.apiSecretEncrypted);
  } catch (err) {
    // A credential that cannot be decrypted (corrupted row, wrong master
    // key after a rotation) must never be treated as "no signature
    // required" — fail closed exactly like a genuine signature mismatch.
    console.error("[apiKey] failed to decrypt stored secret:", err);
    return res.status(401).json({ error: "CREDENTIAL_VERIFICATION_FAILED" });
  }

  const rawBody = req.rawBody ?? Buffer.alloc(0);
  const expectedSignature = computeSignature(apiSecret, timestampHeader, rawBody);
  if (!signaturesMatch(signature, expectedSignature)) {
    return res.status(401).json({ error: "SIGNATURE_MISMATCH" });
  }

  const replayResult = await checkAndRecordSignature(apiKey, signature, Math.ceil(toleranceMs / 1000) + 60);
  if (replayResult === "replayed") {
    return res.status(401).json({ error: "REPLAYED_REQUEST" });
  }
  if (replayResult === "unavailable") {
    // Deliberately fails CLOSED — see replayGuard.ts's class doc.
    return res.status(503).json({ error: "REPLAY_CHECK_UNAVAILABLE" });
  }

  req.applicationId = credential.applicationId;
  next();
}
