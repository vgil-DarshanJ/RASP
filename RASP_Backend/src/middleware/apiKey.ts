import { NextFunction, Request, Response } from "express";
import { prisma } from "../db/prisma";
import { decryptSecret } from "../crypto/secretBox";
import { computeSignature, isTimestampFresh, signaturesMatch } from "../crypto/hmac";
import { checkAndRecordSignature } from "../redis/replayGuard";
import { logError } from "../security/secretFields";

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

  const lookup = await resolveActiveCredential(apiKey);
  if (!lookup.ok) return res.status(lookup.status).json({ error: lookup.error });
  const credential = lookup.credential;

  let apiSecret: string;
  try {
    apiSecret = decryptSecret(credential.apiSecretEncrypted);
  } catch (err) {
    // A credential that cannot be decrypted (corrupted row, wrong master
    // key after a rotation) must never be treated as "no signature
    // required" — fail closed exactly like a genuine signature mismatch.
    logError("[apiKey] failed to decrypt stored secret:", err);
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

type CredentialLookup =
  | { ok: true; credential: { applicationId: string; apiSecretEncrypted: string } }
  | { ok: false; status: number; error: string };

/**
 * Looks up `apiKey` fresh (so revocation takes effect immediately) and
 * requires an ACTIVE credential on a non-archived application.
 */
async function resolveActiveCredential(apiKey: string): Promise<CredentialLookup> {
  let credential;
  try {
    credential = await prisma.apiCredential.findUnique({
      where: { apiKey },
      include: { application: { select: { archivedAt: true } } },
    });
  } catch (err) {
    logError("[apiKey] lookup failed:", err);
    return { ok: false, status: 503, error: "AUTH_BACKEND_UNAVAILABLE" };
  }

  if (!credential || credential.status !== "ACTIVE") {
    return { ok: false, status: 401, error: "INVALID_OR_REVOKED_API_KEY" };
  }
  // An archived application is a decommissioned integration — its SDK
  // should stop being able to ship new events the same way a revoked
  // credential does, even though the credential row itself is untouched.
  if (credential.application.archivedAt) {
    return { ok: false, status: 401, error: "APPLICATION_ARCHIVED" };
  }
  return { ok: true, credential };
}

/**
 * Identifies the application from `X-Api-Key` alone — no HMAC, timestamp or
 * signature-replay check. Only for evidence envelopes, which carry their own
 * authentication (a signature by a registered device key, a per-key counter
 * and nonce; see `ingestion/envelope.ts`). The key still has to be ACTIVE on
 * a non-archived application, so revocation and archiving still stop
 * envelope ingestion.
 */
export async function requireApiKeyIdentity(
  req: ApiKeyedRequest,
  res: Response,
  next: NextFunction,
) {
  const apiKey = req.header("X-Api-Key");
  if (!apiKey) return res.status(401).json({ error: "MISSING_API_KEY" });

  const lookup = await resolveActiveCredential(apiKey);
  if (!lookup.ok) return res.status(lookup.status).json({ error: lookup.error });

  req.applicationId = lookup.credential.applicationId;
  next();
}
