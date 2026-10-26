import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { ApiKeyedRequest, requireApiKey } from "../middleware/apiKey";
import { checkRateLimit } from "../redis/rateLimit";
import {
  evaluateIntegrity,
  INTEGRITY_NONCE_TTL_SECONDS,
  IntegrityDecodeError,
  integrityConfigured,
  integrityDeps,
  issueIntegrityNonce,
  loadIntegrityConfig,
} from "./playIntegrity";

export const integrityRouter = Router();

/** Per application and per client IP, like device challenges. */
async function rateLimited(req: ApiKeyedRequest, scope: string): Promise<boolean> {
  const windowSeconds = Number(process.env.PLAY_INTEGRITY_RATE_LIMIT_WINDOW_SECONDS) || 60;
  for (const [bucket, max] of [
    [`pi_${scope}:app:${req.applicationId}`, Number(process.env.PLAY_INTEGRITY_RATE_LIMIT_PER_API_KEY) || 600],
    [`pi_${scope}:ip:${req.ip ?? "unknown"}`, Number(process.env.PLAY_INTEGRITY_RATE_LIMIT_PER_IP) || 60],
  ] as const) {
    if (!(await checkRateLimit(bucket, max, windowSeconds)).allowed) return true;
  }
  return false;
}

/** POST /v1/integrity/challenge — a one-time nonce for the next Play Integrity request. */
integrityRouter.post("/challenge", requireApiKey, async (req: ApiKeyedRequest, res) => {
  if (!integrityConfigured(loadIntegrityConfig())) return res.status(503).json({ error: "PLAY_INTEGRITY_NOT_CONFIGURED" });
  if (await rateLimited(req, "challenge")) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
  try {
    res.json({ nonce: await issueIntegrityNonce(req.applicationId!), expiresInSeconds: INTEGRITY_NONCE_TTL_SECONDS });
  } catch {
    res.status(503).json({ error: "CHALLENGE_UNAVAILABLE" });
  }
});

const verifyBody = z.object({
  packageName: z.string().min(1).max(255),
  nonce: z.string().min(16).max(500),
  token: z.string().min(1).max(20_000),
});

/**
 * POST /v1/integrity/verify — decodes the token with Google and returns the
 * verdict. The nonce must be one this backend issued to this application
 * and is used up by the call, whatever the outcome. The raw token is never
 * stored or logged.
 */
integrityRouter.post("/verify", requireApiKey, async (req: ApiKeyedRequest, res) => {
  const config = loadIntegrityConfig();
  if (!integrityConfigured(config)) return res.status(503).json({ error: "PLAY_INTEGRITY_NOT_CONFIGURED" });
  if (await rateLimited(req, "verify")) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
  const parsed = verifyBody.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_BODY" });
  const { packageName, nonce, token } = parsed.data;
  if (!config.allowedPackages.has(packageName)) return res.status(400).json({ error: "PACKAGE_NOT_ALLOWED" });
  if (!(await integrityDeps.nonces.consume(req.applicationId!, nonce))) return res.status(400).json({ error: "UNKNOWN_OR_USED_NONCE" });

  let payload;
  try {
    payload = await integrityDeps.decode(packageName, token);
  } catch (e) {
    const code = e instanceof IntegrityDecodeError ? e.code : "GOOGLE_UNAVAILABLE";
    // A token Google refuses is a failed attestation; an outage is not the device's fault.
    if (code === "TOKEN_REJECTED_BY_GOOGLE") {
      return res.json({ verdict: "FAIL", reasons: [code], appRecognition: null, deviceRecognition: [], licensing: null, versionCode: null });
    }
    return res.status(503).json({ error: code });
  }

  const app = await prisma.application.findUnique({
    where: { id: req.applicationId! },
    select: { expectedSigningCertSha256: true },
  });
  res.json(evaluateIntegrity({
    payload,
    packageName,
    nonce,
    expectedCertSha256: app?.expectedSigningCertSha256 ?? null,
    config,
    now: new Date(),
  }));
});
