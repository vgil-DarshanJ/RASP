import { Router } from "express";
import { ApiKeyedRequest, requireApiKey } from "../middleware/apiKey";
import { deviceRateLimiter } from "../redis/deviceRateLimit";
import { checkRateLimit } from "../redis/rateLimit";
import { registerDevice } from "./registration";
import { prismaRegistrationRepository } from "./registrationRepository";
import { CHALLENGE_TTL_SECONDS, issueChallenge } from "./registrationChallenge";
import { attestationTrust, revocationCheckEnabled } from "../crypto/attestationTrust";
import { loadIpRiskConfig } from "../ipRisk/ipRisk";
import { resolveGeo } from "../ipRisk/routes";

/** Country of the request IP for a new registration; null when unknown. Never fails the registration. */
async function registrationCountryOf(req: ApiKeyedRequest): Promise<string | null> {
  try {
    const resolved = await resolveGeo(req, loadIpRiskConfig());
    return resolved.geo?.country ?? null;
  } catch {
    return null;
  }
}

/** Revocation list entries, or null when unavailable; undefined when the check is switched off. */
async function revocationEntries(): Promise<Map<string, string> | null | undefined> {
  if (!revocationCheckEnabled()) return undefined;
  try {
    return (await attestationTrust.statusSource())?.entries ?? null;
  } catch {
    return null;
  }
}

export const devicesRouter = Router();

/**
 * Per app + device (the key id the registered public key will get) limit
 * for registrations, in its own Redis bucket so registrations and event
 * ingestion do not consume each other's budget. Runs before the DB lookup.
 */
const rateLimitRegistration = deviceRateLimiter({
  scope: "register",
  limitEnv: "DEVICE_REGISTRATION_RATE_LIMIT_PER_WINDOW",
  windowEnv: "DEVICE_REGISTRATION_RATE_LIMIT_WINDOW_SECONDS",
  defaultLimit: 60,
  apiKeyLimitEnv: "DEVICE_REGISTRATION_RATE_LIMIT_PER_API_KEY",
  defaultApiKeyLimit: 600,
  ipLimitEnv: "DEVICE_REGISTRATION_RATE_LIMIT_PER_IP",
  defaultIpLimit: 120,
  defaultWindowSeconds: 60,
});

/**
 * POST /v1/devices/challenge — a one-time challenge for the next
 * registration (see registrationChallenge.ts). Authenticated like
 * registration. Limited per API key and per client IP (same budgets as
 * registration).
 */
devicesRouter.post("/challenge", requireApiKey, async (req: ApiKeyedRequest, res) => {
  const windowSeconds = Number(process.env.DEVICE_REGISTRATION_RATE_LIMIT_WINDOW_SECONDS) || 60;
  for (const [bucket, max] of [
    [`challenge:app:${req.applicationId}`, Number(process.env.DEVICE_REGISTRATION_RATE_LIMIT_PER_API_KEY) || 600],
    [`challenge:ip:${req.ip ?? "unknown"}`, Number(process.env.DEVICE_REGISTRATION_RATE_LIMIT_PER_IP) || 120],
  ] as const) {
    if (!(await checkRateLimit(bucket, max, windowSeconds)).allowed) {
      return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
    }
  }
  try {
    const challenge = await issueChallenge(req.applicationId!);
    res.json({ challenge, expiresInSeconds: CHALLENGE_TTL_SECONDS });
  } catch {
    res.status(503).json({ error: "CHALLENGE_UNAVAILABLE" });
  }
});

/**
 * POST /v1/devices/register — binds a device's EC P-256 key to the calling
 * application so its evidence envelopes can be verified.
 *
 * Authenticated like legacy ingestion (`X-Api-Key` + HMAC `X-Signature` over
 * `X-Timestamp.rawBody`). Because that secret ships inside the app, the
 * application's attestation policy (REQUIRE_HARDWARE) is what keeps
 * software keys and repackaged apps out. Rules: see `registerDevice`.
 */
devicesRouter.post("/register", rateLimitRegistration, requireApiKey, async (req: ApiKeyedRequest, res) => {
  const revoked = await revocationEntries();
  const outcome = await registerDevice({
    body: req.body,
    applicationId: req.applicationId!,
    now: new Date(),
    repo: prismaRegistrationRepository,
    registrationCountry: await registrationCountryOf(req),
    revoked,
    revocationRequired: revocationCheckEnabled(),
  });
  res.status(outcome.status).json(outcome.body);
});
