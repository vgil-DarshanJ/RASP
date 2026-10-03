import { Router } from "express";
import { ApiKeyedRequest, requireApiKey } from "../middleware/apiKey";
import { deviceRateLimiter } from "../redis/deviceRateLimit";
import { registerDevice } from "./registration";
import { prismaRegistrationRepository } from "./registrationRepository";

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
  defaultWindowSeconds: 60,
});

/**
 * POST /v1/devices/register — binds a device's EC P-256 key to the calling
 * application so its evidence envelopes can be verified.
 *
 * Authenticated like legacy ingestion (`X-Api-Key` + HMAC `X-Signature` over
 * `X-Timestamp.rawBody`), so the API key alone — which ships inside the app
 * — is not enough to register keys. Rules: see `registerDevice`.
 */
devicesRouter.post("/register", rateLimitRegistration, requireApiKey, async (req: ApiKeyedRequest, res) => {
  const outcome = await registerDevice({
    body: req.body,
    applicationId: req.applicationId!,
    now: new Date(),
    repo: prismaRegistrationRepository,
  });
  res.status(outcome.status).json(outcome.body);
});
