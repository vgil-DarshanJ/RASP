import { NextFunction, Response, Router } from "express";
import { ApiKeyedRequest, requireApiKey } from "../middleware/apiKey";
import { checkRateLimit } from "../redis/rateLimit";
import { registerDevice } from "./registration";
import { prismaRegistrationRepository } from "./registrationRepository";

export const devicesRouter = Router();

/**
 * Per-API-key rate limit for registrations, in its own Redis bucket
 * (`register:<key>`) so registrations and event ingestion do not consume
 * each other's budget. Runs before the DB lookup, like the ingestion limiter.
 */
async function rateLimitRegistration(req: ApiKeyedRequest, res: Response, next: NextFunction) {
  const apiKey = req.header("X-Api-Key");
  if (!apiKey) return next(); // requireApiKey reports the real error

  const limit = Number(process.env.DEVICE_REGISTRATION_RATE_LIMIT_PER_WINDOW) || 60;
  const windowSeconds = Number(process.env.DEVICE_REGISTRATION_RATE_LIMIT_WINDOW_SECONDS) || 60;

  const { allowed, remaining } = await checkRateLimit(`register:${apiKey}`, limit, windowSeconds);
  res.setHeader("X-RateLimit-Limit", String(limit));
  res.setHeader("X-RateLimit-Remaining", String(remaining));
  if (!allowed) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
  next();
}

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
