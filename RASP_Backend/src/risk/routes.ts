import express, { NextFunction, Request, RequestHandler, Response, Router } from "express";
import { ApiKeyedRequest, requireApiKeyIdentity } from "../middleware/apiKey";
import { deviceRateLimiter, RateCheck } from "../redis/deviceRateLimit";
import { loadIpRiskConfig } from "../ipRisk/ipRisk";
import { resolveGeo } from "../ipRisk/routes";
import { prismaRiskAlertDeps, raiseRiskAlerts, RiskAlertDeps } from "./alerts";
import { prismaRiskEventRepository } from "./repository";
import { processRiskEvent, RISK_EVENT_MAX_BODY_BYTES, RiskEventRepository } from "./riskEvents";

/**
 * JSON parser for this router only: 16 KB limit (→ 413 PAYLOAD_TOO_LARGE),
 * malformed JSON → 400 INVALID_JSON. The router is mounted before the
 * app-wide 1 MB parser (app.ts), so that one never sees these requests.
 */
export function riskJsonBodyParser(): RequestHandler {
  const parse = express.json({ limit: RISK_EVENT_MAX_BODY_BYTES, strict: true });
  return (req: Request, res: Response, next: NextFunction) =>
    parse(req, res, (err?: unknown) => {
      if (!err) return next();
      const e = err as { type?: string; status?: number };
      if (e.type === "entity.too.large" || e.status === 413) {
        return res.status(413).json({ error: "PAYLOAD_TOO_LARGE", maxBytes: RISK_EVENT_MAX_BODY_BYTES });
      }
      return res.status(400).json({ error: "INVALID_JSON" });
    });
}

export interface RiskRouterDeps {
  repo?: RiskEventRepository;
  /** Default: the Redis fixed-window counter. */
  rateCheck?: RateCheck;
  /** Default: requireApiKeyIdentity (X-Api-Key; the device signature authenticates the content). */
  authenticate?: RequestHandler;
  /** Default: the IP-risk geo source (trusted header / lookup), null when unknown. */
  ipCountry?: (req: Request) => Promise<string | null>;
  alerts?: RiskAlertDeps;
  now?: () => number;
}

const defaultIpCountry = async (req: Request) => (await resolveGeo(req, loadIpRiskConfig())).geo?.country ?? null;

/**
 * POST /v1/risk/events — session and transaction risk events from the SDK
 * (contract in riskEvents.ts). Order: 16 KB JSON parser → rate limits (per
 * IP, per API key, per app + device key) → API key identifies the
 * application → processRiskEvent (schema, device key, signature, replay,
 * store, rules) → 202. Findings are raised as alerts after the response.
 *
 * Error codes: 400 INVALID_JSON / INVALID_RISK_EVENT, 401 MISSING_API_KEY /
 * INVALID_OR_REVOKED_API_KEY / UNKNOWN_DEVICE_KEY / SIGNATURE_INVALID,
 * 403 APP_ID_MISMATCH, 409 REPLAYED, 413 PAYLOAD_TOO_LARGE, 422
 * EVENT_TOO_OLD / EVENT_FROM_FUTURE, 429 RATE_LIMIT_EXCEEDED.
 */
export function createRiskRouter(deps: RiskRouterDeps = {}): Router {
  const router = Router();
  const repo = deps.repo ?? prismaRiskEventRepository;
  const now = deps.now ?? Date.now;

  router.post(
    "/events",
    riskJsonBodyParser(),
    deviceRateLimiter({
      scope: "risk",
      limitEnv: "RISK_RATE_LIMIT_PER_DEVICE",
      defaultLimit: 60,
      apiKeyLimitEnv: "RISK_RATE_LIMIT_PER_API_KEY",
      defaultApiKeyLimit: 6000,
      ipLimitEnv: "RISK_RATE_LIMIT_PER_IP",
      defaultIpLimit: 600,
      windowEnv: "RISK_RATE_LIMIT_WINDOW_SECONDS",
      defaultWindowSeconds: 60,
      check: deps.rateCheck,
    }),
    deps.authenticate ?? (requireApiKeyIdentity as RequestHandler),
    async (req: ApiKeyedRequest, res: Response) => {
      const applicationId = req.applicationId!;
      const outcome = await processRiskEvent({
        body: req.body,
        applicationId,
        resolveIpCountry: () => (deps.ipCountry ?? defaultIpCountry)(req),
        now: now(),
        repo,
      });
      res.setHeader("Cache-Control", "no-store");
      res.status(outcome.status).json(outcome.body);

      if (outcome.status !== 202) {
        // Rejections are logged (code and app only — never the body, hashes or keys).
        console.warn(`[risk] rejected ${outcome.status} ${String(outcome.body.error)} app=${applicationId}`);
        return;
      }
      const stored = outcome.stored!;
      if (stored.findings.length === 0) return;
      void raiseRiskAlerts(
        {
          applicationId,
          deviceId: stored.device.deviceId ?? stored.envelope.deviceKeyId,
          sdkVersion: stored.envelope.sdkVersion,
          eventType: stored.envelope.type,
          eventId: stored.envelope.eventId,
          receivedAt: new Date(),
          findings: stored.findings,
        },
        deps.alerts ?? prismaRiskAlertDeps,
      ).catch((err) => console.error("[risk] raising alerts failed (non-fatal):", err));
    },
  );
  return router;
}

export const riskRouter = createRiskRouter();
