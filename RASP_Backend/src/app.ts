// Must be imported before any route is registered — patches Express 4 so
// a thrown/rejected error inside an `async (req, res) => {...}` handler
// reaches the error-handling middleware below instead of hanging the
// request forever (Express 4 does not do this on its own; Express 5
// does, but this codebase targets 4 for ecosystem stability). Every route
// file in this app relies on this being imported here, exactly once.
import "express-async-errors";
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import { prisma } from "./db/prisma";
import { pingRedis } from "./redis/client";
import { authRouter } from "./auth/routes";
import { appsRouter } from "./apps/routes";
import { credentialsRouter } from "./credentials/routes";
import { sdkDistributionRouter } from "./sdk-distribution/routes";
import { ingestionRouter } from "./ingestion/routes";
import { devicesRouter } from "./devices/routes";
import { dashboardRouter } from "./dashboard/routes";
import { webhooksRouter } from "./webhooks/routes";
import { ipRiskRouter } from "./ipRisk/routes";
import { riskRouter } from "./risk/routes";
import { reputationRouter } from "./reputation/routes";
import { privacyRouter } from "./privacy/deviceErasure";
import { deviceConfigRouter, remoteConfigAdminRouter } from "./remoteConfig/routes";
import { applyTrustProxy, jsonBodyParser } from "./middleware/requestSetup";
import { logError } from "./security/secretFields";
import { allowedOrigins } from "./security/origins";

export function createApp() {
  const app = express();

  // Client IP behind a proxy (TRUST_PROXY) — see requestSetup.ts.
  applyTrustProxy(app);

  app.use(cors({ origin: allowedOrigins(), credentials: true }));

  // Risk events: own 16 KB JSON parser (413 above it), so mounted before the
  // app-wide 1 MB parser below — see risk/routes.ts.
  app.use("/v1/risk", riskRouter);

  // JSON body + exact raw bytes for HMAC verification — see requestSetup.ts.
  app.use(jsonBodyParser());

  /** Unauthenticated — real dependency checks (not just "the process is
   *  alive"), so a broken DB/Redis connection is visible immediately
   *  rather than discovered on the first real request. */
  app.get("/healthz", async (_req, res) => {
    const [dbOk, redisOk] = await Promise.all([
      prisma.$queryRaw`SELECT 1`.then(() => true).catch(() => false),
      pingRedis(),
    ]);
    const ok = dbOk && redisOk;
    res.status(ok ? 200 : 503).json({ ok, postgres: dbOk, redis: redisOk });
  });

  app.use("/v1/auth", authRouter);
  app.use("/v1/apps/:id/remote-config", remoteConfigAdminRouter);
  app.use("/v1/apps", appsRouter);
  app.use("/v1/credentials", credentialsRouter);
  app.use("/v1/sdk", sdkDistributionRouter);
  app.use("/v1/events", ingestionRouter);
  app.use("/v1/devices", devicesRouter);
  app.use("/v1/dashboard", dashboardRouter);
  app.use("/v1/webhooks", webhooksRouter);
  app.use("/v1/ip-risk", ipRiskRouter);
  app.use("/v1/reputation", reputationRouter);
  app.use("/v1/config", deviceConfigRouter);
  app.use("/v1/privacy", privacyRouter);

  // Last-resort error handler — every route above is async; an unhandled
  // rejection must still resolve to a JSON 500, never an unhandled crash
  // or a hung connection. Kept last in the middleware chain on purpose.
  // The response never carries the error; the log redacts secret values
  // (a Prisma error prints the data it was given, e.g. a new salt).
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    logError("[unhandled]", err);
    if (!res.headersSent) {
      res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
    }
  });

  return app;
}
