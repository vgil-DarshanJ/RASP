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

export function createApp() {
  const app = express();

  // Behind a load balancer/reverse proxy, req.ip is the proxy's address unless
  // Express is told to trust X-Forwarded-For; the per-IP rate limit needs the
  // client IP. TRUST_PROXY: a hop count ("1") or an Express trust-proxy value
  // ("loopback", a subnet list). Unset = trust nothing (direct connections).
  const trustProxy = process.env.TRUST_PROXY;
  if (trustProxy) app.set("trust proxy", /^\d+$/.test(trustProxy) ? Number(trustProxy) : trustProxy);

  const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000").split(",");
  app.use(cors({ origin: allowedOrigins, credentials: true }));

  app.use(
    express.json({
      limit: "1mb",
      // Captures the EXACT bytes received, before Express's JSON parser
      // normalizes them into an object — required by the ingestion
      // endpoint's HMAC verification (middleware/apiKey.ts), which must
      // recompute a signature over the same bytes the SDK actually signed
      // and sent. A re-serialization of `req.body` (JSON.stringify) could
      // differ in whitespace/key order and would make every legitimate
      // signature fail to verify. Attached to every request (not just
      // /v1/events) — cheap (already-buffered body, no extra I/O) and
      // simpler than a route-scoped body parser.
      verify: (req, _res, buf) => {
        (req as Request & { rawBody?: Buffer }).rawBody = buf;
      },
    }),
  );

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
  app.use("/v1/apps", appsRouter);
  app.use("/v1/credentials", credentialsRouter);
  app.use("/v1/sdk", sdkDistributionRouter);
  app.use("/v1/events", ingestionRouter);
  app.use("/v1/devices", devicesRouter);
  app.use("/v1/dashboard", dashboardRouter);
  app.use("/v1/webhooks", webhooksRouter);

  // Last-resort error handler — every route above is async; an unhandled
  // rejection must still resolve to a JSON 500, never an unhandled crash
  // or a hung connection. Kept last in the middleware chain on purpose.
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    console.error("[unhandled]", err);
    if (!res.headersSent) {
      res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
    }
  });

  return app;
}
