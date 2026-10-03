import express, { Express, Request, RequestHandler } from "express";

/**
 * Behind a load balancer/reverse proxy, req.ip is the proxy's address unless
 * Express is told to trust X-Forwarded-For; the per-IP rate limits and
 * GET /v1/ip-risk need the client IP. TRUST_PROXY: a hop count ("1") or an
 * Express trust-proxy value ("loopback", a subnet list). Unset = trust
 * nothing (direct connections).
 */
export function applyTrustProxy(app: Express, env: NodeJS.ProcessEnv = process.env): void {
  const trustProxy = env.TRUST_PROXY;
  if (trustProxy) app.set("trust proxy", /^\d+$/.test(trustProxy) ? Number(trustProxy) : trustProxy);
}

/**
 * JSON body parser that also captures the EXACT bytes received, before
 * Express's JSON parser normalizes them into an object — required by the
 * HMAC verification (middleware/apiKey.ts), which must recompute a signature
 * over the same bytes the SDK actually signed and sent. A re-serialization of
 * `req.body` (JSON.stringify) could differ in whitespace/key order and would
 * make every legitimate signature fail to verify. Attached to every request
 * (not just /v1/events) — cheap (already-buffered body, no extra I/O) and
 * simpler than a route-scoped body parser. A request without a body (e.g.
 * GET /v1/ip-risk) never reaches `verify`, so `rawBody` stays undefined and
 * the HMAC check uses empty bytes.
 */
export function jsonBodyParser(): RequestHandler {
  return express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      (req as Request & { rawBody?: Buffer }).rawBody = buf;
    },
  });
}
