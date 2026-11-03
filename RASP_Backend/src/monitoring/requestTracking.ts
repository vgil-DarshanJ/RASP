import { randomUUID } from "node:crypto";
import { NextFunction, Request, Response } from "express";
import { deviceGroupOf, normalizePath, recordDeviceCall, recordRequest } from "./problemLog";

/** Paths that are not counted: the status page's own polling and health probes. */
const IGNORED = [/^\/healthz$/, /^\/v1\/system\//];

export const REQUEST_ID_HEADER = "X-Request-Id";

/**
 * First middleware of the app. Gives every response an `X-Request-Id` (also
 * shown on the System Status page, so a failure a user reports can be found
 * in the server log), remembers the API `error` code a failed response
 * sends, and on finish records the request in the problem log.
 */
export function trackRequests(req: Request, res: Response, next: NextFunction) {
  const started = process.hrtime.bigint();
  const requestId = randomUUID().slice(0, 8);
  res.locals.requestId = requestId;
  res.setHeader(REQUEST_ID_HEADER, requestId);

  const json = res.json.bind(res);
  res.json = (body?: unknown) => {
    if (res.statusCode >= 400 && body && typeof body === "object" && typeof (body as { error?: unknown }).error === "string") {
      res.locals.errorCode = (body as { error: string }).error;
    }
    return json(body);
  };

  res.on("finish", () => {
    if (req.method === "OPTIONS") return;
    const path = req.originalUrl.split("?")[0];
    if (IGNORED.some((pattern) => pattern.test(path))) return;
    // The matched Express pattern when a route matched (no ids in it), else
    // the path with id-like segments replaced.
    const route = req.route?.path && typeof req.route.path === "string"
      ? normalizePath(`${req.baseUrl}${req.route.path === "/" ? "" : req.route.path}`)
      : normalizePath(path);
    const deviceGroup = deviceGroupOf(path);
    if (deviceGroup) recordDeviceCall(deviceGroup, res.statusCode, res.locals.errorCode);
    recordRequest({
      method: req.method,
      route,
      status: res.statusCode,
      durationMs: Number(process.hrtime.bigint() - started) / 1e6,
      code: res.locals.errorCode,
      message: res.locals.errorMessage,
      requestId,
      clientIp: req.ip,
    });
  });
  next();
}
