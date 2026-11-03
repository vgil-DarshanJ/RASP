import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import express from "express";
import { createApp } from "../src/app";
import { trackRequests } from "../src/monitoring/requestTracking";
import {
  deviceGroupOf,
  deviceRouteStats,
  minuteBuckets,
  normalizePath,
  recentProblems,
  recordRequest,
  resetProblemLog,
  safeMessage,
} from "../src/monitoring/problemLog";

async function withServer(app: express.Express, run: (base: string) => Promise<void>) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  try {
    await run(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test("paths lose ids and query strings before they are stored", () => {
  assert.equal(normalizePath("/v1/apps/clx0a1b2c3d4e5f6g7h8i9j0k/devices/42?token=abc"), "/v1/apps/:id/devices/:id");
  assert.equal(normalizePath("/v1/x/0123456789abcdef0123/y"), "/v1/x/:id/y");
  assert.equal(normalizePath("/healthz"), "/healthz");
});

test("messages are one line and secret-redacted", () => {
  assert.equal(safeMessage(new Error("bad api_secret: \"s3cr3t\"\n    at foo (x.ts:1)")), "Error: bad api_secret: \"[REDACTED]\"");
  assert.equal(safeMessage(undefined), undefined);
  assert.equal(safeMessage("x".repeat(500))!.length, 240);
});

test("4xx/5xx and slow requests become problems; every request is counted per minute", () => {
  resetProblemLog();
  const now = Date.now();
  recordRequest({ method: "GET", route: "/v1/apps", status: 200, durationMs: 12, now });
  recordRequest({ method: "POST", route: "/v1/events", status: 401, durationMs: 5, code: "SIGNATURE_MISMATCH", now });
  recordRequest({ method: "GET", route: "/v1/apps/:id", status: 500, durationMs: 8, now });
  recordRequest({ method: "GET", route: "/v1/dashboard/x", status: 200, durationMs: 4000, now });
  const problems = recentProblems();
  assert.deepEqual(problems.map((p) => [p.status, p.severity]), [[200, "warning"], [500, "error"], [401, "warning"]]);
  assert.equal(problems[2].code, "SIGNATURE_MISMATCH");
  const minute = minuteBuckets(now).at(-1)!;
  assert.deepEqual([minute.requests, minute.clientErrors, minute.serverErrors, minute.slow], [4, 1, 1, 1]);
  assert.equal(minuteBuckets(now).length, 60);
});

test("the tracker sets X-Request-Id, records the route pattern and the error code, and counts device calls", async () => {
  resetProblemLog();
  const app = express();
  app.use(trackRequests);
  app.post("/v1/events", (_req, res) => res.status(401).json({ error: "SIGNATURE_MISMATCH" }));
  app.get("/v1/apps/:id", (_req, res) => res.status(404).json({ error: "APPLICATION_NOT_FOUND" }));
  app.get("/healthz", (_req, res) => res.status(503).json({ ok: false }));
  await withServer(app, async (base) => {
    const r = await fetch(`${base}/v1/events`, { method: "POST" });
    assert.match(r.headers.get("x-request-id") ?? "", /^[0-9a-f]{8}$/);
    await fetch(`${base}/v1/apps/clx0a1b2c3d4e5f6g7h8i9j0k?secret=1`);
    await fetch(`${base}/healthz`);
  });
  const problems = recentProblems();
  assert.equal(problems.length, 2, "/healthz is not recorded");
  assert.equal(problems[0].route, "/v1/apps/:id");
  assert.equal(problems[0].code, "APPLICATION_NOT_FOUND");
  assert.equal(problems[1].route, "/v1/events");
  assert.equal(problems[1].code, "SIGNATURE_MISMATCH");
  const events = deviceRouteStats().find((g) => g.id === "events")!;
  assert.equal(events.failed, 1);
  assert.equal(events.lastFailure?.code, "SIGNATURE_MISMATCH");
  assert.equal(deviceGroupOf("/v1/devices/register"), "devices");
  assert.equal(deviceGroupOf("/v1/dashboard/summary"), undefined);
});

test("the status page needs a signed-in user", async () => {
  await withServer(createApp(), async (base) => {
    const r = await fetch(`${base}/v1/system/status`);
    assert.equal(r.status, 401);
    const checks = await fetch(`${base}/v1/system/checks`, { method: "POST" });
    assert.equal(checks.status, 401);
  });
});
