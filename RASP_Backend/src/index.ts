import "dotenv/config";
import { createApp } from "./app";
import { startRetentionSchedule } from "./privacy/retention";
import { configurationProblems, configurationWarnings } from "./startupChecks";
import { startHealthMonitor } from "./monitoring/healthMonitor";
import { recordProblem, safeMessage } from "./monitoring/problemLog";
import { logError } from "./security/secretFields";

const problems = configurationProblems();
if (problems.length > 0) {
  for (const problem of problems) console.error(`[startup] ${problem}`);
  console.error("[startup] Copy .env.example to .env and fill it in.");
  process.exit(1);
}
for (const warning of configurationWarnings()) console.warn(`[startup] warning: ${warning}`);

const app = createApp();
const host = process.env.HOST || "0.0.0.0";
const port = Number(process.env.PORT) || 4444;

const server = app.listen(port, host, () => {
  console.log(`[rasp-shield-backend] listening on ${host}:${port}`);
});
// Node closes an idle keep-alive socket after 5 s; phones reuse pooled
// sockets for longer, and a request sent on one the server just closed gets
// no answer (high_risk_ip showed "no answer from the backend").
server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;

// Daily deletion of data past its retention period, when one is configured.
startRetentionSchedule();

// Dependency checks every minute for the System Status page (GET /v1/system/status).
startHealthMonitor();

// A promise rejected outside any request (a background job) is logged and
// shown on the System Status page instead of being lost.
process.on("unhandledRejection", (reason) => {
  logError("[unhandledRejection]", reason);
  recordProblem({ kind: "process", severity: "error", title: "Unhandled error in a background task", message: safeMessage(reason) });
});

function shutdown(signal: string) {
  console.log(`[shutdown] received ${signal}, closing server...`);
  server.close(() => process.exit(0));
  // Never hang forever waiting for in-flight requests — force exit if
  // graceful close doesn't complete quickly.
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
