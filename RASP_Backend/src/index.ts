import "dotenv/config";
import { createApp } from "./app";
import { startRetentionSchedule } from "./privacy/retention";
import { configurationProblems, configurationWarnings } from "./startupChecks";

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

// Daily deletion of data past its retention period, when one is configured.
startRetentionSchedule();

function shutdown(signal: string) {
  console.log(`[shutdown] received ${signal}, closing server...`);
  server.close(() => process.exit(0));
  // Never hang forever waiting for in-flight requests — force exit if
  // graceful close doesn't complete quickly.
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
