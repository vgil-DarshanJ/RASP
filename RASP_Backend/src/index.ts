import "dotenv/config";
import { createApp } from "./app";

const requiredEnv = ["DATABASE_URL", "REDIS_URL", "JWT_SECRET"];
const missing = requiredEnv.filter((key) => !process.env[key]);
if (missing.length > 0) {
  console.error(`[startup] Missing required env vars: ${missing.join(", ")}`);
  console.error("[startup] Copy .env.example to .env and fill it in.");
  process.exit(1);
}

const app = createApp();
const port = Number(process.env.PORT) || 4000;

const server = app.listen(port, () => {
  console.log(`[rasp-shield-backend] listening on http://localhost:${port}`);
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
