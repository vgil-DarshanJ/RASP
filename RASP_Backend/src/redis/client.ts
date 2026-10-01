import Redis from "ioredis";

// `lazyConnect` + a bounded retry strategy: a dead/not-yet-started Redis
// container must never crash the whole API process or hang a request
// forever — ingestion/dashboard code that touches Redis treats a failed
// call as "cache miss," never as a fatal error. Postgres remains the
// source of truth regardless of Redis's health.
export const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379", {
  lazyConnect: true,
  maxRetriesPerRequest: 2,
  retryStrategy: (times) => Math.min(times * 200, 2000),
});

redis.on("error", (err) => {
  // Never let an unhandled Redis error crash the process — logged and
  // swallowed; callers already treat Redis as best-effort.
  console.error("[redis] connection error:", err.message);
});

export async function pingRedis(): Promise<boolean> {
  try {
    if (redis.status === "wait") await redis.connect();
    const reply = await redis.ping();
    return reply === "PONG";
  } catch {
    return false;
  }
}
