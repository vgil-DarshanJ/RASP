import { redis } from "./client";

const RECENT_EVENTS_MAX = 50;
const RECENT_EVENTS_TTL_SECONDS = 60 * 60; // 1h — Postgres remains authoritative past this
const DETECTOR_COUNTER_TTL_SECONDS = 60 * 60 * 24 * 8; // 8 days of hourly buckets

function recentEventsKey(applicationId: string) {
  return `app:${applicationId}:recent_events`;
}

function detectorCounterKey(applicationId: string, hourBucket: string) {
  return `app:${applicationId}:detector_counts:${hourBucket}`;
}

function currentHourBucket(): string {
  return new Date().toISOString().slice(0, 13); // "2026-09-11T14"
}

/**
 * Best-effort only — every call here is wrapped so a Redis outage degrades
 * the dashboard to "slower, reads Postgres directly" rather than breaking
 * ingestion. Postgres already has the durable row by the time this runs;
 * this is purely a read-side accelerator.
 */
export async function recordEventForDashboard(applicationId: string, event: {
  id: string;
  detectorId: string;
  status: string;
  receivedAt: string;
}) {
  try {
    const pipeline = redis.pipeline();

    pipeline.lpush(recentEventsKey(applicationId), JSON.stringify(event));
    pipeline.ltrim(recentEventsKey(applicationId), 0, RECENT_EVENTS_MAX - 1);
    pipeline.expire(recentEventsKey(applicationId), RECENT_EVENTS_TTL_SECONDS);

    const bucketKey = detectorCounterKey(applicationId, currentHourBucket());
    pipeline.hincrby(bucketKey, event.detectorId, 1);
    pipeline.expire(bucketKey, DETECTOR_COUNTER_TTL_SECONDS);

    await pipeline.exec();
  } catch (err) {
    console.error("[dashboardCache] recordEventForDashboard failed (non-fatal):", err);
  }
}

export async function getRecentEventsFromCache(applicationId: string): Promise<unknown[] | null> {
  try {
    const raw = await redis.lrange(recentEventsKey(applicationId), 0, RECENT_EVENTS_MAX - 1);
    if (raw.length === 0) return null;
    return raw.map((r) => JSON.parse(r));
  } catch {
    return null;
  }
}

/** Sums the last `hours` hourly buckets — the data behind the "most
 *  common alert type" chart. `null` means Redis was unavailable; the
 *  caller falls back to a Postgres GROUP BY in that case. */
export async function getDetectorCountsFromCache(
  applicationId: string,
  hours: number,
): Promise<Record<string, number> | null> {
  try {
    const now = new Date();
    const totals: Record<string, number> = {};
    for (let i = 0; i < hours; i++) {
      const bucketDate = new Date(now.getTime() - i * 60 * 60 * 1000);
      const bucket = bucketDate.toISOString().slice(0, 13);
      const counts = await redis.hgetall(detectorCounterKey(applicationId, bucket));
      for (const [detectorId, count] of Object.entries(counts)) {
        totals[detectorId] = (totals[detectorId] ?? 0) + Number(count);
      }
    }
    return totals;
  } catch {
    return null;
  }
}
