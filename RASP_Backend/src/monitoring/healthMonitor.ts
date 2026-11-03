import fs from "node:fs";
import path from "node:path";
import { prisma } from "../db/prisma";
import { pingRedis } from "../redis/client";
import { recordProblem, safeMessage } from "./problemLog";

/**
 * Runs the backend's dependency checks once a minute and keeps the last
 * hour of results, so the System Status page can show not just "is it up
 * now" but "when did it break". A check that starts failing is written to
 * the problem log once (and again when it recovers), not every minute.
 *
 * Checks:
 * - postgres   — `SELECT 1`;
 * - redis      — PING;
 * - migrations — every folder in prisma/migrations is applied, none failed;
 * - portal / visitor — the dashboard (DASHBOARD_URL) and the visitor site
 *   (VISITOR_SITE_URL) answer an HTTP GET from this server. Only addresses
 *   from this server's own environment are fetched, never one from a request.
 */

export type CheckId = "postgres" | "redis" | "migrations" | "portal" | "visitor";

export interface CheckResult {
  id: CheckId;
  label: string;
  ok: boolean;
  /** `false` when the check is not configured (e.g. no VISITOR_SITE_URL); not a failure. */
  configured: boolean;
  latencyMs: number;
  detail: string;
}

export interface CheckRun {
  at: string;
  results: CheckResult[];
}

export const CHECK_INTERVAL_MS = 60_000;
const HISTORY_KEPT = 60;
const CHECK_TIMEOUT_MS = 5_000;

const history: CheckRun[] = [];
const failing = new Set<CheckId>();
let timer: NodeJS.Timeout | null = null;

function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${what} did not answer within ${ms / 1000} s`)), ms);
    promise.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

async function timed(id: CheckId, label: string, run: () => Promise<{ ok: boolean; detail: string; configured?: boolean }>): Promise<CheckResult> {
  const started = Date.now();
  try {
    const r = await withTimeout(run(), CHECK_TIMEOUT_MS, label);
    return { id, label, ok: r.ok, configured: r.configured ?? true, latencyMs: Date.now() - started, detail: r.detail };
  } catch (err) {
    return { id, label, ok: false, configured: true, latencyMs: Date.now() - started, detail: safeMessage(err) ?? "failed" };
  }
}

function migrationsDir(): string {
  // src/monitoring or dist/monitoring → <repo>/prisma/migrations
  return path.resolve(__dirname, "..", "..", "prisma", "migrations");
}

async function checkMigrations(): Promise<{ ok: boolean; detail: string }> {
  const onDisk = fs.readdirSync(migrationsDir(), { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  const rows = await prisma.$queryRaw<{ migration_name: string; finished_at: Date | null; rolled_back_at: Date | null }[]>`
    SELECT migration_name, finished_at, rolled_back_at FROM "_prisma_migrations"`;
  const applied = new Set(rows.filter((r) => r.finished_at && !r.rolled_back_at).map((r) => r.migration_name));
  const failed = rows.filter((r) => !r.finished_at && !r.rolled_back_at).map((r) => r.migration_name);
  const pending = onDisk.filter((name) => !applied.has(name));
  if (failed.length > 0) return { ok: false, detail: `Failed migration: ${failed.join(", ")}. Fix it, then run: npx prisma migrate deploy` };
  if (pending.length > 0) return { ok: false, detail: `${pending.length} not applied (${pending.join(", ")}). Run: npx prisma migrate deploy` };
  return { ok: true, detail: `All ${onDisk.length} applied` };
}

async function checkUrl(envName: string): Promise<{ ok: boolean; detail: string; configured?: boolean }> {
  const raw = process.env[envName]?.trim();
  if (!raw) return { ok: true, configured: false, detail: `${envName} is not set, so this is not checked` };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, detail: `${envName} is not a valid URL` };
  }
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), CHECK_TIMEOUT_MS);
  try {
    const res = await fetch(url, { redirect: "manual", signal: controller.signal });
    return { ok: res.status < 500, detail: `${url.origin} answered HTTP ${res.status}` };
  } catch (err) {
    return { ok: false, detail: `${url.origin} did not answer (${safeMessage((err as { cause?: unknown }).cause ?? err) ?? "network error"})` };
  } finally {
    clearTimeout(t);
  }
}

export async function runChecks(): Promise<CheckRun> {
  const results = await Promise.all([
    timed("postgres", "PostgreSQL database", async () => {
      await prisma.$queryRaw`SELECT 1`;
      return { ok: true, detail: "Connected" };
    }),
    timed("redis", "Redis cache", async () => {
      const ok = await pingRedis();
      return { ok, detail: ok ? "PONG" : "No answer to PING (rate limits and replay checks are affected)" };
    }),
    timed("migrations", "Database migrations", checkMigrations),
    timed("portal", "Customer portal (frontend)", () => checkUrl("DASHBOARD_URL")),
    timed("visitor", "Visitor site (frontend)", () => checkUrl("VISITOR_SITE_URL")),
  ]);
  const run: CheckRun = { at: new Date().toISOString(), results };
  history.push(run);
  if (history.length > HISTORY_KEPT) history.shift();

  for (const r of results) {
    if (!r.ok && !failing.has(r.id)) {
      failing.add(r.id);
      recordProblem({ kind: "check", severity: "error", title: `${r.label} check failed`, message: r.detail });
    } else if (r.ok && failing.has(r.id)) {
      failing.delete(r.id);
      recordProblem({ kind: "check", severity: "warning", title: `${r.label} recovered`, message: r.detail });
    }
  }
  return run;
}

/** Last hour of runs, oldest first. */
export function checkHistory(): CheckRun[] {
  return [...history];
}

export function latestRun(): CheckRun | undefined {
  return history[history.length - 1];
}

/** First run now, then every [CHECK_INTERVAL_MS]. Does not keep the process alive. */
export function startHealthMonitor(): void {
  if (timer) return;
  const run = () => runChecks().catch((err) => recordProblem({ kind: "process", severity: "error", title: "Health monitor failed", message: safeMessage(err) }));
  void run();
  timer = setInterval(run, CHECK_INTERVAL_MS);
  timer.unref();
}
