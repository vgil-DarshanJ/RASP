import { redactSecrets } from "../security/secretFields";

/**
 * In-memory record of what went wrong recently, for the dashboard's System
 * Status page (GET /v1/system/status). Two parts:
 *
 * - problems: the last [MAX_PROBLEMS] failed or slow requests, failed
 *   health checks and process-level errors, newest first;
 * - minutes: per-minute request counters for the last [MINUTES_KEPT]
 *   minutes (requests, 4xx, 5xx, slow, total time).
 *
 * Kept in this process only (lost on restart, one view per backend
 * instance) on purpose: no new table, no write on the request path, and a
 * broken database cannot stop the page that is meant to report it.
 *
 * What is never stored: request or response bodies, query strings, headers,
 * cookies, tokens, stack traces. Routes are the matched Express pattern
 * (`/v1/apps/:id`), or the path with id-like segments replaced; messages are
 * one line, secret-redacted and truncated.
 */

export type ProblemKind = "request" | "check" | "process";
export type ProblemSeverity = "error" | "warning";

export interface Problem {
  id: number;
  at: string;
  kind: ProblemKind;
  severity: ProblemSeverity;
  /** Short title, e.g. "GET /v1/apps/:id → 500" or "PostgreSQL check failed". */
  title: string;
  method?: string;
  route?: string;
  status?: number;
  /** The API's `error` code from the response body, e.g. SIGNATURE_MISMATCH. */
  code?: string;
  /** One-line, redacted detail. */
  message?: string;
  durationMs?: number;
  requestId?: string;
  clientIp?: string;
}

export interface MinuteBucket {
  minute: string;
  requests: number;
  clientErrors: number;
  serverErrors: number;
  slow: number;
  totalMs: number;
}

export const MAX_PROBLEMS = 300;
export const MINUTES_KEPT = 60;
/** A request slower than this is recorded as a warning. */
export const SLOW_REQUEST_MS = 3000;
const MESSAGE_MAX = 240;

const problems: Problem[] = [];
const minutes = new Map<number, MinuteBucket>();
let nextId = 1;

function minuteKey(ms: number): number {
  return Math.floor(ms / 60_000) * 60_000;
}

/** One line, secrets redacted, at most [MESSAGE_MAX] characters. */
export function safeMessage(value: unknown): string | undefined {
  let text: string;
  if (value instanceof Error) text = `${value.name}: ${value.message}`;
  else if (typeof value === "string") text = value;
  else if (value === undefined || value === null) return undefined;
  else text = String(value);
  const line = redactSecrets(text.split("\n").map((l) => l.trim()).filter(Boolean)[0] ?? "");
  if (!line) return undefined;
  return line.length > MESSAGE_MAX ? `${line.slice(0, MESSAGE_MAX - 1)}…` : line;
}

const ID_SEGMENT = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|c[a-z0-9]{20,}|[A-Za-z0-9_-]{21}|[0-9a-fA-F]{16,})$/;

/** `/v1/apps/clx…/devices/42?x=1` → `/v1/apps/:id/devices/:id` — no ids, no query. */
export function normalizePath(path: string): string {
  const clean = path.split("?")[0].split("#")[0];
  const normalized = clean
    .split("/")
    .map((segment) => (ID_SEGMENT.test(segment) ? ":id" : segment.length > 40 ? ":value" : segment))
    .join("/");
  return normalized.length > 120 ? `${normalized.slice(0, 119)}…` : normalized;
}

export function recordProblem(problem: Omit<Problem, "id" | "at"> & { at?: string }): void {
  problems.unshift({ ...problem, id: nextId++, at: problem.at ?? new Date().toISOString() });
  if (problems.length > MAX_PROBLEMS) problems.length = MAX_PROBLEMS;
}

export function recordRequest(entry: {
  method: string;
  route: string;
  status: number;
  durationMs: number;
  code?: string;
  message?: string;
  requestId?: string;
  clientIp?: string;
  now?: number;
}): void {
  const now = entry.now ?? Date.now();
  const key = minuteKey(now);
  let bucket = minutes.get(key);
  if (!bucket) {
    bucket = { minute: new Date(key).toISOString(), requests: 0, clientErrors: 0, serverErrors: 0, slow: 0, totalMs: 0 };
    minutes.set(key, bucket);
    for (const old of minutes.keys()) if (old <= key - MINUTES_KEPT * 60_000) minutes.delete(old);
  }
  bucket.requests++;
  bucket.totalMs += entry.durationMs;
  const slow = entry.durationMs >= SLOW_REQUEST_MS;
  if (entry.status >= 500) bucket.serverErrors++;
  else if (entry.status >= 400) bucket.clientErrors++;
  if (slow) bucket.slow++;

  if (entry.status < 400 && !slow) return;
  recordProblem({
    at: new Date(now).toISOString(),
    kind: "request",
    severity: entry.status >= 500 ? "error" : "warning",
    title: `${entry.method} ${entry.route} → ${entry.status}${slow ? ` (slow, ${Math.round(entry.durationMs)} ms)` : ""}`,
    method: entry.method,
    route: entry.route,
    status: entry.status,
    code: entry.code,
    message: entry.message,
    durationMs: Math.round(entry.durationMs),
    requestId: entry.requestId,
    clientIp: entry.clientIp,
  });
}

/**
 * Endpoints the SDK on a phone calls (signed with the app credential), by
 * group — so the status page can answer "are phones getting through?".
 */
export const DEVICE_ROUTE_GROUPS: { id: string; label: string; prefix: string }[] = [
  { id: "events", label: "Security events & location heartbeats", prefix: "/v1/events" },
  { id: "devices", label: "Device registration", prefix: "/v1/devices" },
  { id: "risk", label: "Login & payment risk events", prefix: "/v1/risk" },
  { id: "ip_risk", label: "IP reputation", prefix: "/v1/ip-risk" },
  { id: "config", label: "Remote config", prefix: "/v1/config" },
  { id: "reputation", label: "Malware list", prefix: "/v1/reputation" },
];

export interface DeviceRouteStats {
  id: string;
  label: string;
  prefix: string;
  /** Last [MINUTES_KEPT] minutes. */
  ok: number;
  failed: number;
  lastOkAt: string | null;
  lastFailure: { at: string; status: number; code?: string } | null;
}

interface DeviceGroupState {
  minutes: Map<number, { ok: number; failed: number }>;
  lastOkAt: string | null;
  lastFailure: { at: string; status: number; code?: string } | null;
}
const deviceGroups = new Map<string, DeviceGroupState>();

export function deviceGroupOf(path: string): string | undefined {
  return DEVICE_ROUTE_GROUPS.find((g) => path === g.prefix || path.startsWith(`${g.prefix}/`))?.id;
}

export function recordDeviceCall(groupId: string, status: number, code: string | undefined, now = Date.now()): void {
  let state = deviceGroups.get(groupId);
  if (!state) {
    state = { minutes: new Map(), lastOkAt: null, lastFailure: null };
    deviceGroups.set(groupId, state);
  }
  const key = minuteKey(now);
  const bucket = state.minutes.get(key) ?? { ok: 0, failed: 0 };
  if (status < 400) {
    bucket.ok++;
    state.lastOkAt = new Date(now).toISOString();
  } else {
    bucket.failed++;
    state.lastFailure = { at: new Date(now).toISOString(), status, code };
  }
  state.minutes.set(key, bucket);
  for (const old of state.minutes.keys()) if (old <= key - MINUTES_KEPT * 60_000) state.minutes.delete(old);
}

export function deviceRouteStats(now = Date.now()): DeviceRouteStats[] {
  const oldest = minuteKey(now) - (MINUTES_KEPT - 1) * 60_000;
  return DEVICE_ROUTE_GROUPS.map((g) => {
    const state = deviceGroups.get(g.id);
    let ok = 0;
    let failed = 0;
    for (const [key, b] of state?.minutes ?? []) {
      if (key >= oldest) {
        ok += b.ok;
        failed += b.failed;
      }
    }
    return { ...g, ok, failed, lastOkAt: state?.lastOkAt ?? null, lastFailure: state?.lastFailure ?? null };
  });
}

/** Newest first. */
export function recentProblems(limit = MAX_PROBLEMS): Problem[] {
  return problems.slice(0, limit);
}

/** The last [MINUTES_KEPT] minutes, oldest first, with empty minutes filled in. */
export function minuteBuckets(now = Date.now()): MinuteBucket[] {
  const current = minuteKey(now);
  const out: MinuteBucket[] = [];
  for (let i = MINUTES_KEPT - 1; i >= 0; i--) {
    const key = current - i * 60_000;
    out.push(minutes.get(key) ?? { minute: new Date(key).toISOString(), requests: 0, clientErrors: 0, serverErrors: 0, slow: 0, totalMs: 0 });
  }
  return out;
}

/** Tests only. */
export function resetProblemLog(): void {
  problems.length = 0;
  minutes.clear();
  deviceGroups.clear();
  nextId = 1;
}
