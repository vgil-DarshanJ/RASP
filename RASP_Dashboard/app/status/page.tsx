"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  ActivityIcon,
  AlertTriangleIcon,
  Badge,
  Button,
  Card,
  CheckCircleIcon,
  ClockIcon,
  CopyButton,
  ShieldIcon,
  SmartphoneIcon,
} from "@/components/ui";
import { ThemeToggle } from "@/components/theme-toggle";
import { hasSession, getStoredUser } from "@/lib/auth";
import { CLIENT_PROBLEMS_EVENT, ClientProblem, clearClientProblems, readClientProblems } from "@/lib/clientProblems";
import { explain } from "@/lib/problemCatalog";
import { API_BASE, PORTAL_URL, VISITOR_URL } from "@/lib/sites";

/* ─── Backend payload (GET /v1/system/status) ─────────────────────────── */

interface CheckResult {
  id: string;
  label: string;
  ok: boolean;
  configured: boolean;
  latencyMs: number;
  detail: string;
}
interface Problem {
  id: number;
  at: string;
  kind: "request" | "check" | "process";
  severity: "error" | "warning";
  title: string;
  method?: string;
  route?: string;
  status?: number;
  code?: string;
  message?: string;
  durationMs?: number;
  requestId?: string;
  clientIp?: string;
}
interface MinuteBucket {
  minute: string;
  requests: number;
  clientErrors: number;
  serverErrors: number;
  slow: number;
}
interface Counts {
  requests: number;
  clientErrors: number;
  serverErrors: number;
  slow: number;
}
interface DeviceRoute {
  id: string;
  label: string;
  prefix: string;
  ok: number;
  failed: number;
  lastOkAt: string | null;
  lastFailure: { at: string; status: number; code?: string } | null;
}
interface SystemStatus {
  generatedAt: string;
  checkIntervalSeconds: number;
  server: { version: string; node: string; environment: string; host: string; startedAt: string; uptimeSeconds: number; memoryMb: number };
  checks: CheckResult[];
  checkedAt: string;
  checkHistory: { at: string; failed: string[] }[];
  configuration: { warnings: string[]; corsOrigins: string[]; dashboardUrl: string | null; visitorSiteUrl: string | null; ingestionUrl: string };
  traffic: MinuteBucket[];
  summary: { last5Minutes: Counts; last60Minutes: Counts };
  problems: Problem[];
  devices: {
    routes: DeviceRoute[];
    organization: {
      lastEventAt: string | null;
      lastHeartbeatAt: string | null;
      lastDeviceSeenAt: string | null;
      activeDevices: number;
      activeWindowMinutes: number;
      registeredDevices: number;
    } | null;
  };
}

/* ─── Browser-side probe: can THIS page reach the backend? ────────────── */

type BrowserState = "checking" | "ok" | "degraded" | "cors" | "mixed" | "down";
interface BrowserProbe {
  state: BrowserState;
  latencyMs: number | null;
  postgres: boolean | null;
  redis: boolean | null;
}

async function probeBackend(): Promise<BrowserProbe> {
  const started = performance.now();
  try {
    const res = await fetch(`${API_BASE}/healthz`, { cache: "no-store" });
    const body = await res.json().catch(() => null);
    const latencyMs = Math.round(performance.now() - started);
    return { state: res.ok && body?.ok ? "ok" : "degraded", latencyMs, postgres: body?.postgres ?? null, redis: body?.redis ?? null };
  } catch {
    if (window.location.protocol === "https:" && API_BASE.startsWith("http:")) {
      return { state: "mixed", latencyMs: null, postgres: null, redis: null };
    }
    // An opaque (no-cors) request still succeeds when the server answers:
    // then the backend is up and only CORS refused this page.
    try {
      await fetch(`${API_BASE}/healthz`, { mode: "no-cors", cache: "no-store" });
      return { state: "cors", latencyMs: null, postgres: null, redis: null };
    } catch {
      return { state: "down", latencyMs: null, postgres: null, redis: null };
    }
  }
}

type StatusLoad =
  | { state: "loading" }
  | { state: "ok"; data: SystemStatus }
  | { state: "signin" }
  | { state: "unreachable" }
  | { state: "error"; status: number };

async function loadStatus(): Promise<StatusLoad> {
  try {
    const res = await fetch(`${API_BASE}/v1/system/status`, { credentials: "include", cache: "no-store" });
    if (res.status === 401) return { state: "signin" };
    if (!res.ok) return { state: "error", status: res.status };
    return { state: "ok", data: (await res.json()) as SystemStatus };
  } catch {
    return { state: "unreachable" };
  }
}

/* ─── Helpers ─────────────────────────────────────────────────────────── */

const REFRESH_SECONDS = 60;

function ago(iso: string | null | undefined, now: number): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ago`;
  return `${Math.floor(h / 24)} d ago`;
}

function clock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function duration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m ${seconds % 60}s`;
}

type Tone = "green" | "red" | "amber" | "slate";

const BROWSER_TEXT: Record<BrowserState, { tone: Tone; title: string; detail: string }> = {
  checking: { tone: "slate", title: "Checking…", detail: "" },
  ok: { tone: "green", title: "Connected", detail: "This page reaches the backend and the backend reaches its database and cache." },
  degraded: { tone: "red", title: "Backend answers, but a dependency is down", detail: "See PostgreSQL / Redis below." },
  cors: {
    tone: "red",
    title: "Backend is running but refuses this page (CORS)",
    detail: "Add this page's origin to CORS_ORIGINS in the backend .env, then restart the backend.",
  },
  mixed: {
    tone: "red",
    title: "Blocked: HTTPS page calling an HTTP backend",
    detail: "Open the portal over http://, or put the backend behind HTTPS too.",
  },
  down: {
    tone: "red",
    title: "No answer from the backend",
    detail: "The backend is stopped, the address is wrong, or a firewall blocks the port. On the server: scripts/office-server.sh status",
  },
};

/** One line of the verdict list. */
interface Issue {
  tone: "red" | "amber";
  text: string;
  fix?: string;
}

/* ─── Page ────────────────────────────────────────────────────────────── */

export default function SystemStatusPage() {
  const [browser, setBrowser] = useState<BrowserProbe>({ state: "checking", latencyMs: null, postgres: null, redis: null });
  const [status, setStatus] = useState<StatusLoad>({ state: "loading" });
  const [clientProblems, setClientProblems] = useState<ClientProblem[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const [nextRefreshAt, setNextRefreshAt] = useState(() => Date.now() + REFRESH_SECONDS * 1000);
  const [refreshing, setRefreshing] = useState(false);
  const [runningChecks, setRunningChecks] = useState(false);
  const [filter, setFilter] = useState<"all" | "error" | "warning" | "phones">("all");
  const [signedIn, setSignedIn] = useState(false);
  const [origin, setOrigin] = useState("");

  const refresh = useCallback(async () => {
    setRefreshing(true);
    const [b, s] = await Promise.all([probeBackend(), loadStatus()]);
    setBrowser(b);
    setStatus(s);
    setClientProblems(readClientProblems());
    setNextRefreshAt(Date.now() + REFRESH_SECONDS * 1000);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    setSignedIn(hasSession());
    setOrigin(window.location.origin);
    refresh();
    const onClient = () => setClientProblems(readClientProblems());
    window.addEventListener(CLIENT_PROBLEMS_EVENT, onClient);
    return () => window.removeEventListener(CLIENT_PROBLEMS_EVENT, onClient);
  }, [refresh]);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!refreshing && now >= nextRefreshAt) refresh();
  }, [now, nextRefreshAt, refreshing, refresh]);

  async function runChecksNow() {
    setRunningChecks(true);
    try {
      await fetch(`${API_BASE}/v1/system/checks`, { method: "POST", credentials: "include" });
    } finally {
      setRunningChecks(false);
      refresh();
    }
  }

  const data = status.state === "ok" ? status.data : null;
  const isAdmin = ["OWNER", "ADMIN"].includes(getStoredUser()?.role ?? "");

  const issues = useMemo<Issue[]>(() => {
    const list: Issue[] = [];
    if (browser.state !== "ok" && browser.state !== "checking") {
      list.push({ tone: "red", text: `This browser → backend: ${BROWSER_TEXT[browser.state].title}`, fix: BROWSER_TEXT[browser.state].detail });
    }
    if (status.state === "signin") list.push({ tone: "amber", text: "Sign in to the portal to see the backend's checks, traffic and errors." });
    if (status.state === "error") list.push({ tone: "red", text: `The status endpoint answered HTTP ${status.status}.`, fix: "The backend may be an older version: git pull and restart it." });
    if (!data) return list;
    for (const c of data.checks) if (c.configured && !c.ok) list.push({ tone: "red", text: `${c.label}: ${c.detail}` });
    for (const w of data.configuration.warnings) list.push({ tone: "amber", text: w });
    const s5 = data.summary.last5Minutes;
    if (s5.serverErrors > 0) list.push({ tone: "red", text: `${s5.serverErrors} server error${s5.serverErrors === 1 ? "" : "s"} (HTTP 5xx) in the last 5 minutes.`, fix: "See Recent problems below; look up the request id in the backend log." });
    for (const r of data.devices.routes) {
      if (r.lastFailure && now - new Date(r.lastFailure.at).getTime() < 10 * 60_000 && (!r.lastOkAt || r.lastOkAt < r.lastFailure.at)) {
        const e = explain(r.lastFailure.code, r.lastFailure.status);
        list.push({ tone: "red", text: `Phones → ${r.label}: last call failed (${r.lastFailure.code ?? `HTTP ${r.lastFailure.status}`}). ${e.meaning}`, fix: e.fix });
      }
    }
    const org = data.devices.organization;
    if (org && org.registeredDevices > 0 && org.activeDevices === 0) {
      list.push({ tone: "amber", text: `No phone has reached the backend in the last ${org.activeWindowMinutes} minutes (last seen ${ago(org.lastDeviceSeenAt, now)}).`, fix: "Open the app on the phone. It must be on the office Wi-Fi and its credential must point at this backend." });
    }
    return list;
  }, [browser.state, status, data, now]);

  const verdictTone: Tone = browser.state === "checking" || status.state === "loading" ? "slate" : issues.some((i) => i.tone === "red") ? "red" : issues.length > 0 ? "amber" : "green";
  const secondsLeft = Math.max(0, Math.ceil((nextRefreshAt - now) / 1000));

  const problems = (data?.problems ?? []).filter((p) => {
    if (filter === "error") return p.severity === "error";
    if (filter === "warning") return p.severity === "warning";
    if (filter === "phones") return data?.devices.routes.some((r) => p.route?.startsWith(r.prefix));
    return true;
  });

  return (
    <div className="min-h-screen bg-ink-50">
      <header className="border-b border-ink-100 bg-surface">
        <div className="mx-auto flex max-w-6xl items-center gap-3 px-6 py-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-500/15 text-brand-600 ring-1 ring-brand-400/25">
            <ShieldIcon size={18} />
          </div>
          <div className="flex-1 leading-tight">
            <div className="text-sm font-bold tracking-[0.1em] text-ink-900">RASHIELD</div>
            <div className="text-xs text-ink-500">System status</div>
          </div>
          {signedIn ? (
            <Link href="/dashboard" className="text-sm font-medium text-brand-700 hover:underline">Back to dashboard</Link>
          ) : (
            <Link href="/login" className="text-sm font-medium text-brand-700 hover:underline">Sign in</Link>
          )}
          <ThemeToggle />
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-6 px-6 py-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-ink-900">System status</h1>
            <p className="mt-1 text-sm text-ink-500">
              Is the whole chain working: portal → backend → database, and phones → backend. Refreshes every minute.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 text-xs text-ink-500">
              <ClockIcon size={14} /> {refreshing ? "Refreshing…" : `Next refresh in ${secondsLeft}s`}
            </span>
            {data && isAdmin && (
              <Button variant="secondary" size="sm" loading={runningChecks} onClick={runChecksNow}>Run checks now</Button>
            )}
            <Button size="sm" loading={refreshing} onClick={refresh}>Refresh</Button>
          </div>
        </div>

        <Verdict tone={verdictTone} issues={issues} />

        <FlowMap browser={browser} data={data} statusState={status.state} now={now} origin={origin} />

        {data && <ChecksCard data={data} />}
        {data && <PhonesCard data={data} now={now} />}
        {data && <TrafficCard data={data} />}

        {data && (
          <Card className="p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-ink-900">Recent problems on the backend</h2>
                <p className="text-xs text-ink-500">Failed or slow requests, failed checks and background errors, newest first. Kept since the backend last started.</p>
              </div>
              <div className="flex gap-1 rounded-lg bg-ink-100 p-1 text-xs">
                {(["all", "error", "warning", "phones"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`rounded-md px-3 py-1 font-medium ${filter === f ? "bg-surface text-ink-900 shadow-sm" : "text-ink-500 hover:text-ink-800"}`}
                  >
                    {f === "all" ? "All" : f === "error" ? "Errors" : f === "warning" ? "Warnings" : "Phones"}
                  </button>
                ))}
              </div>
            </div>
            {problems.length === 0 ? (
              <EmptyLine text="Nothing to show. No problems recorded." />
            ) : (
              <ul className="mt-4 divide-y divide-ink-100">
                {problems.slice(0, 100).map((p) => <ProblemRow key={p.id} p={p} now={now} showIp={isAdmin} />)}
              </ul>
            )}
          </Card>
        )}

        <Card className="p-6">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-ink-900">This browser</h2>
              <p className="text-xs text-ink-500">API calls from this tab that failed, including ones that never reached the backend.</p>
            </div>
            {clientProblems.length > 0 && <Button variant="ghost" size="sm" onClick={clearClientProblems}>Clear</Button>}
          </div>
          {clientProblems.length === 0 ? (
            <EmptyLine text="No failed calls from this tab." />
          ) : (
            <ul className="mt-4 divide-y divide-ink-100">
              {clientProblems.map((p, i) => (
                <ProblemRow
                  key={`${p.at}-${i}`}
                  now={now}
                  showIp={false}
                  p={{ id: i, at: p.at, kind: "request", severity: p.status === 0 || p.status >= 500 ? "error" : "warning", title: `${p.method} ${p.path} → ${p.status === 0 ? "no answer" : p.status}`, status: p.status, code: p.code, requestId: p.requestId }}
                />
              ))}
            </ul>
          )}
        </Card>

        <ConfigCard data={data} origin={origin} />
      </main>
    </div>
  );
}

/* ─── Sections ────────────────────────────────────────────────────────── */

function Verdict({ tone, issues }: { tone: Tone; issues: Issue[] }) {
  const styles: Record<Tone, string> = {
    green: "border-emerald-200 bg-emerald-50 text-emerald-900",
    red: "border-red-200 bg-red-50 text-red-900",
    amber: "border-amber-200 bg-amber-50 text-amber-900",
    slate: "border-ink-200 bg-surface text-ink-700",
  };
  const title =
    tone === "green" ? "Everything is working" : tone === "slate" ? "Checking…" : `${issues.length} thing${issues.length === 1 ? "" : "s"} need${issues.length === 1 ? "s" : ""} attention`;
  return (
    <div className={`rounded-2xl border p-5 ${styles[tone]}`}>
      <div className="flex items-center gap-2 text-base font-semibold">
        {tone === "green" ? <CheckCircleIcon size={20} /> : tone === "slate" ? <ActivityIcon size={20} /> : <AlertTriangleIcon size={20} />}
        {title}
      </div>
      {issues.length > 0 && (
        <ul className="mt-3 space-y-2 text-sm">
          {issues.map((i, n) => (
            <li key={n} className="flex gap-2">
              <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${i.tone === "red" ? "bg-red-500" : "bg-amber-500"}`} />
              <span>
                {i.text}
                {i.fix && <span className="block text-xs opacity-80">What to do: {i.fix}</span>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Node({ title, sub, tone, children }: { title: string; sub: string; tone: Tone; children?: React.ReactNode }) {
  const ring: Record<Tone, string> = {
    green: "ring-emerald-300",
    red: "ring-red-300",
    amber: "ring-amber-300",
    slate: "ring-ink-200",
  };
  const dot: Record<Tone, string> = { green: "bg-emerald-500", red: "bg-red-500", amber: "bg-amber-500", slate: "bg-ink-400" };
  return (
    <div className={`min-w-0 flex-1 rounded-xl bg-surface p-4 ring-2 ${ring[tone]}`}>
      <div className="flex items-center gap-2">
        <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${dot[tone]}`} />
        <div className="truncate text-sm font-semibold text-ink-900">{title}</div>
      </div>
      <div className="mt-1 break-all font-mono text-[11px] text-ink-500">{sub}</div>
      {children && <div className="mt-2 text-xs text-ink-600">{children}</div>}
    </div>
  );
}

function Arrow({ ok }: { ok: boolean | null }) {
  return (
    <div className={`hidden shrink-0 items-center self-center text-lg font-bold md:flex ${ok === false ? "text-red-500" : ok ? "text-emerald-500" : "text-ink-300"}`}>
      →
    </div>
  );
}

function FlowMap({ browser, data, statusState, now, origin }: { browser: BrowserProbe; data: SystemStatus | null; statusState: StatusLoad["state"]; now: number; origin: string }) {
  const check = (id: string) => data?.checks.find((c) => c.id === id);
  const toneOf = (ok: boolean | null | undefined, configured = true): Tone => (!configured || ok === null || ok === undefined ? "slate" : ok ? "green" : "red");
  const browserOk = browser.state === "checking" ? null : browser.state === "ok" || browser.state === "degraded";
  const pg = check("postgres")?.ok ?? browser.postgres;
  const rd = check("redis")?.ok ?? browser.redis;
  const portal = check("portal");
  const visitor = check("visitor");
  const events = data?.devices.routes.find((r) => r.id === "events");
  const phonesTone: Tone = !events ? "slate" : events.failed > 0 && (!events.lastOkAt || (events.lastFailure && events.lastOkAt < events.lastFailure.at)) ? "red" : events.ok > 0 ? "green" : "slate";

  return (
    <Card className="p-6">
      <h2 className="text-base font-semibold text-ink-900">How the pieces connect</h2>
      <p className="text-xs text-ink-500">Green = working, red = broken, grey = no data yet or not set up.</p>

      <div className="mt-5 text-[11px] font-semibold uppercase tracking-wider text-ink-400">Websites → backend → data</div>
      <div className="mt-2 flex flex-col gap-3 md:flex-row">
        <div className="flex min-w-0 flex-1 flex-col gap-3">
          <Node title="This browser" sub={origin} tone={browserOk === null ? "slate" : browserOk ? "green" : "red"}>
            {BROWSER_TEXT[browser.state].title}
            {browser.latencyMs !== null && ` · ${browser.latencyMs} ms`}
          </Node>
          <Node title="Customer portal" sub={PORTAL_URL ?? data?.configuration.dashboardUrl ?? "not set"} tone={toneOf(portal?.ok, portal?.configured)}>
            {portal ? portal.detail : "Checked by the backend once signed in"}
          </Node>
          <Node title="Visitor site" sub={VISITOR_URL ?? data?.configuration.visitorSiteUrl ?? "not set"} tone={toneOf(visitor?.ok, visitor?.configured)}>
            {visitor ? visitor.detail : "Checked by the backend once signed in"}
          </Node>
        </div>
        <Arrow ok={browserOk} />
        <div className="flex min-w-0 flex-1 flex-col">
          <Node title="Backend API" sub={API_BASE} tone={browserOk === null ? "slate" : browserOk ? "green" : "red"}>
            {data ? (
              <>Up {duration(data.server.uptimeSeconds)} · v{data.server.version} · {data.summary.last60Minutes.requests} requests in the last hour</>
            ) : statusState === "signin" ? (
              "Sign in for details"
            ) : (
              BROWSER_TEXT[browser.state].detail
            )}
          </Node>
        </div>
        <Arrow ok={pg === null || rd === null ? null : pg && rd} />
        <div className="flex min-w-0 flex-1 flex-col gap-3">
          <Node title="PostgreSQL" sub="database" tone={toneOf(pg)}>{check("postgres")?.detail ?? (pg === null ? "unknown" : pg ? "Connected" : "Down")}</Node>
          <Node title="Redis" sub="cache, rate limits, replay check" tone={toneOf(rd)}>{check("redis")?.detail ?? (rd === null ? "unknown" : rd ? "Connected" : "Down")}</Node>
          <Node title="Migrations" sub="database schema" tone={toneOf(check("migrations")?.ok)}>{check("migrations")?.detail ?? "Sign in for details"}</Node>
        </div>
      </div>

      <div className="mt-6 text-[11px] font-semibold uppercase tracking-wider text-ink-400">Phones → backend</div>
      <div className="mt-2 flex flex-col gap-3 md:flex-row">
        <Node title="Phones (RASP SDK)" sub={data?.configuration.ingestionUrl ?? "credential ingestion_url"} tone={phonesTone}>
          {data?.devices.organization
            ? `${data.devices.organization.activeDevices} active in the last ${data.devices.organization.activeWindowMinutes} min · last event ${ago(data.devices.organization.lastEventAt, now)} · last heartbeat ${ago(data.devices.organization.lastHeartbeatAt, now)}`
            : "Sign in for details"}
        </Node>
        <Arrow ok={phonesTone === "slate" ? null : phonesTone === "green"} />
        <Node title="Backend API" sub="signed with the app credential" tone={phonesTone}>
          {events ? `${events.ok} accepted, ${events.failed} refused in the last hour` : "—"}
        </Node>
      </div>
    </Card>
  );
}

function ChecksCard({ data }: { data: SystemStatus }) {
  return (
    <Card className="p-6">
      <h2 className="text-base font-semibold text-ink-900">Backend checks</h2>
      <p className="text-xs text-ink-500">Run by the backend every {data.checkIntervalSeconds}s. Last run {clock(data.checkedAt)}. The strip shows the last hour, one block per minute.</p>
      <div className="mt-4 divide-y divide-ink-100">
        {data.checks.map((c) => (
          <div key={c.id} className="grid gap-2 py-3 md:grid-cols-[220px_1fr_auto] md:items-center">
            <div className="flex items-center gap-2">
              <Badge tone={!c.configured ? "slate" : c.ok ? "green" : "red"}>{!c.configured ? "Not set" : c.ok ? "OK" : "Failing"}</Badge>
              <span className="text-sm font-medium text-ink-900">{c.label}</span>
            </div>
            <div className="text-sm text-ink-600">{c.detail} <span className="text-xs text-ink-400">· {c.latencyMs} ms</span></div>
            <div className="flex gap-[2px]" aria-label="last hour">
              {data.checkHistory.slice(-60).map((h) => {
                const bad = h.failed.includes(c.id);
                return <span key={h.at} title={`${clock(h.at)}: ${bad ? "failed" : "ok"}`} className={`h-4 w-1 rounded-sm ${!c.configured ? "bg-ink-200" : bad ? "bg-red-500" : "bg-emerald-400"}`} />;
              })}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function PhonesCard({ data, now }: { data: SystemStatus; now: number }) {
  const org = data.devices.organization;
  return (
    <Card className="p-6">
      <div className="flex items-center gap-2">
        <SmartphoneIcon size={18} className="text-ink-500" />
        <h2 className="text-base font-semibold text-ink-900">Phones → backend</h2>
      </div>
      <p className="text-xs text-ink-500">
        Calls the SDK makes with the pasted credential, last hour. Phones must reach <span className="font-mono">{data.configuration.ingestionUrl}</span> (same Wi-Fi as the server).
      </p>
      {org && (
        <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Fact label="Active phones" value={`${org.activeDevices} / ${org.registeredDevices}`} sub={`seen in the last ${org.activeWindowMinutes} min`} />
          <Fact label="Last detector event" value={ago(org.lastEventAt, now)} />
          <Fact label="Last location heartbeat" value={ago(org.lastHeartbeatAt, now)} sub="only while location sharing is on" />
          <Fact label="Last phone seen" value={ago(org.lastDeviceSeenAt, now)} />
        </div>
      )}
      <div className="mt-4 overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs uppercase tracking-wide text-ink-400">
              <th className="py-2 pr-4 font-medium">Endpoint</th>
              <th className="py-2 pr-4 font-medium">Accepted</th>
              <th className="py-2 pr-4 font-medium">Refused</th>
              <th className="py-2 pr-4 font-medium">Last accepted</th>
              <th className="py-2 font-medium">Last refusal</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-100">
            {data.devices.routes.map((r) => (
              <tr key={r.id} className="align-top">
                <td className="py-2.5 pr-4">
                  <div className="font-medium text-ink-900">{r.label}</div>
                  <div className="font-mono text-[11px] text-ink-400">{r.prefix}</div>
                </td>
                <td className="py-2.5 pr-4 text-ink-700">{r.ok}</td>
                <td className={`py-2.5 pr-4 ${r.failed > 0 ? "font-semibold text-red-600" : "text-ink-700"}`}>{r.failed}</td>
                <td className="py-2.5 pr-4 text-ink-600">{ago(r.lastOkAt, now)}</td>
                <td className="py-2.5 text-ink-600">
                  {r.lastFailure ? (
                    <>
                      <span className="font-mono text-xs">{r.lastFailure.code ?? `HTTP ${r.lastFailure.status}`}</span> · {ago(r.lastFailure.at, now)}
                      <div className="text-xs text-ink-500">{explain(r.lastFailure.code, r.lastFailure.status).fix}</div>
                    </>
                  ) : (
                    "none"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function TrafficCard({ data }: { data: SystemStatus }) {
  const rows = data.traffic.map((b) => ({
    t: new Date(b.minute).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    OK: b.requests - b.clientErrors - b.serverErrors,
    "4xx refused": b.clientErrors,
    "5xx failed": b.serverErrors,
  }));
  const s = data.summary;
  return (
    <Card className="p-6">
      <h2 className="text-base font-semibold text-ink-900">Requests per minute (last hour)</h2>
      <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Fact label="Requests (5 min)" value={String(s.last5Minutes.requests)} />
        <Fact label="Refused 4xx (5 min)" value={String(s.last5Minutes.clientErrors)} />
        <Fact label="Failed 5xx (5 min)" value={String(s.last5Minutes.serverErrors)} tone={s.last5Minutes.serverErrors > 0 ? "red" : undefined} />
        <Fact label="Slow > 3 s (60 min)" value={String(s.last60Minutes.slow)} />
      </div>
      <div className="mt-4 h-56">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(127,127,127,0.2)" />
            <XAxis dataKey="t" tick={{ fontSize: 10 }} interval={9} />
            <YAxis allowDecimals={false} tick={{ fontSize: 10 }} />
            <Tooltip />
            <Bar dataKey="OK" stackId="a" fill="#34d399" />
            <Bar dataKey="4xx refused" stackId="a" fill="#f59e0b" />
            <Bar dataKey="5xx failed" stackId="a" fill="#ef4444" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

function ConfigCard({ data, origin }: { data: SystemStatus | null; origin: string }) {
  const corsOk = data ? data.configuration.corsOrigins.includes(origin) : null;
  return (
    <Card className="p-6">
      <h2 className="text-base font-semibold text-ink-900">Addresses and configuration</h2>
      <dl className="mt-4 grid gap-x-6 gap-y-3 text-sm md:grid-cols-2">
        <Row label="Backend this page calls" value={API_BASE} copy />
        <Row label="This page's origin" value={origin || "—"}>
          {corsOk === false && <span className="ml-2 text-xs font-medium text-red-600">not in CORS_ORIGINS</span>}
        </Row>
        <Row label="Customer portal" value={PORTAL_URL ?? data?.configuration.dashboardUrl ?? "not set"} />
        <Row label="Visitor site" value={VISITOR_URL ?? data?.configuration.visitorSiteUrl ?? "not set"} />
        {data && (
          <>
            <Row label="Ingestion URL in new credentials" value={data.configuration.ingestionUrl} copy />
            <Row label="CORS_ORIGINS" value={data.configuration.corsOrigins.join(", ")} />
            <Row label="Backend" value={`v${data.server.version} · ${data.server.environment} · Node ${data.server.node} · ${data.server.memoryMb} MB`} />
            <Row label="Started" value={`${new Date(data.server.startedAt).toLocaleString()} on ${data.server.host}`} />
          </>
        )}
      </dl>
    </Card>
  );
}

/* ─── Small pieces ────────────────────────────────────────────────────── */

function ProblemRow({ p, now, showIp }: { p: Problem; now: number; showIp: boolean }) {
  const e = p.kind === "request" ? explain(p.code, p.status) : null;
  return (
    <li className="py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${p.severity === "error" ? "bg-red-500" : "bg-amber-500"}`} />
        <span className="font-mono text-xs text-ink-400" title={new Date(p.at).toLocaleString()}>{clock(p.at)} · {ago(p.at, now)}</span>
        <span className="text-sm font-medium text-ink-900">{p.title}</span>
        {p.code && <span className="rounded bg-ink-100 px-1.5 py-0.5 font-mono text-[11px] text-ink-700">{p.code}</span>}
      </div>
      <div className="ml-4 mt-1 space-y-0.5 text-xs text-ink-600">
        {p.message && <div className="font-mono text-ink-500">{p.message}</div>}
        {e && <div><span className="font-medium text-ink-700">Meaning:</span> {e.meaning}</div>}
        {e && <div><span className="font-medium text-ink-700">What to do:</span> {e.fix}</div>}
        <div className="text-ink-400">
          {p.requestId && <>request id <span className="font-mono">{p.requestId}</span></>}
          {p.durationMs !== undefined && <> · {p.durationMs} ms</>}
          {showIp && p.clientIp && <> · from {p.clientIp}</>}
        </div>
      </div>
    </li>
  );
}

function Fact({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: "red" }) {
  return (
    <div className="rounded-xl bg-ink-50 p-3 ring-1 ring-inset ring-ink-100">
      <div className="text-[11px] font-medium uppercase tracking-wide text-ink-400">{label}</div>
      <div className={`mt-1 text-lg font-semibold ${tone === "red" ? "text-red-600" : "text-ink-900"}`}>{value}</div>
      {sub && <div className="text-[11px] text-ink-400">{sub}</div>}
    </div>
  );
}

function Row({ label, value, copy, children }: { label: string; value: string; copy?: boolean; children?: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-ink-400">{label}</dt>
      <dd className="mt-0.5 flex flex-wrap items-center gap-2 break-all font-mono text-[13px] text-ink-800">
        {value}
        {copy && <CopyButton value={value} />}
        {children}
      </dd>
    </div>
  );
}

function EmptyLine({ text }: { text: string }) {
  return <div className="mt-4 rounded-xl border border-dashed border-ink-200 p-4 text-center text-sm text-ink-500">{text}</div>;
}
