"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import { Card, CopyButton, DownloadIcon, RiskBadge, SearchIcon, SpinnerIcon, StatusDot } from "@/components/ui";
import { EventDetailDrawer, type SecurityEvent } from "@/components/event-drawer";
import { deviceName, type PickerDevice } from "@/components/device-picker";
import { catalogFor } from "@/lib/alertCatalog";
import { LOG_LEVELS, THREAT_LEVELS, eventsToCsv, levelMeta, logLevelOf, saveTextFile, type LogLevel } from "@/lib/logLevels";
import { LIVE_REFRESH_MS, timeAgo } from "@/lib/usePolled";

const PAGE = 200;
/** Same cap as the backend's CSV export. */
const MAX_EXPORT_ROWS = 20_000;

type Page = { events: SecurityEvent[]; nextCursor: string | null };

interface LogRow {
  key: string;
  event: SecurityEvent;
  level: LogLevel;
  /** Consecutive identical reports folded into this row (1 = not folded). */
  repeat: number;
  oldestAt: string;
}

/**
 * Every log one device sent (all statuses, not only threats), newest first,
 * coloured by level. Live: re-reads the newest page every LIVE_REFRESH_MS
 * and merges it; older pages load on demand. The CSV holds every log of the
 * device that matches the current level and search filter.
 */
export function DeviceLogs({
  applicationId,
  appName,
  device,
  onClose,
}: {
  applicationId: string;
  appName: string;
  device: PickerDevice;
  onClose: () => void;
}) {
  const [events, setEvents] = useState<SecurityEvent[] | null>(null);
  const [olderCursor, setOlderCursor] = useState<string | null>(null);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [failed, setFailed] = useState(false);
  const [live, setLive] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [levels, setLevels] = useState<Set<LogLevel>>(() => new Set(LOG_LEVELS.map((l) => l.id)));
  const [query, setQuery] = useState("");
  const [fold, setFold] = useState(true);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [exportState, setExportState] = useState<{ rows: number } | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [, tick] = useState(0);
  const firstLoad = useRef(true);

  const base = `/v1/dashboard/applications/${applicationId}/events?deviceId=${encodeURIComponent(device.deviceId)}&limit=${PAGE}`;

  const loadNewest = useCallback(async () => {
    try {
      const page = await apiFetch<Page>(base);
      setEvents((prev) => mergeNewest(prev, page.events));
      if (firstLoad.current) {
        setOlderCursor(page.nextCursor);
        firstLoad.current = false;
      }
      setFailed(false);
      setUpdatedAt(Date.now());
    } catch {
      setFailed(true);
    }
  }, [base]);

  useEffect(() => {
    firstLoad.current = true;
    setEvents(null);
    setOlderCursor(null);
    setSelected(null);
    loadNewest();
  }, [loadNewest]);

  useEffect(() => {
    if (!live) return;
    const id = setInterval(loadNewest, LIVE_REFRESH_MS);
    return () => clearInterval(id);
  }, [live, loadNewest]);

  // Repaint "updated 5s ago".
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 5_000);
    return () => clearInterval(id);
  }, []);

  async function loadOlder() {
    if (!olderCursor) return;
    setLoadingOlder(true);
    try {
      const page = await apiFetch<Page>(`${base}&cursor=${encodeURIComponent(olderCursor)}`);
      setEvents((prev) => [...(prev ?? []), ...page.events.filter((e) => !(prev ?? []).some((p) => p.id === e.id))]);
      setOlderCursor(page.nextCursor);
    } finally {
      setLoadingOlder(false);
    }
  }

  const counts = useMemo(() => {
    const c = Object.fromEntries(LOG_LEVELS.map((l) => [l.id, 0])) as Record<LogLevel, number>;
    for (const e of events ?? []) c[logLevelOf(e.detectorId, e.status)]++;
    return c;
  }, [events]);

  const matches = useCallback(
    (e: SecurityEvent) => {
      if (!levels.has(logLevelOf(e.detectorId, e.status))) return false;
      const q = query.trim().toLowerCase();
      if (!q) return true;
      return [catalogFor(e.detectorId).title, e.detectorId, e.reason, e.status].some((v) => v?.toLowerCase().includes(q));
    },
    [levels, query],
  );

  const rows = useMemo(() => buildRows((events ?? []).filter(matches), fold), [events, matches, fold]);
  const shown = useMemo(() => (events ?? []).filter(matches).length, [events, matches]);

  /** Detectors whose newest loaded report is DETECTED — what is wrong right now. */
  const activeNow = useMemo(() => {
    const latest = new Map<string, SecurityEvent>();
    for (const e of events ?? []) if (!latest.has(e.detectorId)) latest.set(e.detectorId, e);
    return [...latest.values()]
      .filter((e) => e.status === "DETECTED")
      .map((e) => ({ id: e.detectorId, level: logLevelOf(e.detectorId, e.status) }))
      .sort((a, b) => THREAT_LEVELS.indexOf(a.level) - THREAT_LEVELS.indexOf(b.level));
  }, [events]);

  function toggleLevel(level: LogLevel) {
    setLevels((prev) => {
      const next = new Set(prev);
      if (next.has(level)) next.delete(level);
      else next.add(level);
      return next;
    });
  }

  function only(set: LogLevel[]) {
    setLevels(new Set(set));
  }

  async function exportCsv() {
    setExportError(null);
    setExportState({ rows: 0 });
    try {
      const all: SecurityEvent[] = [];
      let cursor: string | null = null;
      do {
        const page: Page = await apiFetch<Page>(cursor ? `${base}&cursor=${encodeURIComponent(cursor)}` : base);
        all.push(...page.events);
        cursor = page.nextCursor;
        setExportState({ rows: all.length });
      } while (cursor && all.length < MAX_EXPORT_ROWS);
      const picked = all.filter(matches);
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      const name = `${safe(appName)}_${safe(deviceName(device))}_${device.deviceId.slice(0, 8)}_logs_${stamp}.csv`;
      saveTextFile(name, eventsToCsv(picked));
    } catch {
      setExportError("Could not download the logs. Try again.");
    } finally {
      setExportState(null);
    }
  }

  const allLevels = levels.size === LOG_LEVELS.length;
  const total = events?.length ?? 0;

  return (
    <Card className="overflow-hidden">
      {/* Device header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-ink-100 px-5 py-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs text-ink-500 hover:bg-ink-50 hover:text-ink-800"
            >
              ← All devices
            </button>
            <h2 className="truncate text-lg font-semibold text-ink-900">{deviceName(device)}</h2>
            <RiskBadge score={device.riskScore} level={device.riskLevel} size="sm" />
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-500">
            <span>{device.osPlatform ? `${device.osPlatform} ${device.osVersion ?? ""}` : "OS unknown"}</span>
            {device.appVersion && <span>App {device.appVersion}</span>}
            {device.sdkVersion && <span>SDK {device.sdkVersion}</span>}
            <span>First seen {new Date(device.firstSeen).toLocaleDateString()}</span>
            <span>Last seen {timeAgo(device.lastSeen)}</span>
          </div>
          <div className="mt-1.5 flex items-center gap-2">
            <code className="truncate font-mono text-[11px] text-ink-400">{device.deviceId}</code>
            <CopyButton value={device.deviceId} label="ID" />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setLive((l) => !l)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-ink-200 px-2.5 py-1.5 text-xs font-medium text-ink-700 hover:bg-ink-50"
            title={live ? "Pause live updates" : "Resume live updates"}
          >
            <StatusDot tone={live ? "green" : "slate"} pulse={live} />
            {live ? "Live" : "Paused"}
            {updatedAt && <span className="text-ink-400">· {timeAgo(new Date(updatedAt).toISOString())}</span>}
          </button>
          <button
            type="button"
            onClick={exportCsv}
            disabled={exportState !== null || total === 0}
            className="inline-flex items-center gap-1.5 rounded-lg bg-brand-500 px-3 py-1.5 text-xs font-semibold text-navy-950 shadow-sm transition hover:bg-brand-400 disabled:cursor-not-allowed disabled:opacity-50"
            title="Every log of this device that matches the current level and search filter"
          >
            {exportState ? <SpinnerIcon size={14} /> : <DownloadIcon size={14} />}
            {exportState ? `Preparing ${exportState.rows.toLocaleString()}…` : "Download CSV"}
          </button>
        </div>
      </div>
      {exportError && <p className="border-b border-ink-100 bg-red-500/10 px-5 py-2 text-xs text-red-500">{exportError}</p>}

      {/* Active now + level mix */}
      <div className="grid gap-4 border-b border-ink-100 px-5 py-4 lg:grid-cols-2">
        <div>
          <div className="mb-2 text-[11px] font-medium uppercase tracking-wide text-ink-400">Active threats now</div>
          {events === null ? (
            <div className="h-6 w-2/3 animate-pulse rounded bg-ink-100" />
          ) : activeNow.length === 0 ? (
            <p className="text-xs text-ink-500">
              <span className="lvl-secure lvl-text font-medium">No detector is reporting a threat</span> in the loaded logs.
            </p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {activeNow.map((a) => (
                <span key={a.id} className={`lvl-${a.level} lvl-pill inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium`}>
                  <span className="lvl-dot h-1.5 w-1.5 rounded-full" />
                  {catalogFor(a.id).title}
                </span>
              ))}
            </div>
          )}
        </div>
        <div>
          <div className="mb-2 flex items-center justify-between text-[11px] font-medium uppercase tracking-wide text-ink-400">
            <span>Level mix · {total.toLocaleString()} loaded logs</span>
          </div>
          <LevelBar counts={counts} total={total} />
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 border-b border-ink-100 px-5 py-3">
        <button
          type="button"
          onClick={() => only(LOG_LEVELS.map((l) => l.id))}
          className={`rounded-full px-2.5 py-1 text-xs font-medium transition ${allLevels ? "bg-brand-500/15 text-brand-600 ring-1 ring-inset ring-brand-500/40" : "text-ink-500 hover:bg-ink-50"}`}
        >
          All {total}
        </button>
        <button
          type="button"
          onClick={() => only(THREAT_LEVELS)}
          className="rounded-full px-2.5 py-1 text-xs font-medium text-ink-500 transition hover:bg-ink-50"
        >
          Threats only
        </button>
        <span className="mx-1 h-4 w-px bg-ink-200" />
        {LOG_LEVELS.map((l) => {
          const on = levels.has(l.id);
          return (
            <button
              key={l.id}
              type="button"
              onClick={() => toggleLevel(l.id)}
              onDoubleClick={() => only([l.id])}
              title={`${l.hint} — click to toggle, double-click for only this level`}
              className={`lvl-${l.id} inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium transition ${
                on ? "lvl-chip-on" : "text-ink-400 line-through decoration-ink-300 hover:bg-ink-50"
              }`}
            >
              <span className={`lvl-dot h-1.5 w-1.5 rounded-full ${on ? "" : "opacity-40"}`} />
              {l.label}
              <span className="text-[11px] opacity-70">{counts[l.id]}</span>
            </button>
          );
        })}
        <div className="ml-auto flex items-center gap-3">
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-ink-500" title="Fold back-to-back identical reports into one row">
            <input type="checkbox" checked={fold} onChange={(e) => setFold(e.target.checked)} className="accent-brand-500" />
            Fold repeats
          </label>
          <div className="relative">
            <SearchIcon size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter logs…"
              className="w-44 rounded-lg border border-ink-200 bg-surface py-1.5 pl-7 pr-2 text-xs text-ink-900 outline-none focus:border-brand-500"
            />
          </div>
        </div>
      </div>

      {/* Log stream */}
      {events === null ? (
        failed ? (
          <p className="px-5 py-10 text-center text-sm text-ink-400">Could not load this device&apos;s logs.</p>
        ) : (
          <div className="space-y-2 p-5">
            {[0, 1, 2, 3, 4].map((i) => (
              <div key={i} className="h-9 animate-pulse rounded-lg bg-ink-100" />
            ))}
          </div>
        )
      ) : rows.length === 0 ? (
        <p className="px-5 py-12 text-center text-sm text-ink-400">
          {total === 0 ? "This device has not sent any logs." : "No log matches these levels and search."}
        </p>
      ) : (
        <div className="max-h-[38rem] overflow-y-auto">
          {groupByDay(rows).map(([day, dayRows]) => (
            <section key={day}>
              <div className="sticky top-0 z-10 border-b border-ink-100 bg-surface/95 px-5 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-500 backdrop-blur">
                {day}
                <span className="ml-2 font-normal normal-case text-ink-400">{dayRows.length} rows</span>
              </div>
              <ul>
                {dayRows.map((r) => (
                  <LogLine key={r.key} row={r} onOpen={() => setSelected(r.event)} />
                ))}
              </ul>
            </section>
          ))}
          <div className="flex items-center justify-between gap-3 border-t border-ink-100 px-5 py-3 text-xs text-ink-500">
            <span>
              Showing {shown.toLocaleString()} of {total.toLocaleString()} loaded logs
              {fold && rows.length < shown ? ` in ${rows.length.toLocaleString()} rows` : ""}
            </span>
            {olderCursor ? (
              <button
                type="button"
                onClick={loadOlder}
                disabled={loadingOlder}
                className="inline-flex items-center gap-1.5 rounded-lg border border-ink-200 px-3 py-1.5 font-medium text-ink-700 hover:bg-ink-50 disabled:opacity-50"
              >
                {loadingOlder && <SpinnerIcon size={12} />}
                Load older logs
              </button>
            ) : (
              <span className="text-ink-400">Start of this device&apos;s history</span>
            )}
          </div>
        </div>
      )}

      {selected && <EventDetailDrawer event={selected} onClose={() => setSelected(null)} />}
    </Card>
  );
}

function LogLine({ row, onOpen }: { row: LogRow; onOpen: () => void }) {
  const { event, level, repeat } = row;
  const meta = levelMeta(level);
  const catalog = catalogFor(event.detectorId);
  const t = new Date(event.receivedAt);
  return (
    <li>
      <button
        type="button"
        onClick={onOpen}
        className={`lvl-${level} lvl-row grid w-full grid-cols-[4.75rem_3.5rem_minmax(0,1fr)] items-center gap-x-3 border-b border-ink-100/70 px-5 py-2 text-left sm:grid-cols-[4.75rem_3.5rem_minmax(0,16rem)_minmax(0,1fr)_auto]`}
      >
        <span className="font-mono text-[12px] tabular-nums text-ink-500" title={t.toLocaleString()}>
          {t.toLocaleTimeString([], { hour12: false })}
        </span>
        <span className="lvl-pill rounded px-1.5 py-0.5 text-center font-mono text-[10px] font-bold tracking-wider" title={meta.hint}>
          {meta.short}
        </span>
        <span className="min-w-0">
          <span className="block truncate text-[13px] font-medium text-ink-900">{catalog.title}</span>
          <span className="block truncate font-mono text-[11px] text-ink-500">{event.detectorId}</span>
        </span>
        <span className="hidden min-w-0 truncate text-xs text-ink-600 sm:block" title={event.reason ?? undefined}>
          {event.reason ?? <span className="text-ink-400">{event.status.toLowerCase()}</span>}
        </span>
        <span className="hidden items-center gap-2 sm:flex">
          {repeat > 1 && (
            <span
              className="rounded-full bg-ink-100 px-2 py-0.5 font-mono text-[10px] text-ink-600"
              title={`${repeat} identical reports, ${new Date(row.oldestAt).toLocaleTimeString([], { hour12: false })} – ${t.toLocaleTimeString([], { hour12: false })}`}
            >
              ×{repeat}
            </span>
          )}
          <span className="lvl-text text-[10px] font-semibold uppercase tracking-wide">{event.status}</span>
        </span>
      </button>
    </li>
  );
}

function LevelBar({ counts, total }: { counts: Record<LogLevel, number>; total: number }) {
  if (total === 0) return <div className="h-2.5 rounded-full bg-ink-100" />;
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-full bg-ink-100">
        {LOG_LEVELS.filter((l) => counts[l.id] > 0).map((l) => (
          <span
            key={l.id}
            className={`lvl-${l.id} lvl-dot h-full`}
            style={{ width: `${(counts[l.id] / total) * 100}%` }}
            title={`${l.label}: ${counts[l.id]}`}
          />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
        {LOG_LEVELS.filter((l) => counts[l.id] > 0).map((l) => (
          <span key={l.id} className={`lvl-${l.id} inline-flex items-center gap-1 text-[11px] text-ink-500`}>
            <span className="lvl-dot h-1.5 w-1.5 rounded-full" />
            {l.label} <span className="lvl-text font-medium">{Math.round((counts[l.id] / total) * 100)}%</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function mergeNewest(prev: SecurityEvent[] | null, newest: SecurityEvent[]): SecurityEvent[] {
  if (!prev) return newest;
  const seen = new Set(newest.map((e) => e.id));
  return [...newest, ...prev.filter((e) => !seen.has(e.id))];
}

function buildRows(events: SecurityEvent[], fold: boolean): LogRow[] {
  const rows: LogRow[] = [];
  for (const e of events) {
    const level = logLevelOf(e.detectorId, e.status);
    const last = rows[rows.length - 1];
    if (
      fold &&
      last &&
      last.event.detectorId === e.detectorId &&
      last.event.status === e.status &&
      (last.event.reason ?? "") === (e.reason ?? "") &&
      dayKey(last.oldestAt) === dayKey(e.receivedAt)
    ) {
      last.repeat++;
      last.oldestAt = e.receivedAt;
      continue;
    }
    rows.push({ key: e.id, event: e, level, repeat: 1, oldestAt: e.receivedAt });
  }
  return rows;
}

function dayKey(iso: string) {
  return new Date(iso).toDateString();
}

function groupByDay(rows: LogRow[]): [string, LogRow[]][] {
  const today = new Date().toDateString();
  const yesterday = new Date(Date.now() - 86_400_000).toDateString();
  const groups = new Map<string, LogRow[]>();
  for (const r of rows) {
    const k = dayKey(r.event.receivedAt);
    const label =
      k === today ? "Today" : k === yesterday ? "Yesterday" : new Date(r.event.receivedAt).toLocaleDateString([], { weekday: "short", day: "numeric", month: "short", year: "numeric" });
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label)!.push(r);
  }
  return [...groups.entries()];
}

function safe(s: string) {
  return s.replace(/[^a-z0-9]+/gi, "_").replace(/^_+|_+$/g, "").slice(0, 40) || "device";
}
