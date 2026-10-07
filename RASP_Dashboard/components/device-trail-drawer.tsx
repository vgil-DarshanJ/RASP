"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import { Badge, CategoryChip, PlatformIcon, XIcon, statusTone } from "@/components/ui";
import { ALL_CATEGORIES, CATEGORY_COLORS, catalogFor, type AlertCategory } from "@/lib/alertCatalog";
import { EventDetailDrawer, type SecurityEvent } from "@/components/event-drawer";
import { DeviceRiskCard } from "@/components/risk-events";

/** The latest `high_risk_ip` result for a device, as the SDK reports it. */
interface IpRiskResult {
  status: string;
  country: string | null;
  riskLevel: string | null;
  reasons: string[];
  reason: string | null;
  at: string;
}

function evidenceValue(event: SecurityEvent, key: string): unknown {
  return Array.isArray(event.evidence) ? event.evidence.find((e) => e.key === key)?.value : undefined;
}

function toIpRiskResult(event: SecurityEvent): IpRiskResult {
  const country = evidenceValue(event, "country");
  const riskLevel = evidenceValue(event, "risk_level");
  const reasons = evidenceValue(event, "reasons");
  return {
    status: event.status,
    country: typeof country === "string" ? country : null,
    riskLevel: typeof riskLevel === "string" ? riskLevel : null,
    reasons: Array.isArray(reasons)
      ? reasons.map(String)
      : typeof reasons === "string" && reasons.trim() !== ""
        ? reasons.split(",").map((r) => r.trim())
        : [],
    reason: event.reason,
    at: event.receivedAt,
  };
}

/**
 * The device's latest IP risk check (`high_risk_ip`): status, country, risk
 * level, the rules behind it, and when. Read from the device's own events;
 * live-polled like the rest of the drawer.
 */
function IpRiskCard({ applicationId, deviceId, now }: { applicationId: string; deviceId: string; now: number }) {
  const [result, setResult] = useState<IpRiskResult | null | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      const params = new URLSearchParams({ deviceId, detectorId: "high_risk_ip", limit: "1" });
      try {
        const res = await apiFetch<{ events: SecurityEvent[] }>(
          `/v1/dashboard/applications/${applicationId}/events?${params.toString()}`,
        );
        if (!cancelled) setResult(res.events[0] ? toIpRiskResult(res.events[0]) : null);
      } catch {
        if (!cancelled) setResult(null);
      }
    }
    load();
    const interval = setInterval(load, LIVE_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [applicationId, deviceId]);

  const levelTone = (level: string | null) =>
    level === "high" ? "text-red-600" : level === "medium" ? "text-amber-700" : level === "low" ? "text-emerald-700" : "text-ink-500";

  return (
    <div className="border-b border-ink-100 px-5 py-3">
      <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-ink-400">IP risk</div>
      {result === undefined ? (
        <div className="h-10 animate-pulse rounded-lg bg-ink-100" />
      ) : result === null ? (
        <p className="text-xs text-ink-400">No IP risk result yet</p>
      ) : (
        <div className="space-y-1 text-xs">
          <div className="flex items-center gap-2">
            <Badge tone={statusTone(result.status)}>{result.status}</Badge>
            <span className="font-medium text-ink-800">{result.country ?? "country unknown"}</span>
            {result.riskLevel && <span className={`font-semibold ${levelTone(result.riskLevel)}`}>{result.riskLevel} risk</span>}
          </div>
          {result.reasons.length > 0 && (
            <div className="text-ink-600">Reasons: {result.reasons.join(", ")}</div>
          )}
          {result.reason && <div className="text-ink-500">{result.reason}</div>}
          <div className="text-ink-400" title={new Date(result.at).toLocaleString()}>{relativeTime(result.at, now)}</div>
        </div>
      )}
    </div>
  );
}

export interface DeviceSummary {
  deviceId: string;
  deviceModel: string | null;
  manufacturer: string | null;
  osPlatform: string | null;
  osVersion: string | null;
  appVersion: string | null;
  sdkVersion: string | null;
  lastStatus: string;
  lastSeen: string;
  firstSeen: string;
  eventCount: number;
  threatCount: number;
}

const LIVE_POLL_MS = 4_000;
/** How long a freshly-arrived row keeps its "just happened" highlight. */
const NEW_ROW_HIGHLIGHT_MS = 5_000;
/** How often on-screen relative timestamps ("3s ago") repaint. */
const CLOCK_TICK_MS = 1_000;
/** Recent-window size the left-hand detector list is built from. Grouping
 *  reflects "detector types active recently", not a full lifetime catalog
 *  query — deliberately, so this stays a single cheap live-polled request
 *  rather than a second endpoint. */
const GROUP_WINDOW_SIZE = 200;

function relativeTime(iso: string, nowMs: number): string {
  const deltaMs = nowMs - new Date(iso).getTime();
  const seconds = Math.max(0, Math.floor(deltaMs / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function LiveDot() {
  return (
    <span className="relative flex h-1.5 w-1.5">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand-400 opacity-75" />
      <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-brand-500" />
    </span>
  );
}

interface DetectorGroup {
  detectorId: string;
  title: string;
  category: AlertCategory;
  count: number;
  threatCount: number;
  lastStatus: string;
  lastAt: string;
}

/**
 * "Click a device, see its detector types, drill into one for its own
 * timeline." Left column: every detector this device has reported
 * recently, grouped with a count and last-seen — click one to open its
 * timeline in the right column, which stays open alongside the group list
 * rather than replacing it. Both columns are live: the group list updates
 * from the same polled window; the timeline panel runs its own independent
 * live poll scoped to exactly the selected detectorId (the backend's
 * `/events` endpoint already supports filtering by it directly).
 */
export function DeviceTrailDrawer({
  applicationId,
  applicationPlatform,
  device,
  onClose,
}: {
  applicationId: string;
  applicationPlatform: string;
  device: DeviceSummary;
  onClose: () => void;
}) {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [selectedDetectorId, setSelectedDetectorId] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const knownIdsRef = useRef<Set<string>>(new Set());

  async function fetchWindow() {
    const params = new URLSearchParams({ deviceId: device.deviceId, limit: String(GROUP_WINDOW_SIZE) });
    return apiFetch<{ events: SecurityEvent[]; nextCursor: string | null }>(
      `/v1/dashboard/applications/${applicationId}/events?${params.toString()}`,
    );
  }

  // Initial load for this device.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchWindow().then((res) => {
      if (cancelled) return;
      setEvents(res.events);
      knownIdsRef.current = new Set(res.events.map((e) => e.id));
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device.deviceId]);

  // Live: merge anything new into the group-list window.
  useEffect(() => {
    const interval = setInterval(async () => {
      const res = await fetchWindow();
      const fresh = res.events.filter((e) => !knownIdsRef.current.has(e.id));
      if (fresh.length === 0) return;
      for (const e of fresh) knownIdsRef.current.add(e.id);
      setEvents((prev) => [...fresh, ...prev].slice(0, GROUP_WINDOW_SIZE));
    }, LIVE_POLL_MS);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device.deviceId, applicationId]);

  useEffect(() => {
    const clock = setInterval(() => setNow(Date.now()), CLOCK_TICK_MS);
    return () => clearInterval(clock);
  }, []);

  const groups = useMemo<DetectorGroup[]>(() => {
    const byDetector = new Map<string, DetectorGroup>();
    for (const e of events) {
      const catalog = catalogFor(e.detectorId);
      const existing = byDetector.get(e.detectorId);
      if (!existing) {
        byDetector.set(e.detectorId, {
          detectorId: e.detectorId,
          title: catalog.title,
          category: catalog.category,
          count: 1,
          threatCount: e.status === "DETECTED" ? 1 : 0,
          lastStatus: e.status,
          lastAt: e.receivedAt,
        });
      } else {
        existing.count += 1;
        if (e.status === "DETECTED") existing.threatCount += 1;
        if (new Date(e.receivedAt) > new Date(existing.lastAt)) {
          existing.lastStatus = e.status;
          existing.lastAt = e.receivedAt;
        }
      }
    }
    return Array.from(byDetector.values()).sort(
      (a, b) => new Date(b.lastAt).getTime() - new Date(a.lastAt).getTime(),
    );
  }, [events]);

  const categoryCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const g of groups) counts.set(g.category, (counts.get(g.category) ?? 0) + 1);
    return counts;
  }, [groups]);

  const filteredGroups = useMemo(() => {
    if (!categoryFilter) return groups;
    return groups.filter((g) => g.category === categoryFilter);
  }, [groups, categoryFilter]);

  const selectedGroup = groups.find((g) => g.detectorId === selectedDetectorId) ?? null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-[2px]" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-4xl overflow-hidden bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── Left: device summary + grouped detector list ────────────── */}
        <div className="flex h-full w-80 shrink-0 flex-col border-r border-ink-100">
          <div className="border-b border-ink-100 px-5 py-5">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-ink-50 text-ink-700">
                  <PlatformIcon platform={applicationPlatform} size={18} />
                </div>
                <div className="min-w-0">
                  <h3 className="truncate text-sm font-semibold text-ink-900">
                    {device.deviceModel ?? "Unknown device"}
                  </h3>
                  <p className="truncate font-mono text-[11px] text-ink-400">{device.deviceId}</p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-ink-400 hover:bg-ink-50 hover:text-ink-700"
              >
                <XIcon size={15} />
              </button>
            </div>
            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-medium text-ink-400">
              <LiveDot />
              Live — <span title={new Date(device.lastSeen).toLocaleString()}>{relativeTime(device.lastSeen, now)}</span>
            </div>
          </div>

          <IpRiskCard applicationId={applicationId} deviceId={device.deviceId} now={now} />
          <DeviceRiskCard applicationId={applicationId} deviceId={device.deviceId} />

          <div className="flex flex-wrap items-center gap-1.5 border-b border-ink-100 px-4 py-3">
            <CategoryChip
              label="All"
              colors={{ bg: "bg-brand-50", text: "text-brand-700", dot: "bg-brand-500" }}
              count={groups.length}
              active={categoryFilter === null}
              onClick={() => setCategoryFilter(null)}
            />
            {ALL_CATEGORIES.filter((c) => categoryCounts.has(c)).map((cat) => (
              <CategoryChip
                key={cat}
                label={cat}
                colors={CATEGORY_COLORS[cat]}
                count={categoryCounts.get(cat)}
                active={categoryFilter === cat}
                onClick={() => setCategoryFilter(cat)}
              />
            ))}
          </div>

          <div className="flex-1 overflow-y-auto px-2 py-2">
            {loading ? (
              <div className="animate-pulse space-y-2 px-2">
                {[0, 1, 2, 3, 4].map((i) => (
                  <div key={i} className="h-14 rounded-lg bg-ink-100" />
                ))}
              </div>
            ) : filteredGroups.length === 0 ? (
              <p className="py-10 text-center text-sm text-ink-400">No detector activity yet.</p>
            ) : (
              <ul className="space-y-1">
                {filteredGroups.map((g) => {
                  const colors = CATEGORY_COLORS[g.category];
                  const active = g.detectorId === selectedDetectorId;
                  return (
                    <li key={g.detectorId}>
                      <button
                        onClick={() => setSelectedDetectorId(g.detectorId)}
                        className={`flex w-full items-start gap-2.5 rounded-lg px-3 py-2.5 text-left transition-colors ${
                          active ? "bg-brand-50 ring-1 ring-inset ring-brand-200" : "hover:bg-ink-50"
                        }`}
                      >
                        <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${colors.dot}`} />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="truncate text-sm font-medium text-ink-900">{g.title}</span>
                            {g.threatCount > 0 && (
                              <span className="shrink-0 text-[10px] font-bold text-red-600">{g.threatCount}⚠</span>
                            )}
                          </div>
                          <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-ink-400">
                            <span>{g.count} event{g.count === 1 ? "" : "s"}</span>
                            <span>·</span>
                            <span>{relativeTime(g.lastAt, now)}</span>
                          </div>
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>

        {/* ── Right: timeline for the selected detector — stays open next
             to the group list, never hides it ─────────────────────────── */}
        <div className="flex h-full flex-1 flex-col">
          {selectedGroup ? (
            <DetectorTimelinePanel
              key={selectedGroup.detectorId}
              applicationId={applicationId}
              deviceId={device.deviceId}
              detectorId={selectedGroup.detectorId}
              title={selectedGroup.title}
              onBack={() => setSelectedDetectorId(null)}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 px-8 text-center">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-ink-50 text-ink-400">
                <ClockTrailIcon />
              </div>
              <p className="text-sm font-medium text-ink-600">Select a detector on the left</p>
              <p className="text-xs text-ink-400">
                Its full timeline — every occurrence, in order, live — opens here.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * One detector's own live timeline for one device — independent fetch/poll
 * scoped to `deviceId + detectorId`, so "Load older history" here reaches
 * that detector's real history rather than whatever happened to be in a
 * shared recent-events window.
 */
function DetectorTimelinePanel({
  applicationId,
  deviceId,
  detectorId,
  title,
  onBack,
}: {
  applicationId: string;
  deviceId: string;
  detectorId: string;
  title: string;
  onBack: () => void;
}) {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [detailEvent, setDetailEvent] = useState<SecurityEvent | null>(null);
  const [newlyArrivedIds, setNewlyArrivedIds] = useState<Set<string>>(new Set());
  const [now, setNow] = useState(() => Date.now());

  const knownIdsRef = useRef<Set<string>>(new Set());

  async function fetchPage(cursor?: string) {
    const params = new URLSearchParams({ deviceId, detectorId, limit: "50" });
    if (statusFilter) params.set("status", statusFilter);
    if (cursor) params.set("cursor", cursor);
    return apiFetch<{ events: SecurityEvent[]; nextCursor: string | null }>(
      `/v1/dashboard/applications/${applicationId}/events?${params.toString()}`,
    );
  }

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchPage().then((res) => {
      if (cancelled) return;
      setEvents(res.events);
      setNextCursor(res.nextCursor);
      knownIdsRef.current = new Set(res.events.map((e) => e.id));
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId, detectorId, statusFilter]);

  useEffect(() => {
    const interval = setInterval(async () => {
      const res = await fetchPage();
      const fresh = res.events.filter((e) => !knownIdsRef.current.has(e.id));
      if (fresh.length === 0) return;

      for (const e of fresh) knownIdsRef.current.add(e.id);
      setEvents((prev) => [...fresh, ...prev]);

      setNewlyArrivedIds((prev) => {
        const next = new Set(prev);
        for (const e of fresh) next.add(e.id);
        return next;
      });
      for (const e of fresh) {
        setTimeout(() => {
          setNewlyArrivedIds((prev) => {
            if (!prev.has(e.id)) return prev;
            const next = new Set(prev);
            next.delete(e.id);
            return next;
          });
        }, NEW_ROW_HIGHLIGHT_MS);
      }
    }, LIVE_POLL_MS);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId, detectorId, statusFilter, applicationId]);

  useEffect(() => {
    const clock = setInterval(() => setNow(Date.now()), CLOCK_TICK_MS);
    return () => clearInterval(clock);
  }, []);

  async function loadMore() {
    if (!nextCursor) return;
    setLoadingMore(true);
    const res = await fetchPage(nextCursor);
    for (const e of res.events) knownIdsRef.current.add(e.id);
    setEvents((prev) => [...prev, ...res.events]);
    setNextCursor(res.nextCursor);
    setLoadingMore(false);
  }

  const catalog = catalogFor(detectorId);
  const colors = CATEGORY_COLORS[catalog.category];

  return (
    <>
      <div className="flex items-center gap-3 border-b border-ink-100 px-5 py-4">
        <button
          onClick={onBack}
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-ink-400 hover:bg-ink-50 hover:text-ink-700"
          title="Back to detector list"
        >
          <BackIcon />
        </button>
        <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${colors.dot}`} />
        <div className="min-w-0 flex-1">
          <h3 className="truncate text-sm font-semibold text-ink-900">{title}</h3>
          <p className="truncate text-[11px] text-ink-400">{catalog.description}</p>
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="shrink-0 rounded-md border border-ink-200 bg-surface px-2 py-1 text-xs text-ink-700 outline-none focus:border-brand-500"
        >
          <option value="">All statuses</option>
          <option value="DETECTED">Detected</option>
          <option value="SECURE">Secure</option>
          <option value="ERROR">Error</option>
          <option value="UNAVAILABLE">Unavailable</option>
          <option value="UNKNOWN">Unknown</option>
        </select>
      </div>

      <div className="flex items-center gap-1.5 px-5 py-2 text-[11px] font-medium text-ink-400">
        <LiveDot />
        Live — every new occurrence of this detector appears here automatically
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-1">
        {loading ? (
          <div className="animate-pulse space-y-2 px-2 py-2">
            {[0, 1, 2, 3, 4].map((i) => (
              <div key={i} className="h-14 rounded-lg bg-ink-100" />
            ))}
          </div>
        ) : events.length === 0 ? (
          <p className="py-10 text-center text-sm text-ink-400">No events match this filter.</p>
        ) : (
          <ol className="relative space-y-0.5 pl-3">
            <div className="absolute bottom-3 left-[15px] top-3 w-px bg-ink-100" aria-hidden />
            {events.map((event) => {
              const isNew = newlyArrivedIds.has(event.id);
              return (
                <li key={event.id} className="relative">
                  <button
                    onClick={() => setDetailEvent(event)}
                    className={`flex w-full items-start gap-3 rounded-lg px-2 py-2.5 text-left transition-colors duration-700 hover:bg-ink-50 ${
                      isNew ? "bg-brand-50/70" : ""
                    }`}
                  >
                    <span className={`relative z-10 mt-1.5 h-2 w-2 shrink-0 rounded-full ring-4 ring-surface ${colors.dot}`} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex items-center gap-1.5 truncate text-sm font-medium text-ink-900">
                          {relativeTime(event.receivedAt, now)}
                          {isNew && (
                            <span className="rounded-full bg-brand-500 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-white">
                              New
                            </span>
                          )}
                        </span>
                        <Badge tone={statusTone(event.status)}>{event.status}</Badge>
                      </div>
                      <div className="mt-0.5 text-xs text-ink-400">
                        {new Date(event.receivedAt).toLocaleString()}
                      </div>
                    </div>
                  </button>
                </li>
              );
            })}
          </ol>
        )}

        {nextCursor && !loading && (
          <button
            onClick={loadMore}
            disabled={loadingMore}
            className="mb-2 mt-3 w-full rounded-lg border border-ink-200 py-2 text-xs font-medium text-ink-600 hover:bg-ink-50 disabled:opacity-50"
          >
            {loadingMore ? "Loading…" : "Load older history"}
          </button>
        )}
      </div>

      {detailEvent && <EventDetailDrawer event={detailEvent} onClose={() => setDetailEvent(null)} />}
    </>
  );
}

function ClockTrailIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function BackIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M15 18l-6-6 6-6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
