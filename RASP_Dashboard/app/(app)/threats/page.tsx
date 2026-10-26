"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import {
  AlertTriangleIcon,
  Badge,
  Card,
  CategoryChip,
  SmartphoneIcon,
  StatCard,
  StatusDot,
  statusTone,
} from "@/components/ui";
import { EventDetailDrawer, type SecurityEvent } from "@/components/event-drawer";
import { ALL_CATEGORIES, CATEGORY_COLORS, catalogFor } from "@/lib/alertCatalog";
import { useAppSelection } from "@/lib/app-selection";
import { LIVE_REFRESH_MS } from "@/lib/usePolled";
import { RiskEventsCard } from "@/components/risk-events";

/** Live feed of real `DETECTED` events — `GET .../events?status=DETECTED`,
 *  the same endpoint the Dashboard's filter dropdown already uses, just
 *  pinned to threats and polled tighter (10s) since this is meant to be
 *  watched, not just checked in on. No separate "alerting" system exists
 *  yet — this is the honest live view of what the SDK actually reported. */
export default function ThreatsPage() {
  const { apps, selectedAppId, loading: appsLoading } = useAppSelection();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedAppId) return;
    let cancelled = false;

    async function load() {
      const res = await apiFetch<{ events: SecurityEvent[] }>(
        `/v1/dashboard/applications/${selectedAppId}/events?status=DETECTED&limit=100`,
      );
      if (!cancelled) setEvents(res.events);
    }

    load();
    const interval = setInterval(load, LIVE_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [selectedAppId]);

  const stats = useMemo(() => {
    const uniqueDevices = new Set(events.map((e) => e.deviceId).filter(Boolean)).size;
    const byDetector = new Map<string, number>();
    for (const e of events) byDetector.set(e.detectorId, (byDetector.get(e.detectorId) ?? 0) + 1);
    const top = [...byDetector.entries()].sort((a, b) => b[1] - a[1])[0];
    return { total: events.length, uniqueDevices, topDetector: top ? catalogFor(top[0]).title : "—" };
  }, [events]);

  const categoryCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of events) {
      const cat = catalogFor(e.detectorId).category;
      counts.set(cat, (counts.get(cat) ?? 0) + 1);
    }
    return counts;
  }, [events]);

  const filteredEvents = useMemo(() => {
    if (!categoryFilter) return events;
    return events.filter((e) => catalogFor(e.detectorId).category === categoryFilter);
  }, [events, categoryFilter]);

  const selectedApp = apps.find((a) => a.id === selectedAppId);

  if (appsLoading) return <ThreatsSkeleton />;

  if (apps.length === 0) {
    return (
      <Card className="p-10 text-center">
        <p className="text-sm text-ink-500">
          No applications registered yet — go to{" "}
          <a href="/apps" className="font-medium text-brand-700 hover:underline">
            Applications
          </a>{" "}
          to register one.
        </p>
      </Card>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink-900">Live Threats</h1>
        <p className="mt-1 flex items-center gap-1.5 text-sm text-ink-500">
          <StatusDot tone={stats.total > 0 ? "red" : "green"} pulse />
          {stats.total > 0 ? `${stats.total} active threat findings` : "No active threats"} ·{" "}
          {selectedApp?.name}
        </p>
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Threats · this view" value={stats.total} icon={<AlertTriangleIcon size={18} />} tone={stats.total > 0 ? "red" : "slate"} />
        <StatCard label="Devices affected" value={stats.uniqueDevices} icon={<SmartphoneIcon size={18} />} tone="slate" />
        <StatCard label="Most common threat" value={<span className="font-mono text-base">{stats.topDetector}</span>} icon={<AlertTriangleIcon size={18} />} tone="slate" />
      </div>

      {selectedAppId && <RiskEventsCard applicationId={selectedAppId} />}

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-ink-100 px-5 py-3">
          <CategoryChip
            label="All"
            colors={{ bg: "bg-brand-50", text: "text-brand-700", dot: "bg-brand-500" }}
            count={events.length}
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
        {filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-14 text-center">
            <AlertTriangleIcon size={22} className="text-ink-300" />
            <p className="text-sm text-ink-400">
              {events.length === 0 ? "No threats detected for this application right now." : "No threats match this category."}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                  <th className="py-2.5 pl-5 pr-4 font-medium">Time</th>
                  <th className="py-2.5 pr-4 font-medium">Alert</th>
                  <th className="py-2.5 pr-4 font-medium">Status</th>
                  <th className="py-2.5 pr-4 font-medium">Device</th>
                  <th className="py-2.5 pr-5 font-medium">OS</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((event) => {
                  const catalog = catalogFor(event.detectorId);
                  return (
                    <tr
                      key={event.id}
                      onClick={() => setSelectedEvent(event)}
                      className="cursor-pointer border-b border-red-50 bg-red-50/30 transition hover:bg-red-50/70"
                    >
                      <td className="py-2.5 pl-5 pr-4 text-ink-500">{new Date(event.receivedAt).toLocaleString()}</td>
                      <td className="py-2.5 pr-4">
                        <div className="font-medium text-ink-900">{catalog.title}</div>
                        <div className="font-mono text-[11px] text-ink-400">{event.detectorId}</div>
                      </td>
                      <td className="py-2.5 pr-4">
                        <Badge tone={statusTone(event.status)}>{event.status}</Badge>
                      </td>
                      <td className="py-2.5 pr-4 text-ink-600">{event.deviceModel ?? "—"}</td>
                      <td className="py-2.5 pr-5 text-ink-600">
                        {event.osPlatform ? `${event.osPlatform} ${event.osVersion ?? ""}` : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selectedEvent && <EventDetailDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
    </div>
  );
}

function ThreatsSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-8 w-48 rounded-lg bg-ink-100" />
      <div className="grid grid-cols-3 gap-4">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-24 rounded-2xl bg-ink-100" />
        ))}
      </div>
      <div className="h-72 rounded-2xl bg-ink-100" />
    </div>
  );
}
