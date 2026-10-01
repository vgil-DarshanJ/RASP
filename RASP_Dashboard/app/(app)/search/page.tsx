"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import { Badge, Card, LayersIcon, PlatformIcon, SearchIcon, statusTone } from "@/components/ui";
import { EventDetailDrawer, type SecurityEvent } from "@/components/event-drawer";

interface AppResult {
  id: string;
  name: string;
  platform: string;
  createdAt: string;
}

/** Real org-wide search — `GET /v1/dashboard/search`, a Postgres
 *  `ILIKE`-style query scoped to the caller's own org (see BE
 *  `dashboard/routes.ts`). Debounced client-side; the backend itself
 *  does no caching since this dataset is small. */
export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [apps, setApps] = useState<AppResult[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [searching, setSearching] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  useEffect(() => {
    const q = query.trim();
    if (q.length < 2) {
      setApps([]);
      setEvents([]);
      return;
    }
    setSearching(true);
    const handle = setTimeout(async () => {
      try {
        const res = await apiFetch<{ applications: AppResult[]; events: SecurityEvent[] }>(
          `/v1/dashboard/search?q=${encodeURIComponent(q)}`,
        );
        setApps(res.applications);
        setEvents(res.events);
      } finally {
        setSearching(false);
      }
    }, 300);
    return () => clearTimeout(handle);
  }, [query]);

  const hasQuery = query.trim().length >= 2;

  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold text-ink-900">Global Search</h1>
      <p className="mb-6 text-sm text-ink-500">
        Search across your organization's applications, devices, and events.
      </p>

      <div className="relative mb-6">
        <span className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-ink-400">
          <SearchIcon size={17} />
        </span>
        <input
          autoFocus
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Device model, device ID, detector, manufacturer, or app name…"
          className="w-full rounded-xl border border-ink-200 bg-surface py-3.5 pl-11 pr-4 text-sm outline-none transition placeholder:text-ink-400 focus:border-brand-500 focus:ring-4 focus:ring-brand-100"
        />
      </div>

      {!hasQuery && (
        <Card className="p-10 text-center">
          <SearchIcon size={22} className="mx-auto mb-2 text-ink-300" />
          <p className="text-sm text-ink-400">Type at least 2 characters to search.</p>
        </Card>
      )}

      {hasQuery && !searching && apps.length === 0 && events.length === 0 && (
        <Card className="p-10 text-center">
          <p className="text-sm text-ink-400">No matches for &ldquo;{query}&rdquo;.</p>
        </Card>
      )}

      {apps.length > 0 && (
        <div className="mb-6">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-ink-400">
            Applications ({apps.length})
          </h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {apps.map((app) => (
              <a key={app.id} href="/apps">
                <Card className="flex items-center gap-3 p-4 transition hover:shadow-glow">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-ink-50 text-ink-700">
                    <PlatformIcon platform={app.platform} size={17} />
                  </div>
                  <div className="min-w-0">
                    <div className="truncate font-medium text-ink-900">{app.name}</div>
                    <div className="text-xs text-ink-500">{app.platform.replace("_", " ")}</div>
                  </div>
                </Card>
              </a>
            ))}
          </div>
        </div>
      )}

      {events.length > 0 && (
        <div>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-ink-400">
            Events ({events.length})
          </h2>
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                    <th className="py-2.5 pl-5 pr-4 font-medium">Time</th>
                    <th className="py-2.5 pr-4 font-medium">Application</th>
                    <th className="py-2.5 pr-4 font-medium">Detector</th>
                    <th className="py-2.5 pr-4 font-medium">Status</th>
                    <th className="py-2.5 pr-5 font-medium">Device</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr
                      key={event.id}
                      onClick={() => setSelectedEvent(event)}
                      className="cursor-pointer border-b border-ink-50 transition hover:bg-ink-50/60"
                    >
                      <td className="py-2.5 pl-5 pr-4 text-ink-500">{new Date(event.receivedAt).toLocaleString()}</td>
                      <td className="py-2.5 pr-4 text-ink-700">
                        <span className="inline-flex items-center gap-1.5">
                          <LayersIcon size={13} className="text-ink-400" />
                          {event.application?.name ?? "—"}
                        </span>
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-xs font-medium text-ink-900">{event.detectorId}</td>
                      <td className="py-2.5 pr-4">
                        <Badge tone={statusTone(event.status)}>{event.status}</Badge>
                      </td>
                      <td className="py-2.5 pr-5 text-ink-600">{event.deviceModel ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {selectedEvent && <EventDetailDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
    </div>
  );
}
