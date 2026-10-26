"use client";

import { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { apiDownload, apiFetch } from "@/lib/api-client";
import { BarChartIcon, Button, Card, DownloadIcon, MapPinIcon } from "@/components/ui";
import { useIsDark } from "@/lib/useIsDark";
import { ALL_CATEGORIES, CATEGORY_COLORS, catalogFor } from "@/lib/alertCatalog";
import { useAppSelection } from "@/lib/app-selection";
import { LIVE_REFRESH_MS } from "@/lib/usePolled";

const RANGES = [
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 24 * 7 },
  { label: "30 days", hours: 24 * 30 },
];

const STATUS_COLORS: Record<string, string> = {
  SECURE: "#059669",
  DETECTED: "#dc2626",
  ERROR: "#d97706",
  UNAVAILABLE: "#586485",
  UNKNOWN: "#8894ab",
};

const BRAND = "#1fa285";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#b91c1c",
  high: "#dc2626",
  medium: "#d97706",
  low: "#059669",
};

interface GeoPoint {
  eventId: string;
  detectorId: string;
  deviceId: string | null;
  receivedAt: string;
  latitude: number;
  longitude: number;
}

// Leaflet touches `window` at import time — must never run during SSR.
const ThreatMapClient = dynamic(() => import("@/components/threat-map").then((m) => m.ThreatMap), {
  ssr: false,
  loading: () => (
    <div className="flex h-full items-center justify-center text-sm text-ink-400">Loading map…</div>
  ),
});

/**
 * Extends the Dashboard's existing detector-counts/volume endpoints —
 * both already accept an `hours` window server-side, so a longer-range
 * view needed zero new backend work. The one new derived view (status
 * breakdown) is computed client-side by summing the already-fetched
 * `volume` rows by status — still real data, just aggregated differently
 * than the Dashboard's per-time-bucket line.
 */
export default function AnalyticsPage() {
  const isDark = useIsDark();
  const axisColor = isDark ? "#8b95ab" : "#7784a3";
  const gridColor = isDark ? "#28324a" : "#e8ebf1";

  const { apps, selectedAppId, loading: appsLoading } = useAppSelection();
  const [hours, setHours] = useState(24);
  const [detectorCounts, setDetectorCounts] = useState<Record<string, number>>({});
  const [volume, setVolume] = useState<{ bucket: string; status: string; count: number }[]>([]);
  const [geoPoints, setGeoPoints] = useState<GeoPoint[]>([]);
  const [exporting, setExporting] = useState(false);

  async function handleExport() {
    if (!selectedAppId) return;
    setExporting(true);
    try {
      const res = await apiDownload(
        `/v1/dashboard/applications/${selectedAppId}/events/export?hours=${hours}`,
      );
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${selectedApp?.name ?? "events"}_${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  }

  useEffect(() => {
    if (!selectedAppId) return;
    let cancelled = false;

    async function load() {
      const [countsRes, volumeRes, geoRes] = await Promise.all([
        apiFetch<{ counts: Record<string, number> }>(
          `/v1/dashboard/applications/${selectedAppId}/detector-counts?hours=${hours}`,
        ),
        apiFetch<{ buckets: { bucket: string; status: string; count: number }[] }>(
          `/v1/dashboard/applications/${selectedAppId}/volume?hours=${hours}`,
        ),
        apiFetch<{ points: GeoPoint[] }>(
          `/v1/dashboard/applications/${selectedAppId}/geography?hours=${hours}`,
        ),
      ]);
      if (cancelled) return;
      setDetectorCounts(countsRes.counts);
      setVolume(volumeRes.buckets);
      setGeoPoints(geoRes.points);
    }

    load();
    const interval = setInterval(load, LIVE_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [selectedAppId, hours]);

  const detectorRows = useMemo(() => {
    const total = Object.values(detectorCounts).reduce((a, b) => a + b, 0);
    return Object.entries(detectorCounts)
      .map(([detectorId, count]) => ({ detectorId, count, pct: total > 0 ? (count / total) * 100 : 0 }))
      .sort((a, b) => b.count - a.count);
  }, [detectorCounts]);

  const severityBreakdown = useMemo(() => {
    const bySeverity = new Map<string, number>();
    let total = 0;
    for (const [detectorId, count] of Object.entries(detectorCounts)) {
      const severity = catalogFor(detectorId).severity;
      bySeverity.set(severity, (bySeverity.get(severity) ?? 0) + count);
      total += count;
    }
    const order = ["critical", "high", "medium", "low"];
    return order
      .map((severity) => ({
        severity,
        count: bySeverity.get(severity) ?? 0,
        pct: total > 0 ? ((bySeverity.get(severity) ?? 0) / total) * 100 : 0,
      }))
      .filter((row) => row.count > 0);
  }, [detectorCounts]);

  const categoryBreakdown = useMemo(() => {
    const byCategory = new Map<string, number>();
    let total = 0;
    for (const [detectorId, count] of Object.entries(detectorCounts)) {
      const category = catalogFor(detectorId).category;
      byCategory.set(category, (byCategory.get(category) ?? 0) + count);
      total += count;
    }
    return ALL_CATEGORIES.map((category) => ({
      category,
      count: byCategory.get(category) ?? 0,
      pct: total > 0 ? ((byCategory.get(category) ?? 0) / total) * 100 : 0,
    })).filter((row) => row.count > 0);
  }, [detectorCounts]);

  /** Buckets threat locations to ~11km grid cells (2 decimal places) so
   *  nearby-but-not-identical GPS fixes from the same city cluster into
   *  one row instead of one row per event — a plain list, not a rendered
   *  map (no map-tile dependency added just for this), but still real
   *  aggregated location data, sorted by how many threats came from there. */
  const geoClusters = useMemo(() => {
    const byCell = new Map<string, { lat: number; lng: number; count: number; detectors: Set<string> }>();
    for (const p of geoPoints) {
      const key = `${p.latitude.toFixed(1)},${p.longitude.toFixed(1)}`;
      const cell = byCell.get(key) ?? { lat: p.latitude, lng: p.longitude, count: 0, detectors: new Set<string>() };
      cell.count++;
      cell.detectors.add(p.detectorId);
      byCell.set(key, cell);
    }
    return Array.from(byCell.values())
      .map((c) => ({ ...c, detectors: Array.from(c.detectors) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [geoPoints]);

  const statusBreakdown = useMemo(() => {
    const byStatus = new Map<string, number>();
    let total = 0;
    for (const row of volume) {
      byStatus.set(row.status, (byStatus.get(row.status) ?? 0) + row.count);
      total += row.count;
    }
    return Array.from(byStatus.entries())
      .map(([status, count]) => ({ status, count, pct: total > 0 ? (count / total) * 100 : 0 }))
      .sort((a, b) => b.count - a.count);
  }, [volume]);

  const trendData = useMemo(() => {
    const byBucket = new Map<string, number>();
    for (const row of volume) byBucket.set(row.bucket, (byBucket.get(row.bucket) ?? 0) + row.count);
    return Array.from(byBucket.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([bucket, count]) => ({
        time: new Date(bucket).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" }),
        count,
      }));
  }, [volume]);

  const selectedApp = apps.find((a) => a.id === selectedAppId);

  if (appsLoading) return <AnalyticsSkeleton />;

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
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-ink-900">Threat Analytics</h1>
          <p className="mt-1 text-sm text-ink-500">{selectedApp?.name}</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex rounded-lg border border-ink-200 bg-surface p-1 text-xs">
            {RANGES.map((r) => (
              <button
                key={r.hours}
                onClick={() => setHours(r.hours)}
                className={`rounded-md px-3 py-1.5 font-medium transition ${
                  hours === r.hours ? "bg-brand-600 text-white" : "text-ink-500 hover:text-ink-800"
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
          <Button variant="secondary" size="sm" loading={exporting} onClick={handleExport}>
            <DownloadIcon size={14} />
            Export CSV
          </Button>
        </div>
      </div>

      <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-2">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">Event volume trend</h2>
          {trendData.length === 0 ? (
            <EmptyChart />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: axisColor }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: axisColor }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    borderRadius: 8,
                    border: `1px solid ${gridColor}`,
                    fontSize: 12,
                    background: isDark ? "#141928" : "#ffffff",
                    color: isDark ? "#e4e8f1" : "#101728",
                  }}
                />
                <Line type="monotone" dataKey="count" stroke={BRAND} strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">By status</h2>
          {statusBreakdown.length === 0 ? (
            <EmptyChart small />
          ) : (
            <div className="space-y-3">
              {statusBreakdown.map((s) => (
                <div key={s.status}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="font-medium text-ink-700">{s.status}</span>
                    <span className="text-ink-400">
                      {s.count} · {s.pct.toFixed(0)}%
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-ink-100">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${s.pct}%`, background: STATUS_COLORS[s.status] ?? "#586485" }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">By severity</h2>
          {severityBreakdown.length === 0 ? (
            <EmptyChart small />
          ) : (
            <div className="space-y-3">
              {severityBreakdown.map((s) => (
                <div key={s.severity}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="font-medium capitalize text-ink-700">{s.severity}</span>
                    <span className="text-ink-400">
                      {s.count} · {s.pct.toFixed(0)}%
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-ink-100">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${s.pct}%`, background: SEVERITY_COLORS[s.severity] }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">By category</h2>
          {categoryBreakdown.length === 0 ? (
            <EmptyChart small />
          ) : (
            <div className="space-y-3">
              {categoryBreakdown.map((c) => {
                const colors = CATEGORY_COLORS[c.category];
                return (
                  <div key={c.category}>
                    <div className="mb-1 flex items-center justify-between text-xs">
                      <span className="inline-flex items-center gap-1.5 font-medium text-ink-700">
                        <span className={`h-1.5 w-1.5 rounded-full ${colors.dot}`} />
                        {c.category}
                      </span>
                      <span className="text-ink-400">
                        {c.count} · {c.pct.toFixed(0)}%
                      </span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-ink-100">
                      <div className={`h-full rounded-full ${colors.dot}`} style={{ width: `${c.pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>

      <Card className="mb-6 overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-100 px-5 py-4">
          <h2 className="flex items-center gap-1.5 text-sm font-semibold text-ink-700">
            <MapPinIcon size={15} className="text-ink-400" /> Threat locations
          </h2>
          {geoPoints.length > 0 && (
            <span className="text-xs text-ink-400">
              {geoClusters.length} location{geoClusters.length === 1 ? "" : "s"} · {geoPoints.length} event
              {geoPoints.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
        {geoPoints.length === 0 ? (
          <div className="flex h-56 flex-col items-center justify-center gap-2 text-center text-sm text-ink-400">
            <MapPinIcon size={20} className="text-ink-300" />
            No location data reported yet — the SDK only includes it when
            the host app supplies a location snapshot.
          </div>
        ) : (
          <div className="h-96 w-full">
            <ThreatMapClient points={geoPoints} />
          </div>
        )}
      </Card>

      <Card className="overflow-hidden">
        <div className="border-b border-ink-100 px-5 py-4">
          <h2 className="text-sm font-semibold text-ink-700">Detector breakdown — {RANGES.find((r) => r.hours === hours)?.label}</h2>
        </div>
        {detectorRows.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-14 text-center">
            <BarChartIcon size={22} className="text-ink-300" />
            <p className="text-sm text-ink-400">No events in this window yet.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                  <th className="py-2.5 pl-5 pr-4 font-medium">Detector</th>
                  <th className="py-2.5 pr-4 font-medium">Events</th>
                  <th className="py-2.5 pr-5 font-medium">Share</th>
                </tr>
              </thead>
              <tbody>
                {detectorRows.map((row) => (
                  <tr key={row.detectorId} className="border-b border-ink-50">
                    <td className="py-2.5 pl-5 pr-4 font-mono text-xs font-medium text-ink-900">{row.detectorId}</td>
                    <td className="py-2.5 pr-4 text-ink-700">{row.count}</td>
                    <td className="py-2.5 pr-5">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-24 overflow-hidden rounded-full bg-ink-100">
                          <div className="h-full rounded-full bg-brand-500" style={{ width: `${row.pct}%` }} />
                        </div>
                        <span className="text-xs text-ink-400">{row.pct.toFixed(1)}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function EmptyChart({ small = false }: { small?: boolean }) {
  return (
    <div className={`flex ${small ? "h-40" : "h-[260px]"} flex-col items-center justify-center gap-2 text-sm text-ink-400`}>
      <BarChartIcon size={20} className="text-ink-300" />
      No data yet
    </div>
  );
}

function AnalyticsSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-8 w-56 rounded-lg bg-ink-100" />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="h-72 rounded-2xl bg-ink-100 lg:col-span-2" />
        <div className="h-72 rounded-2xl bg-ink-100" />
      </div>
      <div className="h-64 rounded-2xl bg-ink-100" />
    </div>
  );
}
