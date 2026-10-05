"use client";

import { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { apiFetch } from "@/lib/api-client";
import { useAppSelection } from "@/lib/app-selection";
import { useIsDark } from "@/lib/useIsDark";
import { catalogFor } from "@/lib/alertCatalog";
import { Card, MapPinIcon } from "@/components/ui";
import { roundCoord, SEVERITY_COLOR, type DeviceMapPoint, type MapSeverity } from "@/lib/mapPoints";

/** Leaflet touches `window`, so the map only ever renders in the browser. */
const DeviceMapClient = dynamic(() => import("@/components/device-map").then((m) => m.DeviceMap), {
  ssr: false,
  loading: () => <div className="h-full w-full animate-pulse rounded-2xl bg-ink-100" />,
});

type Range = "24h" | "7d" | "30d";
const RANGES: { value: Range; label: string }[] = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
];
const SEVERITIES: MapSeverity[] = ["high", "medium", "low"];

/**
 * Devices that shared their location (the user opted in inside the app),
 * from `GET /v1/dashboard/map-points`. Devices that did not opt in have no
 * coordinates stored at all and never appear here — the Devices page shows
 * them as "location not shared".
 */
export default function DeviceMapPage() {
  const { apps } = useAppSelection();
  const isDark = useIsDark();
  const [applicationId, setApplicationId] = useState<string>("");
  const [severity, setSeverity] = useState<MapSeverity | "">("");
  const [range, setRange] = useState<Range>("7d");
  const [points, setPoints] = useState<DeviceMapPoint[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const params = new URLSearchParams({ range });
    if (applicationId) params.set("applicationId", applicationId);
    if (severity) params.set("severity", severity);
    setError(null);
    apiFetch<{ points: DeviceMapPoint[] }>(`/v1/dashboard/map-points?${params.toString()}`)
      .then((res) => !cancelled && setPoints(res.points))
      .catch(() => !cancelled && setError("Could not load map points."));
    return () => {
      cancelled = true;
    };
  }, [applicationId, severity, range]);

  const counts = useMemo(() => {
    const c: Record<MapSeverity, number> = { high: 0, medium: 0, low: 0 };
    for (const p of points ?? []) c[p.severity]++;
    return c;
  }, [points]);

  const select = "rounded-lg border border-ink-200 bg-surface px-2.5 py-1.5 text-sm text-ink-900 outline-none";

  return (
    <div>
      <div className="mb-5">
        <h1 className="text-2xl font-semibold text-ink-900">Device Map</h1>
        <p className="mt-1 text-sm text-ink-500">
          Only devices whose users opted in to sharing location. Others are never shown here.
        </p>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <select aria-label="Application" value={applicationId} onChange={(e) => setApplicationId(e.target.value)} className={select}>
          <option value="">All applications</option>
          {apps.map((app) => (
            <option key={app.id} value={app.id}>
              {app.name}
            </option>
          ))}
        </select>
        <select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value as MapSeverity | "")} className={select}>
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s[0].toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
        <select aria-label="Time range" value={range} onChange={(e) => setRange(e.target.value as Range)} className={select}>
          {RANGES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
        <div className="ml-auto flex items-center gap-3 text-xs text-ink-500">
          {SEVERITIES.map((s) => (
            <span key={s} className="inline-flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: SEVERITY_COLOR[s] }} />
              {s} ({counts[s]})
            </span>
          ))}
        </div>
      </div>

      <Card className="mb-4 h-[480px] overflow-hidden p-0">
        <DeviceMapClient points={points ?? []} dark={isDark} />
      </Card>

      <Card className="overflow-hidden">
        {error ? (
          <p className="py-8 text-center text-sm text-red-600">{error}</p>
        ) : points === null ? (
          <p className="py-8 text-center text-sm text-ink-400">Loading…</p>
        ) : points.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-10 text-center">
            <MapPinIcon size={22} className="text-ink-300" />
            <p className="text-sm text-ink-400">No device shared its location in this period.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                  <th className="py-2.5 pl-5 pr-4 font-medium">Device</th>
                  <th className="py-2.5 pr-4 font-medium">Application</th>
                  <th className="py-2.5 pr-4 font-medium">Severity</th>
                  <th className="py-2.5 pr-4 font-medium">Last threat</th>
                  <th className="py-2.5 pr-4 font-medium">Location</th>
                  <th className="py-2.5 pr-5 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {points.map((p) => (
                  <tr key={`${p.applicationId}-${p.deviceId}`} className="border-b border-ink-50">
                    <td className="py-2.5 pl-5 pr-4 font-mono text-xs text-ink-700">{p.deviceId}</td>
                    <td className="py-2.5 pr-4 text-ink-700">{p.applicationName}</td>
                    <td className="py-2.5 pr-4">
                      <span className="inline-flex items-center gap-1.5 text-ink-700">
                        <span className="h-2.5 w-2.5 rounded-full" style={{ background: SEVERITY_COLOR[p.severity] }} />
                        {p.severity}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 text-ink-600">
                      {p.lastThreat ? catalogFor(p.lastThreat.detectorId).title : "—"}
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-xs text-ink-600">
                      {roundCoord(p.latitude)}, {roundCoord(p.longitude)}
                    </td>
                    <td className="py-2.5 pr-5 text-ink-500">{new Date(p.at).toLocaleString()}</td>
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
