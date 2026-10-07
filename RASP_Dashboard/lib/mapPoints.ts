/**
 * Shared, Leaflet-free pieces of the device map, so pages can use them
 * without importing Leaflet (which needs `window`) outside the
 * `ssr: false` dynamic import. No imports, so `node --test
 * lib/mapPoints.test.ts` runs it as is.
 */
export type MapSeverity = "none" | "low" | "medium" | "high";

export interface DeviceMapTrailPoint {
  latitude: number;
  longitude: number;
  at: string;
}

/** One device on `GET /v1/dashboard/map-points`. */
export interface DeviceMapPoint {
  deviceId: string;
  applicationId: string;
  applicationName: string;
  latitude: number;
  longitude: number;
  accuracyM: number | null;
  isMock: boolean | null;
  /** "heartbeat": the SDK's location heartbeat (every minute while sharing is on); "event": a located security event. */
  source: "heartbeat" | "event";
  /** Highest threat severity in the period; "none" without any. */
  severity: MapSeverity;
  lastThreat: { detectorId: string; at: string } | null;
  /** When this location was received. */
  at: string;
  /** The device's newest heartbeat or event. */
  lastSeenAt: string;
  /** The location is older than `staleAfterMinutes`. */
  stale: boolean;
  /** Only when asked for (`trail=true`), oldest first. */
  trail?: DeviceMapTrailPoint[];
}

export interface MapPointsSummary {
  /** Devices the backend heard from in the period (events or location heartbeats). */
  devicesReporting: number;
  /** Of those, the ones with a shared location. */
  devicesWithLocation: number;
}

export interface MapPointsResponse {
  points: DeviceMapPoint[];
  summary: MapPointsSummary;
  staleAfterMinutes: number;
}

export const SEVERITY_ORDER: MapSeverity[] = ["high", "medium", "low", "none"];

export const SEVERITY_COLOR: Record<MapSeverity, string> = {
  none: "#16a34a", // green: no threat in the period
  low: "#ca8a04", // amber
  medium: "#ea580c", // orange
  high: "#dc2626", // red
};

export const SEVERITY_LABEL: Record<MapSeverity, string> = {
  none: "No threats",
  low: "Low",
  medium: "Medium",
  high: "High",
};

/** Grey: the location is older than the stale limit. */
export const STALE_COLOR = "#9ca3af";

/** Marker colour: grey when the location is stale, else by severity. */
export function markerColor(point: Pick<DeviceMapPoint, "severity" | "stale">): string {
  return point.stale ? STALE_COLOR : SEVERITY_COLOR[point.severity];
}

/** Coordinates as shown in the UI: always rounded to 3 decimals (~100 m). */
export function roundCoord(value: number): string {
  return value.toFixed(3);
}

/** "just now", "4 min ago", "3 h ago", "2 d ago". */
export function timeAgo(iso: string, now: number): string {
  const seconds = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.floor(hours / 24)} d ago`;
}

/**
 * Why the map is empty, in words: no device reported at all, devices
 * reported but none shared a location, or the severity filter hides the
 * ones that did. [period] reads like "last 24 hours".
 */
export function emptyMapMessage(summary: MapPointsSummary | null, period: string, severityFiltered: boolean): string {
  if (!summary || summary.devicesReporting === 0) {
    return `No device reported in the ${period}. If the app is running, check that it uses an API credential from this dashboard and can reach this backend.`;
  }
  if (summary.devicesWithLocation === 0) {
    const n = summary.devicesReporting;
    return `${n} ${n === 1 ? "device" : "devices"} reported in the ${period}, but none shared its location. Location appears here only after the app user turns on Share location.`;
  }
  if (severityFiltered) {
    const n = summary.devicesWithLocation;
    return `${n} ${n === 1 ? "device" : "devices"} shared a location in the ${period}, but none matches this severity.`;
  }
  return `No device shared its location in the ${period}.`;
}
