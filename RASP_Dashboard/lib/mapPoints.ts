/**
 * Shared, Leaflet-free pieces of the device map, so pages can use them
 * without importing Leaflet (which needs `window`) outside the
 * `ssr: false` dynamic import.
 */
export type MapSeverity = "low" | "medium" | "high";

/** One device on `GET /v1/dashboard/map-points`. */
export interface DeviceMapPoint {
  deviceId: string;
  applicationId: string;
  applicationName: string;
  latitude: number;
  longitude: number;
  severity: MapSeverity;
  lastThreat: { detectorId: string; at: string } | null;
  at: string;
}

export const SEVERITY_COLOR: Record<MapSeverity, string> = {
  low: "#16a34a", // green
  medium: "#ea580c", // orange
  high: "#dc2626", // red
};

/** Coordinates as shown in the UI: always rounded to 3 decimals (~100 m). */
export function roundCoord(value: number): string {
  return value.toFixed(3);
}
