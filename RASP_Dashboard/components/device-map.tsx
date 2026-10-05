"use client";

import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import markerIcon from "leaflet/dist/images/marker-icon.png";
import markerIcon2x from "leaflet/dist/images/marker-icon-2x.png";
import markerShadow from "leaflet/dist/images/marker-shadow.png";
import { catalogFor } from "@/lib/alertCatalog";
import { roundCoord, SEVERITY_COLOR, type DeviceMapPoint, type MapSeverity } from "@/lib/mapPoints";

/**
 * Leaflet's default marker resolves its PNGs from a path guessed at runtime,
 * which breaks under Next.js bundling. Point it at the bundled assets once,
 * so any default `L.marker()` (without a custom icon) still renders.
 */
const defaultIconPrototype = L.Icon.Default.prototype as unknown as { _getIconUrl?: unknown };
delete defaultIconPrototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconUrl: markerIcon.src,
  iconRetinaUrl: markerIcon2x.src,
  shadowUrl: markerShadow.src,
});

const SEVERITY_RANK: Record<MapSeverity, number> = { low: 0, medium: 1, high: 2 };

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function pinIcon(color: string): L.DivIcon {
  return L.divIcon({
    className: "",
    html: `<svg width="26" height="34" viewBox="0 0 26 34" xmlns="http://www.w3.org/2000/svg">
      <path d="M13 0C5.8 0 0 5.8 0 13c0 9.5 13 21 13 21s13-11.5 13-21C26 5.8 20.2 0 13 0z" fill="${color}" stroke="white" stroke-width="1.5"/>
      <circle cx="13" cy="13" r="5" fill="white"/>
    </svg>`,
    iconSize: [26, 34],
    iconAnchor: [13, 34],
    popupAnchor: [0, -30],
  });
}

function clusterIcon(count: number, color: string): L.DivIcon {
  const size = count < 10 ? 34 : count < 100 ? 40 : 46;
  return L.divIcon({
    className: "",
    html: `<div style="width:${size}px;height:${size}px;border-radius:9999px;background:${color};opacity:0.92;
      border:3px solid rgba(255,255,255,0.9);box-shadow:0 1px 4px rgba(0,0,0,0.35);display:flex;align-items:center;
      justify-content:center;color:#fff;font:600 13px/1 system-ui,sans-serif;">${count}</div>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

function popupHtml(p: DeviceMapPoint): string {
  const threat = p.lastThreat
    ? `${escapeHtml(catalogFor(p.lastThreat.detectorId).title)} · ${escapeHtml(new Date(p.lastThreat.at).toLocaleString())}`
    : "No threat in this period";
  return `<div style="font-size:12px;line-height:1.5;color:#111827;min-width:180px;">
    <div style="display:flex;align-items:center;gap:6px;font-weight:600;">
      <span style="display:inline-block;width:8px;height:8px;border-radius:9999px;background:${SEVERITY_COLOR[p.severity]}"></span>
      ${escapeHtml(p.applicationName)}
    </div>
    <div style="font-family:monospace;font-size:11px;color:#4b5563;">Device ${escapeHtml(p.deviceId)}</div>
    <div style="margin-top:4px;"><span style="color:#6b7280;">Last threat:</span> ${threat}</div>
    <div style="color:#6b7280;">Location at ${escapeHtml(new Date(p.at).toLocaleString())}</div>
    <div style="font-family:monospace;font-size:11px;color:#6b7280;">${roundCoord(p.latitude)}, ${roundCoord(p.longitude)}</div>
  </div>`;
}

/** Pixel radius within which markers are grouped at the current zoom. */
const CLUSTER_RADIUS_PX = 44;

/**
 * Groups points that are close on screen at the map's current zoom
 * (grid of CLUSTER_RADIUS_PX cells in projected pixels). Recomputed on every
 * zoom/move, so clusters split apart as you zoom in.
 */
function clusterPoints(map: L.Map, points: DeviceMapPoint[]): DeviceMapPoint[][] {
  const zoom = map.getZoom();
  const cells = new Map<string, DeviceMapPoint[]>();
  for (const p of points) {
    const px = map.project([p.latitude, p.longitude], zoom);
    const key = `${Math.floor(px.x / CLUSTER_RADIUS_PX)}:${Math.floor(px.y / CLUSTER_RADIUS_PX)}`;
    const cell = cells.get(key);
    if (cell) cell.push(p);
    else cells.set(key, [p]);
  }
  return [...cells.values()];
}

const DEFAULT_CENTER: [number, number] = [20, 0];

/**
 * Devices that shared their location, on OpenStreetMap tiles. Driven
 * imperatively from effects (same lifecycle approach as threat-map.tsx).
 * Markers are coloured by severity; nearby markers are clustered with a count
 * (click a cluster to zoom in). Coordinates are shown rounded to 3 decimals.
 * `dark` dims and inverts the tiles so the map stays readable in dark mode.
 */
export function DeviceMap({ points, dark }: { points: DeviceMapPoint[]; dark: boolean }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const layerRef = useRef<L.LayerGroup | null>(null);
  const pointsRef = useRef<DeviceMapPoint[]>(points);
  const fittedRef = useRef(false);

  function render() {
    const map = mapRef.current;
    const layer = layerRef.current;
    if (!map || !layer) return;
    layer.clearLayers();
    for (const group of clusterPoints(map, pointsRef.current)) {
      if (group.length === 1) {
        const p = group[0];
        L.marker([p.latitude, p.longitude], { icon: pinIcon(SEVERITY_COLOR[p.severity]) })
          .bindPopup(popupHtml(p))
          .addTo(layer);
        continue;
      }
      const worst = group.reduce((a, b) => (SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a));
      const lat = group.reduce((s, p) => s + p.latitude, 0) / group.length;
      const lng = group.reduce((s, p) => s + p.longitude, 0) / group.length;
      const bounds = L.latLngBounds(group.map((p) => [p.latitude, p.longitude] as [number, number]));
      L.marker([lat, lng], { icon: clusterIcon(group.length, SEVERITY_COLOR[worst.severity]) })
        .on("click", () => {
          if (map.getZoom() >= map.getMaxZoom() || bounds.getNorthEast().equals(bounds.getSouthWest())) {
            L.popup().setLatLng([lat, lng]).setContent(group.map(popupHtml).join("<hr style='margin:6px 0'/>")).openOn(map);
          } else {
            map.fitBounds(bounds, { padding: [40, 40], maxZoom: map.getMaxZoom() });
          }
        })
        .addTo(layer);
    }
  }

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    if ((container as unknown as { _leaflet_id?: number })._leaflet_id) {
      delete (container as unknown as { _leaflet_id?: number })._leaflet_id;
    }
    const map = L.map(container, { scrollWheelZoom: true, maxZoom: 18 }).setView(DEFAULT_CENTER, 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      maxZoom: 19,
    }).addTo(map);
    mapRef.current = map;
    layerRef.current = L.layerGroup().addTo(map);
    fittedRef.current = false;
    map.on("zoomend", render);
    render();
    return () => {
      map.off("zoomend", render);
      map.remove();
      mapRef.current = null;
      layerRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    pointsRef.current = points;
    const map = mapRef.current;
    if (!map) return;
    if (!fittedRef.current && points.length > 0) {
      fittedRef.current = true;
      if (points.length === 1) map.setView([points[0].latitude, points[0].longitude], 10);
      else map.fitBounds(L.latLngBounds(points.map((p) => [p.latitude, p.longitude] as [number, number])), { padding: [32, 32], maxZoom: 12 });
    }
    render();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [points]);

  return (
    <div
      ref={containerRef}
      className={`h-full w-full ${dark ? "device-map-dark" : ""}`}
      style={{ background: dark ? "#1b1f2a" : "#e8ebf1" }}
    />
  );
}
