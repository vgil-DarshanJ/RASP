"use client";

import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { catalogFor } from "@/lib/alertCatalog";

const SEVERITY_MARKER_COLOR: Record<string, string> = {
  critical: "#b91c1c",
  high: "#dc2626",
  medium: "#d97706",
  low: "#059669",
};

/** Leaflet's default marker PNGs resolve to broken webpack asset paths
 *  in Next.js unless you hand-manage them — a plain inline SVG divIcon
 *  sidesteps that class of bug entirely and matches this app's own
 *  hand-rolled icon system (`components/ui.tsx`) instead of pulling in
 *  Leaflet's default image assets for a single pin shape. */
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

export interface ThreatMapPoint {
  eventId: string;
  detectorId: string;
  deviceId: string | null;
  receivedAt: string;
  latitude: number;
  longitude: number;
}

const DEFAULT_CENTER: [number, number] = [20, 0];

/**
 * Real device/threat locations on an actual map — OpenStreetMap tiles
 * (free, open-source, no API key), rendered with plain Leaflet driven
 * imperatively from a single effect (deliberately NOT `react-leaflet`'s
 * `<MapContainer>`) — that abstraction re-runs its mount effect against
 * the exact same DOM node during a React 18 dev double-invoke or a
 * Fast-Refresh reload without always calling Leaflet's own cleanup
 * first, which is what "Map container is already initialized" means:
 * Leaflet stamps a `_leaflet_id` on the container div and refuses to
 * `L.map()` it again while that stamp is present. This version owns
 * that lifecycle directly and defensively clears a stale stamp before
 * creating, so a dev-mode remount can never hit that error.
 *
 * Points come straight from `GET .../geography`, which only ever
 * contains a `latitude`/`longitude` pair when the HOST APP supplied one
 * to `RaspLeanSession.currentLocation` — the SDK itself never fetches
 * GPS (see `lean_session.dart`'s own doc) — so an app that never wires
 * that up simply shows no markers, honestly, rather than a fake center.
 */
export function ThreatMap({ points }: { points: ThreatMapPoint[] }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const markersLayerRef = useRef<L.LayerGroup | null>(null);
  const didFitRef = useRef(false);

  // Mount/unmount the map exactly once per real DOM node.
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Defensive: a stale stamp from a prior instance that didn't get a
    // clean `.remove()` (dev HMR, strict-mode double-invoke) must never
    // block creating a fresh map on this node.
    if ((container as unknown as { _leaflet_id?: number })._leaflet_id) {
      delete (container as unknown as { _leaflet_id?: number })._leaflet_id;
    }

    const map = L.map(container, { scrollWheelZoom: false }).setView(DEFAULT_CENTER, 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      maxZoom: 19,
    }).addTo(map);

    mapRef.current = map;
    markersLayerRef.current = L.layerGroup().addTo(map);
    didFitRef.current = false;

    return () => {
      map.remove();
      mapRef.current = null;
      markersLayerRef.current = null;
    };
  }, []);

  // Sync markers whenever `points` changes, without touching the map
  // instance itself.
  useEffect(() => {
    const map = mapRef.current;
    const layer = markersLayerRef.current;
    if (!map || !layer) return;

    layer.clearLayers();
    for (const p of points) {
      const catalog = catalogFor(p.detectorId);
      const color = SEVERITY_MARKER_COLOR[catalog.severity] ?? "#586485";
      const marker = L.marker([p.latitude, p.longitude], { icon: pinIcon(color) });
      const popupHtml = `
        <div style="font-size:12px;line-height:1.5;">
          <div style="font-weight:600;">${catalog.title}</div>
          <div style="font-family:monospace;font-size:11px;color:#6b7280;">${p.detectorId}</div>
          ${p.deviceId ? `<div style="font-family:monospace;font-size:11px;margin-top:2px;">${p.deviceId}</div>` : ""}
          <div style="margin-top:4px;color:#9ca3af;">${new Date(p.receivedAt).toLocaleString()}</div>
        </div>`;
      marker.bindPopup(popupHtml);
      marker.addTo(layer);
    }

    if (!didFitRef.current && points.length > 0) {
      didFitRef.current = true;
      if (points.length === 1) {
        map.setView([points[0].latitude, points[0].longitude], 10);
      } else {
        const bounds = L.latLngBounds(points.map((p) => [p.latitude, p.longitude] as [number, number]));
        map.fitBounds(bounds, { padding: [32, 32], maxZoom: 12 });
      }
    }
  }, [points]);

  return <div ref={containerRef} className="h-full w-full" style={{ background: "#e8ebf1" }} />;
}
