"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import {
  AlertTriangleIcon,
  Badge,
  Card,
  ClockIcon,
  MapPinIcon,
  PlatformIcon,
  RiskBadge,
  SmartphoneIcon,
  statusTone,
} from "@/components/ui";
import { DeviceTrailDrawer } from "@/components/device-trail-drawer";
import { useAppSelection } from "@/lib/app-selection";

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

interface Device {
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
  riskScore: number;
  riskLevel: string;
  riskDetectors: string[];
  /** The device opted in to sharing its location at least once (it can appear on the Device Map). */
  locationShared?: boolean;
}

/**
 * Real device inventory — every value here comes from
 * `GET /v1/dashboard/applications/:id/devices`, which derives it from
 * actual `SecurityEvent` rows a device has reported (see BE
 * `dashboard/routes.ts`). Nothing on this page is placeholder/mock data;
 * an org with no devices reporting yet shows a genuine empty state.
 */
export default function DevicesPage() {
  const { apps, selectedAppId, loading: appsLoading } = useAppSelection();
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!selectedAppId) return;
    let cancelled = false;

    async function load() {
      const res = await apiFetch<{ devices: Device[] }>(
        `/v1/dashboard/applications/${selectedAppId}/devices`,
      );
      if (!cancelled) setDevices(res.devices);
    }

    load();
    // Live — this list (and every device row's "Last seen") refreshes on
    // its own; nothing here needs a manual reload to stay current.
    const interval = setInterval(load, 5_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [selectedAppId]);

  useEffect(() => {
    const clock = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(clock);
  }, []);

  const selectedApp = apps.find((a) => a.id === selectedAppId);
  const flaggedCount = useMemo(() => devices.filter((d) => d.threatCount > 0).length, [devices]);

  if (appsLoading) return <DevicesSkeleton />;

  if (apps.length === 0) {
    return (
      <Card className="p-10 text-center">
        <div className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-ink-100 text-ink-400">
          <SmartphoneIcon size={20} />
        </div>
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
        <div className="flex items-center gap-2.5">
          <h1 className="text-2xl font-semibold text-ink-900">Devices</h1>
          <span className="flex items-center gap-1.5 rounded-full bg-ink-50 px-2 py-0.5 text-[11px] font-medium text-ink-500">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand-400 opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-brand-500" />
            </span>
            Live
          </span>
        </div>
        <p className="mt-1 text-sm text-ink-500">
          {devices.length} device{devices.length === 1 ? "" : "s"} reporting for {selectedApp?.name}
          {flaggedCount > 0 && (
            <span className="ml-1 text-red-600">· {flaggedCount} with active threat findings</span>
          )}
        </p>
      </div>

      <Card className="overflow-hidden">
        {devices.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-14 text-center">
            <SmartphoneIcon size={22} className="text-ink-300" />
            <p className="text-sm text-ink-400">
              No devices have reported events for this application yet. Once the SDK ships its
              first event, it will appear here.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                  <th className="py-2.5 pl-5 pr-4 font-medium">Device</th>
                  <th className="py-2.5 pr-4 font-medium">OS</th>
                  <th className="py-2.5 pr-4 font-medium">App / SDK version</th>
                  <th className="py-2.5 pr-4 font-medium">Last status</th>
                  <th className="py-2.5 pr-4 font-medium">Risk</th>
                  <th className="py-2.5 pr-4 font-medium">Events</th>
                  <th className="py-2.5 pr-4 font-medium">Threats</th>
                  <th className="py-2.5 pr-4 font-medium">Location</th>
                  <th className="py-2.5 pr-5 font-medium">
                    <span className="inline-flex items-center gap-1.5">
                      <ClockIcon size={12} /> Last seen
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr
                    key={d.deviceId}
                    onClick={() => setSelectedDevice(d)}
                    className="cursor-pointer border-b border-ink-50 hover:bg-ink-50/60"
                  >
                    <td className="py-2.5 pl-5 pr-4">
                      <div className="flex items-center gap-2.5">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-ink-50 text-ink-600">
                          <PlatformIcon platform={selectedApp?.platform ?? ""} size={15} />
                        </div>
                        <div className="min-w-0">
                          <div className="truncate font-medium text-ink-900">{d.deviceModel ?? "Unknown device"}</div>
                          <div className="truncate font-mono text-[11px] text-ink-400">{d.deviceId}</div>
                        </div>
                      </div>
                    </td>
                    <td className="py-2.5 pr-4 text-ink-600">
                      {d.osPlatform ? `${d.osPlatform} ${d.osVersion ?? ""}` : "—"}
                      {d.manufacturer && <div className="text-xs text-ink-400">{d.manufacturer}</div>}
                    </td>
                    <td className="py-2.5 pr-4 text-ink-600">
                      <div>{d.appVersion ?? "—"}</div>
                      <div className="text-xs text-ink-400">SDK {d.sdkVersion ?? "—"}</div>
                    </td>
                    <td className="py-2.5 pr-4">
                      <Badge tone={statusTone(d.lastStatus)}>{d.lastStatus}</Badge>
                    </td>
                    <td className="py-2.5 pr-4">
                      <RiskBadge score={d.riskScore} level={d.riskLevel} size="sm" />
                    </td>
                    <td className="py-2.5 pr-4 text-ink-700">{d.eventCount}</td>
                    <td className="py-2.5 pr-4">
                      {d.threatCount > 0 ? (
                        <span className="inline-flex items-center gap-1 font-medium text-red-600">
                          <AlertTriangleIcon size={13} /> {d.threatCount}
                        </span>
                      ) : (
                        <span className="text-ink-400">0</span>
                      )}
                    </td>
                    <td className="py-2.5 pr-4">
                      {d.locationShared ? (
                        <a
                          href="/map"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1 text-xs font-medium text-brand-700 hover:underline"
                        >
                          <MapPinIcon size={12} /> Shared
                        </a>
                      ) : (
                        <span className="text-xs text-ink-400">location not shared</span>
                      )}
                    </td>
                    <td className="py-2.5 pr-5 text-ink-500" title={new Date(d.lastSeen).toLocaleString()}>
                      {relativeTime(d.lastSeen, now)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selectedDevice && selectedApp && (
        <DeviceTrailDrawer
          applicationId={selectedApp.id}
          applicationPlatform={selectedApp.platform}
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
          onErased={() => setDevices((list) => list.filter((d) => d.deviceId !== selectedDevice.deviceId))}
        />
      )}
    </div>
  );
}

function DevicesSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-8 w-48 rounded-lg bg-ink-100" />
      <div className="h-96 rounded-2xl bg-ink-100" />
    </div>
  );
}
