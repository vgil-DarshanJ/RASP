"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import { Badge, Card, ClockIcon, PlatformIcon, ZapIcon } from "@/components/ui";
import { DeviceTrailDrawer, type DeviceSummary } from "@/components/device-trail-drawer";
import { useAppSelection } from "@/lib/app-selection";

type Device = DeviceSummary;

const NEW_WINDOW_MS = 24 * 60 * 60 * 1000;

/** Same real device data as the Devices page (`GET .../devices`), just
 *  sorted by `firstSeen` instead of `lastSeen` — "which devices newly
 *  activated the SDK" rather than "what's the current inventory." No
 *  separate activation-event system exists; this is the honest view of
 *  the same rows through that lens. */
export default function ActivationsPage() {
  const { apps, selectedAppId, loading: appsLoading } = useAppSelection();
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);

  useEffect(() => {
    if (!selectedAppId) return;
    let cancelled = false;
    apiFetch<{ devices: Device[] }>(`/v1/dashboard/applications/${selectedAppId}/devices`).then((res) => {
      if (!cancelled) {
        setDevices([...res.devices].sort((a, b) => b.firstSeen.localeCompare(a.firstSeen)));
      }
    });
    return () => {
      cancelled = true;
    };
  }, [selectedAppId]);

  const newCount = useMemo(
    () => devices.filter((d) => Date.now() - new Date(d.firstSeen).getTime() < NEW_WINDOW_MS).length,
    [devices],
  );

  const selectedApp = apps.find((a) => a.id === selectedAppId);

  if (appsLoading) return <ActivationsSkeleton />;

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
        <h1 className="text-2xl font-semibold text-ink-900">Device Activations</h1>
        <p className="mt-1 text-sm text-ink-500">
          {devices.length} device{devices.length === 1 ? "" : "s"} total
          {newCount > 0 && <span className="ml-1 text-brand-700">· {newCount} new in the last 24h</span>} ·{" "}
          {selectedApp?.name}
        </p>
      </div>

      <Card className="overflow-hidden">
        {devices.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-14 text-center">
            <ZapIcon size={22} className="text-ink-300" />
            <p className="text-sm text-ink-400">No devices have activated the SDK for this application yet.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                  <th className="py-2.5 pl-5 pr-4 font-medium">Device</th>
                  <th className="py-2.5 pr-4 font-medium">OS</th>
                  <th className="py-2.5 pr-4 font-medium">App version</th>
                  <th className="py-2.5 pr-4 font-medium">
                    <span className="inline-flex items-center gap-1.5">
                      <ZapIcon size={12} /> First activated
                    </span>
                  </th>
                  <th className="py-2.5 pr-5 font-medium">Lifetime events</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => {
                  const isNew = Date.now() - new Date(d.firstSeen).getTime() < NEW_WINDOW_MS;
                  return (
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
                            <div className="flex items-center gap-1.5">
                              <span className="truncate font-medium text-ink-900">{d.deviceModel ?? "Unknown device"}</span>
                              {isNew && <Badge tone="green" icon={false}>New</Badge>}
                            </div>
                            <div className="truncate font-mono text-[11px] text-ink-400">{d.deviceId}</div>
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 pr-4 text-ink-600">
                        {d.osPlatform ? `${d.osPlatform} ${d.osVersion ?? ""}` : "—"}
                        {d.manufacturer && <div className="text-xs text-ink-400">{d.manufacturer}</div>}
                      </td>
                      <td className="py-2.5 pr-4 text-ink-600">{d.appVersion ?? "—"}</td>
                      <td className="py-2.5 pr-4 text-ink-500">
                        <span className="inline-flex items-center gap-1.5">
                          <ClockIcon size={12} className="text-ink-300" />
                          {new Date(d.firstSeen).toLocaleString()}
                        </span>
                      </td>
                      <td className="py-2.5 pr-5 text-ink-700">{d.eventCount}</td>
                    </tr>
                  );
                })}
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
        />
      )}
    </div>
  );
}

function ActivationsSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-8 w-56 rounded-lg bg-ink-100" />
      <div className="h-72 rounded-2xl bg-ink-100" />
    </div>
  );
}
