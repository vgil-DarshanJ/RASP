"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import {
  AlertTriangleIcon,
  Badge,
  PlatformIcon,
  RiskBadge,
  SmartphoneIcon,
  XIcon,
  statusTone,
} from "@/components/ui";
import { DeviceTrailDrawer, type DeviceSummary as BaseDeviceSummary } from "@/components/device-trail-drawer";

interface DeviceWithRisk extends BaseDeviceSummary {
  riskScore: number;
  riskLevel: string;
}

/**
 * "How many devices, complete view" — opened from the Licenses page's
 * device-count badge. Reads the exact same
 * `GET /v1/dashboard/applications/:id/devices` endpoint the Devices page
 * itself uses (same risk scores, same live data), just scoped to one
 * application and shown as a drawer instead of a full page — so a
 * license/credential's real usage is one click away without leaving
 * Licenses. Clicking a row drills into the same per-device
 * `DeviceTrailDrawer` the Devices page uses, layered on top.
 */
export function ApplicationDevicesDrawer({
  applicationId,
  applicationName,
  applicationPlatform,
  onClose,
}: {
  applicationId: string;
  applicationName: string;
  applicationPlatform: string;
  onClose: () => void;
}) {
  const [devices, setDevices] = useState<DeviceWithRisk[] | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<DeviceWithRisk | null>(null);

  useEffect(() => {
    let cancelled = false;
    apiFetch<{ devices: DeviceWithRisk[] }>(`/v1/dashboard/applications/${applicationId}/devices`).then((res) => {
      if (!cancelled) setDevices(res.devices);
    });
    return () => {
      cancelled = true;
    };
  }, [applicationId]);

  return (
    <>
      <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-[2px]" onClick={onClose}>
        <div
          className="flex h-full w-full max-w-2xl flex-col bg-surface shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between border-b border-ink-100 px-6 py-5">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-ink-50 text-ink-700">
                <PlatformIcon platform={applicationPlatform} size={20} />
              </div>
              <div>
                <h3 className="text-base font-semibold text-ink-900">{applicationName}</h3>
                <p className="text-xs text-ink-400">
                  {devices ? `${devices.length} device${devices.length === 1 ? "" : "s"} reporting` : "Loading…"}
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-ink-400 hover:bg-ink-50 hover:text-ink-700"
            >
              <XIcon size={16} />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto">
            {devices === null ? (
              <div className="animate-pulse space-y-2 p-4">
                {[0, 1, 2, 3].map((i) => (
                  <div key={i} className="h-14 rounded-lg bg-ink-100" />
                ))}
              </div>
            ) : devices.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-14 text-center">
                <SmartphoneIcon size={22} className="text-ink-300" />
                <p className="text-sm text-ink-400">No devices have reported events for this application yet.</p>
              </div>
            ) : (
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                    <th className="py-2.5 pl-5 pr-4 font-medium">Device</th>
                    <th className="py-2.5 pr-4 font-medium">Status</th>
                    <th className="py-2.5 pr-4 font-medium">Risk</th>
                    <th className="py-2.5 pr-4 font-medium">Threats</th>
                    <th className="py-2.5 pr-5 font-medium">Last seen</th>
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
                        <div className="truncate font-medium text-ink-900">{d.deviceModel ?? "Unknown device"}</div>
                        <div className="truncate font-mono text-[11px] text-ink-400">{d.deviceId}</div>
                      </td>
                      <td className="py-2.5 pr-4">
                        <Badge tone={statusTone(d.lastStatus)}>{d.lastStatus}</Badge>
                      </td>
                      <td className="py-2.5 pr-4">
                        <RiskBadge score={d.riskScore} level={d.riskLevel} size="sm" />
                      </td>
                      <td className="py-2.5 pr-4">
                        {d.threatCount > 0 ? (
                          <span className="inline-flex items-center gap-1 font-medium text-red-600">
                            <AlertTriangleIcon size={13} /> {d.threatCount}
                          </span>
                        ) : (
                          <span className="text-ink-400">0</span>
                        )}
                      </td>
                      <td className="py-2.5 pr-5 text-ink-500">{new Date(d.lastSeen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {selectedDevice && (
        <DeviceTrailDrawer
          applicationId={applicationId}
          applicationPlatform={applicationPlatform}
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
        />
      )}
    </>
  );
}
