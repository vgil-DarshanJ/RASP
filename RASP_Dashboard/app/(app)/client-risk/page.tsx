"use client";

import { useState } from "react";
import { Card, RiskBadge } from "@/components/ui";
import { DeviceTrailDrawer, type DeviceSummary } from "@/components/device-trail-drawer";
import { catalogFor } from "@/lib/alertCatalog";
import { useAppSelection } from "@/lib/app-selection";
import { timeAgo, usePolled } from "@/lib/usePolled";

interface Device extends DeviceSummary {
  riskScore: number;
  riskLevel: string;
  riskDetectors: string[];
}

type Level = "critical" | "high" | "medium" | "low";

/** The action we suggest for a band. A suggestion only — the app and the
 *  bank's own policy decide what actually happens to a session. */
const STATES: { level: Level; state: string; action: string; tone: string; bar: string }[] = [
  { level: "critical", state: "Block", action: "Stop sensitive actions and ask the customer to contact you.", tone: "text-red-700", bar: "bg-red-600" },
  { level: "high", state: "Step-up", action: "Require extra verification before payments or payee changes.", tone: "text-orange-700", bar: "bg-orange-500" },
  { level: "medium", state: "Watch", action: "Allow, with limits on new payees and amounts.", tone: "text-amber-700", bar: "bg-amber-500" },
  { level: "low", state: "Trusted", action: "Allow normally.", tone: "text-emerald-700", bar: "bg-emerald-500" },
];

export default function ClientRiskPage() {
  const { selectedAppId, selectedApp } = useAppSelection();
  const data = usePolled<{ devices: Device[] }>(selectedAppId && `/v1/dashboard/applications/${selectedAppId}/devices`);
  const [band, setBand] = useState<Level | null>(null);
  const [open, setOpen] = useState<Device | null>(null);

  const devices = data.data?.devices ?? [];
  const byLevel = (l: Level) => devices.filter((d) => d.riskLevel === l);
  const shown = band ? byLevel(band) : devices;

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink-900">Client Risk State</h1>
        <p className="mt-1 max-w-2xl text-sm text-ink-500">
          Every device of {selectedApp?.name ?? "this app"} placed in a risk state from the latest result of each detector — a
          detector that recovers stops counting. Use the state to decide how much friction a session gets.
        </p>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {STATES.map((s) => {
          const n = byLevel(s.level).length;
          const active = band === s.level;
          return (
            <button key={s.level} onClick={() => setBand(active ? null : s.level)} className="text-left">
              <Card className={`h-full p-5 transition ${active ? "ring-2 ring-brand-400" : "hover:border-brand-300"}`}>
                <div className="flex items-center justify-between">
                  <span className={`text-sm font-semibold ${s.tone}`}>{s.state}</span>
                  <span className="text-[11px] font-medium uppercase tracking-wide text-ink-400">{s.level} risk</span>
                </div>
                <div className="mt-3 text-3xl font-semibold text-ink-900">{n}</div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink-100">
                  <div className={`h-full ${s.bar}`} style={{ width: `${devices.length ? (n / devices.length) * 100 : 0}%` }} />
                </div>
                <p className="mt-3 text-xs leading-relaxed text-ink-500">{s.action}</p>
              </Card>
            </button>
          );
        })}
      </div>

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-100 px-5 py-4">
          <h2 className="text-sm font-semibold text-ink-700">
            {band ? `${STATES.find((s) => s.level === band)!.state} devices` : "All devices"} · {shown.length}
          </h2>
          {band && (
            <button onClick={() => setBand(null)} className="text-xs font-medium text-brand-700 hover:underline">
              Show all
            </button>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                <th className="py-2.5 pl-5 pr-4 font-medium">Device</th>
                <th className="py-2.5 pr-4 font-medium">Risk</th>
                <th className="py-2.5 pr-4 font-medium">State</th>
                <th className="py-2.5 pr-4 font-medium">Why</th>
                <th className="py-2.5 pr-5 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {data.loading && (
                <tr><td colSpan={5} className="py-10 text-center text-ink-400">Loading devices…</td></tr>
              )}
              {!data.loading && shown.length === 0 && (
                <tr><td colSpan={5} className="py-10 text-center text-ink-400">No devices in this state.</td></tr>
              )}
              {shown.map((d) => {
                const st = STATES.find((s) => s.level === d.riskLevel) ?? STATES[3];
                return (
                  <tr key={d.deviceId} onClick={() => setOpen(d)} className="cursor-pointer border-b border-ink-50 transition hover:bg-ink-50/60">
                    <td className="py-2.5 pl-5 pr-4">
                      <div className="font-medium text-ink-900">{[d.manufacturer, d.deviceModel].filter(Boolean).join(" ") || "Unknown device"}</div>
                      <div className="font-mono text-[11px] text-ink-400">{d.deviceId.slice(0, 16)}…</div>
                    </td>
                    <td className="py-2.5 pr-4"><RiskBadge score={d.riskScore} level={d.riskLevel} size="sm" /></td>
                    <td className={`py-2.5 pr-4 text-sm font-semibold ${st.tone}`}>{st.state}</td>
                    <td className="py-2.5 pr-4">
                      <div className="flex max-w-xs flex-wrap gap-1">
                        {d.riskDetectors.length === 0 ? (
                          <span className="text-xs text-ink-400">No active findings</span>
                        ) : (
                          d.riskDetectors.slice(0, 3).map((id) => (
                            <span key={id} className="rounded bg-ink-100 px-1.5 py-0.5 text-[11px] text-ink-700">{catalogFor(id).title}</span>
                          ))
                        )}
                        {d.riskDetectors.length > 3 && <span className="text-[11px] text-ink-400">+{d.riskDetectors.length - 3}</span>}
                      </div>
                    </td>
                    <td className="py-2.5 pr-5 text-xs text-ink-500">{timeAgo(d.lastSeen)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
      <p className="mt-3 text-xs text-ink-400">
        A reinstall on the same phone keeps its device id; a cloned app runs under a different Android user and shows as a separate device.
      </p>

      {open && selectedApp && (
        <DeviceTrailDrawer applicationId={selectedApp.id} applicationPlatform={selectedApp.platform} device={open} onClose={() => setOpen(null)} />
      )}
    </div>
  );
}
