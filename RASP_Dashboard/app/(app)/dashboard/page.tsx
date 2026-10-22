"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { catalogFor } from "@/lib/alertCatalog";
import { getStoredOrganization } from "@/lib/auth";
import { apiFetch } from "@/lib/api-client";
import {
  ActivityIcon,
  AlertTriangleIcon,
  Badge,
  Card,
  CheckCircleIcon,
  ClockIcon,
  RiskBadge,
  ShieldIcon,
  SmartphoneIcon,
  StatCard,
  StatusDot,
  statusTone,
} from "@/components/ui";
import { EventDetailDrawer, type SecurityEvent } from "@/components/event-drawer";
import { useIsDark } from "@/lib/useIsDark";
import { useAppSelection } from "@/lib/app-selection";

interface RiskSummary {
  totalDevices: number;
  averageRiskScore: number;
  averageRiskLevel: string;
  maxRiskScore: number;
  maxRiskLevel: string;
  distribution: Record<"low" | "medium" | "high" | "critical", number>;
  topRiskyDevices: Array<{ deviceId: string; riskScore: number }>;
  topContributingDetectors: Array<{ detectorId: string; deviceCount: number }>;
}

const BRAND = "#1fa285";
const DONUT_COLORS = ["#d28e15", "#e11d48", "#7c3aed", "#0891b2", "#ea580c", "#7784a3"];

const RESOURCES = [
  { href: "/controls", title: "Mobile App Controls", desc: "Self-assess your app against the OWASP MASVS-mapped checklist." },
  { href: "/capabilities/screen-sharing-risk", title: "Watch: screen-share scam", desc: "Six signals from one video call, recorded on a real phone." },
  { href: "/guide", title: "Integration guide", desc: "Add the SDK to Android native or Flutter in minutes." },
  { href: "/plans", title: "Plans & subscription", desc: "Compare what each plan switches on." },
];

export default function DashboardPage() {
  const isDark = useIsDark();
  const axisColor = isDark ? "#8b95ab" : "#7784a3";
  const gridColor = isDark ? "#28324a" : "#e8ebf1";
  const tickTextColor = isDark ? "#c2ccdf" : "#333c56";

  const { apps, selectedAppId, loading: appsLoading } = useAppSelection();
  const [detectorCounts, setDetectorCounts] = useState<Record<string, number>>({});
  const [volume, setVolume] = useState<{ bucket: string; status: string; count: number }[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);

  useEffect(() => {
    if (!selectedAppId) return;
    let cancelled = false;

    async function load() {
      const [countsRes, volumeRes, eventsRes, riskRes] = await Promise.all([
        apiFetch<{ counts: Record<string, number> }>(
          `/v1/dashboard/applications/${selectedAppId}/detector-counts?hours=24`,
        ),
        apiFetch<{ buckets: { bucket: string; status: string; count: number }[] }>(
          `/v1/dashboard/applications/${selectedAppId}/volume?hours=24`,
        ),
        apiFetch<{ events: SecurityEvent[] }>(
          `/v1/dashboard/applications/${selectedAppId}/events?limit=100${
            statusFilter ? `&status=${statusFilter}` : ""
          }`,
        ),
        apiFetch<RiskSummary>(`/v1/dashboard/applications/${selectedAppId}/risk-summary`),
      ]);
      if (cancelled) return;
      setDetectorCounts(countsRes.counts);
      setVolume(volumeRes.buckets);
      setEvents(eventsRes.events);
      setRiskSummary(riskRes);
    }

    load();
    const interval = setInterval(load, 15_000); // near-real-time polling
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [selectedAppId, statusFilter]);

  // Top 5 detector types plus "Other", for the occurrence donut.
  const occurrence = useMemo(() => {
    const sorted = Object.entries(detectorCounts)
      .map(([detectorId, count]) => ({ title: catalogFor(detectorId).title, count }))
      .sort((a, b) => b.count - a.count);
    const rows = sorted.slice(0, 5);
    const other = sorted.slice(5).reduce((s, r) => s + r.count, 0);
    if (other > 0) rows.push({ title: "Other", count: other });
    return { rows, total: sorted.reduce((s, r) => s + r.count, 0) };
  }, [detectorCounts]);

  const volumeChartData = useMemo(() => {
    const byBucket = new Map<string, number>();
    for (const row of volume) {
      byBucket.set(row.bucket, (byBucket.get(row.bucket) ?? 0) + row.count);
    }
    return Array.from(byBucket.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([bucket, count]) => ({
        time: new Date(bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        count,
      }));
  }, [volume]);

  const stats = useMemo(() => {
    let total = 0;
    let detected = 0;
    let secure = 0;
    for (const row of volume) {
      total += row.count;
      if (row.status === "DETECTED") detected += row.count;
      if (row.status === "SECURE") secure += row.count;
    }
    const uniqueDevices = new Set(events.map((e) => e.deviceId).filter(Boolean)).size;
    return { total, detected, secure, uniqueDevices };
  }, [volume, events]);

  const selectedApp = apps.find((a) => a.id === selectedAppId);

  if (appsLoading) return <DashboardSkeleton />;

  if (apps.length === 0) {
    return (
      <Card className="p-10 text-center">
        <div className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-brand-50 text-brand-600">
          <ActivityIcon size={20} />
        </div>
        <p className="text-sm text-ink-500">
          No applications registered yet — go to{" "}
          <a href="/apps" className="font-medium text-brand-700 hover:underline">
            Applications
          </a>{" "}
          to register one and start receiving events.
        </p>
      </Card>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink-900">Security dashboard</h1>
        <p className="mt-1 flex items-center gap-1.5 text-sm text-ink-500">
          <StatusDot tone="green" pulse />
          Live · updates every 15s · {selectedApp?.name}
        </p>
      </div>

      <div className="relative mb-6 overflow-hidden rounded-2xl border border-brand-400/25 bg-gradient-to-br from-navy-950 via-navy-900 to-black p-6 text-white">
        <div className="pointer-events-none absolute -right-16 -top-16 h-56 w-56 rounded-full bg-brand-500/25 blur-3xl" aria-hidden />
        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-lg font-semibold">
              {getStoredOrganization()?.name ? `${getStoredOrganization()!.name}, ` : ""}your apps are reporting in.
            </h2>
            <p className="mt-1 text-sm text-white/60">Turn signals into decisions: triage alerts, check client risk, close control gaps.</p>
            <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-xs text-white/70">
              {["Screen sharing & mirroring", "USB & device-lock posture", "Remote-access scam signals"].map((t) => (
                <span key={t} className="flex items-center gap-1.5">
                  <CheckCircleIcon size={13} className="text-brand-300" /> {t}
                </span>
              ))}
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            <Link href="/alerts-inbox" className="rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-black hover:bg-brand-400">
              Open Alerts Inbox
            </Link>
            <Link href="/apps" className="rounded-lg border border-white/20 px-4 py-2 text-sm font-medium text-white/85 hover:border-white/40">
              Add application
            </Link>
          </div>
        </div>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard label="Events · 24h" value={stats.total} icon={<ActivityIcon size={18} />} tone="brand" />
        <StatCard
          label="Threats detected"
          value={stats.detected}
          icon={<AlertTriangleIcon size={18} />}
          tone={stats.detected > 0 ? "red" : "slate"}
        />
        <StatCard label="Secure checks" value={stats.secure} icon={<CheckCircleIcon size={18} />} tone="brand" />
        <StatCard label="Devices reporting" value={stats.uniqueDevices} icon={<SmartphoneIcon size={18} />} tone="slate" />
        <StatCard
          label="Highest device risk"
          value={riskSummary ? riskSummary.maxRiskScore : "—"}
          icon={<ShieldIcon size={18} />}
          tone={
            riskSummary?.maxRiskLevel === "critical" || riskSummary?.maxRiskLevel === "high"
              ? "red"
              : riskSummary?.maxRiskLevel === "medium"
              ? "amber"
              : "brand"
          }
          sub={riskSummary ? `avg ${riskSummary.averageRiskScore} across ${riskSummary.totalDevices} devices` : undefined}
        />
      </div>

      {riskSummary && riskSummary.totalDevices > 0 && (
        <Card className="mb-6 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink-700">Risk posture</h2>
            <span className="text-xs text-ink-400">
              Weighted from each device's latest DETECTED findings — see Devices for per-device detail
            </span>
          </div>
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            <div>
              <div className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-400">Devices by risk band</div>
              <div className="space-y-2">
                {(["critical", "high", "medium", "low"] as const).map((level) => {
                  const count = riskSummary.distribution[level];
                  const pct = riskSummary.totalDevices > 0 ? (count / riskSummary.totalDevices) * 100 : 0;
                  return (
                    <div key={level} className="flex items-center gap-3">
                      <div className="w-16 shrink-0">
                        <RiskBadge score={0} level={level} size="sm" />
                      </div>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-ink-100">
                        <div
                          className="h-full rounded-full bg-ink-400"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="w-6 text-right text-xs text-ink-500">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
            <div>
              <div className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-400">
                Top detectors driving risk
              </div>
              {riskSummary.topContributingDetectors.length === 0 ? (
                <p className="text-sm text-ink-400">No active findings right now.</p>
              ) : (
                <div className="space-y-1.5">
                  {riskSummary.topContributingDetectors.slice(0, 5).map((d) => (
                    <div key={d.detectorId} className="flex items-center justify-between text-sm">
                      <span className="font-mono text-xs text-ink-700">{d.detectorId}</span>
                      <span className="text-xs text-ink-400">
                        {d.deviceCount} device{d.deviceCount === 1 ? "" : "s"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Card>
      )}

      <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card className="p-5">
          <h2 className="text-sm font-semibold text-ink-700">Threat occurrence — last 24h</h2>
          <p className="mb-4 text-xs text-ink-400">Top 5 incident types for this application</p>
          {occurrence.rows.length === 0 ? (
            <EmptyChart />
          ) : (
            <div className="flex flex-col items-center gap-6 sm:flex-row">
              <div className="relative h-[200px] w-[200px] shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={occurrence.rows} dataKey="count" nameKey="title" innerRadius={68} outerRadius={92} paddingAngle={2} stroke="none">
                      {occurrence.rows.map((r, i) => (
                        <Cell key={r.title} fill={DONUT_COLORS[i % DONUT_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip content={<ChartTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-semibold text-ink-900">{occurrence.total}</span>
                  <span className="text-xs text-ink-400">Total</span>
                </div>
              </div>
              <ul className="w-full space-y-2">
                {occurrence.rows.map((r, i) => (
                  <li key={r.title} className="flex items-center gap-2 border-b border-ink-100 pb-2 text-sm last:border-0">
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: DONUT_COLORS[i % DONUT_COLORS.length] }} />
                    <span className="flex-1 truncate text-ink-700">{r.title}</span>
                    <span className="text-xs text-ink-500">
                      {Math.round((r.count / occurrence.total) * 100)}% ({r.count})
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>

        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">Event volume — last 24h</h2>
          {volumeChartData.length === 0 ? (
            <EmptyChart />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={volumeChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                <XAxis dataKey="time" tick={{ fontSize: 11, fill: axisColor }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: axisColor }} axisLine={false} tickLine={false} />
                <Tooltip content={<ChartTooltip />} cursor={{ stroke: BRAND, strokeWidth: 1, strokeDasharray: "4 4" }} />
                <Line type="monotone" dataKey="count" stroke={BRAND} strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-100 px-5 py-4">
          <h2 className="text-sm font-semibold text-ink-700">Recent events</h2>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-md border border-ink-200 bg-surface px-2 py-1.5 text-xs text-ink-700 outline-none focus:border-brand-500"
          >
            <option value="">All statuses</option>
            <option value="DETECTED">Detected</option>
            <option value="SECURE">Secure</option>
            <option value="ERROR">Error</option>
            <option value="UNAVAILABLE">Unavailable</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                <th className="py-2.5 pl-5 pr-4 font-medium">
                  <span className="inline-flex items-center gap-1.5">
                    <ClockIcon size={12} /> Time
                  </span>
                </th>
                <th className="py-2.5 pr-4 font-medium">Detector</th>
                <th className="py-2.5 pr-4 font-medium">Status</th>
                <th className="py-2.5 pr-4 font-medium">Device</th>
                <th className="py-2.5 pr-4 font-medium">OS</th>
                <th className="py-2.5 pr-5 font-medium">App version</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-ink-400">
                    No events yet for this application.
                  </td>
                </tr>
              )}
              {events.map((event) => (
                <tr
                  key={event.id}
                  onClick={() => setSelectedEvent(event)}
                  className="cursor-pointer border-b border-ink-50 transition hover:bg-ink-50/60"
                >
                  <td className="py-2.5 pl-5 pr-4 text-ink-500">
                    {new Date(event.receivedAt).toLocaleString()}
                  </td>
                  <td className="py-2.5 pr-4 font-mono text-xs font-medium text-ink-900">{event.detectorId}</td>
                  <td className="py-2.5 pr-4">
                    <Badge tone={statusTone(event.status)}>{event.status}</Badge>
                  </td>
                  <td className="py-2.5 pr-4 text-ink-600">{event.deviceModel ?? "—"}</td>
                  <td className="py-2.5 pr-4 text-ink-600">
                    {event.osPlatform ? `${event.osPlatform} ${event.osVersion ?? ""}` : "—"}
                  </td>
                  <td className="py-2.5 pr-5 text-ink-600">{event.appVersion ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="mb-3 mt-8 text-sm font-medium text-ink-500">Resources</div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {RESOURCES.map((r) => (
          <Link key={r.href} href={r.href} className="group">
            <Card className="h-full p-4 transition group-hover:border-brand-300">
              <div className="text-sm font-semibold text-ink-900 group-hover:text-brand-700">{r.title} →</div>
              <p className="mt-1 text-xs leading-relaxed text-ink-500">{r.desc}</p>
            </Card>
          </Link>
        ))}
      </div>

      {selectedEvent && (
        <EventDetailDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  );
}

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-ink-100 bg-surface px-3 py-2 text-xs shadow-lg">
      {label && <div className="mb-1 font-medium text-ink-700">{label}</div>}
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-1.5 text-ink-600">
          <span className="h-2 w-2 rounded-full" style={{ background: p.color }} />
          {p.value} events
        </div>
      ))}
    </div>
  );
}

function EmptyChart() {
  return (
    <div className="flex h-[260px] flex-col items-center justify-center gap-2 text-sm text-ink-400">
      <ActivityIcon size={22} className="text-ink-300" />
      No data yet
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-8 w-64 rounded-lg bg-ink-100" />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-24 rounded-2xl bg-ink-100" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="h-72 rounded-2xl bg-ink-100" />
        <div className="h-72 rounded-2xl bg-ink-100" />
      </div>
      <div className="h-64 rounded-2xl bg-ink-100" />
    </div>
  );
}
