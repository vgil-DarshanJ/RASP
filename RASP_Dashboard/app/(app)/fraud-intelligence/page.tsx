"use client";

import { useMemo } from "react";
import { Card, StatCard, ActivityIcon, AlertTriangleIcon, MapPinIcon, ZapIcon } from "@/components/ui";
import { RiskEventsCard, type RiskEventRow } from "@/components/risk-events";
import { catalogFor } from "@/lib/alertCatalog";
import { useAppSelection } from "@/lib/app-selection";
import { usePolled } from "@/lib/usePolled";

function Bars({ rows, tone = "bg-brand-500" }: { rows: { label: string; value: number }[]; tone?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  if (rows.length === 0) return <p className="py-6 text-center text-sm text-ink-400">No data yet</p>;
  return (
    <div className="space-y-2.5">
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-3 text-sm">
          <span className="w-40 shrink-0 truncate text-ink-700" title={r.label}>{r.label}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-ink-100">
            <div className={`h-full rounded-full ${tone}`} style={{ width: `${(r.value / max) * 100}%` }} />
          </div>
          <span className="w-8 text-right text-xs font-medium text-ink-500">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

/** Analytics over the most recent 100 session / transaction risk events:
 *  which agents fire, the SDK's own verdicts, where requests come from, and
 *  when. All of it from GET .../risk-events — no extra backend route. */
export default function FraudIntelligencePage() {
  const { selectedAppId, selectedApp } = useAppSelection();
  const risk = usePolled<{ events: RiskEventRow[] }>(
    selectedAppId && `/v1/dashboard/applications/${selectedAppId}/risk-events?limit=100`,
  );
  const events = risk.data?.events ?? [];

  const view = useMemo(() => {
    const tally = (keys: string[]) => {
      const m = new Map<string, number>();
      keys.forEach((k) => m.set(k, (m.get(k) ?? 0) + 1));
      return [...m.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
    };
    const flagged = events.filter((e) => e.rules.length > 0);
    const hours = Array.from({ length: 24 }, (_, i) => ({ hour: i, total: 0, flagged: 0 }));
    const dayAgo = Date.now() - 24 * 3600_000;
    for (const e of events) {
      const t = new Date(e.receivedAt).getTime();
      if (t < dayAgo) continue;
      const slot = 23 - Math.floor((Date.now() - t) / 3600_000);
      if (slot < 0) continue;
      hours[slot].total++;
      if (e.rules.length) hours[slot].flagged++;
    }
    return {
      flagged,
      rules: tally(flagged.flatMap((e) => e.rules.map((r) => catalogFor(r.rule).title))),
      verdicts: tally(events.map((e) => (e.riskVerdict === "UNKNOWN" ? "Not decided" : e.riskVerdict.toLowerCase()))),
      countries: tally(events.map((e) => e.ipCountry ?? "Unknown")).slice(0, 6),
      accounts: new Set(flagged.map((e) => e.accountHash)).size,
      transactions: events.filter((e) => e.type === "transaction").length,
      hours,
    };
  }, [events]);

  const peak = Math.max(1, ...view.hours.map((h) => h.total));

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink-900">Fraud Intelligence</h1>
        <p className="mt-1 max-w-2xl text-sm text-ink-500">
          What the fraud agents see across the last {events.length || 100} session and transaction events of {selectedApp?.name ?? "this app"}.
        </p>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Risk events" value={events.length} icon={<ActivityIcon size={18} />} sub={`${view.transactions} transactions`} />
        <StatCard
          label="Flagged"
          value={view.flagged.length}
          icon={<AlertTriangleIcon size={18} />}
          tone={view.flagged.length ? "red" : "slate"}
          sub={events.length ? `${Math.round((view.flagged.length / events.length) * 100)}% of events` : undefined}
        />
        <StatCard label="Accounts flagged" value={view.accounts} icon={<ZapIcon size={18} />} tone="amber" />
        <StatCard label="Countries seen" value={view.countries.filter((c) => c.label !== "Unknown").length} icon={<MapPinIcon size={18} />} tone="slate" />
      </div>

      <Card className="mb-6 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-ink-700">Risk events · last 24 h</h2>
          <span className="flex items-center gap-3 text-[11px] text-ink-400">
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-ink-300" /> all</span>
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-red-500" /> flagged</span>
          </span>
        </div>
        <div className="flex h-32 items-end gap-1">
          {view.hours.map((h) => (
            <div key={h.hour} className="relative flex-1 rounded-t bg-ink-200" style={{ height: `${(h.total / peak) * 100}%`, minHeight: 2 }} title={`${h.total} events, ${h.flagged} flagged`}>
              <div className="absolute inset-x-0 bottom-0 rounded-t bg-red-500" style={{ height: h.total ? `${(h.flagged / h.total) * 100}%` : 0 }} />
            </div>
          ))}
        </div>
        <div className="mt-1.5 flex justify-between text-[10px] text-ink-400">
          <span>24 h ago</span>
          <span>now</span>
        </div>
      </Card>

      <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">Agents that fired</h2>
          <Bars rows={view.rules} tone="bg-red-500" />
        </Card>
        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">SDK verdicts</h2>
          <Bars rows={view.verdicts} />
        </Card>
        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">Request IP country</h2>
          <Bars rows={view.countries} tone="bg-cyan-500" />
          <p className="mt-3 text-[11px] text-ink-400">From the request IP — VPNs and roaming change it, so treat it as a hint.</p>
        </Card>
      </div>

      {selectedAppId && <RiskEventsCard applicationId={selectedAppId} />}
    </div>
  );
}
