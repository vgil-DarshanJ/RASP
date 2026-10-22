"use client";

import Link from "next/link";
import { Card, ShieldIcon, StatusDot } from "@/components/ui";
import type { RiskEventRow } from "@/components/risk-events";
import { catalogFor } from "@/lib/alertCatalog";
import { useAppSelection } from "@/lib/app-selection";
import { timeAgo, usePolled } from "@/lib/usePolled";
import { capabilitiesOf } from "@/lib/visitor/capabilities";

interface RiskRules {
  deviceChangeVelocity: { maxDevices: number; windowMinutes: number };
  concurrentSessions: { maxDevices: number; windowMinutes: number };
  impossibleTravel: { maxSpeedKmh: number; minMinutes: number; minDistanceKm: number; ipCountryChangeMinutes: number };
  transactionVelocity: { maxCount: number; windowMinutes: number };
}

const mins = (m: number) => (m >= 1440 && m % 1440 === 0 ? `${m / 1440} d` : m >= 60 && m % 60 === 0 ? `${m / 60} h` : `${m} min`);

/** The six server-side rules (BE `risk/rules.ts`), presented as agents:
 *  what each one watches, its current threshold, and what it has caught. */
const AGENTS: { rule: string; watches: string; threshold: (r: RiskRules) => string }[] = [
  {
    rule: "new_device_for_account",
    watches: "An account signs in from a phone it has never used before.",
    threshold: () => "Any new device (a reinstall on the same phone is not new)",
  },
  {
    rule: "device_change_velocity",
    watches: "One account moving across many phones in a short time.",
    threshold: (r) => `More than ${r.deviceChangeVelocity.maxDevices} devices in ${mins(r.deviceChangeVelocity.windowMinutes)}`,
  },
  {
    rule: "concurrent_sessions",
    watches: "The same account active on several phones at once.",
    threshold: (r) => `More than ${r.concurrentSessions.maxDevices} devices within ${mins(r.concurrentSessions.windowMinutes)}`,
  },
  {
    rule: "impossible_travel",
    watches: "Two events further apart than anyone could travel in between.",
    threshold: (r) => `Faster than ${r.impossibleTravel.maxSpeedKmh} km/h over ≥ ${r.impossibleTravel.minDistanceKm} km`,
  },
  {
    rule: "transaction_velocity",
    watches: "A burst of payments from one account.",
    threshold: (r) => `More than ${r.transactionVelocity.maxCount} transactions in ${mins(r.transactionVelocity.windowMinutes)}`,
  },
  {
    rule: "new_beneficiary",
    watches: "Money sent to a payee the account has never paid before.",
    threshold: () => "First payment to any beneficiary",
  },
];

export default function FraudAgentsPage() {
  const { selectedAppId, selectedApp } = useAppSelection();
  const settings = usePolled<{ settings: { riskRules: RiskRules }; canEdit: boolean }>(
    selectedAppId && `/v1/apps/${selectedAppId}/security-settings`,
    60_000,
  );
  const risk = usePolled<{ events: RiskEventRow[] }>(
    selectedAppId && `/v1/dashboard/applications/${selectedAppId}/risk-events?limit=100`,
  );
  const counts = usePolled<{ counts: Record<string, number> }>(
    selectedAppId && `/v1/dashboard/applications/${selectedAppId}/detector-counts?hours=24`,
  );

  const events = risk.data?.events ?? [];
  const rules = settings.data?.settings.riskRules;
  const sentinels = capabilitiesOf("sef");

  return (
    <div>
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink-900">Fraud Prevention Agents</h1>
          <p className="mt-1 max-w-2xl text-sm text-ink-500">
            Explainable rules that run on the server over the session and transaction events {selectedApp?.name ?? "your app"} sends.
            No black box: every finding says which rule fired and why.
          </p>
        </div>
        {settings.data?.canEdit && (
          <Link href="/security-settings" className="rounded-lg bg-brand-600 px-3 py-2 text-xs font-medium text-white hover:bg-brand-700">
            Tune thresholds
          </Link>
        )}
      </div>

      {risk.data && events.length === 0 && (
        <Card className="mb-6 border-dashed p-4 text-sm text-ink-500">
          No session or transaction events received yet. Agents only see what the app reports — until it sends risk events,
          this means &quot;not evaluated&quot;, not &quot;low risk&quot;.
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {AGENTS.map((a) => {
          const cat = catalogFor(a.rule);
          const hits = events.filter((e) => e.rules.some((r) => r.rule === a.rule));
          const last = hits[0];
          return (
            <Card key={a.rule} className="flex flex-col p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-600">
                  <ShieldIcon size={18} />
                </div>
                <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700">
                  <StatusDot tone="green" pulse /> Active
                </span>
              </div>
              <div className="mt-3 font-semibold text-ink-900">{cat.title}</div>
              <p className="mt-1 flex-1 text-sm leading-relaxed text-ink-500">{a.watches}</p>
              <div className="mt-4 rounded-lg bg-ink-50 px-3 py-2 text-xs text-ink-600">
                <span className="font-medium text-ink-400">Fires when · </span>
                {rules ? a.threshold(rules) : "…"}
              </div>
              <div className="mt-4 flex items-end justify-between border-t border-ink-100 pt-3">
                <div>
                  <div className="text-2xl font-semibold text-ink-900">{hits.length}</div>
                  <div className="text-[11px] text-ink-400">hits in last {events.length} events</div>
                </div>
                <div className="text-right text-[11px] text-ink-400">
                  <div className="capitalize">Severity {cat.severity}</div>
                  <div>{last ? `last ${timeAgo(last.receivedAt)}` : "no hits yet"}</div>
                </div>
              </div>
            </Card>
          );
        })}
      </div>

      <h2 className="mb-1 mt-10 text-lg font-semibold text-ink-900">On-device fraud sentinels</h2>
      <p className="mb-4 text-sm text-ink-500">
        Social-engineering signals the app itself reports — the set-up of a scam, before any money moves. Last 24 hours.
      </p>
      <Card className="overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
              <th className="py-2.5 pl-5 pr-4 font-medium">Sentinel</th>
              <th className="hidden py-2.5 pr-4 font-medium md:table-cell">Watches for</th>
              <th className="py-2.5 pr-5 text-right font-medium">Detections · 24h</th>
            </tr>
          </thead>
          <tbody>
            {sentinels.map((s) => {
              const n = counts.data?.counts[s.id] ?? 0;
              return (
                <tr key={s.id} className="border-b border-ink-50">
                  <td className="py-2.5 pl-5 pr-4 font-medium text-ink-900">{catalogFor(s.id).title}</td>
                  <td className="hidden py-2.5 pr-4 text-xs text-ink-500 md:table-cell">{s.summary}</td>
                  <td className={`py-2.5 pr-5 text-right font-semibold ${n > 0 ? "text-red-600" : "text-ink-400"}`}>{n}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
