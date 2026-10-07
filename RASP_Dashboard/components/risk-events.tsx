"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import { Badge, Card } from "@/components/ui";
import { catalogFor } from "@/lib/alertCatalog";

/** One session / transaction risk event as the dashboard API returns it:
 *  hashes already shortened to 12 characters, no coordinates. */
export interface RiskEventRow {
  id: string;
  type: "session" | "transaction";
  deviceKeyId: string;
  accountHash: string;
  sessionHash: string;
  sessionEvent?: string;
  beneficiaryHash?: string;
  currency?: string;
  channel?: string;
  riskScore: number | null;
  riskVerdict: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN" | string;
  ipCountry: string | null;
  locationShared: boolean;
  eventTime: string;
  receivedAt: string;
  rules: { rule: string; severity: string; explanation: string }[];
}

const POLL_MS = 10_000;

function severityTone(severity: string): "red" | "amber" | "slate" {
  return severity === "high" || severity === "critical" ? "red" : severity === "medium" ? "amber" : "slate";
}

/** The SDK's own verdict. UNKNOWN stays "not decided" — never shown as low risk. */
function VerdictBadge({ verdict, score }: { verdict: string; score: number | null }) {
  const tone = verdict === "HIGH" ? "red" : verdict === "MEDIUM" ? "amber" : verdict === "LOW" ? "green" : "slate";
  const label = verdict === "UNKNOWN" ? "not decided" : verdict.toLowerCase();
  return (
    <Badge tone={tone} icon={false}>
      {label}
      {score !== null ? ` · ${score}` : ""}
    </Badge>
  );
}

function What({ event }: { event: RiskEventRow }) {
  if (event.type === "session") {
    return <span className="text-ink-800">Session · {event.sessionEvent}</span>;
  }
  return (
    <span className="text-ink-800">
      Transaction · {event.channel} · {event.currency}
      <span className="ml-1 font-mono text-[11px] text-ink-400" title="Beneficiary (hashed, shortened)">
        → {event.beneficiaryHash}…
      </span>
    </span>
  );
}

function RuleList({ rules }: { rules: RiskEventRow["rules"] }) {
  if (rules.length === 0) return <span className="text-xs text-ink-400">no rule fired</span>;
  return (
    <div className="flex flex-col gap-1">
      {rules.map((r) => (
        <div key={r.rule} className="flex items-start gap-1.5" title={r.explanation}>
          <Badge tone={severityTone(r.severity)} icon={false}>
            {catalogFor(r.rule).title}
          </Badge>
        </div>
      ))}
    </div>
  );
}

function usePolled<T>(path: string | null): T | null | undefined {
  const [data, setData] = useState<T | null | undefined>(undefined);
  useEffect(() => {
    if (!path) return;
    let cancelled = false;
    async function load() {
      try {
        const res = await apiFetch<T>(path!);
        if (!cancelled) setData(res);
      } catch {
        if (!cancelled) setData(null);
      }
    }
    load();
    const interval = setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [path]);
  return data;
}

/**
 * Live Threats: recent session / transaction risk events where at least
 * one rule fired, with the rule explanations. Hashes are shortened; the
 * dashboard never sees account numbers, names or amounts.
 */
export function RiskEventsCard({ applicationId }: { applicationId: string }) {
  const data = usePolled<{ events: RiskEventRow[] }>(
    `/v1/dashboard/applications/${applicationId}/risk-events?limit=50&onlyFlagged=true`,
  );

  return (
    <Card className="mb-6 overflow-hidden">
      <div className="border-b border-ink-100 px-5 py-3">
        <h2 className="text-sm font-semibold text-ink-700">Fraud risk signals</h2>
        <p className="mt-0.5 text-xs text-ink-400">
          Rules over session and transaction events your app sends. Accounts and beneficiaries are hashed; no amounts.
          An app that sends no events shows nothing here — that means not evaluated, not low risk.
        </p>
      </div>
      {data === undefined ? (
        <div className="m-5 h-16 animate-pulse rounded-lg bg-ink-100" />
      ) : data === null ? (
        <p className="px-5 py-6 text-sm text-ink-400">Could not load risk events.</p>
      ) : data.events.length === 0 ? (
        <p className="px-5 py-6 text-sm text-ink-400">No rule has fired on recent risk events.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                <th className="py-2.5 pl-5 pr-4 font-medium">Time</th>
                <th className="py-2.5 pr-4 font-medium">Event</th>
                <th className="py-2.5 pr-4 font-medium">Account</th>
                <th className="py-2.5 pr-4 font-medium">Device key</th>
                <th className="py-2.5 pr-4 font-medium">Rules</th>
                <th className="py-2.5 pr-5 font-medium">SDK verdict</th>
              </tr>
            </thead>
            <tbody>
              {data.events.map((e) => (
                <tr key={e.id} className="border-b border-ink-50 align-top">
                  <td className="py-2.5 pl-5 pr-4 text-ink-500">{new Date(e.receivedAt).toLocaleString()}</td>
                  <td className="py-2.5 pr-4">
                    <What event={e} />
                    <div className="text-[11px] text-ink-400">
                      {e.ipCountry ? `IP country ${e.ipCountry}` : "IP country unknown"}
                      {e.locationShared ? " · location shared" : ""}
                    </div>
                  </td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-ink-600">{e.accountHash}…</td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-ink-600">{e.deviceKeyId}…</td>
                  <td className="py-2.5 pr-4">
                    <RuleList rules={e.rules} />
                    {e.rules.map((r) => (
                      <p key={r.rule} className="mt-1 max-w-sm text-[11px] leading-snug text-ink-500">{r.explanation}</p>
                    ))}
                  </td>
                  <td className="py-2.5 pr-5">
                    <VerdictBadge verdict={e.riskVerdict} score={e.riskScore} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/**
 * Device drawer: how many accounts (hashes) use this device and its recent
 * session / transaction risk events.
 */
export function DeviceRiskCard({ applicationId, deviceId }: { applicationId: string; deviceId: string }) {
  const params = new URLSearchParams({ deviceId, limit: "10" });
  const data = usePolled<{ accountBindingCount: number; events: RiskEventRow[] }>(
    `/v1/dashboard/applications/${applicationId}/device-risk?${params.toString()}`,
  );

  return (
    <div className="border-b border-ink-100 px-5 py-3">
      <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-ink-400">Fraud risk</div>
      {data === undefined ? (
        <div className="h-10 animate-pulse rounded-lg bg-ink-100" />
      ) : data === null ? (
        <p className="text-xs text-ink-400">Could not load risk events</p>
      ) : (
        <div className="space-y-2 text-xs">
          <div className="text-ink-700">
            Accounts bound to this device: <span className="font-semibold">{data.accountBindingCount}</span>
          </div>
          {data.events.length === 0 ? (
            <p className="text-ink-400">No session or transaction risk events from this device</p>
          ) : (
            <ul className="space-y-1.5">
              {data.events.map((e) => (
                <li key={e.id} className="rounded-lg border border-ink-100 px-2.5 py-1.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <What event={e} />
                    <span className="font-mono text-[11px] text-ink-400" title="Account (hashed, shortened)">{e.accountHash}…</span>
                    <VerdictBadge verdict={e.riskVerdict} score={e.riskScore} />
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    <RuleList rules={e.rules} />
                  </div>
                  <div className="mt-0.5 text-[11px] text-ink-400">{new Date(e.receivedAt).toLocaleString()}</div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
