"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AlertTriangleIcon, Badge, Card, CheckCircleIcon, MailIcon, SmartphoneIcon } from "@/components/ui";
import type { SecurityEvent } from "@/components/event-drawer";
import type { RiskEventRow } from "@/components/risk-events";
import { CATEGORY_COLORS, catalogFor } from "@/lib/alertCatalog";
import { useAppSelection } from "@/lib/app-selection";
import { timeAgo, usePolled } from "@/lib/usePolled";

type Severity = "critical" | "high" | "medium" | "low";

interface InboxItem {
  id: string;
  kind: "device" | "fraud";
  title: string;
  severity: Severity;
  at: string;
  source: string;
  device?: SecurityEvent;
  risk?: RiskEventRow;
}

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_DOT: Record<Severity, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-ink-400",
};

type Filter = "all" | "unread" | "urgent" | "fraud";

/** Read marks are a per-viewer convenience kept in this browser; the alerts
 *  themselves are the backend's DETECTED events and flagged risk events. */
const READ_KEY = "rasp:inbox:read";

function loadRead(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(READ_KEY) ?? "[]"));
  } catch {
    return new Set();
  }
}

function saveRead(ids: Set<string>) {
  try {
    localStorage.setItem(READ_KEY, JSON.stringify([...ids].slice(-2000)));
  } catch {
    /* ignore */
  }
}

export default function AlertsInboxPage() {
  const { selectedAppId, selectedApp } = useAppSelection();
  const base = selectedAppId ? `/v1/dashboard/applications/${selectedAppId}` : null;
  const events = usePolled<{ events: SecurityEvent[] }>(base && `${base}/events?status=DETECTED&limit=100`);
  const risk = usePolled<{ events: RiskEventRow[] }>(base && `${base}/risk-events?onlyFlagged=true&limit=50`);
  const [read, setRead] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<Filter>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => setRead(loadRead()), []);

  const items = useMemo<InboxItem[]>(() => {
    const device: InboxItem[] = (events.data?.events ?? []).map((e) => {
      const cat = catalogFor(e.detectorId);
      return {
        id: `d:${e.id}`,
        kind: "device",
        title: cat.title,
        severity: cat.severity,
        at: e.receivedAt,
        source: [e.manufacturer, e.deviceModel].filter(Boolean).join(" ") || "Unknown device",
        device: e,
      };
    });
    const fraud: InboxItem[] = (risk.data?.events ?? []).map((r) => {
      const top = [...r.rules].sort((a, b) => (a.severity === "high" ? -1 : b.severity === "high" ? 1 : 0))[0];
      return {
        id: `r:${r.id}`,
        kind: "fraud",
        title: top ? catalogFor(top.rule).title : "Flagged risk event",
        severity: (top?.severity as Severity) ?? "medium",
        at: r.receivedAt,
        source: `${r.type === "session" ? "Session" : "Transaction"} · account ${r.accountHash}…`,
        risk: r,
      };
    });
    return [...device, ...fraud].sort((a, b) => b.at.localeCompare(a.at));
  }, [events.data, risk.data]);

  const counts = {
    all: items.length,
    unread: items.filter((i) => !read.has(i.id)).length,
    urgent: items.filter((i) => SEV_RANK[i.severity] <= 1).length,
    fraud: items.filter((i) => i.kind === "fraud").length,
  };

  const shown = items.filter((i) =>
    filter === "unread" ? !read.has(i.id) : filter === "urgent" ? SEV_RANK[i.severity] <= 1 : filter === "fraud" ? i.kind === "fraud" : true,
  );
  const selected = items.find((i) => i.id === selectedId) ?? shown[0] ?? null;

  function markRead(ids: string[]) {
    const next = new Set(read);
    ids.forEach((id) => next.add(id));
    setRead(next);
    saveRead(next);
  }

  function open(item: InboxItem) {
    setSelectedId(item.id);
    if (!read.has(item.id)) markRead([item.id]);
  }

  return (
    <div>
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink-900">Alerts Inbox</h1>
          <p className="mt-1 text-sm text-ink-500">
            Every threat a device reported and every flagged fraud event for {selectedApp?.name ?? "this app"}, in one queue.
          </p>
        </div>
        <button
          onClick={() => markRead(items.map((i) => i.id))}
          disabled={counts.unread === 0}
          className="rounded-lg border border-ink-200 px-3 py-1.5 text-xs font-medium text-ink-700 hover:bg-ink-50 disabled:opacity-40"
        >
          Mark all as read
        </button>
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        {(
          [
            ["all", "All"],
            ["unread", "Unread"],
            ["urgent", "Critical & high"],
            ["fraud", "Fraud"],
          ] as [Filter, string][]
        ).map(([f, label]) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`rounded-full px-3 py-1.5 text-xs font-medium transition ${
              filter === f ? "bg-brand-500 text-black" : "bg-ink-100 text-ink-600 hover:bg-ink-200"
            }`}
          >
            {label} <span className="opacity-60">{counts[f]}</span>
          </button>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,22rem)_1fr]">
        <Card className="max-h-[70vh] overflow-y-auto">
          {events.loading || risk.loading ? (
            <div className="p-6 text-sm text-ink-400">Loading alerts…</div>
          ) : shown.length === 0 ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center text-sm text-ink-400">
              <CheckCircleIcon size={22} className="text-emerald-500" />
              Inbox zero — nothing here.
            </div>
          ) : (
            <ul className="divide-y divide-ink-100">
              {shown.map((i) => {
                const unread = !read.has(i.id);
                const active = selected?.id === i.id;
                return (
                  <li key={i.id}>
                    <button
                      onClick={() => open(i)}
                      className={`flex w-full gap-3 px-4 py-3 text-left transition ${active ? "bg-brand-50" : "hover:bg-ink-50"}`}
                    >
                      <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${SEV_DOT[i.severity]}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className={`truncate text-sm ${unread ? "font-semibold text-ink-900" : "text-ink-600"}`}>{i.title}</span>
                          <span className="shrink-0 text-[11px] text-ink-400">{timeAgo(i.at)}</span>
                        </div>
                        <div className="mt-0.5 flex items-center gap-1.5 truncate text-xs text-ink-400">
                          {i.kind === "fraud" ? <MailIcon size={11} /> : <SmartphoneIcon size={11} />}
                          {i.source}
                        </div>
                      </div>
                      {unread && <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-500" />}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card className="p-6">{selected ? <Detail item={selected} /> : <p className="text-sm text-ink-400">Select an alert.</p>}</Card>
      </div>
    </div>
  );
}

function Detail({ item }: { item: InboxItem }) {
  const sevTone = SEV_RANK[item.severity] <= 1 ? "red" : item.severity === "medium" ? "amber" : "slate";
  if (item.device) {
    const e = item.device;
    const cat = catalogFor(e.detectorId);
    const colors = CATEGORY_COLORS[cat.category];
    return (
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={sevTone}>{item.severity}</Badge>
          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${colors.bg} ${colors.text}`}>{cat.category}</span>
          <span className="font-mono text-xs text-ink-400">{e.detectorId}</span>
        </div>
        <h2 className="mt-3 text-xl font-semibold text-ink-900">{cat.title}</h2>
        <p className="mt-2 text-sm leading-relaxed text-ink-600">{cat.description}</p>
        {e.reason && <p className="mt-2 text-sm text-ink-500">Reason: {e.reason}</p>}
        <dl className="mt-5 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
          <Fact label="Device" value={item.source} />
          <Fact label="OS" value={e.osPlatform ? `${e.osPlatform} ${e.osVersion ?? ""}` : "—"} />
          <Fact label="App version" value={e.appVersion ?? "—"} />
          <Fact label="Received" value={new Date(e.receivedAt).toLocaleString()} />
        </dl>
        {e.evidence && e.evidence.length > 0 && (
          <div className="mt-5">
            <div className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-400">Evidence</div>
            <div className="rounded-lg bg-ink-50 p-3 font-mono text-xs text-ink-700">
              {e.evidence.slice(0, 12).map((ev, idx) => (
                <div key={idx}>
                  {ev.key}: {String(ev.value)}
                </div>
              ))}
            </div>
          </div>
        )}
        <div className="mt-6 flex flex-wrap gap-2">
          <Link href="/devices" className="rounded-lg bg-brand-600 px-3 py-2 text-xs font-medium text-white hover:bg-brand-700">
            Open in Devices
          </Link>
          <Link href={`/capabilities/${e.detectorId.replace(/_/g, "-")}`} className="rounded-lg border border-ink-200 px-3 py-2 text-xs font-medium text-ink-700 hover:bg-ink-50">
            How this detector works
          </Link>
        </div>
      </div>
    );
  }
  const r = item.risk!;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={sevTone}>{item.severity}</Badge>
        <span className="rounded-full bg-rose-50 px-2.5 py-0.5 text-xs font-medium text-rose-700">Fraud Risk</span>
        <span className="text-xs text-ink-400">Verdict {r.riskVerdict.toLowerCase()}{r.riskScore !== null ? ` · ${r.riskScore}` : ""}</span>
      </div>
      <h2 className="mt-3 text-xl font-semibold text-ink-900">{item.title}</h2>
      <div className="mt-4 space-y-2">
        {r.rules.map((rule) => (
          <div key={rule.rule} className="flex gap-3 rounded-lg border border-ink-100 p-3">
            <AlertTriangleIcon size={15} className={rule.severity === "high" ? "text-red-500" : "text-amber-500"} />
            <div>
              <div className="text-sm font-medium text-ink-900">{catalogFor(rule.rule).title}</div>
              <div className="text-xs leading-relaxed text-ink-500">{rule.explanation}</div>
            </div>
          </div>
        ))}
      </div>
      <dl className="mt-5 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <Fact label="Event" value={r.type === "session" ? `Session · ${r.sessionEvent ?? ""}` : `Transaction · ${r.channel ?? ""}`} />
        <Fact label="Account" value={`${r.accountHash}…`} />
        <Fact label="Device key" value={`${r.deviceKeyId}…`} />
        <Fact label="IP country" value={r.ipCountry ?? "unknown"} />
      </dl>
      <div className="mt-6 flex flex-wrap gap-2">
        <Link href="/threats" className="rounded-lg bg-brand-600 px-3 py-2 text-xs font-medium text-white hover:bg-brand-700">
          View Live Threats
        </Link>
        <Link href="/security-settings" className="rounded-lg border border-ink-200 px-3 py-2 text-xs font-medium text-ink-700 hover:bg-ink-50">
          Review security settings
        </Link>
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] font-medium uppercase tracking-wide text-ink-400">{label}</dt>
      <dd className="mt-0.5 truncate text-ink-800" title={value}>{value}</dd>
    </div>
  );
}
