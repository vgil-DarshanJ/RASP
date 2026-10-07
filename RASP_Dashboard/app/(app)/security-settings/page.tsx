"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api-client";
import { useAppSelection } from "@/lib/app-selection";
import { Badge, Button, Card, Input, Label } from "@/components/ui";

type RuleKey = "deviceChangeVelocity" | "concurrentSessions" | "impossibleTravel" | "transactionVelocity";
type RiskRules = Record<RuleKey, Record<string, number>>;
type RuleLimits = Record<RuleKey, Record<string, [number, number]>>;

interface SecuritySettingsResponse {
  settings: {
    expectedSigningCertSha256: string | null;
    ipBlockedCountries: string[];
    ipAllowedCountries: string[];
    riskRules: RiskRules;
  };
  riskRuleDefaults: RiskRules;
  riskRuleLimits: RuleLimits;
  canEdit: boolean;
}

interface AuditLog {
  id: string;
  action: string;
  field: string | null;
  oldValue: unknown;
  newValue: unknown;
  performedAt: string;
  performedByEmail: string | null;
}

/** Labels and help for each threshold — what the rule does with it. */
const RULES: { key: RuleKey; title: string; help: string; fields: { key: string; label: string; unit: string }[] }[] = [
  {
    key: "deviceChangeVelocity",
    title: "Device change velocity",
    help: "Alert (high) when an account is used from more new devices than this within the window.",
    fields: [
      { key: "maxDevices", label: "Max new devices", unit: "devices" },
      { key: "windowMinutes", label: "Window", unit: "minutes" },
    ],
  },
  {
    key: "concurrentSessions",
    title: "Concurrent sessions",
    help: "Alert (medium) when an account has active sessions (login/resume without logout) on more devices than this within the window.",
    fields: [
      { key: "maxDevices", label: "Max devices", unit: "devices" },
      { key: "windowMinutes", label: "Window", unit: "minutes" },
    ],
  },
  {
    key: "impossibleTravel",
    title: "Impossible travel",
    help: "Alert (high) when two opted-in locations of an account imply a speed above the limit — only if they are at least the minimum time and distance apart. Without locations: a request-IP country change within the IP window (weaker: VPNs and roaming also cause it; 0 turns it off).",
    fields: [
      { key: "maxSpeedKmh", label: "Max speed", unit: "km/h" },
      { key: "minMinutes", label: "Min time apart", unit: "minutes" },
      { key: "minDistanceKm", label: "Min distance", unit: "km" },
      { key: "ipCountryChangeMinutes", label: "IP country window", unit: "minutes" },
    ],
  },
  {
    key: "transactionVelocity",
    title: "Transaction velocity",
    help: "Alert (high) when an account makes more transactions than this within the window. Amounts are never sent.",
    fields: [
      { key: "maxCount", label: "Max transactions", unit: "transactions" },
      { key: "windowMinutes", label: "Window", unit: "minutes" },
    ],
  },
];

const HASH_RE = /^[0-9a-fA-F]{64}$/;
const COUNTRY_RE = /^[A-Za-z]{2}$/;

function parseCountries(text: string): string[] {
  return text.split(/[\s,]+/).map((c) => c.trim()).filter(Boolean);
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const body = err.body as { error?: string; details?: { invalid?: string[] } } | null;
    if (err.status === 403) return "Only owners and admins can change security settings.";
    if (err.status === 429) return "Too many requests — try again in a minute.";
    if (body?.error === "INVALID_COUNTRY_CODE") return `Invalid country code: ${body.details?.invalid?.join(", ")}`;
    if (body?.error === "INVALID_SIGNING_CERT") return "The signing certificate hash must be 64 hex characters.";
    if (body?.error) return `Rejected by the server: ${body.error}`;
  }
  return "Could not save the settings.";
}

function short(value: unknown): string {
  if (value === null || value === undefined) return "—";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > 160 ? `${text.slice(0, 160)}…` : text;
}

/**
 * Per-application security settings: expected signing certificate, IP
 * country lists and the fraud-risk rule thresholds. Everyone can read;
 * OWNER/ADMIN can change (checked again by the backend, which validates
 * the same ranges and audits every change).
 */
export default function SecuritySettingsPage() {
  const { selectedAppId, selectedApp, loading: appsLoading, apps } = useAppSelection();
  const [data, setData] = useState<SecuritySettingsResponse | null>(null);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [cert, setCert] = useState("");
  const [blocked, setBlocked] = useState("");
  const [allowed, setAllowed] = useState("");
  const [rules, setRules] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!selectedAppId) return;
    setLoadError(null);
    try {
      const [settings, audit] = await Promise.all([
        apiFetch<SecuritySettingsResponse>(`/v1/apps/${selectedAppId}/security-settings`),
        apiFetch<{ logs: AuditLog[] }>(`/v1/apps/${selectedAppId}/settings-audit`),
      ]);
      setData(settings);
      setLogs(audit.logs);
      setCert(settings.settings.expectedSigningCertSha256 ?? "");
      setBlocked(settings.settings.ipBlockedCountries.join(", "));
      setAllowed(settings.settings.ipAllowedCountries.join(", "));
      const flat: Record<string, string> = {};
      for (const rule of RULES) {
        for (const f of rule.fields) flat[`${rule.key}.${f.key}`] = String(settings.settings.riskRules[rule.key][f.key]);
      }
      setRules(flat);
    } catch (err) {
      setLoadError(err instanceof ApiError && err.status === 404 ? "Application not found." : "Could not load the settings.");
    }
  }, [selectedAppId]);

  useEffect(() => {
    setData(null);
    setSaved(null);
    setSaveError(null);
    load();
  }, [load]);

  /** Client-side checks — the same rules the backend applies. */
  const errors = useMemo(() => {
    const out: Record<string, string> = {};
    if (!data) return out;
    const compactCert = cert.replace(/[:\s]/g, "");
    if (compactCert !== "" && !HASH_RE.test(compactCert)) out.cert = "64 hex characters (':' separators allowed), or empty.";
    for (const [key, text] of [["blocked", blocked], ["allowed", allowed]] as const) {
      const bad = parseCountries(text).filter((c) => !COUNTRY_RE.test(c));
      if (bad.length > 0) out[key] = `Not a two-letter country code: ${bad.join(", ")}`;
    }
    for (const rule of RULES) {
      for (const f of rule.fields) {
        const id = `${rule.key}.${f.key}`;
        const [min, max] = data.riskRuleLimits[rule.key][f.key];
        const value = Number(rules[id]);
        if (rules[id] === undefined || rules[id].trim() === "" || !Number.isInteger(value) || value < min || value > max) {
          out[id] = `Whole number from ${min} to ${max}`;
        }
      }
    }
    return out;
  }, [data, cert, blocked, allowed, rules]);

  async function patch(body: Record<string, unknown>, message: string) {
    if (!selectedAppId) return;
    setSaving(true);
    setSaveError(null);
    setSaved(null);
    try {
      await apiFetch(`/v1/apps/${selectedAppId}`, { method: "PATCH", body: JSON.stringify(body) });
      setSaved(message);
      await load();
    } catch (err) {
      setSaveError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  function save() {
    if (!data || Object.keys(errors).length > 0) return;
    const current = data.settings;
    const body: Record<string, unknown> = {};
    const compactCert = cert.replace(/[:\s]/g, "").toUpperCase();
    if (compactCert !== (current.expectedSigningCertSha256 ?? "")) body.expectedSigningCertSha256 = compactCert === "" ? null : compactCert;
    const blockedList = parseCountries(blocked).map((c) => c.toUpperCase());
    const allowedList = parseCountries(allowed).map((c) => c.toUpperCase());
    if (blockedList.join(",") !== current.ipBlockedCountries.join(",")) body.ipBlockedCountries = blockedList;
    if (allowedList.join(",") !== current.ipAllowedCountries.join(",")) body.ipAllowedCountries = allowedList;
    const riskRules: Record<string, Record<string, number>> = {};
    for (const rule of RULES) {
      for (const f of rule.fields) {
        const value = Number(rules[`${rule.key}.${f.key}`]);
        if (value !== current.riskRules[rule.key][f.key]) (riskRules[rule.key] ??= {})[f.key] = value;
      }
    }
    if (Object.keys(riskRules).length > 0) body.riskRules = riskRules;
    if (Object.keys(body).length === 0) {
      setSaved("Nothing changed.");
      return;
    }
    patch(body, "Saved. The change is in the audit log below.");
  }

  if (appsLoading) return <div className="h-72 animate-pulse rounded-2xl bg-ink-100" />;
  if (apps.length === 0) {
    return (
      <Card className="p-10 text-center">
        <p className="text-sm text-ink-500">No applications registered yet.</p>
      </Card>
    );
  }

  const canEdit = data?.canEdit ?? false;
  const disabled = !canEdit || saving;

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink-900">Security Settings</h1>
        <p className="mt-1 text-sm text-ink-500">
          {selectedApp?.name} · signing certificate, IP country policy and fraud-risk rule thresholds
        </p>
      </div>

      {loadError && <Card className="mb-6 p-5 text-sm text-red-600">{loadError}</Card>}
      {!data && !loadError && <div className="h-72 animate-pulse rounded-2xl bg-ink-100" />}

      {data && (
        <>
          {!canEdit && (
            <Card className="mb-6 p-4 text-sm text-ink-600">
              <Badge tone="slate">read only</Badge> Only owners and admins can change these settings.
            </Card>
          )}

          <Card className="mb-6 p-6">
            <h2 className="mb-4 text-sm font-semibold text-ink-700">App integrity and IP policy</h2>
            <div className="grid gap-5 md:grid-cols-2">
              <div className="md:col-span-2">
                <Label>Expected signing certificate SHA-256</Label>
                <Input value={cert} onChange={(e) => setCert(e.target.value)} disabled={disabled} maxLength={200}
                  placeholder="64 hex characters; empty = not checked" className="font-mono text-xs" />
                {errors.cert && <p className="mt-1 text-xs text-red-600">{errors.cert}</p>}
                <p className="mt-1 text-xs text-ink-400">A tamper result reporting another certificate raises “Signing certificate mismatch” (high).</p>
              </div>
              <div>
                <Label>Blocked countries</Label>
                <Input value={blocked} onChange={(e) => setBlocked(e.target.value)} disabled={disabled} maxLength={1000} placeholder="e.g. KP, IR — empty = server default" />
                {errors.blocked && <p className="mt-1 text-xs text-red-600">{errors.blocked}</p>}
              </div>
              <div>
                <Label>Allowed countries</Label>
                <Input value={allowed} onChange={(e) => setAllowed(e.target.value)} disabled={disabled} maxLength={1000} placeholder="e.g. IN — empty = no allow-list" />
                {errors.allowed && <p className="mt-1 text-xs text-red-600">{errors.allowed}</p>}
              </div>
            </div>
          </Card>

          <Card className="mb-6 p-6">
            <div className="mb-1 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-ink-700">Fraud-risk rule thresholds</h2>
              {canEdit && (
                <Button size="sm" variant="ghost" disabled={saving}
                  onClick={() => patch({ riskRules: null }, "Rule thresholds reset to the defaults.")}>
                  Reset to defaults
                </Button>
              )}
            </div>
            <p className="mb-5 text-xs text-ink-400">
              Simple rules over the hashed session and transaction events your app sends — no machine learning. They flag
              patterns worth a look; they do not stop all fraud, and an app that sends no events is not evaluated.
            </p>
            <div className="space-y-6">
              {RULES.map((rule) => (
                <div key={rule.key}>
                  <h3 className="text-sm font-medium text-ink-800">{rule.title}</h3>
                  <p className="mb-2 text-xs text-ink-500">{rule.help}</p>
                  <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                    {rule.fields.map((f) => {
                      const id = `${rule.key}.${f.key}`;
                      const [min, max] = data.riskRuleLimits[rule.key][f.key];
                      return (
                        <div key={id}>
                          <Label>{f.label}</Label>
                          <Input type="number" min={min} max={max} step={1} value={rules[id] ?? ""} disabled={disabled}
                            onChange={(e) => setRules((prev) => ({ ...prev, [id]: e.target.value }))} />
                          <p className={`mt-1 text-[11px] ${errors[id] ? "text-red-600" : "text-ink-400"}`}>
                            {errors[id] ?? `${f.unit} · default ${data.riskRuleDefaults[rule.key][f.key]} · ${min}–${max}`}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {canEdit && (
            <div className="mb-8 flex items-center gap-3">
              <Button onClick={save} loading={saving} disabled={Object.keys(errors).length > 0}>Save changes</Button>
              {saved && <span className="text-sm text-emerald-700">{saved}</span>}
              {saveError && <span className="text-sm text-red-600">{saveError}</span>}
            </div>
          )}

          <Card className="overflow-hidden">
            <div className="border-b border-ink-100 px-5 py-3">
              <h2 className="text-sm font-semibold text-ink-700">Settings audit log</h2>
            </div>
            {logs.length === 0 ? (
              <p className="px-5 py-6 text-sm text-ink-400">No changes recorded yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                      <th className="py-2.5 pl-5 pr-4 font-medium">When</th>
                      <th className="py-2.5 pr-4 font-medium">Who</th>
                      <th className="py-2.5 pr-4 font-medium">What</th>
                      <th className="py-2.5 pr-5 font-medium">Old → new</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((l) => (
                      <tr key={l.id} className="border-b border-ink-50 align-top">
                        <td className="py-2.5 pl-5 pr-4 text-ink-500">{new Date(l.performedAt).toLocaleString()}</td>
                        <td className="py-2.5 pr-4 text-ink-700">{l.performedByEmail ?? "—"}</td>
                        <td className="py-2.5 pr-4">
                          <div className="font-mono text-xs text-ink-800">{l.field ?? "—"}</div>
                          <div className="text-[11px] text-ink-400">{l.action}</div>
                        </td>
                        <td className="max-w-xl py-2.5 pr-5 font-mono text-[11px] text-ink-600">
                          {l.action === "SETTINGS_UPDATED" ? `${short(l.oldValue)} → ${short(l.newValue)}` : "value not recorded"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
