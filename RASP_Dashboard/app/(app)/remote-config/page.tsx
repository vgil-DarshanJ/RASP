"use client";

import { useCallback, useEffect, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api-client";
import { useAppSelection } from "@/lib/app-selection";
import { Badge, Button, Card, Input, Label, LayersIcon } from "@/components/ui";

type Settings = Record<string, unknown>;

interface Version {
  version: number;
  settings: Settings;
  active: boolean;
  expired: boolean;
  createdAt: string;
  expiresAt: string;
  createdByEmail: string;
  copiedFromVersion: number | null;
}

interface AuditRow {
  id: string;
  action: "PUBLISHED" | "ROLLED_BACK";
  version: number;
  fromVersion: number | null;
  performedAt: string;
  performedByEmail: string;
}

interface RemoteConfigView {
  signingConfigured: boolean;
  keyId: string | null;
  current: Version | null;
  history: Version[];
  audit: AuditRow[];
  limits: {
    fields: string[];
    detectors: string[];
    bounds: { expiresInDays: { min: number; max: number; default: number } } & Record<string, unknown>;
    neverRemote: string[];
  };
}

/** Plain wording for the backend's error codes. */
function errorText(err: unknown): string {
  if (err instanceof ApiError) {
    const code = (err.body as { error?: string } | null)?.error;
    if (code === "REMOTE_CONFIG_SIGNING_UNAVAILABLE") return "The server has no CONFIG_SIGNING_KEY, so nothing can be signed.";
    if (code === "INVALID_REMOTE_CONFIG") return "The settings are not valid: check the field names and bounds below.";
    if (code === "REMOTE_CONFIG_VERSION_CONFLICT") return "Someone published at the same time. Reload and try again.";
    if (err.status === 403) return "Only an owner or admin can publish a remote config.";
    return code ?? `Request failed (HTTP ${err.status})`;
  }
  return "Request failed";
}

/**
 * Signed remote configuration for the selected application —
 * `GET/PUT /v1/apps/:id/remote-config` and `POST …/rollback`. Each publish
 * is a new, higher version, signed with the server's Ed25519 key; phones
 * pick it up through `GET /v1/config` and report `remote_config_rejected`
 * when one does not verify. Publishing `{}` sends every phone back to the
 * app's own settings.
 */
export default function RemoteConfigPage() {
  const { selectedApp } = useAppSelection();
  const [view, setView] = useState<RemoteConfigView | null>(null);
  const [draft, setDraft] = useState("{}");
  const [days, setDays] = useState("30");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    if (!selectedApp) return;
    const res = await apiFetch<RemoteConfigView>(`/v1/apps/${selectedApp.id}/remote-config`);
    setView(res);
    setDraft(JSON.stringify(res.current?.settings ?? {}, null, 2));
  }, [selectedApp]);

  useEffect(() => {
    setView(null);
    setMessage(null);
    load().catch((err) => setMessage({ ok: false, text: errorText(err) }));
  }, [load]);

  async function publish() {
    if (!selectedApp) return;
    let settings: Settings;
    try {
      settings = JSON.parse(draft);
    } catch {
      setMessage({ ok: false, text: "The settings are not valid JSON." });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const res = await apiFetch<{ version: number }>(`/v1/apps/${selectedApp.id}/remote-config`, {
        method: "PUT",
        body: JSON.stringify({ settings, expiresInDays: Number(days) }),
      });
      setMessage({ ok: true, text: `Published version ${res.version}. Phones pick it up on their next config check.` });
      await load();
    } catch (err) {
      setMessage({ ok: false, text: errorText(err) });
    } finally {
      setBusy(false);
    }
  }

  async function rollback(version: number) {
    if (!selectedApp) return;
    setBusy(true);
    setMessage(null);
    try {
      const res = await apiFetch<{ version: number }>(`/v1/apps/${selectedApp.id}/remote-config/rollback`, {
        method: "POST",
        body: JSON.stringify({ version, expiresInDays: Number(days) }),
      });
      setMessage({ ok: true, text: `Version ${version} published again as version ${res.version}.` });
      await load();
    } catch (err) {
      setMessage({ ok: false, text: errorText(err) });
    } finally {
      setBusy(false);
    }
  }

  if (!selectedApp) {
    return (
      <Card className="p-10 text-center">
        <p className="text-sm text-ink-400">Create an application first.</p>
      </Card>
    );
  }

  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold text-ink-900">Remote Config</h1>
      <p className="mb-6 text-sm text-ink-500">
        Signed settings for <span className="font-medium text-ink-700">{selectedApp.name}</span>, applied by its phones without an app update.
      </p>

      {message && (
        <Card className={`mb-4 p-4 text-sm ${message.ok ? "text-green-700" : "text-red-700"}`}>{message.text}</Card>
      )}

      {view === null ? (
        <div className="h-64 animate-pulse rounded-2xl bg-ink-100" />
      ) : (
        <div className="space-y-6">
          <Card className="p-5">
            <div className="flex flex-wrap items-center gap-3">
              <LayersIcon size={18} className="text-ink-400" />
              {view.signingConfigured ? (
                <Badge tone="green">Signing key configured{view.keyId ? ` · key ${view.keyId}` : ""}</Badge>
              ) : (
                <Badge tone="red">No CONFIG_SIGNING_KEY on the server</Badge>
              )}
              {view.current ? (
                <Badge tone={view.current.expired ? "amber" : "green"} icon={false}>
                  Version {view.current.version} {view.current.expired ? "expired" : "active"} until {new Date(view.current.expiresAt).toLocaleDateString()}
                </Badge>
              ) : (
                <Badge tone="slate" icon={false}>Nothing published yet</Badge>
              )}
            </div>
            {!view.signingConfigured && (
              <p className="mt-3 text-sm text-ink-500">
                Run <code>npm run config:keygen</code> on the server, put the private key in <code>CONFIG_SIGNING_KEY</code>, restart the backend, then copy the
                app&apos;s credential again so phones receive <code>config_public_key</code>.
              </p>
            )}
          </Card>

          <Card className="p-5">
            <h2 className="mb-3 text-sm font-semibold text-ink-900">Publish a new version</h2>
            <Label>Settings (JSON)</Label>
            <textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              rows={10}
              spellCheck={false}
              className="mb-3 w-full rounded-xl border border-ink-200 bg-white p-3 font-mono text-xs text-ink-900 dark:bg-ink-50"
            />
            <div className="mb-3 flex flex-wrap items-end gap-3">
              <div className="w-40">
                <Label>Expires in (days)</Label>
                <Input type="number" min={view.limits.bounds.expiresInDays.min} max={view.limits.bounds.expiresInDays.max} value={days} onChange={(e) => setDays(e.target.value)} />
              </div>
              <Button onClick={publish} disabled={busy || !view.signingConfigured}>Publish</Button>
              <Button variant="secondary" onClick={() => setDraft("{}")} disabled={busy}>
                Reset to {"{}"} (app&apos;s own settings)
              </Button>
            </div>
            <p className="text-xs text-ink-500">
              Fields: {view.limits.fields.join(", ")}. Example: <code>{`{"detectors": {"vpn": true}, "pollIntervalSeconds": 4}`}</code>.
              Detectors that can be switched remotely: {view.limits.detectors.join(", ")}.
            </p>
            <p className="mt-2 text-xs text-ink-500">Never remote: {view.limits.neverRemote.join("; ")}.</p>
          </Card>

          <Card className="overflow-hidden">
            <h2 className="px-5 pt-5 text-sm font-semibold text-ink-900">History</h2>
            {view.history.length === 0 ? (
              <p className="p-5 text-sm text-ink-400">No versions yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="mt-3 w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                      <th className="py-2.5 pl-5 pr-4 font-medium">Version</th>
                      <th className="py-2.5 pr-4 font-medium">Published</th>
                      <th className="py-2.5 pr-4 font-medium">By</th>
                      <th className="py-2.5 pr-4 font-medium">Settings</th>
                      <th className="py-2.5 pr-5 font-medium" />
                    </tr>
                  </thead>
                  <tbody>
                    {view.history.map((v) => (
                      <tr key={v.version} className="border-b border-ink-50 align-top">
                        <td className="py-2.5 pl-5 pr-4 font-medium text-ink-900">
                          {v.version}{" "}
                          {v.active && <Badge tone={v.expired ? "amber" : "green"} icon={false}>{v.expired ? "expired" : "active"}</Badge>}
                          {v.copiedFromVersion !== null && <span className="block text-xs text-ink-400">copy of {v.copiedFromVersion}</span>}
                        </td>
                        <td className="py-2.5 pr-4 text-ink-500">{new Date(v.createdAt).toLocaleString()}</td>
                        <td className="py-2.5 pr-4 text-ink-600">{v.createdByEmail}</td>
                        <td className="py-2.5 pr-4 font-mono text-xs text-ink-600">{JSON.stringify(v.settings)}</td>
                        <td className="py-2.5 pr-5">
                          {!v.active && (
                            <Button size="sm" variant="ghost" onClick={() => rollback(v.version)} disabled={busy || !view.signingConfigured}>
                              Publish again
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
