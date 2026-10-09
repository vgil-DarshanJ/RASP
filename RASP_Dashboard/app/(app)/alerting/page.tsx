"use client";

import { useEffect, useState } from "react";
import { webhookErrorMessage } from "@/lib/webhookErrors";
import { apiFetch } from "@/lib/api-client";
import {
  BellIcon,
  Button,
  Card,
  CheckCircleIcon,
  CopyButton,
  Input,
  Label,
} from "@/components/ui";
import { useAppSelection } from "@/lib/app-selection";

interface WebhookConfig {
  id: string;
  url: string;
  minSeverity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  lastTriggeredAt: string | null;
  lastStatusCode: number | null;
  lastError: string | null;
}

/**
 * Outbound alert policy — "call this URL when a DETECTED event meets or
 * exceeds this severity." One config per application, delivered via
 * `POST /v1/webhooks/applications/:id` (see BE `webhooks/routes.ts` +
 * `webhooks/dispatch.ts`), fired from the ingestion path itself and never
 * able to affect its response — a slow/unreachable customer endpoint
 * can't add latency to the SDK's own calls. A configurable
 * threat-response action, kept intentionally simple here: alert-only (no in-app block decision is
 * made server-side).
 */
export default function AlertingPage() {
  const { apps, selectedAppId, loading: appsLoading } = useAppSelection();
  const [config, setConfig] = useState<WebhookConfig | null>(null);

  const [url, setUrl] = useState("");
  const [minSeverity, setMinSeverity] = useState<WebhookConfig["minSeverity"]>("HIGH");
  const [enabled, setEnabled] = useState(true);

  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadConfig(appId: string) {
    const res = await apiFetch<{ webhook: WebhookConfig | null }>(`/v1/webhooks/applications/${appId}`);
    setConfig(res.webhook);
    setUrl(res.webhook?.url ?? "");
    setMinSeverity(res.webhook?.minSeverity ?? "HIGH");
    setEnabled(res.webhook?.enabled ?? true);
    setRevealedSecret(null);
  }

  useEffect(() => {
    if (selectedAppId) loadConfig(selectedAppId);
  }, [selectedAppId]);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedAppId) return;
    setSaving(true);
    setError(null);
    try {
      const res = await apiFetch<{ webhook: WebhookConfig; secret: string | null }>(
        `/v1/webhooks/applications/${selectedAppId}`,
        { method: "PUT", body: JSON.stringify({ url, minSeverity, enabled }) },
      );
      setConfig(res.webhook);
      if (res.secret) setRevealedSecret(res.secret);
    } catch (err: any) {
      setError(webhookErrorMessage(err?.body?.error, "Failed to save webhook configuration"));
    } finally {
      setSaving(false);
    }
  }

  async function handleRotate() {
    if (!selectedAppId) return;
    if (!confirm("Rotate the webhook signing secret? Any endpoint verifying the old signature will start rejecting deliveries until updated.")) return;
    setRotating(true);
    setError(null);
    try {
      const res = await apiFetch<{ webhook: WebhookConfig; secret: string }>(
        `/v1/webhooks/applications/${selectedAppId}/rotate-secret`,
        { method: "POST" },
      );
      setConfig(res.webhook);
      setRevealedSecret(res.secret);
    } catch (err: any) {
      setError(webhookErrorMessage(err?.body?.error, "Failed to rotate the signing secret"));
    } finally {
      setRotating(false);
    }
  }

  async function handleTest() {
    if (!selectedAppId) return;
    setTesting(true);
    setError(null);
    try {
      const res = await apiFetch<{ webhook: WebhookConfig | null }>(
        `/v1/webhooks/applications/${selectedAppId}/test`,
        { method: "POST" },
      );
      setConfig(res.webhook);
    } catch (err: any) {
      setError(webhookErrorMessage(err?.body?.error, "Failed to send the test alert"));
    } finally {
      setTesting(false);
    }
  }

  async function handleDelete() {
    if (!selectedAppId) return;
    if (!confirm("Remove this webhook configuration? Alerts will stop being sent for this application.")) return;
    try {
      await apiFetch(`/v1/webhooks/applications/${selectedAppId}`, { method: "DELETE" });
    } catch (err: any) {
      setError(webhookErrorMessage(err?.body?.error, "Failed to remove the webhook"));
      return;
    }
    setConfig(null);
    setUrl("");
    setEnabled(true);
    setMinSeverity("HIGH");
  }

  const selectedApp = apps.find((a) => a.id === selectedAppId);

  if (appsLoading) return <AlertingSkeleton />;

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
        <h1 className="text-2xl font-semibold text-ink-900">Alerting</h1>
        <p className="mt-1 text-sm text-ink-500">
          Send a webhook the moment a threat is detected · {selectedApp?.name}
        </p>
      </div>

      {revealedSecret && (
        <Card className="mb-6 overflow-hidden border-brand-200">
          <div className="flex items-center justify-between bg-brand-50 px-6 py-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-brand-800">
              <CheckCircleIcon size={16} />
              Save this signing secret now
            </h2>
            <button className="text-sm text-brand-700 hover:underline" onClick={() => setRevealedSecret(null)}>
              Dismiss
            </button>
          </div>
          <div className="p-6">
            <p className="mb-4 text-sm text-ink-600">
              This secret signs every webhook delivery: <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">X-Webhook-Signature: v1=…</code>{" "}
              is HMAC-SHA256 over <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">&lt;X-Webhook-Timestamp&gt;.&lt;raw JSON body&gt;</code>.
              On your endpoint, recompute it, compare in constant time, reject timestamps older than 5 minutes, and ignore a repeated{" "}
              <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">X-Webhook-Id</code> (failed deliveries are retried up to 3 times). Shown{" "}
              <strong>once</strong>; if lost, rotate to get a new one.
            </p>
            <div className="relative flex items-center gap-2 rounded-xl bg-ink-950 p-4">
              <pre className="flex-1 overflow-x-auto font-mono text-xs text-ink-100">{revealedSecret}</pre>
              <CopyButton value={revealedSecret} />
            </div>
          </div>
        </Card>
      )}

      <Card className="mb-6 p-6">
        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <Label>Webhook URL</Label>
            <Input
              type="url"
              required
              placeholder="https://your-service.example.com/rasp-alerts"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <Label>Minimum severity to alert on</Label>
              <select
                value={minSeverity}
                onChange={(e) => setMinSeverity(e.target.value as WebhookConfig["minSeverity"])}
                className="w-full rounded-lg border border-ink-200 bg-surface px-3 py-2.5 text-sm text-ink-900 outline-none focus:border-brand-500 focus:ring-4 focus:ring-brand-100"
              >
                <option value="LOW">Low and above — every DETECTED finding</option>
                <option value="MEDIUM">Medium and above</option>
                <option value="HIGH">High and above (recommended)</option>
                <option value="CRITICAL">Critical only</option>
              </select>
            </div>
            <div className="flex items-end pb-1">
              <label className="flex items-center gap-2 text-sm font-medium text-ink-700">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-ink-300 text-brand-600 focus:ring-brand-500"
                />
                Enabled
              </label>
            </div>
          </div>

          {error && <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

          <div className="flex flex-wrap gap-3">
            <Button type="submit" loading={saving}>
              {config ? "Save changes" : "Create webhook"}
            </Button>
            {config && (
              <>
                <Button type="button" variant="secondary" loading={testing} onClick={handleTest}>
                  <BellIcon size={14} /> Send test alert
                </Button>
                <Button type="button" variant="secondary" loading={rotating} onClick={handleRotate}>
                  Rotate secret
                </Button>
                <Button type="button" variant="danger" onClick={handleDelete}>
                  Remove
                </Button>
              </>
            )}
          </div>
        </form>
      </Card>

      {config && (
        <Card className="p-6">
          <h2 className="mb-4 text-sm font-semibold text-ink-700">Delivery status</h2>
          <dl className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-xs uppercase tracking-wide text-ink-400">Last triggered</dt>
              <dd className="mt-1 text-ink-800">
                {config.lastTriggeredAt ? new Date(config.lastTriggeredAt).toLocaleString() : "Never"}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-ink-400">Last response</dt>
              <dd className="mt-1 text-ink-800">
                {config.lastStatusCode ? (
                  <span className={config.lastStatusCode < 300 ? "text-emerald-700" : "text-red-700"}>
                    HTTP {config.lastStatusCode}
                  </span>
                ) : (
                  "—"
                )}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-ink-400">Last error</dt>
              <dd className="mt-1 text-ink-800">{config.lastError ?? "None"}</dd>
            </div>
          </dl>
        </Card>
      )}
    </div>
  );
}

function AlertingSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-8 w-56 rounded-lg bg-ink-100" />
      <div className="h-72 rounded-2xl bg-ink-100" />
    </div>
  );
}
