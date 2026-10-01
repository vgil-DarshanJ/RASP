"use client";

import { useState } from "react";
import {
  Badge,
  Button,
  KeyIcon,
  PlatformIcon,
  SmartphoneIcon,
  XIcon,
} from "@/components/ui";

export interface CredentialDetail {
  id: string;
  apiKey: string;
  status: "ACTIVE" | "REVOKED";
  createdAt: string;
  rotatedAt: string | null;
  revokedAt: string | null;
  application: { id: string; name: string; platform: string; deviceCount: number };
}

/** `min-w-0` is load-bearing here, not decoration — a grid item defaults
 *  to `min-width: auto`, which lets an unbroken string (an `apiKey`, a
 *  URL) size the cell to its own intrinsic width and spill into the
 *  next column instead of wrapping. `break-all` on the value is the
 *  other half: normal word-wrap never breaks a token with no spaces. */
function Field({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-ink-400">{label}</dt>
      <dd className={`mt-1 break-all text-sm text-ink-900 ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

/**
 * "Click the row, see everything" for one credential — a beautified
 * detail view, not just a wider table row. Reads entirely off the same
 * `GET /v1/credentials` payload the Licenses table already has (plus the
 * response's shared `organizationId`/`ingestionUrl`), so opening this
 * costs no extra request.
 *
 * "Copy config" reassembles everything an already-issued credential can
 * still prove EXCEPT the secret — `api_secret` was a one-time reveal at
 * issuance (see `credentials/routes.ts`'s doc) and is never
 * reconstructable here. The copied JSON says so explicitly rather than
 * silently omitting the field, so nobody pastes an incomplete config
 * into an app and wonders why shipping still fails.
 */
export function CredentialDetailDrawer({
  credential,
  organizationId,
  ingestionUrl,
  onClose,
  onRevoke,
  onUnrevoke,
  onDelete,
  onViewDevices,
  revoking,
  unrevoking,
  deleting,
}: {
  credential: CredentialDetail;
  organizationId: string;
  ingestionUrl: string;
  onClose: () => void;
  onRevoke: () => void;
  onUnrevoke: () => void;
  onDelete: () => void;
  onViewDevices: () => void;
  revoking: boolean;
  unrevoking: boolean;
  deleting: boolean;
}) {
  const [justCopied, setJustCopied] = useState(false);

  const configJson = JSON.stringify(
    {
      organization_id: organizationId,
      application_id: credential.application.id,
      application_name: credential.application.name,
      platform: credential.application.platform,
      api_key: credential.apiKey,
      ingestion_url: ingestionUrl,
      note:
        "api_secret was shown once at issuance and cannot be recovered from here — issue a new credential (rotate) if it was lost.",
    },
    null,
    2,
  );

  async function copyConfig() {
    try {
      await navigator.clipboard.writeText(configJson);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = configJson;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
    setJustCopied(true);
    setTimeout(() => setJustCopied(false), 1500);
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-[2px]" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-lg flex-col bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="border-b border-ink-100 bg-gradient-to-b from-ink-50/70 to-transparent px-6 py-5">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-brand-50 text-brand-700 ring-1 ring-brand-100">
                <PlatformIcon platform={credential.application.platform} size={20} />
              </div>
              <div className="min-w-0">
                <h3 className="truncate text-base font-semibold text-ink-900">{credential.application.name}</h3>
                <div className="mt-1 flex items-center gap-2">
                  <Badge tone={credential.status === "ACTIVE" ? "green" : "slate"}>{credential.status}</Badge>
                  <button
                    onClick={onViewDevices}
                    className="inline-flex items-center gap-1 text-xs font-medium text-ink-500 hover:text-brand-700"
                  >
                    <SmartphoneIcon size={12} />
                    {credential.application.deviceCount} device{credential.application.deviceCount === 1 ? "" : "s"}
                  </button>
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-ink-400 hover:bg-ink-50 hover:text-ink-700"
            >
              <XIcon size={16} />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-6">
          <div className="mb-6">
            <div className="mb-2 flex items-center justify-between">
              <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-ink-500">
                <KeyIcon size={13} /> Config
              </h4>
              <Button size="sm" variant={justCopied ? "primary" : "secondary"} onClick={copyConfig}>
                {justCopied ? "Copied ✓" : "Copy config"}
              </Button>
            </div>
            <pre className="overflow-x-auto rounded-xl bg-ink-950 p-4 font-mono text-[11px] leading-relaxed text-ink-100 ring-1 ring-white/5">
              {configJson}
            </pre>
          </div>

          <dl className="grid grid-cols-2 gap-x-6 gap-y-5">
            <Field label="API key" value={credential.apiKey} mono />
            <Field label="Platform" value={credential.application.platform} />
            <Field label="Issued" value={new Date(credential.createdAt).toLocaleString()} />
            <Field
              label="Revoked"
              value={credential.revokedAt ? new Date(credential.revokedAt).toLocaleString() : "—"}
            />
            <div className="col-span-2">
              <Field label="Ingestion URL" value={ingestionUrl} mono />
            </div>
          </dl>
        </div>

        <div className="flex justify-end gap-3 border-t border-ink-100 px-6 py-4">
          {credential.status === "ACTIVE" && (
            <Button variant="danger" loading={revoking} onClick={onRevoke}>
              Revoke
            </Button>
          )}
          {credential.status === "REVOKED" && (
            <>
              <Button variant="secondary" loading={unrevoking} onClick={onUnrevoke}>
                Un-revoke
              </Button>
              <Button variant="secondary" loading={deleting} onClick={onDelete}>
                Delete
              </Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
