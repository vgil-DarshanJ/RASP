"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import { Badge, Button, Card, Input, KeyIcon, PlatformIcon, SmartphoneIcon } from "@/components/ui";
import { ApplicationDevicesDrawer } from "@/components/application-devices-drawer";
import { CredentialDetailDrawer, type CredentialDetail } from "@/components/credential-detail-drawer";

interface CredentialsResponse {
  organizationId: string;
  ingestionUrl: string;
  credentials: CredentialDetail[];
}

/** Every credential ever issued across every app in the org —
 *  `GET /v1/credentials` (real Postgres data, active AND revoked, never
 *  soft-deleted ones). Click a row to open the full detail drawer
 *  (config copy, device count, revoke/delete) instead of acting inline
 *  in the table — keeps the table itself scannable. */
export default function LicensesPage() {
  const [data, setData] = useState<CredentialsResponse | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [unrevokingId, setUnrevokingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CredentialDetail | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [selectedCredential, setSelectedCredential] = useState<CredentialDetail | null>(null);
  const [devicesDrawerApp, setDevicesDrawerApp] = useState<CredentialDetail["application"] | null>(null);

  async function load() {
    const res = await apiFetch<CredentialsResponse>("/v1/credentials");
    setData(res);
    // Keep the open detail drawer's data fresh after a revoke/delete.
    setSelectedCredential((prev) => (prev ? res.credentials.find((c) => c.id === prev.id) ?? null : prev));
  }

  useEffect(() => {
    load();
  }, []);

  async function revoke(cred: CredentialDetail) {
    if (!confirm(`Revoke this credential for "${cred.application.name}"? The SDK will stop being able to ship events immediately.`)) {
      return;
    }
    setRevokingId(cred.id);
    try {
      await apiFetch(`/v1/credentials/applications/${cred.application.id}/credentials/${cred.id}/revoke`, {
        method: "POST",
      });
      await load();
    } finally {
      setRevokingId(null);
    }
  }

  async function unrevoke(cred: CredentialDetail) {
    if (!confirm(`Reactivate this credential for "${cred.application.name}"? The SDK will be able to ship events with it again immediately.`)) {
      return;
    }
    setUnrevokingId(cred.id);
    try {
      await apiFetch(`/v1/credentials/applications/${cred.application.id}/credentials/${cred.id}/unrevoke`, {
        method: "POST",
      });
      await load();
    } finally {
      setUnrevokingId(null);
    }
  }

  async function confirmDelete() {
    if (!deleteTarget || deleteConfirmText !== deleteTarget.application.name) return;
    setDeletingId(deleteTarget.id);
    try {
      await apiFetch(`/v1/credentials/applications/${deleteTarget.application.id}/credentials/${deleteTarget.id}`, {
        method: "DELETE",
      });
      setDeleteTarget(null);
      setDeleteConfirmText("");
      setSelectedCredential(null);
      await load();
    } finally {
      setDeletingId(null);
    }
  }

  if (data === null) return <LicensesSkeleton />;

  const { credentials, organizationId, ingestionUrl } = data;
  const activeCount = credentials.filter((c) => c.status === "ACTIVE").length;

  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold text-ink-900">Licenses</h1>
      <p className="mb-6 text-sm text-ink-500">
        {credentials.length} credential{credentials.length === 1 ? "" : "s"} issued · {activeCount} active
      </p>

      {credentials.length === 0 ? (
        <Card className="p-10 text-center">
          <KeyIcon size={22} className="mx-auto mb-2 text-ink-300" />
          <p className="text-sm text-ink-400">
            No credentials issued yet — go to{" "}
            <a href="/apps" className="font-medium text-brand-700 hover:underline">
              Applications
            </a>{" "}
            to issue one.
          </p>
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                  <th className="py-2.5 pl-5 pr-4 font-medium">Application</th>
                  <th className="py-2.5 pr-4 font-medium">Devices</th>
                  <th className="py-2.5 pr-4 font-medium">API key</th>
                  <th className="py-2.5 pr-4 font-medium">Status</th>
                  <th className="py-2.5 pr-4 font-medium">Issued</th>
                  <th className="py-2.5 pr-4 font-medium">Revoked</th>
                  <th className="py-2.5 pr-5 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {credentials.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => setSelectedCredential(c)}
                    className="cursor-pointer border-b border-ink-50 transition hover:bg-ink-50/60"
                  >
                    <td className="py-2.5 pl-5 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-ink-50 text-ink-600">
                          <PlatformIcon platform={c.application.platform} size={14} />
                        </div>
                        <span className="font-medium text-ink-900">{c.application.name}</span>
                      </div>
                    </td>
                    <td className="py-2.5 pr-4">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setDevicesDrawerApp(c.application);
                        }}
                        className="inline-flex items-center gap-1.5 rounded-full bg-ink-100 px-2.5 py-1 text-xs font-medium text-ink-700 transition hover:bg-brand-50 hover:text-brand-700"
                        title="View devices using this application"
                      >
                        <SmartphoneIcon size={12} />
                        {c.application.deviceCount}
                      </button>
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-xs text-ink-600">{c.apiKey}</td>
                    <td className="py-2.5 pr-4">
                      <Badge tone={c.status === "ACTIVE" ? "green" : "slate"}>{c.status}</Badge>
                    </td>
                    <td className="py-2.5 pr-4 text-ink-500">{new Date(c.createdAt).toLocaleDateString()}</td>
                    <td className="py-2.5 pr-4 text-ink-500">
                      {c.revokedAt ? new Date(c.revokedAt).toLocaleDateString() : "—"}
                    </td>
                    <td className="py-2.5 pr-5 text-right">
                      <div className="flex justify-end gap-2">
                        {c.status === "ACTIVE" && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              revoke(c);
                            }}
                            disabled={revokingId === c.id}
                            className="rounded-md border border-red-200 px-2.5 py-1 text-xs font-medium text-red-700 transition hover:bg-red-50 disabled:opacity-50"
                          >
                            {revokingId === c.id ? "Revoking…" : "Revoke"}
                          </button>
                        )}
                        {c.status === "REVOKED" && (
                          <>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                unrevoke(c);
                              }}
                              disabled={unrevokingId === c.id}
                              className="rounded-md border border-emerald-200 px-2.5 py-1 text-xs font-medium text-emerald-700 transition hover:bg-emerald-50 disabled:opacity-50"
                            >
                              {unrevokingId === c.id ? "Reactivating…" : "Un-revoke"}
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setDeleteTarget(c);
                                setDeleteConfirmText("");
                              }}
                              className="rounded-md border border-ink-200 px-2.5 py-1 text-xs font-medium text-ink-600 transition hover:border-red-200 hover:bg-red-50 hover:text-red-700"
                            >
                              Delete
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {selectedCredential && (
        <CredentialDetailDrawer
          credential={selectedCredential}
          organizationId={organizationId}
          ingestionUrl={ingestionUrl}
          onClose={() => setSelectedCredential(null)}
          onRevoke={() => revoke(selectedCredential)}
          onUnrevoke={() => unrevoke(selectedCredential)}
          onDelete={() => {
            setDeleteTarget(selectedCredential);
            setDeleteConfirmText("");
          }}
          onViewDevices={() => setDevicesDrawerApp(selectedCredential.application)}
          revoking={revokingId === selectedCredential.id}
          unrevoking={unrevokingId === selectedCredential.id}
          deleting={deletingId === selectedCredential.id}
        />
      )}

      {deleteTarget && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 backdrop-blur-[2px]"
          onClick={() => setDeleteTarget(null)}
        >
          <div onClick={(e) => e.stopPropagation()}>
            <Card className="w-full max-w-md p-6">
              <h2 className="text-base font-semibold text-ink-900">Delete this credential?</h2>
              <p className="mt-2 text-sm text-ink-600">
                This permanently removes{" "}
                <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">{deleteTarget.apiKey}</code> from
                your Licenses list. Its issue/revoke/delete history stays in the audit log. This cannot be undone
                from here.
              </p>
              <p className="mt-4 text-sm text-ink-700">
                Type <strong>{deleteTarget.application.name}</strong> to confirm.
              </p>
              <Input
                autoFocus
                value={deleteConfirmText}
                onChange={(e) => setDeleteConfirmText(e.target.value)}
                placeholder={deleteTarget.application.name}
                className="mt-2"
              />
              <div className="mt-5 flex justify-end gap-3">
                <Button variant="secondary" onClick={() => setDeleteTarget(null)}>
                  Cancel
                </Button>
                <Button
                  variant="danger"
                  disabled={deleteConfirmText !== deleteTarget.application.name}
                  loading={deletingId === deleteTarget.id}
                  onClick={confirmDelete}
                >
                  Delete permanently
                </Button>
              </div>
            </Card>
          </div>
        </div>
      )}

      {devicesDrawerApp && (
        <ApplicationDevicesDrawer
          applicationId={devicesDrawerApp.id}
          applicationName={devicesDrawerApp.name}
          applicationPlatform={devicesDrawerApp.platform}
          onClose={() => setDevicesDrawerApp(null)}
        />
      )}
    </div>
  );
}

function LicensesSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-8 w-40 rounded-lg bg-ink-100" />
      <div className="h-64 rounded-2xl bg-ink-100" />
    </div>
  );
}
