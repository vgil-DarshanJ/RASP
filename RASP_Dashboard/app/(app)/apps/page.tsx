"use client";

import { FormEvent, useEffect, useState } from "react";
import { ApiError, apiDownload, apiFetch } from "@/lib/api-client";
import { useAppSelection } from "@/lib/app-selection";
import {
  Badge,
  Button,
  Card,
  CheckCircleIcon,
  CopyButton,
  DownloadIcon,
  Input,
  KeyIcon,
  Label,
  LayersIcon,
  PlatformIcon,
  PlusIcon,
  TrashIcon,
  XIcon,
} from "@/components/ui";

type Platform = "ANDROID_NATIVE" | "FLUTTER" | "IOS" | "REACT_NATIVE";

interface SdkCatalogEntry {
  platform: Platform;
  displayName: string;
  available: boolean;
  minVersion: string;
  minOsVersion: string;
  language: string;
  requirements: string[];
  setupDocsPath: string;
}

interface Application {
  id: string;
  name: string;
  platform: Platform;
  createdAt: string;
  credentials: { id: string; apiKey: string; createdAt: string }[];
}

interface IssuedCredential {
  organization_id: string;
  application_id: string;
  application_name: string;
  platform: Platform;
  api_key: string;
  api_secret: string;
  /** Key for the SDK's account/session/beneficiary hashes; same for every credential of the app. */
  account_hash_salt: string;
  ingestion_url: string;
  sdk_min_version: string | null;
  issued_at: string;
}

export default function AppsPage() {
  const [catalog, setCatalog] = useState<SdkCatalogEntry[]>([]);
  const [apps, setApps] = useState<Application[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [platform, setPlatform] = useState<Platform | null>(null);
  const [creating, setCreating] = useState(false);
  const [issued, setIssued] = useState<IssuedCredential | null>(null);
  /** "new": just issued; "shown": an existing credential shown again. */
  const [issuedMode, setIssuedMode] = useState<"new" | "shown">("new");
  const [error, setError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Application | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [detailApp, setDetailApp] = useState<Application | null>(null);

  const { refresh: refreshSelection } = useAppSelection();

  async function refresh() {
    const [catalogRes, appsRes] = await Promise.all([
      apiFetch<{ platforms: SdkCatalogEntry[] }>("/v1/sdk/catalog"),
      apiFetch<{ applications: Application[] }>("/v1/apps"),
    ]);
    setCatalog(catalogRes.platforms);
    setApps(appsRes.applications);
    // Keep the "Viewing" picker in step: new apps appear, archived ones go.
    await refreshSelection().catch(() => {});
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    if (!platform) {
      setError("Pick a platform first.");
      return;
    }
    setError(null);
    setCreating(true);
    try {
      const { application } = await apiFetch<{ application: Application }>("/v1/apps", {
        method: "POST",
        body: JSON.stringify({ name, platform }),
      });
      const credential = await apiFetch<IssuedCredential>(
        `/v1/credentials/applications/${application.id}/credentials`,
        { method: "POST" },
      );
      setIssued(credential);
      setIssuedMode("new");
      setShowForm(false);
      setName("");
      setPlatform(null);
      await refresh();
    } catch {
      setError("Could not create the application. Please try again.");
    } finally {
      setCreating(false);
    }
  }

  /** From the app drawer: issue a new credential (the old ones keep working
   *  until revoked on the Licenses page) or show an active one again. */
  async function getCredential(app: Application, credentialId: string | null) {
    const base = `/v1/credentials/applications/${app.id}/credentials`;
    const credential = credentialId
      ? await apiFetch<IssuedCredential>(`${base}/${credentialId}/reveal`, { method: "POST" })
      : await apiFetch<IssuedCredential>(base, { method: "POST" });
    setIssued(credential);
    setIssuedMode(credentialId ? "shown" : "new");
    setDetailApp(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
    await refresh();
  }

  function downloadCredentialJson(cred: IssuedCredential) {
    const blob = new Blob([JSON.stringify(cred, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rasp-shield-credential-${cred.application_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function confirmDeleteApp() {
    if (!deleteTarget || deleteConfirmText !== deleteTarget.name) return;
    setDeleting(true);
    try {
      await apiFetch(`/v1/apps/${deleteTarget.id}`, { method: "DELETE" });
      setDeleteTarget(null);
      setDeleteConfirmText("");
      await refresh();
    } finally {
      setDeleting(false);
    }
  }

  async function downloadSdk(platform: Platform) {
    const res = await apiDownload(`/v1/sdk/download/${platform}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rasp-shield-${platform.toLowerCase()}.zip`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink-900">Applications</h1>
          <p className="mt-1 text-sm text-ink-500">Register an app per platform you protect with RASP Shield.</p>
        </div>
        {!showForm && (
          <Button onClick={() => setShowForm(true)}>
            <PlusIcon size={15} /> Register application
          </Button>
        )}
      </div>

      {showForm && (
        <Card className="mb-8 p-6">
          <form onSubmit={onCreate} className="space-y-6">
            <div>
              <Label>Application name</Label>
              <Input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Acme Mobile Banking — Android"
              />
            </div>

            <div>
              <Label>Which platform are you integrating?</Label>
              <div className="mt-2 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                {catalog.map((entry) => (
                  <button
                    type="button"
                    key={entry.platform}
                    disabled={!entry.available}
                    onClick={() => setPlatform(entry.platform)}
                    className={`relative rounded-xl border p-4 text-left transition ${
                      !entry.available
                        ? "cursor-not-allowed border-ink-100 bg-ink-50/60 opacity-60"
                        : platform === entry.platform
                          ? "border-brand-400 bg-brand-50 shadow-glow"
                          : "border-ink-200 bg-surface hover:border-brand-300 hover:shadow-card"
                    }`}
                  >
                    <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-ink-50 text-ink-700">
                      <PlatformIcon platform={entry.platform} size={19} />
                    </div>
                    <div className="text-sm font-semibold text-ink-900">{entry.displayName}</div>
                    <div className="mt-1 text-xs text-ink-500">{entry.language}</div>
                    <div className="mt-3">
                      {entry.available ? (
                        <Badge tone="green" icon={false}>
                          Available · v{entry.minVersion}
                        </Badge>
                      ) : (
                        <Badge tone="slate" icon={false}>
                          Coming soon
                        </Badge>
                      )}
                    </div>
                    {platform === entry.platform && (
                      <span className="absolute right-3 top-3 flex h-5 w-5 items-center justify-center rounded-full bg-brand-500 text-white">
                        <CheckCircleIcon size={12} />
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {error && <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

            <div className="flex gap-3">
              <Button type="submit" loading={creating}>
                {creating ? "Creating…" : "Create & issue credential"}
              </Button>
              <Button type="button" variant="secondary" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {issued && (
        <Card className="mb-8 overflow-hidden border-brand-200">
          <div className="flex items-center justify-between bg-brand-50 px-6 py-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-brand-800">
              <CheckCircleIcon size={16} />
              {issuedMode === "new"
                ? `${issued.application_name} is ready — save this credential now`
                : `${issued.application_name} — existing credential`}
            </h2>
            <button className="text-sm text-brand-700 hover:underline" onClick={() => setIssued(null)}>
              Dismiss
            </button>
          </div>
          <div className="p-6">
            <p className="mb-4 flex items-start gap-2 text-sm text-ink-600">
              <KeyIcon size={15} className="mt-0.5 shrink-0 text-ink-400" />
              <span>
                The <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">api_secret</code> below is
                secret: share this JSON only with the people who set up the app. An administrator can show it again
                from the application (each view is recorded in Audit Logs); revoke it on the Licenses page if it
                leaks.
              </span>
            </p>
            <div className="relative mb-4 max-h-64 overflow-auto rounded-xl bg-ink-950 p-4">
              <div className="absolute right-3 top-3">
                <CopyButton value={JSON.stringify(issued, null, 2)} label="Copy JSON" />
              </div>
              <pre className="font-mono text-xs leading-relaxed text-ink-100">{JSON.stringify(issued, null, 2)}</pre>
            </div>
            <div className="flex flex-wrap gap-3">
              <Button onClick={() => downloadCredentialJson(issued)}>
                <DownloadIcon size={15} /> Download credential.json
              </Button>
              <Button variant="secondary" onClick={() => downloadSdk(issued.platform)}>
                <DownloadIcon size={15} /> Download SDK ({catalog.find((c) => c.platform === issued.platform)?.displayName})
              </Button>
            </div>
            <SetupInstructions platform={issued.platform} catalog={catalog} />
          </div>
        </Card>
      )}

      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-ink-400">Registered applications</h2>
      {apps.length === 0 ? (
        <Card className="p-10 text-center">
          <div className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-ink-100 text-ink-400">
            <LayersIcon size={20} />
          </div>
          <p className="text-sm text-ink-500">No applications yet — register your first one above.</p>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {apps.map((app) => (
            <Card
              key={app.id}
              onClick={() => setDetailApp(app)}
              className="group relative cursor-pointer p-5 transition hover:shadow-glow"
            >
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setDeleteTarget(app);
                  setDeleteConfirmText("");
                }}
                title="Delete application"
                className="absolute right-3 top-3 flex h-7 w-7 items-center justify-center rounded-md text-ink-300 opacity-0 transition hover:bg-red-50 hover:text-red-600 group-hover:opacity-100"
              >
                <TrashIcon size={14} />
              </button>
              <div className="mb-3 flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-ink-50 text-ink-700">
                  <PlatformIcon platform={app.platform} size={18} />
                </div>
                <span className="font-semibold text-ink-900">{app.name}</span>
              </div>
              <div className="mb-3 text-xs text-ink-500">
                {app.platform.replace("_", " ")} · created {new Date(app.createdAt).toLocaleDateString()}
              </div>
              <Badge tone={app.credentials.length > 0 ? "green" : "amber"}>
                {app.credentials.length > 0 ? `${app.credentials.length} active credential(s)` : "No credential yet"}
              </Badge>
              <p className="mt-3 flex items-center gap-1 text-xs font-medium text-brand-700 opacity-0 transition group-hover:opacity-100">
                <KeyIcon size={12} /> Click for credentials and SDK
              </p>
            </Card>
          ))}
        </div>
      )}

      {deleteTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-[2px]"
          onClick={() => setDeleteTarget(null)}
        >
          <div onClick={(e) => e.stopPropagation()}>
            <Card className="w-full max-w-md p-6">
              <h2 className="text-base font-semibold text-ink-900">Delete this application?</h2>
              <p className="mt-2 text-sm text-ink-600">
                <strong>{deleteTarget.name}</strong> and every log it has ever reported will disappear from the
                dashboard — devices, threats, analytics, credentials, all of it. Nothing is actually erased: every row
                stays in the database in archived form, and its SDK credential immediately stops being able to ship
                new events. This cannot be undone from here.
              </p>
              <p className="mt-4 text-sm text-ink-700">
                Type <strong>{deleteTarget.name}</strong> to confirm.
              </p>
              <Input
                autoFocus
                value={deleteConfirmText}
                onChange={(e) => setDeleteConfirmText(e.target.value)}
                placeholder={deleteTarget.name}
                className="mt-2"
              />
              <div className="mt-5 flex justify-end gap-3">
                <Button variant="secondary" onClick={() => setDeleteTarget(null)}>
                  Cancel
                </Button>
                <Button
                  variant="danger"
                  disabled={deleteConfirmText !== deleteTarget.name}
                  loading={deleting}
                  onClick={confirmDeleteApp}
                >
                  Delete application
                </Button>
              </div>
            </Card>
          </div>
        </div>
      )}

      {detailApp && (
        <AppDetailDrawer
          app={detailApp}
          catalog={catalog}
          onClose={() => setDetailApp(null)}
          onDownload={downloadSdk}
          onGetCredential={(credentialId) => getCredential(detailApp, credentialId)}
        />
      )}
    </div>
  );
}

/**
 * Click any registered application, any time — not just right after
 * creating it — to re-download its SDK. The zip is built fresh from
 * current source on every request (see BE `sdk-distribution/routes.ts`:
 * "zipping source on every request", never a cached/pinned build), so
 * this is always the latest SDK, whether the app was registered five
 * minutes or five months ago. Registering a brand-new application is
 * never required just to get a fresh download.
 */
function AppDetailDrawer({
  app,
  catalog,
  onClose,
  onDownload,
  onGetCredential,
}: {
  app: Application;
  catalog: SdkCatalogEntry[];
  onClose: () => void;
  onDownload: (platform: Platform) => void;
  /** null: issue a new credential; an id: show that active credential again. */
  onGetCredential: (credentialId: string | null) => Promise<void>;
}) {
  const entry = catalog.find((c) => c.platform === app.platform);
  const [busy, setBusy] = useState<string | null>(null);
  const [credentialError, setCredentialError] = useState<string | null>(null);

  async function getCredential(credentialId: string | null) {
    setBusy(credentialId ?? "new");
    setCredentialError(null);
    try {
      await onGetCredential(credentialId);
    } catch (e) {
      setCredentialError(
        e instanceof ApiError && e.status === 403
          ? "Only an owner or admin can issue or show credentials."
          : "Could not get the credential. Please try again.",
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-[2px]" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-md flex-col bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between border-b border-ink-100 px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-ink-50 text-ink-700">
              <PlatformIcon platform={app.platform} size={20} />
            </div>
            <div className="min-w-0">
              <h3 className="truncate text-base font-semibold text-ink-900">{app.name}</h3>
              <p className="text-xs text-ink-500">
                {app.platform.replace("_", " ")} · created {new Date(app.createdAt).toLocaleDateString()}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-ink-400 hover:bg-ink-50 hover:text-ink-700"
          >
            <XIcon size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-6">
          <Badge tone={app.credentials.length > 0 ? "green" : "amber"}>
            {app.credentials.length > 0 ? `${app.credentials.length} active credential(s)` : "No credential yet"}
          </Badge>

          <div className="mt-5 rounded-xl border border-brand-200 bg-brand-50 p-4">
            <h3 className="flex items-center gap-1.5 text-sm font-semibold text-brand-800">
              <DownloadIcon size={15} /> Download SDK
            </h3>
            <p className="mt-1 text-xs text-brand-700">
              Always the current source — built fresh on every download, not a cached copy. Use this any time you
              need a fresh zip, including after we ship a fix; you never need to register a new application just to
              get an updated SDK.
            </p>
            <Button className="mt-3" onClick={() => onDownload(app.platform)}>
              <DownloadIcon size={15} /> Download SDK ({entry?.displayName ?? app.platform})
            </Button>
          </div>

          <div className="mt-5 rounded-xl border border-ink-100 p-4">
            <h3 className="flex items-center gap-1.5 text-sm font-semibold text-ink-900">
              <KeyIcon size={15} /> Credentials
            </h3>
            {app.credentials.length === 0 ? (
              <p className="mt-1 text-xs text-amber-800">
                This app has no active credential — you&apos;ll need one to connect the SDK. Issue a new one below.
              </p>
            ) : (
              <ul className="mt-3 space-y-2">
                {app.credentials.map((c) => (
                  <li key={c.id} className="flex items-center justify-between gap-3 rounded-lg bg-ink-50 px-3 py-2">
                    <div className="min-w-0">
                      <div className="truncate font-mono text-xs text-ink-700">{c.apiKey}</div>
                      <div className="text-[11px] text-ink-500">issued {new Date(c.createdAt).toLocaleString()}</div>
                    </div>
                    <Button
                      size="sm"
                      variant="secondary"
                      loading={busy === c.id}
                      disabled={busy !== null}
                      onClick={() => getCredential(c.id)}
                    >
                      Show credential
                    </Button>
                  </li>
                ))}
              </ul>
            )}
            <Button
              className="mt-3"
              variant="secondary"
              loading={busy === "new"}
              disabled={busy !== null}
              onClick={() => getCredential(null)}
            >
              <PlusIcon size={15} /> Issue new credential
            </Button>
            <p className="mt-2 text-[11px] text-ink-500">
              A new credential does not stop the old ones; revoke those on the{" "}
              <a href="/licenses" className="font-medium underline">
                Licenses
              </a>{" "}
              page. Showing or issuing a credential is recorded in Audit Logs.
            </p>
            {credentialError && (
              <p className="mt-2 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700">{credentialError}</p>
            )}
          </div>

          <SetupInstructions platform={app.platform} catalog={catalog} />
        </div>
      </div>
    </div>
  );
}

function SetupInstructions({ platform, catalog }: { platform: Platform; catalog: SdkCatalogEntry[] }) {
  const entry = catalog.find((c) => c.platform === platform);
  if (!entry) return null;
  return (
    <div className="mt-5 rounded-xl border border-ink-100 bg-ink-50/60 p-4">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">Requirements</h3>
      <ul className="mb-3 space-y-1 text-sm text-ink-700">
        {entry.requirements.map((r) => (
          <li key={r} className="flex items-start gap-2">
            <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-ink-400" />
            {r}
          </li>
        ))}
      </ul>
      <p className="break-words text-xs text-ink-500">
        Minimum OS: {entry.minOsVersion} · Full setup guide:{" "}
        <code className="break-all rounded bg-ink-100 px-1 py-0.5 font-mono">{entry.setupDocsPath}</code> (bundled in
        the SDK download)
      </p>
    </div>
  );
}
