"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import { Badge, Card, ScrollTextIcon } from "@/components/ui";

interface AuditLogRow {
  id: string;
  action: "ISSUED" | "REVOKED" | "REACTIVATED" | "DELETED" | "REVEALED";
  performedAt: string;
  performedByEmail: string;
  ipAddress: string | null;
  credential: { apiKey: string; application: { id: string; name: string } };
}

/** Org-wide credential lifecycle audit trail — `GET /v1/credentials/audit-log`
 *  (new endpoint), backed by the `CredentialAuditLog` table that already
 *  existed and was already written to on every issue/revoke (see
 *  `credentials/routes.ts`) — this just gives it a real page for the
 *  first time. Append-only by convention on the backend; nothing here is
 *  editable. */
export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLogRow[] | null>(null);

  useEffect(() => {
    apiFetch<{ logs: AuditLogRow[] }>("/v1/credentials/audit-log").then((res) => setLogs(res.logs));
  }, []);

  if (logs === null) return <AuditSkeleton />;

  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold text-ink-900">Audit Logs</h1>
      <p className="mb-6 text-sm text-ink-500">
        Who issued or revoked which credential, when, and from where — {logs.length} entr
        {logs.length === 1 ? "y" : "ies"}.
      </p>

      {logs.length === 0 ? (
        <Card className="p-10 text-center">
          <ScrollTextIcon size={22} className="mx-auto mb-2 text-ink-300" />
          <p className="text-sm text-ink-400">No credential activity recorded yet.</p>
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                  <th className="py-2.5 pl-5 pr-4 font-medium">Time</th>
                  <th className="py-2.5 pr-4 font-medium">Action</th>
                  <th className="py-2.5 pr-4 font-medium">Application</th>
                  <th className="py-2.5 pr-4 font-medium">API key</th>
                  <th className="py-2.5 pr-4 font-medium">Performed by</th>
                  <th className="py-2.5 pr-5 font-medium">IP address</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id} className="border-b border-ink-50">
                    <td className="py-2.5 pl-5 pr-4 text-ink-500">{new Date(log.performedAt).toLocaleString()}</td>
                    <td className="py-2.5 pr-4">
                      <Badge tone={log.action === "ISSUED" || log.action === "REACTIVATED" ? "green" : log.action === "REVEALED" ? "slate" : "amber"} icon={false}>
                        {log.action}
                      </Badge>
                    </td>
                    <td className="py-2.5 pr-4 font-medium text-ink-900">{log.credential.application.name}</td>
                    <td className="py-2.5 pr-4 font-mono text-xs text-ink-600">{log.credential.apiKey}</td>
                    <td className="py-2.5 pr-4 text-ink-600">{log.performedByEmail}</td>
                    <td className="py-2.5 pr-5 font-mono text-xs text-ink-500">{log.ipAddress ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

function AuditSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-8 w-40 rounded-lg bg-ink-100" />
      <div className="h-64 rounded-2xl bg-ink-100" />
    </div>
  );
}
