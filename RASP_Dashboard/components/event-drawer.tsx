"use client";

import { Badge, CategoryChip, MapPinIcon, statusTone, XIcon } from "@/components/ui";
import { CATEGORY_COLORS, catalogFor } from "@/lib/alertCatalog";

export interface EvidenceEntry {
  key: string;
  value: unknown;
  note?: string;
}

export interface SecurityEvent {
  id: string;
  applicationId?: string;
  detectorId: string;
  status: string;
  reason: string | null;
  evidence?: EvidenceEntry[] | null;
  deviceId: string | null;
  deviceModel: string | null;
  manufacturer: string | null;
  osPlatform: string | null;
  osVersion: string | null;
  appVersion: string | null;
  sdkVersion: string | null;
  receivedAt: string;
  application?: { id: string; name: string; platform: string };
}

/** The event's location, only when the user opted in to sharing it
 *  (`location_opt_in: true` in the evidence; the backend stores no
 *  coordinates otherwise). Shown rounded to 3 decimals. `null` = not shared. */
function extractLocation(evidence: EvidenceEntry[] | null | undefined) {
  if (!evidence) return null;
  if (evidence.find((e) => e.key === "location_opt_in")?.value !== true) return null;
  const lat = evidence.find((e) => e.key === "latitude")?.value;
  const lng = evidence.find((e) => e.key === "longitude")?.value;
  const accuracy = evidence.find((e) => e.key === "location_accuracy_m")?.value;
  if (typeof lat !== "number" || typeof lng !== "number") return null;
  return { lat, lng, accuracy: typeof accuracy === "number" ? accuracy : null };
}

export function EventDetailDrawer({ event, onClose }: { event: SecurityEvent; onClose: () => void }) {
  const catalog = catalogFor(event.detectorId);
  const colors = CATEGORY_COLORS[catalog.category];
  const location = extractLocation(event.evidence);
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-[2px]" onClick={onClose}>
      <div
        className="h-full w-full max-w-md overflow-y-auto bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-ink-100 px-6 py-5">
          <div>
            <h3 className="text-base font-semibold text-ink-900">{catalog.title}</h3>
            <p className="mt-0.5 font-mono text-xs text-ink-400">{event.id}</p>
          </div>
          <button
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-md text-ink-400 hover:bg-ink-50 hover:text-ink-700"
          >
            <XIcon size={16} />
          </button>
        </div>
        <div className="px-6 py-5">
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <Badge tone={statusTone(event.status)}>{event.status}</Badge>
            <CategoryChip label={catalog.category} colors={colors} />
          </div>
          {catalog.description && <p className="mb-4 text-sm text-ink-500">{catalog.description}</p>}
          <dl className="space-y-3 text-sm">
            {event.application && <Row label="Application" value={event.application.name} />}
            <Row label="Detector" value={<span className="font-mono text-xs">{event.detectorId}</span>} />
            {event.reason && <Row label="Reason" value={event.reason} />}
            <Row label="Device ID" value={<span className="font-mono text-xs">{event.deviceId ?? "—"}</span>} />
            <Row label="Device model" value={event.deviceModel ?? "—"} />
            <Row label="Manufacturer" value={event.manufacturer ?? "—"} />
            <Row label="OS" value={event.osPlatform ? `${event.osPlatform} ${event.osVersion ?? ""}` : "—"} />
            <Row label="App version" value={event.appVersion ?? "—"} />
            <Row label="SDK version" value={event.sdkVersion ?? "—"} />
            <Row label="Received at (server)" value={new Date(event.receivedAt).toLocaleString()} />
            {location ? (
              <Row
                label="Location"
                value={
                  <a
                    href={`https://www.google.com/maps?q=${location.lat.toFixed(3)},${location.lng.toFixed(3)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-brand-700 hover:underline"
                  >
                    <MapPinIcon size={13} />
                    {location.lat.toFixed(3)}, {location.lng.toFixed(3)}
                    {location.accuracy != null && ` (±${Math.round(location.accuracy)}m)`}
                  </a>
                }
              />
            ) : (
              <Row label="Location" value={<span className="text-ink-400">location not shared</span>} />
            )}
          </dl>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 border-b border-ink-50 pb-2.5">
      <dt className="shrink-0 text-ink-500">{label}</dt>
      <dd className="text-right font-medium text-ink-900">{value}</dd>
    </div>
  );
}
