import { catalogFor } from "@/lib/alertCatalog";
import type { SecurityEvent } from "@/components/event-drawer";

/**
 * One event's level in the device log view and its CSV — the same rule as
 * the backend's `logLevelOf` (BE src/detectors/severity.ts): a DETECTED
 * event takes its detector's severity; every other status says what the
 * check itself did. Colours: `.lvl-*` classes in app/globals.css.
 */
export type LogLevel = "critical" | "high" | "medium" | "low" | "error" | "unavailable" | "secure";

export const LOG_LEVELS: { id: LogLevel; label: string; short: string; hint: string }[] = [
  { id: "critical", label: "Critical", short: "CRIT", hint: "Threat detected · critical detector (root, Frida, hooking…)" },
  { id: "high", label: "High", short: "HIGH", hint: "Threat detected · high-severity detector" },
  { id: "medium", label: "Medium", short: "MED", hint: "Threat detected · medium-severity detector" },
  { id: "low", label: "Low", short: "LOW", hint: "Threat detected · low-severity detector" },
  { id: "error", label: "Error", short: "ERR", hint: "The check failed on the device" },
  { id: "unavailable", label: "Not checked", short: "N/A", hint: "Unavailable or unknown — not evidence of safety" },
  { id: "secure", label: "Secure", short: "OK", hint: "The check ran and passed" },
];

export const THREAT_LEVELS: LogLevel[] = ["critical", "high", "medium", "low"];

export function logLevelOf(detectorId: string, status: string): LogLevel {
  switch (status) {
    case "DETECTED":
      return catalogFor(detectorId).severity;
    case "SECURE":
      return "secure";
    case "ERROR":
      return "error";
    default:
      return "unavailable";
  }
}

export function levelMeta(level: LogLevel) {
  return LOG_LEVELS.find((l) => l.id === level)!;
}

/** Same guard as the backend's csvField: always quoted, and a cell that a
 *  spreadsheet would run as a formula is prefixed with `'`. Values come
 *  from devices, so they are untrusted. */
function csvField(value: unknown): string {
  if (value === null || value === undefined) return "";
  let str = typeof value === "string" ? value : JSON.stringify(value);
  if (/^[=+\-@\t\r]/.test(str)) str = `'${str}`;
  return `"${str.replace(/"/g, '""')}"`;
}

const CSV_COLUMNS = [
  "receivedAt",
  "level",
  "alert",
  "detectorId",
  "status",
  "reason",
  "deviceId",
  "deviceModel",
  "manufacturer",
  "osPlatform",
  "osVersion",
  "appVersion",
  "sdkVersion",
  "evidence",
] as const;

export function eventsToCsv(events: SecurityEvent[]): string {
  const lines = [CSV_COLUMNS.join(",")];
  for (const e of events) {
    const row: Record<(typeof CSV_COLUMNS)[number], unknown> = {
      receivedAt: e.receivedAt,
      level: logLevelOf(e.detectorId, e.status),
      alert: catalogFor(e.detectorId).title,
      detectorId: e.detectorId,
      status: e.status,
      reason: e.reason,
      deviceId: e.deviceId,
      deviceModel: e.deviceModel,
      manufacturer: e.manufacturer,
      osPlatform: e.osPlatform,
      osVersion: e.osVersion,
      appVersion: e.appVersion,
      sdkVersion: e.sdkVersion,
      evidence: e.evidence ?? null,
    };
    lines.push(CSV_COLUMNS.map((c) => csvField(row[c])).join(","));
  }
  // BOM so Excel opens it as UTF-8.
  return "﻿" + lines.join("\r\n");
}

export function saveTextFile(name: string, text: string, type = "text/csv;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
