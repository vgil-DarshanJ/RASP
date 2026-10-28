"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { PlatformIcon, RiskBadge, SearchIcon, SmartphoneIcon, XIcon } from "@/components/ui";
import type { DeviceSummary } from "@/components/device-trail-drawer";
import { timeAgo } from "@/lib/usePolled";

/** A device row from `GET .../devices` (the summary plus its risk score). */
export interface PickerDevice extends DeviceSummary {
  riskScore: number;
  riskLevel: string;
}

export function deviceName(d: Pick<DeviceSummary, "deviceModel" | "manufacturer" | "deviceId">) {
  if (d.deviceModel) return d.manufacturer && !d.deviceModel.toLowerCase().startsWith(d.manufacturer.toLowerCase())
    ? `${d.manufacturer} ${d.deviceModel}`
    : d.deviceModel;
  return `Device ${d.deviceId.slice(0, 8)}`;
}

/**
 * "Select device" button with a searchable pop-up list, riskiest first.
 * Keyboard: ↑/↓ to move, Enter to pick, Esc to close.
 */
export function DevicePicker({
  devices,
  selectedId,
  onSelect,
}: {
  devices: PickerDevice[] | null;
  selectedId: string | null;
  onSelect: (device: PickerDevice) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = devices ?? [];
    if (!q) return list;
    return list.filter((d) =>
      [d.deviceModel, d.manufacturer, d.deviceId, d.osPlatform, d.osVersion, d.appVersion]
        .some((v) => v?.toLowerCase().includes(q)),
    );
  }, [devices, query]);

  useEffect(() => {
    if (!open) return;
    setCursor(0);
    inputRef.current?.focus();
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  useEffect(() => setCursor(0), [query]);

  function pick(d: PickerDevice) {
    onSelect(d);
    setOpen(false);
    setQuery("");
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") setOpen(false);
    else if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => Math.min(c + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => Math.max(c - 1, 0));
    } else if (e.key === "Enter" && filtered[cursor]) {
      e.preventDefault();
      pick(filtered[cursor]);
    }
  }

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="inline-flex items-center gap-2 rounded-lg border border-ink-200 bg-surface px-3 py-1.5 text-xs font-medium text-ink-800 transition hover:border-brand-400 hover:text-brand-600"
      >
        <SmartphoneIcon size={14} />
        Select device
        {devices && <span className="rounded-full bg-ink-100 px-1.5 text-[10px] text-ink-600">{devices.length}</span>}
      </button>

      {open && (
        <div
          className="absolute right-0 z-30 mt-2 w-[min(26rem,calc(100vw-2rem))] overflow-hidden rounded-xl border border-ink-200 bg-surface shadow-2xl"
          onKeyDown={onKeyDown}
        >
          <div className="flex items-center gap-2 border-b border-ink-100 px-3 py-2">
            <SearchIcon size={14} className="text-ink-400" />
            <input
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search model, OS, device ID…"
              className="w-full bg-transparent py-1 text-sm text-ink-900 outline-none placeholder:text-ink-400"
            />
            <button type="button" onClick={() => setOpen(false)} className="text-ink-400 hover:text-ink-700" aria-label="Close">
              <XIcon size={14} />
            </button>
          </div>
          <ul role="listbox" className="max-h-80 overflow-y-auto py-1">
            {devices === null ? (
              <li className="px-4 py-6 text-center text-xs text-ink-400">Loading devices…</li>
            ) : filtered.length === 0 ? (
              <li className="px-4 py-6 text-center text-xs text-ink-400">No device matches “{query}”.</li>
            ) : (
              filtered.map((d, i) => (
                <li key={d.deviceId} role="option" aria-selected={d.deviceId === selectedId}>
                  <button
                    type="button"
                    onMouseEnter={() => setCursor(i)}
                    onClick={() => pick(d)}
                    className={`flex w-full items-center gap-3 px-3 py-2.5 text-left transition ${
                      i === cursor ? "bg-ink-50" : ""
                    } ${d.deviceId === selectedId ? "ring-1 ring-inset ring-brand-400/50" : ""}`}
                  >
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-ink-100 text-ink-600">
                      {d.osPlatform ? <PlatformIcon platform={platformKey(d.osPlatform)} size={16} /> : <SmartphoneIcon size={16} />}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-ink-900">{deviceName(d)}</span>
                      <span className="block truncate text-[11px] text-ink-500">
                        {d.osPlatform ? `${d.osPlatform} ${d.osVersion ?? ""}` : "OS unknown"} · {d.eventCount} logs ·{" "}
                        <span className={d.threatCount > 0 ? "text-red-500" : ""}>{d.threatCount} threats</span> · {timeAgo(d.lastSeen)}
                      </span>
                      <span className="block truncate font-mono text-[10px] text-ink-400">{d.deviceId}</span>
                    </span>
                    <RiskBadge score={d.riskScore} level={d.riskLevel} size="sm" />
                  </button>
                </li>
              ))
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

function platformKey(os: string) {
  const o = os.toLowerCase();
  if (o.includes("ios")) return "IOS";
  if (o.includes("android")) return "ANDROID_NATIVE";
  return os;
}
