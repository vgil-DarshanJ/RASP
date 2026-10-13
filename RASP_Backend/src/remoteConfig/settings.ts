import { z } from "zod";
import { countrySet, toCountryCode } from "../ipRisk/ipRisk";

/**
 * What a signed remote configuration may change (Task 10.0) — and nothing
 * else. The engine applies the same list and the same bounds again on the
 * phone (RaspRemoteConfig.kt); `test/fixtures/remote-config/` checks that
 * both sides agree.
 *
 * Never settable remotely: the ingestion URL, the credential, device-key or
 * envelope settings, TLS pins and their enforcement, request signing, and the
 * screenshot / clipboard protections (they change how the app behaves for the
 * user). Unknown fields are rejected, not ignored.
 *
 * Every setting is optional: a field that is absent keeps the value the app
 * was built with. Publishing `{}` returns every device to the app's own
 * configuration.
 */

/** Detector ids remote config may turn on or off. The host app's ceiling
 *  (RaspLeanConfig.remoteManagedDetectors) narrows this further. */
export const REMOTE_MANAGEABLE_DETECTORS = [
  "usb_connection", "adb_enabled", "screenshot_event",
  "root_jailbreak", "emulator", "device_binding", "clone", "developer_mode", "device_lock_missing",
  "secure_hardware_unavailable", "device_fingerprint",
  "frida", "debugger", "re_tools", "hook_detection", "risky_app",
  "tamper", "untrusted_install_source", "repackage",
  "vpn", "mitm", "high_risk_ip",
  "overlay", "accessibility", "external_display",
  "mock_location", "time_spoofing", "unsafe_wifi", "screen_recording",
  "vishing_call", "sim_change", "third_party_keyboard", "task_hijack",
  "device_state_attestation", "malware_reputation",
  "otp_interception_risk", "sms_reader_abuse", "otp_forwarding_risk", "remote_control_app", "screen_sharing_risk",
] as const;

/** Hard bounds, inclusive. The phone rejects a config outside them. */
export const REMOTE_CONFIG_BOUNDS = {
  pollIntervalSeconds: { min: 2, max: 60 },
  heartbeatIntervalSeconds: { min: 10, max: 300 },
  locationHeartbeatIntervalSeconds: { min: 30, max: 600 },
  riskThreshold: { min: 1, max: 100 },
  reputationRefreshHours: { min: 1, max: 168 },
  expiresInDays: { min: 1, max: 180, default: 30 },
  countries: { max: 250 },
} as const;

/** The order fields are written in the signed payload (stable, so the signed text never depends on input order). */
export const SETTING_FIELDS = [
  "detectors",
  "pollIntervalSeconds",
  "heartbeatIntervalSeconds",
  "locationHeartbeatIntervalSeconds",
  "riskMediumThreshold",
  "riskHighThreshold",
  "stepUpThreshold",
  "highRiskTransactionMode",
  "allowedCountries",
  "blockedCountries",
  "reputationRefreshHours",
] as const;

export type SettingField = (typeof SETTING_FIELDS)[number];

export interface RemoteSettings {
  detectors?: Record<string, boolean>;
  pollIntervalSeconds?: number;
  heartbeatIntervalSeconds?: number;
  locationHeartbeatIntervalSeconds?: number;
  riskMediumThreshold?: number;
  riskHighThreshold?: number;
  /** null = step-up only at HIGH (the engine default). */
  stepUpThreshold?: number | null;
  highRiskTransactionMode?: boolean;
  /** ISO 3166-1 alpha-2; used by GET /v1/ip-risk for this application. */
  allowedCountries?: string[];
  blockedCountries?: string[];
  reputationRefreshHours?: number;
}

const B = REMOTE_CONFIG_BOUNDS;
const int = (min: number, max: number) => z.number().int().min(min).max(max);
const detectorSet = new Set<string>(REMOTE_MANAGEABLE_DETECTORS);

const settingsSchema = z
  .object({
    detectors: z
      .record(z.string(), z.boolean())
      .refine((d) => Object.keys(d).every((id) => detectorSet.has(id)), { message: "UNKNOWN_DETECTOR" })
      .optional(),
    pollIntervalSeconds: int(B.pollIntervalSeconds.min, B.pollIntervalSeconds.max).optional(),
    heartbeatIntervalSeconds: int(B.heartbeatIntervalSeconds.min, B.heartbeatIntervalSeconds.max).optional(),
    locationHeartbeatIntervalSeconds: int(B.locationHeartbeatIntervalSeconds.min, B.locationHeartbeatIntervalSeconds.max).optional(),
    riskMediumThreshold: int(B.riskThreshold.min, B.riskThreshold.max).optional(),
    riskHighThreshold: int(B.riskThreshold.min, B.riskThreshold.max).optional(),
    stepUpThreshold: int(B.riskThreshold.min, B.riskThreshold.max).nullable().optional(),
    highRiskTransactionMode: z.boolean().optional(),
    allowedCountries: z.array(z.string().max(10)).max(B.countries.max).optional(),
    blockedCountries: z.array(z.string().max(10)).max(B.countries.max).optional(),
    reputationRefreshHours: int(B.reputationRefreshHours.min, B.reputationRefreshHours.max).optional(),
  })
  .strict();

const publishSchema = z
  .object({
    settings: settingsSchema,
    expiresInDays: int(B.expiresInDays.min, B.expiresInDays.max).optional(),
  })
  .strict();

export type ParseResult<T> = { ok: true; data: T } | { ok: false; error: string; details?: unknown };

/** Validates a settings object and normalizes it (country codes upper-case and unique, fixed field order). Pure. */
export function parseRemoteSettings(input: unknown): ParseResult<RemoteSettings> {
  const parsed = settingsSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: "INVALID_REMOTE_CONFIG", details: parsed.error.flatten() };
  const s = parsed.data;
  if (s.riskMediumThreshold !== undefined && s.riskHighThreshold !== undefined && s.riskMediumThreshold >= s.riskHighThreshold) {
    return { ok: false, error: "INVALID_REMOTE_CONFIG", details: { riskMediumThreshold: "must be below riskHighThreshold" } };
  }
  for (const field of ["allowedCountries", "blockedCountries"] as const) {
    const invalid = (s[field] ?? []).filter((code) => toCountryCode(code) === null);
    if (invalid.length > 0) return { ok: false, error: "INVALID_COUNTRY_CODE", details: { field, invalid } };
  }
  return { ok: true, data: normalizeSettings(s) };
}

/** PUT body: `{ settings, expiresInDays? }`. */
export function parsePublishBody(body: unknown): ParseResult<{ settings: RemoteSettings; expiresInDays: number }> {
  const parsed = publishSchema.safeParse(body);
  if (!parsed.success) return { ok: false, error: "INVALID_REMOTE_CONFIG", details: parsed.error.flatten() };
  const settings = parseRemoteSettings(parsed.data.settings);
  if (!settings.ok) return settings;
  return { ok: true, data: { settings: settings.data, expiresInDays: parsed.data.expiresInDays ?? B.expiresInDays.default } };
}

/** The same settings with fields in [SETTING_FIELDS] order, detectors sorted, countries normalized. */
export function normalizeSettings(s: RemoteSettings): RemoteSettings {
  const out: Record<string, unknown> = {};
  for (const field of SETTING_FIELDS) {
    const value = s[field];
    if (value === undefined) continue;
    if (field === "detectors") {
      const d = value as Record<string, boolean>;
      out.detectors = Object.fromEntries(Object.keys(d).sort().map((id) => [id, d[id]]));
    } else if (field === "allowedCountries" || field === "blockedCountries") {
      out[field] = [...countrySet(value as string[])].sort();
    } else {
      out[field] = value;
    }
  }
  return out as RemoteSettings;
}

/** One entry per field whose value differs between two settings objects (absent = the app's own value). */
export function settingsChanges(previous: RemoteSettings | null, next: RemoteSettings) {
  const before = (previous ?? {}) as Record<string, unknown>;
  const after = next as Record<string, unknown>;
  return SETTING_FIELDS.filter((f) => JSON.stringify(before[f] ?? null) !== JSON.stringify(after[f] ?? null)).map((field) => ({
    field,
    oldValue: before[field] ?? null,
    newValue: after[field] ?? null,
  }));
}
