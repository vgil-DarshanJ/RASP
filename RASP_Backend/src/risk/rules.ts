import { z } from "zod";

/**
 * Fraud-risk rules for POST /v1/risk/events. Simple, explainable rules over
 * the hashed account / session / beneficiary ids an application sends —
 * no machine learning, no scoring model. Each rule that fires produces a
 * finding with a plain-language explanation and the numbers behind it.
 *
 * Thresholds are per application (Application.riskRules, edited through
 * PATCH /v1/apps/:id); anything not set uses DEFAULT_RISK_RULES.
 *
 * What the rules can and cannot see (honest limits):
 * - They only see what the app reports. An app that never sends
 *   session/transaction events gets no findings — that is "not evaluated",
 *   not "low risk".
 * - A rule that lacks its input (no location, unknown IP country, first
 *   event of an account) does not fire; it never concludes "safe".
 * - impossible_travel by IP country is weak evidence: VPNs, mobile
 *   roaming and carrier NAT also change the IP country. The finding says so.
 */

export const RISK_RULE_IDS = [
  "new_device_for_account",
  "device_change_velocity",
  "concurrent_sessions",
  "impossible_travel",
  "transaction_velocity",
  "new_beneficiary",
] as const;
export type RiskRuleId = (typeof RISK_RULE_IDS)[number];

export type RiskSeverity = "low" | "medium" | "high";

export const RULE_SEVERITY: Record<RiskRuleId, RiskSeverity> = {
  new_device_for_account: "medium",
  device_change_velocity: "high",
  concurrent_sessions: "medium",
  impossible_travel: "high",
  transaction_velocity: "high",
  new_beneficiary: "low",
};

export interface RiskRulesConfig {
  deviceChangeVelocity: { maxDevices: number; windowMinutes: number };
  concurrentSessions: { maxDevices: number; windowMinutes: number };
  impossibleTravel: {
    maxSpeedKmh: number;
    minMinutes: number;
    minDistanceKm: number;
    /** Request-IP country change within this many minutes fires (IP-based, weak); 0 = off. */
    ipCountryChangeMinutes: number;
  };
  transactionVelocity: { maxCount: number; windowMinutes: number };
}

export const DEFAULT_RISK_RULES: RiskRulesConfig = {
  deviceChangeVelocity: { maxDevices: 3, windowMinutes: 1440 },
  concurrentSessions: { maxDevices: 2, windowMinutes: 30 },
  impossibleTravel: { maxSpeedKmh: 900, minMinutes: 5, minDistanceKm: 100, ipCountryChangeMinutes: 60 },
  transactionVelocity: { maxCount: 5, windowMinutes: 10 },
};

/** Allowed range of every threshold — the same ranges the dashboard form uses. */
export const RISK_RULE_LIMITS = {
  deviceChangeVelocity: { maxDevices: [1, 50], windowMinutes: [1, 10080] },
  concurrentSessions: { maxDevices: [1, 50], windowMinutes: [1, 1440] },
  impossibleTravel: { maxSpeedKmh: [50, 5000], minMinutes: [0, 1440], minDistanceKm: [1, 20000], ipCountryChangeMinutes: [0, 1440] },
  transactionVelocity: { maxCount: [1, 1000], windowMinutes: [1, 1440] },
} as const;

const bounded = (range: readonly [number, number]) => z.number().int().min(range[0]).max(range[1]);

/** A partial update: any subset of rules and fields; unknown keys rejected. */
export const riskRulesPatchSchema = z
  .object({
    deviceChangeVelocity: z.object({
      maxDevices: bounded(RISK_RULE_LIMITS.deviceChangeVelocity.maxDevices),
      windowMinutes: bounded(RISK_RULE_LIMITS.deviceChangeVelocity.windowMinutes),
    }).partial().strict().optional(),
    concurrentSessions: z.object({
      maxDevices: bounded(RISK_RULE_LIMITS.concurrentSessions.maxDevices),
      windowMinutes: bounded(RISK_RULE_LIMITS.concurrentSessions.windowMinutes),
    }).partial().strict().optional(),
    impossibleTravel: z.object({
      maxSpeedKmh: bounded(RISK_RULE_LIMITS.impossibleTravel.maxSpeedKmh),
      minMinutes: bounded(RISK_RULE_LIMITS.impossibleTravel.minMinutes),
      minDistanceKm: bounded(RISK_RULE_LIMITS.impossibleTravel.minDistanceKm),
      ipCountryChangeMinutes: bounded(RISK_RULE_LIMITS.impossibleTravel.ipCountryChangeMinutes),
    }).partial().strict().optional(),
    transactionVelocity: z.object({
      maxCount: bounded(RISK_RULE_LIMITS.transactionVelocity.maxCount),
      windowMinutes: bounded(RISK_RULE_LIMITS.transactionVelocity.windowMinutes),
    }).partial().strict().optional(),
  })
  .strict();

export type RiskRulesPatch = z.infer<typeof riskRulesPatchSchema>;

/**
 * The thresholds in force for an application: the stored JSON merged over
 * the defaults, field by field. A stored value that is missing or out of
 * range (hand-edited row) falls back to the default for that field.
 */
export function effectiveRiskRules(stored: unknown): RiskRulesConfig {
  const result: RiskRulesConfig = structuredClone(DEFAULT_RISK_RULES);
  if (!stored || typeof stored !== "object" || Array.isArray(stored)) return result;
  const source = stored as Record<string, unknown>;
  for (const rule of Object.keys(DEFAULT_RISK_RULES) as (keyof RiskRulesConfig)[]) {
    const values = source[rule];
    if (!values || typeof values !== "object") continue;
    const limits = RISK_RULE_LIMITS[rule] as Record<string, readonly [number, number]>;
    const target = result[rule] as Record<string, number>;
    for (const field of Object.keys(target)) {
      const v = (values as Record<string, unknown>)[field];
      const [min, max] = limits[field];
      if (typeof v === "number" && Number.isInteger(v) && v >= min && v <= max) target[field] = v;
    }
  }
  return result;
}

/** [current] with [patch] applied. Pure. */
export function mergeRiskRules(current: RiskRulesConfig, patch: RiskRulesPatch): RiskRulesConfig {
  const next: RiskRulesConfig = structuredClone(current);
  for (const rule of Object.keys(patch) as (keyof RiskRulesConfig)[]) {
    Object.assign(next[rule], patch[rule]);
  }
  return next;
}

// ── Rule inputs ────────────────────────────────────────────────────────

export interface RiskLocation {
  latitude: number;
  longitude: number;
  capturedAt: Date;
}

/**
 * Which phone a key belongs to, for the device rules (F-15): the stable
 * device id the SDK sent at registration (hashed ANDROID_ID, survives a
 * reinstall), else the key id. A reinstall gets a new key but keeps the
 * device id, so it is not a "new device" for its accounts. The id comes from
 * the device and proves nothing on its own; the key and its attestation do.
 */
export function deviceIdentityOf(x: { deviceKeyId: string; deviceIdentity?: string }): string {
  return x.deviceIdentity ?? x.deviceKeyId;
}

/** The event being evaluated (already verified and not a replay). */
export interface RiskEventFacts {
  type: "session" | "transaction";
  deviceKeyId: string;
  /** See [deviceIdentityOf]. */
  deviceIdentity?: string;
  accountHash: string;
  sessionHash: string;
  sessionEvent?: "login" | "resume" | "logout";
  beneficiaryHash?: string;
  eventTime: Date;
  receivedAt: Date;
  location: RiskLocation | null;
  ipCountry: string | null;
}

/** What the store already knows about this account, before this event. */
export interface AccountHistory {
  /** Devices bound to the account (firstSeenAt = server time it was first seen). */
  bindings: { deviceKeyId: string; deviceIdentity?: string; firstSeenAt: Date }[];
  /** Session events of the account with eventTime in the concurrent-sessions window. */
  recentSessions: { deviceKeyId: string; deviceIdentity?: string; sessionHash: string; sessionEvent: string; eventTime: Date }[];
  /** Latest earlier event (session or transaction) of the account with a location. */
  lastLocated: { location: RiskLocation; deviceKeyId: string } | null;
  /** Latest earlier event of the account with a known request-IP country. */
  lastIpCountry: { country: string; receivedAt: Date; deviceKeyId: string } | null;
  /** Transactions of the account with eventTime in the velocity window, before this one. */
  recentTransactionCount: number;
  /** The beneficiary was used by this account before. */
  beneficiarySeenBefore: boolean;
}

/** Which windows the repository must load history for. */
export function historyWindows(rules: RiskRulesConfig) {
  return {
    concurrentSessionsMinutes: rules.concurrentSessions.windowMinutes,
    transactionVelocityMinutes: rules.transactionVelocity.windowMinutes,
  };
}

export interface RiskFinding {
  rule: RiskRuleId;
  severity: RiskSeverity;
  explanation: string;
  evidence: Record<string, string | number>;
}

/** First 12 hex characters — enough to tell hashes apart on screen. */
export function shortHash(hash: string): string {
  return hash.slice(0, 12);
}

const MINUTE_MS = 60_000;

/** Great-circle distance in km (haversine, mean Earth radius). */
export function distanceKm(a: { latitude: number; longitude: number }, b: { latitude: number; longitude: number }): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(b.latitude - a.latitude);
  const dLon = toRad(b.longitude - a.longitude);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(a.latitude)) * Math.cos(toRad(b.latitude)) * Math.sin(dLon / 2) ** 2;
  return 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(h)));
}

const finding = (rule: RiskRuleId, explanation: string, evidence: Record<string, string | number>): RiskFinding =>
  ({ rule, severity: RULE_SEVERITY[rule], explanation, evidence });

/**
 * Evaluates every rule for one event. Pure: same inputs, same findings.
 *
 * - new_device_for_account: the account already has at least one device and
 *   this device is not one of them (an account's very first device is
 *   enrolment, not a change).
 * - device_change_velocity: on a new device, more than maxDevices distinct
 *   devices first seen for the account within windowMinutes (this one included).
 * - concurrent_sessions: on login/resume, more than maxDevices devices with a
 *   session whose latest event in the window is login/resume (not logout).
 * - impossible_travel: opted-in locations of this and the account's previous
 *   located event imply a speed above maxSpeedKmh — only when they are at
 *   least minMinutes and minDistanceKm apart. Without a location pair: the
 *   request-IP country changed within ipCountryChangeMinutes (but not
 *   sooner than minMinutes); weak evidence, see the file doc.
 * - transaction_velocity: more than maxCount transactions of the account
 *   within windowMinutes (this one included).
 * - new_beneficiary: the account never sent to this beneficiary before.
 */
export function evaluateRiskRules(event: RiskEventFacts, history: AccountHistory, rules: RiskRulesConfig): RiskFinding[] {
  const findings: RiskFinding[] = [];
  const account = shortHash(event.accountHash);
  const thisDevice = deviceIdentityOf(event);
  const knownDevices = new Set(history.bindings.map(deviceIdentityOf));
  const isNewDevice = !knownDevices.has(thisDevice);

  if (isNewDevice && knownDevices.size > 0) {
    findings.push(finding(
      "new_device_for_account",
      `Account ${account}… used a device it has not used before (${knownDevices.size} known device${knownDevices.size === 1 ? "" : "s"}).`,
      { account_hash: account, known_devices: knownDevices.size },
    ));
  }

  if (isNewDevice) {
    const { maxDevices, windowMinutes } = rules.deviceChangeVelocity;
    const since = event.receivedAt.getTime() - windowMinutes * MINUTE_MS;
    const recent = new Set(history.bindings.filter((b) => b.firstSeenAt.getTime() >= since).map(deviceIdentityOf));
    recent.add(thisDevice);
    if (recent.size > maxDevices) {
      findings.push(finding(
        "device_change_velocity",
        `Account ${account}… was used from ${recent.size} new devices within ${windowMinutes} minutes (limit ${maxDevices}).`,
        { account_hash: account, devices_in_window: recent.size, max_devices: maxDevices, window_minutes: windowMinutes },
      ));
    }
  }

  if (event.type === "session" && (event.sessionEvent === "login" || event.sessionEvent === "resume")) {
    const { maxDevices, windowMinutes } = rules.concurrentSessions;
    const since = event.eventTime.getTime() - windowMinutes * MINUTE_MS;
    const latestPerSession = new Map<string, { deviceKeyId: string; sessionEvent: string; time: number }>();
    for (const s of history.recentSessions) {
      const time = s.eventTime.getTime();
      if (time < since || time > event.eventTime.getTime()) continue;
      const key = `${deviceIdentityOf(s)}|${s.sessionHash}`;
      const prev = latestPerSession.get(key);
      if (!prev || time >= prev.time) latestPerSession.set(key, { deviceKeyId: deviceIdentityOf(s), sessionEvent: s.sessionEvent, time });
    }
    const activeDevices = new Set<string>([thisDevice]);
    for (const s of latestPerSession.values()) {
      if (s.sessionEvent === "login" || s.sessionEvent === "resume") activeDevices.add(s.deviceKeyId);
    }
    if (activeDevices.size > maxDevices) {
      findings.push(finding(
        "concurrent_sessions",
        `Account ${account}… has active sessions on ${activeDevices.size} devices within ${windowMinutes} minutes (limit ${maxDevices}).`,
        { account_hash: account, active_devices: activeDevices.size, max_devices: maxDevices, window_minutes: windowMinutes },
      ));
    }
  }

  const travel = impossibleTravel(event, history, rules.impossibleTravel);
  if (travel) findings.push(travel);

  if (event.type === "transaction") {
    const { maxCount, windowMinutes } = rules.transactionVelocity;
    const count = history.recentTransactionCount + 1;
    if (count > maxCount) {
      findings.push(finding(
        "transaction_velocity",
        `Account ${account}… made ${count} transactions within ${windowMinutes} minutes (limit ${maxCount}).`,
        { account_hash: account, transactions_in_window: count, max_count: maxCount, window_minutes: windowMinutes },
      ));
    }
    if (event.beneficiaryHash && !history.beneficiarySeenBefore) {
      const beneficiary = shortHash(event.beneficiaryHash);
      findings.push(finding(
        "new_beneficiary",
        `Account ${account}… sent to a beneficiary (${beneficiary}…) it has not used before.`,
        { account_hash: account, beneficiary_hash: beneficiary },
      ));
    }
  }

  return findings;
}

function impossibleTravel(
  event: RiskEventFacts,
  history: AccountHistory,
  rules: RiskRulesConfig["impossibleTravel"],
): RiskFinding | null {
  const account = shortHash(event.accountHash);

  if (event.location && history.lastLocated) {
    const previous = history.lastLocated.location;
    const minutes = (event.location.capturedAt.getTime() - previous.capturedAt.getTime()) / MINUTE_MS;
    const km = distanceKm(previous, event.location);
    // Location pair available: decided by it alone (no IP fallback).
    if (minutes < rules.minMinutes || km < rules.minDistanceKm) return null;
    const speed = km / (minutes / 60);
    if (speed <= rules.maxSpeedKmh) return null;
    return finding(
      "impossible_travel",
      `Account ${account}… appeared ${Math.round(km)} km away ${Math.round(minutes)} minutes after its previous location (≈${Math.round(speed)} km/h, limit ${rules.maxSpeedKmh} km/h).`,
      {
        account_hash: account,
        basis: "location",
        distance_km: Math.round(km),
        minutes: Math.round(minutes),
        speed_kmh: Math.round(speed),
        max_speed_kmh: rules.maxSpeedKmh,
      },
    );
  }

  if (rules.ipCountryChangeMinutes > 0 && event.ipCountry && history.lastIpCountry) {
    const previous = history.lastIpCountry;
    if (previous.country === event.ipCountry) return null;
    const minutes = (event.receivedAt.getTime() - previous.receivedAt.getTime()) / MINUTE_MS;
    if (minutes < rules.minMinutes || minutes > rules.ipCountryChangeMinutes) return null;
    return finding(
      "impossible_travel",
      `Account ${account}… connected from ${event.ipCountry} ${Math.round(minutes)} minutes after connecting from ${previous.country} (request IP country; a VPN or mobile roaming can also cause this).`,
      {
        account_hash: account,
        basis: "ip_country",
        from_country: previous.country,
        to_country: event.ipCountry,
        minutes: Math.round(minutes),
        window_minutes: rules.ipCountryChangeMinutes,
      },
    );
  }
  return null;
}
