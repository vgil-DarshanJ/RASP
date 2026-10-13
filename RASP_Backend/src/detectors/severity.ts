/**
 * Canonical severity/weight for every detectorId — the single source
 * (F-26). `npm run export:severities -- <file>...` writes it as JSON for the
 * dashboard (FE/lib/detectorSeverities.json) and the Flutter plugin
 * (test/fixtures/detector_severities.json); their tests fail when
 * alertCatalog.ts or the Dart descriptors disagree with that copy, or the
 * copy with this table. After a change here, export again.
 *
 * `weight` drives [scoreForDetections] below — our own risk-scoring
 * methodology, not a reproduction of any vendor's proprietary formula.
 * Points added per currently-DETECTED detector, capped at 100:
 *   critical → 40, high → 25, medium → 12, low → 5
 * A detector the device has never reported (or that came back
 * UNAVAILABLE/UNKNOWN/ERROR) contributes 0 — silence is not evidence of
 * safety, so it must never inflate a score, only a real DETECTED does.
 */
export type DetectorSeverity = "critical" | "high" | "medium" | "low";

const WEIGHT_BY_SEVERITY: Record<DetectorSeverity, number> = {
  critical: 40,
  high: 25,
  medium: 12,
  low: 5,
};

export const DETECTOR_SEVERITY: Record<string, DetectorSeverity> = {
  // Original 4 lean controls
  screenshot_protection: "medium",
  clipboard_protection: "low",
  usb_connection: "low",
  adb_enabled: "medium",
  // Screenshot-event detection (v1.0.3, API 34+ only) — distinct from
  // screenshot_protection above.
  screenshot_event: "medium",

  // Device integrity
  root_jailbreak: "critical",
  emulator: "medium",
  device_binding: "high",
  clone: "high",
  developer_mode: "low",
  device_lock_missing: "medium",
  secure_hardware_unavailable: "low",
  device_fingerprint: "medium",

  // Runtime protection
  frida: "critical",
  debugger: "medium",
  re_tools: "high",
  hook_detection: "critical",
  risky_app: "high",

  // App integrity
  tamper: "high",
  // Raised by the backend (ingestion/tamperAlerts.ts) when a reported
  // signing certificate differs from the expected one.
  tamper_signing_mismatch: "high",
  untrusted_install_source: "high",
  repackage: "high",

  // Network security
  vpn: "low",
  mitm: "high",
  high_risk_ip: "medium",

  // Privacy & screen
  overlay: "medium",
  accessibility: "medium",
  external_display: "medium",

  // Task 3a — location, time, network, screen
  mock_location: "high",
  time_spoofing: "medium",
  unsafe_wifi: "medium",
  screen_recording: "high",

  // Task 3b — fraud-pattern signals
  vishing_call: "high",
  sim_change: "high",
  third_party_keyboard: "medium",
  task_hijack: "high",

  // Task 3c — attested device state, known malware
  device_state_attestation: "high",
  malware_reputation: "critical",

  // Task 8.1 — OTP / remote-control / screen-sharing signals (SDK)
  otp_interception_risk: "high",
  sms_reader_abuse: "high",
  otp_forwarding_risk: "medium",
  remote_control_app: "high",
  screen_sharing_risk: "high",

  // Task 10.0 — the SDK refused a remote configuration (bad signature,
  // rollback, expired or invalid): a forged or replayed config, or a MITM.
  remote_config_rejected: "high",

  // Task 8.1 — fraud-risk rules raised by the backend (risk/rules.ts)
  new_device_for_account: "medium",
  device_change_velocity: "high",
  concurrent_sessions: "medium",
  impossible_travel: "high",
  transaction_velocity: "high",
  new_beneficiary: "low",
};

export function severityOf(detectorId: string): DetectorSeverity {
  return DETECTOR_SEVERITY[detectorId] ?? "low";
}

export function weightOf(detectorId: string): number {
  return WEIGHT_BY_SEVERITY[severityOf(detectorId)];
}

export type RiskLevel = "low" | "medium" | "high" | "critical";

/** Maps a capped 0-100 score to a display band — thresholds chosen so a
 *  single critical detector (40 pts) alone already reads as at least
 *  "high", matching the intuition that one confirmed critical threat
 *  (root, Frida, hooking) should never be shown as merely "medium risk." */
export function riskLevelForScore(score: number): RiskLevel {
  if (score >= 70) return "critical";
  if (score >= 40) return "high";
  if (score >= 15) return "medium";
  return "low";
}

/**
 * Computes a 0-100 risk score from a map of detectorId -> latest status.
 * Only `"DETECTED"` statuses contribute points; every other status
 * (SECURE/UNAVAILABLE/UNKNOWN/ERROR) contributes nothing, on purpose —
 * see this file's class doc for why "unknown" must never read as "risk."
 */
export function scoreForLatestStatuses(latestStatusByDetector: Record<string, string>): number {
  let total = 0;
  for (const [detectorId, status] of Object.entries(latestStatusByDetector)) {
    if (status === "DETECTED") total += weightOf(detectorId);
  }
  return Math.min(100, total);
}

/** Which detectors (of those DETECTED) contributed to a score, heaviest
 *  first — powers the "why is this risky" breakdown in the UI. */
const SEVERITY_RANK: Record<DetectorSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** `true` when `severity` is at or above `threshold` — e.g. a `critical`
 *  detection meets a `high` threshold, but a `medium` one does not. Used
 *  by webhook alerting to decide whether a DETECTED event is worth
 *  paging someone about. */
export function meetsSeverityThreshold(severity: DetectorSeverity, threshold: DetectorSeverity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}

export function contributingDetectors(
  latestStatusByDetector: Record<string, string>,
): Array<{ detectorId: string; severity: DetectorSeverity; weight: number }> {
  return Object.entries(latestStatusByDetector)
    .filter(([, status]) => status === "DETECTED")
    .map(([detectorId]) => ({
      detectorId,
      severity: severityOf(detectorId),
      weight: weightOf(detectorId),
    }))
    .sort((a, b) => b.weight - a.weight);
}
