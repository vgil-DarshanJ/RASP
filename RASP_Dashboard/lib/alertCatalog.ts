/**
 * Canonical metadata for every detector this project's SDK ships — a
 * human-readable name, category, and default severity for a raw
 * `detectorId` string, the way Amplitude/WebEngage give a raw event key
 * ("btn_click_v2") a display name and a type. Presentation only: never
 * sent to or required by the backend, which stores/accepts detectorId as
 * a free-form string on purpose (see BE ingestion schema's own doc) so a
 * new detector never needs a schema migration to ship — it just shows up
 * here as "Other" until someone adds a catalog entry.
 *
 * Kept in sync by hand with `RaspLeanConfig`/`RaspLeanSession` in both
 * `sdk_rasp/flutter/rasp_shield_sdk/lib/sdk/lean_session.dart` (Flutter)
 * and `sdk_rasp/android_native/rasp_shield_native/.../RaspLeanSession.kt`
 * (native Android) — every detectorId, title, category and severity below
 * matches those two files (and `RaspShieldCore`'s own internal ids)
 * exactly, so a log looks identical regardless of which platform shipped
 * it.
 */

export type AlertCategory =
  | "Privacy & Screen"
  | "Device Integrity"
  | "Runtime Protection"
  | "App Integrity"
  | "Network Security"
  | "Other";

export interface AlertCatalogEntry {
  title: string;
  category: AlertCategory;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

export const ALERT_CATALOG: Record<string, AlertCatalogEntry> = {
  // ── Original 4 lean controls ─────────────────────────────────────────
  screenshot_protection: {
    title: "Screenshot & Video Block",
    category: "Privacy & Screen",
    severity: "medium",
    description: "FLAG_SECURE screenshot/screen-recording protection state.",
  },
  screenshot_event: {
    title: "Screenshot Taken",
    category: "Privacy & Screen",
    severity: "medium",
    description:
      "A real screenshot was just taken — distinct from screenshot_protection " +
      "(which reports whether blocking is active, never whether an attempt " +
      "happened). Android 14 (API 34) and above only.",
  },
  clipboard_protection: {
    title: "Clipboard Protection",
    category: "Privacy & Screen",
    severity: "low",
    description: "Whether the clipboard auto-clear guard is active.",
  },
  usb_connection: {
    title: "USB Connection",
    category: "Device Integrity",
    severity: "low",
    description: "Physical USB cable/dock connection state.",
  },
  adb_enabled: {
    title: "USB Debugging (ADB)",
    category: "Device Integrity",
    severity: "medium",
    description: "Whether ADB is enabled in Developer Options.",
  },

  // ── Device integrity ──────────────────────────────────────────────────
  root_jailbreak: {
    title: "Root / Jailbreak",
    category: "Device Integrity",
    severity: "critical",
    description: "Superuser binaries, root managers, and jailbreak artefacts.",
  },
  emulator: {
    title: "Emulator Detection",
    category: "Device Integrity",
    severity: "medium",
    description: "QEMU/VirtualBox artefacts and generic hardware identifiers.",
  },
  device_binding: {
    title: "Device Binding",
    category: "Device Integrity",
    severity: "high",
    description: "A hardware-backed Keystore key tying this install to this device.",
  },
  clone: {
    title: "App Clone / Dual Space",
    category: "Device Integrity",
    severity: "high",
    description: "Cloning containers and abnormal data paths used to run a second copy of the app.",
  },
  developer_mode: {
    title: "Developer Mode",
    category: "Device Integrity",
    severity: "low",
    description: "Whether Developer options have been unlocked.",
  },
  device_lock_missing: {
    title: "Device Lock",
    category: "Device Integrity",
    severity: "medium",
    description: "Whether a PIN, pattern, password, or biometric lock is configured.",
  },
  secure_hardware_unavailable: {
    title: "Hardware-Backed Keystore",
    category: "Device Integrity",
    severity: "low",
    description: "Whether a Trusted Execution Environment or StrongBox is available.",
  },
  device_fingerprint: {
    title: "Device Fingerprint",
    category: "Device Integrity",
    severity: "medium",
    description: "Screen lock, USB debugging, SELinux state, install source and hardware identity drift.",
  },

  // ── Runtime protection ────────────────────────────────────────────────
  frida: {
    title: "Frida / Instrumentation",
    category: "Runtime Protection",
    severity: "critical",
    description: "The Frida server, injected agents, and instrumentation artefacts.",
  },
  debugger: {
    title: "Debugger Attached",
    category: "Runtime Protection",
    severity: "medium",
    description: "Whether the app is a debug build or has a debugger attached.",
  },
  re_tools: {
    title: "Reverse-Engineering Tools",
    category: "Runtime Protection",
    severity: "high",
    description: "Xposed/LSPosed, Magisk, Lucky Patcher, GameGuardian and similar.",
  },
  hook_detection: {
    title: "Hooking / Method Interception",
    category: "Runtime Protection",
    severity: "critical",
    description: "Resident hooking frameworks and writable+executable memory.",
  },
  risky_app: {
    title: "Risky Application / Environment",
    category: "Other",
    severity: "high",
    description: "Known remote-access/instrumentation packages, or an active third-party accessibility service.",
  },

  // ── App integrity ─────────────────────────────────────────────────────
  tamper: {
    title: "App Tampering",
    category: "App Integrity",
    severity: "high",
    description: "Whether the app has been modified from its original signed package.",
  },
  untrusted_install_source: {
    title: "Installation Source",
    category: "App Integrity",
    severity: "high",
    description: "Whether the installing package is an official app store.",
  },
  repackage: {
    title: "Signature / Repackaging",
    category: "App Integrity",
    severity: "high",
    description: "Whether this build is signed by the expected certificate.",
  },

  // ── Network security ──────────────────────────────────────────────────
  vpn: {
    title: "VPN Connection",
    category: "Network Security",
    severity: "low",
    description: "Whether traffic is routed through a VPN tunnel or tun/ppp/tap interface.",
  },
  mitm: {
    title: "SSL / MITM Detection",
    category: "Network Security",
    severity: "high",
    description: "System proxies and certificate-pinning failures indicating traffic interception.",
  },
  high_risk_ip: {
    title: "IP Reputation",
    category: "Network Security",
    severity: "medium",
    description: "Whether the public IP falls in a high-risk region or known proxy/anonymizer range.",
  },

  // ── Privacy & screen ──────────────────────────────────────────────────
  overlay: {
    title: "Overlay Attack",
    category: "Privacy & Screen",
    severity: "medium",
    description: "Other apps drawing over this one via SYSTEM_ALERT_WINDOW (tapjacking).",
  },
  accessibility: {
    title: "Accessibility Abuse",
    category: "Privacy & Screen",
    severity: "medium",
    description: "Third-party accessibility services that can read screen content and act on the user's behalf.",
  },
  external_display: {
    title: "External Display / Mirroring",
    category: "Privacy & Screen",
    severity: "medium",
    description: "A connected external, wireless, or presentation display — a possible screen-mirroring surface.",
  },

  // ── Task 3a ────────────────────────────────────────────────────────────
  mock_location: {
    title: "Mock Location",
    category: "Device Integrity",
    severity: "high",
    description:
      "The location the app supplied is marked by Android as a mock (fake GPS) fix. Evaluated only when the app passes a location.",
  },
  time_spoofing: {
    title: "Time Spoofing",
    category: "Device Integrity",
    severity: "medium",
    description:
      "At least two of: wall clock jumped against the monotonic clock, clock far from server time, automatic time turned off.",
  },
  unsafe_wifi: {
    title: "Unsafe Wi-Fi",
    category: "Network Security",
    severity: "medium",
    description: "Connected to an open (unencrypted) or WEP Wi-Fi network, or one behind a captive portal.",
  },
  screen_recording: {
    title: "Screen Recording",
    category: "Privacy & Screen",
    severity: "high",
    description: "This app's screens are visible in an active screen recording. Android 15 (API 35) and above only.",
  },
};

export const CATEGORY_COLORS: Record<AlertCategory, { bg: string; text: string; dot: string }> = {
  "Privacy & Screen": { bg: "bg-violet-50", text: "text-violet-700", dot: "bg-violet-500" },
  "Device Integrity": { bg: "bg-amber-50", text: "text-amber-700", dot: "bg-amber-500" },
  "Runtime Protection": { bg: "bg-red-50", text: "text-red-700", dot: "bg-red-500" },
  "App Integrity": { bg: "bg-blue-50", text: "text-blue-700", dot: "bg-blue-500" },
  "Network Security": { bg: "bg-cyan-50", text: "text-cyan-700", dot: "bg-cyan-500" },
  Other: { bg: "bg-ink-100", text: "text-ink-600", dot: "bg-ink-400" },
};

export function catalogFor(detectorId: string): AlertCatalogEntry {
  return (
    ALERT_CATALOG[detectorId] ?? {
      title: detectorId,
      category: "Other",
      severity: "low",
      description: "",
    }
  );
}

export const ALL_CATEGORIES: AlertCategory[] = [
  "Privacy & Screen",
  "Device Integrity",
  "Runtime Protection",
  "App Integrity",
  "Network Security",
  "Other",
];
