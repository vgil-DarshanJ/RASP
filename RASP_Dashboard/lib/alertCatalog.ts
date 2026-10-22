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
  | "Fraud Risk"
  | "Other";

export interface AlertCatalogEntry {
  title: string;
  category: AlertCategory;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

export const ALERT_CATALOG: Record<string, AlertCatalogEntry> = {
  remote_config_rejected: {
    title: "Remote Config Rejected",
    category: "App Integrity",
    severity: "high",
    description:
      "The app refused a signed remote configuration (bad signature, wrong app, expired " +
      "or rolled back) and kept the last good one.",
  },

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
  tamper_signing_mismatch: {
    title: "Signing Certificate Mismatch",
    category: "App Integrity",
    severity: "high",
    description:
      "Raised by the backend: a device reported a signing certificate other than the one set in " +
      "Security Settings, so this copy of the app was re-signed (repackaged).",
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

  // ── Task 3b ────────────────────────────────────────────────────────────
  vishing_call: {
    title: "Call During App Use",
    category: "Privacy & Screen",
    severity: "high",
    description:
      "A phone call was ringing or in progress while the app was in the foreground — the usual pattern of voice-phishing (vishing) fraud. Telephony calls only; VoIP calls are not seen.",
  },
  sim_change: {
    title: "SIM Change",
    category: "Device Integrity",
    severity: "high",
    description:
      "The set of SIM cards differs from the one recorded earlier (possible SIM swap). Stays reported until the app acknowledges it after re-verifying the customer. No phone number or IMEI is collected.",
  },
  third_party_keyboard: {
    title: "Third-party Keyboard",
    category: "Privacy & Screen",
    severity: "medium",
    description:
      "The active keyboard is neither a system keyboard nor an allowlisted one installed from Google Play. A keyboard sees every key typed.",
  },
  task_hijack: {
    title: "Task Hijacking",
    category: "App Integrity",
    severity: "high",
    description:
      "Another installed app declares this app's task affinity, so its screens can appear inside this app's task (fake login screens).",
  },

  // ── Task 3c ────────────────────────────────────────────────────────────
  device_state_attestation: {
    title: "Device State Attestation",
    category: "Device Integrity",
    severity: "high",
    description:
      "The hardware key attestation reports an unlocked bootloader or unverified/failed verified boot (or, if configured, an outdated security patch). Read on the device; the backend check against Google's attestation roots is still to come.",
  },
  malware_reputation: {
    title: "Known Malware Installed",
    category: "Device Integrity",
    severity: "critical",
    description:
      "An installed app is on the signed malware reputation list the app was configured with. Evidence names the package, category and severity from the list.",
  },

  // ── Task 8.1 — OTP, remote control, screen sharing (SDK) ──────────────
  otp_interception_risk: {
    title: "OTP Interception Risk",
    category: "Privacy & Screen",
    severity: "high",
    description:
      "Conditions under which a one-time passcode could be read by something other than the customer (for example an app that can read incoming SMS together with another risk signal). No SMS content is collected.",
  },
  sms_reader_abuse: {
    title: "SMS Reader Apps",
    category: "Privacy & Screen",
    severity: "high",
    description:
      "Other installed apps hold permission to read incoming SMS, so they could read OTPs. Reports package names only, never messages, contacts or phone numbers.",
  },
  otp_forwarding_risk: {
    title: "OTP Forwarding Risk (hint)",
    category: "Privacy & Screen",
    severity: "medium",
    description:
      "A hint that OTPs may be forwarded off the device (for example an app that can both read and send SMS). A hint only: legitimate apps can hold the same permissions.",
  },
  remote_control_app: {
    title: "Remote Control App",
    category: "Privacy & Screen",
    severity: "high",
    description:
      "A remote-access / remote-control app is installed or active, the usual tool in screen-sharing fraud where a caller operates the customer's phone.",
  },
  screen_sharing_risk: {
    title: "Screen Sharing During App Use",
    category: "Privacy & Screen",
    severity: "high",
    description:
      "The screen appears to be shared or mirrored while the app is in use, so someone else may be watching balances, OTPs or card details.",
  },

  // ── Task 8.1 — fraud-risk rules (raised by the backend) ───────────────
  new_device_for_account: {
    title: "New Device for Account",
    category: "Fraud Risk",
    severity: "medium",
    description:
      "An account (hashed id) was used from a device it had not used before. The account's first device is not reported.",
  },
  device_change_velocity: {
    title: "Device Change Velocity",
    category: "Fraud Risk",
    severity: "high",
    description:
      "An account was used from more new devices than the application's limit within its time window (default: more than 3 in 24 hours).",
  },
  concurrent_sessions: {
    title: "Concurrent Sessions",
    category: "Fraud Risk",
    severity: "medium",
    description:
      "An account has active sessions (login/resume without logout) on more devices than the application's limit within its window (default: more than 2 in 30 minutes).",
  },
  impossible_travel: {
    title: "Impossible Travel",
    category: "Fraud Risk",
    severity: "high",
    description:
      "Two events of one account are too far apart for the time between them: opted-in locations implying more than 900 km/h (default), or the request-IP country changing within 60 minutes — which a VPN or roaming can also cause.",
  },
  transaction_velocity: {
    title: "Transaction Velocity",
    category: "Fraud Risk",
    severity: "high",
    description:
      "An account made more transactions than the application's limit within its window (default: more than 5 in 10 minutes). Amounts are never sent.",
  },
  new_beneficiary: {
    title: "New Beneficiary",
    category: "Fraud Risk",
    severity: "low",
    description: "An account sent to a beneficiary (hashed id) it had not used before.",
  },
};

export const CATEGORY_COLORS: Record<AlertCategory, { bg: string; text: string; dot: string }> = {
  "Privacy & Screen": { bg: "bg-violet-50", text: "text-violet-700", dot: "bg-violet-500" },
  "Device Integrity": { bg: "bg-amber-50", text: "text-amber-700", dot: "bg-amber-500" },
  "Runtime Protection": { bg: "bg-red-50", text: "text-red-700", dot: "bg-red-500" },
  "App Integrity": { bg: "bg-blue-50", text: "text-blue-700", dot: "bg-blue-500" },
  "Network Security": { bg: "bg-cyan-50", text: "text-cyan-700", dot: "bg-cyan-500" },
  "Fraud Risk": { bg: "bg-rose-50", text: "text-rose-700", dot: "bg-rose-500" },
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
  "Fraud Risk",
  "Other",
];
