/**
 * The Mobile App Controls self-assessment: what a mobile banking team should
 * have in place, grouped into three pillars. `coveredBy` names the detector
 * ids (or console features) of this product that help with a control — a
 * hint, never a claim that the control is met. Answers are the customer's
 * own and are kept in their browser (see app/(app)/controls/page.tsx).
 */

export type Priority = "P0" | "P1" | "P2";

export interface Control {
  id: string;
  topic: string;
  consider: string;
  why: string;
  how: string;
  masvs: string;
  priority: Priority;
  frameworks: string;
  coveredBy?: string[];
}

export interface ControlSection {
  id: string;
  title: string;
  controls: Control[];
}

export interface Pillar {
  id: "mobile" | "dev" | "server";
  title: string;
  subtitle: string;
  sections: ControlSection[];
}

export const PILLARS: Pillar[] = [
  {
    id: "mobile",
    title: "Mobile App Controls",
    subtitle: "What runs on the customer's phone",
    sections: [
      {
        id: "privacy",
        title: "User Privacy and Awareness",
        controls: [
          { id: "m-priv-1", topic: "Privacy notice and consent", consider: "Readability, consent granularity.", why: "Required by data-protection law; missing consent means fines and store removal.", how: "Show the privacy notice before collecting data, get explicit consent, document retention.", masvs: "MASVS-PRIVACY-3", priority: "P0", frameworks: "DPDP, GDPR" },
          { id: "m-priv-2", topic: "Explain detected risks to users", consider: "Message clarity, next step for the user.", why: "Users who understand a warning fix the cause far more often.", how: "Show a plain-language summary when a risk is found, with what to do.", masvs: "MASVS-PRIVACY-3", priority: "P2", frameworks: "MASVS", coveredBy: ["device_fingerprint"] },
          { id: "m-priv-3", topic: "Device misconfiguration guidance", consider: "User education, required action.", why: "No screen lock or USB debugging on weakens every other control.", how: "Detect missing screen lock, USB debugging, outdated OS; tell the user how to fix it.", masvs: "MASVS-PLATFORM-1", priority: "P1", frameworks: "RBI guidance", coveredBy: ["device_lock_missing", "adb_enabled", "developer_mode"] },
        ],
      },
      {
        id: "screen",
        title: "Screen and Display Protection",
        controls: [
          { id: "m-scr-1", topic: "Block screenshots of sensitive screens", consider: "Which screens, accessibility impact.", why: "Screenshots of balances and OTPs leak through galleries and cloud backups.", how: "Set FLAG_SECURE on sensitive screens.", masvs: "MASVS-PLATFORM-3", priority: "P1", frameworks: "MASVS", coveredBy: ["screenshot_protection", "screenshot_event"] },
          { id: "m-scr-2", topic: "Detect screen sharing, casting and recording", consider: "Response: warn, pause or end the session.", why: "Screen-share scams let a fraudster watch the victim type credentials.", how: "Detect mirroring, recording and sharing; warn and step up before payments.", masvs: "MASVS-PLATFORM-3", priority: "P0", frameworks: "MASVS, RBI fraud advisories", coveredBy: ["external_display", "screen_recording", "screen_sharing_risk"] },
          { id: "m-scr-3", topic: "Overlay and tapjacking protection", consider: "Sensitive buttons, filterTouchesWhenObscured.", why: "Overlays trick users into approving actions they cannot see.", how: "Ignore obscured touches on confirm buttons; detect overlays.", masvs: "MASVS-PLATFORM-3", priority: "P1", frameworks: "MASVS", coveredBy: ["overlay"] },
        ],
      },
      {
        id: "malware",
        title: "Malware and Remote-Access Detection",
        controls: [
          { id: "m-mal-1", topic: "Known malicious apps", consider: "List freshness, signed list delivery.", why: "Banking trojans sit on the same phone as the app.", how: "Compare installed apps with a signed, regularly updated list.", masvs: "MASVS-RESILIENCE-1", priority: "P1", frameworks: "MASVS", coveredBy: ["malware_reputation", "risky_app"] },
          { id: "m-mal-2", topic: "Remote-control and accessibility abuse", consider: "False positives from legitimate assistive apps.", why: "Remote-access scams drive the session on the victim's phone.", how: "Detect remote-control apps and accessibility services that can tap.", masvs: "MASVS-PLATFORM-1", priority: "P0", frameworks: "RBI fraud advisories", coveredBy: ["remote_control_app", "accessibility"] },
          { id: "m-mal-3", topic: "OTP interception risk", consider: "Notification listeners, SMS readers, forwarders.", why: "A stolen OTP defeats the second factor.", how: "Detect apps that can read notifications or SMS, or forward them.", masvs: "MASVS-AUTH-2", priority: "P1", frameworks: "MASVS", coveredBy: ["otp_interception_risk", "sms_reader_abuse", "otp_forwarding_risk"] },
          { id: "m-mal-4", topic: "Call during sensitive actions", consider: "When to warn: login, payee add, transfer.", why: "Vishing fraudsters talk the victim through a transfer.", how: "Detect an active call and add friction to payments.", masvs: "MASVS-PLATFORM-1", priority: "P1", frameworks: "RBI fraud advisories", coveredBy: ["vishing_call"] },
        ],
      },
      {
        id: "storage",
        title: "Secure Storage",
        controls: [
          { id: "m-sto-1", topic: "Keys in secure hardware", consider: "TEE vs StrongBox, fallback on old phones.", why: "Keys in software can be copied off the device.", how: "Generate keys in Android Keystore; check hardware backing.", masvs: "MASVS-STORAGE-1", priority: "P0", frameworks: "MASVS", coveredBy: ["secure_hardware_unavailable", "device_binding"] },
          { id: "m-sto-2", topic: "No secrets in logs, backups or clipboard", consider: "Debug logging, allowBackup, copy actions.", why: "Leaked data in logs and backups is the easiest exfiltration path.", how: "Strip logs in release, disable backup of sensitive files, clear clipboard.", masvs: "MASVS-STORAGE-2", priority: "P1", frameworks: "MASVS", coveredBy: ["clipboard_protection"] },
        ],
      },
      {
        id: "runtime",
        title: "Runtime App Protection",
        controls: [
          { id: "m-run-1", topic: "Instrumentation and hooking detection", consider: "Response policy, native vs managed checks.", why: "Hooks change what the app does: skip checks, alter amounts.", how: "Detect instrumentation toolkits and hooks; report and react.", masvs: "MASVS-RESILIENCE-4", priority: "P0", frameworks: "MASVS", coveredBy: ["frida", "hook_detection"] },
          { id: "m-run-2", topic: "Debugger detection", consider: "Debug builds, release flags.", why: "A debugger reads memory and changes control flow.", how: "Detect attached debuggers and debuggable builds.", masvs: "MASVS-RESILIENCE-4", priority: "P1", frameworks: "MASVS", coveredBy: ["debugger", "re_tools"] },
          { id: "m-run-3", topic: "Tamper and repackaging detection", consider: "Expected signing certificate, server-side check.", why: "Repackaged apps carry malware under your brand.", how: "Verify the signing certificate on the device and on the server.", masvs: "MASVS-RESILIENCE-2", priority: "P0", frameworks: "MASVS", coveredBy: ["tamper", "repackage", "untrusted_install_source"] },
        ],
      },
      {
        id: "device",
        title: "Runtime OS / Environment / Device Controls",
        controls: [
          { id: "m-dev-1", topic: "Root and emulator detection", consider: "Response: warn, limit, block.", why: "Root removes app isolation; emulators drive automated fraud.", how: "Detect root signals and emulators; decide per action.", masvs: "MASVS-RESILIENCE-1", priority: "P0", frameworks: "MASVS, RBI guidance", coveredBy: ["root_jailbreak", "emulator"] },
          { id: "m-dev-2", topic: "Hardware-backed device attestation", consider: "Server-side verification, revocation list.", why: "Proves a real, unmodified phone holds the key.", how: "Verify key attestation on the server; require hardware for high risk.", masvs: "MASVS-RESILIENCE-1", priority: "P1", frameworks: "MASVS", coveredBy: ["device_state_attestation"] },
          { id: "m-dev-3", topic: "USB, ADB and developer options", consider: "Support staff and testers.", why: "A cable plus ADB lets a computer control the phone.", how: "Detect USB connection, ADB and developer mode.", masvs: "MASVS-PLATFORM-1", priority: "P2", frameworks: "MASVS", coveredBy: ["usb_connection", "adb_enabled", "developer_mode"] },
          { id: "m-dev-4", topic: "SIM change and clone detection", consider: "Re-binding flow after a real SIM change.", why: "SIM swap is the first step to hijacking OTPs.", how: "Remember SIMs and detect cloned app instances.", masvs: "MASVS-AUTH-2", priority: "P1", frameworks: "RBI guidance", coveredBy: ["sim_change", "clone"] },
        ],
      },
      {
        id: "network",
        title: "Network Communication",
        controls: [
          { id: "m-net-1", topic: "TLS with certificate pinning", consider: "Pin rotation plan.", why: "Without pinning, a user-installed CA reads all traffic.", how: "Pin your server keys; detect proxies and user CAs.", masvs: "MASVS-NETWORK-2", priority: "P0", frameworks: "MASVS", coveredBy: ["mitm"] },
          { id: "m-net-2", topic: "Risky network context", consider: "VPNs used legitimately.", why: "Data-centre IPs and open Wi-Fi are common in fraud.", how: "Score IP risk on the server; warn on unsafe Wi-Fi.", masvs: "MASVS-NETWORK-1", priority: "P2", frameworks: "MASVS", coveredBy: ["high_risk_ip", "vpn", "unsafe_wifi"] },
        ],
      },
    ],
  },
  {
    id: "dev",
    title: "Development Processes",
    subtitle: "How the app is built and tested",
    sections: [
      {
        id: "sdlc",
        title: "App Development Processes",
        controls: [
          { id: "d-sdl-1", topic: "Dependency and SDK inventory", consider: "SBOM, update cadence.", why: "Vulnerable libraries are a top source of mobile CVEs.", how: "Keep an SBOM; update with automated alerts.", masvs: "MASVS-CODE-3", priority: "P1", frameworks: "MASVS, SOC 2" },
          { id: "d-sdl-2", topic: "Release signing key custody", consider: "HSM or Play App Signing, access list.", why: "A leaked signing key lets anyone ship 'your' app.", how: "Store keys in an HSM or managed signing; restrict access.", masvs: "MASVS-CODE-1", priority: "P0", frameworks: "ISO 27001" },
          { id: "d-sdl-3", topic: "Obfuscation and string protection", consider: "R8 rules, native code.", why: "Readable code makes reverse engineering cheap.", how: "Enable R8 full mode; move secrets server-side.", masvs: "MASVS-RESILIENCE-3", priority: "P2", frameworks: "MASVS" },
        ],
      },
      {
        id: "testing",
        title: "App Security Testing Processes",
        controls: [
          { id: "d-tst-1", topic: "Static and dynamic testing in CI", consider: "Blocking vs advisory findings.", why: "Catching issues before release is far cheaper.", how: "Run SAST on each PR and DAST on release candidates.", masvs: "MASVS-CODE-4", priority: "P1", frameworks: "MASVS" },
          { id: "d-tst-2", topic: "Yearly penetration test", consider: "Scope: app, API, backend.", why: "Regulators and partners expect independent testing.", how: "Commission a test against the current release; track fixes.", masvs: "—", priority: "P1", frameworks: "RBI, PCI DSS" },
        ],
      },
    ],
  },
  {
    id: "server",
    title: "Server-Side Controls",
    subtitle: "What the backend decides",
    sections: [
      {
        id: "backend",
        title: "Online & Application Logic (Backend Controls)",
        controls: [
          { id: "s-be-1", topic: "Verify device signals on the server", consider: "Signed events, replay protection.", why: "A client can lie; signed evidence cannot be forged cheaply.", how: "Accept only signed, non-replayed events from registered device keys.", masvs: "MASVS-RESILIENCE-1", priority: "P0", frameworks: "MASVS", coveredBy: ["console:signed-telemetry"] },
          { id: "s-be-2", topic: "Risk-based step-up", consider: "Which actions, which signals.", why: "Blocking everything hurts users; risk lets you be precise.", how: "Use the device risk score to require step-up on risky sessions.", masvs: "MASVS-AUTH-3", priority: "P1", frameworks: "RBI guidance", coveredBy: ["console:client-risk"] },
          { id: "s-be-3", topic: "Fraud rules on sessions and payments", consider: "Thresholds per product.", why: "Velocity and new-device patterns precede account takeover.", how: "Run rules for device change, travel, velocity, new beneficiary.", masvs: "—", priority: "P1", frameworks: "RBI fraud framework", coveredBy: ["console:fraud-agents"] },
        ],
      },
      {
        id: "siem",
        title: "SIEM, Audit and Monitoring",
        controls: [
          { id: "s-mon-1", topic: "Alert routing to the SOC", consider: "Webhook, SIEM, on-call.", why: "An alert nobody sees protects nobody.", how: "Forward high-severity findings by webhook to your SIEM.", masvs: "—", priority: "P1", frameworks: "ISO 27001, SOC 2", coveredBy: ["console:webhooks"] },
          { id: "s-mon-2", topic: "Audit trail of admin actions", consider: "Immutability, retention.", why: "You must show who changed a credential or setting.", how: "Keep an append-only audit log of credentials and settings.", masvs: "—", priority: "P0", frameworks: "ISO 27001", coveredBy: ["console:audit-log"] },
        ],
      },
    ],
  },
];

export const ALL_CONTROLS = PILLARS.flatMap((p) => p.sections.flatMap((s) => s.controls));

export const CONSOLE_FEATURES: Record<string, { label: string; href: string }> = {
  "console:signed-telemetry": { label: "Signed telemetry", href: "/security-settings" },
  "console:client-risk": { label: "Client Risk State", href: "/client-risk" },
  "console:fraud-agents": { label: "Fraud Prevention Agents", href: "/fraud-agents" },
  "console:webhooks": { label: "Alerting webhooks", href: "/alerting" },
  "console:audit-log": { label: "Audit Logs", href: "/audit-logs" },
};
