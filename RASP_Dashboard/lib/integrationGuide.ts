/**
 * Data behind the "Integration Guide" page (`app/(app)/guide`) — for each
 * of the 26 detectors, the exact `RaspLeanConfig` field name on each
 * implemented platform, and what actually happens if a bank chooses not
 * to turn it on. Kept in sync by hand with the SDKs, the same way
 * `alertCatalog.ts`'s own header documents doing (source of truth:
 * `sdk_rasp/flutter/rasp_shield_sdk/lib/sdk/lean_session.dart`'s
 * `RaspLeanConfig` and `sdk_rasp/android_native/rasp_shield_native/.../
 * RaspLeanSession.kt`'s `RaspLeanConfig` — both verified field-by-field
 * against the real source before writing this file, not guessed).
 *
 * Only Flutter and Android Native have real field names here — iOS and
 * React Native are `available: false` in the backend's own
 * `SDK_CATALOG` (see `BE/src/sdk-distribution/catalog.ts`), so this page
 * shows them as "coming soon" rather than inventing instructions for an
 * SDK that doesn't exist yet.
 */

export interface DetectorGuideEntry {
  detectorId: string;
  /** RaspLeanConfig field name on the Flutter/Dart side. */
  dartField: string;
  /** RaspLeanConfig field name on the Android Native/Kotlin side. */
  kotlinField: string;
  /** What a bank is actually exposed to if this stays off. */
  consequenceIfDisabled: string;
}

export const DETECTOR_GUIDE: DetectorGuideEntry[] = [
  {
    detectorId: "screenshot_protection",
    dartField: "screenshotProtection",
    kotlinField: "screenshotProtection",
    consequenceIfDisabled:
      "Screens showing account numbers, balances, or OTPs can be screenshotted or screen-recorded by any other app or the OS itself, with no record of it happening.",
  },
  {
    detectorId: "clipboard_protection",
    dartField: "clipboardProtection",
    kotlinField: "clipboardProtection",
    consequenceIfDisabled:
      "A malicious keyboard or clipboard-monitoring app can silently read anything copied in your app (account numbers, one-time passcodes) with no visibility into it happening.",
  },
  {
    detectorId: "usb_connection",
    dartField: "usbDetection",
    kotlinField: "usbDetection",
    consequenceIfDisabled:
      "A physical USB debugging rig or data-exfiltration dock can be attached to the device during a session with no audit trail of it.",
  },
  {
    detectorId: "adb_enabled",
    dartField: "adbDetection",
    kotlinField: "adbDetection",
    consequenceIfDisabled:
      "ADB gives a connected computer full shell access to the device — app data, logs, and in some configurations the ability to install/manipulate apps — with your app never knowing it's exposed.",
  },
  {
    detectorId: "root_jailbreak",
    dartField: "rootDetection",
    kotlinField: "rootDetection",
    consequenceIfDisabled:
      "A rooted device has no OS-enforced sandbox left — another app (or an attacker with physical access) can read your app's private storage, memory, and Keystore-protected data directly.",
  },
  {
    detectorId: "emulator",
    dartField: "emulatorDetection",
    kotlinField: "emulatorDetection",
    consequenceIfDisabled:
      "Fraud rings running your app at scale inside emulator farms (for bonus abuse, account takeover testing, or bot fraud) look identical to a real customer's phone.",
  },
  {
    detectorId: "device_binding",
    dartField: "deviceBindingCheck",
    kotlinField: "deviceBindingCheck",
    consequenceIfDisabled:
      "A session or credential can be lifted and replayed from a different physical device with nothing on the device side flagging that the identity moved.",
  },
  {
    detectorId: "clone",
    dartField: "cloneDetection",
    kotlinField: "cloneDetection",
    consequenceIfDisabled:
      "Dual-space/cloning apps let a second, isolated copy of your banking app run alongside the real one — a common way session tokens and locally-cached data get harvested.",
  },
  {
    detectorId: "developer_mode",
    dartField: "developerModeDetection",
    kotlinField: "developerModeDetection",
    consequenceIfDisabled:
      "Developer options unlock a wider attack surface (USB debugging, mock locations, unrestricted background services) without your app ever seeing that the device's posture changed.",
  },
  {
    detectorId: "device_lock_missing",
    dartField: "deviceLockCheck",
    kotlinField: "deviceLockCheck",
    consequenceIfDisabled:
      "A lost or stolen phone with no PIN/pattern/biometric lock leaves every locally-cached session and credential immediately accessible to whoever picks it up.",
  },
  {
    detectorId: "secure_hardware_unavailable",
    dartField: "secureHardwareCheck",
    kotlinField: "secureHardwareCheck",
    consequenceIfDisabled:
      "Without a TEE/StrongBox-backed Keystore, cryptographic keys your app relies on for signing/binding fall back to software storage that a compromised OS can extract.",
  },
  {
    detectorId: "device_fingerprint",
    dartField: "deviceFingerprintCheck",
    kotlinField: "deviceFingerprintCheck",
    consequenceIfDisabled:
      "You lose the composite signal (lock state, ADB, SELinux, install source, hardware identity) that usually catches a device drifting into a risky posture before any single detector fires alone.",
  },
  {
    detectorId: "frida",
    dartField: "fridaDetection",
    kotlinField: "fridaDetection",
    consequenceIfDisabled:
      "Frida lets an attacker hook and rewrite your app's running code in memory — bypass a PIN check, alter a displayed balance, or intercept a request before encryption — with zero trace on disk.",
  },
  {
    detectorId: "debugger",
    dartField: "debuggerDetection",
    kotlinField: "debuggerDetection",
    consequenceIfDisabled:
      "A debugger attached to a production build can step through business logic line-by-line, dump decrypted memory, and defeat any check that isn't independently enforced server-side.",
  },
  {
    detectorId: "re_tools",
    dartField: "reverseEngineeringToolsDetection",
    kotlinField: "reverseEngineeringToolsDetection",
    consequenceIfDisabled:
      "Xposed/LSPosed and similar frameworks let a third-party module patch your app's behavior system-wide (e.g. auto-approve a transaction dialog) without modifying the APK itself.",
  },
  {
    detectorId: "hook_detection",
    dartField: "hookDetection",
    kotlinField: "hookDetection",
    consequenceIfDisabled:
      "A resident hooking framework already active in memory can intercept and alter any function call your app makes — including ones that decide whether a security check passed.",
  },
  {
    detectorId: "risky_app",
    dartField: "riskyAppDetection",
    kotlinField: "riskyAppDetection",
    consequenceIfDisabled:
      "A remote-access tool (e.g. a screen-sharing/support app) or unofficial accessibility service running alongside yours can see and act on everything displayed, matching a common social-engineering fraud pattern.",
  },
  {
    detectorId: "tamper",
    dartField: "tamperDetection",
    kotlinField: "tamperDetection",
    consequenceIfDisabled:
      "A modified build of your app (different bytecode, injected code) can run and report to your backend indistinguishably from the real, unmodified release.",
  },
  {
    detectorId: "untrusted_install_source",
    dartField: "untrustedInstallSourceDetection",
    kotlinField: "untrustedInstallSourceDetection",
    consequenceIfDisabled:
      "A sideloaded copy from outside the Play Store/App Store — often a repackaged or trojanized clone distributed via phishing — is treated exactly like a legitimate install.",
  },
  {
    detectorId: "repackage",
    dartField: "repackagingDetection",
    kotlinField: "repackagingDetection",
    consequenceIfDisabled:
      "Anyone can decompile your app, splice in malicious code (ad fraud, credential theft, a fake login screen), re-sign it, and distribute it as if it were your bank's real app — with no signature check catching it. Requires configuring `expectedSigningCertSha256` to enable.",
  },
  {
    detectorId: "vpn",
    dartField: "vpnDetection",
    kotlinField: "vpnDetection",
    consequenceIfDisabled:
      "You lose visibility into whether traffic is routed through a VPN tunnel — useful context for fraud scoring (a sudden VPN session from a new country on an existing account), never enforced on its own.",
  },
  {
    detectorId: "mitm",
    dartField: "mitmDetection",
    kotlinField: "mitmDetection",
    consequenceIfDisabled:
      "A system-installed proxy or CA cert can transparently intercept and read (or alter) every request/response between the app and your backend, including ones carrying credentials or transaction details.",
  },
  {
    detectorId: "high_risk_ip",
    dartField: "highRiskIpDetection",
    kotlinField: "highRiskIpDetection",
    consequenceIfDisabled:
      "Sessions originating from known anonymizer/proxy ranges or high-risk geographies score identically to a trusted retail customer connection.",
  },
  {
    detectorId: "overlay",
    dartField: "overlayDetection",
    kotlinField: "overlayDetection",
    consequenceIfDisabled:
      "A tapjacking overlay from another app can sit invisibly on top of yours, capturing taps meant for a real button (e.g. a transfer confirmation) without the user noticing anything is wrong.",
  },
  {
    detectorId: "accessibility",
    dartField: "accessibilityDetection",
    kotlinField: "accessibilityDetection",
    consequenceIfDisabled:
      "A malicious accessibility service (a common banking-trojan technique) can read every value on screen and even perform taps/gestures on the user's behalf, unnoticed.",
  },
  {
    detectorId: "external_display",
    dartField: "externalDisplayDetection",
    kotlinField: "externalDisplayDetection",
    consequenceIfDisabled:
      "Screen mirroring to an external/wireless display during a session — e.g. to record a card number or a QR code — happens with nothing on the device side flagging it.",
  },
];

export function guideEntryFor(detectorId: string): DetectorGuideEntry | undefined {
  return DETECTOR_GUIDE.find((d) => d.detectorId === detectorId);
}
