import { catalogFor } from "@/lib/alertCatalog";

/**
 * The public capability catalogue behind the visitor portal (/, /capabilities,
 * /plans). Every on-device detector the engine ships (43) belongs to exactly
 * one module; the wording of `summary`, `howToShow` and `needs` follows the
 * trial app's Feature lab (`trial_app/rasp_trial/lib/feature_catalog.dart`)
 * so a visitor reads the same thing the demo phone shows. Titles and
 * severities come from `alertCatalog` — one name per detector everywhere.
 *
 * Product rules for this copy: no absolute security claims, no other
 * products' names, demo steps use ordinary phone settings only.
 */

export type ModuleId = "dpa" | "dit" | "dxp" | "sef" | "rtp" | "ais" | "nts";

export interface CapabilityModule {
  id: ModuleId;
  /** Short code shown on badges. */
  code: string;
  name: string;
  tagline: string;
  description: string;
  /** Tailwind classes for the module accent (icon tile + dot). */
  accent: { tile: string; dot: string; text: string; ring: string };
  /** A recorded demo that walks through several features of the module. */
  showcase?: { video: VideoRef; chapters: Chapter[] };
}

export interface Chapter {
  at: number;
  label: string;
  /** The feature this chapter shows, if it is about one. */
  featureId?: string;
}

export interface VideoRef {
  src: string;
  poster: string;
  /** Play only this part of the file, in seconds (looped). */
  start?: number;
  end?: number;
}

export interface Capability {
  id: string;
  slug: string;
  module: ModuleId;
  summary: string;
  howToShow: string[];
  needs?: string;
  /** Protects (on = protected) rather than detects. */
  isProtection?: boolean;
  demo?: { video: VideoRef; chapters: Chapter[]; caption: string };
}

const MEDIA = "/media/features";
const SESSION = `${MEDIA}/screen-share-session.mp4`;

export const MODULES: CapabilityModule[] = [
  {
    id: "dxp",
    code: "DXP",
    name: "Display Exfiltration Prevention",
    tagline: "Screenshot & video block, screen sharing, mirroring and recording",
    description:
      "Keeps what the app shows on the phone. Screens can be blocked from screenshots and recordings, " +
      "and the engine reports the moment the display is cast, mirrored, recorded or shared on a call.",
    accent: { tile: "bg-violet-500/15 text-violet-300", dot: "bg-violet-400", text: "text-violet-300", ring: "ring-violet-400/30" },
    showcase: {
      video: { src: SESSION, poster: `${MEDIA}/screen-share-session.jpg` },
      chapters: [
        { at: 0, label: "Live video call: the test phone presents its screen" },
        { at: 6, label: "Screenshot & Video Block on: the viewer only sees black", featureId: "screenshot_protection" },
        { at: 15, label: "Cast / mirroring detected", featureId: "external_display" },
        { at: 23, label: "Screen recording detected", featureId: "screen_recording" },
        { at: 32, label: "Call during app use detected", featureId: "vishing_call" },
        { at: 40, label: "Remote control / sharing tool detected", featureId: "remote_control_app" },
        { at: 46, label: "Screen sharing during app use detected", featureId: "screen_sharing_risk" },
        { at: 52, label: "Overview: every sharing signal raised at once" },
        { at: 56, label: "Block on again: the shared screen goes dark", featureId: "screenshot_protection" },
      ],
    },
  },
  {
    id: "dpa",
    code: "DPA",
    name: "Device Posture Assurance",
    tagline: "USB & ADB, device lock, root, emulator, hardware attestation",
    description:
      "Measures whether the phone itself can be trusted: a cable or debugger attached, no screen lock, " +
      "a rooted or emulated device, keys outside secure hardware, an unlocked bootloader.",
    accent: { tile: "bg-amber-500/15 text-amber-300", dot: "bg-amber-400", text: "text-amber-300", ring: "ring-amber-400/30" },
  },
  {
    id: "sef",
    code: "SEF",
    name: "Social-Engineering & Remote-Access Fraud Defense",
    tagline: "Calls, remote control, overlays, OTP theft, malicious apps",
    description:
      "Spots the set-up of an authorised-push-payment scam: a call in progress, a remote-control tool, " +
      "something drawing over the app, or an app that can read OTPs and notifications.",
    accent: { tile: "bg-rose-500/15 text-rose-300", dot: "bg-rose-400", text: "text-rose-300", ring: "ring-rose-400/30" },
  },
  {
    id: "dit",
    code: "DIT",
    name: "Device Identity & Telecom Integrity",
    tagline: "SIM swap, device binding, clones, fake location and time",
    description:
      "Ties an install to one real phone and notices when the identity around it shifts: a new SIM, " +
      "a cloned app, a faked GPS position or a clock moved away from real time.",
    accent: { tile: "bg-sky-500/15 text-sky-300", dot: "bg-sky-400", text: "text-sky-300", ring: "ring-sky-400/30" },
  },
  {
    id: "rtp",
    code: "RTP",
    name: "Runtime Tamper & Instrumentation Defense",
    tagline: "Hooking, instrumentation, debuggers, reverse-engineering tools",
    description:
      "Watches the running process for someone changing what the app does while it runs — " +
      "instrumentation toolkits, method hooks, attached debuggers and analysis tools.",
    accent: { tile: "bg-red-500/15 text-red-300", dot: "bg-red-400", text: "text-red-300", ring: "ring-red-400/30" },
  },
  {
    id: "ais",
    code: "AIS",
    name: "Application Integrity & Supply Chain",
    tagline: "Signature, repackaging, install source, task hijack, signed config",
    description:
      "Confirms that the binary on the phone is the one you shipped, came from a trusted store, " +
      "and only accepts remote settings that carry your signature.",
    accent: { tile: "bg-blue-500/15 text-blue-300", dot: "bg-blue-400", text: "text-blue-300", ring: "ring-blue-400/30" },
  },
  {
    id: "nts",
    code: "NTS",
    name: "Network Trust & Transport Security",
    tagline: "Interception, proxies, VPN, risky IPs, unsafe Wi-Fi",
    description:
      "Flags networks where the app's traffic can be read or redirected: proxies and user-installed " +
      "certificates, VPNs, data-centre IP addresses and open Wi-Fi.",
    accent: { tile: "bg-cyan-500/15 text-cyan-300", dot: "bg-cyan-400", text: "text-cyan-300", ring: "ring-cyan-400/30" },
  },
];

const segment = (start: number, end: number, poster: string): VideoRef => ({
  src: SESSION,
  poster: `${MEDIA}/${poster}.jpg`,
  start,
  end,
});

type Def = Omit<Capability, "slug">;

const DEFS: Def[] = [
  // ── Display Exfiltration Prevention ────────────────────────────────────
  {
    id: "screenshot_protection",
    module: "dxp",
    isProtection: true,
    summary:
      "Blocks screenshots and screen recording of the app's screens (Android FLAG_SECURE). One control covers " +
      "still pictures, video, and what a viewer sees when the screen is shared on a call.",
    howToShow: [
      "Enable the feature.",
      "Take a screenshot: Android refuses it (\"Screenshots restricted\"), or the picture is black.",
      "Share the screen on a video call: the other side sees a black screen.",
      "Disable the feature and try again: now the screen is captured.",
    ],
    demo: {
      caption: "Protection on: Android refuses the screenshot. Protection off: the screenshot is taken and reported.",
      video: { src: `${MEDIA}/screenshot-block.mp4`, poster: `${MEDIA}/screenshot-block.jpg` },
      chapters: [
        { at: 0, label: "Protection is active" },
        { at: 2.5, label: "Screenshot attempt — refused by Android" },
        { at: 6, label: "Protection switched off" },
        { at: 8, label: "Screenshot succeeds — and the app is told about it" },
      ],
    },
  },
  {
    id: "screenshot_event",
    module: "dxp",
    needs: "Android 14 or newer.",
    summary: "Reports the moment a screenshot of the app is taken, so a capture of a sensitive screen leaves a trace.",
    howToShow: [
      "Enable the feature (and switch Screenshot & Video Block off, so the screenshot is allowed).",
      "Take a screenshot: DETECTED for one check, and it stays in the detection log.",
    ],
  },
  {
    id: "screen_recording",
    module: "dxp",
    needs: "Android 15 or newer.",
    summary: "Reports when the app's screen is being recorded.",
    howToShow: [
      "Enable the feature.",
      "Quick settings → Screen record → start: DETECTED.",
      "Stop recording: SECURE.",
    ],
    demo: {
      caption: "While the screen is shared on a call, the recording signal turns to THREAT DETECTED.",
      video: segment(23, 31, "screen-recording"),
      chapters: [
        { at: 23, label: "Open Screen Recording while presenting" },
        { at: 28, label: "Recording detected" },
      ],
    },
  },
  {
    id: "external_display",
    module: "dxp",
    summary: "Reports when the screen is mirrored or cast to another display — a TV, a projector, or a capture device.",
    howToShow: [
      "Enable the feature.",
      "Quick settings → Cast / Screen mirroring: DETECTED.",
      "Stop casting: SECURE.",
    ],
    demo: {
      caption: "The phone presents its screen on a live call; External Display / Mirroring flips to detected.",
      video: segment(15, 23, "external-display"),
      chapters: [
        { at: 15, label: "Open External Display / Mirroring" },
        { at: 18, label: "First check → THREAT DETECTED" },
      ],
    },
  },
  {
    id: "screen_sharing_risk",
    module: "dxp",
    needs: "Android 15 or newer for recordings; casting works on any version.",
    summary: "Reports when the screen is shared or cast while the app is open — the core move of a screen-share scam.",
    howToShow: [
      "Enable the feature.",
      "Start a screen share on a video call, then open the app: DETECTED.",
      "Stop sharing: SECURE.",
    ],
    demo: {
      caption: "The screen is presented on a video call; Screen Sharing During App Use reports it.",
      video: segment(46, 53, "screen-sharing-risk"),
      chapters: [
        { at: 46, label: "Open Screen Sharing During App Use" },
        { at: 48, label: "Sharing detected" },
      ],
    },
  },
  {
    id: "clipboard_protection",
    module: "dxp",
    isProtection: true,
    summary:
      "Notices when something is copied in the app and clears the clipboard, so account numbers or OTPs are not " +
      "left behind for other apps. It never reads what was copied.",
    howToShow: [
      "Enable the feature.",
      "Copy text inside the app.",
      "The copy shows in the detection log, and pasting elsewhere gives nothing.",
    ],
  },

  // ── Device Posture Assurance ───────────────────────────────────────────
  {
    id: "usb_connection",
    module: "dpa",
    summary: "Reports when a USB cable, computer or dock is connected to the phone — the first step of most on-device tooling.",
    howToShow: [
      "Enable the feature.",
      "Plug the phone into a computer with a USB cable: DETECTED within a few seconds.",
      "Unplug it: back to SECURE.",
    ],
    demo: {
      caption: "Cable already attached: as soon as the feature is enabled the engine reports the USB connection.",
      video: { src: `${MEDIA}/usb-connection.mp4`, poster: `${MEDIA}/usb-connection.jpg` },
      chapters: [
        { at: 0, label: "Feature off — not running" },
        { at: 3, label: "Enabled — first check" },
        { at: 4, label: "USB cable / dock connected → THREAT DETECTED" },
      ],
    },
  },
  {
    id: "adb_enabled",
    module: "dpa",
    summary: "Reports when USB debugging (ADB) is switched on, which lets a computer control the phone.",
    howToShow: [
      "Enable the feature.",
      "Settings → Developer options → turn USB debugging on: DETECTED.",
      "Turn USB debugging off: SECURE.",
    ],
  },
  {
    id: "developer_mode",
    module: "dpa",
    summary: "Reports when Developer options are unlocked on the phone.",
    howToShow: [
      "Enable the feature.",
      "Settings → About phone → tap Build number 7 times: DETECTED.",
      "Turn Developer options off: SECURE.",
    ],
  },
  {
    id: "device_lock_missing",
    module: "dpa",
    summary:
      "Checks the screen lock and the fingerprint. An enrolled fingerprint is a safety feature and reads SECURE; a phone with no fingerprint enrolled is a low-level finding, " +
      "and a phone with no screen lock at all is open to anyone holding it, with the app's hardware-backed keys losing their user-authentication guarantee.",
    howToShow: [
      "Enable the feature.",
      "Fingerprint enrolled in Settings → Security: SECURE.",
      "Remove every fingerprint (or set Screen lock → None): DETECTED, low severity.",
    ],
    demo: {
      caption: "The phone opens with a plain swipe — no PIN, pattern or biometrics — and Device Lock reports it.",
      video: { src: `${MEDIA}/device-lock.mp4`, poster: `${MEDIA}/device-lock.jpg` },
      chapters: [
        { at: 0, label: "Feature on: no screen lock → detected" },
        { at: 2, label: "Lock the phone…" },
        { at: 5, label: "…and it opens with a swipe: no PIN, pattern or biometrics" },
        { at: 12, label: "Back in the app: still flagged" },
        { at: 18, label: "Feature off — not running" },
        { at: 21, label: "Enabled again → detected on the first check" },
      ],
    },
  },
  {
    id: "root_jailbreak",
    module: "dpa",
    summary: "Looks for signs that the phone has been rooted, which removes Android's app isolation.",
    howToShow: [
      "Enable the feature.",
      "On a normal phone: SECURE.",
      "On a test phone prepared by your security team: DETECTED, with the signals listed as evidence.",
    ],
  },
  {
    id: "emulator",
    module: "dpa",
    summary: "Reports when the app runs on an emulator instead of a real phone — common in automated fraud.",
    howToShow: ["Enable the feature.", "On a real phone: SECURE.", "Install the same build on an Android emulator: DETECTED."],
  },
  {
    id: "secure_hardware_unavailable",
    module: "dpa",
    summary: "Checks that the phone stores keys in secure hardware (TEE or StrongBox), not only in software.",
    howToShow: ["Enable the feature.", "Most current phones: SECURE.", "An emulator or very old phone: DETECTED."],
  },
  {
    id: "device_fingerprint",
    module: "dpa",
    summary:
      "Sums up the phone's security posture (screen lock, USB debugging, SELinux, install source) and reports which parts are weak.",
    howToShow: [
      "Enable the feature.",
      "Turn USB debugging on, or remove the screen lock: DETECTED, with the reason in the evidence.",
      "Restore both: SECURE.",
    ],
  },
  {
    id: "device_state_attestation",
    module: "dpa",
    summary: "Asks the phone's secure hardware to vouch for its boot state (locked bootloader, verified boot) and patch level.",
    howToShow: [
      "Enable the feature.",
      "Retail phone with a locked bootloader: SECURE.",
      "A phone with an unlocked bootloader: DETECTED.",
    ],
  },

  // ── Social-Engineering & Remote-Access Fraud Defense ──────────────────
  {
    id: "vishing_call",
    module: "sef",
    needs: "Phone permission (READ_PHONE_STATE).",
    summary: "Reports a phone call during app use — fraudsters often talk a victim through a transfer.",
    howToShow: [
      "Enable the feature and grant the phone permission.",
      "Call the phone from another phone and answer, then return to the app: DETECTED.",
      "Hang up: SECURE.",
    ],
    demo: {
      caption: "Recorded on a real phone: the feature is switched on while a call is running, and Call During App Use shows THREAT DETECTED with the call state as evidence.",
      video: { src: `${MEDIA}/call-during-app-call.mp4`, poster: `${MEDIA}/call-during-app-call.jpg` },
      chapters: [
        { at: 0, label: "Open Call During App Use" },
        { at: 3, label: "Feature is off: Not running" },
        { at: 6, label: "Call in progress → THREAT DETECTED" },
        { at: 9, label: "Evidence: call_state OFFHOOK, app in foreground" },
      ],
    },
  },
  {
    id: "remote_control_app",
    module: "sef",
    summary: "Reports remote-support or remote-control apps installed, or screen sharing now — the tools used in remote-access scams.",
    howToShow: ["Enable the feature.", "Install a well-known remote-support app: DETECTED.", "Uninstall it: SECURE."],
    demo: {
      caption: "With a sharing tool active, Remote Control App moves from waiting to detected.",
      video: segment(40, 47, "remote-control-app"),
      chapters: [
        { at: 40, label: "Open Remote Control App" },
        { at: 42, label: "Remote access tool → THREAT DETECTED" },
      ],
    },
  },
  {
    id: "overlay",
    module: "sef",
    summary: "Reports when another app draws over this one while the user touches it — used to trick people into tapping the wrong thing.",
    howToShow: [
      "Enable the feature.",
      "Open a floating bubble or chat head from another app over the screen and tap through it: DETECTED.",
      "Close the bubble: SECURE after the next touch.",
    ],
  },
  {
    id: "accessibility",
    module: "sef",
    summary: "Reports accessibility services that can read the screen or tap for the user, a common way for malware to take over a banking session.",
    howToShow: ["Enable the feature.", "Settings → Accessibility → turn on a downloaded accessibility app: DETECTED.", "Turn it off: SECURE."],
  },
  {
    id: "third_party_keyboard",
    module: "sef",
    summary: "Reports when the active keyboard is not a system or trusted keyboard; a keyboard sees every password and OTP typed.",
    howToShow: [
      "Enable the feature.",
      "Install another keyboard app and make it the default keyboard: DETECTED.",
      "Switch back to the phone's own keyboard: SECURE.",
    ],
  },
  {
    id: "otp_interception_risk",
    module: "sef",
    summary: "Reports apps that can read notifications or the screen, so they could read an OTP.",
    howToShow: ["Enable the feature.", "Settings → Notification access → allow a downloaded app: DETECTED.", "Remove the access: SECURE."],
  },
  {
    id: "sms_reader_abuse",
    module: "sef",
    summary: "Lists apps (other than the default SMS app) that are allowed to read SMS. It never reads any message.",
    howToShow: ["Enable the feature.", "Grant the SMS permission to a downloaded app: DETECTED.", "Remove the permission: SECURE."],
  },
  {
    id: "otp_forwarding_risk",
    module: "sef",
    summary:
      "A risk hint: SMS auto-forward apps, accessibility services that can tap, or remote-control apps that could pass an OTP on. " +
      "Never proof that an OTP was forwarded.",
    howToShow: ["Enable the feature.", "Install an SMS auto-forward app, or turn on an accessibility app: DETECTED (risk hint).", "Remove it: SECURE."],
  },
  {
    id: "malware_reputation",
    module: "sef",
    needs: "A backend credential (the signed list is served by the backend).",
    summary: "Compares installed apps with a signed list of known malicious apps, kept current from the backend.",
    howToShow: ["Enable the feature.", "Install an app on the list (your security team keeps a test entry): DETECTED.", "Remove it: SECURE."],
  },
  {
    id: "risky_app",
    module: "sef",
    summary: "Looks for apps and settings on the phone that make fraud easier (for example tools that change the device identity).",
    howToShow: [
      "Enable the feature.",
      "Normal phone: SECURE.",
      "A test phone set up by your security team: DETECTED, with the app category as evidence.",
    ],
  },

  // ── Device Identity & Telecom Integrity ───────────────────────────────
  {
    id: "sim_change",
    module: "dit",
    needs: "Phone permission (READ_PHONE_STATE).",
    summary: "Remembers the SIM cards and reports when they change — a step in SIM-swap fraud.",
    howToShow: [
      "Enable the feature and grant the phone permission.",
      "First check: UNKNOWN \"baseline stored\".",
      "Swap or remove a SIM and open the app: DETECTED.",
    ],
    demo: {
      caption: "The first check stores a SIM baseline; later checks compare against it.",
      video: { src: `${MEDIA}/sim-change.mp4`, poster: `${MEDIA}/sim-change.jpg` },
      chapters: [
        { at: 0, label: "Grant the phone permission" },
        { at: 3, label: "Enable the feature" },
        { at: 4, label: "First check stores the SIM baseline" },
        { at: 5, label: "No change since the baseline → secure" },
        { at: 10, label: "Evidence and detection log" },
      ],
    },
  },
  {
    id: "device_binding",
    module: "dit",
    summary:
      "Keeps a hardware-backed key that ties this install to this phone, so a copied app data folder on another phone does not pass as the original.",
    howToShow: ["Enable the feature.", "First run: the binding key is provisioned.", "Later runs on the same phone: SECURE."],
  },
  {
    id: "clone",
    module: "dit",
    summary: "Reports when the app runs as a clone (dual-app or parallel space), where a second copy can be controlled by someone else.",
    howToShow: ["Enable the feature.", "Normal install: SECURE.", "Clone the app with the phone's own \"dual apps\" setting and open the clone: DETECTED."],
  },
  {
    id: "mock_location",
    module: "dit",
    needs: "Location permission and location sharing on.",
    summary: "Reports when the location comes from a mock-location app instead of the real GPS.",
    howToShow: [
      "Enable the feature and switch location sharing on.",
      "Real location: SECURE.",
      "Developer options → Select mock location app, start a fake location: DETECTED.",
    ],
    demo: {
      caption:
        "Recorded on a real phone with location sharing on: on the real GPS the feature reports no threat, and the phone's shared location shows up on the console's map.",
      video: { src: `${MEDIA}/mock-location.mp4`, poster: `${MEDIA}/mock-location.jpg` },
      chapters: [
        { at: 0, label: "Feature on, real GPS → No threat found" },
        { at: 3, label: "Console map: the phone's shared location" },
      ],
    },
  },
  {
    id: "time_spoofing",
    module: "dit",
    summary: "Reports when the phone's clock has been moved away from real time, which can defeat time-based limits and one-time codes.",
    howToShow: [
      "Enable the feature.",
      "Settings → Date & time → turn automatic time off, then move the clock by an hour.",
      "Come back to the app: DETECTED (two signals are needed, one alone is not enough).",
    ],
  },

  // ── Runtime Tamper & Instrumentation Defense ──────────────────────────
  {
    id: "frida",
    module: "rtp",
    summary: "Looks for a dynamic instrumentation toolkit attached to the app, used to change what the app does while it runs.",
    howToShow: ["Enable the feature.", "Normal use: SECURE.", "During an authorised penetration test of the build: DETECTED."],
  },
  {
    id: "hook_detection",
    module: "rtp",
    summary: "Looks for hooking frameworks that intercept the app's own method calls.",
    howToShow: ["Enable the feature.", "Normal phone: SECURE.", "A test phone prepared by your security team: DETECTED."],
  },
  {
    id: "debugger",
    module: "rtp",
    summary: "Reports a debugger attached to the app, or a debuggable build.",
    howToShow: ["Enable the feature.", "A debug build shows DETECTED (build_mode = debug).", "A release build with no debugger: SECURE."],
  },
  {
    id: "re_tools",
    module: "rtp",
    summary: "Looks for reverse-engineering tools on the phone.",
    howToShow: ["Enable the feature.", "Normal phone: SECURE.", "A test phone with analysis tools installed by your security team: DETECTED."],
  },

  // ── Application Integrity & Supply Chain ──────────────────────────────
  {
    id: "tamper",
    module: "ais",
    summary: "Checks that the app's signing certificate is the one the build expects, so a modified copy is noticed.",
    howToShow: ["Enable the feature.", "Your release build: SECURE.", "A copy re-signed with another key: DETECTED."],
  },
  {
    id: "repackage",
    module: "ais",
    summary: "Reports when the app has been unpacked and rebuilt (repackaged) with another signature.",
    howToShow: ["Enable the feature.", "Your release build: SECURE.", "A rebuilt copy signed with another key: DETECTED."],
  },
  {
    id: "untrusted_install_source",
    module: "ais",
    summary: "Reports when the app was not installed from a trusted app store.",
    howToShow: ["Enable the feature.", "Installed from an APK file or a computer: DETECTED.", "The same app installed from the store: SECURE."],
    demo: {
      caption:
        "Recorded on a real phone with the trial build installed from a computer, not a store: THREAT DETECTED, and again on the first check after it is re-enabled.",
      video: { src: `${MEDIA}/install-source.mp4`, poster: `${MEDIA}/install-source.jpg` },
      chapters: [
        { at: 0, label: "Installed from a computer → THREAT DETECTED" },
        { at: 4, label: "Feature off — not running" },
        { at: 5, label: "Enabled again → detected on the first check" },
        { at: 12, label: "How to show it working" },
        { at: 13, label: "Detection log" },
      ],
    },
  },
  {
    id: "task_hijack",
    module: "ais",
    summary: "Reports another installed app that tries to join this app's task, so it can show a fake screen in the app's place.",
    howToShow: ["Enable the feature.", "Normal phone: SECURE.", "With a test app from your security team installed: DETECTED."],
  },
  {
    id: "remote_config_rejected",
    module: "ais",
    needs: "A backend credential with the config public key.",
    summary:
      "Fetches the app's signed settings from the backend and applies them only when the signature, app, expiry and version all check out. " +
      "A refused config changes nothing and is reported.",
    howToShow: [
      "Publish a remote config for the app from the console.",
      "The phone picks it up: SECURE, with the version as evidence.",
      "A config signed with the wrong key is refused: DETECTED, and the last good config stays in use.",
    ],
  },

  // ── Network Trust & Transport Security ────────────────────────────────
  {
    id: "mitm",
    module: "nts",
    summary:
      "Reports a proxy, a user-installed certificate authority or a wrong server certificate — signs that someone can read the app's traffic.",
    howToShow: [
      "Enable the feature.",
      "Wi-Fi settings → this network → Proxy: Manual (any host): DETECTED.",
      "Set the proxy back to None: SECURE.",
    ],
  },
  {
    id: "vpn",
    module: "nts",
    summary: "Reports when traffic goes through a VPN.",
    howToShow: ["Enable the feature.", "Connect any VPN app: DETECTED.", "Disconnect it: SECURE."],
    demo: {
      caption: "Recorded on a real phone with a VPN app connected: the VPN feature reports THREAT DETECTED, and again as soon as it is re-enabled.",
      video: { src: `${MEDIA}/vpn-detection.mp4`, poster: `${MEDIA}/vpn-detection.jpg` },
      chapters: [
        { at: 0, label: "Feature on, VPN connected → THREAT DETECTED" },
        { at: 4, label: "Detection log" },
        { at: 6, label: "Notification shade: VPN app connected" },
        { at: 12, label: "Feature off — not running" },
        { at: 16, label: "Enabled again → detected on the first check" },
      ],
    },
  },
  {
    id: "high_risk_ip",
    module: "nts",
    needs: "A backend credential.",
    summary: "Asks the backend whether the phone's public IP address is high-risk (hosting, proxy, blocked country).",
    howToShow: ["Enable the feature.", "Home or mobile network: SECURE.", "Through a data-centre VPN: DETECTED."],
  },
  {
    id: "unsafe_wifi",
    module: "nts",
    summary: "Reports an open (no password) or WEP Wi-Fi network, or one behind a login page.",
    howToShow: [
      "Enable the feature.",
      "Join an open guest network (or a hotspot with security \"None\"): DETECTED.",
      "Back on a WPA2/WPA3 network or mobile data: SECURE.",
    ],
  },
];

export const CAPABILITIES: Capability[] = DEFS.map((d) => ({ ...d, slug: d.id.replace(/_/g, "-") }));

export const FEATURED_DEMO_IDS = [
  "screenshot_protection",
  "usb_connection",
  "device_lock_missing",
  "screen_sharing_risk",
  "external_display",
  "sim_change",
  "vishing_call",
  "vpn",
  "mock_location",
  "untrusted_install_source",
] as const;

export function moduleById(id: ModuleId): CapabilityModule {
  return MODULES.find((m) => m.id === id)!;
}

export function capabilitiesOf(moduleId: ModuleId): Capability[] {
  return CAPABILITIES.filter((c) => c.module === moduleId);
}

export function capabilityBySlug(slug: string): Capability | undefined {
  return CAPABILITIES.find((c) => c.slug === slug);
}

export function capabilityById(id: string): Capability | undefined {
  return CAPABILITIES.find((c) => c.id === id);
}

/** Display title and severity — from the dashboard's alert catalogue. */
export function titleOf(id: string): string {
  return catalogFor(id).title;
}

export function severityOf(id: string) {
  return catalogFor(id).severity;
}

/** Server-side services that sit on top of the on-device modules. */
export const PLATFORM_SERVICES = [
  {
    name: "Signed telemetry",
    desc: "Every event is signed with a hardware-backed device key (ES256) and replay-checked before it reaches the console.",
  },
  {
    name: "Signed remote configuration",
    desc: "Change intervals and thresholds in the field with Ed25519-signed configs the app verifies before it applies them.",
  },
];
