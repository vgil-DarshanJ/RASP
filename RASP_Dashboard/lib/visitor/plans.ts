/**
 * The four plans on the visitor portal and the comparison matrix behind
 * /plans. Which product parts each plan includes is real (every row names a
 * shipped capability); the commercial values — device counts, retention,
 * support levels, trial length — are placeholders until the business sets
 * them (see "[TBD] business facts" in the project decision log). Change them
 * here only; the pages read nothing else.
 */

export type PlanId = "demo" | "addplus" | "startup" | "largecap";

export interface Plan {
  id: PlanId;
  name: string;
  audience: string;
  price: string;
  priceNote: string;
  cta: { label: string; href: string };
  highlights: string[];
  featured?: boolean;
}

export const PLANS: Plan[] = [
  {
    id: "demo",
    name: "RASP Demo",
    audience: "Evaluate on a real phone",
    price: "Free",
    priceNote: "14-day evaluation",
    cta: { label: "Start the demo", href: "/register" },
    highlights: [
      "Demo app with the Feature lab",
      "Screen, USB, ADB and device-lock controls",
      "Read-only console with live events",
    ],
  },
  {
    id: "addplus",
    name: "RASP Add+",
    audience: "Add protection to one app",
    price: "Per app",
    priceNote: "billed monthly",
    cta: { label: "Talk to us", href: "/register" },
    highlights: [
      "All 43 on-device detectors",
      "Alerts Inbox and device monitoring",
      "Webhook alerting",
    ],
  },
  {
    id: "startup",
    name: "RASP for Startups",
    audience: "Fintechs and growing teams",
    price: "Startup pricing",
    priceNote: "for young companies",
    cta: { label: "Apply", href: "/register" },
    featured: true,
    highlights: [
      "Everything in Add+",
      "Expanded security operations",
      "Device Map with opt-in location",
    ],
  },
  {
    id: "largecap",
    name: "RASP for Large-cap Business",
    audience: "Banks and regulated enterprises",
    price: "Custom",
    priceNote: "annual agreement",
    cta: { label: "Contact sales", href: "/register" },
    highlights: [
      "Everything in Startups",
      "Signed remote configuration and hardware attestation policy",
      "Self-hosted deployment, dedicated support",
    ],
  },
];

/** The detectors the demo plan switches on; every paid plan has all of them. */
export const DEMO_DETECTORS = new Set([
  "screenshot_protection",
  "clipboard_protection",
  "usb_connection",
  "adb_enabled",
  "device_lock_missing",
  "sim_change",
]);

/** Whether a plan includes a detector (matches the matrix rows below). */
export function planIncludes(plan: PlanId, detectorId: string): boolean {
  if (detectorId === "remote_config_rejected") return plan === "largecap";
  return plan !== "demo" || DEMO_DETECTORS.has(detectorId);
}

/** `true` = included, `false` = not included, string = included with this limit. */
export type Cell = boolean | string;

export interface MatrixRow {
  label: string;
  hint?: string;
  /** Link to the capability or module this row is about. */
  href?: string;
  cells: Record<PlanId, Cell>;
}

export interface MatrixGroup {
  title: string;
  rows: MatrixRow[];
}

const all = (v: Cell = true): Record<PlanId, Cell> => ({ demo: v, addplus: v, startup: v, largecap: v });

export const MATRIX: MatrixGroup[] = [
  {
    title: "On-device protection",
    rows: [
      {
        label: "Display Exfiltration Prevention",
        hint: "Screenshot & video block, mirroring, recording, screen sharing, clipboard",
        href: "/capabilities#dxp",
        cells: { demo: "Screenshot block + clipboard", addplus: true, startup: true, largecap: true },
      },
      {
        label: "Device Posture Assurance",
        hint: "USB, ADB, device lock, developer mode, root, emulator, attestation",
        href: "/capabilities#dpa",
        cells: { demo: "USB, ADB, device lock", addplus: true, startup: true, largecap: true },
      },
      {
        label: "Social-Engineering & Remote-Access Fraud Defense",
        hint: "Call during use, remote control, overlay, OTP risks, malware list",
        href: "/capabilities#sef",
        cells: { demo: false, addplus: true, startup: true, largecap: true },
      },
      {
        label: "Device Identity & Telecom Integrity",
        hint: "SIM change, device binding, clones, mock location, time spoofing",
        href: "/capabilities#dit",
        cells: { demo: "SIM change", addplus: true, startup: true, largecap: true },
      },
      {
        label: "Runtime Tamper & Instrumentation Defense",
        hint: "Instrumentation, hooks, debugger, reverse-engineering tools",
        href: "/capabilities#rtp",
        cells: { demo: false, addplus: true, startup: true, largecap: true },
      },
      {
        label: "Application Integrity & Supply Chain",
        hint: "Signature, repackaging, install source, task hijack",
        href: "/capabilities#ais",
        cells: { demo: false, addplus: true, startup: true, largecap: true },
      },
      {
        label: "Network Trust & Transport Security",
        hint: "Interception, VPN, high-risk IP, unsafe Wi-Fi",
        href: "/capabilities#nts",
        cells: { demo: false, addplus: true, startup: true, largecap: true },
      },
      { label: "Native core with integrity self-check", cells: all() },
      { label: "Android native and Flutter (Android) SDKs", cells: all() },
    ],
  },
  {
    title: "Console & intelligence",
    rows: [
      { label: "Security dashboard and live threats", cells: all() },
      { label: "Devices and per-device timeline", cells: all() },
      { label: "Mobile App Controls self-assessment", cells: all() },
      { label: "Alerts Inbox", cells: { demo: false, addplus: true, startup: true, largecap: true } },
      { label: "Webhook alerting", cells: { demo: false, addplus: true, startup: true, largecap: true } },
      { label: "Device Map (opt-in location)", cells: { demo: false, addplus: false, startup: true, largecap: true } },
      { label: "Signed remote configuration", cells: { demo: false, addplus: false, startup: false, largecap: true } },
      { label: "Hardware attestation policy", cells: { demo: false, addplus: false, startup: false, largecap: true } },
      { label: "Audit log of credentials and settings", cells: all() },
    ],
  },
  {
    title: "Scale & support",
    rows: [
      { label: "Applications", cells: { demo: "1 demo app", addplus: "1", startup: "Up to 3", largecap: "Unlimited" } },
      { label: "Monthly active devices", cells: { demo: "Up to 25", addplus: "Up to 10k", startup: "Up to 50k", largecap: "Custom" } },
      { label: "Event retention", cells: { demo: "7 days", addplus: "30 days", startup: "90 days", largecap: "Configurable" } },
      { label: "Self-hosted deployment", cells: { demo: false, addplus: false, startup: false, largecap: true } },
      {
        label: "Support",
        cells: { demo: "Documentation", addplus: "Email", startup: "Priority email + onboarding", largecap: "Dedicated engineer" },
      },
    ],
  },
];
