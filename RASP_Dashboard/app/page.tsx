"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { hasSession } from "@/lib/auth";
import { ShieldEmblem } from "@/components/shield-emblem";
import {
  ActivityIcon,
  AlertTriangleIcon,
  CheckIcon,
  KeyIcon,
  ScrollTextIcon,
  ShieldIcon,
  ZapIcon,
} from "@/components/ui";

/** Intro-sequence stages, in order. `checking` is the brief auth-gate
 *  moment (do we even show the splash, or bounce straight to the
 *  dashboard?) and renders nothing. */
type Stage = "checking" | "loading" | "portal" | "reveal" | "hero";

const NAV_LINKS = [
  { href: "#detectors", label: "Detectors" },
  { href: "#platform", label: "Platform" },
  { href: "#security", label: "Security" },
];

const DETECTORS = [
  {
    icon: AlertTriangleIcon,
    title: "Root & Jailbreak",
    desc: "Catches rooted and jailbroken devices before they ever reach your API.",
  },
  {
    icon: ZapIcon,
    title: "Frida & Hooking",
    desc: "Detects instrumentation frameworks and live runtime-hooking attempts.",
  },
  {
    icon: ShieldIcon,
    title: "Tamper & Repackaging",
    desc: "Flags modified binaries, signature mismatches, and resigned builds.",
  },
  {
    icon: ActivityIcon,
    title: "MITM & Overlay",
    desc: "Spots proxy interception, pinning bypass, and screen-overlay attacks.",
  },
];

const STATS = [
  { value: "42", label: "On-device detectors" },
  { value: "ES256", label: "Device-signed event ingestion" },
  { value: "Live", label: "Threat telemetry" },
  { value: "2", label: "SDKs — Android native, Flutter (Android)" },
];

const CAPABILITIES = [
  "Per-application credentials with full issuance/revocation audit log",
  "Replay-protected event ingestion — every payload signed, every replay rejected",
  "Live dashboard — alert breakdown, volume trends, per-device drill-down",
  "License and device-activation controls, enforced at the SDK",
];

/** RASHIELD's front page. Signed-in visitors skip straight to the
 *  dashboard (see the `checking` stage below) — the intro sequence is
 *  only for a first, logged-out landing: a loader that counts up, a
 *  zoom-through-the-mark transition, the shield emblem igniting with a
 *  ray burst, then the marketing page settling into place around it. */
export default function RootPage() {
  const router = useRouter();
  const [stage, setStage] = useState<Stage>("checking");
  const [percent, setPercent] = useState(0);
  const skippedRef = useRef(false);

  useEffect(() => {
    if (hasSession()) {
      router.replace("/dashboard");
      return;
    }
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    setStage(reduceMotion ? "hero" : "loading");
  }, [router]);

  // Loader counter — drives the "INITIALIZING SHIELD… NN%" readout.
  useEffect(() => {
    if (stage !== "loading") return;
    const start = Date.now();
    const duration = 1500;
    const id = setInterval(() => {
      if (skippedRef.current) return;
      const pct = Math.min(100, Math.round(((Date.now() - start) / duration) * 100));
      setPercent(pct);
      if (pct >= 100) {
        clearInterval(id);
        setStage("portal");
      }
    }, 35);
    return () => clearInterval(id);
  }, [stage]);

  // Portal zoom → emblem reveal → hero, each a short timed handoff.
  useEffect(() => {
    if (stage === "portal") {
      const t = setTimeout(() => !skippedRef.current && setStage("reveal"), 480);
      return () => clearTimeout(t);
    }
    if (stage === "reveal") {
      // Matches the 3D medallion's spin-in duration (see
      // .animate-emblem-spin-in in globals.css) so the handoff to the
      // idle-tilt animation lands after the spin settles, not mid-turn.
      const t = setTimeout(() => !skippedRef.current && setStage("hero"), 1100);
      return () => clearTimeout(t);
    }
  }, [stage]);

  function skipIntro() {
    skippedRef.current = true;
    setStage("hero");
  }

  const introActive = stage === "loading" || stage === "portal";
  const emblemVisible = stage === "reveal" || stage === "hero";

  return (
    <div className="relative min-h-screen overflow-hidden bg-black text-white">
      <div className="pointer-events-none fixed inset-0 overflow-hidden" aria-hidden>
        <div className="absolute left-1/2 top-0 h-[56rem] w-[56rem] -translate-x-1/2 -translate-y-1/3 rounded-full bg-brand-500/25 blur-[120px]" />
        <div className="absolute left-1/2 top-24 h-[26rem] w-[26rem] -translate-x-1/2 rounded-full bg-brand-300/15 blur-[100px]" />
        <div className="absolute bottom-0 right-0 h-[32rem] w-[32rem] translate-x-1/3 translate-y-1/3 rounded-full bg-brand-400/15 blur-[100px]" />
        <div className="absolute bottom-0 left-0 h-[24rem] w-[24rem] -translate-x-1/3 translate-y-1/3 rounded-full bg-brand-600/10 blur-[100px]" />
      </div>

      {introActive && (
        <div
          className={`fixed inset-0 z-50 flex items-center justify-center bg-black transition-all duration-500 ease-[cubic-bezier(0.6,0,0.9,0.4)] ${
            stage === "portal" ? "scale-[4] opacity-0 blur-2xl" : "scale-100 opacity-100 blur-0"
          }`}
        >
          <div className="relative flex w-[min(92vw,26rem)] flex-col items-center gap-8 rounded-3xl border border-white/[0.06] bg-white/[0.02] px-8 py-10">
            <div className="flex w-full items-center justify-between text-[11px] font-medium uppercase tracking-[0.16em] text-white/40">
              <span>Initializing shield…</span>
              <span className="tabular-nums text-brand-300">{percent}%</span>
            </div>

            <ShieldEmblem size={128} />

            <div className="text-center leading-tight">
              <div className="text-lg font-bold tracking-[0.14em] text-white">RASHIELD</div>
              <div className="mt-1 text-[10px] font-medium tracking-[0.18em] text-brand-300/80">
                REAL-TIME APPLICATION SHIELD
              </div>
            </div>

            <div className="h-[3px] w-full overflow-hidden rounded-full bg-white/[0.06]">
              <div
                className="h-full rounded-full bg-brand-400 shadow-[0_0_10px_1px_rgba(234,168,40,0.6)] transition-[width] duration-75"
                style={{ width: `${percent}%` }}
              />
            </div>
          </div>

          <button
            onClick={skipIntro}
            className="absolute bottom-6 right-6 text-xs font-medium text-white/30 transition hover:text-white/70"
          >
            Skip →
          </button>
        </div>
      )}

      {emblemVisible && (
        <>
          <nav className="animate-hero-rise relative z-10 mx-auto flex max-w-6xl items-center justify-between px-6 py-6 lg:px-10">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/15 text-brand-300 ring-1 ring-brand-400/30">
                <ShieldIcon size={16} />
              </div>
              <span className="text-sm font-bold tracking-[0.12em] text-white">RASHIELD</span>
            </div>
            <div className="hidden items-center gap-8 text-sm text-white/60 md:flex">
              {NAV_LINKS.map((l) => (
                <a key={l.href} href={l.href} className="transition hover:text-white">
                  {l.label}
                </a>
              ))}
            </div>
            <div className="flex items-center gap-3">
              <Link href="/login" className="text-sm font-medium text-white/70 transition hover:text-white">
                Sign in
              </Link>
              <Link
                href="/register"
                className="rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-black shadow-glow transition hover:bg-brand-400"
              >
                Get Started
              </Link>
            </div>
          </nav>

          <main className="relative z-10">
            <div className="mx-auto flex max-w-6xl flex-col items-center px-6 pt-6 lg:px-10">
              <div className="relative">
                {stage === "reveal" && (
                  <div
                    className="animate-ray-burst absolute inset-0 rounded-full bg-brand-400/40 blur-2xl"
                    aria-hidden
                  />
                )}
                <ShieldEmblem size={240} spinIn={stage === "reveal"} />
              </div>
            </div>

            <div className="animate-hero-rise flex justify-center px-6 pt-8">
              <div className="inline-flex items-center gap-2 rounded-full border border-brand-400/25 bg-brand-400/[0.07] px-3.5 py-1.5 text-[11px] font-medium uppercase tracking-[0.14em] text-brand-200">
                <span className="h-1.5 w-1.5 rounded-full bg-brand-400 shadow-[0_0_8px_2px_rgba(234,168,40,0.7)]" />
                Real-time runtime protection
              </div>
            </div>

            <div className="animate-hero-rise mx-auto grid max-w-6xl grid-cols-1 items-end gap-10 px-6 pb-24 pt-8 lg:grid-cols-2 lg:px-10">
              <h1 className="text-center text-5xl font-bold uppercase leading-[1.05] tracking-tight text-white sm:text-6xl lg:text-left lg:text-7xl">
                Detect attacks.
                <br />
                <span className="text-brand-300">In real time.</span>
              </h1>
              <div className="text-center lg:text-left">
                <p className="mx-auto max-w-md text-sm leading-relaxed text-white/55 lg:mx-0">
                  RASHIELD is the runtime shield for mobile and web apps that can&apos;t afford to be
                  wrong — root and jailbreak detection, anti-tampering, MITM defense, and live threat
                  telemetry, wired straight into your SDK.
                </p>
                <div className="mt-6 flex flex-wrap items-center justify-center gap-3 lg:justify-start">
                  <Link
                    href="/register"
                    className="rounded-lg bg-brand-500 px-5 py-2.5 text-sm font-semibold text-black shadow-glow transition hover:bg-brand-400"
                  >
                    Register your organization
                  </Link>
                  <Link
                    href="/login"
                    className="rounded-lg border border-white/15 px-5 py-2.5 text-sm font-medium text-white/80 transition hover:border-white/30 hover:text-white"
                  >
                    Sign in
                  </Link>
                </div>
              </div>
            </div>

            <section id="detectors" className="border-t border-white/[0.06] bg-white/[0.015] py-20">
              <div className="mx-auto max-w-6xl px-6 lg:px-10">
                <div className="mb-10 max-w-lg">
                  <div className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-300/80">
                    Detectors
                  </div>
                  <h2 className="mt-2 text-2xl font-semibold text-white">
                    42 detectors watching every device your app runs on.
                  </h2>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  {DETECTORS.map((d) => (
                    <div
                      key={d.title}
                      className="rounded-2xl border border-white/[0.06] bg-white/[0.02] p-5 transition hover:border-brand-400/25 hover:bg-white/[0.04]"
                    >
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-500/15 text-brand-300">
                        <d.icon size={17} />
                      </div>
                      <div className="mt-3 text-sm font-semibold text-white">{d.title}</div>
                      <p className="mt-1.5 text-xs leading-relaxed text-white/50">{d.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section id="platform" className="border-t border-white/[0.06] py-20">
              <div className="mx-auto max-w-6xl px-6 lg:px-10">
                <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
                  {STATS.map((s) => (
                    <div key={s.label} className="text-center sm:text-left">
                      <div className="text-3xl font-bold text-brand-300">{s.value}</div>
                      <div className="mt-1 text-xs leading-snug text-white/45">{s.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section id="security" className="border-t border-white/[0.06] bg-white/[0.015] py-20">
              <div className="mx-auto grid max-w-6xl grid-cols-1 gap-10 px-6 lg:grid-cols-2 lg:px-10">
                <div>
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-500/15 text-brand-300">
                    <KeyIcon size={18} />
                  </div>
                  <h2 className="mt-4 text-2xl font-semibold text-white">
                    Every credential, every event, fully accounted for.
                  </h2>
                  <p className="mt-3 max-w-md text-sm leading-relaxed text-white/50">
                    Issue and revoke per-application credentials, and see every action in an
                    immutable audit trail — built for teams that get asked to prove it.
                  </p>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {CAPABILITIES.map((c) => (
                    <div
                      key={c}
                      className="flex items-start gap-2.5 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 text-xs leading-relaxed text-white/60"
                    >
                      <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-brand-400/15 text-brand-300">
                        <CheckIcon size={10} />
                      </span>
                      {c}
                    </div>
                  ))}
                </div>
              </div>
            </section>
          </main>

          <footer className="relative z-10 border-t border-white/[0.06] px-6 py-8 lg:px-10">
            <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 text-xs text-white/35 sm:flex-row">
              <span className="flex items-center gap-2">
                <ScrollTextIcon size={13} />© {new Date().getFullYear()} RASHIELD — Real-Time
                Application Shield
              </span>
              <div className="flex items-center gap-2">
                <ShieldIcon size={13} />
                Built on the RASP Shield runtime engine
              </div>
            </div>
          </footer>
        </>
      )}
    </div>
  );
}
