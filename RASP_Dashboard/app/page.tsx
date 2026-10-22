"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { hasSession } from "@/lib/auth";
import { ShieldEmblem } from "@/components/shield-emblem";
import { VisitorFooter, VisitorNav } from "@/components/visitor/visitor-shell";
import { DemoVideo } from "@/components/visitor/demo-video";
import { PlanCards } from "@/components/visitor/plan-cards";
import {
  CAPABILITIES,
  FEATURED_DEMO_IDS,
  MODULES,
  PLATFORM_SERVICES,
  capabilitiesOf,
  capabilityById,
  moduleById,
  titleOf,
} from "@/lib/visitor/capabilities";

/** Intro-sequence stages, in order. `checking` decides whether to play the
 *  intro at all (signed-in visitors and reduced motion skip it). */
type Stage = "checking" | "loading" | "portal" | "reveal" | "hero";

const STATS = [
  { value: String(CAPABILITIES.length), label: "On-device detectors" },
  { value: String(MODULES.length), label: "Protection modules" },
  { value: "6", label: "Server-side fraud agents" },
  { value: "ES256", label: "Signed device telemetry" },
];

/** The visitor portal's front page: what the product protects against,
 *  real-phone recordings of it working, and the plans. */
export default function RootPage() {
  const [stage, setStage] = useState<Stage>("checking");
  const [percent, setPercent] = useState(0);
  const skippedRef = useRef(false);

  useEffect(() => {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    setStage(reduceMotion || hasSession() || window.location.hash ? "hero" : "loading");
  }, []);

  useEffect(() => {
    if (stage !== "loading") return;
    const start = Date.now();
    const id = setInterval(() => {
      if (skippedRef.current) return;
      const pct = Math.min(100, Math.round(((Date.now() - start) / 1300) * 100));
      setPercent(pct);
      if (pct >= 100) {
        clearInterval(id);
        setStage("portal");
      }
    }, 35);
    return () => clearInterval(id);
  }, [stage]);

  useEffect(() => {
    if (stage === "portal") {
      const t = setTimeout(() => !skippedRef.current && setStage("reveal"), 480);
      return () => clearTimeout(t);
    }
    if (stage === "reveal") {
      const t = setTimeout(() => !skippedRef.current && setStage("hero"), 1100);
      return () => clearTimeout(t);
    }
  }, [stage]);

  useEffect(() => {
    // An anchor link (/#demos) lands after the content exists.
    if (stage === "hero" && window.location.hash) {
      document.querySelector(window.location.hash)?.scrollIntoView();
    }
  }, [stage]);

  function skipIntro() {
    skippedRef.current = true;
    setStage("hero");
  }

  const introActive = stage === "loading" || stage === "portal";
  const emblemVisible = stage === "reveal" || stage === "hero";

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-black text-white">
      <div className="pointer-events-none fixed inset-0 overflow-hidden" aria-hidden>
        <div className="absolute left-1/2 top-0 h-[56rem] w-[56rem] -translate-x-1/2 -translate-y-1/3 rounded-full bg-brand-500/20 blur-[120px]" />
        <div className="absolute bottom-0 right-0 h-[32rem] w-[32rem] translate-x-1/3 translate-y-1/3 rounded-full bg-brand-400/10 blur-[100px]" />
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
              <div className="mt-1 text-[10px] font-medium tracking-[0.18em] text-brand-300/80">REAL-TIME APPLICATION SHIELD</div>
            </div>
            <div className="h-[3px] w-full overflow-hidden rounded-full bg-white/[0.06]">
              <div
                className="h-full rounded-full bg-brand-400 shadow-[0_0_10px_1px_rgba(234,168,40,0.6)] transition-[width] duration-75"
                style={{ width: `${percent}%` }}
              />
            </div>
          </div>
          <button onClick={skipIntro} className="absolute bottom-6 right-6 text-xs font-medium text-white/30 transition hover:text-white/70">
            Skip →
          </button>
        </div>
      )}

      {emblemVisible && (
        <>
          <div className="animate-hero-rise relative z-40">
            <VisitorNav />
          </div>

          <main className="relative z-10">
            {/* ── Hero ─────────────────────────────────────────────── */}
            <section className="mx-auto grid max-w-6xl grid-cols-1 items-center gap-10 px-4 pb-16 pt-12 sm:px-6 lg:grid-cols-[1.1fr_0.9fr] lg:px-10">
              <div className="animate-hero-rise text-center lg:text-left">
                <div className="inline-flex items-center gap-2 rounded-full border border-brand-400/25 bg-brand-400/[0.07] px-3.5 py-1.5 text-[11px] font-medium uppercase tracking-[0.14em] text-brand-200">
                  <span className="h-1.5 w-1.5 rounded-full bg-brand-400 shadow-[0_0_8px_2px_rgba(234,168,40,0.7)]" />
                  Runtime protection for mobile banking
                </div>
                <h1 className="mt-6 text-4xl font-bold leading-[1.05] tracking-tight sm:text-6xl">
                  Your app knows
                  <br />
                  <span className="text-brand-300">when it&apos;s under attack.</span>
                </h1>
                <p className="mx-auto mt-5 max-w-lg text-[15px] leading-relaxed text-white/55 lg:mx-0">
                  {CAPABILITIES.length} on-device detectors in {MODULES.length} modules — screen capture, USB and
                  device-lock posture, remote-access scams, tampering and network interception — reporting signed
                  evidence to a console your fraud team can act on.
                </p>
                <div className="mt-7 flex flex-wrap items-center justify-center gap-3 lg:justify-start">
                  <a href="#demos" className="rounded-lg bg-brand-500 px-5 py-2.5 text-sm font-semibold text-black shadow-glow transition hover:bg-brand-400">
                    Watch it on a real phone
                  </a>
                  <Link href="/plans" className="rounded-lg border border-white/15 px-5 py-2.5 text-sm font-medium text-white/80 transition hover:border-white/30 hover:text-white">
                    Compare plans
                  </Link>
                </div>
              </div>
              <div className="relative mx-auto">
                {stage === "reveal" && <div className="animate-ray-burst absolute inset-0 rounded-full bg-brand-400/40 blur-2xl" aria-hidden />}
                <ShieldEmblem size={260} spinIn={stage === "reveal"} />
              </div>
            </section>

            <section className="border-y border-white/[0.06] bg-white/[0.015]">
              <div className="mx-auto grid max-w-6xl grid-cols-2 gap-6 px-4 py-8 sm:grid-cols-4 sm:px-6 lg:px-10">
                {STATS.map((s) => (
                  <div key={s.label} className="text-center sm:text-left">
                    <div className="text-3xl font-bold text-brand-300">{s.value}</div>
                    <div className="mt-1 text-xs text-white/45">{s.label}</div>
                  </div>
                ))}
              </div>
            </section>

            {/* ── Modules ──────────────────────────────────────────── */}
            <section id="modules" className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-10">
              <SectionHead eyebrow="Protection modules" title="Seven modules. Each one answers a different attack." />
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {MODULES.map((m) => (
                  <Link
                    key={m.id}
                    href={`/capabilities#${m.id}`}
                    className="group rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5 transition hover:-translate-y-0.5 hover:border-brand-400/30 hover:bg-white/[0.04]"
                  >
                    <div className="flex items-center justify-between">
                      <span className={`rounded-lg px-2 py-1 font-mono text-xs font-bold ring-1 ${m.accent.tile} ${m.accent.ring}`}>{m.code}</span>
                      <span className="text-xs text-white/35">{capabilitiesOf(m.id).length} detectors</span>
                    </div>
                    <div className="mt-4 font-semibold text-white">{m.name}</div>
                    <p className="mt-1.5 text-xs leading-relaxed text-white/50">{m.tagline}</p>
                    <div className="mt-4 text-xs font-medium text-brand-300 opacity-0 transition group-hover:opacity-100">Explore →</div>
                  </Link>
                ))}
              </div>
            </section>

            {/* ── Live demos ───────────────────────────────────────── */}
            <FeaturedDemos />

            {/* ── Screen-share showcase ────────────────────────────── */}
            <ShareShowcase />

            {/* ── Platform ─────────────────────────────────────────── */}
            <section className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-10">
              <SectionHead eyebrow="Beyond the device" title="Detection is half the job. The console turns it into decisions." />
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                {PLATFORM_SERVICES.map((s) => (
                  <div key={s.name} className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
                    <div className="font-semibold text-white">{s.name}</div>
                    <p className="mt-1.5 text-sm leading-relaxed text-white/50">{s.desc}</p>
                  </div>
                ))}
              </div>
            </section>

            {/* ── Plans ────────────────────────────────────────────── */}
            <section id="plans" className="border-t border-white/[0.06] bg-white/[0.015] py-20">
              <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-10">
                <SectionHead eyebrow="Plans" title="Start with the demo. Grow into fraud intelligence." />
                <PlanCards />
                <div className="mt-8 text-center">
                  <Link href="/plans" className="text-sm font-medium text-brand-300 hover:text-brand-200">
                    See the full feature comparison →
                  </Link>
                </div>
              </div>
            </section>
          </main>

          <VisitorFooter />
        </>
      )}
    </div>
  );
}

function SectionHead({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div className="mb-10 max-w-2xl">
      <div className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-300/80">{eyebrow}</div>
      <h2 className="mt-2 text-2xl font-semibold text-white sm:text-3xl">{title}</h2>
    </div>
  );
}

function FeaturedDemos() {
  const [active, setActive] = useState<string>(FEATURED_DEMO_IDS[0]);
  const cap = capabilityById(active)!;
  const mod = moduleById(cap.module);

  return (
    <section id="demos" className="scroll-mt-20 border-t border-white/[0.06] bg-white/[0.015] py-20">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-10">
        <SectionHead eyebrow="Live demos" title="Recorded on a real phone. No mock-ups." />
        <div className="grid gap-8 lg:grid-cols-[16rem_1fr]">
          <div className="-mx-4 flex gap-2 overflow-x-auto px-4 pb-2 lg:mx-0 lg:flex-col lg:overflow-visible lg:px-0">
            {FEATURED_DEMO_IDS.map((id) => {
              const c = capabilityById(id)!;
              const m = moduleById(c.module);
              const on = id === active;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setActive(id)}
                  className={`shrink-0 rounded-xl px-4 py-3 text-left transition ${
                    on ? "bg-brand-400/10 ring-1 ring-inset ring-brand-400/30" : "hover:bg-white/[0.04]"
                  }`}
                >
                  <div className={`font-mono text-[10px] font-bold ${m.accent.text}`}>{m.code}</div>
                  <div className={`text-sm font-medium ${on ? "text-white" : "text-white/60"}`}>{titleOf(id)}</div>
                </button>
              );
            })}
          </div>
          <div key={active} className="animate-hero-rise rounded-3xl border border-white/[0.07] bg-black/40 p-5 sm:p-8">
            <div className="mb-5 flex flex-wrap items-center gap-2">
              <span className={`rounded-md px-2 py-0.5 font-mono text-[11px] font-bold ring-1 ${mod.accent.tile} ${mod.accent.ring}`}>{mod.code}</span>
              <span className="text-xs text-white/40">{mod.name}</span>
            </div>
            <h3 className="text-xl font-semibold">{titleOf(active)}</h3>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-white/55">{cap.summary}</p>
            <div className="mt-6">{cap.demo && <DemoVideo video={cap.demo.video} chapters={cap.demo.chapters} caption={cap.demo.caption} />}</div>
            <Link href={`/capabilities/${cap.slug}`} className="mt-6 inline-block text-sm font-medium text-brand-300 hover:text-brand-200">
              How it works and how to try it →
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}

function ShareShowcase() {
  const dxp = moduleById("dxp");
  if (!dxp.showcase) return null;
  return (
    <section className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-10">
      <SectionHead eyebrow="Scenario · screen-share scam" title="One video call. Six signals. The viewer sees a black screen." />
      <p className="-mt-6 mb-10 max-w-2xl text-sm leading-relaxed text-white/50">
        A fraudster asks the victim to share their screen on a call. The left phone runs the protected app; the right
        phone is the other side of the call. Click a step to jump to it.
      </p>
      <DemoVideo video={dxp.showcase.video} chapters={dxp.showcase.chapters} />
    </section>
  );
}
