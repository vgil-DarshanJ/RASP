"use client";

import Link from "next/link";
import { VisitorShell } from "@/components/visitor/visitor-shell";
import { DemoVideo } from "@/components/visitor/demo-video";
import { AlertCircleIcon, CheckIcon } from "@/components/ui";
import { capabilitiesOf, capabilityBySlug, moduleById, severityOf, titleOf } from "@/lib/visitor/capabilities";
import { PLANS, planIncludes } from "@/lib/visitor/plans";

/** One detector: what it protects against, how to try it, and its demo. */
export function CapabilityDetail({ slug }: { slug: string }) {
  const cap = capabilityBySlug(slug)!;
  const mod = moduleById(cap.module);
  const siblings = capabilitiesOf(cap.module);
  const index = siblings.findIndex((c) => c.id === cap.id);
  const prev = siblings[index - 1];
  const next = siblings[index + 1];
  const sev = severityOf(cap.id);

  // Other recordings that show this feature (chapters of a module showcase).
  const showcaseChapters = mod.showcase?.chapters.filter((c) => c.featureId === cap.id) ?? [];

  return (
    <VisitorShell>
      <div className="mx-auto max-w-6xl px-4 pb-24 pt-10 sm:px-6 lg:px-10">
        <nav className="flex flex-wrap items-center gap-2 text-xs text-white/40">
          <Link href="/capabilities" className="hover:text-white">Capabilities</Link>
          <span>/</span>
          <Link href={`/capabilities#${mod.id}`} className="hover:text-white">{mod.name}</Link>
        </nav>

        <div className="mt-6 grid gap-10 lg:grid-cols-[1fr_20rem]">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded-md px-2 py-0.5 font-mono text-[11px] font-bold ring-1 ${mod.accent.tile} ${mod.accent.ring}`}>{mod.code}</span>
              <span className="rounded-md bg-white/5 px-2 py-0.5 text-[11px] capitalize text-white/60">Severity: {sev}</span>
              {cap.isProtection && <span className="rounded-md bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-300">Protection control</span>}
              <span className="font-mono text-[11px] text-white/30">{cap.id}</span>
            </div>
            <h1 className="mt-4 text-3xl font-bold sm:text-5xl">{titleOf(cap.id)}</h1>
            <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-white/60">{cap.summary}</p>

            {cap.demo ? (
              <div className="mt-10 rounded-3xl border border-white/[0.07] bg-white/[0.015] p-5 sm:p-7">
                <div className="mb-5 text-xs font-semibold uppercase tracking-[0.16em] text-brand-300/80">See it working</div>
                <DemoVideo video={cap.demo.video} chapters={cap.demo.chapters} caption={cap.demo.caption} />
              </div>
            ) : (
              <div className="mt-10 rounded-2xl border border-dashed border-white/10 p-6 text-sm text-white/45">
                No recording for this detector yet — follow the steps below on the demo app to see it yourself.
              </div>
            )}

            {showcaseChapters.length > 0 && mod.showcase && (
              <div className="mt-6 rounded-2xl border border-white/[0.07] bg-white/[0.015] p-5">
                <div className="text-sm font-semibold">Also in the screen-share scam scenario</div>
                <p className="mt-1 text-xs text-white/45">
                  Seen at {showcaseChapters.map((c) => `0:${String(c.at).padStart(2, "0")}`).join(" and ")} of the recorded video call.
                </p>
                <div className="mt-4">
                  <DemoVideo
                    video={{ ...mod.showcase.video, start: showcaseChapters[0].at, end: showcaseChapters[0].at + 7 }}
                    compact
                  />
                </div>
              </div>
            )}

            <div className="mt-10 grid gap-6 sm:grid-cols-2">
              <div className="rounded-2xl border border-white/[0.07] bg-white/[0.015] p-5">
                <div className="text-sm font-semibold">How to show it working</div>
                <ol className="mt-4 space-y-3">
                  {cap.howToShow.map((step, i) => (
                    <li key={step} className="flex gap-3 text-sm text-white/60">
                      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-400/15 text-[11px] font-semibold text-brand-300">
                        {i + 1}
                      </span>
                      {step}
                    </li>
                  ))}
                </ol>
              </div>
              <div className="space-y-4">
                <div className="rounded-2xl border border-white/[0.07] bg-white/[0.015] p-5">
                  <div className="text-sm font-semibold">What the console receives</div>
                  <p className="mt-2 text-sm leading-relaxed text-white/55">
                    A signed event with the result (SECURE, DETECTED or UNKNOWN), evidence, device and app version. It feeds
                    Live Threats, the Alerts Inbox and the device&apos;s Client Risk State.
                  </p>
                </div>
                {cap.needs && (
                  <div className="flex gap-3 rounded-2xl border border-amber-400/20 bg-amber-400/[0.05] p-5 text-sm text-amber-100/80">
                    <AlertCircleIcon size={16} className="mt-0.5 shrink-0 text-amber-300" />
                    <div>
                      <div className="font-semibold text-amber-200">Needs</div>
                      {cap.needs}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="mt-10 flex justify-between gap-4 border-t border-white/[0.06] pt-6 text-sm">
              {prev ? (
                <Link href={`/capabilities/${prev.slug}`} className="text-white/55 hover:text-white">← {titleOf(prev.id)}</Link>
              ) : <span />}
              {next && <Link href={`/capabilities/${next.slug}`} className="text-right text-white/55 hover:text-white">{titleOf(next.id)} →</Link>}
            </div>
          </div>

          <aside className="space-y-4 lg:sticky lg:top-24 lg:self-start">
            <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
              <div className="text-xs font-semibold uppercase tracking-[0.14em] text-white/40">Included in</div>
              <ul className="mt-3 space-y-2">
                {PLANS.map((p) => {
                  const included = planIncludes(p.id, cap.id);
                  return (
                    <li key={p.id} className="flex items-center justify-between gap-2 text-sm">
                      <span className={included ? "text-white/80" : "text-white/35"}>{p.name}</span>
                      {included ? <CheckIcon size={14} className="text-brand-300" /> : <span className="text-white/25">—</span>}
                    </li>
                  );
                })}
              </ul>
              <Link href="/plans" className="mt-4 block text-xs font-medium text-brand-300 hover:text-brand-200">Compare plans →</Link>
            </div>
            <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
              <div className="text-xs font-semibold uppercase tracking-[0.14em] text-white/40">More in {mod.code}</div>
              <ul className="mt-3 space-y-1">
                {siblings.map((s) => (
                  <li key={s.id}>
                    <Link
                      href={`/capabilities/${s.slug}`}
                      className={`flex items-center justify-between rounded-lg px-2 py-1.5 text-sm transition ${
                        s.id === cap.id ? "bg-brand-400/10 text-white" : "text-white/55 hover:bg-white/[0.04] hover:text-white"
                      }`}
                    >
                      {titleOf(s.id)}
                      {s.demo && <span className="text-[10px] text-brand-300">▶</span>}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </aside>
        </div>
      </div>
    </VisitorShell>
  );
}
