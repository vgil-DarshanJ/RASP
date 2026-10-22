"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { VisitorShell } from "@/components/visitor/visitor-shell";
import { SearchIcon } from "@/components/ui";
import { CAPABILITIES, MODULES, capabilitiesOf, severityOf, titleOf } from "@/lib/visitor/capabilities";

const SEVERITY_TONE: Record<string, string> = {
  critical: "text-red-300 bg-red-500/10",
  high: "text-orange-300 bg-orange-500/10",
  medium: "text-amber-200 bg-amber-500/10",
  low: "text-white/50 bg-white/5",
};

/** Every module and every detector in it; search narrows by name or text. */
export default function CapabilitiesPage() {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const matches = useMemo(
    () => new Set(CAPABILITIES.filter((c) => !q || `${titleOf(c.id)} ${c.summary} ${c.id}`.toLowerCase().includes(q)).map((c) => c.id)),
    [q],
  );

  return (
    <VisitorShell>
      <section className="mx-auto max-w-6xl px-4 pb-8 pt-14 sm:px-6 lg:px-10">
        <div className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-300/80">Capabilities</div>
        <h1 className="mt-2 text-3xl font-bold sm:text-5xl">
          {CAPABILITIES.length} detectors, <span className="text-brand-300">{MODULES.length} modules</span>
        </h1>
        <p className="mt-4 max-w-2xl text-sm leading-relaxed text-white/55">
          Each detector runs inside your app on the phone and reports SECURE, DETECTED or UNKNOWN with evidence.
          Open one to see what it protects against, how to try it yourself, and — where we recorded it — a video from a real phone.
        </p>
        <div className="mt-8 flex flex-col gap-4 sm:flex-row sm:items-center">
          <label className="relative w-full sm:max-w-sm">
            <SearchIcon size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-white/35" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search: screen, USB, SIM, overlay…"
              className="w-full rounded-lg border border-white/10 bg-white/[0.03] py-2.5 pl-9 pr-3 text-sm text-white outline-none placeholder:text-white/30 focus:border-brand-400/50"
            />
          </label>
          <div className="flex flex-wrap gap-2">
            {MODULES.map((m) => (
              <a key={m.id} href={`#${m.id}`} className={`rounded-md px-2 py-1 font-mono text-[11px] font-bold ring-1 transition hover:opacity-80 ${m.accent.tile} ${m.accent.ring}`}>
                {m.code}
              </a>
            ))}
          </div>
        </div>
      </section>

      <div className="mx-auto max-w-6xl space-y-6 px-4 pb-24 sm:px-6 lg:px-10">
        {MODULES.map((m) => {
          const caps = capabilitiesOf(m.id).filter((c) => matches.has(c.id));
          if (caps.length === 0) return null;
          return (
            <section key={m.id} id={m.id} className="scroll-mt-28 rounded-3xl border border-white/[0.07] bg-white/[0.015] p-5 sm:p-7">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <span className={`rounded-md px-2 py-0.5 font-mono text-[11px] font-bold ring-1 ${m.accent.tile} ${m.accent.ring}`}>{m.code}</span>
                  <h2 className="mt-3 text-xl font-semibold">{m.name}</h2>
                  <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-white/50">{m.description}</p>
                </div>
                <span className="shrink-0 text-xs text-white/35">{capabilitiesOf(m.id).length} detectors</span>
              </div>
              <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {caps.map((c) => {
                  const sev = severityOf(c.id);
                  return (
                    <Link
                      key={c.id}
                      href={`/capabilities/${c.slug}`}
                      className="group flex flex-col rounded-xl border border-white/[0.06] bg-black/30 p-4 transition hover:border-brand-400/30 hover:bg-white/[0.03]"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="text-sm font-semibold text-white">{titleOf(c.id)}</div>
                        {c.demo && (
                          <span className="shrink-0 rounded-full bg-brand-400/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-brand-200">
                            ▶ Video
                          </span>
                        )}
                      </div>
                      <p className="mt-1.5 line-clamp-3 flex-1 text-xs leading-relaxed text-white/50">{c.summary}</p>
                      <div className="mt-3 flex items-center gap-2 text-[11px]">
                        <span className={`rounded px-1.5 py-0.5 capitalize ${SEVERITY_TONE[sev]}`}>{sev}</span>
                        {c.isProtection && <span className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-emerald-300">Protection</span>}
                        <span className="ml-auto font-mono text-white/25">{c.id}</span>
                      </div>
                    </Link>
                  );
                })}
              </div>
            </section>
          );
        })}
        {matches.size === 0 && <p className="py-16 text-center text-sm text-white/40">Nothing matches “{query}”.</p>}
      </div>
    </VisitorShell>
  );
}
