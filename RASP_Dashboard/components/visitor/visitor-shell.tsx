"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { hasSession } from "@/lib/auth";
import { ScrollTextIcon, ShieldIcon } from "@/components/ui";

const NAV_LINKS = [
  { href: "/capabilities", label: "Capabilities" },
  { href: "/#demos", label: "Live demos" },
  { href: "/plans", label: "Plans" },
];

/** Top bar of the public visitor portal. A signed-in visitor gets a
 *  "Open console" button instead of Sign in / Get started. */
export function VisitorNav() {
  const pathname = usePathname();
  const [signedIn, setSignedIn] = useState(false);
  useEffect(() => setSignedIn(hasSession()), []);

  return (
    <nav className="sticky top-0 z-40 border-b border-white/[0.06] bg-black/70 backdrop-blur-xl">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-10">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/15 text-brand-300 ring-1 ring-brand-400/30">
            <ShieldIcon size={16} />
          </div>
          <span className="text-sm font-bold tracking-[0.12em] text-white">RASHIELD</span>
        </Link>
        <div className="hidden items-center gap-8 text-sm text-white/60 md:flex">
          {NAV_LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={`transition hover:text-white ${pathname === l.href ? "text-white" : ""}`}
            >
              {l.label}
            </Link>
          ))}
        </div>
        <div className="flex items-center gap-3">
          {signedIn ? (
            <Link
              href="/dashboard"
              className="rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-black shadow-glow transition hover:bg-brand-400"
            >
              Open console
            </Link>
          ) : (
            <>
              <Link href="/login" className="hidden text-sm font-medium text-white/70 transition hover:text-white sm:inline">
                Sign in
              </Link>
              <Link
                href="/register"
                className="rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-black shadow-glow transition hover:bg-brand-400"
              >
                Get started
              </Link>
            </>
          )}
        </div>
      </div>
      <div className="flex justify-center gap-6 border-t border-white/[0.04] py-2 text-xs text-white/60 md:hidden">
        {NAV_LINKS.map((l) => (
          <Link key={l.href} href={l.href} className="hover:text-white">
            {l.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}

export function VisitorFooter() {
  return (
    <footer className="relative z-10 border-t border-white/[0.06] px-4 py-10 sm:px-6 lg:px-10">
      <div className="mx-auto grid max-w-6xl gap-8 text-xs text-white/45 sm:grid-cols-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-bold tracking-[0.12em] text-white">
            <ShieldIcon size={14} className="text-brand-300" /> RASHIELD
          </div>
          <p className="mt-2 max-w-xs leading-relaxed">
            Runtime application self-protection for mobile banking and fintech apps, with a console for the
            people who answer for them.
          </p>
        </div>
        <div className="flex flex-col gap-2">
          <span className="font-semibold uppercase tracking-[0.14em] text-white/70">Product</span>
          <Link href="/capabilities" className="hover:text-white">Capabilities</Link>
          <Link href="/plans" className="hover:text-white">Plans &amp; comparison</Link>
          <Link href="/#demos" className="hover:text-white">Live demos</Link>
        </div>
        <div className="flex flex-col gap-2">
          <span className="font-semibold uppercase tracking-[0.14em] text-white/70">Customers</span>
          <Link href="/login" className="hover:text-white">Sign in to the console</Link>
          <Link href="/register" className="hover:text-white">Register your organization</Link>
        </div>
      </div>
      <div className="mx-auto mt-8 flex max-w-6xl items-center gap-2 text-[11px] text-white/30">
        <ScrollTextIcon size={12} />© {new Date().getFullYear()} RASHIELD — Real-Time Application Shield
      </div>
    </footer>
  );
}

/** Dark page frame shared by every visitor page except the home page,
 *  which runs its own intro sequence first. */
export function VisitorShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative min-h-screen overflow-x-hidden bg-black text-white">
      <div className="pointer-events-none fixed inset-0 overflow-hidden" aria-hidden>
        <div className="absolute left-1/2 top-0 h-[44rem] w-[44rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-brand-500/15 blur-[120px]" />
        <div className="absolute bottom-0 right-0 h-[28rem] w-[28rem] translate-x-1/3 translate-y-1/3 rounded-full bg-brand-400/10 blur-[100px]" />
      </div>
      <VisitorNav />
      <main className="relative z-10">{children}</main>
      <VisitorFooter />
    </div>
  );
}
