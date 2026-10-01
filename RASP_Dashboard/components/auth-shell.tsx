import type { ReactNode } from "react";
import { CheckIcon, ShieldIcon } from "@/components/ui";
import { ShieldEmblem } from "@/components/shield-emblem";

const FEATURES = [
  "26-detector runtime threat engine — root, Frida, tamper, MITM, overlay",
  "HMAC-signed, replay-protected event ingestion",
  "Per-application credentials with full issuance/revocation audit log",
  "Live dashboard — alert breakdown, volume trends, per-device detail",
];

/** Shared split-screen frame for /login and /register — a black, gold-lit
 *  hero panel on the left (brand mark, animated shield emblem, and feature
 *  proof-points — not just a logo) and the actual form in a light card on
 *  the right. Hero is hidden below `lg` so the form gets the full viewport
 *  on mobile instead of being squeezed. */
export function AuthShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
}) {
  return (
    <div className="flex min-h-screen bg-surface">
      <div className="relative hidden w-[46%] flex-col justify-between overflow-hidden bg-black p-10 text-white lg:flex">
        <div className="absolute inset-0 bg-grid bg-[length:32px_32px] opacity-[0.15]" />
        <div
          className="absolute -left-24 -top-24 h-72 w-72 rounded-full bg-brand-500/20 blur-3xl"
          aria-hidden
        />
        <div
          className="absolute bottom-0 right-0 h-96 w-96 translate-x-1/3 translate-y-1/3 rounded-full bg-brand-400/10 blur-3xl"
          aria-hidden
        />

        <div className="relative flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-500/15 text-brand-300 ring-1 ring-brand-400/30">
            <ShieldIcon size={19} />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-bold tracking-[0.12em] text-white">RASHIELD</div>
            <div className="text-[10px] font-medium tracking-[0.16em] text-brand-300/80">
              REAL-TIME APPLICATION SHIELD
            </div>
          </div>
        </div>

        <div className="relative flex flex-col items-center">
          <ShieldEmblem size={208} />

          <div className="animate-hero-rise mt-8 text-center">
            <h2 className="text-3xl font-bold uppercase leading-[1.15] tracking-tight text-white">
              Detect attacks.
              <br />
              <span className="text-brand-300">In real time.</span>
            </h2>
            <p className="mx-auto mt-3 max-w-sm text-sm leading-relaxed text-white/50">
              One place to issue credentials, ship your SDK, and see every security event your
              protected apps report — the instant it happens.
            </p>
          </div>

          <div className="mt-8 grid w-full max-w-md grid-cols-1 gap-2 sm:grid-cols-2">
            {FEATURES.map((f) => (
              <div
                key={f}
                className="flex items-start gap-2.5 rounded-xl border border-white/[0.06] bg-white/[0.03] p-3 text-left text-xs leading-relaxed text-white/60"
              >
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-brand-400/15 text-brand-300">
                  <CheckIcon size={10} />
                </span>
                {f}
              </div>
            ))}
          </div>
        </div>

        <div className="relative flex items-center justify-between text-xs text-white/30">
          <span>© {new Date().getFullYear()} RASHIELD</span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-brand-400 shadow-[0_0_8px_2px_rgba(234,168,40,0.6)]" />
            Runtime engine online
          </span>
        </div>
      </div>

      <div className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-600 text-white">
              <ShieldIcon size={20} />
            </div>
            <div className="leading-tight">
              <div className="text-sm font-bold tracking-[0.12em] text-ink-900">RASHIELD</div>
              <div className="text-[10px] font-medium tracking-[0.14em] text-ink-400">
                REAL-TIME APPLICATION SHIELD
              </div>
            </div>
          </div>
          <h1 className="text-2xl font-semibold text-ink-900">{title}</h1>
          <p className="mt-1.5 text-sm text-ink-500">{subtitle}</p>
          <div className="mt-7">{children}</div>
        </div>
      </div>
    </div>
  );
}
