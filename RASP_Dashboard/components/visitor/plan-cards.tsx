import Link from "next/link";
import { CheckIcon } from "@/components/ui";
import { PLANS } from "@/lib/visitor/plans";

export function PlanCards() {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {PLANS.map((p) => (
        <div
          key={p.id}
          className={`relative flex flex-col rounded-2xl border p-6 transition ${
            p.featured
              ? "border-brand-400/40 bg-gradient-to-b from-brand-500/[0.12] to-white/[0.02] shadow-[0_20px_60px_-25px_rgba(234,168,40,0.45)]"
              : "border-white/[0.07] bg-white/[0.02] hover:border-white/15"
          }`}
        >
          {p.featured && (
            <span className="absolute -top-2.5 left-6 rounded-full bg-brand-400 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.14em] text-black">
              Most chosen
            </span>
          )}
          <div className="text-xs font-medium uppercase tracking-[0.14em] text-white/40">{p.audience}</div>
          <h3 className="mt-2 text-lg font-semibold text-white">{p.name}</h3>
          <div className="mt-4 text-3xl font-bold text-brand-300">{p.price}</div>
          <div className="text-xs text-white/40">{p.priceNote}</div>
          <ul className="mt-5 flex-1 space-y-2.5">
            {p.highlights.map((h) => (
              <li key={h} className="flex items-start gap-2 text-sm text-white/65">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-brand-400/15 text-brand-300">
                  <CheckIcon size={10} />
                </span>
                {h}
              </li>
            ))}
          </ul>
          <Link
            href={p.cta.href}
            className={`mt-6 rounded-lg px-4 py-2.5 text-center text-sm font-semibold transition ${
              p.featured ? "bg-brand-500 text-black hover:bg-brand-400" : "border border-white/15 text-white/85 hover:border-white/30 hover:text-white"
            }`}
          >
            {p.cta.label}
          </Link>
        </div>
      ))}
    </div>
  );
}
