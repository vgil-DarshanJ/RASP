import Link from "next/link";
import { VisitorShell } from "@/components/visitor/visitor-shell";
import { PlanCards } from "@/components/visitor/plan-cards";
import { CheckIcon } from "@/components/ui";
import { MATRIX, PLANS, type Cell } from "@/lib/visitor/plans";

export const metadata = { title: "Plans & comparison — RASHIELD" };

function CellView({ cell }: { cell: Cell }) {
  if (cell === true) {
    return (
      <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-brand-400/15 text-brand-300">
        <CheckIcon size={12} />
      </span>
    );
  }
  if (cell === false) return <span className="text-white/20">—</span>;
  return <span className="text-xs text-white/70">{cell}</span>;
}

export default function PlansPage() {
  return (
    <VisitorShell>
      <section className="mx-auto max-w-6xl px-4 pb-12 pt-14 text-center sm:px-6 lg:px-10">
        <div className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-300/80">Plans</div>
        <h1 className="mx-auto mt-2 max-w-3xl text-3xl font-bold sm:text-5xl">
          From a demo on one phone to <span className="text-brand-300">fraud intelligence at bank scale</span>
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-sm leading-relaxed text-white/55">
          Every plan uses the same engine and the same console. Plans differ in which modules are switched on,
          which fraud tools you get, and how far you scale.
        </p>
      </section>

      <section className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-10">
        <PlanCards />
      </section>

      <section className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-10">
        <h2 className="mb-6 text-2xl font-semibold">Full comparison</h2>
        <div className="overflow-x-auto rounded-2xl border border-white/[0.07]">
          <table className="w-full min-w-[46rem] text-left text-sm">
            <thead className="sticky top-0 bg-black/90 backdrop-blur">
              <tr className="border-b border-white/[0.07]">
                <th className="w-[34%] px-5 py-4 text-xs font-medium uppercase tracking-[0.14em] text-white/40">Feature</th>
                {PLANS.map((p) => (
                  <th key={p.id} className={`px-4 py-4 text-center text-sm font-semibold ${p.featured ? "text-brand-300" : "text-white"}`}>
                    {p.name}
                  </th>
                ))}
              </tr>
            </thead>
            {MATRIX.map((group) => (
              <tbody key={group.title}>
                <tr>
                  <td colSpan={PLANS.length + 1} className="bg-white/[0.03] px-5 py-2.5 text-xs font-semibold uppercase tracking-[0.14em] text-brand-300/80">
                    {group.title}
                  </td>
                </tr>
                {group.rows.map((row) => (
                  <tr key={row.label} className="border-t border-white/[0.04] transition hover:bg-white/[0.02]">
                    <td className="px-5 py-3.5">
                      {row.href ? (
                        <Link href={row.href} className="font-medium text-white hover:text-brand-300">{row.label}</Link>
                      ) : (
                        <span className="font-medium text-white/85">{row.label}</span>
                      )}
                      {row.hint && <div className="mt-0.5 text-xs text-white/40">{row.hint}</div>}
                    </td>
                    {PLANS.map((p) => (
                      <td key={p.id} className={`px-4 py-3.5 text-center ${p.featured ? "bg-brand-400/[0.03]" : ""}`}>
                        <CellView cell={row.cells[p.id]} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            ))}
          </table>
        </div>
        <p className="mt-4 text-xs text-white/35">
          Limits shown are indicative; your agreement sets the final numbers. No plan blocks a device on its own — your app
          decides what to do with each result.
        </p>
      </section>
    </VisitorShell>
  );
}
