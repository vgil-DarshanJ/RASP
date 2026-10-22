"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Card, CheckCircleIcon, ShieldIcon } from "@/components/ui";
import { getStoredOrganization } from "@/lib/auth";
import { catalogFor } from "@/lib/alertCatalog";
import { ALL_CONTROLS, CONSOLE_FEATURES, PILLARS, type Control, type Pillar, type Priority } from "@/lib/controlsChecklist";

interface Answers {
  covered: Record<string, boolean>;
  notes: Record<string, string>;
}

const EMPTY: Answers = { covered: {}, notes: {} };

/** Answers live in this browser only — they are the customer's own notes,
 *  not product data, and the backend has no place for them. */
function storageKey() {
  return `rasp:controls:${getStoredOrganization()?.id ?? "anon"}`;
}

function load(): Answers {
  try {
    const raw = localStorage.getItem(storageKey());
    return raw ? { ...EMPTY, ...JSON.parse(raw) } : EMPTY;
  } catch {
    return EMPTY;
  }
}

const PRIORITY_TONE: Record<Priority, string> = {
  P0: "bg-red-500/10 text-red-600 ring-red-500/20",
  P1: "bg-amber-500/10 text-amber-700 ring-amber-500/20",
  P2: "bg-emerald-500/10 text-emerald-700 ring-emerald-500/20",
};

function pct(done: number, total: number) {
  return total === 0 ? 0 : Math.round((done / total) * 100);
}

function Progress({ value }: { value: number }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-ink-100">
      <div className="h-full rounded-full bg-brand-500 transition-all" style={{ width: `${value}%` }} />
    </div>
  );
}

export default function ControlsPage() {
  const [answers, setAnswers] = useState<Answers>(EMPTY);
  const [open, setOpen] = useState<{ pillar: Pillar["id"]; section: string } | null>(null);

  useEffect(() => setAnswers(load()), []);

  function update(next: Answers) {
    setAnswers(next);
    try {
      localStorage.setItem(storageKey(), JSON.stringify(next));
    } catch {
      /* private mode: answers last until the tab closes */
    }
  }

  const coveredCount = useMemo(() => ALL_CONTROLS.filter((c) => answers.covered[c.id]).length, [answers]);

  if (open) {
    const pillar = PILLARS.find((p) => p.id === open.pillar)!;
    const section = pillar.sections.find((s) => s.id === open.section)!;
    return (
      <SectionView
        pillar={pillar}
        sectionId={section.id}
        answers={answers}
        onChange={update}
        onSection={(id) => setOpen({ pillar: pillar.id, section: id })}
        onBack={() => setOpen(null)}
        total={{ done: coveredCount, all: ALL_CONTROLS.length }}
      />
    );
  }

  return (
    <div>
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink-900">Mobile App Controls</h1>
          <p className="mt-1 max-w-2xl text-sm text-ink-500">
            A self-assessment of {ALL_CONTROLS.length} controls a mobile banking team should have in place, mapped to OWASP
            MASVS. Where this product helps with a control, the detector is named — tick a control only when your team has it.
          </p>
        </div>
        <Card className="w-full p-4 sm:w-64">
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium uppercase tracking-wide text-ink-400">Total coverage</span>
            <span className="font-semibold text-brand-600">{pct(coveredCount, ALL_CONTROLS.length)}%</span>
          </div>
          <div className="mt-2">
            <Progress value={pct(coveredCount, ALL_CONTROLS.length)} />
          </div>
          <div className="mt-1.5 text-[11px] text-ink-400">
            {coveredCount} of {ALL_CONTROLS.length} covered · saved in this browser
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {PILLARS.map((p) => {
          const controls = p.sections.flatMap((s) => s.controls);
          const done = controls.filter((c) => answers.covered[c.id]).length;
          return (
            <Card key={p.id} className={`p-5 ${p.id === "mobile" ? "lg:row-span-2" : ""}`}>
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-600">
                  <ShieldIcon size={18} />
                </div>
                <div>
                  <div className="font-semibold text-ink-900">{p.title}</div>
                  <div className="text-xs text-ink-400">
                    {done} of {controls.length} controls covered · {p.subtitle}
                  </div>
                </div>
              </div>
              <div className="mt-4 flex items-center justify-between text-[11px] font-medium uppercase tracking-wide text-ink-400">
                <span>Overall coverage</span>
                <span className="text-brand-600">{pct(done, controls.length)}%</span>
              </div>
              <div className="mt-1.5">
                <Progress value={pct(done, controls.length)} />
              </div>
              <div className="mt-4 space-y-2.5">
                {p.sections.map((s) => {
                  const sDone = s.controls.filter((c) => answers.covered[c.id]).length;
                  const helped = s.controls.filter((c) => c.coveredBy?.length).length;
                  return (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => setOpen({ pillar: p.id, section: s.id })}
                      className="block w-full rounded-xl border border-ink-100 bg-ink-50/60 p-3.5 text-left transition hover:border-brand-300"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-medium text-ink-900">{s.title}</span>
                        <span className="text-xs font-semibold text-brand-600">{pct(sDone, s.controls.length)}%</span>
                      </div>
                      <div className="mt-2 flex items-center gap-3">
                        <Progress value={pct(sDone, s.controls.length)} />
                        <span className="shrink-0 text-[11px] font-medium uppercase tracking-wide text-ink-400">Open ›</span>
                      </div>
                      {helped > 0 && (
                        <div className="mt-2 text-[11px] text-ink-400">
                          {helped} of {s.controls.length} supported by RASHIELD
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function SectionView({
  pillar,
  sectionId,
  answers,
  onChange,
  onSection,
  onBack,
  total,
}: {
  pillar: Pillar;
  sectionId: string;
  answers: Answers;
  onChange: (a: Answers) => void;
  onSection: (id: string) => void;
  onBack: () => void;
  total: { done: number; all: number };
}) {
  const section = pillar.sections.find((s) => s.id === sectionId)!;
  const done = section.controls.filter((c) => answers.covered[c.id]).length;

  return (
    <div>
      <div className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <button onClick={onBack} className="rounded-lg px-2 py-1 text-ink-500 hover:bg-ink-100" aria-label="Back">
            ‹
          </button>
          <div>
            <h1 className="text-xl font-semibold text-ink-900">{pillar.title}</h1>
            <div className="text-xs text-brand-600">{section.title}</div>
          </div>
        </div>
        <div className="w-full sm:w-56">
          <div className="flex justify-between text-[11px] font-medium uppercase tracking-wide text-ink-400">
            <span>Total coverage</span>
            <span className="text-brand-600">{pct(total.done, total.all)}%</span>
          </div>
          <div className="mt-1.5">
            <Progress value={pct(total.done, total.all)} />
          </div>
        </div>
      </div>

      <div className="mb-4 flex gap-2 overflow-x-auto pb-1">
        {pillar.sections.map((s) => (
          <button
            key={s.id}
            onClick={() => onSection(s.id)}
            className={`shrink-0 rounded-full px-3 py-1.5 text-xs font-medium transition ${
              s.id === sectionId ? "bg-brand-500 text-black" : "bg-ink-100 text-ink-600 hover:bg-ink-200"
            }`}
          >
            {s.title}
          </button>
        ))}
      </div>

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-100 px-5 py-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-brand-600">{section.title}</h2>
          <span className="text-xs text-ink-400">
            {done} / {section.controls.length} covered
          </span>
        </div>
        <div className="divide-y divide-ink-100">
          {section.controls.map((c) => (
            <ControlRow key={c.id} control={c} answers={answers} onChange={onChange} />
          ))}
        </div>
      </Card>
    </div>
  );
}

function ControlRow({ control: c, answers, onChange }: { control: Control; answers: Answers; onChange: (a: Answers) => void }) {
  const checked = !!answers.covered[c.id];
  return (
    <div className={`grid gap-4 p-5 lg:grid-cols-[2rem_1.2fr_1fr_1fr_1.3fr_14rem] ${checked ? "bg-brand-50/40" : ""}`}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange({ ...answers, covered: { ...answers.covered, [c.id]: e.target.checked } })}
        className="mt-1 h-5 w-5 cursor-pointer accent-[#d28e15]"
        aria-label={`Covered: ${c.topic}`}
      />
      <div>
        <div className="font-semibold text-ink-900">{c.topic}</div>
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className={`rounded px-1.5 py-0.5 font-bold ring-1 ring-inset ${PRIORITY_TONE[c.priority]}`}>{c.priority}</span>
          <span className="font-mono text-brand-600">{c.masvs}</span>
          <span className="text-ink-400">{c.frameworks}</span>
        </div>
      </div>
      <Field label="Consider">{c.consider}</Field>
      <Field label="Why">{c.why}</Field>
      <div>
        <Field label="How">{c.how}</Field>
        {c.coveredBy && (
          <div className="mt-2 flex flex-wrap gap-1">
            {c.coveredBy.map((id) => {
              const consoleFeature = CONSOLE_FEATURES[id];
              const label = consoleFeature?.label ?? catalogFor(id).title;
              const href = consoleFeature?.href ?? `/capabilities/${id.replace(/_/g, "-")}`;
              return (
                <Link
                  key={id}
                  href={href}
                  className="inline-flex items-center gap-1 rounded-full bg-brand-50 px-2 py-0.5 text-[11px] font-medium text-brand-700 ring-1 ring-inset ring-brand-200 hover:bg-brand-100"
                >
                  <CheckCircleIcon size={10} />
                  {label}
                </Link>
              );
            })}
          </div>
        )}
      </div>
      <textarea
        value={answers.notes[c.id] ?? ""}
        onChange={(e) => onChange({ ...answers, notes: { ...answers.notes, [c.id]: e.target.value } })}
        placeholder="Add note…"
        rows={3}
        className="w-full resize-y rounded-lg border border-ink-200 bg-surface px-3 py-2 text-xs text-ink-800 outline-none placeholder:text-ink-400 focus:border-brand-500"
      />
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-400">{label}</div>
      <div className="text-xs leading-relaxed text-ink-600">{children}</div>
    </div>
  );
}
