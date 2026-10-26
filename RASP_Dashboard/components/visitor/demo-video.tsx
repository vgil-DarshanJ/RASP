"use client";

import { useEffect, useRef, useState } from "react";
import type { Chapter, VideoRef } from "@/lib/visitor/capabilities";

function fmt(s: number) {
  const m = Math.floor(s / 60);
  return `${m}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
}

/**
 * A recorded phone demo. Plays muted and loops; with `start`/`end` it loops
 * only that part of the file (one long recording serves several features).
 * Chapters are clickable and the current one is highlighted. Starts playing
 * only when scrolled into view, so a page with many demos stays light.
 */
export function DemoVideo({
  video,
  chapters = [],
  caption,
  compact = false,
}: {
  video: VideoRef;
  chapters?: Chapter[];
  caption?: string;
  compact?: boolean;
}) {
  const ref = useRef<HTMLVideoElement>(null);
  const [time, setTime] = useState(video.start ?? 0);
  const [playing, setPlaying] = useState(false);
  const [hintVisible, setHintVisible] = useState(false);
  const start = video.start ?? 0;
  // A manual pause must not be overridden by the scroll-into-view autoplay.
  const pausedByUser = useRef(false);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          if (!pausedByUser.current) el.play().catch(() => {});
        } else {
          el.pause();
        }
      },
      { threshold: 0.35 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  // Briefly reveal the play/pause sign, then fade it out after 2s.
  function flashHint() {
    setHintVisible(true);
    if (hideTimer.current) clearTimeout(hideTimer.current);
    hideTimer.current = setTimeout(() => setHintVisible(false), 2000);
  }

  useEffect(() => () => {
    if (hideTimer.current) clearTimeout(hideTimer.current);
  }, []);

  // Click the video to toggle: one click pauses, the next resumes.
  function toggle() {
    const el = ref.current;
    if (!el) return;
    if (el.paused) {
      pausedByUser.current = false;
      el.play().catch(() => {});
    } else {
      pausedByUser.current = true;
      el.pause();
    }
    flashHint();
  }

  function onTime() {
    const el = ref.current;
    if (!el) return;
    if (video.end !== undefined && el.currentTime >= video.end) el.currentTime = start;
    setTime(el.currentTime);
  }

  function seek(at: number) {
    const el = ref.current;
    if (!el) return;
    el.currentTime = at;
    pausedByUser.current = false;
    el.play().catch(() => {});
  }

  const current = [...chapters].reverse().find((c) => time >= c.at);

  return (
    <div className={compact ? "" : "grid gap-6 md:grid-cols-[minmax(0,18rem)_1fr] md:items-start"}>
      <div className="relative mx-auto w-full max-w-[18rem] overflow-hidden rounded-[1.75rem] border border-white/10 bg-black shadow-[0_30px_80px_-20px_rgba(234,168,40,0.25)]">
        <video
          ref={ref}
          src={video.src}
          poster={video.poster}
          muted
          playsInline
          loop={video.end === undefined}
          preload="metadata"
          onLoadedMetadata={() => {
            if (ref.current && start > 0) ref.current.currentTime = start;
          }}
          onTimeUpdate={onTime}
          onPlay={() => setPlaying(true)}
          onPause={() => setPlaying(false)}
          className="aspect-[9/16] w-full object-contain"
          aria-label={caption ?? "Product demo recording"}
        />
        <button
          type="button"
          onClick={toggle}
          aria-label={playing ? "Pause video" : "Play video"}
          className="absolute inset-0 z-10 flex items-center justify-center bg-transparent"
        >
          <span
            className={`flex h-14 w-14 items-center justify-center rounded-full bg-black/55 text-white backdrop-blur transition-opacity duration-500 ${
              hintVisible ? "opacity-100" : "opacity-0"
            }`}
          >
            {playing ? (
              <svg viewBox="0 0 24 24" className="h-6 w-6 fill-current" aria-hidden="true">
                <path d="M7 5h3.2v14H7zM13.8 5H17v14h-3.2z" />
              </svg>
            ) : (
              <svg viewBox="0 0 24 24" className="ml-0.5 h-6 w-6 fill-current" aria-hidden="true">
                <path d="M8 5v14l11-7z" />
              </svg>
            )}
          </span>
        </button>
        <span className="pointer-events-none absolute left-3 top-3 z-20 inline-flex items-center gap-1.5 rounded-full bg-black/70 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-brand-200 backdrop-blur">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-red-500" /> Real device
        </span>
      </div>

      {!compact && (chapters.length > 0 || caption) && (
        <div>
          {caption && <p className="text-sm leading-relaxed text-white/60">{caption}</p>}
          {chapters.length > 0 && (
            <ol className="mt-4 space-y-1">
              {chapters.map((c) => {
                const active = current === c;
                return (
                  <li key={`${c.at}-${c.label}`}>
                    <button
                      type="button"
                      onClick={() => seek(c.at)}
                      className={`flex w-full items-start gap-3 rounded-xl px-3 py-2 text-left text-sm transition ${
                        active ? "bg-brand-400/10 text-white ring-1 ring-inset ring-brand-400/25" : "text-white/55 hover:bg-white/[0.04] hover:text-white"
                      }`}
                    >
                      <span className={`mt-0.5 font-mono text-[11px] ${active ? "text-brand-300" : "text-white/35"}`}>{fmt(c.at)}</span>
                      {c.label}
                    </button>
                  </li>
                );
              })}
            </ol>
          )}
        </div>
      )}
    </div>
  );
}
