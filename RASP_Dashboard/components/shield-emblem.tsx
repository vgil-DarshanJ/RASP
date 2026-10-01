import { ShieldIcon } from "@/components/ui";

/** RASHIELD's identity mark — a genuinely 3D medallion, not a flat icon:
 *  `.emblem-scene`/`.emblem-rotor` (globals.css) give it real
 *  `perspective`/`rotateY`, so it foreshortens and goes edge-on as it
 *  turns, the way the reference video's spinning token does. Two motion
 *  modes share that same rotor — `spinIn` for the dramatic multi-turn
 *  entrance on the landing page's reveal beat, and the default gentle
 *  idle tilt (plus a sweeping specular highlight) for everywhere else,
 *  so it never sits dead-still. Wrapped in the same gold sunburst rays
 *  used throughout the brand. */
export function ShieldEmblem({
  size = 208,
  className = "",
  spinIn = false,
}: {
  size?: number;
  className?: string;
  spinIn?: boolean;
}) {
  const core = size * 0.42;
  return (
    <div
      className={`relative mx-auto flex items-center justify-center ${className}`}
      style={{ width: size, height: size }}
    >
      {/* Atmosphere — two stacked, differently-sized blurs so the glow
          reads as bright and voluminous instead of a thin halo. */}
      <div className="absolute -inset-8 rounded-full bg-brand-400/25 blur-3xl" aria-hidden />
      <div className="absolute inset-0 rounded-full bg-brand-500/20 blur-2xl" aria-hidden />

      <div className="hero-rays absolute inset-0 rounded-full" aria-hidden />
      <div className="hero-rays-inner absolute inset-[10%] rounded-full" aria-hidden />
      <div className="absolute inset-[34%] rounded-full border border-brand-400/30" aria-hidden />

      {/* The 3D medallion itself. */}
      <div className="emblem-scene relative" style={{ width: core, height: core }}>
        <div
          className={`emblem-rotor relative h-full w-full rounded-full ${
            spinIn ? "animate-emblem-spin-in" : "animate-emblem-idle"
          }`}
          style={{
            background:
              "radial-gradient(circle at 32% 26%, rgba(255,240,205,0.95) 0%, rgba(234,168,40,0.6) 26%, rgba(50,34,8,0.95) 64%, #000 100%)",
            boxShadow:
              "inset 0 1px 2px rgba(255,255,255,0.35), inset 0 -8px 16px rgba(0,0,0,0.65), 0 10px 26px rgba(0,0,0,0.5)",
          }}
        >
          <div className="emblem-shine absolute inset-0 overflow-hidden rounded-full" aria-hidden />
          <div className="absolute inset-0 flex items-center justify-center text-brand-100">
            <ShieldIcon size={Math.round(size * 0.3)} className="drop-shadow-[0_1px_3px_rgba(0,0,0,0.7)]" />
          </div>
        </div>
      </div>
    </div>
  );
}
