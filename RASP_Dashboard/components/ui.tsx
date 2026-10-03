import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SVGProps } from "react";

/* ────────────────────────────────────────────────────────────────────────
 * Icons — a small hand-rolled set (Feather-style: 1.75 stroke, 24 viewbox)
 * so the product has consistent line-icon language everywhere instead of
 * emoji. Kept local (no icon-library dependency) since only ~20 are used.
 * ──────────────────────────────────────────────────────────────────────── */

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Icon({ size = 18, children, ...props }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      {children}
    </svg>
  );
}

export const ShieldIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z" />
    <path d="M9 12l2 2 4-4" />
  </Icon>
);
export const LayersIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3l8 4.5-8 4.5-8-4.5L12 3z" />
    <path d="M4 12l8 4.5 8-4.5" />
    <path d="M4 16.5l8 4.5 8-4.5" />
  </Icon>
);
export const ActivityIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M22 12h-4l-3 8-6-16-3 8H2" />
  </Icon>
);
export const LogOutIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
    <path d="M16 17l5-5-5-5" />
    <path d="M21 12H9" />
  </Icon>
);
export const CheckCircleIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M8.5 12.5l2.3 2.3L16 10" />
  </Icon>
);
export const AlertTriangleIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 4.5L21 19H3L12 4.5z" />
    <path d="M12 10v4" />
    <path d="M12 17.2v.05" />
  </Icon>
);
export const AlertCircleIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7.5v5" />
    <path d="M12 16v.05" />
  </Icon>
);
export const HelpCircleIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M9.5 9.2a2.5 2.5 0 014.9.8c0 1.7-2.4 1.9-2.4 3.5" />
    <path d="M12 17v.05" />
  </Icon>
);
export const CopyIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="9" y="9" width="12" height="12" rx="2" />
    <path d="M5 15V5a2 2 0 012-2h10" />
  </Icon>
);
export const DownloadIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3v12" />
    <path d="M7 11l5 5 5-5" />
    <path d="M4 20h16" />
  </Icon>
);
export const PlusIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 5v14" />
    <path d="M5 12h14" />
  </Icon>
);
export const ClockIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3.5 2" />
  </Icon>
);
export const SmartphoneIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="6" y="2.5" width="12" height="19" rx="2.5" />
    <path d="M11 18.2h2" />
  </Icon>
);
export const KeyIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="8" cy="15" r="4" />
    <path d="M11 12l8-8" />
    <path d="M16 7l2.5 2.5" />
    <path d="M13.5 9.5L16 12" />
  </Icon>
);
export const SearchIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="M21 21l-4.3-4.3" />
  </Icon>
);
export const BarChartIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M5 20V10" />
    <path d="M12 20V4" />
    <path d="M19 20v-7" />
  </Icon>
);
export const ZapIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M13 3L5 13h6l-1 8 8-10h-6l1-8z" />
  </Icon>
);
export const MapPinIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 21s-7-6.5-7-11.5A7 7 0 0119 9.5C19 14.5 12 21 12 21z" />
    <circle cx="12" cy="9.5" r="2.3" />
  </Icon>
);
export const ScrollTextIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 3h11a2 2 0 012 2v13a2 2 0 01-2 2H8a2 2 0 01-2-2V3z" />
    <path d="M6 3a2 2 0 00-2 2v12a2 2 0 002 2" />
    <path d="M9 8h7M9 12h7M9 16h4" />
  </Icon>
);
export const SunIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="4.2" />
    <path d="M12 3v2M12 19v2M5 5l1.5 1.5M17.5 17.5L19 19M3 12h2M19 12h2M5 19l1.5-1.5M17.5 6.5L19 5" />
  </Icon>
);
export const MoonIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M20 14.5A8.5 8.5 0 1110 3.2a6.8 6.8 0 000 12.6 6.7 6.7 0 0010-1.3z" />
  </Icon>
);
export const MailIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="5" width="18" height="14" rx="2" />
    <path d="M3.5 6.5L12 13l8.5-6.5" />
  </Icon>
);
export const LockIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
    <path d="M8 10.5V7a4 4 0 018 0v3.5" />
  </Icon>
);
export const XIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 6l12 12" />
    <path d="M18 6L6 18" />
  </Icon>
);
export const BuildingIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="4" y="3" width="16" height="18" rx="1.5" />
    <path d="M8 7.5h1.5M8 11h1.5M8 14.5h1.5M14.5 7.5H16M14.5 11H16M14.5 14.5H16" />
    <path d="M10 21v-4h4v4" />
  </Icon>
);
export const BellIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 10.5a6 6 0 1112 0c0 4 1.3 5.5 2 6.3H4c.7-.8 2-2.3 2-6.3z" />
    <path d="M10.2 20a2 2 0 003.6 0" />
  </Icon>
);
export const BookOpenIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 5.5c2-.9 5-.9 8 .6 3-1.5 6-1.5 8-.6v13c-2-.9-5-.9-8 .6-3-1.5-6-1.5-8-.6z" />
    <path d="M12 6.1v13" />
  </Icon>
);
export const TrashIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M5 7h14" />
    <path d="M9 7V4.5a1 1 0 011-1h4a1 1 0 011 1V7" />
    <path d="M7 7l1 12.5a1.5 1.5 0 001.5 1.4h5a1.5 1.5 0 001.5-1.4L17 7" />
    <path d="M10 11v6M14 11v6" />
  </Icon>
);
export const CheckIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 12l5 5L20 6" />
  </Icon>
);
export const SpinnerIcon = (p: IconProps) => (
  <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" className="animate-spin" {...p}>
    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.5" opacity="0.2" />
    <path d="M21 12a9 9 0 00-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
  </svg>
);

/** Branded loading state — a scanning ring around the shield mark, with
 *  a soft brand glow, instead of a generic bare spinner. Used for the
 *  auth-gate's initial "checking session" moment (previously a blank
 *  white/black flash) and available anywhere else a loading state
 *  deserves more presence than [SpinnerIcon]. */
export function CyberLoader({ label, size = 40 }: { label?: string; size?: number }) {
  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: size, height: size }}>
        <div
          className="absolute inset-0 rounded-full opacity-60 blur-md"
          style={{ background: "radial-gradient(circle, rgba(31,162,133,0.55) 0%, transparent 70%)" }}
        />
        <svg viewBox="0 0 40 40" className="absolute inset-0 animate-spin" style={{ animationDuration: "1.4s" }}>
          <circle
            cx="20"
            cy="20"
            r="17"
            fill="none"
            stroke="rgb(31 162 133 / 0.9)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeDasharray="26 80"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center text-brand-500">
          <ShieldIcon size={Math.round(size * 0.45)} />
        </div>
      </div>
      {label && <p className="text-xs font-medium tracking-wide text-ink-400">{label}</p>}
    </div>
  );
}

/** Full-viewport variant of [CyberLoader] — the app shell's auth-check
 *  gate, and anywhere else a whole page has nothing to show yet. */
export function PageLoader({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <CyberLoader label={label} size={52} />
    </div>
  );
}

export const AndroidLogo = (p: IconProps) => (
  <svg width={p.size ?? 22} height={p.size ?? 22} viewBox="0 0 24 24" fill="currentColor" {...p}>
    <path d="M7.2 8.5h9.6v7.3a1 1 0 01-1 1h-.5v2.4a1.3 1.3 0 01-2.6 0v-2.4h-1.4v2.4a1.3 1.3 0 01-2.6 0v-2.4h-.5a1 1 0 01-1-1V8.5z" />
    <rect x="4.6" y="9.2" width="1.9" height="5.6" rx="0.95" />
    <rect x="17.5" y="9.2" width="1.9" height="5.6" rx="0.95" />
    <path d="M8 7.7c.1-1.7 1.7-3.1 4-3.1s3.9 1.4 4 3.1H8z" />
    <circle cx="10.1" cy="6.1" r="0.5" fill="#fff" />
    <circle cx="13.9" cy="6.1" r="0.5" fill="#fff" />
    <path d="M9 3.2l.9 1.2M15 3.2l-.9 1.2" stroke="currentColor" strokeWidth="0.8" fill="none" strokeLinecap="round" />
  </svg>
);
export const FlutterLogo = (p: IconProps) => (
  <svg width={p.size ?? 22} height={p.size ?? 22} viewBox="0 0 24 24" fill="currentColor" {...p}>
    <path d="M6 15.5L15.5 6h5L11 15.5H6z" />
    <path d="M11 15.5l4.5 4.5h5L15.5 15.5H11z" opacity="0.55" />
    <path d="M6 15.5l4-4 2.7 2.7-4 4-2.7-2.7z" />
  </svg>
);
export const AppleLogo = (p: IconProps) => (
  <svg width={p.size ?? 22} height={p.size ?? 22} viewBox="0 0 24 24" fill="currentColor" {...p}>
    <path d="M16.7 12.4c0-2.1 1.7-3.1 1.8-3.2-1-1.4-2.5-1.6-3-1.6-1.3-.1-2.5.7-3.1.7-.6 0-1.6-.7-2.7-.7-1.4 0-2.6.8-3.3 2-1.4 2.4-.4 6 1 8 .7 1 1.5 2.1 2.6 2 1-.1 1.4-.7 2.7-.7 1.3 0 1.6.7 2.7.6 1.1 0 1.8-1 2.5-2 .6-.9.9-1.7 1.1-2.2-2.5-1-2.3-2.9-2.3-2.9z" />
    <path d="M14.3 5.6c.6-.7 1-1.7.9-2.6-.9.1-1.9.6-2.5 1.3-.5.6-1 1.6-.8 2.5.9.1 1.8-.5 2.4-1.2z" />
  </svg>
);
export const ReactLogo = (p: IconProps) => (
  <svg width={p.size ?? 22} height={p.size ?? 22} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.3} {...p}>
    <circle cx="12" cy="12" r="1.8" fill="currentColor" stroke="none" />
    <ellipse cx="12" cy="12" rx="9" ry="3.6" />
    <ellipse cx="12" cy="12" rx="9" ry="3.6" transform="rotate(60 12 12)" />
    <ellipse cx="12" cy="12" rx="9" ry="3.6" transform="rotate(120 12 12)" />
  </svg>
);

/* ────────────────────────────────────────────────────────────────────────
 * Primitives
 * ──────────────────────────────────────────────────────────────────────── */

export function Card({
  children,
  className = "",
  onClick,
}: {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
}) {
  return (
    <div
      className={`rounded-2xl border border-ink-100 bg-surface shadow-card ${className}`}
      onClick={onClick}
    >
      {children}
    </div>
  );
}

export function Button({
  className = "",
  variant = "primary",
  size = "md",
  loading = false,
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md";
  loading?: boolean;
}) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition disabled:opacity-50 disabled:cursor-not-allowed";
  const sizes: Record<string, string> = {
    sm: "px-3 py-1.5 text-xs",
    md: "px-4 py-2.5 text-sm",
  };
  const variants: Record<string, string> = {
    primary: "bg-brand-600 text-white shadow-sm hover:bg-brand-700 active:bg-brand-800",
    secondary: "bg-ink-50 text-ink-800 border border-ink-200 hover:bg-ink-100",
    danger: "bg-red-50 text-red-700 border border-red-200 hover:bg-red-100",
    ghost: "text-ink-600 hover:bg-ink-50",
  };
  return (
    <button
      className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}
      disabled={props.disabled || loading}
      {...props}
    >
      {loading && <SpinnerIcon size={14} />}
      {children}
    </button>
  );
}

export function Input({ icon, className = "", ...props }: InputHTMLAttributes<HTMLInputElement> & { icon?: ReactNode }) {
  if (icon) {
    return (
      <div className="relative">
        <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-400">{icon}</span>
        <input
          {...props}
          className={`w-full rounded-lg border border-ink-200 bg-surface py-2.5 pl-10 pr-3 text-sm text-ink-900 outline-none transition placeholder:text-ink-400 focus:border-brand-500 focus:ring-4 focus:ring-brand-100 ${className}`}
        />
      </div>
    );
  }
  return (
    <input
      {...props}
      className={`w-full rounded-lg border border-ink-200 bg-surface px-3 py-2.5 text-sm text-ink-900 outline-none transition placeholder:text-ink-400 focus:border-brand-500 focus:ring-4 focus:ring-brand-100 ${className}`}
    />
  );
}

export function Label({ children }: { children: ReactNode }) {
  return <label className="mb-1.5 block text-sm font-medium text-ink-700">{children}</label>;
}

export function Badge({
  tone,
  children,
  icon = true,
}: {
  tone: "green" | "red" | "amber" | "slate";
  children: ReactNode;
  icon?: boolean;
}) {
  const tones: Record<string, string> = {
    green: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    red: "bg-red-50 text-red-700 ring-red-200",
    amber: "bg-amber-50 text-amber-800 ring-amber-200",
    slate: "bg-ink-100 text-ink-700 ring-ink-200",
  };
  const icons: Record<string, ReactNode> = {
    green: <CheckCircleIcon size={12} />,
    red: <AlertTriangleIcon size={12} />,
    amber: <AlertCircleIcon size={12} />,
    slate: <HelpCircleIcon size={12} />,
  };
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${tones[tone]}`}
    >
      {icon && icons[tone]}
      {children}
    </span>
  );
}

export function statusTone(status: string): "green" | "red" | "amber" | "slate" {
  switch (status) {
    case "SECURE":
      return "green";
    case "DETECTED":
      return "red";
    case "ERROR":
      return "amber";
    default:
      return "slate";
  }
}

/** Small live-status dot with an optional pulse ring — used next to
 *  "listening for events" / connection-state indicators. */
export function StatusDot({ tone = "green", pulse = false }: { tone?: "green" | "red" | "slate"; pulse?: boolean }) {
  const colors: Record<string, string> = {
    green: "bg-emerald-500",
    red: "bg-red-500",
    slate: "bg-ink-400",
  };
  return (
    <span className="relative inline-flex h-2 w-2">
      {pulse && <span className={`absolute inline-flex h-full w-full animate-pulse-ring rounded-full ${colors[tone]}`} />}
      <span className={`relative inline-flex h-2 w-2 rounded-full ${colors[tone]}`} />
    </span>
  );
}

export function StatCard({
  label,
  value,
  icon,
  tone = "brand",
  sub,
}: {
  label: string;
  value: ReactNode;
  icon: ReactNode;
  tone?: "brand" | "red" | "amber" | "slate";
  sub?: string;
}) {
  const tones: Record<string, string> = {
    brand: "bg-brand-50 text-brand-700",
    red: "bg-red-50 text-red-600",
    amber: "bg-amber-50 text-amber-700",
    slate: "bg-ink-100 text-ink-600",
  };
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-ink-400">{label}</div>
          <div className="mt-2 text-2xl font-semibold text-ink-900">{value}</div>
          {sub && <div className="mt-1 text-xs text-ink-400">{sub}</div>}
        </div>
        <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${tones[tone]}`}>{icon}</div>
      </div>
    </Card>
  );
}

/** Copies text to the clipboard and flashes a "Copied" confirmation.
 *  `navigator.clipboard` only exists in a secure context (https:, or
 *  http://localhost) — this app is also reached over plain
 *  `http://<lan-ip>:3000`, where that API is simply undefined, not just
 *  permission-denied. Falls back to the older `document.execCommand`
 *  path (a hidden, focused, selected textarea) which still works over
 *  plain HTTP, instead of throwing an unhandled rejection. */
export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  return (
    <button
      type="button"
      onClick={async (e) => {
        // Capture before any await: React clears e.currentTarget once the
        // handler yields, so reading it after the clipboard call gave null.
        const el = e.currentTarget;
        const original = el.textContent;
        let ok = true;
        try {
          if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(value);
          } else {
            const textarea = document.createElement("textarea");
            textarea.value = value;
            textarea.style.position = "fixed";
            textarea.style.opacity = "0";
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            ok = document.execCommand("copy");
            document.body.removeChild(textarea);
          }
        } catch {
          ok = false;
        }
        el.textContent = ok ? "Copied" : "Copy failed";
        setTimeout(() => {
          el.textContent = original;
        }, 1200);
      }}
      className="inline-flex items-center gap-1 rounded-md border border-ink-200 bg-surface px-2 py-1 text-xs font-medium text-ink-600 hover:border-brand-300 hover:text-brand-700"
    >
      <CopyIcon size={12} />
      {label}
    </button>
  );
}

const PLATFORM_LOGOS: Record<string, (p: IconProps) => ReactNode> = {
  ANDROID_NATIVE: AndroidLogo,
  FLUTTER: FlutterLogo,
  IOS: AppleLogo,
  REACT_NATIVE: ReactLogo,
};

export function PlatformIcon({ platform, size = 20, className = "" }: { platform: string; size?: number; className?: string }) {
  const Logo = PLATFORM_LOGOS[platform] ?? ShieldIcon;
  return <Logo size={size} className={className} />;
}

const RISK_TONES: Record<string, { bg: string; text: string; ring: string; dot: string }> = {
  low: { bg: "bg-emerald-50", text: "text-emerald-700", ring: "ring-emerald-200", dot: "bg-emerald-500" },
  medium: { bg: "bg-amber-50", text: "text-amber-800", ring: "ring-amber-200", dot: "bg-amber-500" },
  high: { bg: "bg-orange-50", text: "text-orange-700", ring: "ring-orange-200", dot: "bg-orange-500" },
  critical: { bg: "bg-red-50", text: "text-red-700", ring: "ring-red-200", dot: "bg-red-600" },
};

/** Risk-score pill — `score` is our own 0-100 weighted rollup (see BE
 *  `src/detectors/severity.ts`), `level` its display band. Kept separate
 *  from [Badge] (which renders a raw detector `status`) since a risk
 *  score is a derived posture metric, not a single detector's result. */
export function RiskBadge({ score, level, size = "md" }: { score: number; level: string; size?: "sm" | "md" }) {
  const tone = RISK_TONES[level] ?? RISK_TONES.low;
  const padding = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-medium ring-1 ring-inset ${tone.bg} ${tone.text} ${tone.ring} ${padding}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
      {score} · {level[0].toUpperCase() + level.slice(1)}
    </span>
  );
}

/** Small colored category pill — imports its color map from
 *  `lib/alertCatalog` at the call site rather than owning the palette
 *  here, so this stays a dumb rendering primitive. */
export function CategoryChip({
  label,
  colors,
  count,
  active = false,
  onClick,
}: {
  label: string;
  colors: { bg: string; text: string; dot: string };
  count?: number;
  active?: boolean;
  onClick?: () => void;
}) {
  const Tag = onClick ? "button" : "span";
  return (
    <Tag
      type={onClick ? "button" : undefined}
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium transition ${
        active ? `${colors.bg} ${colors.text} ring-1 ring-inset ring-current/20` : "text-ink-500 hover:bg-ink-50"
      } ${onClick ? "cursor-pointer" : ""}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${colors.dot}`} />
      {label}
      {count !== undefined && <span className="text-[11px] opacity-70">{count}</span>}
    </Tag>
  );
}
