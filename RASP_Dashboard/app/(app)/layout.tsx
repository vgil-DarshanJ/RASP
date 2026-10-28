"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { clearSession, getStoredOrganization, getStoredUser, hasSession, saveSession, StoredSession } from "@/lib/auth";
import { apiFetch } from "@/lib/api-client";
import { useHealth } from "@/lib/useHealth";
import { AppSelectionProvider, useAppSelection } from "@/lib/app-selection";
import { useIsDark } from "@/lib/useIsDark";
import {
  ActivityIcon,
  AlertTriangleIcon,
  BarChartIcon,
  BellIcon,
  BookOpenIcon,
  BuildingIcon,
  CheckCircleIcon,
  KeyIcon,
  LayersIcon,
  LockIcon,
  LogOutIcon,
  MailIcon,
  MapPinIcon,
  PageLoader,
  PlatformIcon,
  ScrollTextIcon,
  SearchIcon,
  ShieldIcon,
  SmartphoneIcon,
  StatusDot,
  ZapIcon,
} from "@/components/ui";
import { ThemeToggle } from "@/components/theme-toggle";

/** Routes that read `useAppSelection()` — the shared app picker only
 *  renders on these, since Applications/Licenses/Search/Audit
 *  Logs/Integration Guide are org-wide or platform-scoped, not scoped to
 *  one application. Kept as a literal list (not inferred from the nav)
 *  so a page choosing to opt in/out is an explicit, one-line decision. */
const APP_SCOPED_ROUTES = [
  "/dashboard",
  "/alerts-inbox",
  "/analytics", "/devices", "/threats", "/activations", "/alerting", "/security-settings", "/remote-config"];

function AppPickerBar() {
  const pathname = usePathname();
  const { apps, selectedAppId, selectedApp, setSelectedAppId, loading } = useAppSelection();

  if (!APP_SCOPED_ROUTES.some((r) => pathname?.startsWith(r))) return null;
  if (loading || apps.length === 0) return null;

  return (
    <div className="glass sticky top-0 z-40 px-8 py-3">
      <div className="mx-auto flex max-w-6xl items-center gap-3">
        <span className="text-xs font-medium uppercase tracking-wide text-ink-400">Viewing</span>
        <div className="flex items-center gap-2 rounded-lg border border-ink-200 bg-ink-50 px-2 py-1.5">
          <PlatformIcon platform={selectedApp?.platform ?? ""} size={14} className="text-ink-500" />
          <select
            value={selectedAppId ?? ""}
            onChange={(e) => setSelectedAppId(e.target.value)}
            className="cursor-pointer bg-transparent text-sm font-medium text-ink-900 outline-none"
            aria-label="Application"
          >
            {apps.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name}
              </option>
            ))}
          </select>
        </div>
        <span className="text-xs text-ink-400">
          Applies to every per-app view
        </span>
      </div>
    </div>
  );
}

/** Grouped sidebar nav. Every item here is backed by a real endpoint —
 *  see the "real-data tier" scoping decision: no page exists in this nav
 *  unless it reads genuine data (no mocked charts/lists). Mobile App
 *  Controls is a self-assessment (answers kept in this browser); "Pro"
 *  marks the modules sold with the fraud plans (see /plans). */
const NAV_GROUPS: {
  label: string | null;
  items: { href: string; label: string; icon: typeof ActivityIcon; badge?: string }[];
}[] = [
  {
    label: "CONTROL",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: ActivityIcon },
      { href: "/apps", label: "Applications", icon: LayersIcon },
      { href: "/controls", label: "Mobile App Controls", icon: CheckCircleIcon },
      { href: "/alerts-inbox", label: "Alerts Inbox", icon: MailIcon, badge: "Pro" },
    ],
  },
  {
    label: "MONITORING",
    items: [
      { href: "/threats", label: "Live Threats", icon: AlertTriangleIcon },
      { href: "/analytics", label: "Threat Analytics", icon: BarChartIcon },
      { href: "/devices", label: "Devices", icon: SmartphoneIcon },
      { href: "/map", label: "Device Map", icon: MapPinIcon },
      { href: "/search", label: "Global Search", icon: SearchIcon },
    ],
  },
  {
    label: "SDK & LICENSING",
    items: [
      { href: "/licenses", label: "Licenses", icon: KeyIcon },
      { href: "/activations", label: "Device Activations", icon: ZapIcon },
      { href: "/audit-logs", label: "Audit Logs", icon: ScrollTextIcon },
    ],
  },
  {
    label: "MAINTENANCE",
    items: [
      { href: "/status", label: "System Status", icon: ActivityIcon },
      { href: "/alerting", label: "Alerting", icon: BellIcon },
      { href: "/remote-config", label: "Remote Config", icon: LayersIcon },
      { href: "/security-settings", label: "Security Settings", icon: LockIcon },
      { href: "/guide", label: "Documentation", icon: BookOpenIcon },
      { href: "/plans", label: "Plans & Subscription", icon: BuildingIcon },
    ],
  },
];

export default function AppShellLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!hasSession()) {
      router.replace("/login");
      return;
    }
    setReady(true);
    // The cookie decides: an expired or revoked session gets 401 here and
    // apiFetch sends the browser to /login. A role change shows up at once.
    apiFetch<StoredSession>("/v1/auth/me").then(saveSession).catch(() => {});
  }, [router]);

  const health = useHealth();
  const isDark = useIsDark();

  if (!ready) return <PageLoader label="Securing your session…" />;

  const org = getStoredOrganization();
  const user = getStoredUser();
  const initials = (user?.email || "?").slice(0, 2).toUpperCase();

  const healthLabel: Record<typeof health.status, string> = {
    checking: "Checking backend…",
    healthy: "Ingestion online",
    degraded: `Degraded${!health.postgres ? " · DB down" : ""}${!health.redis ? " · cache down" : ""}`,
    unreachable: "Backend unreachable",
  };
  const healthTone: Record<typeof health.status, "green" | "red" | "slate"> = {
    checking: "slate",
    healthy: "green",
    degraded: "red",
    unreachable: "red",
  };

  async function logout() {
    // Revokes every token of this user on the backend and removes the cookie.
    await apiFetch("/v1/auth/logout", { method: "POST" }).catch(() => {});
    clearSession();
    router.replace("/login");
  }

  return (
    <div className="flex min-h-screen bg-ink-50">
      <aside className="flex w-64 shrink-0 flex-col bg-black text-navy-200">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-500/15 text-brand-300 ring-1 ring-brand-400/25">
            <ShieldIcon size={18} />
          </div>
          <div className="min-w-0 flex-1 leading-tight">
            <div className="text-sm font-bold tracking-[0.1em] text-white">RASHIELD</div>
            <div className="truncate text-[11px] text-navy-500">{org?.name}</div>
          </div>
          <ThemeToggle />
        </div>

        <div className="mx-5 mb-3 mt-1 flex items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.03] px-3 py-2 text-xs text-navy-300">
          <StatusDot tone={healthTone[health.status]} pulse={health.status === "healthy"} />
          {healthLabel[health.status]}
        </div>

        <div className="mx-5 border-t border-white/[0.06]" />

        <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-5">
          {NAV_GROUPS.map((group, gi) => (
            <div key={group.label ?? `group-${gi}`}>
              {group.label && (
                <div className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-navy-500/80">
                  {group.label}
                </div>
              )}
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const active = pathname?.startsWith(item.href);
                  const ItemIcon = item.icon;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${
                        active
                          ? "bg-brand-400/[0.12] text-white ring-1 ring-inset ring-brand-400/20"
                          : "text-navy-300 hover:bg-white/[0.05] hover:text-white"
                      }`}
                    >
                      <ItemIcon
                        size={17}
                        className={active ? "text-brand-300" : "text-navy-500 group-hover:text-navy-300"}
                      />
                      <span className="flex-1 leading-tight">{item.label}</span>
                      {item.badge && (
                        <span className="rounded-full bg-brand-400/15 px-1.5 py-px text-[9px] font-bold uppercase tracking-wider text-brand-300 ring-1 ring-inset ring-brand-400/25">
                          {item.badge}
                        </span>
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-white/[0.06] px-4 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-500/15 text-xs font-semibold text-brand-300 ring-1 ring-brand-400/25">
              {initials}
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-semibold text-white">{user?.email}</div>
              <div className="truncate text-[11px] uppercase tracking-wide text-navy-500">{user?.role}</div>
            </div>
            <button
              onClick={logout}
              title="Sign out"
              className="flex h-7 w-7 items-center justify-center rounded-md text-navy-500 transition hover:bg-brand-400/10 hover:text-brand-300"
            >
              <LogOutIcon size={15} />
            </button>
          </div>
        </div>
      </aside>

      <main className="relative flex-1 overflow-y-auto">
        {isDark && (
          <div className="pointer-events-none fixed inset-y-0 left-64 right-0 overflow-hidden" aria-hidden>
            <div className="absolute inset-0 bg-cyber-grid opacity-[0.35]" />
            <div className="cyber-glow-a absolute -left-32 -top-32 h-96 w-96 rounded-full blur-3xl" />
            <div className="cyber-glow-b absolute bottom-0 right-0 h-[28rem] w-[28rem] translate-x-1/4 translate-y-1/4 rounded-full blur-3xl" />
          </div>
        )}
        <AppSelectionProvider>
          <AppPickerBar />
          <div className="relative mx-auto max-w-6xl px-8 py-8">{children}</div>
        </AppSelectionProvider>
      </main>
    </div>
  );
}
