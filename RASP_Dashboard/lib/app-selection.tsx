"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api-client";

export interface Application {
  id: string;
  name: string;
  platform: string;
}

interface AppSelectionValue {
  apps: Application[];
  selectedAppId: string | null;
  selectedApp: Application | null;
  setSelectedAppId: (id: string) => void;
  loading: boolean;
  refresh: () => Promise<void>;
}

const AppSelectionContext = createContext<AppSelectionValue | null>(null);

const STORAGE_KEY = "rasp_shield_selected_app_id";

/**
 * One shared "which application am I looking at" selection for the
 * whole app shell — Dashboard, Threat Analytics, Devices, Live Threats,
 * Device Activations and Alerting all used to fetch `/v1/apps` and keep
 * their OWN `selectedAppId` state, so switching pages silently reset you
 * back to the first app every time. This context fetches the app list
 * once, remembers the choice in `localStorage` (so it survives a
 * reload, not just in-session navigation), and every page reads/writes
 * the same value through [useAppSelection].
 */
export function AppSelectionProvider({ children }: { children: React.ReactNode }) {
  const [apps, setApps] = useState<Application[]>([]);
  const [selectedAppId, setSelectedAppIdState] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    const res = await apiFetch<{ applications: Application[] }>("/v1/apps");
    setApps(res.applications);

    let stored: string | null = null;
    try {
      stored = localStorage.getItem(STORAGE_KEY);
    } catch {
      // localStorage can throw in a private/locked-down browser context —
      // fall back to "no stored preference" rather than crash the shell.
    }
    const stillExists = stored && res.applications.some((a) => a.id === stored);
    setSelectedAppIdState(stillExists ? stored : res.applications[0]?.id ?? null);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const setSelectedAppId = useCallback((id: string) => {
    setSelectedAppIdState(id);
    try {
      localStorage.setItem(STORAGE_KEY, id);
    } catch {
      // Selection still works for this session even if it can't persist.
    }
  }, []);

  const selectedApp = useMemo(
    () => apps.find((a) => a.id === selectedAppId) ?? null,
    [apps, selectedAppId],
  );

  const value = useMemo(
    () => ({ apps, selectedAppId, selectedApp, setSelectedAppId, loading, refresh: load }),
    [apps, selectedAppId, selectedApp, setSelectedAppId, loading, load],
  );

  return <AppSelectionContext.Provider value={value}>{children}</AppSelectionContext.Provider>;
}

export function useAppSelection(): AppSelectionValue {
  const ctx = useContext(AppSelectionContext);
  if (!ctx) {
    throw new Error("useAppSelection must be used within AppSelectionProvider");
  }
  return ctx;
}
