"use client";

import { useEffect, useState } from "react";
import { MoonIcon, SunIcon } from "@/components/ui";

/**
 * Explicit light/dark toggle. On mount, reads whatever `data-theme` the
 * inline no-flash script (see root `layout.tsx`) already applied to
 * `<html>` before hydration — never guesses independently, so this can
 * never fight that script and cause a flash. Persists the user's
 * explicit choice to localStorage; before any explicit choice, the
 * `@media (prefers-color-scheme)` rule in globals.css is what's actually
 * driving the theme.
 */
export function ThemeToggle({ className = "" }: { className?: string }) {
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);

  useEffect(() => {
    const current = document.documentElement.getAttribute("data-theme");
    if (current === "dark" || current === "light") {
      setTheme(current);
    } else {
      setTheme(window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    }
  }, []);

  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("theme", next);
    } catch {
      // Private browsing / storage disabled — the toggle still works for
      // this page load via the DOM attribute, it just won't persist.
    }
  }

  return (
    <button
      type="button"
      onClick={toggle}
      title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      className={`flex h-7 w-7 items-center justify-center rounded-md text-navy-500 transition hover:bg-white/[0.06] hover:text-white ${className}`}
    >
      {theme === "dark" ? <SunIcon size={15} /> : <MoonIcon size={15} />}
    </button>
  );
}
