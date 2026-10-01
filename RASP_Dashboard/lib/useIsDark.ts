"use client";

import { useEffect, useState } from "react";

/**
 * Recharts takes its axis/gridline/tooltip colors as literal SVG prop
 * values, not CSS classes — a CSS variable swap can't reach them, so
 * chart pages need to know the resolved theme in JS. Combines the
 * explicit `data-theme` attribute (set by the toggle / the no-flash
 * script) with the `prefers-color-scheme` media query for whichever one
 * is actually driving the theme right now, and stays live: a
 * MutationObserver catches the toggle switching `data-theme`, and a
 * matchMedia listener catches the OS theme changing while no explicit
 * choice has been made.
 */
export function useIsDark(): boolean {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const mql = window.matchMedia("(prefers-color-scheme: dark)");

    function resolve() {
      const explicit = document.documentElement.getAttribute("data-theme");
      if (explicit === "dark") return setIsDark(true);
      if (explicit === "light") return setIsDark(false);
      setIsDark(mql.matches);
    }

    resolve();

    const observer = new MutationObserver(resolve);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    mql.addEventListener("change", resolve);

    return () => {
      observer.disconnect();
      mql.removeEventListener("change", resolve);
    };
  }, []);

  return isDark;
}
