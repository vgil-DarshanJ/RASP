"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";
import { siteRedirect } from "@/lib/sites";

/** Sends a page opened on the wrong site (visitor vs portal) to the right one — see lib/sites.ts. */
export function SiteGuard() {
  const pathname = usePathname();
  useEffect(() => {
    const target = siteRedirect(window.location);
    if (target) window.location.replace(target);
  }, [pathname]);
  return null;
}
