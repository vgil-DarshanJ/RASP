/**
 * One build of this app serves two sites (the same files, two processes):
 *
 * - the visitor site (NEXT_PUBLIC_VISITOR_URL, office: http://192.168.2.208:6050)
 *   — `/`, `/capabilities…` and `/plans…`;
 * - the customer portal (NEXT_PUBLIC_PORTAL_URL, office: http://192.168.2.208:5050)
 *   — sign-in, the dashboard, `/status` and everything else.
 *
 * [SiteGuard] sends a page opened on the wrong site to the right one, in the
 * browser, so it also works with the static export (no server-side proxy).
 * With either URL unset (local `npm run dev`, the Docker image) nothing is
 * redirected and one origin serves every page.
 */
export const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://192.168.2.208:4444";
export const PORTAL_URL = trimUrl(process.env.NEXT_PUBLIC_PORTAL_URL);
export const VISITOR_URL = trimUrl(process.env.NEXT_PUBLIC_VISITOR_URL);

function trimUrl(value: string | undefined): string | null {
  const v = value?.trim().replace(/\/+$/, "");
  return v ? v : null;
}

function originOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

const startsWithSegment = (pathname: string, base: string) => pathname === base || pathname.startsWith(`${base}/`);

/** Pages only the visitor site shows. */
export function isVisitorOnlyPath(pathname: string): boolean {
  return pathname === "/" || startsWithSegment(pathname, "/capabilities");
}

/** Pages both sites show (the portal links to the plans from its menu). */
export function isSharedPath(pathname: string): boolean {
  return startsWithSegment(pathname, "/plans");
}

/**
 * Where a page at [location] should go instead, or null to stay. Pure, for
 * tests: `{ origin, pathname, search, hash }` of `window.location`.
 */
export function siteRedirect(
  location: { origin: string; pathname: string; search: string; hash: string },
  portalUrl: string | null = PORTAL_URL,
  visitorUrl: string | null = VISITOR_URL,
): string | null {
  const portal = originOf(portalUrl);
  const visitor = originOf(visitorUrl);
  if (!portal || !visitor || portal === visitor) return null;
  const { origin, pathname, search, hash } = location;
  if (origin === visitor && !isVisitorOnlyPath(pathname) && !isSharedPath(pathname)) {
    return `${portalUrl}${pathname}${search}${hash}`;
  }
  if (origin === portal) {
    if (pathname === "/") return "/dashboard";
    if (isVisitorOnlyPath(pathname)) return `${visitorUrl}${pathname}${search}${hash}`;
  }
  return null;
}
