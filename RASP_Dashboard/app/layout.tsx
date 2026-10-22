import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { SiteGuard } from "@/components/site-guard";

const sans = Inter({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  title: "RASHIELD — Real-Time Application Shield",
  description: "Organization, SDK, and audit-log management for the RASP Shield runtime engine.",
};

/**
 * Applies the visitor's stored theme choice to `<html data-theme>`
 * BEFORE the browser paints anything — a synchronous, un-deferred inline
 * script is the only way to avoid a flash of the wrong theme on load,
 * since React itself can't run early enough. Reads only localStorage; if
 * nothing's stored, this does nothing and the `@media
 * (prefers-color-scheme)` rule in globals.css decides instead. Wrapped
 * in try/catch — private browsing can throw on localStorage access, and
 * that must never block rendering.
 */
const THEME_INIT_SCRIPT = `(function(){try{var t=localStorage.getItem("theme");if(t==="light"||t==="dark"){document.documentElement.setAttribute("data-theme",t);}}catch(e){}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <body className="min-h-screen font-sans antialiased">
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
        <SiteGuard />
        {children}
      </body>
    </html>
  );
}
