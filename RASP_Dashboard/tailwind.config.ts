import type { Config } from "tailwindcss";

/** Builds a Tailwind color scale backed by CSS custom properties (the
 *  standard `rgb(var(--x) / <alpha-value>)` recipe) so every existing
 *  `bg-ink-900`/`text-ink-500`/`border-ink-200/60` class in the codebase
 *  automatically responds to the `.dark` class — swapping the variable
 *  values in globals.css is enough, no component file has to add a
 *  `dark:` variant. */
function cssVarScale(prefix: string, shades: number[]) {
  return Object.fromEntries(shades.map((s) => [s, `rgb(var(--${prefix}-${s}) / <alpha-value>)`]));
}

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      colors: {
        // Primary brand — a rich gold, paired everywhere with the
        // near-black `ink`/`navy` scale for the product's "gold on black"
        // identity. Same values in both themes — a mid-tone gold reads
        // fine on both a light and a dark surface.
        brand: {
          50: "#fffbea",
          100: "#fef0c7",
          200: "#fbdd8b",
          300: "#f7c34e",
          400: "#eea828",
          500: "#d28e15",
          600: "#b07211",
          700: "#8c5a12",
          800: "#714a15",
          900: "#5e3e16",
          950: "#2f1e08",
        },
        // Theme-reversible neutral scale for main content — text,
        // surfaces, borders. `ink-900` means "primary text," `ink-50`
        // means "faintest surface" in BOTH themes; globals.css flips
        // which literal RGB each variable holds under `.dark`.
        ink: cssVarScale("ink", [50, 100, 200, 300, 400, 500, 600, 700, 800, 850, 900, 950]),
        // Fixed, non-reversible dark navy — for elements that are
        // deliberately dark regardless of site theme (the sidebar, the
        // auth-page hero panel). Literal hex, same values as the old
        // `ink` scale before it became reversible, so nothing there
        // "flips" when the user toggles theme.
        navy: {
          50: "#f5f7fa",
          100: "#e8ebf1",
          200: "#cdd4e2",
          300: "#a3aec7",
          400: "#7784a3",
          500: "#586485",
          600: "#434e6b",
          700: "#333c56",
          800: "#212840",
          850: "#181e33",
          900: "#111628",
          950: "#0a0e1c",
        },
        // Card/input/drawer backgrounds — white in light mode, a dark
        // navy panel in dark mode.
        surface: "rgb(var(--surface) / <alpha-value>)",
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(234,168,40,0.18), 0 8px 24px -4px rgba(234,168,40,0.3)",
        card: "0 1px 2px rgba(15,23,42,0.04), 0 1px 3px rgba(15,23,42,0.06)",
      },
      backgroundImage: {
        grid: "linear-gradient(to right, rgba(255,255,255,0.06) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.06) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};

export default config;
