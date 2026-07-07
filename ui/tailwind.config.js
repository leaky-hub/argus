/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Neutral ramp, biased a few degrees toward the accent's blue-violet so
        // the greys read as chosen, not stock Tailwind. Every gray-* class in
        // the app picks these up, which is what shifts the whole tone at once.
        gray: {
          50: "#f5f6f9",
          100: "#eceef4",
          200: "#dde1ea",
          300: "#c6ccda",
          400: "#98a0b3",
          500: "#6b7385",
          600: "#515868",
          700: "#3a4150",
          800: "#262b38",
          900: "#171b26",
          950: "#0b0e15",
        },
        // Iris indigo, the single interactive accent (active nav, selection,
        // focus ring, primary action). Used sparingly, on purpose.
        accent: {
          50: "#eef0fc",
          100: "#e2e5fb",
          200: "#c9cdf6",
          300: "#a7adee",
          400: "#828be4",
          500: "#6470da",
          600: "#4b53c4",
          700: "#3e43a2",
          800: "#333884",
          900: "#2e3169",
        },
        // Severity ramp, retuned per intent: medium is a distinct amber that
        // won't read as high, low is a calmer blue. Dark variants are handled
        // in theme.ts where the chips live.
        sev: {
          critical: "#c92a30",
          high: "#d95d10",
          medium: "#c98a10",
          low: "#2f74c0",
          info: "#6b7386",
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      borderRadius: {
        // Controls and chips at 6, panels and the drawer at 10; nothing else.
        DEFAULT: "6px",
        md: "6px",
        lg: "10px",
        xl: "10px",
      },
      boxShadow: {
        // A resting hairline shadow, and one heavier token for floating surfaces.
        sm: "0 1px 2px rgba(15, 20, 34, 0.06)",
        DEFAULT: "0 12px 32px rgba(15, 20, 34, 0.16)",
        float: "0 16px 40px rgba(0, 0, 0, 0.28)",
      },
      ringColor: {
        DEFAULT: "#4b53c4",
      },
    },
  },
  plugins: [],
};
