import type { Config } from "tailwindcss";

export default {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        sidebar: {
          bg: "#0f172a",
          text: "#94a3b8",
          active: "#1e293b",
          border: "#1e293b",
          label: "#475569",
        },
        brand: {
          blue: "#3b82f6",
          "blue-dark": "#2563eb",
          "blue-light": "#dbeafe",
        },
        threat: {
          critical: "#ef4444",
          "critical-bg": "#fef2f2",
          high: "#f97316",
          "high-bg": "#fff7ed",
          suspicious: "#eab308",
          "suspicious-bg": "#fefce8",
          low: "#22c55e",
          "low-bg": "#f0fdf4",
          safe: "#10b981",
          "safe-bg": "#ecfdf5",
        },
        surface: {
          bg: "#f8fafc",
          card: "#ffffff",
          border: "#e2e8f0",
          "border-light": "#f1f5f9",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 1px 3px 0 rgba(0, 0, 0, 0.07), 0 1px 2px -1px rgba(0, 0, 0, 0.04)",
        "card-hover": "0 4px 12px 0 rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.06)",
        sidebar: "1px 0 0 0 #1e293b",
      },
      animation: {
        "fade-in": "fadeIn 0.3s ease-in-out",
        "slide-up": "slideUp 0.3s ease-out",
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
