// Replaces the inline `tailwind.config = {...}` blocks that were in every page (merged: login/services had two extra colours).
/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: ["./static/**/*.html", "./static/js/**/*.js"],
  theme: {
    extend: {
      colors: {
        "primary": "#13ec5b",
        "primary-hover": "#0fb847",
        "background-light": "#f6f8f6",
        "background-dark": "#102216",
        "surface-dark": "#111813",
        "surface-highlight": "#28392e",
        "text-muted": "#9db9a6",
        "log-bg": "#0a110d",
        "log-text": "#d4d4d4",
      },
      fontFamily: {
        "display": ["Inter", "sans-serif"],
        "mono": ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "Liberation Mono", "Courier New", "monospace"],
      },
      borderRadius: { "DEFAULT": "0.25rem", "lg": "0.5rem", "xl": "0.75rem", "full": "9999px" },
    },
  },
  plugins: [require("@tailwindcss/forms"), require("@tailwindcss/container-queries")],
};
