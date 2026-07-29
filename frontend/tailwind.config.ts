import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0e0c",
        surface: "#0f1411",
        border: "#1e2a22",
        text: "#cfe0d2",
        muted: "#6d8074",
        accent: "#7ee787",
        danger: "#ff6b6b",
        warn: "#e5a04c",
        info: "#58a6ff",
        // "Held for review" verdicts read as neither pass nor fail, so they get
        // their own hue rather than borrowing the warning colour.
        suspect: "#bc8cff",
      },
      fontFamily: {
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "SF Mono",
          "Menlo",
          "Consolas",
          "Liberation Mono",
          "monospace",
        ],
      },
      borderRadius: {
        // Terminal surfaces are panels, not pills: corners stay tight.
        lg: "4px",
        xl: "5px",
        "2xl": "6px",
      },
    },
  },
  plugins: [],
};
export default config;
