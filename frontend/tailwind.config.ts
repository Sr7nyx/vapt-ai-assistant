import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0e0c",
        // Lifted from #0f1411, which sat only 1.04:1 from the background and left
        // panels doing no work: the borders were carrying all the separation.
        // 1.23:1 reads as a genuine surface without becoming a second theme.
        surface: "#1a251e",
        border: "#25332a",
        text: "#cfe0d2",
        // Raised from #6d8074, which was 4.4:1 on the old surface -- already under
        // the 4.5 body-text threshold before the lift, and worse after it.
        muted: "#7f9386",
        // The workhorse: borders, labels, links. Calm enough to read at length.
        accent: "#7ee787",
        // Reserved for live and active states -- the cursor, the current selection,
        // the orb. Deliberately not used for structure: at 16.4:1 it is fatiguing
        // as a general-purpose accent.
        highlight: "#C6FF34",
        danger: "#ff6b6b",
        warn: "#e5a04c",
        info: "#58a6ff",
        // "Held for review" verdicts read as neither pass nor fail, so they get
        // their own hue rather than borrowing the warning colour. Lavender at
        // 11.9:1 replaces #bc8cff, which was the weakest token at 7.7:1.
        suspect: "#D2C3F6",
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
